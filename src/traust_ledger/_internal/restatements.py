"""Administrative restatements — pure projection and chain replay.

A restatement is an appended event carrying a ``restatement`` block. It covers
signature-bound layer METADATA only: those fields are mutable, and rewriting
one destroyed the prior value, the actor and the reason all at once.

Event content is not restatable, deliberately. Events are immutable
(append-only storage + leaf_format 2), and the ledger already supersedes a wrong
determination with a later one under latest-wins precedence. A read-time overlay
would be a second read-time transform competing with the v1->v2 normaliser, with
no defined ordering between them (classifier-disposition plan R1, D13).

Pure computation over an events list. Writing a restatement is gated
(``_internal/gates.py``); reading one is not.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from traust_contracts.v1.enums import RestatementTarget, SourceType

#: ``finding_ref`` for a restatement that targets the layer envelope. The schema
#: requires the field; a real-looking finding id would put the restatement into
#: that finding's event stream.
LAYER_SCOPE_REF = "__layer__"

#: Metadata fields whose digests signature format 4 binds.
SIGNED_METADATA_FIELDS: tuple[str, ...] = (
    RestatementTarget.CLAIM_HASHES,
    RestatementTarget.AUDIT_REPORT_SHA256,
    RestatementTarget.ARTIFACT_DIGESTS,
)

#: Every restatement target is signature-bound. ``finding_aliases`` is
#: deliberately absent: a ``rebaseline`` event already records a rename inside
#: the Merkle tree, so the metadata table is a rebuildable projection.
RESTATABLE_METADATA_FIELDS: tuple[str, ...] = SIGNED_METADATA_FIELDS

#: Targets whose value is a map, so ``before``/``after`` carry a delta.
MAP_TARGETS: frozenset[str] = frozenset(
    {RestatementTarget.CLAIM_HASHES, RestatementTarget.ARTIFACT_DIGESTS}
)


def merge_delta(current: object, after: object) -> object:
    """Apply a restatement's ``after`` to the stored value.

    Map targets merge per key so the event carries only what changed; a null
    value deletes that key. Scalar targets replace outright.
    """
    if not isinstance(after, dict) or not isinstance(current, dict):
        return after
    merged = dict(current)
    for key, value in after.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def retired_values(events: Iterable[object], target: str, key: str | None) -> list:
    """Values this target (or map key) has already moved away from.

    The monotonic guard reads this: restoring a retired value reverses an
    earlier decision, which needs its own stated reason rather than arriving as
    a silent rollback. It is also what stops an A->B->A->B loop from appending
    events forever.
    """
    out = []
    for block in restatements_for(events, target):
        before, after = block.get("before"), block.get("after")
        if key is None:
            out.extend([before, after])
            continue
        if isinstance(before, dict) and key in before:
            out.append(before[key])
        if isinstance(after, dict) and key in after:
            out.append(after[key])
    return out


def is_destructive_change(prior: object, new: object) -> bool:
    """True when *new* drops or overwrites something *prior* already recorded.

    First writes are not restatements: pinning a claim hash for a finding that
    had none destroys no evidence, and those writes are routine harness work.
    Only an overwrite needs a restatement to record what was there.

    Per key for maps, so adding a newly-baselined finding to ``claim_hashes``
    stays an addition while changing an existing entry does not.
    """
    if prior in (None, {}, ""):
        return False
    if isinstance(prior, dict) and isinstance(new, dict):
        return any(new.get(key) != value for key, value in prior.items())
    return new != prior


def is_restatement(event: object) -> bool:
    """True for a restatement block on a restatement-typed event.

    Both halves: a hand-written layer could put a block on an ordinary
    determination, which must not grant it authority over metadata.
    """
    if not isinstance(event, dict):
        return False
    if not isinstance(event.get("restatement"), dict):
        return False
    return (event.get("source") or {}).get("type") == SourceType.RESTATEMENT


def restatements(events: Iterable[object]) -> list[dict]:
    """Restatement blocks in append order, each paired with its event."""
    return [{"event": e, "block": e["restatement"]} for e in (events or []) if is_restatement(e)]


def restatements_for(events: Iterable[object], target: str) -> list[dict]:
    """Restatement blocks naming *target*, oldest first."""
    return [c["block"] for c in restatements(events) if c["block"].get("target") == target]


def terminal_value(events: Iterable[object], target: str) -> tuple[bool, Any]:
    """``(restated, expected)`` for a metadata field after replaying its chain.

    Deltas make this per key: the chain never holds a whole map, so what is
    replayed is "the last value each restated key was given". A verifier
    compares only those keys and leaves the rest alone, which is stricter than
    the snapshot form was — an untouched key is genuinely unconstrained rather
    than silently asserted.

    The flag separates "never restated" from "restated to None".
    """
    chain = restatements_for(events, target)
    if not chain:
        return False, None
    expected: Any = None
    for block in chain:
        expected = merge_delta(expected if isinstance(expected, dict) else None, block.get("after"))
    return True, expected


def apply_restatements(events: Sequence[object]) -> list[dict]:
    """Events with restatements removed.

    Restatements are not evidence and must never reach the precedence engine.
    The input is not mutated — the Merkle root covers the stored bytes.
    """
    return [e for e in (events or []) if isinstance(e, dict) and not is_restatement(e)]


__all__ = [
    "LAYER_SCOPE_REF",
    "MAP_TARGETS",
    "RESTATABLE_METADATA_FIELDS",
    "SIGNED_METADATA_FIELDS",
    "apply_restatements",
    "is_destructive_change",
    "is_restatement",
    "merge_delta",
    "restatements",
    "restatements_for",
    "retired_values",
    "terminal_value",
]

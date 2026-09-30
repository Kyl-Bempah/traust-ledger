from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from traust_contracts.v1.enums import Validity
from traust_contracts.v1.models.layer import LayerActor, LayerEvent

from traust_ledger._internal.disposition import EXEC_SOURCE_TYPES
from traust_ledger._internal.events.builders import VALIDITY_FALSE_POSITIVE
from traust_ledger._internal.kinds import EventKind
from traust_ledger.constants import (
    ACTOR_KIND_HUMAN,
    ACTOR_KIND_MACHINE,
    LAYER_KEY_EVENTS,
    LAYER_KEY_METADATA,
    METADATA_KEY_MERKLE_EPOCH,
    RATIONALE_MIN_LENGTH,
    TIMESTAMP_FUTURE_LIMIT_HOURS,
)
from traust_ledger.service.errors import (
    IdentityRequiredError,
    IdentityUnverifiedError,
    InsufficientApproversError,
    InvalidEpochError,
    MachineDispositionError,
    NotAnAdminError,
    NothingToRestateError,
    RationaleTooShortError,
    RestatementAuthorityError,
    RetiredValueRestatedError,
    ServiceError,
    StaleRestatementError,
    TimestampFutureError,
    TwoPersonViolatedError,
)

logger = logging.getLogger(__name__)


def _reject_gate(
    gate: str,
    error: ServiceError,
    *,
    actor_identity: str | None = None,
    **context: object,
) -> None:
    context_bits = " ".join(f"{key}={value}" for key, value in context.items() if value)
    actor_bit = f" actor={actor_identity}" if actor_identity else ""
    logger.warning(
        "gate rejection gate=%s reason=%s%s%s",
        gate,
        error.detail,
        actor_bit,
        f" {context_bits}" if context_bits else "",
    )
    error.gate = gate
    error.actor_identity = actor_identity
    raise error


def reject_machine_disposition(actor: dict[str, object], disposition: dict[str, object]) -> None:
    if actor.get("kind") != ACTOR_KIND_MACHINE:
        return
    if not disposition:
        return
    identity = actor.get("identity")
    _reject_gate(
        "machine_disposition",
        MachineDispositionError(),
        actor_identity=str(identity) if identity else None,
    )


def reject_machine_human_lane(actor: LayerActor, event_kind: EventKind) -> None:
    if event_kind not in (EventKind.COUNTERSIGN, EventKind.SEVERITY):
        return
    if actor.kind != ACTOR_KIND_MACHINE:
        return
    _reject_gate(
        "machine_human_lane",
        MachineDispositionError(),
        actor_identity=actor.identity,
        event_kind=event_kind.value,
    )


def require_human_identity(actor: LayerActor, event_kind: EventKind) -> None:
    if event_kind not in (EventKind.COUNTERSIGN, EventKind.SEVERITY):
        return
    if not actor.identity:
        _reject_gate(
            "human_identity",
            IdentityRequiredError(),
            event_kind=event_kind.value,
        )


def _is_verified(actor: LayerActor) -> bool:
    """OIDC-first check, with legacy ldap_verified/employee_status fallback."""
    if actor.identity_verified is not None:
        return bool(actor.identity_verified)
    if actor.employee_status is not None:
        return actor.employee_status == "active"
    return bool(actor.ldap_verified)


def require_verified_for_false_positive(actor: LayerActor, validity: str) -> None:
    if validity != VALIDITY_FALSE_POSITIVE:
        return
    if actor.kind != ACTOR_KIND_HUMAN:
        return
    if actor.identity and _is_verified(actor):
        return
    _reject_gate(
        "verified_false_positive",
        IdentityUnverifiedError(),
        actor_identity=actor.identity,
    )


def require_verified_human(actor: LayerActor, gate: str) -> None:
    """The actor is a named, verified human.

    An attribution rule, not a permission: a restatement records a human
    decision, so a machine or anonymous actor cannot be its author whoever runs
    the write.
    """
    identity = (actor.identity or "").strip()
    if actor.kind != ACTOR_KIND_HUMAN or not identity:
        _reject_gate(gate, IdentityRequiredError(), actor_identity=actor.identity)
    if not _is_verified(actor):
        _reject_gate(gate, IdentityUnverifiedError(), actor_identity=actor.identity)


def require_admin(actor: LayerActor, admin_identities: Sequence[str]) -> None:
    """Only a verified human on the configured admin list may restate.

    Authorization: only meaningful where the caller cannot edit the list, so
    it is applied at the REST boundary (``service.auth``), never in a handler.
    Fails closed on an empty admin set.
    """
    require_verified_human(actor, "admin")
    identity = (actor.identity or "").strip().lower()
    allowed = {a.strip().lower() for a in admin_identities if a and a.strip()}
    if identity not in allowed:
        _reject_gate(
            "admin",
            NotAnAdminError(identity=actor.identity),
            actor_identity=actor.identity,
            configured_admins=len(allowed),
        )


def require_restatement_authority(block: dict[str, object]) -> None:
    """Semantic checks the schema cannot make: authority present, change real.

    A no-op restatement records an authorised change to a field that did not
    move — the shape of a cover story.
    """
    target = block.get("target")
    if not target:
        _reject_gate("restatement_authority", RestatementAuthorityError(detail="target required"))
    authority = block.get("authority")
    ticket = (authority or {}).get("ticket") if isinstance(authority, dict) else None
    if not (isinstance(ticket, str) and ticket.strip()):
        _reject_gate(
            "restatement_authority",
            RestatementAuthorityError(
                detail="authority.ticket is required — an unattributed restatement "
                "is indistinguishable from the rewrite this path exists to prevent"
            ),
        )
    if "after" not in block:
        _reject_gate("restatement_authority", RestatementAuthorityError(detail="after is required"))
    if "before" in block and block["before"] == block["after"]:
        _reject_gate(
            "restatement_authority",
            RestatementAuthorityError(
                detail=f"restatement for {target} changes nothing — before == after"
            ),
        )


def require_something_to_restate(block: dict[str, object], actual: object) -> None:
    """Every entry a restatement replaces must already hold a value.

    Setting something for the first time destroys nothing, so it needs no
    ticket and belongs on the ordinary write path. Checked per key for map
    targets: adding a newly baselined finding is an addition, not a
    restatement, even when other keys exist.
    """
    target = str(block.get("target"))
    before = block.get("before")
    if isinstance(before, dict):
        if not isinstance(actual, dict):
            _reject_gate("nothing_to_restate", NothingToRestateError(target=target))
            return
        absent = sorted(k for k in before if k not in actual)
        if absent:
            _reject_gate(
                "nothing_to_restate",
                NothingToRestateError(target=f"{target}[{', '.join(absent)}]"),
            )
        return
    if actual in (None, {}, ""):
        _reject_gate("nothing_to_restate", NothingToRestateError(target=target))


def require_fresh_restatement(block: dict[str, object], actual: object) -> None:
    """``before`` must match what the layer holds, entry by entry.

    Otherwise two admins restating from the same read both succeed and the log
    records both as applied.
    """
    before = block.get("before")
    if isinstance(before, dict) and isinstance(actual, dict):
        stale = {k: v for k, v in before.items() if actual.get(k) != v}
        if stale:
            _reject_gate(
                "restatement_freshness",
                StaleRestatementError(
                    target=block.get("target"),
                    before=stale,
                    actual={k: actual.get(k) for k in stale},
                ),
            )
        return
    if before != actual:
        _reject_gate(
            "restatement_freshness",
            StaleRestatementError(target=block.get("target"), before=before, actual=actual),
        )


def require_monotonic_restatement(block: dict[str, object], events: object) -> None:
    """A restatement may not restore a value the chain already retired.

    Two reasons. Reversing an earlier decision is itself a decision and needs
    its own stated reason, not a silent rollback to a value someone already
    moved away from. And without this an A->B->A->B loop passes every other
    gate forever: each step's ``before`` matches what is stored, so an actor
    with admin credentials can append events without bound, re-hashing and
    re-signing the layer every time.
    """
    from traust_ledger._internal.restatements import retired_values

    target = str(block.get("target"))
    after = block.get("after")
    if isinstance(after, dict):
        replayed = {
            key: value
            for key, value in after.items()
            if value in retired_values(events, target, key)
        }
        if replayed:
            _reject_gate(
                "restatement_monotonic",
                RetiredValueRestatedError(target=target, keys=", ".join(sorted(replayed))),
            )
        return
    if after in retired_values(events, target, None):
        _reject_gate(
            "restatement_monotonic",
            RetiredValueRestatedError(target=target, keys="(whole value)"),
        )


def require_restatement_approvers(
    block: dict[str, object], actor: LayerActor, minimum: int
) -> None:
    """Deployment-configured approval threshold for a restatement.

    Zero (the default) means the admin's own attribution is the authority.
    Higher values require named approvers who are not the actor -- the same
    shape as the two-person rule, applied to metadata authority instead of a
    false-positive reassertion.
    """
    if minimum <= 0:
        return
    authority = block.get("authority")
    raw = (authority or {}).get("approved_by") if isinstance(authority, dict) else None
    approvers = (
        [a.strip().lower() for a in raw.split(",") if a.strip()] if isinstance(raw, str) else []
    )
    independent = {a for a in approvers if a != (actor.identity or "").strip().lower()}
    if len(independent) < minimum:
        _reject_gate(
            "restatement_approvers",
            InsufficientApproversError(required=minimum, found=len(independent)),
            actor_identity=actor.identity,
        )


def require_rationale_length(rationale: str) -> None:
    if len(rationale) >= RATIONALE_MIN_LENGTH:
        return
    _reject_gate(
        "rationale_length",
        RationaleTooShortError(min_length=RATIONALE_MIN_LENGTH),
        rationale_length=len(rationale),
    )


class _UnparseableEvent:
    """Sentinel for an event that could not be parsed.

    The two-person gate must treat unparseable events as present-and-unknown
    rather than absent — silently dropping them let a single human bypass
    execution-confirmed findings.
    """

    __slots__ = ()


_UNPARSEABLE = _UnparseableEvent()

logger = logging.getLogger(__name__)


def _parse_event(raw: object) -> LayerEvent | _UnparseableEvent | None:
    if isinstance(raw, LayerEvent):
        return raw
    if isinstance(raw, dict):
        try:
            return LayerEvent.model_validate(raw)
        except Exception:
            logger.warning("unparseable event in layer: %s", raw)
            return _UNPARSEABLE
    return None


def _matches_finding(event: LayerEvent, finding_ref: str) -> bool:
    if event.finding_ref == finding_ref:
        return True
    return event.fingerprint == finding_ref if event.fingerprint else False


def _layer_event_actor_verified(event: LayerEvent) -> bool:
    a = event.source.actor
    if a.identity_verified is not None:
        return bool(a.identity_verified)
    return bool(a.ldap_verified)


def require_two_person(
    layer: dict[str, object],
    finding_ref: str,
    actor_identity: str,
    incoming_validity: str,
) -> None:
    """Two-person rule for FP reassertion after execution-confirmed challenge.

    Only fires when the incoming event asserts false_positive on a finding
    that has prior execution-class confirmation. In that case, a second
    independent verified human must concur -- the actor cannot be their
    own second signer.

    Non-FP countersigns and findings without execution proof pass freely.
    """
    if incoming_validity != VALIDITY_FALSE_POSITIVE:
        return

    raw_events = layer.get(LAYER_KEY_EVENTS)
    if not isinstance(raw_events, list):
        return

    parsed = [_parse_event(raw) for raw in raw_events]

    has_unparseable_for_finding = False
    matching: list[LayerEvent] = []
    for p in parsed:
        if p is None:
            continue
        if isinstance(p, _UnparseableEvent):
            has_unparseable_for_finding = True
            continue
        if _matches_finding(p, finding_ref):
            matching.append(p)

    has_exec_confirmed = any(
        e.source.type in EXEC_SOURCE_TYPES and e.disposition.validity == Validity.CONFIRMED
        for e in matching
    )
    if not has_exec_confirmed and not has_unparseable_for_finding:
        return

    if has_unparseable_for_finding:
        _reject_gate(
            "two_person",
            TwoPersonViolatedError(),
            actor_identity=actor_identity,
            finding_ref=finding_ref,
            reason="unparseable events in history — cannot verify two-person rule",
        )

    prior_fp_human_ids = {
        e.source.actor.identity
        for e in matching
        if e.disposition.validity == Validity.FALSE_POSITIVE
        and e.source.actor.kind == ACTOR_KIND_HUMAN
        and _layer_event_actor_verified(e)
        and e.source.actor.identity
    }

    if actor_identity in prior_fp_human_ids:
        _reject_gate(
            "two_person",
            TwoPersonViolatedError(),
            actor_identity=actor_identity,
            finding_ref=finding_ref,
        )


def _parse_recorded_at(recorded_at: str) -> datetime:
    parsed = datetime.fromisoformat(recorded_at)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def require_timestamp_bounds(recorded_at: str) -> None:
    parsed = _parse_recorded_at(recorded_at)
    limit = datetime.now(UTC) + timedelta(hours=TIMESTAMP_FUTURE_LIMIT_HOURS)
    if parsed <= limit:
        return
    _reject_gate(
        "timestamp_bounds",
        TimestampFutureError(hours=TIMESTAMP_FUTURE_LIMIT_HOURS),
        recorded_at=recorded_at,
    )


def require_valid_epoch(layer: dict[str, object]) -> None:
    events = layer.get(LAYER_KEY_EVENTS)
    if not isinstance(events, list) or not events:
        return
    metadata = layer.get(LAYER_KEY_METADATA)
    if not isinstance(metadata, dict):
        _reject_gate("valid_epoch", InvalidEpochError())
        return
    raw_epoch = metadata.get(METADATA_KEY_MERKLE_EPOCH)
    if raw_epoch is None:
        _reject_gate("valid_epoch", InvalidEpochError())
        return
    epoch = int(raw_epoch)
    if epoch < 0 or epoch > len(events):
        _reject_gate(
            "valid_epoch",
            InvalidEpochError(),
            merkle_epoch=epoch,
            event_count=len(events),
        )

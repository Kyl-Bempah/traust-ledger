"""`ledger restate` — administrative restatement of committed ledger metadata."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_ledger.cli import local_writer
from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.commands._fmt import utc_now_iso
from traust_ledger.cli.errors import cli_exit_service_error
from traust_ledger.cli.identity.actor import require_verified_actor
from traust_ledger.errors import ServiceError
from traust_ledger.handlers.restatement_handler import (
    apply_restatement,
    apply_restatement_batch,
)

TARGETS = ("claim_hashes", "audit_report_sha256", "artifact_digests")
REASONS = ("data_error", "schema_migration", "baseline_rewrite", "operator_error")


def _load_json_arg(raw: str) -> object:
    """A JSON literal, or a file's contents when prefixed with `@`.

    Keeps digests out of shell quoting.
    """
    if raw.startswith("@"):
        return json.loads(Path(raw[1:]).read_text(encoding="utf-8"))
    return json.loads(raw)


def _block_from_args(args: argparse.Namespace) -> dict:
    authority: dict[str, object] = {"ticket": args.ticket}
    if args.approved_by:
        authority["approved_by"] = args.approved_by
    block: dict[str, object] = {
        "target": args.target,
        "reason": args.reason,
        "before": _load_json_arg(args.before),
        "after": _load_json_arg(args.after),
        "authority": authority,
    }
    for flag, key in (("schema_from", "schema_from"), ("schema_to", "schema_to")):
        if getattr(args, flag, None):
            block[key] = getattr(args, flag)
    if args.finding_ref:
        block["finding_ref"] = args.finding_ref
    return block


def _batch_items(path: Path) -> list[dict]:
    """A bulk restatement file: ``[{layer, rationale, ...block}, …]``.

    One file, applied in order, no separate plan step — a caller who knows what
    they are doing should not have to stage it first. Each item is still gated
    individually, so a bad item fails alone rather than voiding the run.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    items = document.get("restatements") if isinstance(document, dict) else document
    if not isinstance(items, list) or not items:
        raise ValueError("expected a non-empty JSON array, or {'restatements': [...]}")
    return items


def cmd_restate(args: argparse.Namespace) -> int:
    """ledger restate --layer L --target T … | ledger restate --from batch.json"""
    if require_cli_auth():
        return 1
    actor = require_verified_actor()
    if actor is None:
        return 1

    writer, config = local_writer()

    if args.batch:
        try:
            items = _batch_items(Path(args.batch))
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        report = apply_restatement_batch(items, actor, writer, config)
        print(json.dumps(report, indent=2))
        return 1 if report["failed"] else 0

    required = (args.layer, args.target, args.reason, args.before, args.after, args.ticket)
    if not all(required):
        print(
            "error: --layer, --target, --reason, --before, --after and --ticket "
            "are required unless --from is used",
            file=sys.stderr,
        )
        return 1
    try:
        block = _block_from_args(args)
    except (OSError, ValueError) as exc:
        print(f"error: could not read restatement value: {exc}", file=sys.stderr)
        return 1
    try:
        result = apply_restatement(
            args.layer, block, args.rationale, actor, utc_now_iso(), writer, config
        )
    except ServiceError as exc:
        return cli_exit_service_error(exc)
    print(json.dumps(result.model_dump(), indent=2))
    return 0


def register_restate_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "restate",
        help="Append an administrative restatement event (records actor and ticket)",
        description=(
            "Restate signature-bound metadata a layer already committed to. An "
            "APPEND: the prior entries, your verified identity, the ticket and the "
            "rationale are recorded on the event, the root moves, the layer "
            "re-signs. --before/--after carry only the entries that change, not "
            "the whole map. Use --from to apply many in one run. The admin list "
            "(LAAS_ADMIN_IDENTITIES) is enforced by the REST service, not here: "
            "a local caller controls its own environment."
        ),
    )
    p.add_argument("--layer", help="Target layer ID")
    p.add_argument("--target", choices=TARGETS)
    p.add_argument("--reason", choices=REASONS)
    p.add_argument("--after", help="Replacement entries (a delta): JSON literal or @file")
    p.add_argument("--before", help="The same entries as stored now: JSON literal or @file")
    p.add_argument("--ticket", help="Change record authorising this restatement")
    p.add_argument("--approved-by", dest="approved_by", help="Approver(s), comma-separated")
    p.add_argument("--rationale", help="Why the data was wrong")
    p.add_argument("--finding-ref", dest="finding_ref", help="Scope to one finding")
    p.add_argument("--schema-from", dest="schema_from", help="For --reason schema_migration")
    p.add_argument("--schema-to", dest="schema_to", help="For --reason schema_migration")
    p.add_argument(
        "--from",
        dest="batch",
        help="Bulk file: JSON array of items, each {layer, rationale, target, before, after, …}",
    )
    p.set_defaults(handler=cmd_restate)


__all__ = ["cmd_restate", "register_restate_parser"]

"""Declarative, allowlisted layer-listing filters.

A caller says which keys it wants to filter on; the registry declares where
each key lives — a real storage column (pushed down to SQLAlchemy as a bound
expression) or a field inside a JSON payload (filtered structurally against
decoded documents). Requests only ever *select* from this registry: keys,
operators, and value types are fixed here, and values reach the database as
bound parameters through SQLAlchemy expression objects. No request input is
interpolated into SQL text.

Adding a filterable key is one registry entry; backends and routes need no
further changes.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ColumnFilterDef:
    """Filter resolved against a real ``layers`` table column."""

    column: str
    ops: frozenset[str]
    parse: Callable[[str], Any]


@dataclass(frozen=True)
class JsonItemFilterDef:
    """Filter resolved against a field of each item in a JSON payload."""

    payload: str
    item_field: str
    ops: frozenset[str]
    parse: Callable[[str], Any]


FilterDef = ColumnFilterDef | JsonItemFilterDef


def _parse_datetime(raw: str) -> datetime:
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp filter requires a timezone: {raw!r}")
    return parsed


#: The allowlist. Everything a request may filter on is declared here.
FILTER_REGISTRY: dict[str, FilterDef] = {
    "product_repo_id": ColumnFilterDef("product_repo_id", frozenset({"eq", "in"}), str),
    "layer_id": ColumnFilterDef("layer_id", frozenset({"eq", "in"}), str),
    "merkle_epoch": ColumnFilterDef("merkle_epoch", frozenset({"gte", "lte"}), int),
    "updated_at": ColumnFilterDef("updated_at", frozenset({"gte", "lte"}), _parse_datetime),
    "review_status": JsonItemFilterDef("needs_review", "status", frozenset({"eq", "in"}), str),
    "review_queue_reason": JsonItemFilterDef(
        "needs_review", "queue_reason", frozenset({"eq", "in"}), str
    ),
}

#: Column filters the file backend can evaluate (no table to push down into).
FILE_SUPPORTED_COLUMN_FILTERS = frozenset({"layer_id", "product_repo_id"})


@dataclass(frozen=True)
class Filter:
    key: str
    op: str
    value: Any


@dataclass(frozen=True)
class LayerEntry:
    """One layer in a filtered listing."""

    layer_id: str
    product_repo_id: str | None
    #: Matching queue entries when reviews were requested; None otherwise.
    needs_review: list | None = None


def parse_filter(raw: str) -> Filter:
    """Parse ``key:op:value``. The value keeps any colons (ISO timestamps)."""
    key, separator, rest = raw.partition(":")
    if not separator:
        raise ValueError(f"filter must be key:op:value, got {raw!r}")
    op, separator, value = rest.partition(":")
    if not separator:
        raise ValueError(f"filter must be key:op:value, got {raw!r}")
    definition = FILTER_REGISTRY.get(key)
    if definition is None:
        raise ValueError(f"unknown filter key {key!r}")
    if op not in definition.ops:
        raise ValueError(f"filter {key!r} does not support op {op!r}")
    try:
        if op == "in":
            members = [part for part in value.split(",") if part != ""]
            if not members:
                raise ValueError("in-filter requires at least one value")
            parsed: Any = [definition.parse(part) for part in members]
        else:
            parsed = definition.parse(value)
    except ValueError as exc:
        raise ValueError(f"invalid value for filter {key!r}: {exc}") from exc
    return Filter(key=key, op=op, value=parsed)


def parse_filters(raw: Sequence[str]) -> list[Filter]:
    return [parse_filter(item) for item in raw]


def column_filters(filters: Sequence[Filter]) -> list[Filter]:
    return [f for f in filters if isinstance(FILTER_REGISTRY[f.key], ColumnFilterDef)]


def json_item_filters(filters: Sequence[Filter]) -> list[Filter]:
    return [f for f in filters if isinstance(FILTER_REGISTRY[f.key], JsonItemFilterDef)]


def item_matches(filters: Sequence[Filter], item: Any) -> bool:
    """Apply every JSON-item filter to one payload item."""
    if not isinstance(item, dict):
        return False
    for f in filters:
        definition = FILTER_REGISTRY[f.key]
        assert isinstance(definition, JsonItemFilterDef)
        actual = item.get(definition.item_field)
        if f.op == "eq":
            if actual != f.value:
                return False
        elif f.op == "in":
            if actual not in f.value:
                return False
        else:  # pragma: no cover - registry gates the op set
            raise ValueError(f"unsupported json item op {f.op!r}")
    return True

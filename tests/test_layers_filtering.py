"""GET /v1/ledger/layers declarative filtering.

Filters are 'key:op:value' strings selected from a server-side registry:
column keys push down as bound SQLAlchemy expressions, JSON-item keys filter
structurally against decoded payloads. sci-api's pending-countersign sweep
becomes one call instead of ~8,600 per-item requests.
"""

from __future__ import annotations

from pathlib import Path

from conftest import RECORDED_AT, canonical_shell
from fastapi import FastAPI
from fastapi.testclient import TestClient
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.query import parse_filter, parse_filters
from traust_ledger.config import ServiceConfig
from traust_ledger.constants import ACTOR_KIND_HUMAN
from traust_ledger.service.app import create_app


class _FixedActorVerifier:
    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, request):
        from traust_ledger.service.identity.tokens import extract_bearer_token

        extract_bearer_token(request)
        return self._actor.model_copy()


def _verified_human() -> LayerActor:
    return LayerActor(
        kind=ACTOR_KIND_HUMAN,
        identity="user:test@example.com",
        identity_verified=True,
        identity_provider="oidc",
    )


AUTH = {"Authorization": "Bearer test"}


def _review_item(source_ref: str, status: str, queue_reason: str = "weak_confirmation") -> dict:
    return {
        "queued_at": RECORDED_AT,
        "source_ref": source_ref,
        "quote": "suspect",
        "author": "reporter@example.test",
        "suggested_finding_ref": "FIND-001",
        "queue_reason": queue_reason,
        "status": status,
    }


def _app_with_layers(tmp_path: Path) -> FastAPI:
    config = ServiceConfig(backend_type="file", data_dir=str(tmp_path), signing_required=False)
    app = create_app(config, verifier=_FixedActorVerifier(_verified_human()))
    # layer-a: one pending item; layer-b: pending + rejected; layer-c: empty queue
    app.state.backend.initialize(tmp_path / "layer-a.json", canonical_shell())
    app.state.backend.initialize(tmp_path / "layer-b.json", canonical_shell())
    app.state.backend.initialize(tmp_path / "layer-c.json", canonical_shell())
    app.state.backend.mutate(
        tmp_path / "layer-a.json",
        lambda doc: doc.update({"needs_review": [_review_item("scan-a", "pending")]}),
    )
    app.state.backend.mutate(
        tmp_path / "layer-b.json",
        lambda doc: doc.update(
            {
                "needs_review": [
                    _review_item("scan-b1", "pending"),
                    _review_item("scan-b2", "rejected", queue_reason="needs_manual_test"),
                ]
            }
        ),
    )
    return app


# ── filter parsing (registry gate) ──────────────────────────────────────────


def test_parse_filter_accepts_registry_keys_and_keeps_value_colons() -> None:
    f = parse_filter("updated_at:gte:2026-10-13T16:00:00+00:00")
    assert f.key == "updated_at" and f.op == "gte"
    assert str(f.value) == "2026-10-13 16:00:00+00:00"


def test_parse_filter_rejects_unknown_key_op_and_values() -> None:
    for raw in (
        "no-such-key:eq:x",
        "layer_id:gte:layer-a",
        "merkle_epoch:gte:not-a-number",
        "updated_at:gte:2026-10-13T16:00:00",  # naive timestamp
        "layer_id:in:",
        "not-a-filter",
        "layer_id:eq",
    ):
        try:
            parse_filter(raw)
        except ValueError:
            continue
        raise AssertionError(f"parse_filter({raw!r}) should have raised")


def test_parse_filter_in_op_builds_lists() -> None:
    f = parse_filter("review_status:in:pending,rejected")
    assert f.value == ["pending", "rejected"]


# ── route behavior ──────────────────────────────────────────────────────────


def test_refs_only_listing_shape_is_unchanged(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get("/v1/ledger/layers", headers=AUTH)
    assert resp.status_code == 200
    assert resp.json() == {
        "layers": [
            {"layer_id": "layer-a", "product_repo_id": None},
            {"layer_id": "layer-b", "product_repo_id": None},
            {"layer_id": "layer-c", "product_repo_id": None},
        ]
    }


def test_json_item_filter_selects_layers_and_embeds_matching_items(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get(
        "/v1/ledger/layers", params={"filter": "review_status:eq:pending"}, headers=AUTH
    )
    assert resp.status_code == 200
    layers = resp.json()["layers"]
    assert [layer["layer_id"] for layer in layers] == ["layer-a", "layer-b"]
    assert layers[0]["needs_review"] == [_review_item("scan-a", "pending")]
    assert layers[1]["needs_review"] == [_review_item("scan-b1", "pending")]

    resp = client.get(
        "/v1/ledger/layers", params={"filter": "review_status:in:pending,rejected"}, headers=AUTH
    )
    layers = resp.json()["layers"]
    assert [layer["layer_id"] for layer in layers] == ["layer-a", "layer-b"]
    assert len(layers[1]["needs_review"]) == 2

    # a second json key narrows within the same queue
    resp = client.get(
        "/v1/ledger/layers",
        params={"filter": ["review_queue_reason:eq:needs_manual_test"]},
        headers=AUTH,
    )
    layers = resp.json()["layers"]
    assert [layer["layer_id"] for layer in layers] == ["layer-b"]
    assert layers[0]["needs_review"] == [
        _review_item("scan-b2", "rejected", queue_reason="needs_manual_test")
    ]


def test_column_filters_combine_with_json_filters(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get(
        "/v1/ledger/layers",
        params={"filter": ["layer_id:eq:layer-b", "review_status:eq:pending"]},
        headers=AUTH,
    )
    assert resp.status_code == 200
    layers = resp.json()["layers"]
    assert [layer["layer_id"] for layer in layers] == ["layer-b"]
    assert layers[0]["needs_review"] == [_review_item("scan-b1", "pending")]


def test_injection_shaped_values_are_data_not_sql(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get(
        "/v1/ledger/layers",
        params={"filter": "layer_id:eq:' OR '1'='1"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["layers"] == []  # compared as a literal string, no rows match

    resp = client.get(
        "/v1/ledger/layers",
        params={"filter": "review_status:eq:pending; DROP TABLE layers;--"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["layers"] == []
    # the ledger still works afterwards
    assert client.get("/v1/ledger/layers", headers=AUTH).status_code == 200


def test_unknown_filter_key_is_a_422(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get("/v1/ledger/layers", params={"filter": "evil_key:eq:x"}, headers=AUTH)
    assert resp.status_code == 422
    resp = client.get("/v1/ledger/layers", params={"filter": "layer_id:like:%"}, headers=AUTH)
    assert resp.status_code == 422


def test_include_reviews_embeds_whole_queues_skipping_empty(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get("/v1/ledger/layers", params={"include_reviews": "true"}, headers=AUTH)
    assert resp.status_code == 200
    layers = resp.json()["layers"]
    assert [layer["layer_id"] for layer in layers] == ["layer-a", "layer-b"]
    assert len(layers[1]["needs_review"]) == 2


def test_legacy_product_repo_param_still_404s_on_missing_owner(tmp_path: Path) -> None:
    client = TestClient(_app_with_layers(tmp_path))
    resp = client.get(
        "/v1/ledger/layers",
        params={"product_repo_id": "11111111-1111-1111-1111-111111111111"},
        headers=AUTH,
    )
    assert resp.status_code == 404


# ── db backend ──────────────────────────────────────────────────────────────


def test_query_layers_pushes_columns_and_json_filters_to_db(tmp_path: Path) -> None:
    from sqlalchemy import create_engine
    from storage_db import prepare_storage

    target = f"sqlite:///{tmp_path / 'ledger.db'}"
    owner_a = prepare_storage(target)
    owner_b = prepare_storage(target, product="ledger-tests-b")
    engine = create_engine(target)
    DbBackend.create_tables(engine)
    backend = DbBackend(engine)
    backend.initialize(Path("layer-a"), canonical_shell(), product_repo_id=owner_a)
    backend.initialize(Path("layer-b"), canonical_shell(), product_repo_id=owner_b)
    backend.store(
        Path("layer-a"), {**canonical_shell(), "needs_review": [_review_item("scan-a", "pending")]}
    )
    backend.store(
        Path("layer-b"),
        {
            **canonical_shell(),
            "needs_review": [
                _review_item("scan-b1", "pending"),
                _review_item("scan-b2", "rejected", queue_reason="needs_manual_test"),
            ],
        },
    )

    entries = backend.query_layers(parse_filters([]), include_reviews=False)
    assert [(e.layer_id, e.product_repo_id, e.needs_review) for e in entries] == [
        ("layer-a", owner_a, None),
        ("layer-b", owner_b, None),
    ]

    pending = backend.query_layers(
        parse_filters(["review_status:eq:pending", f"product_repo_id:eq:{owner_b}"]),
        include_reviews=False,
    )
    assert [(e.layer_id, e.needs_review) for e in pending] == [
        ("layer-b", [_review_item("scan-b1", "pending")])
    ]

    everything = backend.query_layers(parse_filters([]), include_reviews=True)
    assert {e.layer_id: len(e.needs_review) for e in everything} == {"layer-a": 1, "layer-b": 2}


def test_file_backend_rejects_filters_it_cannot_evaluate(tmp_path: Path) -> None:
    app = _app_with_layers(tmp_path)
    client = TestClient(app)
    resp = client.get("/v1/ledger/layers", params={"filter": "merkle_epoch:gte:5"}, headers=AUTH)
    assert resp.status_code == 422
    assert "file backend" in resp.json()["detail"]

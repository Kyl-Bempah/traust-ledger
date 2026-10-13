"""Concurrent request safety of the sync-route service.

Routes run as plain `def` handlers in the Starlette threadpool, so requests
that used to be accidentally serialized on the event loop now genuinely
overlap. This test hammers the service with parallel submits and reads on the
same layer and asserts the ledger's integrity invariants: every event lands
exactly once, reads never observe a torn layer, and healthz stays responsive.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from conftest import LAYER_ID, RECORDED_AT, canonical_shell
from fastapi import FastAPI
from fastapi.testclient import TestClient
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.config import ServiceConfig
from traust_ledger.constants import ACTOR_KIND_HUMAN
from traust_ledger.service.app import create_app

AUTH = {"Authorization": "Bearer test"}
WORKERS = 8
SUBMITS_PER_WORKER = 5


class _FixedActorVerifier:
    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, request):
        from traust_ledger.service.identity.tokens import extract_bearer_token

        extract_bearer_token(request)
        return self._actor.model_copy()


def _app(tmp_path: Path) -> FastAPI:
    config = ServiceConfig(backend_type="file", data_dir=str(tmp_path), signing_required=False)
    app = create_app(
        config,
        verifier=_FixedActorVerifier(
            LayerActor(
                kind=ACTOR_KIND_HUMAN,
                identity="user:test@example.com",
                identity_verified=True,
                identity_provider="oidc",
            )
        ),
    )
    app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    return app


def _event(worker: int, seq: int) -> dict:
    return {
        "finding_ref": f"FIND-{worker:02d}-{seq:02d}",
        "disposition": {"validity": "confirmed"},
        "source": {"type": "triage_report", "ref": f"src-{worker}-{seq}", "actor": {}},
        "recorded_at": RECORDED_AT,
        "rationale": "Concurrency probe event with a unique finding reference.",
    }


def test_parallel_submits_and_reads_preserve_integrity(tmp_path: Path) -> None:
    app = _app(tmp_path)
    errors: list[str] = []
    healthz_max = [0.0]

    def worker(worker_id: int) -> None:
        client = TestClient(app)
        try:
            for seq in range(SUBMITS_PER_WORKER):
                resp = client.post(
                    f"/v1/ledger/layers/{LAYER_ID}/submit",
                    json={
                        "source_ref": f"concurrency-{worker_id}-{seq}",
                        "recorded_at": RECORDED_AT,
                        "events": [_event(worker_id, seq)],
                        "needs_review": [],
                    },
                    headers=AUTH,
                )
                if resp.status_code != 200:
                    errors.append(f"submit {worker_id}/{seq}: {resp.status_code} {resp.text[:120]}")
                    return
                layer = client.get(f"/v1/ledger/layers/{LAYER_ID}", headers=AUTH).json()
                if not isinstance(layer.get("events"), list):
                    errors.append(f"read {worker_id}/{seq}: torn layer")
                    return
        except Exception as exc:  # pragma: no cover - failure reporting only
            errors.append(f"worker {worker_id}: {exc!r}")

    def healthz_sampler(stop: threading.Event) -> None:
        client = TestClient(app)
        while not stop.is_set():
            t0 = time.perf_counter()
            resp = client.get("/healthz")
            healthz_max[0] = max(healthz_max[0], time.perf_counter() - t0)
            if resp.status_code != 200:
                errors.append(f"healthz: {resp.status_code}")

    stop = threading.Event()
    sampler = threading.Thread(target=healthz_sampler, args=(stop,))
    sampler.start()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(WORKERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stop.set()
    sampler.join()

    assert not errors, errors[:5]

    layer = TestClient(app).get(f"/v1/ledger/layers/{LAYER_ID}", headers=AUTH).json()
    events = layer["events"]
    refs = [event["finding_ref"] for event in events]
    assert len(refs) == WORKERS * SUBMITS_PER_WORKER, f"lost events: {len(refs)}"
    assert len(set(refs)) == len(refs), "duplicate events — append-only invariant broken"
    # healthz never starved behind the concurrent traffic
    assert healthz_max[0] < 2.0, f"healthz latency {healthz_max[0]:.2f}s under load"

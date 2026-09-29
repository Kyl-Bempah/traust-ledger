from __future__ import annotations

from pydantic import BaseModel


class ServiceConfig(BaseModel):
    """Plain config bag — importable with no optional deps.

    For env-auto-loading (REST service), use ``ServiceSettings`` from
    ``traust_ledger.service.settings`` which inherits this and adds
    ``pydantic_settings.BaseSettings``.
    """

    backend_type: str = "file"
    database_url: str | None = None
    data_dir: str = "/var/lib/laas/data"
    signing_required: bool = False
    signing_key_path: str | None = None
    signing_method: str = "cosign"
    log_level: str = "INFO"

    # ── Service-layer identity (who is calling the API) ──
    identity_provider: str = "oidc"

    #: Identities permitted to append restatement events. Empty by default, and
    #: the gate fails closed on empty: a restatement can move signature-bound
    #: state, so an unconfigured deployment grants that to nobody rather than
    #: to everybody who can already write.
    admin_identities: list[str] = []

    #: Independent approvers a restatement must name in ``authority.approved_by``
    #: (comma-separated), excluding the actor. 0 = the actor's own attribution
    #: is the authority. Per-deployment: the right threshold depends on whether
    #: your admin set is two people or twenty.
    restatement_min_approvers: int = 0

    # OIDC token validation (guards API access)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_machine_claim: str = "azp"
    oidc_identity_claim: str = "email"

    # Multiple trusted OIDC issuers — JSON array of objects.
    oidc_trust: str = ""

    # ── Ledger signing (sigstore-oidc, separate from API auth) ──
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None

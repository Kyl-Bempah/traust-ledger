"""FastAPI auth dependencies — thin wiring layer.

All identity logic lives in ``traust_ledger.service.identity``.
This module provides the FastAPI ``Depends`` callables that delegate
to the ``ActorResolver`` on ``app.state``.
"""

from __future__ import annotations

from fastapi import Request
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.gates import require_admin, require_restatement_approvers
from traust_ledger.config import ServiceConfig


async def resolve_actor(request: Request) -> LayerActor:
    """Resolve request identity via the app's ActorResolver."""
    resolver = request.app.state.resolver
    return resolver.resolve(request)


async def require_identity(request: Request) -> None:
    """Gate: verify identity is valid but don't inject the actor."""
    resolver = request.app.state.resolver
    resolver.resolve(request)


def authorize_restatement(actor: LayerActor, block: dict, config: ServiceConfig) -> None:
    """Who may restate — enforced here, at the service boundary.

    The admin list and approver threshold are deployment settings the operator
    owns and the caller cannot change, which is what makes them authorization.
    The shared handler keeps only the integrity rules, so CLI and SDK callers
    (who own their own environment) are not handed a self-grantable check.
    """
    require_admin(actor, config.admin_identities)
    require_restatement_approvers(block, actor, config.restatement_min_approvers)

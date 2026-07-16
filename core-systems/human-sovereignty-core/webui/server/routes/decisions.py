# human-sovereignty-core/webui/server/routes/decisions.py
# Read-only WebUI routes for decision packets.
# Contract: LIST / GET only. No mutation, no approval, no execution.
# Python 3.11+ recommended.

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

# FastAPI is treated as an infrastructure dependency of WebUI.
# This file only defines routes and contracts.
try:
    from fastapi import APIRouter, Depends, HTTPException, Query, status  # type: ignore
except Exception as _e:  # pragma: no cover
    raise ImportError("decisions.py requires fastapi to be installed") from _e


router = APIRouter(
    prefix="/decisions",
    tags=["decisions"],
)


class DecisionAccessError(RuntimeError):
    """Base error for decision access."""


class DecisionNotFoundError(DecisionAccessError):
    """Raised when decision packet is not found."""


def _require_scope(required: str):
    """
    Dependency stub for RBAC scope enforcement.

    The actual implementation is expected to be provided
    by the WebUI auth layer.
    """

    def _dep() -> None:
        # This function is intentionally empty.
        # Real scope validation must be injected at runtime.
        return None

    return _dep


class DecisionReadRepository:
    """
    Abstract read-only repository for decision packets.

    Infrastructure layer must provide a concrete implementation
    via dependency injection.
    """

    def list(
        self,
        *,
        limit: int,
        offset: int,
        state: Optional[str],
    ) -> List[Mapping[str, Any]]:
        raise NotImplementedError

    def get(self, decision_id: str) -> Mapping[str, Any]:
        raise NotImplementedError


def get_decision_repo() -> DecisionReadRepository:
    """
    Dependency provider for decision repository.

    Must be overridden by the WebUI application container.
    """
    raise RuntimeError("DecisionReadRepository is not configured")


def _serialize_decision(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Safe serializer for decision packets.

    Filters out any internal or sensitive fields.
    """
    return {
        "decision_id": raw.get("decision_id"),
        "state": raw.get("state"),
        "created_at": _iso(raw.get("created_at")),
        "updated_at": _iso(raw.get("updated_at")),
        "summary": raw.get("summary"),
        "risk_level": raw.get("risk_level"),
    }


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return None


@router.get(
    "",
    summary="List decision packets",
    dependencies=[Depends(_require_scope("decisions:read"))],
)
def list_decisions(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    state: Optional[str] = Query(None),
    repo: DecisionReadRepository = Depends(get_decision_repo),
) -> Dict[str, Any]:
    """
    Returns a paginated list of decision packets.

    Read-only.
    """
    try:
        rows = repo.list(limit=limit, offset=offset, state=state)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e

    return {
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "items": [_serialize_decision(r) for r in rows],
    }


@router.get(
    "/{decision_id}",
    summary="Get decision packet by id",
    dependencies=[Depends(_require_scope("decisions:read"))],
)
def get_decision(
    decision_id: str,
    repo: DecisionReadRepository = Depends(get_decision_repo),
) -> Dict[str, Any]:
    """
    Returns a single decision packet.

    Read-only.
    """
    try:
        raw = repo.get(decision_id)
    except DecisionNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Decision not found",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e

    return _serialize_decision(raw)

from fastapi import APIRouter
from src.db import database

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.get("/ready")
async def readiness():
    # Simple readiness: check DB connection
    try:
        if not getattr(database, "is_connected", False):
            await database.connect()
            await database.disconnect()
        return {"status": "ready"}
    except Exception:
        return {"status": "not ready"}


@router.get("/security/status")
async def security_status():
    # Minimal compatibility endpoint for frontend widgets
    # Returns an object matching SecurityStatusData in the frontend
    from datetime import datetime
    from src.models import security_incidents
    import logging
    logger = logging.getLogger("security_status")
    incidents = []
    try:
        # fetch incidents from the database; if DB unavailable return empty list
        if not getattr(database, "is_connected", False):
            await database.connect()

        rows = await database.fetch_all(
            security_incidents.select().order_by(security_incidents.c.created_at.desc()).limit(10)
        )
        for r in rows:
            rec = dict(r)
            created_at = rec.get("created_at")
            incidents.append(
                {
                    "id": str(rec.get("id")),
                    "title": rec.get("title"),
                    "severity": rec.get("severity"),
                    "ts": created_at.isoformat() if created_at is not None else None,
                }
            )
    except Exception as exc:
        logger.exception("failed to fetch security incidents: %s", exc)
        incidents = []

    return {
        "id": "security",
        "overall": "ok" if not incidents else "degraded",
        "incidents": incidents,
        "lastChecked": datetime.utcnow().isoformat() + "Z",
    }

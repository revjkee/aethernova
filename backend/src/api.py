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
    try:
        # fetch incidents from the database; if DB unavailable return empty list
        if not getattr(database, "is_connected", False):
            await database.connect()

        rows = await database.fetch_all(security_incidents.select().order_by(security_incidents.c.created_at.desc()).limit(10))
        incidents = [
            {"id": str(r["id"]), "title": r["title"], "severity": r.get("severity"), "ts": r.get("created_at").isoformat() if r.get("created_at") is not None else None}
            for r in rows
        ]
    except Exception:
        incidents = []

    return {
        "id": "security",
        "overall": "ok" if not incidents else "degraded",
        "incidents": incidents,
        "lastChecked": datetime.utcnow().isoformat() + "Z",
    }

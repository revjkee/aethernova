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

import asyncio
import json

import pytest
from httpx import AsyncClient

from src.main import app


@pytest.mark.asyncio
async def test_security_status_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        r = await ac.get("/api/v1/security/status")
        assert r.status_code == 200
        data = r.json()
        assert "id" in data
        assert "incidents" in data

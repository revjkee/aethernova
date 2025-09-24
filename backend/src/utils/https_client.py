import aiohttp
import asyncio
from typing import Optional, Dict, Any

class AsyncHttpClient:
    def __init__(self, base_url: Optional[str] = None, timeout: int = 10):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def request(
        self, method: str, url: str, params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        if not self.session:
            raise RuntimeError("HTTP session not initialized. Use async context manager.")

        full_url = f"{self.base_url}{url}"
        async with self.session.request(method=method, url=full_url, params=params, json=json, headers=headers) as resp:
            resp.raise_for_status()
            try:
                return await resp.json()
            except aiohttp.ContentTypeError:
                return {"text": await resp.text()}

    async def get(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        return await self.request("GET", url, params=params, headers=headers)

    async def post(self, url: str, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        return await self.request("POST", url, json=json, headers=headers)

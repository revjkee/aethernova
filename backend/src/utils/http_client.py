from src.utils.https_client import AsyncHttpClient as HttpClient

# Provide a simple sync facade expected by older tests
class HttpClientFacade:
    def __init__(self, *args, **kwargs):
        self._client = HttpClient(*args, **kwargs)

    async def get(self, url, **kwargs):
        async with self._client as c:
            return await c.get(url, **kwargs)

    async def post(self, url, json=None, **kwargs):
        async with self._client as c:
            return await c.post(url, json=json, **kwargs)


# Export names for compatibility
HttpClient = HttpClientFacade

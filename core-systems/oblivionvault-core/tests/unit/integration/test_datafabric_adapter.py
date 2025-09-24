# file: tests/integration/test_datafabric_adapter.py
import os
import sys
import json
import time
import socket
import hashlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

import pytest

# ---------- Optional import of the adapter under test ----------
# Expected (but not required) location:
#   oblivionvault/adapters/datafabric_adapter.py
# with class AsyncDataFabricAdapter(base_url: str, api_key: str | None = None, **kwargs)
# and async methods: health(), ensure_bucket(name), put_object(bucket, key, data|async-iter, size=None, content_type=None, sha256=None),
# get_object(bucket, key) -> bytes, list_objects(bucket, prefix="")->list[str], delete_object(bucket,key)->bool
try:
    from oblivionvault.adapters.datafabric_adapter import AsyncDataFabricAdapter  # type: ignore
    _HAS_ADAPTER = True
except Exception:
    _HAS_ADAPTER = False


# =========================
# In-memory DataFabric stub
# =========================

class _MemStore:
    def __init__(self):
        self.buckets = set()
        # objects[(bucket, key)] = dict(bytes=b"...", etag="sha256:...", content_type="...", mtime=float)
        self.objects = {}

    def ensure_bucket(self, name: str):
        self.buckets.add(name)

    def put(self, bucket: str, key: str, data: bytes, content_type: str | None):
        if bucket not in self.buckets:
            self.ensure_bucket(bucket)
        sha = hashlib.sha256(data).hexdigest()
        self.objects[(bucket, key)] = {
            "bytes": data,
            "etag": f"sha256:{sha}",
            "content_type": content_type or "application/octet-stream",
            "mtime": time.time(),
            "size": len(data),
        }

    def get(self, bucket: str, key: str):
        return self.objects[(bucket, key)]

    def exists(self, bucket: str, key: str) -> bool:
        return (bucket, key) in self.objects

    def delete(self, bucket: str, key: str) -> bool:
        return self.objects.pop((bucket, key), None) is not None

    def list(self, bucket: str, prefix: str = ""):
        out = []
        for (b, k), meta in self.objects.items():
            if b == bucket and k.startswith(prefix):
                out.append({"key": k, "size": meta["size"], "etag": meta["etag"]})
        return out


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _decode_path_parts(path: str):
    # Expected paths:
    #   /health
    #   /buckets/{bucket}
    #   /objects/{bucket}/{key...}
    parts = [unquote(p) for p in path.split("/") if p]
    return parts


class _StubHandler(BaseHTTPRequestHandler):
    store: _MemStore = _MemStore()
    api_key_env: str | None = None  # if set, require header Authorization: Bearer <key>

    server_version = "DataFabricStub/1.0"
    sys_version = ""

    def _auth_ok(self) -> bool:
        if not self.api_key_env:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {self.api_key_env}"

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def log_message(self, fmt, *args):
        # Keep stdout clean for pytest; write to stderr quietly
        sys.stderr.write("STUB " + (fmt % args) + "\n")

    def do_GET(self):
        if not self._auth_ok():
            self.send_response(401); self.end_headers(); return

        parts = _decode_path_parts(urlparse(self.path).path)
        if parts == ["health"]:
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}'); return

        if len(parts) >= 2 and parts[0] == "objects":
            bucket = parts[1]
            if len(parts) == 2:
                # list with ?prefix=
                qs = parse_qs(urlparse(self.path).query or "")
                prefix = (qs.get("prefix") or [""])[0]
                items = self.store.list(bucket, prefix)
                body = json.dumps({"items": items}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            key = "/".join(parts[2:])
            if not self.store.exists(bucket, key):
                self.send_response(404); self.end_headers(); return
            meta = self.store.get(bucket, key)
            body = meta["bytes"]
            self.send_response(200)
            self.send_header("Content-Type", meta["content_type"])
            self.send_header("ETag", meta["etag"])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404); self.end_headers()

    def do_HEAD(self):
        if not self._auth_ok():
            self.send_response(401); self.end_headers(); return
        parts = _decode_path_parts(urlparse(self.path).path)
        if parts == ["health"]:
            self.send_response(200); self.end_headers(); return
        self.send_response(404); self.end_headers()

    def do_PUT(self):
        if not self._auth_ok():
            self.send_response(401); self.end_headers(); return
        parts = _decode_path_parts(urlparse(self.path).path)

        if len(parts) == 2 and parts[0] == "buckets":
            self.store.ensure_bucket(parts[1])
            self.send_response(204); self.end_headers(); return

        if len(parts) >= 3 and parts[0] == "objects":
            bucket = parts[1]
            key = "/".join(parts[2:])
            data = self._read_body()
            self.store.put(bucket, key, data, self.headers.get("Content-Type"))
            self.send_response(201)
            self.send_header("ETag", self.store.get(bucket, key)["etag"])
            self.end_headers()
            return

        self.send_response(404); self.end_headers()

    def do_DELETE(self):
        if not self._auth_ok():
            self.send_response(401); self.end_headers(); return
        parts = _decode_path_parts(urlparse(self.path).path)
        if len(parts) >= 3 and parts[0] == "objects":
            bucket = parts[1]
            key = "/".join(parts[2:])
            ok = self.store.delete(bucket, key)
            self.send_response(204 if ok else 404)
            self.end_headers()
            return
        self.send_response(404); self.end_headers()


@pytest.fixture(scope="session")
def datafabric_stub_server():
    """
    Start a lightweight stub server for tests if no external DATAFABRIC_BASE_URL is provided.
    """
    base_url = os.getenv("DATAFABRIC_BASE_URL")
    api_key = os.getenv("DATAFABRIC_API_KEY")
    if base_url:
        # Use external deployment
        yield {"base_url": base_url.rstrip("/"), "api_key": api_key}
        return

    port = _find_free_port()
    addr = ("127.0.0.1", port)
    httpd = HTTPServer(addr, _StubHandler)
    _StubHandler.api_key_env = api_key
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    yield {"base_url": f"http://{addr[0]}:{addr[1]}", "api_key": api_key}
    httpd.shutdown()
    th.join(timeout=3)


@pytest.fixture(scope="session")
def event_loop():
    # Make pytest-asyncio happy with session-scoped loop
    loop = pytest.importorskip("asyncio").new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def adapter(datafabric_stub_server):
    if not _HAS_ADAPTER:
        pytest.skip("AsyncDataFabricAdapter not found; integration tests skipped.")
    base = datafabric_stub_server["base_url"]
    key = datafabric_stub_server["api_key"]
    # Adapter is expected to accept base_url and optional api_key
    return AsyncDataFabricAdapter(base_url=base, api_key=key)  # type: ignore


# =========================
# Utility helpers for tests
# =========================

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _rand_bytes(n: int) -> bytes:
    import os as _os
    return _os.urandom(n)


# =========================
# Integration test cases
# =========================

@pytest.mark.asyncio
async def test_health(adapter):
    ok = await adapter.health()
    assert ok is True


@pytest.mark.asyncio
async def test_put_get_roundtrip(adapter):
    bucket = "itg-bucket"
    key = "folder/test-object.bin"
    payload = b"hello-datafabric"
    await adapter.ensure_bucket(bucket)
    await adapter.put_object(bucket, key, payload, size=len(payload), content_type="application/octet-stream", sha256=_sha256(payload))
    data = await adapter.get_object(bucket, key)
    assert data == payload


@pytest.mark.asyncio
async def test_list_with_prefix(adapter):
    bucket = "itg-list"
    await adapter.ensure_bucket(bucket)
    objs = {
        "logs/2025-08-26/app.log": b"l1",
        "logs/2025-08-26/app.1.log": b"l2",
        "images/logo.png": b"\x89PNG",
    }
    for k, v in objs.items():
        await adapter.put_object(bucket, k, v, size=len(v), content_type="application/octet-stream", sha256=_sha256(v))
    lst = await adapter.list_objects(bucket, prefix="logs/2025-08-26/")
    keys = {item["key"] if isinstance(item, dict) else item for item in lst}
    assert "logs/2025-08-26/app.log" in keys
    assert "logs/2025-08-26/app.1.log" in keys
    assert "images/logo.png" not in keys


@pytest.mark.asyncio
async def test_delete_and_missing(adapter):
    bucket = "itg-del"
    key = "to-delete.txt"
    await adapter.ensure_bucket(bucket)
    await adapter.put_object(bucket, key, b"X", size=1, content_type="text/plain", sha256=_sha256(b"X"))
    ok = await adapter.delete_object(bucket, key)
    assert ok is True
    with pytest.raises(Exception):
        await adapter.get_object(bucket, key)


@pytest.mark.asyncio
async def test_idempotent_overwrite_checksum(adapter):
    bucket = "itg-overwrite"
    key = "obj.bin"
    await adapter.ensure_bucket(bucket)
    data1 = b"A" * 1024
    data2 = b"B" * 1024
    # First upload
    await adapter.put_object(bucket, key, data1, size=len(data1), content_type="application/octet-stream", sha256=_sha256(data1))
    # Overwrite with new content and sha
    await adapter.put_object(bucket, key, data2, size=len(data2), content_type="application/octet-stream", sha256=_sha256(data2))
    got = await adapter.get_object(bucket, key)
    assert got == data2


@pytest.mark.asyncio
async def test_large_streaming_upload(adapter):
    bucket = "itg-large"
    key = "large.dat"
    size = 3 * 1024 * 1024 + 137  # > 3 MiB
    data = _rand_bytes(size)

    async def gen():
        # Async chunk generator to verify streaming path
        mv = memoryview(data)
        step = 256 * 1024
        for i in range(0, len(mv), step):
            yield bytes(mv[i:i+step])

    await adapter.ensure_bucket(bucket)
    await adapter.put_object(bucket, key, gen(), size=size, content_type="application/octet-stream", sha256=_sha256(data))
    got = await adapter.get_object(bucket, key)
    assert _sha256(got) == _sha256(data)
    assert len(got) == size


@pytest.mark.asyncio
async def test_concurrent_puts(adapter):
    bucket = "itg-concurrent"
    await adapter.ensure_bucket(bucket)
    items = [(f"k/{i}.bin", _rand_bytes(50_000)) for i in range(8)]

    async def upload_one(k, v):
        await adapter.put_object(bucket, k, v, size=len(v), content_type="application/octet-stream", sha256=_sha256(v))

    import asyncio
    await asyncio.gather(*(upload_one(k, v) for k, v in items))

    lst = await adapter.list_objects(bucket, prefix="k/")
    keys = {item["key"] if isinstance(item, dict) else item for item in lst}
    assert all(k in keys for k, _ in items)

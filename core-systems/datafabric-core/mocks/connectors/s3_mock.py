# datafabric-core/mocks/connectors/s3_mock.py
# Industrial S3 mock client for local/in-memory testing.
# - Compatible subset of boto3 S3 client methods:
#   create_bucket, list_buckets, put_object, get_object, head_object,
#   delete_object, delete_objects, upload_fileobj, download_fileobj,
#   copy_object, list_objects_v2 (+ paginator), generate_presigned_url,
#   multipart: create_multipart_upload, upload_part, complete_multipart_upload, abort_multipart_upload
# - Storage models: filesystem-backed (default) or in-memory
# - Atomic writes, thread-safety, optional eventual consistency, chaos (failures/latency)
# - Deterministic mode for reproducible tests
# No external dependencies.

from __future__ import annotations

import io
import json
import os
import random
import shutil
import string
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# =========================
# Exceptions (shape-compatible)
# =========================
class BotoCoreError(Exception):
    pass

class ClientError(Exception):
    def __init__(self, error_response: Dict[str, Any], operation_name: str):
        super().__init__(f"{operation_name} failed: {error_response}")
        self.response = error_response
        self.operation_name = operation_name

def _client_error(code: str, msg: str, op: str, http_status: int = 400) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": msg},
            "ResponseMetadata": {"HTTPStatusCode": http_status},
        },
        op,
    )

# =========================
# Configuration & Chaos
# =========================
@dataclass
class MockChaos:
    latency_ms: int = 0
    fail_ratio: float = 0.0
    fail_codes: Tuple[str, ...] = ("InternalError",)
    seed: Optional[int] = None

    def __post_init__(self):
        if self.seed is not None:
            random.seed(self.seed)

    def maybe_sleep(self) -> None:
        if self.latency_ms > 0:
            time.sleep(self.latency_ms / 1000.0)

    def maybe_fail(self, op: str) -> None:
        if self.fail_ratio <= 0:
            return
        if random.random() < self.fail_ratio:
            code = random.choice(self.fail_codes) if self.fail_codes else "InternalError"
            raise _client_error(code, f"Injected failure in {op}", op, 500)

@dataclass
class MockConfig:
    root_dir: Optional[Path] = None         # filesystem root; if None -> in-memory
    page_size: int = 1000                   # default max keys per page
    eventual_consistency: bool = False      # if True, list may lag writes
    consistency_lag_ms: int = 0             # simulated lag window
    deterministic: bool = True              # use deterministic UUIDs/etags
    chaos: MockChaos = field(default_factory=MockChaos)

# =========================
# Helpers
# =========================
def _now_ts() -> float:
    return time.time()

def _rand_suffix(n: int = 8, deterministic: bool = False) -> str:
    if deterministic:
        return "0" * n
    alpha = string.ascii_lowercase + string.digits
    return "".join(random.choice(alpha) for _ in range(n))

def _etag_for_bytes(data: bytes, deterministic: bool = False) -> str:
    if deterministic:
        # Stable fake ETag (fixed) to keep tests predictable
        return '"00000000000000000000000000000000"'
    import hashlib
    return '"' + hashlib.md5(data).hexdigest() + '"'  # noqa: S324 (test-only mock)

def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp-" + _rand_suffix(6))
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def _read_all(stream: io.BufferedReader, chunk: int = 1024 * 1024) -> bytes:
    buf = bytearray()
    for b in iter(lambda: stream.read(chunk), b""):
        buf.extend(b)
    return bytes(buf)

# =========================
# Storage engines
# =========================
class _MemoryStore:
    def __init__(self):
        # buckets -> key -> (bytes, meta)
        self._data: Dict[str, Dict[str, Tuple[bytes, Dict[str, Any]]]] = {}
        self._bmeta: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create_bucket(self, name: str) -> None:
        with self._lock:
            self._data.setdefault(name, {})
            self._bmeta.setdefault(name, {"CreationDate": _now_ts()})

    def list_buckets(self) -> List[Tuple[str, float]]:
        with self._lock:
            return [(b, m["CreationDate"]) for b, m in self._bmeta.items()]

    def put(self, bucket: str, key: str, data: bytes, meta: Dict[str, Any]) -> None:
        with self._lock:
            if bucket not in self._data:
                raise _client_error("NoSuchBucket", f"Bucket {bucket} not found", "PutObject", 404)
            self._data[bucket][key] = (data, meta)

    def get(self, bucket: str, key: str) -> Tuple[bytes, Dict[str, Any]]:
        with self._lock:
            try:
                return self._data[bucket][key]
            except KeyError:
                raise _client_error("NoSuchKey", f"Key {key} not found", "GetObject", 404)

    def delete(self, bucket: str, key: str) -> bool:
        with self._lock:
            if bucket not in self._data:
                return False
            return self._data[bucket].pop(key, None) is not None

    def iter_prefix(self, bucket: str, prefix: str) -> Iterator[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            if bucket not in self._data:
                return iter(())
            for k, (_, meta) in self._data[bucket].items():
                if k.startswith(prefix):
                    yield k, meta

class _FSStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _bdir(self, bucket: str) -> Path:
        return self.root / bucket

    def create_bucket(self, name: str) -> None:
        with self._lock:
            (self.root / name / ".bucket").mkdir(parents=True, exist_ok=True)
            (self.root / name / ".meta.json").write_text(json.dumps({"CreationDate": _now_ts()}))

    def list_buckets(self) -> List[Tuple[str, float]]:
        with self._lock:
            out = []
            for p in self.root.iterdir():
                if p.is_dir():
                    meta = p / ".meta.json"
                    if meta.exists():
                        try:
                            cd = json.loads(meta.read_text()).get("CreationDate", _now_ts())
                        except Exception:
                            cd = _now_ts()
                        out.append((p.name, cd))
            return out

    def put(self, bucket: str, key: str, data: bytes, meta: Dict[str, Any]) -> None:
        with self._lock:
            bdir = self._bdir(bucket)
            if not bdir.exists():
                raise _client_error("NoSuchBucket", f"Bucket {bucket} not found", "PutObject", 404)
            kpath = bdir / key
            _atomic_write(kpath, data)
            _atomic_write(kpath.with_suffix(kpath.suffix + ".meta.json"), json.dumps(meta).encode("utf-8"))

    def get(self, bucket: str, key: str) -> Tuple[bytes, Dict[str, Any]]:
        with self._lock:
            bdir = self._bdir(bucket)
            kpath = bdir / key
            if not kpath.exists():
                raise _client_error("NoSuchKey", f"Key {key} not found", "GetObject", 404)
            data = kpath.read_bytes()
            mpath = kpath.with_suffix(kpath.suffix + ".meta.json")
            meta = json.loads(mpath.read_text()) if mpath.exists() else {}
            return data, meta

    def delete(self, bucket: str, key: str) -> bool:
        with self._lock:
            bdir = self._bdir(bucket)
            kpath = bdir / key
            mpath = kpath.with_suffix(kpath.suffix + ".meta.json")
            if not kpath.exists():
                return False
            kpath.unlink(missing_ok=True)  # py>=3.8 ok to pass missing_ok
            mpath.unlink(missing_ok=True)
            return True

    def iter_prefix(self, bucket: str, prefix: str) -> Iterator[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            bdir = self._bdir(bucket)
            if not bdir.exists():
                return iter(())
            # Traverse file tree; keys are relative paths with '/'
            for p in bdir.rglob("*"):
                if not p.is_file():
                    continue
                # skip .meta.json
                if p.name.endswith(".meta.json"):
                    continue
                key = str(p.relative_to(bdir)).replace(os.sep, "/")
                if key.startswith(prefix):
                    mpath = p.with_suffix(p.suffix + ".meta.json")
                    meta = json.loads(mpath.read_text()) if mpath.exists() else {}
                    yield key, meta

# =========================
# Paginator
# =========================
class S3MockPaginator:
    def __init__(self, client: "S3MockClient", op_name: str):
        self.client = client
        self.op_name = op_name

    def paginate(self, **kwargs) -> Iterator[Dict[str, Any]]:
        if self.op_name != "list_objects_v2":
            raise NotImplementedError("Only list_objects_v2 is implemented for paginator")
        token = None
        while True:
            page = self.client.list_objects_v2(ContinuationToken=token, **kwargs)
            yield page
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")

# =========================
# Main client
# =========================
class S3MockClient:
    def __init__(self, config: Optional[MockConfig] = None):
        self.cfg = config or MockConfig(root_dir=Path(os.getenv("S3MOCK_ROOT", "./.s3mock")))
        self._lock = threading.RLock()
        self._multipart: Dict[str, Dict[str, Any]] = {}  # upload_id -> state
        if self.cfg.root_dir is None:
            self._store = _MemoryStore()
        else:
            self._store = _FSStore(self.cfg.root_dir)

    # ---- utilities ----
    def _maybe_consistency_delay(self):
        if self.cfg.eventual_consistency and self.cfg.consistency_lag_ms > 0:
            time.sleep(self.cfg.consistency_lag_ms / 1000.0)

    def get_paginator(self, op_name: str) -> S3MockPaginator:
        return S3MockPaginator(self, op_name)

    # ---- bucket ops ----
    def create_bucket(self, *, Bucket: str, **_) -> Dict[str, Any]:
        op = "CreateBucket"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        with self._lock:
            self._store.create_bucket(Bucket)
            return {"Location": f"/{Bucket}", "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_buckets(self) -> Dict[str, Any]:
        op = "ListBuckets"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        buckets = [{"Name": b, "CreationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cd))}
                   for b, cd in self._store.list_buckets()]
        return {"Buckets": buckets, "Owner": {"ID": "mock"}, "ResponseMetadata": {"HTTPStatusCode": 200}}

    # ---- object ops ----
    def put_object(self, *, Bucket: str, Key: str, Body: Any, **kwargs) -> Dict[str, Any]:
        op = "PutObject"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        if isinstance(Body, (bytes, bytearray)):
            data = bytes(Body)
        elif hasattr(Body, "read"):
            data = _read_all(Body)  # type: ignore
        else:
            data = str(Body).encode("utf-8")
        meta = {
            "ContentLength": len(data),
            "ContentType": kwargs.get("ContentType"),
            "Metadata": kwargs.get("Metadata") or {},
            "LastModified": _now_ts(),
            "ETag": _etag_for_bytes(data, self.cfg.deterministic),
        }
        self._store.put(Bucket, Key, data, meta)
        return {"ETag": meta["ETag"], "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_object(self, *, Bucket: str, Key: str, **_) -> Dict[str, Any]:
        op = "GetObject"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        data, meta = self._store.get(Bucket, Key)
        self._maybe_consistency_delay()
        return {
            "Body": io.BytesIO(data),
            "ContentLength": meta.get("ContentLength", len(data)),
            "ContentType": meta.get("ContentType", None),
            "ETag": meta.get("ETag"),
            "LastModified": time.gmtime(meta.get("LastModified", _now_ts())),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def head_object(self, *, Bucket: str, Key: str, **_) -> Dict[str, Any]:
        op = "HeadObject"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        _, meta = self._store.get(Bucket, Key)
        return {
            "ContentLength": meta.get("ContentLength"),
            "ContentType": meta.get("ContentType"),
            "ETag": meta.get("ETag"),
            "LastModified": time.gmtime(meta.get("LastModified", _now_ts())),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def delete_object(self, *, Bucket: str, Key: str, **_) -> Dict[str, Any]:
        op = "DeleteObject"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        ok = self._store.delete(Bucket, Key)
        return {"DeleteMarker": ok, "ResponseMetadata": {"HTTPStatusCode": 204 if ok else 404}}

    def delete_objects(self, *, Bucket: str, Delete: Dict[str, Any], **_) -> Dict[str, Any]:
        op = "DeleteObjects"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        deleted = []
        errors = []
        for obj in Delete.get("Objects", []):
            key = obj.get("Key")
            if self._store.delete(Bucket, key):
                deleted.append({"Key": key})
            else:
                errors.append({"Key": key, "Code": "NoSuchKey", "Message": "Not Found"})
        return {"Deleted": deleted, "Errors": errors, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def copy_object(self, *, Bucket: str, Key: str, CopySource: Dict[str, str] | str, **kwargs) -> Dict[str, Any]:
        op = "CopyObject"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        if isinstance(CopySource, str):
            # format "src-bucket/src/key"
            parts = CopySource.split("/", 1)
            if len(parts) != 2:
                raise _client_error("InvalidRequest", "Bad CopySource", op)
            sb, sk = parts[0], parts[1]
        else:
            sb, sk = CopySource.get("Bucket"), CopySource.get("Key")
        data, meta = self._store.get(sb, sk)
        meta = dict(meta)
        if kwargs.get("MetadataDirective") == "REPLACE":
            meta["Metadata"] = kwargs.get("Metadata") or {}
            if "ContentType" in kwargs:
                meta["ContentType"] = kwargs["ContentType"]
        self._store.put(Bucket, Key, data, meta)
        return {"CopyObjectResult": {"ETag": meta.get("ETag")}, "ResponseMetadata": {"HTTPStatusCode": 200}}

    # ---- fileobj convenience ----
    def upload_fileobj(self, Fileobj: Any, Bucket: str, Key: str, ExtraArgs: Optional[Dict[str, Any]] = None, Callback: Any = None, Config: Any = None) -> None:
        data = _read_all(Fileobj)
        if Callback:
            Callback(len(data))
        self.put_object(Bucket=Bucket, Key=Key, Body=data, **(ExtraArgs or {}))

    def download_fileobj(self, Bucket: str, Key: str, Fileobj: Any, Callback: Any = None, Config: Any = None) -> None:
        obj = self.get_object(Bucket=Bucket, Key=Key)
        buf = obj["Body"].read()
        if Callback:
            Callback(len(buf))
        Fileobj.write(buf)

    # ---- list with pagination ----
    def list_objects_v2(self, *, Bucket: str, Prefix: str = "", ContinuationToken: Optional[str] = None,
                        MaxKeys: Optional[int] = None, **_) -> Dict[str, Any]:
        op = "ListObjectsV2"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        page = MaxKeys or self.cfg.page_size
        # emulate lag
        self._maybe_consistency_delay()
        items = list(self._store.iter_prefix(Bucket, Prefix))
        # deterministic sort
        items.sort(key=lambda kv: kv[0])
        start = 0
        if ContinuationToken:
            try:
                start = int(ContinuationToken)
            except ValueError:
                start = 0
        slice_items = items[start:start + page]
        contents = []
        for key, meta in slice_items:
            contents.append({
                "Key": key,
                "Size": meta.get("ContentLength", 0),
                "ETag": meta.get("ETag"),
                "LastModified": time.gmtime(meta.get("LastModified", _now_ts())),
                "StorageClass": "STANDARD",
            })
        end = start + len(slice_items)
        is_trunc = end < len(items)
        out = {
            "Name": Bucket,
            "Prefix": Prefix,
            "KeyCount": len(slice_items),
            "MaxKeys": page,
            "IsTruncated": is_trunc,
            "Contents": contents,
        }
        if is_trunc:
            out["NextContinuationToken"] = str(end)
        return out

    # ---- presign (mock) ----
    def generate_presigned_url(self, ClientMethod: str, Params: Dict[str, Any], ExpiresIn: int = 3600, HttpMethod: Optional[str] = None) -> str:
        # Non-cryptographic mock: stable URL for tests
        bucket = Params.get("Bucket")
        key = Params.get("Key")
        return f"https://s3.mock/{bucket}/{key}?method={ClientMethod}&exp={ExpiresIn}"

    # ---- multipart ----
    def create_multipart_upload(self, *, Bucket: str, Key: str, **_) -> Dict[str, Any]:
        op = "CreateMultipartUpload"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        upload_id = f"upload-{_rand_suffix(12, self.cfg.deterministic)}"
        with self._lock:
            self._multipart[upload_id] = {"Bucket": Bucket, "Key": Key, "Parts": {}, "Started": _now_ts()}
        return {"Bucket": Bucket, "Key": Key, "UploadId": upload_id, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def upload_part(self, *, Bucket: str, Key: str, PartNumber: int, UploadId: str, Body: Any, **_) -> Dict[str, Any]:
        op = "UploadPart"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        if isinstance(Body, (bytes, bytearray)):
            data = bytes(Body)
        elif hasattr(Body, "read"):
            data = _read_all(Body)  # type: ignore
        else:
            data = str(Body).encode("utf-8")
        with self._lock:
            st = self._multipart.get(UploadId)
            if not st or st["Bucket"] != Bucket or st["Key"] != Key:
                raise _client_error("NoSuchUpload", "Upload not found", op, 404)
            etag = _etag_for_bytes(data, self.cfg.deterministic)
            st["Parts"][int(PartNumber)] = {"ETag": etag, "Data": data}
            return {"ETag": etag, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def complete_multipart_upload(self, *, Bucket: str, Key: str, UploadId: str, MultipartUpload: Dict[str, Any], **_) -> Dict[str, Any]:
        op = "CompleteMultipartUpload"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        with self._lock:
            st = self._multipart.pop(UploadId, None)
            if not st:
                raise _client_error("NoSuchUpload", "Upload not found", op, 404)
            # Concatenate parts in order of PartNumber from request
            parts_req = MultipartUpload.get("Parts", [])
            ordered = []
            for p in parts_req:
                pn = int(p["PartNumber"])
                part = st["Parts"].get(pn)
                if not part or part["ETag"] != p.get("ETag"):
                    raise _client_error("InvalidPart", f"Part {pn} missing or ETag mismatch", op)
                ordered.append(part["Data"])
            data = b"".join(ordered)
            meta = {
                "ContentLength": len(data),
                "ETag": _etag_for_bytes(data, self.cfg.deterministic),
                "LastModified": _now_ts(),
                "Metadata": {},
            }
            self._store.put(Bucket, Key, data, meta)
            return {"Bucket": Bucket, "Key": Key, "ETag": meta["ETag"], "ResponseMetadata": {"HTTPStatusCode": 200}}

    def abort_multipart_upload(self, *, Bucket: str, Key: str, UploadId: str, **_) -> Dict[str, Any]:
        op = "AbortMultipartUpload"
        self.cfg.chaos.maybe_sleep()
        self.cfg.chaos.maybe_fail(op)
        with self._lock:
            self._multipart.pop(UploadId, None)
        return {"ResponseMetadata": {"HTTPStatusCode": 204}}

# =========================
# Factory
# =========================
def client(config: Optional[MockConfig] = None) -> S3MockClient:
    """
    Factory that mirrors boto3.client('s3') shape.
    """
    return S3MockClient(config=config)

# =========================
# Simple self-test
# =========================
if __name__ == "__main__":
    cfg = MockConfig(root_dir=Path("./.s3mock"), deterministic=True)
    s3 = client(cfg)
    s3.create_bucket(Bucket="test")
    s3.put_object(Bucket="test", Key="a/b/c.txt", Body=b"hello")
    s3.put_object(Bucket="test", Key="a/b/d.txt", Body=b"world")
    print(s3.list_objects_v2(Bucket="test", Prefix="a/b/"))
    up = s3.create_multipart_upload(Bucket="test", Key="big.bin")
    s3.upload_part(Bucket="test", Key="big.bin", UploadId=up["UploadId"], PartNumber=1, Body=b"AAA")
    s3.upload_part(Bucket="test", Key="big.bin", UploadId=up["UploadId"], PartNumber=2, Body=b"BBB")
    s3.complete_multipart_upload(
        Bucket="test", Key="big.bin", UploadId=up["UploadId"], MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": '"00000000000000000000000000000000"'},
            {"PartNumber": 2, "ETag": '"00000000000000000000000000000000"'},
        ]}
    )
    print(s3.head_object(Bucket="test", Key="big.bin"))

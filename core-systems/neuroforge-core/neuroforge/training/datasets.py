# neuroforge-core/neuroforge/training/datasets.py
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import time
import gzip
import bz2
import math
import hashlib
import logging
import asyncio
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, AsyncIterator, Optional, List, Tuple, Callable, Union
from urllib.parse import urlparse, urlunparse

# ------------------------- ЛОГИРОВАНИЕ -------------------------

log = logging.getLogger("neuroforge.training.datasets")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
    log.addHandler(h)
log.setLevel(logging.INFO)

# ------------------------- ОПЦИОНАЛЬНЫЕ ЗАВИСИМОСТИ -------------------------

try:
    import jsonschema  # type: ignore
except Exception:  # pragma: no cover
    jsonschema = None

try:
    import pyarrow.parquet as pq  # type: ignore
    import pyarrow as pa  # type: ignore
except Exception:  # pragma: no cover
    pq = None
    pa = None

try:
    import zstandard as zstd  # type: ignore
except Exception:  # pragma: no cover
    zstd = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # pragma: no cover
    AESGCM = None

# Быстрый blake3 если установлен
try:
    import blake3  # type: ignore
except Exception:  # pragma: no cover
    blake3 = None

# ------------------------- ИСКЛЮЧЕНИЯ -------------------------

class DatasetError(Exception): ...
class ManifestValidationError(DatasetError): ...
class StorageUnavailable(DatasetError): ...
class IntegrityError(DatasetError): ...
class DecryptionError(DatasetError): ...
class FormatNotSupported(DatasetError): ...
class MissingDependencyError(DatasetError): ...

# ------------------------- НАСТРОЙКИ ПО УМОЛЧАНИЮ -------------------------

DEFAULT_HTTP_TIMEOUT = 15.0
DEFAULT_HTTP_RETRIES = 3
DEFAULT_HTTP_BACKOFF = 0.5
DEFAULT_CHUNK_SIZE = 1 << 20  # 1 MiB

# ------------------------- УТИЛИТЫ -------------------------

def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _sha3_256(b: bytes) -> str:
    return hashlib.sha3_256(b).hexdigest()

def _blake3_hex(b: bytes) -> str:
    if blake3 is None:
        raise MissingDependencyError("blake3 is not installed")
    return blake3.blake3(b).hexdigest()

def hexdigest(data: bytes, algo: str) -> str:
    algo = algo.lower()
    if algo == "sha256":
        return _sha256(data)
    if algo in ("sha3-256", "sha3"):
        return _sha3_256(data)
    if algo == "blake3":
        return _blake3_hex(data)
    raise IntegrityError(f"Unsupported hash algorithm: {algo}")

def _detect_compression(name: str) -> str:
    name = name.lower()
    if name.endswith(".gz") or name.endswith(".gzip"):
        return "gzip"
    if name.endswith(".bz2"):
        return "bz2"
    if name.endswith(".zst") or name.endswith(".zstd"):
        return "zstd"
    return "none"

def _open_by_compression(raw: bytes, comp: str) -> io.BytesIO:
    if comp == "none":
        return io.BytesIO(raw)
    if comp == "gzip":
        return io.BytesIO(gzip.decompress(raw))
    if comp == "bz2":
        return io.BytesIO(bz2.decompress(raw))
    if comp == "zstd":
        if zstd is None:
            raise MissingDependencyError("zstandard is not installed")
        d = zstd.ZstdDecompressor().decompress(raw)
        return io.BytesIO(d)
    raise FormatNotSupported(f"Unknown compression: {comp}")

def _glob_to_regex(glob: str) -> re.Pattern:
    # Простой перевод glob -> regex для фильтра путей
    return re.compile("^" + re.escape(glob).replace("\\*", ".*").replace("\\?", ".") + "$")

# ------------------------- ХРАНИЛИЩА -------------------------

class StorageAdapter:
    def open(self, uri: str) -> bytes:
        raise NotImplementedError
    def exists(self, uri: str) -> bool:
        raise NotImplementedError
    def listdir(self, uri: str) -> List[str]:
        raise NotImplementedError

class FileAdapter(StorageAdapter):
    def _path(self, uri: str) -> Path:
        p = urlparse(uri)
        if p.scheme not in ("file", ""):
            raise StorageUnavailable(f"Unsupported scheme for FileAdapter: {p.scheme}")
        # Windows: netloc может содержать диск, но Path сам справится
        return Path(p.path)

    def open(self, uri: str) -> bytes:
        path = self._path(uri)
        with path.open("rb") as f:
            return f.read()

    def exists(self, uri: str) -> bool:
        path = self._path(uri)
        return path.exists()

    def listdir(self, uri: str) -> List[str]:
        path = self._path(uri)
        if not path.is_dir():
            return []
        return [urlunparse(("file", "", str((path / name).absolute()), "", "", "")) for name in os.listdir(path)]

class HttpAdapter(StorageAdapter):
    def __init__(self, timeout: float = DEFAULT_HTTP_TIMEOUT, retries: int = DEFAULT_HTTP_RETRIES, backoff: float = DEFAULT_HTTP_BACKOFF):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff

    def open(self, uri: str) -> bytes:
        import urllib.request
        last = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(uri, headers={"User-Agent": "neuroforge-dataset/1.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read()
            except Exception as e:
                last = e
                if attempt >= self.retries:
                    break
                sleep = self.backoff * (2 ** attempt)
                time.sleep(sleep)
        raise StorageUnavailable(f"HTTP error for {uri}: {last}")

    def exists(self, uri: str) -> bool:
        import urllib.request
        try:
            req = urllib.request.Request(uri, method="HEAD", headers={"User-Agent": "neuroforge-dataset/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 400
        except Exception:
            return False

    def listdir(self, uri: str) -> List[str]:
        # Не универсально для HTTP. Возвращаем пусто.
        return []

class IpfsAdapter(HttpAdapter):
    def __init__(self, gateway: str = "https://ipfs.io", **kw):
        super().__init__(**kw)
        self.gateway = gateway.rstrip("/")

    def _map(self, uri: str) -> str:
        # ipfs://<CID>/<path> -> https://gateway/ipfs/<CID>/<path>
        p = urlparse(uri)
        if p.scheme != "ipfs":
            raise StorageUnavailable(f"Not an IPFS URI: {uri}")
        cid = p.netloc or p.path.lstrip("/")
        path = p.path if p.netloc else "/".join(p.path.split("/")[1:])
        return f"{self.gateway}/ipfs/{cid}{('/' + path) if path else ''}"

    def open(self, uri: str) -> bytes:
        return super().open(self._map(uri))

    def exists(self, uri: str) -> bool:
        return super().exists(self._map(uri))

    def listdir(self, uri: str) -> List[str]:
        return []

# Заглушки облачных адаптеров с проверкой зависимостей

class S3Adapter(StorageAdapter):
    def __init__(self):
        try:
            import boto3  # type: ignore
        except Exception as e:
            raise MissingDependencyError("boto3 is required for s3:// URIs") from e
        self._boto3 = boto3

    def _parse(self, uri: str) -> Tuple[str, str]:
        p = urlparse(uri)
        bucket = p.netloc
        key = p.path.lstrip("/")
        return bucket, key

    def open(self, uri: str) -> bytes:
        s3 = self._boto3.client("s3")
        bucket, key = self._parse(uri)
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    def exists(self, uri: str) -> bool:
        s3 = self._boto3.client("s3")
        bucket, key = self._parse(uri)
        try:
            s3.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def listdir(self, uri: str) -> List[str]:
        s3 = self._boto3.client("s3")
        bucket, prefix = self._parse(uri)
        if not prefix.endswith("/"):
            prefix += "/"
        res = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter="/")
        out = []
        for obj in res.get("Contents", []):
            out.append(f"s3://{bucket}/{obj['Key']}")
        return out

class GCSAdapter(StorageAdapter):
    def __init__(self):
        try:
            from google.cloud import storage  # type: ignore
        except Exception as e:
            raise MissingDependencyError("google-cloud-storage is required for gs:// URIs") from e
        self._storage = storage

    def _parse(self, uri: str) -> Tuple[str, str]:
        p = urlparse(uri)
        return p.netloc, p.path.lstrip("/")

    def open(self, uri: str) -> bytes:
        client = self._storage.Client()
        b, k = self._parse(uri)
        return client.bucket(b).blob(k).download_as_bytes()

    def exists(self, uri: str) -> bool:
        client = self._storage.Client()
        b, k = self._parse(uri)
        return client.bucket(b).blob(k).exists()

    def listdir(self, uri: str) -> List[str]:
        client = self._storage.Client()
        b, prefix = self._parse(uri)
        if not prefix.endswith("/"):
            prefix += "/"
        blobs = client.list_blobs(b, prefix=prefix)
        return [f"gs://{b}/{bl.name}" for bl in blobs]

class AzureBlobAdapter(StorageAdapter):
    def __init__(self):
        try:
            from azure.storage.blob import BlobServiceClient  # type: ignore
        except Exception as e:
            raise MissingDependencyError("azure-storage-blob is required for az:// URIs") from e
        self._client = BlobServiceClient.from_connection_string(os.getenv("AZURE_BLOB_CONNECTION_STRING", ""))

    def _parse(self, uri: str) -> Tuple[str, str]:
        # az://<container>/<path>
        p = urlparse(uri)
        container = p.netloc
        key = p.path.lstrip("/")
        return container, key

    def open(self, uri: str) -> bytes:
        c, k = self._parse(uri)
        blob = self._client.get_container_client(c).get_blob_client(k)
        return blob.download_blob().readall()

    def exists(self, uri: str) -> bool:
        c, k = self._parse(uri)
        blob = self._client.get_container_client(c).get_blob_client(k)
        try:
            blob.get_blob_properties()
            return True
        except Exception:
            return False

    def listdir(self, uri: str) -> List[str]:
        c, prefix = self._parse(uri)
        if not prefix.endswith("/"):
            prefix += "/"
        cont = self._client.get_container_client(c)
        return [f"az://{c}/{b.name}" for b in cont.list_blobs(name_starts_with=prefix)]

def get_adapter(uri: str) -> StorageAdapter:
    sch = urlparse(uri).scheme
    if sch in ("", "file"):
        return FileAdapter()
    if sch in ("http", "https"):
        return HttpAdapter()
    if sch == "ipfs":
        return IpfsAdapter()
    if sch == "s3":
        return S3Adapter()
    if sch == "gs":
        return GCSAdapter()
    if sch == "az":
        return AzureBlobAdapter()
    raise StorageUnavailable(f"Unsupported scheme: {sch}")

# ------------------------- МАНИФЕСТ -------------------------

@dataclass
class Manifest:
    raw: Dict[str, Any]
    uri: str

    @classmethod
    def load(cls, uri: str, schema: Optional[Dict[str, Any]] = None, schema_uri: Optional[str] = None) -> "Manifest":
        adapter = get_adapter(uri)
        data = adapter.open(uri)
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception as e:
            raise ManifestValidationError(f"Invalid JSON: {e}") from e

        if jsonschema is not None and (schema or schema_uri):
            if schema_uri:
                sch_adapter = get_adapter(schema_uri)
                sdata = sch_adapter.open(schema_uri)
                schema = json.loads(sdata.decode("utf-8"))
            try:
                jsonschema.Draft202012Validator(schema).validate(obj)  # type: ignore
            except Exception as e:  # pragma: no cover
                raise ManifestValidationError(f"Schema validation failed: {e}") from e
        elif schema or schema_uri:
            # Запросили валидацию, но нет jsonschema
            raise MissingDependencyError("jsonschema is required to validate the manifest")

        return cls(raw=obj, uri=uri)

    def get(self, path: str, default: Any = None) -> Any:
        cur: Any = self.raw
        for key in path.split("."):
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return default
        return cur

# ------------------------- ИНДЕКС ФАЙЛОВ -------------------------

@dataclass
class FileRecord:
    uri: str
    bytes: Optional[int] = None
    hash_algo: Optional[str] = None
    hash_hex: Optional[str] = None
    split: Optional[str] = None

def load_files_manifest(uri: str) -> List[FileRecord]:
    adapter = get_adapter(uri)
    data = adapter.open(uri)
    # Ожидаем JSONL: {"uri": "...", "bytes": 123, "hash": {"algorithm":"sha256","value":"..."},"split":"train"}
    out: List[FileRecord] = []
    bio = io.BytesIO(data)
    for line in bio.read().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line.decode("utf-8"))
        algo = None
        hexv = None
        if "hash" in rec and isinstance(rec["hash"], dict):
            algo = rec["hash"].get("algorithm")
            hexv = rec["hash"].get("value")
        out.append(FileRecord(
            uri=rec.get("uri") or rec.get("path"),
            bytes=rec.get("bytes"),
            hash_algo=algo,
            hash_hex=hexv,
            split=rec.get("split")
        ))
    return out

# ------------------------- ДЕШИФРОВАНИЕ -------------------------

@dataclass
class DecryptConfig:
    enabled: bool
    algo: Optional[str] = None
    key_hex: Optional[str] = None
    aad: Optional[bytes] = None

def decrypt_if_needed(buf: bytes, cfg: Optional[DecryptConfig]) -> bytes:
    if not cfg or not cfg.enabled:
        return buf
    algo = (cfg.algo or "").upper()
    if algo not in ("AES-256-GCM",):
        raise DecryptionError(f"Unsupported cipher: {cfg.algo}")
    if AESGCM is None:
        raise MissingDependencyError("cryptography is required for AES-256-GCM decryption")
    if not cfg.key_hex:
        raise DecryptionError("Missing key for decryption")
    key = bytes.fromhex(cfg.key_hex)
    # Протокол контейнера: nonce(12) + ciphertext + tag(16)
    if len(buf) < 12 + 16:
        raise DecryptionError("Ciphertext too short")
    nonce = buf[:12]
    ct = buf[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, cfg.aad)
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e

# ------------------------- ЧИТАТЕЛИ ФОРМАТОВ -------------------------

class Reader:
    def __init__(self, decrypt: Optional[DecryptConfig] = None):
        self.decrypt = decrypt

    def read_bytes(self, uri: str) -> bytes:
        adapter = get_adapter(uri)
        raw = adapter.open(uri)
        return decrypt_if_needed(raw, self.decrypt)

class JsonlReader(Reader):
    def iter(self, uris: Iterable[str]) -> Iterator[Dict[str, Any]]:
        for uri in uris:
            data = self.read_bytes(uri)
            comp = _detect_compression(uri)
            bio = _open_by_compression(data, comp)
            for line in bio.read().splitlines():
                if not line.strip():
                    continue
                yield json.loads(line.decode("utf-8"))

class CsvReader(Reader):
    def iter(self, uris: Iterable[str]) -> Iterator[Dict[str, Any]]:
        for uri in uris:
            data = self.read_bytes(uri)
            comp = _detect_compression(uri)
            bio = _open_by_compression(data, comp)
            txt = io.TextIOWrapper(bio, encoding="utf-8")
            reader = csv.DictReader(txt)
            for row in reader:
                yield dict(row)

class ParquetReader(Reader):
    def iter(self, uris: Iterable[str]) -> Iterator[Dict[str, Any]]:
        if pq is None or pa is None:
            raise MissingDependencyError("pyarrow is required for Parquet")
        for uri in uris:
            data = self.read_bytes(uri)
            table = pq.read_table(io.BytesIO(data))
            for batch in table.to_batches():
                for row in batch.to_pylist():
                    yield row

class WebDatasetReader(Reader):
    """
    Минимальная поддержка tar-шардов с JSONL элементами.
    Ищет внутри tar файлы *.jsonl и отдаёт записи.
    """
    def iter(self, uris: Iterable[str]) -> Iterator[Dict[str, Any]]:
        for uri in uris:
            data = self.read_bytes(uri)
            comp = _detect_compression(uri)
            bio = _open_by_compression(data, comp)
            with tarfile.open(fileobj=bio, mode="r:") as tar:
                for m in tar.getmembers():
                    if not m.isfile() or not m.name.lower().endswith(".jsonl"):
                        continue
                    f = tar.extractfile(m)
                    if not f:
                        continue
                    for line in f:
                        if not line.strip():
                            continue
                        yield json.loads(line.decode("utf-8"))

# ------------------------- DATASET CORE -------------------------

@dataclass
class DatasetConfig:
    manifest_uri: str
    schema_uri: Optional[str] = None
    split: Optional[str] = None          # "train" | "val" | "test" | custom
    limit: Optional[int] = None
    decrypt_key_hex: Optional[str] = None
    decrypt_algo: Optional[str] = None
    decrypt_aad: Optional[bytes] = None
    verify_hashes: bool = True

class Dataset:
    def __init__(self, cfg: DatasetConfig):
        self.cfg = cfg
        self.manifest = Manifest.load(cfg.manifest_uri, schema_uri=cfg.schema_uri) if cfg.schema_uri else Manifest.load(cfg.manifest_uri)
        self._format = self.manifest.get("storage.format", "jsonl")
        self._files_manifest_uri = self.manifest.get("integrity.files_manifest_uri")
        if not self._files_manifest_uri:
            raise ManifestValidationError("integrity.files_manifest_uri is required for dataset reading")
        self._records = load_files_manifest(self._files_manifest_uri)
        self._filter_records()
        self._reader = self._make_reader()
        self._hash_algo = self.manifest.get("integrity.hash_algorithm", "sha256")

    def _filter_records(self) -> None:
        split = self.cfg.split
        if split:
            # 1) фильтр по split из files_manifest
            recs = [r for r in self._records if r.split == split]
            # 2) если не размечены, пробуем по паттернам из манифеста
            if not recs:
                partitions = self.manifest.get("splits.partitions", []) or []
                globs = [p.get("path_glob") for p in partitions if p.get("name") == split and p.get("path_glob")]
                if globs:
                    regs = [_glob_to_regex(g) for g in globs]
                    for r in self._records:
                        path = urlparse(r.uri).path
                        if any(rx.match(path) for rx in regs):
                            recs.append(r)
            self._records = recs

        if self.cfg.limit is not None and self.cfg.limit >= 0:
            self._records = self._records[: self.cfg.limit]

        if not self._records:
            log.warning("No file records selected after split/limit filters")

    def _make_reader(self) -> Reader:
        dec = None
        if self.cfg.decrypt_key_hex or (self.manifest.get("encryption.enabled") is True):
            dec = DecryptConfig(
                enabled=True,
                algo=self.cfg.decrypt_algo or self.manifest.get("encryption.algorithm", "AES-256-GCM"),
                key_hex=self.cfg.decrypt_key_hex,
                aad=self.cfg.decrypt_aad,
            )
        fmt = (self._format or "jsonl").lower()
        if fmt in ("jsonl", "jsonlines"):
            return JsonlReader(dec)
        if fmt == "csv":
            return CsvReader(dec)
        if fmt == "parquet":
            return ParquetReader(dec)
        if fmt in ("webdataset", "wds", "tar"):
            return WebDatasetReader(dec)
        raise FormatNotSupported(f"Unsupported dataset format: {fmt}")

    # ---------------- СИНХРОННЫЕ ИТЕРАТОРЫ ----------------

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        for rec in self._records:
            if self.cfg.verify_hashes and rec.hash_algo and rec.hash_hex:
                self._verify(rec)
            yield from self._reader.iter([rec.uri])

    def iter_files(self) -> Iterator[FileRecord]:
        return iter(self._records)

    # ---------------- АСИНХРОННЫЕ ИТЕРАТОРЫ ----------------

    async def aiter(self) -> AsyncIterator[Dict[str, Any]]:
        loop = asyncio.get_event_loop()
        for rec in self._records:
            if self.cfg.verify_hashes and rec.hash_algo and rec.hash_hex:
                # проверку хеша делаем в пуле потоков
                await loop.run_in_executor(None, self._verify, rec)
            # чтение и парсинг файла как задача CPU/IO
            rows = await loop.run_in_executor(None, lambda: list(self._reader.iter([rec.uri])))
            for row in rows:
                yield row

    # ---------------- ПРОВЕРКА ЦЕЛОСТНОСТИ ----------------

    def _verify(self, rec: FileRecord) -> None:
        adapter = get_adapter(rec.uri)
        data = adapter.open(rec.uri)
        comp = _detect_compression(rec.uri)
        # Проверяем хеш по сжатым байтам (манифест обычно хранит хеш на файл в хранилище)
        calc = hexdigest(data, rec.hash_algo or self._hash_algo)
        if rec.hash_hex and calc.lower() != rec.hash_hex.lower():
            raise IntegrityError(f"Hash mismatch for {rec.uri}: expected {rec.hash_hex}, got {calc}")
        # Проверяем размер, если задан
        if rec.bytes is not None and len(data) != rec.bytes:
            raise IntegrityError(f"Size mismatch for {rec.uri}: expected {rec.bytes}, got {len(data)}")
        # Дополнительно проверим читабельность
        try:
            _open_by_compression(data, comp)
        except Exception as e:
            raise IntegrityError(f"Decompression failed for {rec.uri}: {e}") from e

# ------------------------- УТИЛИТЫ ВЫСОКОГО УРОВНЯ -------------------------

def load_dataset(
    manifest_uri: str,
    schema_uri: Optional[str] = None,
    split: Optional[str] = None,
    limit: Optional[int] = None,
    decrypt_key_hex: Optional[str] = None,
    verify_hashes: bool = True,
) -> Dataset:
    """
    Высокоуровневая точка входа. Возвращает Dataset.
    """
    cfg = DatasetConfig(
        manifest_uri=manifest_uri,
        schema_uri=schema_uri,
        split=split,
        limit=limit,
        decrypt_key_hex=decrypt_key_hex,
        decrypt_algo=None,
        decrypt_aad=None,
        verify_hashes=verify_hashes,
    )
    return Dataset(cfg)

# ------------------------- ПРИМЕР ИСПОЛЬЗОВАНИЯ -------------------------
# ds = load_dataset("s3://bucket/path/dataset.manifest.json", schema_uri="s3://bucket/schemas/jsonschema/v1/dataset.schema.json", split="train")
# for sample in ds:
#     ... train ...
# async for sample in ds.aiter():
#     ... async train ...

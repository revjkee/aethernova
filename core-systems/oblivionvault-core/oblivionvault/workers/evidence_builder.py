# File: oblivionvault/workers/evidence_builder.py
# Industrial Evidence Builder for oblivionvault-core
# Python 3.10+

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import hmac
import io
import json
import logging
import os
import re
import tarfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, Union

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    _TRACER = None  # type: ignore

# Optional BigQuery adapter
try:
    from google.cloud import bigquery  # type: ignore
    _HAS_BQ = True
except Exception:  # pragma: no cover
    _HAS_BQ = False

try:
    from oblivionvault.adapters.storage_bigquery import (
        BigQueryStorageAdapter,
        BigQueryConfig,
        BQField,
    )  # type: ignore
    _HAS_OV_BQ_ADAPTER = True
except Exception:  # pragma: no cover
    _HAS_OV_BQ_ADAPTER = False


# ============================== Utilities ===================================

_CHUNK = 1024 * 1024  # 1 MiB

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uuid() -> str:
    return uuid.uuid4().hex

def _canonical_json(obj: Any) -> bytes:
    # Deterministic JSON for hashing / storage
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _blake2b_new() -> "hashlib._Hash":
    return hashlib.blake2b(digest_size=32)

def _blake2b_hex(data: bytes) -> str:
    h = _blake2b_new()
    h.update(data)
    return h.hexdigest()

def _safe_alias(name: str) -> str:
    # Keep only safe chars, collapse whitespace, limit length
    base = Path(name).name
    base = re.sub(r"[^\w.\-+@]", "_", base)
    base = re.sub(r"_+", "_", base).strip("._")
    return base[:180] or "artifact"

class EvidenceBuilderError(RuntimeError):
    pass

class EvidenceVerificationError(EvidenceBuilderError):
    pass

def _maybe_span(name: str):
    class _NullCtx:
        def __enter__(self): return None
        def __exit__(self, exc_type, exc, tb): return False
    if _TRACER:
        return _TRACER.start_as_current_span(name)
    return _NullCtx()


# ============================== Data model ==================================

@dataclass(slots=True)
class ArtifactInput:
    """
    One of:
      - path: file on disk (will be streamed into archive)
      - inline_json: JSON object to store as UTF-8 file
    """
    path: Optional[Union[str, Path]] = None
    inline_json: Optional[Dict[str, Any]] = None
    alias: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)

    def kind(self) -> str:
        if self.path is not None:
            return "file"
        if self.inline_json is not None:
            return "inline_json"
        raise EvidenceBuilderError("ArtifactInput must have 'path' or 'inline_json'")

@dataclass(slots=True)
class RetryPolicy:
    max_attempts: int = 5
    initial_delay: float = 0.5
    max_delay: float = 8.0
    multiplier: float = 2.0

@dataclass(slots=True)
class EvidenceConfig:
    # Identity / context
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "oblivionvault"))
    node_id: str = field(default_factory=lambda: os.getenv("NODE_ID", "node-unknown"))
    tenant_id: Optional[str] = field(default_factory=lambda: os.getenv("TENANT_ID", None))

    # Storage
    base_dir: Union[str, Path] = field(default_factory=lambda: os.getenv("EVIDENCE_BASE_DIR", "/var/lib/oblivionvault/evidence"))
    make_parents: bool = True

    # Security
    redact_keys: Sequence[str] = field(default_factory=lambda: ("password", "secret", "token", "ssn"))
    store_source_path: bool = False  # do not leak absolute FS paths by default
    hmac_keys: Dict[str, bytes] = field(default_factory=dict)  # {"k2025q3": b"..."} for bundle sidecar
    active_key_id: Optional[str] = None

    # Behavior
    include_manifest_in_tar: bool = True
    include_attestation_in_tar: bool = True

    # Retry
    retry: RetryPolicy = field(default_factory=RetryPolicy)

# ============================== Sink API ====================================

class EvidenceSink(Protocol):
    def publish(self, result: "EvidenceResult") -> None: ...
    def close(self) -> None: ...

@dataclass(slots=True)
class EvidenceResult:
    case_id: str
    evidence_id: str
    created: str
    file_count: int
    bundle_path: Path
    signature_path: Path
    bundle_digest_hex: str
    merkle_root_hex: str
    labels: Dict[str, str]
    meta: Dict[str, Any]  # manifest top-level for sinks

class LocalFilesystemSink:
    """
    Default sink: files already written locally by the builder — nothing to do
    besides logging. Kept for symmetry with other sinks.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.log = logger or logging.getLogger(__name__)
    def publish(self, result: EvidenceResult) -> None:
        self.log.info("Evidence stored",
                      extra={"bundle": str(result.bundle_path),
                             "signature": str(result.signature_path),
                             "evidence_id": result.evidence_id})
    def close(self) -> None:
        return

class BigQueryMetadataSink:
    """
    Optional metadata sink to BigQuery using oblivionvault.adapters.storage_bigquery.
    Stores evidence metadata (not the tarball itself).
    """
    def __init__(self, dataset: Optional[str] = None, table: str = "evidence_meta",
                 config: Optional[BigQueryConfig] = None, logger: Optional[logging.Logger] = None, ensure_table: bool = True):
        if not (_HAS_BQ and _HAS_OV_BQ_ADAPTER):
            raise RuntimeError("BigQuery dependencies/adapter are not available")
        self.log = logger or logging.getLogger(__name__)
        self._bq = BigQueryStorageAdapter(config=config or BigQueryConfig(dataset=dataset or os.getenv("BQ_DATASET", "oblivionvault")))
        self._table = table
        if ensure_table:
            self._ensure_schema()

    def _ensure_schema(self) -> None:
        schema: List[BQField] = [
            bigquery.SchemaField("case_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("evidence_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("created", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("app_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("node_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("tenant_id", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("file_count", "INT64", mode="REQUIRED"),
            bigquery.SchemaField("bundle_path", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("signature_path", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("bundle_digest_hex", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("merkle_root_hex", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("labels", "RECORD", mode="REPEATED", fields=[
                bigquery.SchemaField("key", "STRING"),
                bigquery.SchemaField("value", "STRING"),
            ]),
            bigquery.SchemaField("manifest_json", "JSON", mode="REQUIRED"),
        ]
        self._bq.ensure_dataset()
        self._bq.ensure_table(
            table=self._table,
            schema=schema,
            description="OblivionVault evidence metadata",
            time_partitioning_field="created",
            time_partitioning_type="DAY",
            clustering_fields=("case_id",),
            labels={"purpose": "evidence"},
        )

    @staticmethod
    def _labels_to_pairs(labels: Dict[str, str]) -> List[Dict[str, str]]:
        return [{"key": k, "value": v} for k, v in sorted(labels.items())]

    def publish(self, result: EvidenceResult) -> None:
        row = {
            "case_id": result.case_id,
            "evidence_id": result.evidence_id,
            "created": result.created,
            "app_name": result.meta.get("builder", {}).get("app_name"),
            "node_id": result.meta.get("builder", {}).get("node_id"),
            "tenant_id": result.meta.get("builder", {}).get("tenant_id"),
            "file_count": result.file_count,
            "bundle_path": str(result.bundle_path),
            "signature_path": str(result.signature_path),
            "bundle_digest_hex": result.bundle_digest_hex,
            "merkle_root_hex": result.merkle_root_hex,
            "labels": self._labels_to_pairs(result.labels),
            "manifest_json": result.meta,  # BigQuery JSON type
        }
        self._bq.insert_rows_json(self._table, [row])

    def close(self) -> None:
        self._bq.close()


# ============================== Evidence Builder ============================

@dataclass(slots=True)
class _Leaf:
    alias: str
    digest_hex: str

class EvidenceBuilder:
    """
    Builds immutable evidence bundles:
      - Streams and hashes artifacts with BLAKE2b-256
      - Generates Merkle root over artifact digests
      - Produces manifest.json (canonical)
      - Packs tar.gz bundle (artifacts/..., manifest.json, optional attestation.json)
      - Computes bundle digest and writes sidecar signature (.sig.json)
      - Publishes metadata via configured sinks
    """

    def __init__(self, config: EvidenceConfig, sinks: Optional[Sequence[EvidenceSink]] = None,
                 logger: Optional[logging.Logger] = None):
        self.cfg = config
        self.log = logger or logging.getLogger(__name__)
        self.sinks = list(sinks or [LocalFilesystemSink()])
        self._lock = threading.RLock()

    # ----------------------------- Public API --------------------------------

    def build(self,
              case_id: str,
              artifacts: Sequence[ArtifactInput],
              labels: Optional[Dict[str, str]] = None,
              related_events: Optional[Sequence[str]] = None,
              attestation: Optional[Dict[str, Any]] = None) -> EvidenceResult:
        """
        Build evidence bundle synchronously and publish metadata via sinks.
        """
        with _maybe_span("evidence.build"):
            case_id = _safe_alias(case_id)
            evidence_id = _uuid()
            created = _utcnow_iso()
            labels = labels or {}

            base_dir = Path(self.cfg.base_dir) / case_id / evidence_id
            if self.cfg.make_parents:
                base_dir.mkdir(parents=True, exist_ok=True)

            # 1) Prepare and hash artifacts
            leaves, file_specs = self._hash_artifacts(artifacts)

            # 2) Build Merkle root
            merkle_root = self._merkle_root([l.digest_hex for l in leaves])

            # 3) Build manifest
            manifest = self._build_manifest(case_id, evidence_id, created, labels, related_events, leaves, file_specs)

            # 4) Pack tar.gz
            bundle_path = base_dir / f"evidence-{evidence_id}.tar.gz"
            self._write_tar(bundle_path, manifest, file_specs, attestation)

            # 5) Compute bundle digest and write sidecar signature
            bundle_digest_hex = self._hash_file(bundle_path)
            signature_path = base_dir / f"evidence-{evidence_id}.sig.json"
            self._write_signature(signature_path, evidence_id, bundle_digest_hex)

            # 6) Publish to sinks
            result = EvidenceResult(
                case_id=case_id,
                evidence_id=evidence_id,
                created=created,
                file_count=len(file_specs),
                bundle_path=bundle_path,
                signature_path=signature_path,
                bundle_digest_hex=bundle_digest_hex,
                merkle_root_hex=merkle_root,
                labels=dict(labels),
                meta=manifest,
            )
            self._publish(result)
            return result

    async def abuild(self, *args, **kwargs) -> EvidenceResult:
        # Lazy import to avoid mandatory asyncio in sync flows
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.build(*args, **kwargs))

    def close(self) -> None:
        for s in self.sinks:
            try:
                s.close()
            except Exception as e:
                self.log.warning("Sink close error: %s", e)

    # ----------------------------- Internals ---------------------------------

    def _hash_artifacts(self, inputs: Sequence[ArtifactInput]) -> Tuple[List[_Leaf], List[Dict[str, Any]]]:
        leaves: List[_Leaf] = []
        specs: List[Dict[str, Any]] = []
        used_aliases = set()

        for idx, art in enumerate(inputs):
            kind = art.kind()
            if art.alias:
                alias = _safe_alias(art.alias)
            else:
                alias = _safe_alias((Path(art.path).name if art.path else f"inline_{idx}.json"))
            # ensure unique alias
            i = 1
            base_alias = alias
            while alias in used_aliases:
                alias = f"{base_alias}_{i}"
                i += 1
            used_aliases.add(alias)

            if kind == "file":
                p = Path(art.path)  # type: ignore[arg-type]
                if not p.exists() or not p.is_file():
                    raise EvidenceBuilderError(f"Artifact file not found: {p}")
                digest_hex, size, mtime = self._hash_file_stream(p)
                spec = {
                    "type": "file",
                    "alias": alias,
                    "size": size,
                    "mtime": int(mtime),
                    "digest": {"alg": "BLAKE2B-256", "value": digest_hex},
                    "source_path": (str(p) if self.cfg.store_source_path else None),
                    "labels": dict(art.labels),
                }
                specs.append(spec)
                leaves.append(_Leaf(alias=alias, digest_hex=digest_hex))

            elif kind == "inline_json":
                # Canonicalize JSON, hash and store bytes (will be packed)
                body = self._redact_dict(art.inline_json or {})
                data = _canonical_json(body)
                h = _blake2b_new()
                h.update(data)
                digest_hex = h.hexdigest()
                spec = {
                    "type": "inline_json",
                    "alias": alias if alias.endswith(".json") else f"{alias}.json",
                    "size": len(data),
                    "mtime": int(time.time()),
                    "digest": {"alg": "BLAKE2B-256", "value": digest_hex},
                    "labels": dict(art.labels),
                    "inline_json": body,  # kept in manifest for transparency
                }
                specs.append(spec)
                leaves.append(_Leaf(alias=spec["alias"], digest_hex=digest_hex))

            else:
                raise EvidenceBuilderError(f"Unsupported artifact kind: {kind}")

        return leaves, specs

    def _hash_file_stream(self, path: Path) -> Tuple[str, int, float]:
        h = _blake2b_new()
        size = 0
        with path.open("rb") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                h.update(chunk)
        stat = path.stat()
        return h.hexdigest(), size, stat.st_mtime

    def _hash_file(self, path: Path) -> str:
        h = _blake2b_new()
        with path.open("rb") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _merkle_root(self, leaf_hexes: Sequence[str]) -> str:
        if not leaf_hexes:
            return _blake2b_hex(b"")
        # Convert hex -> bytes
        level = [bytes.fromhex(x) for x in leaf_hexes]
        # Pairwise hash until root
        while len(level) > 1:
            nxt: List[bytes] = []
            it = iter(level)
            for left in it:
                try:
                    right = next(it)
                except StopIteration:
                    right = left  # duplicate last if odd
                h = _blake2b_new()
                h.update(left)
                h.update(right)
                nxt.append(h.digest())
            level = nxt
        return level[0].hex()

    def _build_manifest(self,
                        case_id: str,
                        evidence_id: str,
                        created: str,
                        labels: Dict[str, str],
                        related_events: Optional[Sequence[str]],
                        leaves: List[_Leaf],
                        specs: List[Dict[str, Any]]) -> Dict[str, Any]:
        manifest = {
            "schema": "oblivionvault.evidence.manifest/1",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "created": created,
            "builder": {
                "app_name": self.cfg.app_name,
                "node_id": self.cfg.node_id,
                "tenant_id": self.cfg.tenant_id,
            },
            "labels": dict(labels),
            "related_events": list(related_events or []),
            "artifacts": [
                {
                    "alias": s["alias"],
                    "type": s["type"],
                    "size": s["size"],
                    "mtime": s["mtime"],
                    "digest": s["digest"],
                    **({"source_path": s["source_path"]} if "source_path" in s else {}),
                    **({"labels": s["labels"]} if s.get("labels") else {}),
                    **({"inline_json": s["inline_json"]} if s["type"] == "inline_json" else {}),
                }
                for s in specs
            ],
            "merkle": {
                "alg": "BLAKE2B-256",
                "leaves": [l.digest_hex for l in leaves],
                "root": self._merkle_root([l.digest_hex for l in leaves]),
            },
        }
        return manifest

    def _write_tar(self, bundle_path: Path, manifest: Dict[str, Any], specs: List[Dict[str, Any]],
                   attestation: Optional[Dict[str, Any]]) -> None:
        # Ensure parent dir
        bundle_path.parent.mkdir(parents=True, exist_ok=True)

        with _maybe_span("evidence.pack_tar"):
            # Open tarfile with gzip; python's tarfile will handle compression internally
            with tarfile.open(bundle_path, mode="w:gz") as tar:
                # manifest.json
                if self.cfg.include_manifest_in_tar:
                    data = _canonical_json(manifest)
                    info = tarfile.TarInfo(name="manifest.json")
                    info.size = len(data)
                    info.mtime = int(time.time())
                    tar.addfile(info, io.BytesIO(data))

                # attestation.json (optional)
                if self.cfg.include_attestation_in_tar and attestation is not None:
                    att = dict(attestation)
                    att_bytes = _canonical_json(att)
                    info = tarfile.TarInfo(name="attestation.json")
                    info.size = len(att_bytes)
                    info.mtime = int(time.time())
                    tar.addfile(info, io.BytesIO(att_bytes))

                # artifacts
                for s in specs:
                    arcname = f"artifacts/{s['alias']}"
                    if s["type"] == "file":
                        src = s.get("source_path")
                        if not src:
                            raise EvidenceBuilderError("source_path missing for file artifact (store_source_path=False?)")
                        p = Path(src)
                        # Use TarInfo for safer control (avoid symlinks, etc.)
                        with p.open("rb") as f:
                            data_stream = f  # streamed
                            # Build TarInfo
                            info = tarfile.TarInfo(name=arcname)
                            info.size = s["size"]
                            info.mtime = s["mtime"]
                            info.type = tarfile.REGTYPE
                            info.mode = 0o640
                            tar.addfile(info, data_stream)
                    elif s["type"] == "inline_json":
                        body = s.get("inline_json", {})
                        data = _canonical_json(body)
                        info = tarfile.TarInfo(name=arcname)
                        info.size = len(data)
                        info.mtime = s["mtime"]
                        info.type = tarfile.REGTYPE
                        info.mode = 0o640
                        tar.addfile(info, io.BytesIO(data))
                    else:
                        raise EvidenceBuilderError(f"Unsupported artifact type in spec: {s['type']}")

    def _write_signature(self, signature_path: Path, evidence_id: str, bundle_digest_hex: str) -> None:
        obj = {
            "schema": "oblivionvault.evidence.signature/1",
            "evidence_id": evidence_id,
            "created": _utcnow_iso(),
            "bundle_digest": {"alg": "BLAKE2B-256", "value": bundle_digest_hex},
            "hmac": None,
        }
        key_id = self.cfg.active_key_id
        if key_id and key_id in self.cfg.hmac_keys:
            sig = hmac.new(self.cfg.hmac_keys[key_id], bundle_digest_hex.encode("utf-8"), hashlib.blake2b).hexdigest()
            obj["hmac"] = {"alg": "HMAC-BLAKE2B", "key_id": key_id, "value": sig}
        # Write sidecar JSON
        signature_path.parent.mkdir(parents=True, exist_ok=True)
        with signature_path.open("wb") as f:
            f.write(_canonical_json(obj))

    def _publish(self, result: EvidenceResult) -> None:
        delay = self.cfg.retry.initial_delay
        for s in self.sinks:
            attempts = 0
            while True:
                attempts += 1
                try:
                    with _maybe_span("evidence.publish"):
                        s.publish(result)
                    break
                except Exception as e:
                    if attempts >= self.cfg.retry.max_attempts:
                        self.log.error("Sink publish failed permanently for %s: %s", type(s).__name__, e, exc_info=True)
                        break
                    self.log.warning("Sink publish failed (attempt %s) for %s: %s; retry in %.2fs",
                                     attempts, type(s).__name__, e, delay)
                    time.sleep(delay)
                    delay = min(delay * self.cfg.retry.multiplier, self.cfg.retry.max_delay)

    # ----------------------------- Helpers -----------------------------------

    def _redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        keys = {k.lower() for k in self.cfg.redact_keys}
        def _mask(v: Any) -> Any:
            if v is None:
                return None
            s = str(v)
            if len(s) <= 4:
                return "***"
            return s[:2] + "***" + s[-2:]
        def _walk(o: Any) -> Any:
            if isinstance(o, dict):
                return {k: (_mask(v) if k.lower() in keys else _walk(v)) for k, v in o.items()}
            if isinstance(o, list):
                return [_walk(x) for x in o]
            return o
        return _walk(dict(data))

# ============================== Verification ================================

def verify_bundle(bundle_path: Union[str, Path],
                  signature_path: Union[str, Path],
                  expected_merkle_root: Optional[str] = None,
                  hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Verify packed evidence:
      - Recompute bundle digest and compare with sidecar
      - Validate HMAC (if provided)
      - Recompute manifest Merkle root by hashing artifacts inside tar.gz
    Returns minimal report dict; raises EvidenceVerificationError on failure.
    """
    bundle_path = Path(bundle_path)
    signature_path = Path(signature_path)

    if not bundle_path.exists():
        raise EvidenceVerificationError("Bundle not found")
    if not signature_path.exists():
        raise EvidenceVerificationError("Signature sidecar not found")

    # 1) Verify bundle digest
    h = _blake2b_new()
    with bundle_path.open("rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    bundle_digest_hex = h.hexdigest()

    sig_obj = json.loads(signature_path.read_text(encoding="utf-8"))
    sidecar_digest = sig_obj.get("bundle_digest", {}).get("value")
    if not sidecar_digest or sidecar_digest != bundle_digest_hex:
        raise EvidenceVerificationError("Bundle digest mismatch")

    # 2) Verify HMAC if present / provided
    hmac_obj = sig_obj.get("hmac")
    hmac_ok = None
    if hmac_obj and hmac_key:
        expected = hmac_obj.get("value")
        calc = hmac.new(hmac_key, bundle_digest_hex.encode("utf-8"), hashlib.blake2b).hexdigest()
        hmac_ok = (expected == calc)
        if not hmac_ok:
            raise EvidenceVerificationError("HMAC signature mismatch")

    # 3) Verify Merkle root from manifest and artifacts
    with tarfile.open(bundle_path, mode="r:gz") as tar:
        # read manifest
        try:
            m = tar.extractfile("manifest.json")
            if m is None:
                raise KeyError
            manifest = json.loads(m.read().decode("utf-8"))
        except KeyError:
            raise EvidenceVerificationError("manifest.json not found in bundle")

        # recompute leaves by reading artifacts/* files in tar
        leaves: List[str] = []
        for m_info in tar.getmembers():
            if not m_info.isfile() or not m_info.name.startswith("artifacts/"):
                continue
            f = tar.extractfile(m_info)
            if f is None:
                raise EvidenceVerificationError(f"Cannot read {m_info.name}")
            hleaf = _blake2b_new()
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                hleaf.update(chunk)
            leaves.append(hleaf.hexdigest())

        if sorted(leaves) != sorted(manifest.get("merkle", {}).get("leaves", [])):
            raise EvidenceVerificationError("Leaf digests mismatch with manifest")

        # recompute root
        def _root(lst: Sequence[str]) -> str:
            if not lst:
                return _blake2b_hex(b"")
            level = [bytes.fromhex(x) for x in lst]
            while len(level) > 1:
                nxt: List[bytes] = []
                it = iter(level)
                for left in it:
                    try:
                        right = next(it)
                    except StopIteration:
                        right = left
                    hh = _blake2b_new()
                    hh.update(left)
                    hh.update(right)
                    nxt.append(hh.digest())
                level = nxt
            return level[0].hex()

        recomputed_root = _root(leaves)
        manifest_root = manifest.get("merkle", {}).get("root")
        if recomputed_root != manifest_root:
            raise EvidenceVerificationError("Merkle root mismatch with manifest")

        if expected_merkle_root and recomputed_root != expected_merkle_root:
            raise EvidenceVerificationError("Merkle root mismatch with expected value")

    return {
        "bundle_digest_hex": bundle_digest_hex,
        "hmac_verified": hmac_ok,
        "merkle_root_hex": recomputed_root,
        "ok": True,
    }

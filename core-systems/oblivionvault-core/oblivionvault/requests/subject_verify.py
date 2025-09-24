from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import io
import json
import logging
import mimetypes
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# Опционально: BLAKE3 и OpenTelemetry
try:
    import blake3  # type: ignore
    _BLAKE3_OK = True
except Exception:
    _BLAKE3_OK = False

try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:
    _TRACER = None

log = logging.getLogger("oblivionvault.subject_verify")


# =========================
# Исключения
# =========================
class SubjectError(Exception):
    pass


class DownloadError(SubjectError):
    pass


class DigestMismatch(SubjectError):
    pass


class SizeLimitExceeded(SubjectError):
    pass


class UnsupportedURI(SubjectError):
    pass


# =========================
# Типы данных результата
# =========================
@dataclass
class DigestSpec:
    alg: str                      # "sha256" | "sha512" | "sha3_256" | "blake3"
    expected_hex: str             # ожидание в hex (без 0x)
    source: str = "value"         # value|multibase|dict


@dataclass
class VerificationResult:
    ok: bool
    uri: str
    computed_hex: Dict[str, str] = field(default_factory=dict)     # alg -> hex
    matched: Dict[str, bool] = field(default_factory=dict)         # alg -> True/False
    expected_hex: Dict[str, str] = field(default_factory=dict)     # alg -> hex
    size_ok: Optional[bool] = None
    size_bytes: Optional[int] = None
    media_type: Optional[str] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    stored_path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def ensure_ok(self) -> "VerificationResult":
        if not self.ok:
            raise DigestMismatch(f"Verification failed for {self.uri}: {self.matched}")
        return self


# =========================
# Утилиты дайджестов
# =========================
_SUPPORTED_ALGS = {"sha256", "sha512", "sha3_256"}
if _BLAKE3_OK:
    _SUPPORTED_ALGS.add("blake3")


def _hex(b: bytes) -> str:
    return b.hex()


def _normalize_alg(alg: str) -> str:
    a = alg.strip().lower().replace("-", "_")
    if a == "sha3-256":
        a = "sha3_256"
    return a


def _parse_digest_items(digests: Iterable[Mapping[str, Any]]) -> List[DigestSpec]:
    out: List[DigestSpec] = []
    for d in digests:
        alg = _normalize_alg(str(d.get("alg", "")))
        if not alg:
            continue
        if "hex" in d and d["hex"]:
            out.append(DigestSpec(alg=alg, expected_hex=str(d["hex"]).lower(), source="value"))
            continue
        if "base64" in d and d["base64"]:
            try:
                val = base64.b64decode(str(d["base64"]), validate=True)
                out.append(DigestSpec(alg=alg, expected_hex=_hex(val), source="value"))
                continue
            except Exception:
                pass
        if "multibase" in d and d["multibase"]:
            # Простая поддержка multibase: допускаем u=base64url, f=hex
            m = str(d["multibase"])
            if m.startswith("u"):
                try:
                    val = base64.urlsafe_b64decode(m[1:] + "=" * (-len(m[1:]) % 4))
                    out.append(DigestSpec(alg=alg, expected_hex=_hex(val), source="multibase"))
                    continue
                except Exception:
                    pass
            if m.startswith("f"):
                try:
                    out.append(DigestSpec(alg=alg, expected_hex=m[1:].lower(), source="multibase"))
                    continue
                except Exception:
                    pass
        # игнорируем нераспознанные записи
    return out


def _digester_for(alg: str):
    alg = _normalize_alg(alg)
    if alg not in _SUPPORTED_ALGS:
        raise SubjectError(f"Unsupported digest algorithm: {alg}")
    if alg == "sha256":
        return hashlib.sha256()
    if alg == "sha512":
        return hashlib.sha512()
    if alg == "sha3_256":
        return hashlib.sha3_256()
    if alg == "blake3":
        if not _BLAKE3_OK:
            raise SubjectError("blake3 module not installed")
        return blake3.blake3()
    raise SubjectError(f"No digester for {alg}")


# =========================
# Интерфейс загрузчиков
# =========================
class Fetcher:
    scheme: str = ""

    def head(self, uri: str, timeout: float) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Вернуть (content_length, etag, last_modified) если возможно."""
        return None, None, None

    def stream(self, uri: str, timeout: float, max_bytes: Optional[int]) -> Tuple[Iterable[bytes], Optional[int], Optional[str], Optional[str], Optional[str]]:
        """Вернуть (итератор байтов, content_length, media_type, etag, last_modified)."""
        raise NotImplementedError


class FileFetcher(Fetcher):
    scheme = "file"

    def head(self, uri: str, timeout: float) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        path = self._path(uri)
        if not path.exists():
            raise DownloadError("file_not_found")
        return path.stat().st_size, None, None

    def stream(self, uri: str, timeout: float, max_bytes: Optional[int]):
        path = self._path(uri)
        if not path.exists():
            raise DownloadError("file_not_found")
        size = path.stat().st_size
        if max_bytes is not None and size > max_bytes:
            raise SizeLimitExceeded(f"file too large: {size} > {max_bytes}")
        def gen():
            with path.open("rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    yield chunk
        media, _ = mimetypes.guess_type(path.name)
        return gen(), size, media or "application/octet-stream", None, None

    @staticmethod
    def _path(uri: str) -> Path:
        if uri.startswith("file://"):
            return Path(uri[len("file://"):])
        return Path(uri)


class HTTPFetcher(Fetcher):
    scheme = "http"

    def head(self, uri: str, timeout: float):
        import urllib.request
        req = urllib.request.Request(uri, method="HEAD", headers={
            "User-Agent": "oblivionvault-subject/1.0",
            "Accept-Encoding": "identity",
        })
        with contextlib.closing(urllib.request.urlopen(req, timeout=timeout)) as resp:
            clen = resp.headers.get("Content-Length")
            etag = resp.headers.get("ETag")
            lm = resp.headers.get("Last-Modified")
            try:
                length = int(clen) if clen is not None else None
            except Exception:
                length = None
            return length, etag, lm

    def stream(self, uri: str, timeout: float, max_bytes: Optional[int]):
        import urllib.request
        req = urllib.request.Request(uri, method="GET", headers={
            "User-Agent": "oblivionvault-subject/1.0",
            "Accept-Encoding": "identity",   # важно для совпадения дайджеста
        })
        resp = urllib.request.urlopen(req, timeout=timeout)
        clen_hdr = resp.headers.get("Content-Length")
        media = resp.headers.get_content_type() if hasattr(resp.headers, "get_content_type") else resp.headers.get("Content-Type")
        etag = resp.headers.get("ETag")
        lm = resp.headers.get("Last-Modified")
        length = None
        try:
            length = int(clen_hdr) if clen_hdr is not None else None
        except Exception:
            pass
        if max_bytes is not None:
            # Если сервер не сообщил размер, будем контролировать на лету
            if length is not None and length > max_bytes:
                resp.close()
                raise SizeLimitExceeded(f"http content too large: {length} > {max_bytes}")
        def gen():
            read = 0
            try:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    read += len(chunk)
                    if max_bytes is not None and read > max_bytes:
                        raise SizeLimitExceeded(f"http stream exceeded {max_bytes} bytes")
                    yield chunk
            finally:
                resp.close()
        return gen(), length, media or "application/octet-stream", etag, lm


# =========================
# Основной верификатор
# =========================
@dataclass
class VerifierConfig:
    timeout: float = 15.0
    max_bytes: Optional[int] = 1024 * 1024 * 1024   # 1 GiB по умолчанию
    allowed_schemes: Tuple[str, ...] = ("file", "http", "https")
    # Каталог для кэширования/ETag (зарезервировано для будущего; текущая реализация без физического кэша)
    cache_dir: Optional[str] = None
    chunk_size: int = 1024 * 1024
    required_algs: Tuple[str, ...] = tuple()  # если указать — все эти алгоритмы должны присутствовать и совпасть


class SubjectVerifier:
    def __init__(self, cfg: Optional[VerifierConfig] = None):
        self.cfg = cfg or VerifierConfig()
        self._fetchers: Dict[str, Fetcher] = {
            "file": FileFetcher(),
            "http": HTTPFetcher(),
            "https": HTTPFetcher(),
        }

    def register_fetcher(self, scheme: str, fetcher: Fetcher) -> None:
        self._fetchers[scheme] = fetcher

    # -------- Публичные API ----------
    def verify_from_artifact_ref(
        self,
        ref: Mapping[str, Any],
        *,
        store_path: Optional[str] = None
    ) -> VerificationResult:
        uri = str(ref.get("uri", ""))
        if not uri:
            raise SubjectError("artifact_ref_uri_missing")
        digs = _parse_digest_items(ref.get("digests", []))
        size = ref.get("size_bytes")
        media = ref.get("media_type")
        return self.verify(uri, digs, expected_size=size, expected_media_type=media, store_path=store_path)

    def verify(
        self,
        uri: str,
        expected: Iterable[DigestSpec],
        *,
        expected_size: Optional[int] = None,
        expected_media_type: Optional[str] = None,
        store_path: Optional[str] = None
    ) -> VerificationResult:
        if _TRACER:
            with _TRACER.start_as_current_span("subject.verify") as span:
                span.set_attribute("uri", uri)
                return self._verify_impl(uri, list(expected), expected_size, expected_media_type, store_path)
        return self._verify_impl(uri, list(expected), expected_size, expected_media_type, store_path)

    # -------- Внутренняя логика ----------
    def _verify_impl(
        self,
        uri: str,
        expected: List[DigestSpec],
        expected_size: Optional[int],
        expected_media_type: Optional[str],
        store_path: Optional[str]
    ) -> VerificationResult:
        scheme = _scheme_of(uri)
        if scheme not in self.cfg.allowed_schemes:
            raise UnsupportedURI(f"scheme {scheme} not allowed")
        fetcher = self._fetchers.get(scheme)
        if not fetcher:
            raise UnsupportedURI(f"no fetcher for scheme {scheme}")

        # HEAD попытка (если поддерживается; для file вернёт размер локально)
        try:
            head_len, etag, last_modified = fetcher.head(uri, self.cfg.timeout)
        except Exception:
            head_len, etag, last_modified = None, None, None

        # Сверка ожидаемого размера до загрузки
        if expected_size is not None and head_len is not None and expected_size != head_len:
            raise SizeLimitExceeded(f"expected size {expected_size} != remote {head_len}")

        # Подготовка дайджестеров
        digesters: Dict[str, Any] = {}
        for ds in expected:
            a = _normalize_alg(ds.alg)
            if a not in digesters:
                digesters[a] = _digester_for(a)
        for a in self.cfg.required_algs:
            a = _normalize_alg(a)
            if a not in digesters:
                digesters[a] = _digester_for(a)

        # Начинаем потоковое чтение
        stream, content_len, media_type, etag2, lm2 = fetcher.stream(uri, self.cfg.timeout, self.cfg.max_bytes)
        etag = etag or etag2
        last_modified = last_modified or lm2

        stored_fp = None
        stored_final_path: Optional[str] = None
        if store_path:
            Path(store_path).parent.mkdir(parents=True, exist_ok=True)
            stored_fp = open(store_path, "wb")

        total = 0
        try:
            for chunk in stream:
                total += len(chunk)
                # дополнительная страховка лимита
                if self.cfg.max_bytes is not None and total > self.cfg.max_bytes:
                    raise SizeLimitExceeded(f"stream exceeded {self.cfg.max_bytes} bytes")
                if stored_fp:
                    stored_fp.write(chunk)
                for d in digesters.values():
                    d.update(chunk)
        finally:
            if stored_fp:
                stored_fp.flush()
                stored_fp.close()
                stored_final_path = store_path

        # Определяем медиа-тип при отсутствии
        if not media_type:
            media_type = "application/octet-stream"
            if scheme == "file":
                media_type = mimetypes.guess_type(uri)[0] or media_type

        # Размер и условие равенства ожидаемого
        size_ok = None
        if expected_size is not None:
            size_ok = (total == expected_size)

        # Формируем результат
        computed_hex = {alg: dig.hexdigest() if hasattr(dig, "hexdigest") else dig.digest().hex()
                        for alg, dig in digesters.items()}
        expected_hex = { _normalize_alg(ds.alg): ds.expected_hex for ds in expected }
        matched = { alg: (expected_hex.get(alg) == hx) for alg, hx in computed_hex.items() if alg in expected_hex }

        # Если заданы required_algs — они должны присутствовать в expected и совпасть
        if self.cfg.required_algs:
            for alg in self.cfg.required_algs:
                alg_n = _normalize_alg(alg)
                if alg_n not in expected_hex or matched.get(alg_n) is not True:
                    ok = False
                    res = VerificationResult(
                        ok=False, uri=uri, computed_hex=computed_hex, matched=matched,
                        expected_hex=expected_hex, size_ok=size_ok, size_bytes=total,
                        media_type=media_type, etag=etag, last_modified=last_modified,
                        stored_path=stored_final_path,
                        details={"reason": f"required_alg_mismatch:{alg_n}"}
                    )
                    _annotate_span(res)
                    return res

        # Итог: true, если есть хотя бы одно совпадение или вообще не было ожиданий
        ok = True
        if expected_hex:
            ok = any(matched.values()) and all(
                (expected_hex[a] == computed_hex.get(a)) for a in expected_hex.keys()
            )

        res = VerificationResult(
            ok=ok,
            uri=uri,
            computed_hex=computed_hex,
            matched=matched,
            expected_hex=expected_hex,
            size_ok=size_ok,
            size_bytes=total,
            media_type=expected_media_type or media_type,
            etag=etag,
            last_modified=last_modified,
            stored_path=stored_final_path,
            details={
                "head_content_length": content_len,
            }
        )
        _annotate_span(res)
        return res


# =========================
# Вспомогательные функции
# =========================
def _annotate_span(res: VerificationResult) -> None:
    if not _TRACER:
        return
    span = trace.get_current_span()
    try:
        span.set_attribute("subject.uri", res.uri)
        span.set_attribute("subject.ok", res.ok)
        span.set_attribute("subject.size_bytes", int(res.size_bytes or 0))
        if res.media_type:
            span.set_attribute("subject.media_type", res.media_type)
    except Exception:
        pass


def _scheme_of(uri: str) -> str:
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", uri)
    if not m:
        # трактуем как локальный путь
        return "file"
    return m.group(1).lower()


# =========================
# Пример использования (docstring)
# =========================
"""
Примеры:

from oblivionvault.requests.subject_verify import SubjectVerifier, VerifierConfig, DigestSpec

verifier = SubjectVerifier(VerifierConfig(timeout=10.0, max_bytes=100*1024*1024, required_algs=("sha256",)))

# 1) Локальный файл
res = verifier.verify(
    "file:///var/data/artifact.bin",
    [DigestSpec(alg="sha256", expected_hex="c0ffee...")]
).ensure_ok()

# 2) HTTP ресурс с сохранением на диск и проверкой размера
res = verifier.verify(
    "https://example.com/release.tar.gz",
    [DigestSpec(alg="sha256", expected_hex="deadbeef...")],
    expected_size=1234567,
    store_path="/tmp/release.tar.gz"
)

# 3) ArtifactRef-стиль
ref = {
  "uri": "https://example.com/a.bin",
  "digests": [{"alg":"sha256","hex":"..."}],
  "size_bytes": 42,
  "media_type": "application/octet-stream"
}
res = verifier.verify_from_artifact_ref(ref).ensure_ok()
"""

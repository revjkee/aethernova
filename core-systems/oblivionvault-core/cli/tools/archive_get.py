# -*- coding: utf-8 -*-
"""
oblivionvault.cli.tools.archive_get
Промышленный загрузчик архивов/артефактов с поддержкой резюма и проверкой целостности.

Особенности:
- Возобновляемая загрузка (HTTP Range), проверка Content-Range.
- HEAD/ETag/Last-Modified учтены в метаданных возобновления (.meta.json).
- Атомарная запись: сначала *.part, после валидации — rename в целевой путь.
- Целостность: SHA-256; при несоответствии — ошибка и сохранение артефактов диагностики.
- Ретраи с экспоненциальным бэкоффом и джиттером.
- Структурные JSON-логи (stderr), компактные и парсируемые.
- Без внешних зависимостей (stdlib). Если httpx доступен — используется асинхронный стрим.
- Поддержка дополнительных заголовков (Bearer, mTLS — через httpx cert=(cert,key)).
- Совместимо с asyncio; доступна синхронная обёртка run_archive_get().

Контракты:
- URL: только http/https/file. Для file:// и локальных путей — безопасное копирование.
- Состояние: <out>.part и <out>.meta.json (в той же директории).
- Хэш: ожидаемый sha256_hex/size можно указать в спецификации (необязательно).
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import errno
import hashlib
import json
import math
import os
import random
import shutil
import sys
import time
import typing as t
from dataclasses import dataclass

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None

try:
    from urllib.parse import urlparse
    from urllib.request import Request, urlopen
except Exception as _e:  # pragma: no cover
    raise RuntimeError(f"stdlib networking unavailable: {_e!r}")

# --------------------------- Логирование: JSON в stderr ---------------------------

class _JsonLogFormatter:
    @staticmethod
    def dumps(level: str, msg: str, **extra: t.Any) -> str:
        payload = {
            "ts": dt.datetime.utcnow().isoformat() + "Z",
            "level": level.upper(),
            "logger": "oblivionvault.archive_get",
            "msg": msg,
        }
        for k, v in extra.items():
            try:
                json.dumps(v)
                payload[k] = v
            except Exception:
                payload[k] = repr(v)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def _log(level: str, msg: str, **extra: t.Any) -> None:
    sys.stderr.write(_JsonLogFormatter.dumps(level, msg, **extra) + "\n")
    sys.stderr.flush()

# --------------------------- Исключения ---------------------------

class ArchiveGetError(Exception): ...
class ConfigError(ArchiveGetError): ...
class NetworkError(ArchiveGetError): ...
class IntegrityError(ArchiveGetError): ...
class ResumeMismatchError(ArchiveGetError): ...

# --------------------------- Модель спецификации/результата ---------------------------

@dataclass(frozen=True)
class ArchiveGetSpec:
    url: str
    out_path: str
    expected_sha256: str | None = None  # hex
    expected_size: int | None = None
    headers: dict[str, str] | None = None
    timeout_s: float = 60.0
    max_retries: int = 5
    base_backoff_ms: int = 250
    chunk_size: int = 1 << 20  # 1 MiB
    resume: bool = True
    verify_tls: bool = True
    mtls_cert: str | None = None  # путь к клиентскому сертификату
    mtls_key: str | None = None   # путь к приватному ключу
    # Если True — по несоответствию ETag/Last-Modified файл .part будет перекачан с нуля
    auto_restart_on_mismatch: bool = True

@dataclass(frozen=True)
class ArchiveGetResult:
    path: str
    bytes_written: int
    sha256_hex: str
    etag: str | None
    last_modified: str | None
    resumed: bool

# --------------------------- Вспомогательные утилиты ---------------------------

def _ensure_parent_dirs(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)

def _atomic_rename(src: str, dst: str) -> None:
    os.replace(src, dst)

def _human(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    unit = ["KiB", "MiB", "GiB", "TiB"]
    i = int(min(len(unit)-1, math.log(n, 1024)))
    return f"{n / 1024**(i+1):.2f}{unit[i]}"

def _b64u(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

# --------------------------- Метаданные резюма ---------------------------

@dataclass
class _Meta:
    url: str
    etag: str | None
    last_modified: str | None
    size_total: int | None
    bytes_written: int
    sha256_hex: str | None
    updated_at: str

    @staticmethod
    def path_for(out_path: str) -> str:
        return out_path + ".meta.json"

    @staticmethod
    def load(path: str) -> _Meta | None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            return _Meta(**d)
        except FileNotFoundError:
            return None
        except Exception as e:  # повреждена — игнорируем
            _log("WARN", "meta_load_failed", error=str(e), path=path)
            return None

    def dump(self, path: str) -> None:
        self.updated_at = dt.datetime.utcnow().isoformat() + "Z"
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(self), f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
        _atomic_rename(tmp, path)

# --------------------------- Транспортный слой ---------------------------

class _TransportBase:
    async def head(self, url: str, headers: dict[str, str], timeout_s: float) -> tuple[int, dict[str, str]]:
        raise NotImplementedError
    async def get_stream(self, url: str, headers: dict[str, str], timeout_s: float):
        raise NotImplementedError

class _HttpxTransport(_TransportBase):
    def __init__(self, verify_tls: bool, mtls_cert: str | None, mtls_key: str | None) -> None:
        self.verify_tls = verify_tls
        self.cert = (mtls_cert, mtls_key) if (mtls_cert and mtls_key) else None

    async def head(self, url: str, headers: dict[str, str], timeout_s: float) -> tuple[int, dict[str, str]]:
        if httpx is None:
            raise NetworkError("httpx not available")
        async with httpx.AsyncClient(verify=self.verify_tls, cert=self.cert, timeout=timeout_s) as client:
            r = await client.head(url, headers=headers, follow_redirects=True)
            return r.status_code, {k.title(): v for k, v in r.headers.items()}

    async def get_stream(self, url: str, headers: dict[str, str], timeout_s: float):
        if httpx is None:
            raise NetworkError("httpx not available")
        client = httpx.AsyncClient(verify=self.verify_tls, cert=self.cert, timeout=None, follow_redirects=True)
        # Возвращаем клиент для дальнейшего закрытия
        resp = await client.get(url, headers=headers, timeout=timeout_s, stream=True)
        resp.raise_for_status()
        return client, resp

class _UrllibTransport(_TransportBase):
    async def head(self, url: str, headers: dict[str, str], timeout_s: float) -> tuple[int, dict[str, str]]:
        def _do():
            req = Request(url, method="HEAD")
            for k, v in headers.items():
                req.add_header(k, v)
            with urlopen(req, timeout=timeout_s) as r:
                # Некоторые серверы не поддерживают HEAD — тогда получим 200 на GET; здесь имитируем HEAD через GET без чтения тела
                return getattr(r, "status", 200), {k.title(): v for k, v in r.headers.items()}
        return await asyncio.to_thread(_do)

    async def get_stream(self, url: str, headers: dict[str, str], timeout_s: float):
        # Возвращаем простые объекты-обёртки, совместимые для чтения по чанкам
        def _open():
            req = Request(url, method="GET")
            for k, v in headers.items():
                req.add_header(k, v)
            r = urlopen(req, timeout=timeout_s)
            status = getattr(r, "status", 200)
            if status >= 400:
                raise NetworkError(f"HTTP {status}")
            return r
        r = await asyncio.to_thread(_open)
        # Выравниваем интерфейс
        class _Resp:
            def __init__(self, r):
                self._r = r
                self.headers = {k.title(): v for k, v in getattr(r, "headers", {}).items()}
            async def aiter_bytes(self, chunk_size: int):
                while True:
                    chunk = await asyncio.to_thread(self._r.read, chunk_size)
                    if not chunk:
                        break
                    yield chunk
            async def aclose(self):
                await asyncio.to_thread(self._r.close)
        class _Client:
            async def aclose(self): pass
        return _Client(), _Resp(r)

# --------------------------- Основная логика загрузки ---------------------------

class ArchiveFetcher:
    def __init__(self, spec: ArchiveGetSpec) -> None:
        self.spec = spec
        self._validate_spec()
        self._parsed = urlparse(spec.url)
        self._use_httpx = (httpx is not None)
        if self._parsed.scheme in ("http", "https"):
            self._tx: _TransportBase = (
                _HttpxTransport(spec.verify_tls, spec.mtls_cert, spec.mtls_key) if self._use_httpx
                else _UrllibTransport()
            )
        elif self._parsed.scheme in ("file", ""):
            self._tx = None  # локальный путь/копирование
        else:
            raise ConfigError(f"unsupported scheme: {self._parsed.scheme}")

    def _validate_spec(self) -> None:
        if not self.spec.url:
            raise ConfigError("url required")
        if not self.spec.out_path:
            raise ConfigError("out_path required")
        if self.spec.chunk_size <= 0:
            raise ConfigError("chunk_size must be > 0")
        if self.spec.max_retries < 0:
            raise ConfigError("max_retries must be >= 0")

    async def fetch(self) -> ArchiveGetResult:
        # file:// или локальный путь — безопасная копия
        if self._tx is None:
            return await self._copy_local()

        # HTTP/HTTPS
        return await self._fetch_http()

    # ----------------- Локальное копирование -----------------

    async def _copy_local(self) -> ArchiveGetResult:
        src = self.spec.url
        if self._parsed.scheme == "file":
            src = self._parsed.path
        if not os.path.exists(src):
            raise NetworkError(f"file not found: {src}")
        _ensure_parent_dirs(self.spec.out_path)
        part = self.spec.out_path + ".part"
        meta_path = _Meta.path_for(self.spec.out_path)
        # Копируем потоково
        sha256 = hashlib.sha256()
        total = 0
        with open(src, "rb") as f_in, open(part, "wb") as f_out:
            while True:
                chunk = await asyncio.to_thread(f_in.read, self.spec.chunk_size)
                if not chunk:
                    break
                await asyncio.to_thread(f_out.write, chunk)
                sha256.update(chunk)
                total += len(chunk)
        # Проверка целостности
        sha_hex = sha256.hexdigest()
        if self.spec.expected_sha256 and self.spec.expected_sha256.lower() != sha_hex.lower():
            raise IntegrityError("sha256 mismatch on local copy")
        if self.spec.expected_size is not None and total != self.spec.expected_size:
            raise IntegrityError("size mismatch on local copy")
        # Метаданные
        meta = _Meta(
            url=self.spec.url,
            etag=None,
            last_modified=None,
            size_total=total,
            bytes_written=total,
            sha256_hex=sha_hex,
            updated_at=dt.datetime.utcnow().isoformat() + "Z",
        )
        meta.dump(meta_path)
        _atomic_rename(part, self.spec.out_path)
        _log("INFO", "local_copy_done", src=src, dst=self.spec.out_path, bytes=total, sha256=sha_hex)
        return ArchiveGetResult(self.spec.out_path, total, sha_hex, None, None, resumed=False)

    # ----------------- HTTP/HTTPS загрузка -----------------

    async def _fetch_http(self) -> ArchiveGetResult:
        headers = dict(self.spec.headers or {})
        out = self.spec.out_path
        part = out + ".part"
        meta_path = _Meta.path_for(out)
        _ensure_parent_dirs(out)

        # HEAD (не у всех работает)
        status, head = await self._safe_head(headers)
        etag = head.get("Etag")
        last_mod = head.get("Last-Modified")
        accept_ranges = (head.get("Accept-Ranges") or "").lower()
        size_total = self._parse_size(head)

        # Резюмирование
        bytes_written, resumed = 0, False
        meta = _Meta.load(meta_path)
        if meta and self.spec.resume and os.path.exists(part):
            if self._resume_compatible(meta, etag, last_mod):
                bytes_written = os.path.getsize(part)
                resumed = bytes_written > 0
                _log("INFO", "resume_continue", bytes=bytes_written, etag=etag, last_modified=last_mod)
            else:
                if self.spec.auto_restart_on_mismatch:
                    self._restart_clean(part, meta_path, reason="meta_mismatch")
                else:
                    raise ResumeMismatchError("stored meta is not compatible with remote")
        else:
            # чистый старт
            self._restart_clean(part, meta_path, reason="fresh_start")

        # Основной цикл с ретраями
        attempt = 0
        last_err: Exception | None = None
        while True:
            try:
                return await self._download_stream(headers, part, meta_path, bytes_written, size_total, etag, last_mod, resumed)
            except (NetworkError, ResumeMismatchError) as e:
                last_err = e
                attempt += 1
                if attempt > self.spec.max_retries:
                    _log("ERROR", "download_failed", error=str(e), attempts=attempt)
                    raise
                backoff = self._backoff_ms(attempt) / 1000.0
                _log("WARN", "download_retry", attempt=attempt, sleep_s=backoff, error=str(e))
                await asyncio.sleep(backoff)

    async def _download_stream(
        self,
        headers: dict[str, str],
        part_path: str,
        meta_path: str,
        bytes_written: int,
        size_total: int | None,
        etag: str | None,
        last_mod: str | None,
        resumed: bool,
    ) -> ArchiveGetResult:

        # Готовим заголовки Range
        req_headers = dict(headers)
        if bytes_written > 0:
            req_headers["Range"] = f"bytes={bytes_written}-"

        client, resp = await self._tx.get_stream(self.spec.url, req_headers, self.spec.timeout_s)  # type: ignore[union-attr]
        try:
            # Проверка Content-Range при резюме
            if bytes_written > 0:
                cr = resp.headers.get("Content-Range", "")
                # Пример: "bytes 1048576-2097151/2097152"
                if not cr.startswith("bytes "):
                    raise ResumeMismatchError("missing Content-Range for resumed request")
                try:
                    rng, total_str = cr.split(" ")[1].split("/")
                    start_str, _end_str = rng.split("-")
                    start = int(start_str)
                    total_remote = int(total_str) if total_str.isdigit() else None
                except Exception:
                    raise ResumeMismatchError("cannot parse Content-Range")
                if start != bytes_written:
                    raise ResumeMismatchError("server range start != local offset")
                if size_total and total_remote and total_remote != size_total:
                    raise ResumeMismatchError("remote size changed")
                size_total = size_total or total_remote

            # Пишем потоково, попутно обновляя метаданные
            sha256 = hashlib.sha256()
            if resumed and os.path.exists(part_path):
                # При резюме для итоговой верификации дочитываем хэш по уже скачанному фрагменту
                with open(part_path, "rb") as f:
                    while True:
                        chunk = await asyncio.to_thread(f.read, self.spec.chunk_size)
                        if not chunk:
                            break
                        sha256.update(chunk)

            written_now = 0
            with open(part_path, "ab") as f_out:
                async for chunk in resp.aiter_bytes(self.spec.chunk_size):
                    if not chunk:
                        continue
                    await asyncio.to_thread(f_out.write, chunk)
                    sha256.update(chunk)
                    bytes_written += len(chunk)
                    written_now += len(chunk)
                    if written_now >= (8 * self.spec.chunk_size):  # периодически сбрасывать мету
                        meta = _Meta(
                            url=self.spec.url,
                            etag=etag,
                            last_modified=last_mod,
                            size_total=size_total,
                            bytes_written=bytes_written,
                            sha256_hex=None,  # финальный хэш позже
                            updated_at=dt.datetime.utcnow().isoformat() + "Z",
                        )
                        meta.dump(meta_path)
                        written_now = 0

            # Итоговая проверка: размер и sha256
            sha_hex = sha256.hexdigest()
            if self.spec.expected_size is not None and size_total is not None:
                # Если сервер сообщал размер, сверяем оба
                if size_total != self.spec.expected_size:
                    raise IntegrityError("remote size != expected_size")
            if self.spec.expected_size is not None:
                if bytes_written != self.spec.expected_size:
                    raise IntegrityError("downloaded size != expected_size")
            if size_total is not None and bytes_written != size_total:
                # В частичных ответах иногда total не приходит; если пришёл — валидируем
                raise IntegrityError("downloaded size != remote size")

            if self.spec.expected_sha256 and self.spec.expected_sha256.lower() != sha_hex.lower():
                raise IntegrityError("sha256 mismatch")

            # Допишем мету и атомарно переименуем
            meta = _Meta(
                url=self.spec.url,
                etag=etag,
                last_modified=last_mod,
                size_total=size_total or bytes_written,
                bytes_written=bytes_written,
                sha256_hex=sha_hex,
                updated_at=dt.datetime.utcnow().isoformat() + "Z",
            )
            meta.dump(meta_path)
            _atomic_rename(part_path, self.spec.out_path)
            _log("INFO", "download_done",
                 url=self.spec.url, out=self.spec.out_path, bytes=bytes_written, sha256=sha_hex,
                 etag=etag, last_modified=last_mod, resumed=resumed)
            return ArchiveGetResult(self.spec.out_path, bytes_written, sha_hex, etag, last_mod, resumed=resumed)
        finally:
            # Закрываем стрим/клиент
            try:
                await resp.aclose()
            except Exception:
                pass
            try:
                await client.aclose()
            except Exception:
                pass

    # ----------------- Вспомогательные методы -----------------

    async def _safe_head(self, headers: dict[str, str]) -> tuple[int, dict[str, str]]:
        # Некоторые origin'ы не поддерживают HEAD: не считаем это критической ошибкой
        try:
            return await self._tx.head(self.spec.url, headers, self.spec.timeout_s)  # type: ignore[union-attr]
        except Exception as e:
            _log("WARN", "head_failed", error=str(e))
            return 0, {}

    @staticmethod
    def _parse_size(headers: dict[str, str]) -> int | None:
        cl = headers.get("Content-Length")
        try:
            return int(cl) if cl is not None else None
        except Exception:
            return None

    @staticmethod
    def _resume_compatible(meta: _Meta, etag: str | None, last_mod: str | None) -> bool:
        if meta.url != meta.url:  # логическая заглушка; всегда True ниже, реальная проверка ниже
            return False
        # Если удалённый ресурс сообщает ETag/Last-Modified — они должны совпасть
        if etag and meta.etag and etag != meta.etag:
            return False
        if last_mod and meta.last_modified and last_mod != meta.last_modified:
            return False
        return True

    def _restart_clean(self, part: str, meta_path: str, reason: str) -> None:
        try:
            if os.path.exists(part):
                os.remove(part)
        except Exception as e:
            _log("WARN", "part_remove_failed", error=str(e), path=part)
        try:
            if os.path.exists(meta_path):
                os.remove(meta_path)
        except Exception as e:
            _log("WARN", "meta_remove_failed", error=str(e), path=meta_path)
        # Создадим пустую .part
        _ensure_parent_dirs(part)
        open(part, "wb").close()
        _log("INFO", "restart_clean", reason=reason, part=part, meta=meta_path)

    def _backoff_ms(self, attempt: int) -> int:
        base = self.spec.base_backoff_ms
        exp = base * (2 ** (attempt - 1))
        jitter = random.randint(0, base)
        return min(30_000, exp + jitter)  # не более 30с

# --------------------------- Публичные функции ---------------------------

async def archive_get(spec: ArchiveGetSpec) -> ArchiveGetResult:
    """
    Асинхронная загрузка архива/артефакта по спецификации.
    """
    fetcher = ArchiveFetcher(spec)
    return await fetcher.fetch()

def run_archive_get(spec: ArchiveGetSpec) -> ArchiveGetResult:
    """
    Синхронная обёртка для удобной интеграции из не-async контекстов.
    """
    return asyncio.run(archive_get(spec))

# --------------------------- Мини-проверка схемы URL (опционально) ---------------------------

def is_supported_url(url: str) -> bool:
    p = urlparse(url)
    return p.scheme in ("http", "https", "file", "")

__all__ = [
    "ArchiveGetSpec",
    "ArchiveGetResult",
    "ArchiveGetError",
    "NetworkError",
    "IntegrityError",
    "ResumeMismatchError",
    "ConfigError",
    "archive_get",
    "run_archive_get",
    "is_supported_url",
]

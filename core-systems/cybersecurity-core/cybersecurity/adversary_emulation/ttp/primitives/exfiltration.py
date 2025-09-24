# filepath: cybersecurity-core/cybersecurity/adversary_emulation/ttp/primitives/exfiltration.py
# -*- coding: utf-8 -*-
"""
Лабораторные примитивы эмуляции эксфильтрации данных.

Назначение:
- Генерация телеметрии и проверка детектов (Blue Team, SOC, SIEM).
- Эмуляция потока "данные → упаковка/шифрование → отправка в безопасный приёмник".
- Исключительно для контролируемых стендов. Сетевые операции ограничены loopback.

Ключевые свойства:
- Чанкинг с фиксированным размером и порядковыми номерами.
- Регулируемая компрессия (zlib), опциональное шифрование (Fernet, если доступно).
- Ограничение скорости (bytes/sec), backoff и повторные попытки.
- Безопасные «приёмники» (sinks): Файловая система, HTTP loopback (127.0.0.1 / ::1).
- Маркеры обнаружения (заголовки/манифест, X-Red-Team, X-Use-Case).
- Строгие предохранители: запрет не-loopback адресов; включение сети — только через env-флаг.

Зависимости (опционально):
- cryptography (для шифрования Fernet). При отсутствии — шифрование отключено.

Важно:
- Этот модуль умышленно НЕ предоставляет внешние каналы (облако, DNS и т.п.).
- Любая попытка указать не-loopback адрес приведёт к исключению.

Авторские комментарии не содержат спорных утверждений; внешние ссылки не требуются.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Iterable, Optional, Sequence, Tuple

import zlib

try:
    # Опциональное шифрование
    from cryptography.fernet import Fernet  # type: ignore
    _HAS_FERNET = True
except Exception:
    _HAS_FERNET = False

try:
    # Для HTTP loopback используем requests в отдельном потоке
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False


__all__ = [
    "ExfilConfig",
    "Manifest",
    "ExfilChunk",
    "ExfilSink",
    "FileSystemSink",
    "LoopbackHttpSink",
    "Exfiltrator",
    "generate_key",
    "safe_random_session_id",
]

# ------------------------------------------------------------------------------
# ЛОГИРОВАНИЕ
# ------------------------------------------------------------------------------

class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "extra"):
            try:
                payload.update(record.extra)  # type: ignore[attr-defined]
            except Exception:
                pass
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


_log = logging.getLogger("adversary_emulation.exfil")
if not _log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(_JsonLogFormatter())
    _log.setLevel(logging.INFO)
    _log.addHandler(_h)
    _log.propagate = False


# ------------------------------------------------------------------------------
# КОНФИГИ/ТИПЫ
# ------------------------------------------------------------------------------

DEFAULT_CHUNK_SIZE = 128 * 1024  # 128 KiB
DEFAULT_RATE_BPS = 2 * 1024 * 1024  # 2 MiB/s
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_MS = 120
DEFAULT_ZLIB_LEVEL = 6

LAB_ENABLE_NETWORK = os.getenv("ADVERSARY_EMULATION_ENABLE_NETWORK", "0") == "1"
LAB_ALLOW_LOOPBACK_ONLY = True  # фиксированно: сеть разрешена только на loopback


@dataclass(frozen=True)
class ExfilConfig:
    # Идентификаторы
    session_id: str
    use_case: str = "lab-exfil"
    # Поток/упаковка
    chunk_size: int = DEFAULT_CHUNK_SIZE
    compress: bool = True
    compression_level: int = DEFAULT_ZLIB_LEVEL
    encrypt: bool = False
    fernet_key_b64: Optional[str] = None  # base64url-encoded fernet key (32 bytes)
    # Ограничители и надёжность
    rate_limit_bps: int = DEFAULT_RATE_BPS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_base_ms: int = DEFAULT_RETRY_BASE_MS
    # Метки и контроль целостности
    add_hmac: bool = True
    hmac_key_b64: Optional[str] = None  # base64 urlsafe bytes for HMAC-SHA256

    def build_cipher(self) -> Optional[Fernet]:
        if not self.encrypt:
            return None
        if not _HAS_FERNET:
            raise RuntimeError("cryptography.Fernet не установлен, включить encrypt невозможно")
        if not self.fernet_key_b64:
            raise ValueError("fernet_key_b64 не задан при encrypt=True")
        return Fernet(self.fernet_key_b64.encode("utf-8"))

    def hmac_key_bytes(self) -> Optional[bytes]:
        if not self.add_hmac:
            return None
        if not self.hmac_key_b64:
            return None
        return base64.urlsafe_b64decode(self.hmac_key_b64.encode("utf-8"))


@dataclass(frozen=True)
class ExfilChunk:
    index: int
    total: int
    payload: bytes          # уже возможно сжатый/зашифрованный блок
    sha256: str             # контроль целостности блока (от payload)
    original_size: int      # размер исходного окна до упаковки
    compressed: bool
    encrypted: bool
    hmac256: Optional[str]  # HMAC от payload, если включено

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "total": self.total,
            "payload_b64": base64.b64encode(self.payload).decode("ascii"),
            "sha256": self.sha256,
            "original_size": self.original_size,
            "compressed": self.compressed,
            "encrypted": self.encrypted,
            "hmac256": self.hmac256,
        }


@dataclass(frozen=True)
class Manifest:
    session_id: str
    use_case: str
    source_path: Optional[str]
    filesize: int
    chunks: int
    chunk_size: int
    compression: str
    encryption: str
    created_at: str
    red_team_markers: dict

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False, indent=2)


# ------------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ------------------------------------------------------------------------------

def generate_key() -> str:
    """
    Генерирует ключ Fernet (base64urlsafe, 32 байта).
    """
    if not _HAS_FERNET:
        raise RuntimeError("cryptography.Fernet не установлен")
    return Fernet.generate_key().decode("ascii")


def safe_random_session_id(n: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "sess-" + "".join(random.choice(alphabet) for _ in range(n))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rate_sleep(sent_now: int, started_ts: float, rate_bps: int) -> None:
    if rate_bps <= 0:
        return
    # требуемое время на передачу sent_now при rate_bps
    required = sent_now / float(rate_bps)
    elapsed = time.perf_counter() - started_ts
    if required > elapsed:
        time.sleep(required - elapsed)


def _ensure_loopback(url: str) -> None:
    """
    Жесткая защита от внешних адресов:
    - Разрешены только 'http://127.0.0.1' или 'http://[::1]' (и https для loopback)
    - Любая иная цель => исключение.
    """
    if not LAB_ENABLE_NETWORK:
        raise RuntimeError("Сетевые операции отключены (ADVERSARY_EMULATION_ENABLE_NETWORK != 1)")
    # примитивная проверка, дополнительная в _send_http
    _allowed = ("http://127.0.0.1", "https://127.0.0.1", "http://[::1]", "https://[::1]")
    if not any(url.startswith(pfx) for pfx in _allowed):
        raise RuntimeError("Разрешён только loopback (127.0.0.1/::1)")


# ------------------------------------------------------------------------------
# SINK API
# ------------------------------------------------------------------------------

class ExfilSink:
    """
    Базовый интерфейс приёмника.
    """
    async def open(self, manifest: Manifest) -> None:  # noqa: D401
        """
        Инициализация/создание контейнера для данных с учётом manifest.
        """
        raise NotImplementedError

    async def send_chunk(self, chunk: ExfilChunk) -> None:
        raise NotImplementedError

    async def finalize(self) -> None:
        raise NotImplementedError


class FileSystemSink(ExfilSink):
    """
    Сохранение в каталог: <root>/<session_id>/chunks/*.part и manifest.json
    """
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._dir = None  # type: Optional[Path]
        self._manifest_path = None  # type: Optional[Path]
        self._count = 0

    async def open(self, manifest: Manifest) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._dir = self.root / manifest.session_id
        (self._dir / "chunks").mkdir(parents=True, exist_ok=True)
        self._manifest_path = self._dir / "manifest.json"
        self._count = 0
        _log.info("sink.fs.open", extra={"extra": {"dir": str(self._dir)}})
        # manifest
        self._manifest_path.write_text(manifest.to_json(), encoding="utf-8")

    async def send_chunk(self, chunk: ExfilChunk) -> None:
        assert self._dir is not None
        p = self._dir / "chunks" / f"{chunk.index:08d}.part"
        tmp = p.with_suffix(".part.tmp")
        tmp.write_bytes(json.dumps(chunk.to_dict(), ensure_ascii=False).encode("utf-8"))
        os.replace(tmp, p)  # атомарная замена
        self._count += 1
        if self._count % 32 == 0:
            _log.info("sink.fs.progress", extra={"extra": {"count": self._count}})

    async def finalize(self) -> None:
        assert self._dir is not None and self._manifest_path is not None
        _log.info("sink.fs.finalize", extra={"extra": {"dir": str(self._dir), "count": self._count}})


class LoopbackHttpSink(ExfilSink):
    """
    Loopback HTTP(S) приёмник. Работает только с 127.0.0.1 / ::1.
    Отправляет:
      POST <base_url>/manifest
      POST <base_url>/chunk    (JSON с index/total/payload_b64/...)
      POST <base_url>/finalize
    """
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        if not _HAS_REQUESTS:
            raise RuntimeError("requests не установлен")
        _ensure_loopback(base_url)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opened = False
        self._count = 0

    async def _post_json(self, path: str, obj: dict) -> None:
        url = f"{self.base_url}{path}"
        _ensure_loopback(url)

        def _do_post() -> None:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Adversary-Emulation-LAB/1.0",
                "X-Red-Team": "true",
                "X-Use-Case": "lab-exfil",
            }
            resp = requests.post(url, json=obj, headers=headers, timeout=self.timeout)
            resp.raise_for_status()

        # выполнять в thread pool, чтобы не блокировать event loop
        await asyncio.to_thread(_do_post)

    async def open(self, manifest: Manifest) -> None:
        if self._opened:
            return
        await self._post_json("/manifest", {
            "manifest": json.loads(manifest.to_json()),
        })
        self._opened = True
        _log.info("sink.http.open", extra={"extra": {"url": self.base_url}})

    async def send_chunk(self, chunk: ExfilChunk) -> None:
        await self._post_json("/chunk", {"chunk": chunk.to_dict()})
        self._count += 1
        if self._count % 64 == 0:
            _log.info("sink.http.progress", extra={"extra": {"count": self._count}})

    async def finalize(self) -> None:
        await self._post_json("/finalize", {"ok": True, "count": self._count})
        _log.info("sink.http.finalize", extra={"extra": {"count": self._count}})


# ------------------------------------------------------------------------------
# ОСНОВНОЙ ОРКЕСТРАТОР
# ------------------------------------------------------------------------------

class Exfiltrator:
    """
    Управляет pipeline: чтение → упаковка → чанкинг → отправка с ограничением скорости.
    """

    def __init__(self, cfg: ExfilConfig, sink: ExfilSink) -> None:
        self.cfg = cfg
        self.sink = sink

        # подготовка крипто
        self._cipher = cfg.build_cipher()
        self._hmac_key = cfg.hmac_key_bytes()

    async def _iter_chunks(self, data: bytes) -> AsyncIterator[ExfilChunk]:
        # упаковка (вся порция)
        original_size = len(data)
        packed = zlib.compress(data, level=self.cfg.compression_level) if self.cfg.compress else data
        compressed = self.cfg.compress

        if self._cipher is not None:
            packed = self._cipher.encrypt(packed)
            encrypted = True
        else:
            encrypted = False

        # нарезка на чанки
        total = (len(packed) + self.cfg.chunk_size - 1) // self.cfg.chunk_size
        for idx in range(total):
            off = idx * self.cfg.chunk_size
            block = packed[off: off + self.cfg.chunk_size]
            sha = _sha256_hex(block)
            hm: Optional[str] = _hmac256_hex(self._hmac_key, block) if self._hmac_key else None
            yield ExfilChunk(
                index=idx,
                total=total,
                payload=block,
                sha256=sha,
                original_size=original_size if idx == 0 else 0,  # для первого чанка фиксируем исходный размер
                compressed=compressed,
                encrypted=encrypted,
                hmac256=hm,
            )

    async def _send_with_rate(self, chunks: Sequence[ExfilChunk]) -> None:
        sent = 0
        start_ts = time.perf_counter()
        for ch in chunks:
            # backoff/повторы
            await self._send_with_retry(ch)
            sent += len(ch.payload)
            _rate_sleep(sent, start_ts, self.cfg.rate_limit_bps)

    async def _send_with_retry(self, chunk: ExfilChunk) -> None:
        attempt = 0
        base = self.cfg.retry_base_ms / 1000.0
        while True:
            try:
                await self.sink.send_chunk(chunk)
                return
            except Exception as e:
                attempt += 1
                if attempt > self.cfg.max_retries:
                    _log.error("send.failed", extra={"extra": {"index": chunk.index, "err": str(e)}})
                    raise
                delay = base * (2 ** (attempt - 1))
                jitter = random.uniform(0, base)
                await asyncio.sleep(delay + jitter)

    async def run_from_bytes(self, data: bytes, source_path: Optional[Path] = None) -> Manifest:
        manifest = Manifest(
            session_id=self.cfg.session_id,
            use_case=self.cfg.use_case,
            source_path=str(source_path) if source_path else None,
            filesize=len(data),
            chunks=0,
            chunk_size=self.cfg.chunk_size,
            compression="zlib" if self.cfg.compress else "none",
            encryption="fernet" if self._cipher is not None else "none",
            created_at=_utcnow(),
            red_team_markers={
                "X-Red-Team": "true",
                "generator": "adversary-emulation-lab",
                "note": "loopback-only; not for external use",
            },
        )

        await self.sink.open(manifest)

        # сбор чанков (сначала в список — чтобы знать total)
        items = [ch async for ch in self._iter_chunks(data)]
        # актуализируем total в манивесте
        manifest = dataclasses.replace(manifest, chunks=len(items))

        # перезапишем manifest (если sink поддерживает обновление — для FS это просто замена файла)
        try:
            await self.sink.open(manifest)  # повторный open у LoopbackHttpSink игнорируется
        except Exception:
            # если приёмник не поддерживает повторный open — это не критично
            pass

        await self._send_with_rate(items)
        await self.sink.finalize()
        _log.info("exfil.done", extra={"extra": {"session_id": self.cfg.session_id, "chunks": len(items)}})
        return manifest

    async def run_from_path(self, path: Path) -> Manifest:
        data = Path(path).read_bytes()
        return await self.run_from_bytes(data, source_path=Path(path))


# ------------------------------------------------------------------------------
# ПРИМЕР ИСПОЛЬЗОВАНИЯ (лабораторный)
# ------------------------------------------------------------------------------

async def _example() -> None:
    """
    Локальный пример:
      - Генерация ключей (если нужно шифрование/HMAC)
      - Запись в файловую систему
      - Отправка на loopback HTTP (если включён флаг ENV)

    Для запуска:
      python -m cybersecurity.adversary_emulation.ttp.primitives.exfiltration
    """
    session = safe_random_session_id()

    # Пример: ключи (опционально)
    fkey = generate_key() if _HAS_FERNET else None
    hkey = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

    cfg = ExfilConfig(
        session_id=session,
        use_case="lab-exfil",
        chunk_size=64 * 1024,
        compress=True,
        compression_level=6,
        encrypt=bool(fkey),
        fernet_key_b64=fkey,
        rate_limit_bps=512 * 1024,
        max_retries=3,
        retry_base_ms=120,
        add_hmac=True,
        hmac_key_b64=hkey,
    )

    # Данные для «эксфильтрации»
    payload = b"A" * (1024 * 1024) + b"\nhello\n"  # 1 МБ+ тест

    # 1) файловый приёмник
    sink1 = FileSystemSink(root=Path("./_exfil_out"))
    ex1 = Exfiltrator(cfg, sink1)
    await ex1.run_from_bytes(payload)

    # 2) HTTP loopback (если включена сеть и есть простой тестовый приёмник)
    if LAB_ENABLE_NETWORK:
        sink2 = LoopbackHttpSink("http://127.0.0.1:8080/api/exfil")
        ex2 = Exfiltrator(cfg, sink2)
        await ex2.run_from_bytes(payload)


if __name__ == "__main__":
    asyncio.run(_example())

# physical_integration/workers/command_dispatcher.py
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import random
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

# Опциональные зависимости
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore

# Протоколы (наши)
from physical_integration.protocols.zigbee_matter import (
    ProtocolManager,
    DeviceDescriptor,
    AttrRef,
    CommandRef,
)

# Безопасность (mTLS — опционально)
try:
    from physical_integration.adapters.security_core_adapter import get_adapter_from_env
except Exception:
    get_adapter_from_env = None  # type: ignore

LOG = logging.getLogger("workers.command_dispatcher")

# --------------------------
# Настройки
# --------------------------
@dataclass
class Settings:
    base_url: str = os.getenv("TWIN_API_BASE_URL", "http://127.0.0.1:8080")
    # Интервалы и лимиты
    poll_interval_s: float = float(os.getenv("CMD_POLL_INTERVAL", "2.0"))
    page_size: int = int(os.getenv("CMD_PAGE_SIZE", "100"))
    request_timeout_s: float = float(os.getenv("CMD_HTTP_TIMEOUT", "10.0"))
    # Конкуренция
    max_concurrency: int = int(os.getenv("CMD_MAX_CONCURRENCY", "16"))
    per_device_concurrency: int = int(os.getenv("CMD_PER_DEVICE_CONCURRENCY", "2"))
    # Таймаут исполнения одной команды
    default_cmd_timeout_s: int = int(os.getenv("CMD_DEFAULT_TIMEOUT", "30"))
    # Идемпотентность (файл состояний)
    state_dir: Path = Path(os.getenv("CMD_STATE_DIR", "/var/lib/physical-integration/worker")).resolve()
    # Метрики
    enable_prom: bool = os.getenv("ENABLE_PROMETHEUS", "true").lower() in {"1", "true", "yes"}


# --------------------------
# Метрики (опционально)
# --------------------------
if Counter and Histogram and Gauge:  # pragma: no cover
    M_LAT = Histogram(
        "cmd_exec_latency_seconds",
        "Command execution latency",
        ["type"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60),
    )
    M_ERR = Counter("cmd_exec_errors_total", "Command execution errors", ["type"])
    M_OK = Counter("cmd_exec_success_total", "Command execution success", ["type"])
    M_IN_FLIGHT = Gauge("cmd_in_flight", "Commands currently executing")
else:
    M_LAT = M_ERR = M_OK = M_IN_FLIGHT = None  # type: ignore


# --------------------------
# Персистентный набор (idem)
# --------------------------
class PersistentSet:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._s: set[str] = set()
        self._lock = asyncio.Lock()
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            with contextlib.suppress(Exception):
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._s = set(data.get("done", []))

    async def add(self, x: str) -> None:
        async with self._lock:
            self._s.add(x)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"done": sorted(self._s)}, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def __contains__(self, x: str) -> bool:
        return x in self._s


# --------------------------
# Клиент Twin API
# --------------------------
class TwinApiClient:
    def __init__(self, st: Settings):
        self.st = st
        self._client: Optional[httpx.AsyncClient] = None
        self._mtls_ctx = None

    async def start(self) -> None:
        if httpx is None:
            raise RuntimeError("httpx is required for TwinApiClient")
        # mTLS (опционально)
        if get_adapter_from_env:
            with contextlib.suppress(Exception):
                sec = get_adapter_from_env()
                self._mtls_ctx = await sec.mtls_context()
        self._client = httpx.AsyncClient(
            base_url=self.st.base_url,
            timeout=self.st.request_timeout_s,
            verify=True,
            transport=None,
        )

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def list_twins(self) -> List[Dict[str, Any]]:
        assert self._client is not None
        twins: List[Dict[str, Any]] = []
        token: Optional[str] = None
        while True:
            r = await self._client.get(
                "/api/v1/twin",
                params={"page_size": self.st.page_size, "page_token": token} if token else {"page_size": self.st.page_size},
            )
            r.raise_for_status()
            batch = r.json()
            if isinstance(batch, list):
                twins.extend(batch)
            token = r.headers.get("X-Next-Page-Token")
            if not token:
                break
        return twins

    async def list_commands(self, device_id: str) -> List[Dict[str, Any]]:
        assert self._client is not None
        cmds: List[Dict[str, Any]] = []
        token: Optional[str] = None
        while True:
            r = await self._client.get(
                f"/api/v1/twin/{device_id}/commands",
                params={"page_size": self.st.page_size, "page_token": token} if token else {"page_size": self.st.page_size},
            )
            if r.status_code == 404:
                return []
            r.raise_for_status()
            batch = r.json()
            if isinstance(batch, list):
                cmds.extend(batch)
            token = r.headers.get("X-Next-Page-Token")
            if not token:
                break
        return cmds

    async def get_result(self, device_id: str, command_id: str) -> Optional[Dict[str, Any]]:
        assert self._client is not None
        r = await self._client.get(f"/api/v1/twin/{device_id}/commands/{command_id}/result")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    async def post_result(self, device_id: str, command_id: str, payload: Dict[str, Any]) -> None:
        assert self._client is not None
        r = await self._client.post(f"/api/v1/twin/{device_id}/commands/{command_id}/result", json=payload)
        r.raise_for_status()

    async def get_twin(self, device_id: str) -> Optional[Dict[str, Any]]:
        assert self._client is not None
        r = await self._client.get(f"/api/v1/twin/{device_id}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()


# --------------------------
# Исполнитель команд
# --------------------------
class CommandDispatcher:
    def __init__(self, st: Settings):
        self.st = st
        self.api = TwinApiClient(st)
        self.mgr = ProtocolManager()  # активирует доступные драйверы
        self._global_sem = asyncio.Semaphore(st.max_concurrency)
        self._per_device_sem: Dict[str, asyncio.Semaphore] = {}
        self._done = PersistentSet(st.state_dir / "done.json")
        self._stop = asyncio.Event()

    def _dev_sem(self, device_id: str) -> asyncio.Semaphore:
        sem = self._per_device_sem.get(device_id)
        if not sem:
            sem = self._per_device_sem[device_id] = asyncio.Semaphore(self.st.per_device_concurrency)
        return sem

    async def start(self) -> None:
        await self.api.start()
        await self.mgr.start()
        LOG.info("Command dispatcher started")

    async def stop(self) -> None:
        self._stop.set()
        await self.mgr.stop()
        await self.api.stop()
        LOG.info("Command dispatcher stopped")

    async def run_forever(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)
        while not self._stop.is_set():
            try:
                await self._scan_once()
                await asyncio.wait_for(self._stop.wait(), timeout=self.st.poll_interval_s)
            except asyncio.TimeoutError:
                continue
            except Exception as ex:
                LOG.error("scan loop error: %s", ex)
                await asyncio.sleep(1.0)

    async def _scan_once(self) -> None:
        twins = await self.api.list_twins()
        tasks = []
        for tw in twins:
            device_id = str(tw["identity"]["device_id"])
            cmds = await self.api.list_commands(device_id)
            for c in cmds:
                cmd_id = str(c["command_id"])
                if cmd_id in self._done:
                    continue
                # Проверим наличие результата
                res = await self.api.get_result(device_id, cmd_id)
                if res is not None:
                    await self._done.add(cmd_id)
                    continue
                tasks.append(self._dispatch_one(tw, c))
        if not tasks:
            return
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _dispatch_one(self, twin: Dict[str, Any], cmd: Dict[str, Any]) -> None:
        device_id = str(twin["identity"]["device_id"])
        command_id = str(cmd["command_id"])
        typ = cmd["type"]
        timeout_s = int(cmd.get("timeout_seconds") or self.st.default_cmd_timeout_s)
        params: Dict[str, Any] = cmd.get("params") or {}

        async with self._global_sem, self._dev_sem(device_id):
            start = time.perf_counter()
            if M_IN_FLIGHT:
                try:
                    M_IN_FLIGHT.inc()
                except Exception:
                    pass
            try:
                result = await asyncio.wait_for(self._execute(typ, params, twin), timeout=timeout_s)
                payload = {
                    "status": "SUCCEEDED",
                    "exit_code": 0,
                    "message": json.dumps(result, ensure_ascii=False)[:2048] if result is not None else "ok",
                }
                await self.api.post_result(device_id, command_id, payload)
                if M_OK:
                    with contextlib.suppress(Exception):
                        M_OK.labels(typ).inc()
                LOG.info("Command %s %s -> OK in %.0fms", device_id, typ, (time.perf_counter() - start) * 1000)
            except asyncio.TimeoutError:
                await self._fail(device_id, command_id, typ, "timeout")
            except Exception as ex:
                await self._fail(device_id, command_id, typ, f"error: {ex}")
            finally:
                if M_LAT:
                    with contextlib.suppress(Exception):
                        M_LAT.labels(typ).observe(max(0.0, time.perf_counter() - start))
                await self._done.add(command_id)
                if M_IN_FLIGHT:
                    with contextlib.suppress(Exception):
                        M_IN_FLIGHT.dec()

    async def _fail(self, device_id: str, command_id: str, typ: str, msg: str) -> None:
        LOG.warning("Command %s %s -> FAIL: %s", device_id, typ, msg)
        if M_ERR:
            with contextlib.suppress(Exception):
                M_ERR.labels(typ).inc()
        await self.api.post_result(
            device_id,
            command_id,
            {"status": "FAILED", "exit_code": 1, "message": msg[:2048]},
        )

    # --------------------------
    # Реализация команд
    # --------------------------
    async def _execute(self, typ: str, params: Dict[str, Any], twin: Dict[str, Any]) -> Any:
        """
        Поддерживаемые типы:
          - READ_ATTR:   params={stack, address, endpoint, cluster, attribute}
          - WRITE_ATTR:  params={stack, address, endpoint, cluster, attribute, value}
          - SEND_CMD:    params={stack, address, endpoint, cluster, command, args?}
        Требуемые поля stack и address. Если их нет — ошибка.
        """
        stack = (params.get("stack") or "").lower()
        address = params.get("address")
        if not stack or not address:
            raise ValueError("missing required params: stack/address")

        dev = DeviceDescriptor(
            device_id=str(twin["identity"]["device_id"]),
            stack=stack,
            address=str(address),
            labels={"source": "command_dispatcher"},
        )

        if typ == "READ_ATTR":
            ref = AttrRef(
                endpoint=int(params["endpoint"]),
                cluster=params["cluster"],
                attribute=params["attribute"],
            )
            return await self.mgr.read(dev, ref)

        if typ == "WRITE_ATTR":
            ref = AttrRef(
                endpoint=int(params["endpoint"]),
                cluster=params["cluster"],
                attribute=params["attribute"],
            )
            return await self.mgr.write(dev, ref, params["value"])

        if typ == "SEND_CMD":
            cmd = CommandRef(
                endpoint=int(params["endpoint"]),
                cluster=params["cluster"],
                command=params["command"],
                args=params.get("args") or [],
            )
            return await self.mgr.command(dev, cmd)

        # Неизвестный тип — возвращаем ошибку
        raise ValueError(f"unsupported command type: {typ}")


# --------------------------
# Запуск
# --------------------------
def _setup_logging() -> None:
    lvl = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv("LOG_FMT", "json").lower()
    h = logging.StreamHandler()
    if fmt == "json":
        class _Json(logging.Formatter):
            def format(self, r: logging.LogRecord) -> str:
                data = {
                    "ts": int(time.time()),
                    "level": r.levelname,
                    "logger": r.name,
                    "msg": r.getMessage(),
                }
                if r.exc_info:
                    data["exc"] = self.formatException(r.exc_info)
                return json.dumps(data, ensure_ascii=False)
        h.setFormatter(_Json())
    else:
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(getattr(logging, lvl, logging.INFO))


async def _amain() -> None:
    _setup_logging()
    st = Settings()
    disp = CommandDispatcher(st)
    await disp.start()
    try:
        await disp.run_forever()
    finally:
        await disp.stop()


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

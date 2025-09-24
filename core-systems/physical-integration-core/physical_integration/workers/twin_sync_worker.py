# physical_integration/workers/twin_sync_worker.py
from __future__ import annotations

import abc
import argparse
import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import signal
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# Встроенная устойчивость: используем наш промышленный адаптер
from physical_integration.adapters.resilience_adapter import (
    ResilienceAdapter,
    ResilienceConfig,
    ResilienceMetrics,
)

__all__ = [
    "TwinSyncConfig",
    "TwinSyncMetrics",
    "StateSnapshot",
    "ConflictPolicy",
    "CheckpointStatus",
    "CheckpointStore",
    "SQLiteCheckpointStore",
    "JSONPatchOp",
    "compute_json_patch",
    "apply_json_patch",
    "DeviceEndpoint",
    "TwinEndpoint",
    "TwinSyncWorker",
    "main",
]

# =========================
# Конфигурации и метрики
# =========================

class ConflictPolicy:
    DEVICE_WINS = "device_wins"
    TWIN_WINS = "twin_wins"
    LAST_WRITE_WINS = "last_write_wins"


@dataclass(frozen=True)
class TwinSyncConfig:
    devices: Sequence[str]
    poll_interval_s: float = 1.0
    concurrency: int = 8
    batch_size: int = 32  # сколько устройств за тик брать в работу
    conflict_policy: str = ConflictPolicy.LAST_WRITE_WINS
    partial_updates: bool = True
    allow_deletes: bool = True
    max_patch_bytes: int = 128 * 1024  # защита от "fat patch"
    # Идемпотентность
    idempotency_ttl_s: int = 24 * 3600
    # Где хранить чекпоинты/идемпотентные ключи
    checkpoint_path: str = "twin_sync.sqlite"
    # Метки
    service_name: str = "twin-sync"
    # Таймаут acquire на параллельные лимитеры ResilienceAdapter уже настроены в нем
    guard_timeout_s: float = 5.0


@dataclass
class TwinSyncMetrics:
    sync_cycles: int = 0
    sync_success: int = 0
    sync_errors: int = 0
    conflicts: int = 0
    device_to_twin_patches: int = 0
    twin_to_device_patches: int = 0
    skipped_empty: int = 0
    oversized_patch_drops: int = 0
    last_cycle_latency_s: Optional[float] = None

    def export(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# =========================
# Снэпшот состояния
# =========================

@dataclass(frozen=True)
class StateSnapshot:
    state: Mapping[str, Any]
    version: Optional[str]  # ETag/Version/Hash
    modified_ts: Optional[float]  # epoch seconds when this state changed at source


# =========================
# Чекпоинты и идемпотентность
# =========================

@dataclass
class CheckpointStatus:
    device_id: str
    last_device_version: Optional[str] = None
    last_twin_version: Optional[str] = None
    last_sync_ts: float = field(default_factory=lambda: time.time())
    last_error: Optional[str] = None


class CheckpointStore(abc.ABC):
    @abc.abstractmethod
    def get(self, device_id: str) -> CheckpointStatus:
        ...

    @abc.abstractmethod
    def put(self, status: CheckpointStatus) -> None:
        ...

    @abc.abstractmethod
    def remember_idempotency(self, key: str, ttl_s: int) -> None:
        ...

    @abc.abstractmethod
    def seen_idempotency(self, key: str) -> bool:
        ...

    @abc.abstractmethod
    def close(self) -> None:
        ...


class SQLiteCheckpointStore(CheckpointStore):
    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoint_status (
                device_id TEXT PRIMARY KEY,
                last_device_version TEXT,
                last_twin_version TEXT,
                last_sync_ts REAL,
                last_error TEXT
            );
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                key TEXT PRIMARY KEY,
                expires_at REAL
            );
            """
        )
        self._db.commit()

    def get(self, device_id: str) -> CheckpointStatus:
        cur = self._db.execute(
            "SELECT device_id, last_device_version, last_twin_version, last_sync_ts, last_error FROM checkpoint_status WHERE device_id=?",
            (device_id,),
        )
        row = cur.fetchone()
        if row:
            return CheckpointStatus(
                device_id=row[0],
                last_device_version=row[1],
                last_twin_version=row[2],
                last_sync_ts=row[3],
                last_error=row[4],
            )
        # default
        return CheckpointStatus(device_id=device_id)

    def put(self, status: CheckpointStatus) -> None:
        self._db.execute(
            """
            INSERT INTO checkpoint_status(device_id, last_device_version, last_twin_version, last_sync_ts, last_error)
            VALUES(?,?,?,?,?)
            ON CONFLICT(device_id) DO UPDATE SET
                last_device_version=excluded.last_device_version,
                last_twin_version=excluded.last_twin_version,
                last_sync_ts=excluded.last_sync_ts,
                last_error=excluded.last_error
            """,
            (
                status.device_id,
                status.last_device_version,
                status.last_twin_version,
                status.last_sync_ts,
                status.last_error,
            ),
        )
        self._db.commit()

    def remember_idempotency(self, key: str, ttl_s: int) -> None:
        expires_at = time.time() + ttl_s
        self._db.execute(
            """
            INSERT INTO idempotency_keys(key, expires_at) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET expires_at=excluded.expires_at
            """,
            (key, expires_at),
        )
        # Очистка протухших периодически
        self._db.execute("DELETE FROM idempotency_keys WHERE expires_at < ?", (time.time(),))
        self._db.commit()

    def seen_idempotency(self, key: str) -> bool:
        cur = self._db.execute("SELECT 1 FROM idempotency_keys WHERE key=? AND expires_at >= ?", (key, time.time()))
        return cur.fetchone() is not None

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:
            pass


# =========================
# JSON Patch (детерминированный)
# =========================

@dataclass(frozen=True)
class JSONPatchOp:
    op: str  # "set" | "remove"
    path: Tuple[str, ...]
    value: Optional[Any] = None

    def to_json_obj(self) -> Mapping[str, Any]:
        obj: Dict[str, Any] = {"op": self.op, "path": "/".join(self.path)}
        if self.op == "set":
            obj["value"] = self.value
        return obj


def _is_scalar(x: Any) -> bool:
    return isinstance(x, (str, int, float, bool)) or x is None


def _sorted_keys(m: Mapping[str, Any]) -> List[str]:
    return sorted(m.keys(), key=lambda k: (len(k), k))


def compute_json_patch(src: Mapping[str, Any], dst: Mapping[str, Any], allow_deletes: bool = True) -> List[JSONPatchOp]:
    """
    Строит минимальный детерминированный patch, покрывающий изменения src->dst.
    Правила:
      - Скалярные различия => set
      - Объект->объект — рекурсивно
      - Отсутствующие в dst ключи => remove (если allow_deletes)
      - Порядок операций детерминирован по путям (короткие, потом лексикографически)
    """
    ops: List[JSONPatchOp] = []

    def walk(prefix: Tuple[str, ...], a: Any, b: Any) -> None:
        if _is_scalar(a) and _is_scalar(b):
            if a != b:
                ops.append(JSONPatchOp("set", prefix, b))
            return
        if isinstance(a, Mapping) and isinstance(b, Mapping):
            akeys = set(a.keys())
            bkeys = set(b.keys())
            for k in _sorted_keys({**a, **b}):
                pa = prefix + (k,)
                if k in akeys and k in bkeys:
                    walk(pa, a[k], b[k])
                elif k in bkeys:
                    ops.append(JSONPatchOp("set", pa, b[k]))
                elif allow_deletes and k in akeys:
                    ops.append(JSONPatchOp("remove", pa, None))
            return
        # Тип изменился или коллекции — тритуем как set целиком
        ops.append(JSONPatchOp("set", prefix, b))

    walk((), src, dst)
    # Стабильная сортировка по длине пути, затем по строке пути
    ops.sort(key=lambda op: (len(op.path), "/".join(op.path)))
    return ops


def apply_json_patch(doc: MutableMapping[str, Any], ops: Sequence[JSONPatchOp]) -> None:
    for op in ops:
        cur: MutableMapping[str, Any] = doc
        # пройти к родителю
        for key in op.path[:-1]:
            nxt = cur.get(key)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[key] = nxt
            cur = nxt  # type: ignore
        leaf = op.path[-1] if op.path else ""
        if op.op == "set":
            cur[leaf] = op.value
        elif op.op == "remove":
            cur.pop(leaf, None)
        else:
            raise ValueError(f"Unknown op: {op.op}")


# =========================
# Интерфейсы Endpoints
# =========================

class DeviceEndpoint(abc.ABC):
    @abc.abstractmethod
    async def read_state(self, device_id: str) -> StateSnapshot:
        ...

    @abc.abstractmethod
    async def apply_patch(self, device_id: str, patch: Sequence[JSONPatchOp], *, if_version: Optional[str], idempotency_key: str) -> str:
        """
        Возвращает новую версию состояния устройства.
        """
        ...


class TwinEndpoint(abc.ABC):
    @abc.abstractmethod
    async def read_state(self, device_id: str) -> StateSnapshot:
        ...

    @abc.abstractmethod
    async def apply_patch(self, device_id: str, patch: Sequence[JSONPatchOp], *, if_version: Optional[str], idempotency_key: str) -> str:
        """
        Возвращает новую версию состояния twin.
        """
        ...


# =========================
# Воркер синхронизации
# =========================

@dataclass
class _WorkItem:
    device_id: str
    scheduled_at: float


class TwinSyncWorker:
    def __init__(
        self,
        cfg: TwinSyncConfig,
        device_ep: DeviceEndpoint,
        twin_ep: TwinEndpoint,
        *,
        store: Optional[CheckpointStore] = None,
        logger: Optional[logging.Logger] = None,
        device_resilience: Optional[ResilienceAdapter[Any]] = None,
        twin_resilience: Optional[ResilienceAdapter[Any]] = None,
    ) -> None:
        self.cfg = cfg
        self.device_ep = device_ep
        self.twin_ep = twin_ep
        self.store = store or SQLiteCheckpointStore(cfg.checkpoint_path)
        self.logger = logger or logging.getLogger(f"{cfg.service_name}.worker")
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

        # Устойчивые адаптеры вокруг endpoint вызовов
        self.device_res = device_resilience or ResilienceAdapter(
            ResilienceConfig(service_name="device", resource_id="*")
        )
        self.twin_res = twin_resilience or ResilienceAdapter(
            ResilienceConfig(service_name="twin", resource_id="*")
        )

        self.metrics = TwinSyncMetrics()
        self._queue: asyncio.Queue[_WorkItem] = asyncio.Queue(maxsize=max(1, self.cfg.batch_size * 4))
        self._stop = asyncio.Event()
        self._tasks: List[asyncio.Task[None]] = []

    # --------- Публичный API ---------

    async def start(self) -> None:
        self.logger.info("Starting TwinSyncWorker with %d devices", len(self.cfg.devices))
        # Планировщик
        self._tasks.append(asyncio.create_task(self._scheduler(), name="twin-sync-scheduler"))
        # Пул воркеров
        for i in range(max(1, self.cfg.concurrency)):
            self._tasks.append(asyncio.create_task(self._worker_loop(i), name=f"twin-sync-worker-{i}"))

    async def stop(self) -> None:
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self.store.close()
        self.device_res.close()
        self.twin_res.close()
        self.logger.info("TwinSyncWorker stopped")

    # --------- Внутреннее ---------

    async def _scheduler(self) -> None:
        idx = 0
        try:
            while not self._stop.is_set():
                batch = self.cfg.devices[idx : idx + self.cfg.batch_size]
                if not batch:
                    idx = 0
                    await asyncio.sleep(self.cfg.poll_interval_s)
                    continue
                now = time.time()
                for d in batch:
                    item = _WorkItem(device_id=d, scheduled_at=now)
                    # backpressure: если очередь полна — вытолкнуть самый старый и заменить новым
                    if self._queue.full():
                        try:
                            _ = self._queue.get_nowait()
                            self._queue.task_done()
                        except asyncio.QueueEmpty:
                            pass
                    await self._queue.put(item)
                idx += self.cfg.batch_size
                await asyncio.sleep(self.cfg.poll_interval_s)
        except asyncio.CancelledError:
            return

    async def _worker_loop(self, wid: int) -> None:
        try:
            while not self._stop.is_set():
                item = await self._queue.get()
                t0 = time.perf_counter()
                try:
                    await self._sync_device(item.device_id)
                    self.metrics.sync_success += 1
                except Exception as e:
                    self.metrics.sync_errors += 1
                    self.logger.error("Sync error device=%s err=%r", item.device_id, e)
                    # Записать ошибку в чекпоинт
                    st = self.store.get(item.device_id)
                    st.last_error = repr(e)
                    st.last_sync_ts = time.time()
                    self.store.put(st)
                finally:
                    self.metrics.sync_cycles += 1
                    self.metrics.last_cycle_latency_s = time.perf_counter() - t0
                    self._queue.task_done()
        except asyncio.CancelledError:
            return

    # Основной алгоритм синхронизации одного устройства
    async def _sync_device(self, device_id: str) -> None:
        # Чтение состояния обеих сторон через устойчивые адаптеры
        device_snapshot = await self._aread_device_state(device_id)
        twin_snapshot = await self._aread_twin_state(device_id)

        cp = self.store.get(device_id)

        device_changed = device_snapshot.version is not None and device_snapshot.version != cp.last_device_version
        twin_changed = twin_snapshot.version is not None and twin_snapshot.version != cp.last_twin_version

        # Если ничего не изменилось — выходим
        if not device_changed and not twin_changed:
            self.metrics.skipped_empty += 1
            return

        # Конфликт, если обе стороны поменялись с прошлого раза
        if device_changed and twin_changed:
            self.metrics.conflicts += 1
            decision = self.cfg.conflict_policy
        else:
            decision = ConflictPolicy.DEVICE_WINS if device_changed else ConflictPolicy.TWIN_WINS

        # Вычисление патча по выбранной стороне‑источнику
        if decision == ConflictPolicy.DEVICE_WINS:
            src = device_snapshot
            dst = twin_snapshot
            direction = "device->twin"
        elif decision == ConflictPolicy.TWIN_WINS:
            src = twin_snapshot
            dst = device_snapshot
            direction = "twin->device"
        elif decision == ConflictPolicy.LAST_WRITE_WINS:
            # Сравнить modified_ts, если неизвестно — fallback к DEVICE_WINS
            dts = device_snapshot.modified_ts or 0.0
            tts = twin_snapshot.modified_ts or 0.0
            if dts >= tts:
                src = device_snapshot
                dst = twin_snapshot
                direction = "device->twin"
            else:
                src = twin_snapshot
                dst = device_snapshot
                direction = "twin->device"
        else:
            # безопасный дефолт
            src = device_snapshot
            dst = twin_snapshot
            direction = "device->twin"

        allow_deletes = self.cfg.allow_deletes
        if not self.cfg.partial_updates:
            # полный set "root" — минимальный патч
            patch = [JSONPatchOp("set", tuple(), src.state)]
        else:
            patch = compute_json_patch(dst.state, src.state, allow_deletes=allow_deletes)

        if not patch:
            self.metrics.skipped_empty += 1
            await self._update_checkpoint(device_id, device_snapshot, twin_snapshot, None)
            return

        # Ограничение размера патча
        patch_json = json.dumps([op.to_json_obj() for op in patch], separators=(",", ":"), ensure_ascii=False)
        if len(patch_json.encode("utf-8")) > self.cfg.max_patch_bytes:
            self.metrics.oversized_patch_drops += 1
            self.logger.warning("Patch too large dropped device=%s bytes=%d", device_id, len(patch_json))
            return

        # Идемпотентный ключ
        idem_key = self._make_idempotency_key(device_id, direction, patch_json, src.version or "", dst.version or "")
        if self.store.seen_idempotency(idem_key):
            # уже применяли — просто обновим чекпоинт
            await self._update_checkpoint(device_id, device_snapshot, twin_snapshot, None)
            return

        # Применение патча
        if direction == "device->twin":
            new_ver = await self._apply_twin_patch(device_id, patch, if_version=twin_snapshot.version, idem_key=idem_key)
            self.metrics.device_to_twin_patches += 1
            twin_snapshot = StateSnapshot(state=src.state, version=new_ver or src.version, modified_ts=time.time())
        else:
            new_ver = await self._apply_device_patch(device_id, patch, if_version=device_snapshot.version, idem_key=idem_key)
            self.metrics.twin_to_device_patches += 1
            device_snapshot = StateSnapshot(state=src.state, version=new_ver or src.version, modified_ts=time.time())

        # Запомнить идемпотентный ключ
        self.store.remember_idempotency(idem_key, self.cfg.idempotency_ttl_s)

        # Обновить чекпоинт
        await self._update_checkpoint(device_id, device_snapshot, twin_snapshot, None)

    async def _update_checkpoint(
        self,
        device_id: str,
        device_snapshot: StateSnapshot,
        twin_snapshot: StateSnapshot,
        error: Optional[str],
    ) -> None:
        st = self.store.get(device_id)
        st.last_device_version = device_snapshot.version
        st.last_twin_version = twin_snapshot.version
        st.last_sync_ts = time.time()
        st.last_error = error
        self.store.put(st)

    # --------- Обертки над endpoint с устойчивостью ---------

    async def _aread_device_state(self, device_id: str) -> StateSnapshot:
        async def fn() -> StateSnapshot:
            return await self.device_ep.read_state(device_id)

        return await self.twin_res.aexecute(fn, op_name="read_device")

    async def _aread_twin_state(self, device_id: str) -> StateSnapshot:
        async def fn() -> StateSnapshot:
            return await self.twin_ep.read_state(device_id)

        return await self.twin_res.aexecute(fn, op_name="read_twin")

    async def _apply_twin_patch(self, device_id: str, patch: Sequence[JSONPatchOp], *, if_version: Optional[str], idem_key: str) -> str:
        async def fn() -> str:
            return await self.twin_ep.apply_patch(device_id, patch, if_version=if_version, idempotency_key=idem_key)

        return await self.twin_res.aexecute(fn, op_name="patch_twin")

    async def _apply_device_patch(self, device_id: str, patch: Sequence[JSONPatchOp], *, if_version: Optional[str], idem_key: str) -> str:
        async def fn() -> str:
            return await self.device_ep.apply_patch(device_id, patch, if_version=if_version, idempotency_key=idempotency_key)

        # опечатка защиты: правильное имя переменной
        idempotency_key = idem_key
        return await self.device_res.aexecute(fn, op_name="patch_device")

    # --------- Утилиты ---------

    def _make_idempotency_key(self, device_id: str, direction: str, patch_json: str, src_ver: str, dst_ver: str) -> str:
        h = hashlib.sha256()
        h.update(device_id.encode("utf-8"))
        h.update(b"|")
        h.update(direction.encode("utf-8"))
        h.update(b"|")
        h.update(src_ver.encode("utf-8"))
        h.update(b"|")
        h.update(dst_ver.encode("utf-8"))
        h.update(b"|")
        h.update(patch_json.encode("utf-8"))
        return h.hexdigest()


# =========================
# Минимальные in-memory endpoints (для CLI/отладки)
# =========================

class _MemoryEndpoint(DeviceEndpoint, TwinEndpoint):
    """
    Потокобезопасный in-memory endpoint.
    Версия — sha256 от JSON состояния.
    modified_ts — время последнего изменения.
    """
    def __init__(self, name: str, initial: Optional[Mapping[str, Any]] = None) -> None:
        self._name = name
        self._state: Dict[str, Any] = dict(initial or {})
        self._version: Optional[str] = self._calc_ver()
        self._modified: float = time.time()
        self._lock = asyncio.Lock()

    def _calc_ver(self) -> str:
        payload = json.dumps(self._state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    async def read_state(self, device_id: str) -> StateSnapshot:
        async with self._lock:
            return StateSnapshot(state=json.loads(json.dumps(self._state)), version=self._version, modified_ts=self._modified)

    async def apply_patch(self, device_id: str, patch: Sequence[JSONPatchOp], *, if_version: Optional[str], idempotency_key: str) -> str:
        async with self._lock:
            if if_version is not None and self._version is not None and if_version != self._version:
                # имитация 412 Precondition Failed
                raise RuntimeError(f"{self._name}: version conflict: if_match={if_version} current={self._version}")
            doc = self._state
            apply_json_patch(doc, patch)
            self._version = self._calc_ver()
            self._modified = time.time()
            return self._version


# =========================
# CLI
# =========================

def _install_signal_handlers(loop: asyncio.AbstractEventLoop, stopper: Callable[[], Awaitable[None]]) -> None:
    def _handler():
        loop.create_task(stopper())
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handler)
        except NotImplementedError:
            # Windows
            pass


async def _run_cli(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")

    # Подготовка источников
    device_initial: Dict[str, Any] = {}
    twin_initial: Dict[str, Any] = {}
    if args.device_json and os.path.exists(args.device_json):
        device_initial = json.load(open(args.device_json, "r", encoding="utf-8"))
    if args.twin_json and os.path.exists(args.twin_json):
        twin_initial = json.load(open(args.twin_json, "r", encoding="utf-8"))

    device_ep = _MemoryEndpoint("device", device_initial)
    twin_ep = _MemoryEndpoint("twin", twin_initial)

    cfg = TwinSyncConfig(
        devices=args.devices,
        poll_interval_s=args.poll,
        concurrency=args.concurrency,
        batch_size=args.batch,
        conflict_policy=args.policy,
        partial_updates=not args.full_set,
        allow_deletes=not args.no_delete,
        max_patch_bytes=args.max_patch,
        idempotency_ttl_s=args.idem_ttl,
        checkpoint_path=args.checkpoint,
    )

    worker = TwinSyncWorker(cfg, device_ep, twin_ep)

    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop, worker.stop)
    await worker.start()

    # Работаем указанное время или до сигнала
    try:
        if args.duration > 0:
            await asyncio.sleep(args.duration)
        else:
            while True:
                await asyncio.sleep(3600)
    finally:
        await worker.stop()

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Digital Twin synchronization worker")
    p.add_argument("--devices", nargs="+", default=["dev-1"], help="List of device ids")
    p.add_argument("--poll", type=float, default=1.0, help="Poll interval seconds")
    p.add_argument("--concurrency", type=int, default=4, help="Concurrent workers")
    p.add_argument("--batch", type=int, default=32, help="Batch size per tick")
    p.add_argument("--policy", choices=[ConflictPolicy.DEVICE_WINS, ConflictPolicy.TWIN_WINS, ConflictPolicy.LAST_WRITE_WINS], default=ConflictPolicy.LAST_WRITE_WINS, help="Conflict policy")
    p.add_argument("--full-set", action="store_true", help="Send full root set instead of partial patch")
    p.add_argument("--no-delete", action="store_true", help="Disable delete operations in patch")
    p.add_argument("--max-patch", type=int, default=128 * 1024, help="Max patch size in bytes")
    p.add_argument("--idem-ttl", type=int, default=24 * 3600, help="Idempotency TTL seconds")
    p.add_argument("--checkpoint", type=str, default="twin_sync.sqlite", help="SQLite path for checkpoints")
    p.add_argument("--duration", type=int, default=0, help="Run seconds (0 = infinity)")
    p.add_argument("--device-json", type=str, default="", help="Initial JSON for device endpoint")
    p.add_argument("--twin-json", type=str, default="", help="Initial JSON for twin endpoint")
    args = p.parse_args(argv)

    return asyncio.run(_run_cli(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

# physical-integration-core/physical_integration/protocols/opcua_client.py
from __future__ import annotations

import asyncio
import logging
import math
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    # asyncua входит в пакет "opcua"
    from asyncua import Client, Node, ua
except Exception as exc:  # noqa: BLE001
    raise RuntimeError("The 'asyncua' client (package 'opcua') is required") from exc


logger = logging.getLogger("physical_integration_core.protocols.opcua")


# ------------------------------- Константы -----------------------------------

MAX_BATCH_NODES = 200            # разумный лимит на батч чтений/записей
DEFAULT_SOCKET_TIMEOUT = 10.0    # сокетный таймаут клиента, сек
DEFAULT_OP_TIMEOUT = 5.0         # таймаут операций (read/write/call), сек
DEFAULT_SESSION_TIMEOUT_MS = 30_000
DEFAULT_KEEPALIVE_NODE = "i=2258"  # Server_ServerStatus_CurrentTime
DEFAULT_PUBLISHING_INTERVAL_MS = 500
DEFAULT_SAMPLING_INTERVAL_MS = 250
DEFAULT_QUEUE_SIZE = 20
EVENT_QUEUE_MAX = 10_000         # per-subscription очередь событий
RECONNECT_MIN_S = 1.0
RECONNECT_MAX_S = 30.0
RECONNECT_JITTER_S = 0.3
NS_CACHE_TTL_S = 300.0

# ------------------------------- Настройки -----------------------------------


@dataclass
class SecurityConfig:
    # Политика безопасности и режим сообщения.
    # Пример policy: "Basic256Sha256" | "Basic256" | "Basic128Rsa15" | "None"
    # Пример mode: "SignAndEncrypt" | "Sign" | "None"
    policy: str = "Basic256Sha256"
    mode: str = "SignAndEncrypt"
    certificate_path: Optional[str] = None
    private_key_path: Optional[str] = None
    # Пользовательские креды (опц.)
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class SubscriptionConfig:
    publishing_interval_ms: int = DEFAULT_PUBLISHING_INTERVAL_MS
    sampling_interval_ms: int = DEFAULT_SAMPLING_INTERVAL_MS
    queue_size: int = DEFAULT_QUEUE_SIZE
    discard_oldest: bool = True
    event_queue_max: int = EVENT_QUEUE_MAX
    drop_policy_oldest: bool = True  # при переполнении очереди событий


@dataclass
class OPCUAClientSettings:
    endpoint_url: str
    application_name: str = "physical-integration-core"
    application_uri: Optional[str] = None
    socket_timeout_s: float = DEFAULT_SOCKET_TIMEOUT
    session_timeout_ms: int = DEFAULT_SESSION_TIMEOUT_MS
    op_timeout_s: float = DEFAULT_OP_TIMEOUT
    security: SecurityConfig = field(default_factory=SecurityConfig)
    keepalive_node: str = DEFAULT_KEEPALIVE_NODE
    keepalive_period_s: float = 10.0
    reconnect_min_s: float = RECONNECT_MIN_S
    reconnect_max_s: float = RECONNECT_MAX_S
    reconnect_jitter_s: float = RECONNECT_JITTER_S
    ns_cache_ttl_s: float = NS_CACHE_TTL_S
    # Лимиты
    max_batch_nodes: int = MAX_BATCH_NODES
    # Вкл./выкл. автосоздание подписки при вызове subscribe()
    auto_recover_subscriptions: bool = True


# --------------------------- Вспомогательные типы ----------------------------

NodeIdLike = Union[str, Node]
MonitoredHandle = Tuple[int, List[Node]]  # (subscription_id, monitored_nodes)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------- Обработчик событий -----------------------------


class _DataChangeHandler:
    """
    Handler, вызываемый asyncua при изменениях данных.
    Помещает события в асинхронную очередь (bounded) с политикой дропа.
    """

    def __init__(self, queue: "asyncio.Queue[Dict[str, Any]]", drop_oldest: bool) -> None:
        self._queue = queue
        self._drop_oldest = drop_oldest

    # asyncua вызывает синхронно
    def datachange_notification(self, node: Node, val: Any, data: ua.DataChangeNotification) -> None:
        evt = {
            "node_id": node.nodeid.to_string(),
            "server_ts": getattr(data.monitored_item.Value.ServerTimestamp, "datetime", None),
            "source_ts": getattr(data.monitored_item.Value.SourceTimestamp, "datetime", None),
            "status": int(data.monitored_item.Value.StatusCode),
            "value": val,
            "received_at": _now_iso(),
        }
        try:
            self._queue.put_nowait(evt)  # если очередь полна — бросит исключение
        except asyncio.QueueFull:
            if self._drop_oldest:
                try:
                    # выталкиваем старое и помещаем новое
                    self._queue.get_nowait()
                    self._queue.put_nowait(evt)
                except Exception:
                    # тихо дропаем новое, если не удалось
                    pass
            else:
                # дроп нового
                pass


# ------------------------------- Основной клиент ------------------------------


class OPCUAClient:
    """
    Промышленный асинхронный OPC UA-клиент с авто-реконнектом и восстановлением подписок.
    """

    def __init__(self, settings: OPCUAClientSettings) -> None:
        self.s = settings
        self._client: Optional[Client] = None
        self._connected = asyncio.Event()
        self._closing = False
        self._supervisor_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None

        # кеш namespace array (ttl)
        self._ns_array: Tuple[float, List[str]] = (0.0, [])

        # подписки: sub_id -> (Subscription, handler, queue, cfg)
        self._subs: Dict[int, Tuple[Any, _DataChangeHandler, "asyncio.Queue[Dict[str, Any]]", SubscriptionConfig]] = {}

        # конфигурации для восстановления: sub_id -> (node_ids, cfg)
        self._recover_plan: Dict[int, Tuple[List[str], SubscriptionConfig]] = {}

        # генератор sub_id для наших внутренних идентификаторов (не равен server handle)
        self._next_sub_id = 1

    # --------------------------- Публичный интерфейс --------------------------

    async def start(self) -> None:
        """
        Инициализация и запуск фонового супервизора (подключение и поддержка).
        """
        self._closing = False
        self._supervisor_task = asyncio.create_task(self._supervise_loop(), name="opcua-supervisor")

    async def stop(self) -> None:
        """
        Останов: закрываем фоновые задачи, подписки и клиент.
        """
        self._closing = True
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            with contextlib.suppress(Exception):
                await self._keepalive_task
        if self._supervisor_task and not self._supervisor_task.done():
            self._supervisor_task.cancel()
            with contextlib.suppress(Exception):
                await self._supervisor_task
        await self._disconnect()

    async def ready(self) -> None:
        """
        Дождаться установления соединения/сессии.
        """
        await self._connected.wait()

    async def read_values(self, node_ids: Sequence[NodeIdLike], timeout_s: Optional[float] = None) -> List[Any]:
        """
        Батчевое чтение значений (с соблюдением лимита на размер батча).
        """
        c = await self._require_client()
        nodes = [await self._to_node(c, n) for n in node_ids]
        out: List[Any] = []
        deadline = time.monotonic() + (timeout_s or self.s.op_timeout_s)
        for chunk in _chunks(nodes, self.s.max_batch_nodes):
            remaining = max(0.1, deadline - time.monotonic())
            with ua_timeout(c, remaining):
                vals = await c.read_values(chunk)
                out.extend(vals)
        return out

    async def write_values(self, items: Sequence[Tuple[NodeIdLike, Any]], timeout_s: Optional[float] = None) -> List[ua.StatusCode]:
        """
        Батчевая запись значений.
        """
        c = await self._require_client()
        nodes = [await self._to_node(c, n) for n, _ in items]
        values = [v for _, v in items]
        out: List[ua.StatusCode] = []
        deadline = time.monotonic() + (timeout_s or self.s.op_timeout_s)
        for chunk_nodes, chunk_vals in _zip_chunks(nodes, values, self.s.max_batch_nodes):
            remaining = max(0.1, deadline - time.monotonic())
            with ua_timeout(c, remaining):
                res = await c.write_values(chunk_nodes, chunk_vals)
                out.extend(res)
        return out

    async def call_method(self, obj: NodeIdLike, method: NodeIdLike, args: Optional[List[Any]] = None, timeout_s: Optional[float] = None) -> List[Any]:
        """
        Вызов метода на узле.
        """
        c = await self._require_client()
        obj_node = await self._to_node(c, obj)
        method_node = await self._to_node(c, method)
        with ua_timeout(c, timeout_s or self.s.op_timeout_s):
            return await obj_node.call_method(method_node, *(args or []))

    async def subscribe_data_change(
        self,
        node_ids: Sequence[NodeIdLike],
        cfg: Optional[SubscriptionConfig] = None,
    ) -> Tuple[int, "asyncio.Queue[Dict[str, Any]]"]:
        """
        Создать подписку на изменения для набора нод. Возвращает наш sub_id и очередь событий.
        """
        cfg = cfg or SubscriptionConfig()
        c = await self._require_client()

        # Очередь событий (bounded)
        q: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=cfg.event_queue_max)
        handler = _DataChangeHandler(q, drop_oldest=cfg.drop_policy_oldest)

        # Создаем подписку
        sub = await c.create_subscription(cfg.publishing_interval_ms, handler)
        nodes = [await self._to_node(c, n) for n in node_ids]

        params = ua.MonitoringParameters(
            ClientHandle=random.randint(1, 2**31 - 1),
            SamplingInterval=cfg.sampling_interval_ms,
            Filter=None,
            QueueSize=cfg.queue_size,
            DiscardOldest=cfg.discard_oldest,
        )
        reqs = [ua.MonitoredItemCreateRequest(
            ua.ReadValueId(node.nodeid, ua.AttributeIds.Value, None, None),
            ua.MonitoringMode.Reporting,
            params,
        ) for node in nodes]
        await sub.create_monitored_items(ua.TimestampsToReturn.Both, reqs)

        sub_id = self._next_sub_id
        self._next_sub_id += 1

        self._subs[sub_id] = (sub, handler, q, cfg)
        # план восстановления
        if self.s.auto_recover_subscriptions:
            self._recover_plan[sub_id] = ([n if isinstance(n, str) else n.nodeid.to_string() for n in node_ids], cfg)

        logger.info("OPCUA subscribe ok sub_id=%s nodes=%d", sub_id, len(node_ids))
        return sub_id, q

    async def unsubscribe(self, sub_id: int) -> None:
        """
        Снять подписку по нашему идентификатору.
        """
        tup = self._subs.pop(sub_id, None)
        self._recover_plan.pop(sub_id, None)
        if not tup:
            return
        sub, _, _, _ = tup
        with contextlib.suppress(Exception):
            await sub.delete()

    async def namespace_array(self, force_refresh: bool = False) -> List[str]:
        """
        Кешированный NamespaceArray.
        """
        now = time.monotonic()
        ts, arr = self._ns_array
        if not force_refresh and (now - ts) < self.s.ns_cache_ttl_s and arr:
            return arr
        c = await self._require_client()
        arr = await c.get_namespace_array()
        self._ns_array = (now, arr)
        return arr

    # --------------------------- Внутренние детали ----------------------------

    async def _require_client(self) -> Client:
        if not self._client or not self._connected.is_set():
            await self.ready()
        assert self._client is not None
        return self._client

    async def _connect_once(self) -> None:
        settings = self.s
        client = Client(
            url=settings.endpoint_url,
            timeout=settings.socket_timeout_s,
            name=settings.application_name,
            server_timeout=settings.session_timeout_ms / 1000.0,
        )

        # Безопасность
        sec = settings.security
        if sec.policy:
            # set_security_string формат: "Policy,Mode,cert,key"
            # При policy=None можно не вызывать
            cpath = sec.certificate_path or ""
            kpath = sec.private_key_path or ""
            sec_str = f"{sec.policy},{sec.mode},{cpath},{kpath}"
            client.set_security_string(sec_str)
        if sec.username:
            client.set_user(sec.username)
            if sec.password:
                client.set_password(sec.password)

        # Подключение
        await client.connect()
        # Health-проверка
        await client.nodes.server_serverstatus_currenttime.read_value()

        # Успех
        self._client = client
        self._connected.set()
        logger.info("OPCUA connected url=%s", settings.endpoint_url)

        # Старт keepalive
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="opcua-keepalive")

        # Восстановление подписок
        if self.s.auto_recover_subscriptions and self._recover_plan:
            await self._recover_subscriptions()

    async def _disconnect(self) -> None:
        self._connected.clear()
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            with contextlib.suppress(Exception):
                await self._keepalive_task
        if self._client:
            with contextlib.suppress(Exception):
                # удалим все активные подписки у сервера
                for sub_id, (sub, _, _, _) in list(self._subs.items()):
                    with contextlib.suppress(Exception):
                        await sub.delete()
                self._subs.clear()
            with contextlib.suppress(Exception):
                await self._client.disconnect()
        self._client = None
        logger.info("OPCUA disconnected")

    async def _supervise_loop(self) -> None:
        """
        Управляет жизненным циклом соединения: подключение, переподключение.
        """
        delay = self.s.reconnect_min_s
        while not self._closing:
            try:
                await self._connect_once()
                # сброс задержки после успешного коннекта
                delay = self.s.reconnect_min_s
                # Ждем, пока соединение живое, но выходим по флагу
                while not self._closing and self._connected.is_set():
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                logger.warning("OPCUA connect failed: %s", exc)
                self._connected.clear()
                await self._safe_sleep(delay + random.uniform(0, self.s.reconnect_jitter_s))
                delay = min(self.s.reconnect_max_s, delay * 2)
            finally:
                if not self._closing:
                    # Попробуем закрыть остатки перед новым циклом
                    with contextlib.suppress(Exception):
                        await self._disconnect()

    async def _keepalive_loop(self) -> None:
        """
        Периодический health-check серверного времени (как легковесный ping).
        При ошибке — инициирует реконнект.
        """
        while not self._closing and self._client:
            try:
                await asyncio.sleep(self.s.keepalive_period_s)
                c = self._client
                if not c:
                    continue
                node = await self._to_node(c, self.s.keepalive_node)
                with ua_timeout(c, self.s.op_timeout_s):
                    await node.read_value()
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                logger.warning("OPCUA keepalive failed: %s", exc)
                # инициируем реконнект
                self._connected.clear()
                with contextlib.suppress(Exception):
                    await self._disconnect()
                break

    async def _recover_subscriptions(self) -> None:
        """
        Пересоздание подписок после реконнекта.
        """
        if not self._recover_plan:
            return
        logger.info("OPCUA recovering %d subscriptions", len(self._recover_plan))
        # Сохраняем план и очищаем текущую карту подписок
        plan = list(self._recover_plan.items())
        self._subs.clear()
        self._recover_plan.clear()
        for saved_id, (node_ids, cfg) in plan:
            try:
                new_sub_id, q = await self.subscribe_data_change(node_ids, cfg)
                logger.info("OPCUA recovered sub old=%s new=%s nodes=%d", saved_id, new_sub_id, len(node_ids))
            except Exception as exc:  # noqa: BLE001
                logger.error("OPCUA recover subscription failed old=%s: %s", saved_id, exc)

    async def _to_node(self, client: Client, node_id: NodeIdLike) -> Node:
        if isinstance(node_id, Node):
            return node_id
        return client.get_node(str(node_id))

    @staticmethod
    async def _safe_sleep(seconds: float) -> None:
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            raise

# --------------------------- Утилиты/Контекст-менеджеры ----------------------

import contextlib  # noqa: E402


@contextlib.contextmanager
def ua_timeout(client: Client, seconds: float):
    """
    Контекст «тайм-аут операции» для совместимости с asyncua:
    смена socket timeout на время вызова.
    """
    seconds = max(0.1, float(seconds))
    old = getattr(client, "timeout", DEFAULT_SOCKET_TIMEOUT)
    try:
        client.timeout = seconds
        yield
    finally:
        client.timeout = old


def _chunks(seq: Sequence[Any], n: int) -> Iterable[Sequence[Any]]:
    n = max(1, int(n))
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def _zip_chunks(a: Sequence[Any], b: Sequence[Any], n: int) -> Iterable[Tuple[Sequence[Any], Sequence[Any]]]:
    n = max(1, int(n))
    for i in range(0, len(a), n):
        yield a[i : i + n], b[i : i + n]

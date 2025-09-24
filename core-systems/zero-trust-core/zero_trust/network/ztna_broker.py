# zero-trust-core/zero_trust/network/ztna_broker.py
from __future__ import annotations

import asyncio
import base64
import json
import time
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState

# Попытка импортировать реальный AuthContext из вашего middleware.
# Если модуль не доступен на этапе генерации, используем тип-заглушку только для аннотаций.
try:
    from zero_trust_core.api.http.middleware.auth import AuthContext  # type: ignore
except Exception:
    @dataclass
    class AuthContext:  # type: ignore
        principal: str
        tenant_id: Optional[str]
        scopes: Tuple[str, ...]
        token_id: Optional[str]
        session_id: Optional[str]
        trust_level: Optional[str]
        risk_score: Optional[float]
        token_binding: Optional[str]
        token_binding_thumbprint: Optional[str]
        claims: Mapping[str, Any]


# ============================== Вспомогательные утилиты ==============================

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _now() -> int:
    return int(time.time())


# ============================== Аудит/Политика/Рейтлимиты ==============================

class Logger(Protocol):
    def __call__(self, name: str, fields: Mapping[str, Any]) -> None: ...


class Policy(Protocol):
    """
    Интерфейс дополнительного энфорсмента для брокера (поверх AuthMiddleware),
    например: проверка права connect к resource_id/протоколу.
    Возвращает (allowed, reasons).
    """
    async def can_connect(self, ctx: AuthContext, resource_id: str, protocol: str) -> Tuple[bool, Tuple[str, ...]]: ...


class TokenBucket:
    """
    Простой токен-бакет для rps/бинарных лимитов.
    """
    def __init__(self, capacity: int, refill_per_s: float) -> None:
        self.capacity = max(1, capacity)
        self.refill = float(refill_per_s)
        self.tokens = float(capacity)
        self.ts = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.ts
        if delta > 0:
            self.tokens = min(self.capacity, self.tokens + delta * self.refill)
            self.ts = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# ============================== Конфигурация брокера ==============================

@dataclass
class BrokerConfig:
    connector_ttl_s: int = 60
    connector_keepalive_s: int = 20
    selector_strategy: str = "least_sessions"  # "least_sessions" | "round_robin"
    max_session_duration_s: int = 3600
    idle_timeout_s: int = 120
    max_message_bytes: int = 1 << 20  # 1 MiB
    per_principal_rps: int = 50
    per_tenant_rps: int = 500
    audit_sample_rate: float = 1.0  # 0..1 (можно снизить при больших нагрузках)


# ============================== Структуры коннекторов/сессий ==============================

@dataclass
class Connector:
    connector_id: str
    resource_id: str
    tenant_id: Optional[str]
    principal: str
    protocol: str  # "tcp" | "http" | "raw"
    ws: WebSocket
    connected_at: int = field(default_factory=_now)
    last_seen: int = field(default_factory=_now)
    active_sessions: int = 0
    total_bytes_up: int = 0
    total_bytes_down: int = 0
    round_robin_order: int = 0  # для RR селектора


@dataclass
class Session:
    session_id: str
    resource_id: str
    principal: str
    tenant_id: Optional[str]
    started_at: int = field(default_factory=_now)
    last_activity: int = field(default_factory=_now)
    bytes_up: int = 0
    bytes_down: int = 0
    connector: Optional[Connector] = None


# ============================== Простейшая реестр/селектор ==============================

class ConnectorRegistry:
    def __init__(self) -> None:
        self._by_resource: Dict[str, List[Connector]] = {}
        self._rr_counter = 0

    def add(self, c: Connector) -> None:
        lst = self._by_resource.setdefault(c.resource_id, [])
        self._rr_counter += 1
        c.round_robin_order = self._rr_counter
        lst.append(c)

    def remove(self, c: Connector) -> None:
        lst = self._by_resource.get(c.resource_id, [])
        try:
            lst.remove(c)
        except ValueError:
            pass
        if not lst:
            self._by_resource.pop(c.resource_id, None)

    def list_for(self, resource_id: str) -> List[Connector]:
        return [c for c in self._by_resource.get(resource_id, [])]

    def select(self, resource_id: str, strategy: str = "least_sessions") -> Optional[Connector]:
        lst = self.list_for(resource_id)
        if not lst:
            return None
        if strategy == "least_sessions":
            lst.sort(key=lambda c: (c.active_sessions, c.last_seen))
            return lst[0]
        # round_robin
        lst.sort(key=lambda c: c.round_robin_order)
        # ротация
        c = lst.pop(0)
        self._rr_counter += 1
        c.round_robin_order = self._rr_counter
        lst.append(c)
        self._by_resource[resource_id] = lst
        return c


# ============================== Протокол сообщений WS ==============================

# Управляющие JSON‑кадры (text):
#  - connector->broker: {"type":"register","resource_id":"db-admin","protocol":"tcp","version":"1.0"}
#  - broker->connector: {"type":"ready"}
#  - any->any: {"type":"ping"} / {"type":"pong"}
#  - broker->connector: {"type":"start","session_id":"..."}  # подготовь туннель к цели
#  - connector->broker: {"type":"accept","session_id":"..."} / {"type":"error","session_id":"...","reason":"..."}
#  Бинарные кадры (bytes) — полезная нагрузка с префиксом 16 байт session_id (uuid4 bytes, для расширений многоканальности). В текущей версии — один канал 1:1, поэтому передаем «чистые» bytes.


# ============================== Брокер ZTNA ==============================

class ZTNABroker:
    def __init__(self, config: Optional[BrokerConfig] = None, logger: Optional[Logger] = None, policy: Optional[Policy] = None) -> None:
        self.cfg = config or BrokerConfig()
        self.log = logger or (lambda n, f: None)
        self.policy = policy
        self.registry = ConnectorRegistry()
        self.sessions: Dict[str, Session] = {}
        self._rps_principal: Dict[str, TokenBucket] = {}
        self._rps_tenant: Dict[str, TokenBucket] = {}

    # ------------------------ Коннектор: регистрация/жизненный цикл ------------------------

    async def handle_connector(self, ws: WebSocket, ctx: AuthContext) -> None:
        await ws.accept()
        try:
            # Ждем register
            msg = await ws.receive_text()
            reg = json.loads(msg)
            if not isinstance(reg, dict) or reg.get("type") != "register":
                await ws.close(code=1008)
                return
            resource_id = str(reg.get("resource_id") or "").strip()
            proto = str(reg.get("protocol") or "tcp").strip().lower()
            if not resource_id or proto not in ("tcp", "http", "raw"):
                await ws.close(code=1008)
                return

            connector = Connector(
                connector_id=secrets.token_hex(8),
                resource_id=resource_id,
                tenant_id=ctx.tenant_id,
                principal=ctx.principal,
                protocol=proto,
                ws=ws,
            )
            self.registry.add(connector)
            self.log("ztna.connector.registered", {
                "rid": resource_id, "cid": connector.connector_id, "sub": ctx.principal, "tid": ctx.tenant_id, "proto": proto
            })
            await ws.send_text(json.dumps({"type": "ready"}))

            # Keepalive/TTL
            while True:
                if ws.client_state != WebSocketState.CONNECTED:
                    break
                try:
                    ev = await asyncio.wait_for(ws.receive(), timeout=self.cfg.connector_keepalive_s)
                except asyncio.TimeoutError:
                    # Посылаем ping; если разрыв — исключение закроет цикл
                    try:
                        await ws.send_text(json.dumps({"type": "ping"}))
                    except RuntimeError:
                        break
                    continue

                if "text" in ev:
                    try:
                        data = json.loads(ev["text"])
                    except Exception:
                        continue
                    t = data.get("type")
                    if t == "pong":
                        connector.last_seen = _now()
                    elif t == "ping":
                        connector.last_seen = _now()
                        await ws.send_text(json.dumps({"type": "pong"}))
                    elif t == "accept":
                        # подтверждение готовности туннеля (не используется в базовой 1:1 схеме)
                        pass
                    elif t == "error":
                        # ошибка на коннекторе
                        self.log("ztna.connector.error", {"rid": resource_id, "cid": connector.connector_id, "reason": data.get("reason")})
                    else:
                        # игнорируем прочие управляющие кадры
                        pass
                elif "bytes" in ev:
                    # Бинарные кадры от коннектора будут отправлены соответствующему клиенту в _bridge()
                    # Здесь не обрабатываем — обмен идет в отдельной задаче.
                    pass

                # Снятие по TTL
                if _now() - connector.last_seen > self.cfg.connector_ttl_s:
                    self.log("ztna.connector.ttl_expired", {"rid": resource_id, "cid": connector.connector_id})
                    break

        except WebSocketDisconnect:
            pass
        except Exception as e:
            self.log("ztna.connector.exception", {"err": type(e).__name__})
        finally:
            # Удаляем из реестра
            for r in list(self.registry.list_for(getattr(connector, "resource_id", ""))):
                if r.ws is ws:
                    self.registry.remove(r)
            try:
                await ws.close()
            except Exception:
                pass

    # ------------------------ Клиент: подключение/мост ------------------------

    async def handle_client(self, ws: WebSocket, ctx: AuthContext, resource_id: str, protocol: str = "tcp") -> None:
        # Аутентифицированный клиент; дополнительно — policy.can_connect
        await ws.accept()
        if self.policy:
            allowed, reasons = await self.policy.can_connect(ctx, resource_id, protocol)
            if not allowed:
                await self._close_with_policy(ws, reasons)
                return

        # RPS лимиты
        if not self._allow_rps(ctx):
            await ws.close(code=1013, reason="rate_limited")
            return

        connector = self.registry.select(resource_id, strategy=self.cfg.selector_strategy)
        if not connector:
            await ws.close(code=1013, reason="no_connector")
            return

        session_id = secrets.token_hex(16)
        sess = Session(session_id=session_id, resource_id=resource_id, principal=ctx.principal, tenant_id=ctx.tenant_id, connector=connector)
        self.sessions[session_id] = sess
        connector.active_sessions += 1
        self.log("ztna.session.start", {"sid": session_id, "rid": resource_id, "sub": ctx.principal, "cid": connector.connector_id})

        try:
            # Инициируем старт на коннекторе (управляющий кадр)
            try:
                await connector.ws.send_text(json.dumps({"type": "start", "session_id": session_id, "protocol": protocol}))
            except RuntimeError:
                await ws.close(code=1011, reason="connector_unavailable")
                return

            # Двунаправленный мост данных
            await self._bridge(ws, connector.ws, sess)
        except WebSocketDisconnect:
            pass
        except Exception as e:
            self.log("ztna.session.exception", {"sid": session_id, "err": type(e).__name__})
        finally:
            connector.active_sessions = max(0, connector.active_sessions - 1)
            self.sessions.pop(session_id, None)
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.close()
            except Exception:
                pass
            self.log("ztna.session.end", {"sid": session_id, "rid": resource_id, "bytes_up": sess.bytes_up, "bytes_down": sess.bytes_down})

    # ------------------------ Мостирование ------------------------

    async def _bridge(self, client_ws: WebSocket, conn_ws: WebSocket, sess: Session) -> None:
        idle_timeout = self.cfg.idle_timeout_s
        absolute_deadline = sess.started_at + self.cfg.max_session_duration_s

        async def c2k() -> None:
            while True:
                if _now() > absolute_deadline:
                    await client_ws.close(code=1000)
                    return
                try:
                    ev = await asyncio.wait_for(client_ws.receive(), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    await client_ws.close(code=1000, reason="idle_timeout")
                    return
                if "bytes" in ev:
                    b = ev["bytes"]
                    if not b:
                        continue
                    if len(b) > self.cfg.max_message_bytes:
                        await client_ws.close(code=1009, reason="message_too_big")
                        return
                    sess.last_activity = _now()
                    sess.bytes_up += len(b)
                    try:
                        await conn_ws.send_bytes(b)
                    except RuntimeError:
                        await client_ws.close(code=1011, reason="connector_broken")
                        return
                elif "text" in ev:
                    # Клиентские управляющие кадры
                    try:
                        data = json.loads(ev["text"])
                    except Exception:
                        continue
                    t = data.get("type")
                    if t == "ping":
                        await client_ws.send_text(json.dumps({"type": "pong"}))
                    else:
                        # прочие текстовые игнорируем
                        pass
                else:
                    return

        async def k2c() -> None:
            while True:
                if _now() > absolute_deadline:
                    await conn_ws.close(code=1000)
                    return
                try:
                    ev = await asyncio.wait_for(conn_ws.receive(), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    # если коннектор не активен — закрываем
                    await client_ws.close(code=1011, reason="connector_idle")
                    return
                if "bytes" in ev:
                    b = ev["bytes"]
                    if not b:
                        continue
                    if len(b) > self.cfg.max_message_bytes:
                        await client_ws.close(code=1009, reason="message_too_big")
                        return
                    sess.last_activity = _now()
                    sess.bytes_down += len(b)
                    try:
                        await client_ws.send_bytes(b)
                    except RuntimeError:
                        await conn_ws.close(code=1011, reason="client_broken")
                        return
                elif "text" in ev:
                    try:
                        data = json.loads(ev["text"])
                    except Exception:
                        continue
                    t = data.get("type")
                    if t == "ping":
                        await conn_ws.send_text(json.dumps({"type": "pong"}))
                    elif t == "error":
                        await client_ws.close(code=1011, reason=str(data.get("reason", "upstream_error")))
                        return
                    elif t == "accept":
                        # ok to proceed
                        pass
                    else:
                        # игнорируем
                        pass
                else:
                    return

        # Запускаем параллельные перекачки
        await asyncio.gather(c2k(), k2c())

    # ------------------------ Внутреннее ------------------------

    async def _close_with_policy(self, ws: WebSocket, reasons: Tuple[str, ...]) -> None:
        try:
            await ws.send_text(json.dumps({"type": "deny", "reasons": list(reasons)}))
        except Exception:
            pass
        await ws.close(code=1008, reason="policy_denied")

    def _allow_rps(self, ctx: AuthContext) -> bool:
        key_p = ctx.principal or "anon"
        key_t = ctx.tenant_id or "global"
        bkt_p = self._rps_principal.setdefault(key_p, TokenBucket(self.cfg.per_principal_rps, float(self.cfg.per_principal_rps)))
        bkt_t = self._rps_tenant.setdefault(key_t, TokenBucket(self.cfg.per_tenant_rps, float(self.cfg.per_tenant_rps)))
        return bkt_p.allow() and bkt_t.allow()


# ============================== FastAPI роутер ==============================

router = APIRouter(prefix="/api/v1/broker", tags=["ztna-broker"])
_broker = ZTNABroker()


@router.websocket("/connector/register")
async def connector_register(ws: WebSocket) -> None:
    """
    Регистрация коннектора.
    Требования:
      - Клиент проходит AuthMiddleware; в request.state.auth лежит AuthContext.
      - Первый текстовый кадр: {"type":"register","resource_id":"...","protocol":"tcp|http|raw"}.
    """
    ctx: Optional[AuthContext] = getattr(ws.scope.get("state", {}), "auth", None) or ws.scope.get("state", {}).get("auth")  # type: ignore
    if not ctx:
        await ws.close(code=4401)  # non-standard 'Unauthorized'
        return
    await _broker.handle_connector(ws, ctx)  # type: ignore[arg-type]


@router.websocket("/client/{resource_id}")
async def client_connect(ws: WebSocket, resource_id: str, protocol: str = "tcp") -> None:
    """
    Клиентское подключение к ресурсу через брокер.
    Требования:
      - Клиент проходит AuthMiddleware; в request.state.auth лежит AuthContext.
      - Политика (если настроена) может дополнительно запретить подключение.
    """
    ctx: Optional[AuthContext] = getattr(ws.scope.get("state", {}), "auth", None) or ws.scope.get("state", {}).get("auth")  # type: ignore
    if not ctx:
        await ws.close(code=4401)
        return
    await _broker.handle_client(ws, ctx, resource_id, protocol)  # type: ignore[arg-type]


# ============================== Точки расширения ==============================

def set_broker(broker: ZTNABroker) -> None:
    """
    Позволяет внедрить собственный экземпляр (с кастомной политикой/логгером/конфигом).
    """
    global _broker
    _broker = broker


def set_logger(logger: Logger) -> None:
    """
    Установить внешний логгер для брокера.
    """
    _broker.log = logger

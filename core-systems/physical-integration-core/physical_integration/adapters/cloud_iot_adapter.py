from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import random
import ssl
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
)

# ============================================================
# Структурные логи по умолчанию (JSON‑форматтер без внешних зависимостей)
# ============================================================

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Включаем стандартные поля, если заданы
        for k in ("module", "funcName", "lineno"):
            payload[k] = getattr(record, k, None)
        # Поля из extra
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)
        # Исключения
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _default_logger(name: str = "physical_integration.cloud_iot_adapter") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


log = _default_logger()

# ============================================================
# Метрики: минимальный интерфейс без внешних зависимостей
# ============================================================

class Metrics(Protocol):
    def inc_counter(self, name: str, value: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None: ...
    def observe(self, name: str, value: float, labels: Optional[Mapping[str, str]] = None) -> None: ...


class NoopMetrics:
    def inc_counter(self, name: str, value: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        pass
    def observe(self, name: str, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        pass


# ============================================================
# Конфигурация
# ============================================================

@dataclass(frozen=True)
class TopicTemplates:
    telemetry: str = "devices/{device_id}/telemetry"
    events: str = "devices/{device_id}/events/{event_type}"
    commands_subscribe: str = "devices/{device_id}/commands/#"
    twin_update: str = "devices/{device_id}/twin/update"
    twin_get: str = "devices/{device_id}/twin/get"
    # Дополнительно — любое число произвольных тем через mapping в адаптере при необходимости


@dataclass(frozen=True)
class TLSConfig:
    enable: bool = True
    ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    # Пиннинг по отпечатку SHA256 (DER сертификата сервера). Если задан — проверяем вручную.
    server_cert_sha256_pin: Optional[str] = None
    # Разрешить слабые шифры — по умолчанию нет
    allow_weak_ciphers: bool = False


@dataclass(frozen=True)
class AuthConfig:
    username: Optional[str] = None
    password: Optional[str] = None  # или токен
    # HMAC подпись исходящих сообщений (добавляет поле "sig" в envelope)
    hmac_secret: Optional[str] = None
    hmac_alg: str = "sha256"


@dataclass(frozen=True)
class RetryPolicy:
    # экспоненциальный backoff с джиттером
    max_attempts: int = 0  # 0 = бесконечно
    base_delay_sec: float = 0.5
    max_delay_sec: float = 30.0
    multiplier: float = 2.0
    jitter: float = 0.2  # 0..1 как доля от delay


@dataclass(frozen=True)
class CloudIoTConfig:
    provider: str = "generic"
    endpoint: str = "localhost"
    port: int = 1883
    client_id: str = "physical-integration-core"
    keepalive_sec: int = 60
    qos: int = 1
    clean_session: bool = True
    use_websockets: bool = False  # для MQTT брокера с WS
    tls: TLSConfig = field(default_factory=TLSConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    topics: TopicTemplates = field(default_factory=TopicTemplates)
    # Поддержка режима офлайн/локальной шины
    allow_local_fallback: bool = True
    # Таймауты
    connect_timeout_sec: float = 15.0
    op_timeout_sec: float = 10.0


# ============================================================
# Утилиты безопасности и backoff
# ============================================================

def _hmac_sign(secret: str, payload: bytes, alg: str = "sha256") -> str:
    digestmod = getattr(hashlib, alg)
    return hmac.new(secret.encode("utf-8"), payload, digestmod).hexdigest()


def _jittered_backoff(
    attempt: int, base: float, multiplier: float, max_delay: float, jitter: float
) -> float:
    delay = min(base * (multiplier ** max(0, attempt - 1)), max_delay)
    if jitter > 0:
        r = random.random() * 2 - 1  # [-1, 1)
        delay = delay * (1 + r * jitter)
    return max(0.0, delay)


def _json_dumps(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ============================================================
# Транспортный слой
# ============================================================

class AsyncTransport(ABC):
    def __init__(self) -> None:
        self._connect_lock = asyncio.Lock()

    @abstractmethod
    async def connect(self) -> None: ...
    @abstractmethod
    async def disconnect(self) -> None: ...
    @abstractmethod
    async def publish(self, topic: str, payload: bytes, qos: int = 1, retain: bool = False) -> None: ...
    @abstractmethod
    async def subscribe(self, topic: str, handler: Callable[[str, bytes], Awaitable[None]]) -> None: ...
    @abstractmethod
    def is_connected(self) -> bool: ...


# -------- LocalTransport: офлайн/тестовая шина --------

class LocalTransport(AsyncTransport):
    def __init__(self) -> None:
        super().__init__()
        self._connected = False
        self._subs: Dict[str, Callable[[str, bytes], Awaitable[None]]] = {}

    async def connect(self) -> None:
        async with self._connect_lock:
            self._connected = True
            log.info("LocalTransport connected", extra={"extra": {"transport": "local"}})

    async def disconnect(self) -> None:
        self._connected = False
        self._subs.clear()
        log.info("LocalTransport disconnected", extra={"extra": {"transport": "local"}})

    def is_connected(self) -> bool:
        return self._connected

    async def publish(self, topic: str, payload: bytes, qos: int = 1, retain: bool = False) -> None:
        if not self._connected:
            raise RuntimeError("LocalTransport is not connected")
        # Примитивный матчинг '+' и '#'
        for pat, handler in list(self._subs.items()):
            if _topic_match(pat, topic):
                await handler(topic, payload)

    async def subscribe(self, topic: str, handler: Callable[[str, bytes], Awaitable[None]]) -> None:
        if not self._connected:
            raise RuntimeError("LocalTransport is not connected")
        self._subs[topic] = handler


def _topic_match(pattern: str, topic: str) -> bool:
    # MQTT‑подобный матчинг для локального транспорта
    p_levels = pattern.split("/")
    t_levels = topic.split("/")
    for i, p in enumerate(p_levels):
        if p == "#":
            return True
        if i >= len(t_levels):
            return False
        if p != "+" and p != t_levels[i]:
            return False
    return len(p_levels) == len(t_levels)


# -------- MqttTransport на paho‑mqtt (необязательная зависимость) --------

class MqttTransport(AsyncTransport):
    def __init__(
        self,
        cfg: CloudIoTConfig,
        metrics: Metrics = None,
        logger: logging.Logger = None,
    ) -> None:
        super().__init__()
        try:
            import paho.mqtt.client as mqtt  # type: ignore
        except Exception as e:
            raise RuntimeError("paho-mqtt не установлен") from e

        self._mqtt = mqtt
        self._cfg = cfg
        self._metrics = metrics or NoopMetrics()
        self._log = logger or log

        self._client = mqtt.Client(
            client_id=cfg.client_id or "",
            clean_session=cfg.clean_session,
            transport="websockets" if cfg.use_websockets else "tcp",
            protocol=mqtt.MQTTv311,
        )
        if cfg.auth.username is not None:
            self._client.username_pw_set(cfg.auth.username, cfg.auth.password or "")

        if cfg.tls.enable:
            ctx = _make_ssl_context(cfg.tls)
            self._client.tls_set_context(ctx)

        self._futures_puback: Dict[int, asyncio.Future[None]] = {}
        self._handlers: Dict[str, Callable[[str, bytes], Awaitable[None]]] = {}
        self._connected = asyncio.Event()

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message
        self._client.on_publish = self._on_publish

        # Асинхронный цикл MQTT в отдельном потоке
        self._client.loop_start()

    # ---- callbacks ----

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected.set()
            self._log.info("MQTT connected", extra={"extra": {"endpoint": self._cfg.endpoint, "port": self._cfg.port}})
        else:
            self._log.error("MQTT connect failed", extra={"extra": {"rc": rc}})

    def _on_disconnect(self, client, userdata, rc):
        self._connected.clear()
        self._log.info("MQTT disconnected", extra={"extra": {"rc": rc}})

    def _on_publish(self, client, userdata, mid):
        fut = self._futures_puback.pop(mid, None)
        if fut and not fut.done():
            fut.set_result(None)

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        payload = msg.payload
        for pat, handler in list(self._handlers.items()):
            if _topic_match(pat, topic):
                asyncio.get_event_loop().create_task(handler(topic, payload))

    # ---- AsyncTransport ----

    async def connect(self) -> None:
        async with self._connect_lock:
            if self.is_connected():
                return
            attempt = 1
            while True:
                try:
                    self._client.connect(self._cfg.endpoint, self._cfg.port, keepalive=self._cfg.keepalive_sec)
                    # ожидаем on_connect
                    await asyncio.wait_for(self._connected.wait(), timeout=self._cfg.connect_timeout_sec)
                    return
                except Exception as e:
                    self._metrics.inc_counter("mqtt_connect_errors")
                    delay = _jittered_backoff(
                        attempt, self._cfg.retry.base_delay_sec, self._cfg.retry.multiplier,
                        self._cfg.retry.max_delay_sec, self._cfg.retry.jitter
                    )
                    self._log.error(
                        "MQTT connect attempt failed",
                        extra={"extra": {"attempt": attempt, "error": repr(e), "sleep_sec": round(delay, 3)}},
                    )
                    attempt += 1
                    if self._cfg.retry.max_attempts and attempt > self._cfg.retry.max_attempts:
                        raise
                    await asyncio.sleep(delay)

    async def disconnect(self) -> None:
        self._client.disconnect()
        # ждём on_disconnect
        for _ in range(20):
            if not self.is_connected():
                break
            await asyncio.sleep(0.05)
        self._client.loop_stop()

    def is_connected(self) -> bool:
        return self._connected.is_set()

    async def publish(self, topic: str, payload: bytes, qos: int = 1, retain: bool = False) -> None:
        start = time.perf_counter()
        rc, mid = self._client.publish(topic, payload, qos=qos, retain=retain)
        if rc != self._mqtt.MQTT_ERR_SUCCESS:
            self._metrics.inc_counter("mqtt_publish_errors")
            raise RuntimeError(f"MQTT publish error rc={rc}")
        if qos > 0:
            fut: asyncio.Future[None] = asyncio.get_event_loop().create_future()
            self._futures_puback[mid] = fut
            await asyncio.wait_for(fut, timeout=self._cfg.op_timeout_sec)
        self._metrics.observe("mqtt_publish_latency_sec", time.perf_counter() - start, labels={"topic": topic})

    async def subscribe(self, topic: str, handler: Callable[[str, bytes], Awaitable[None]]) -> None:
        rc, _ = self._client.subscribe(topic, qos=self._cfg.qos)
        if rc != self._mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT subscribe error rc={rc}")
        self._handlers[topic] = handler


def _make_ssl_context(tls: TLSConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if tls.ca_cert_path:
        ctx.load_verify_locations(cafile=tls.ca_cert_path)
    if tls.client_cert_path and tls.client_key_path:
        ctx.load_cert_chain(certfile=tls.client_cert_path, keyfile=tls.client_key_path)
    if not tls.allow_weak_ciphers:
        with contextlib.suppress(Exception):
            ctx.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
    # Принудительная проверка имени хоста — по умолчанию включена
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    if tls.server_cert_sha256_pin:
        # Оборачиваем SSLContext для проверки пиннинга при рукопожатии
        orig_wrap = ctx.wrap_socket

        def wrap_socket_with_pin(*args, **kwargs):
            sslsock = orig_wrap(*args, **kwargs)
            cert_bin = sslsock.getpeercert(binary_form=True)
            fp = hashlib.sha256(cert_bin).hexdigest()
            if fp.lower() != tls.server_cert_sha256_pin.lower():
                raise ssl.SSLError("Server certificate pinning check failed")
            return sslsock

        ctx.wrap_socket = wrap_socket_with_pin  # type: ignore
    return ctx


# ============================================================
# Адаптер верхнего уровня
# ============================================================

class CloudIoTAdapter:
    """
    Промышленный адаптер облачного IoT через абстрактный транспорт.
    Не содержит провайдер‑специфичных предположений: всё настраивается темами.
    """

    def __init__(
        self,
        config: CloudIoTConfig,
        metrics: Optional[Metrics] = None,
        logger: Optional[logging.Logger] = None,
        transport: Optional[AsyncTransport] = None,
    ) -> None:
        self._cfg = config
        self._log = logger or log
        self._metrics = metrics or NoopMetrics()
        self._twin_cache: MutableMapping[str, Dict[str, Any]] = {}
        self._devices: MutableMapping[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

        if transport is not None:
            self._transport = transport
        else:
            # Пытаемся создать MQTT транспорт; если не выходит и разрешён локальный — используем локальный
            with contextlib.suppress(Exception):
                self._transport = MqttTransport(config, metrics=self._metrics, logger=self._log)  # type: ignore
            if not hasattr(self, "_transport"):
                if not self._cfg.allow_local_fallback:
                    raise RuntimeError("MQTT транспорт недоступен, а локальный запретен конфигом")
                self._log.warning("Fallback to LocalTransport", extra={"extra": {"reason": "paho-mqtt unavailable"}})
                self._transport = LocalTransport()

    # ------------- Жизненный цикл -------------

    async def connect(self) -> None:
        await self._transport.connect()

    async def disconnect(self) -> None:
        await self._transport.disconnect()

    # ------------- Регистрация устройств -------------

    async def register_device(self, device_id: str, attrs: Optional[Mapping[str, Any]] = None) -> None:
        async with self._lock:
            self._devices[device_id] = {"attrs": dict(attrs or {}), "ts": time.time()}
        self._metrics.inc_counter("device_registered", labels={"device_id": device_id})
        self._log.info("Device registered", extra={"extra": {"device_id": device_id}})

    async def deregister_device(self, device_id: str) -> None:
        async with self._lock:
            self._devices.pop(device_id, None)
            self._twin_cache.pop(device_id, None)
        self._metrics.inc_counter("device_deregistered", labels={"device_id": device_id})
        self._log.info("Device deregistered", extra={"extra": {"device_id": device_id}})

    # ------------- Публикация данных -------------

    async def publish_telemetry(
        self,
        device_id: str,
        payload: Mapping[str, Any],
        timestamp_ms: Optional[int] = None,
        retain: bool = False,
    ) -> None:
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)

        envelope = {
            "device_id": device_id,
            "ts": timestamp_ms,
            "type": "telemetry",
            "payload": payload,
        }
        body = self._encode_envelope(envelope)
        topic = self._cfg.topics.telemetry.format(device_id=device_id)
        await self._transport.publish(topic, body, qos=self._cfg.qos, retain=retain)
        self._metrics.inc_counter("telemetry_published", labels={"device_id": device_id})
        self._log.info("Telemetry published", extra={"extra": {"device_id": device_id, "topic": topic}})

    async def publish_event(
        self,
        device_id: str,
        event_type: str,
        attributes: Mapping[str, Any],
        retain: bool = False,
    ) -> None:
        envelope = {
            "device_id": device_id,
            "ts": int(time.time() * 1000),
            "type": "event",
            "event_type": event_type,
            "payload": attributes,
        }
        body = self._encode_envelope(envelope)
        topic = self._cfg.topics.events.format(device_id=device_id, event_type=event_type)
        await self._transport.publish(topic, body, qos=self._cfg.qos, retain=retain)
        self._metrics.inc_counter("event_published", labels={"device_id": device_id, "event_type": event_type})
        self._log.info("Event published", extra={"extra": {"device_id": device_id, "topic": topic}})

    # ------------- Twin / тень устройства -------------

    async def update_twin(self, device_id: str, patch: Mapping[str, Any]) -> None:
        envelope = {
            "device_id": device_id,
            "ts": int(time.time() * 1000),
            "type": "twin.update",
            "patch": patch,
        }
        body = self._encode_envelope(envelope)
        topic = self._cfg.topics.twin_update.format(device_id=device_id)
        await self._transport.publish(topic, body, qos=self._cfg.qos, retain=False)
        async with self._lock:
            cur = self._twin_cache.get(device_id, {})
            cur.update(patch)
            self._twin_cache[device_id] = cur
        self._metrics.inc_counter("twin_update_published", labels={"device_id": device_id})

    async def get_twin(self, device_id: str) -> Dict[str, Any]:
        # Возвращаем кэш. При необходимости вы можете расширить до запроса twin_get и ожидания ответа/репорта.
        async with self._lock:
            return dict(self._twin_cache.get(device_id, {}))

    # ------------- Команды (входящие) -------------

    async def subscribe_commands(
        self,
        device_id: str,
        handler: Callable[[str, Dict[str, Any]], Awaitable[Dict[str, Any]]],
    ) -> None:
        """
        handler(topic, message_dict) -> await -> reply_dict
        Для подтверждения и ответа публикатор должен знать, куда слать reply.
        В этом примере ответ публикуется в topic + "/reply" (общая практика, без предположений о провайдерах).
        """
        topic_pat = self._cfg.topics.commands_subscribe.format(device_id=device_id)

        async def _on_message(topic: str, payload: bytes) -> None:
            started = time.perf_counter()
            try:
                msg = json.loads(payload.decode("utf-8"))
                if not self._verify_envelope(msg):
                    self._metrics.inc_counter("command_dropped_bad_signature")
                    self._log.warning("Command signature invalid", extra={"extra": {"topic": topic}})
                    return
                reply = await handler(topic, msg)
                reply_body = self._encode_envelope({
                    "device_id": device_id,
                    "ts": int(time.time() * 1000),
                    "type": "command.reply",
                    "correlation_id": msg.get("correlation_id"),
                    "payload": reply,
                })
                reply_topic = f"{topic}/reply"
                await self._transport.publish(reply_topic, reply_body, qos=self._cfg.qos, retain=False)
                self._metrics.observe("command_handle_latency_sec", time.perf_counter() - started)
                self._metrics.inc_counter("command_handled_ok")
            except Exception as e:
                self._metrics.inc_counter("command_handled_error")
                self._log.error("Command handling error", extra={"extra": {"topic": topic, "error": repr(e)}})

        await self._transport.subscribe(topic_pat, _on_message)
        self._log.info("Subscribed for commands", extra={"extra": {"device_id": device_id, "topic": topic_pat}})

    # ------------- Health -------------

    async def health(self) -> Dict[str, Any]:
        return {
            "connected": self._transport.is_connected(),
            "provider": self._cfg.provider,
            "endpoint": self._cfg.endpoint,
            "qos": self._cfg.qos,
            "devices": len(self._devices),
            "twin_cache": len(self._twin_cache),
        }

    # ------------- Вспомогательные -------------

    def _encode_envelope(self, envelope: Dict[str, Any]) -> bytes:
        body = _json_dumps(envelope)
        if self._cfg.auth.hmac_secret:
            sig = _hmac_sign(self._cfg.auth.hmac_secret, body, self._cfg.auth.hmac_alg)
            # Важно: подпись добавляем к объекту и повторно сериализуем, сохраняя каноничность
            signed = dict(envelope)
            signed["sig"] = {"alg": self._cfg.auth.hmac_alg, "value": sig}
            body = _json_dumps(signed)
        return body

    def _verify_envelope(self, envelope: Mapping[str, Any]) -> bool:
        sig = envelope.get("sig")
        if not sig:
            return True if not self._cfg.auth.hmac_secret else False
        if not self._cfg.auth.hmac_secret:
            return False
        try:
            # Проверяем подпись по канонично сериализованному объекту без поля sig
            clone = dict(envelope)
            clone.pop("sig", None)
            body = _json_dumps(clone)
            expected = _hmac_sign(self._cfg.auth.hmac_secret, body, sig.get("alg", "sha256"))
            return hmac.compare_digest(expected, sig.get("value", ""))
        except Exception:
            return False


# ============================================================
# Пример минимального использования (можно удалить в проде)
# ============================================================

async def _example() -> None:
    cfg = CloudIoTConfig(
        provider="generic",
        endpoint=os.environ.get("MQTT_ENDPOINT", "localhost"),
        port=int(os.environ.get("MQTT_PORT", "1883")),
        client_id="physical-integration-core-example",
        tls=TLSConfig(enable=False),
        auth=AuthConfig(username=os.environ.get("MQTT_USER"), password=os.environ.get("MQTT_PASS"), hmac_secret="secret"),
        allow_local_fallback=True,
    )
    adapter = CloudIoTAdapter(cfg)
    await adapter.connect()
    await adapter.register_device("dev-1", {"model": "X1000"})

    async def on_cmd(topic: str, msg: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": True, "echo": msg.get("payload")}

    await adapter.subscribe_commands("dev-1", on_cmd)
    await adapter.publish_telemetry("dev-1", {"temp": 21.7})
    await adapter.publish_event("dev-1", "boot", {"fw": "1.2.3"})
    await adapter.update_twin("dev-1", {"threshold": 42})

    h = await adapter.health()
    log.info("Health", extra={"extra": h})
    await adapter.disconnect()


if __name__ == "__main__":
    # Не блокируем основной поток в проде — это только демонстрация
    asyncio.run(_example())

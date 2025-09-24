# physical-integration-core/physical_integration/protocols/mqtt_client.py
"""
Industrial MQTT client for Physical Integration Core.

Dependencies (Python >= 3.10):
  asyncio-mqtt>=0.16
  prometheus_client>=0.19
  httpx>=0.27       # only if OAuth2 is used (PIC_MQTT_OAUTH_TOKEN_URL set)
  orjson>=3.9       # optional (fast JSON)

Key features:
- TLS/mTLS, configurable via env
- Optional OAuth2 Client Credentials (password = bearer token); auto-reconnect on expiry
- Robust reconnect with exponential backoff + jitter
- Last Will and Testament (LWT) + Birth message (retained)
- Global rate limits (recv/publish), max payload size, idempotency window
- Prometheus metrics + structured logging
- JSON decode/encode helpers, sane defaults
- Pluggable message handler callback
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import random
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from asyncio_mqtt import Client, MqttError
from prometheus_client import Counter, Histogram, Gauge

try:
    import orjson  # type: ignore

    def json_dumps(obj: Any) -> str:
        return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY).decode()

    def json_loads(data: bytes) -> Any:
        return orjson.loads(data)
except Exception:  # pragma: no cover
    def json_dumps(obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def json_loads(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))

# =========================
# Logging
# =========================
LOG = logging.getLogger("pic.mqtt")
if not LOG.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO if os.getenv("PIC_DEBUG", "false").lower() != "true" else logging.DEBUG)

# =========================
# Prometheus metrics
# =========================
MQTT_CONNECTED = Gauge("mqtt_connected", "MQTT connection status (1=connected,0=down)")
MQTT_RECONNECTS = Counter("mqtt_reconnects_total", "Reconnect attempts")
MQTT_MESSAGES_IN = Counter("mqtt_messages_in_total", "MQTT messages received", ["topic"])
MQTT_MESSAGES_OUT = Counter("mqtt_messages_out_total", "MQTT messages published", ["topic"])
MQTT_ERRORS = Counter("mqtt_errors_total", "MQTT errors", ["stage"])
MQTT_RECV_LAT = Histogram("mqtt_receive_latency_seconds", "Message handling latency", buckets=(0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5))
MQTT_PUB_LAT = Histogram("mqtt_publish_latency_seconds", "Publish latency", buckets=(0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5))

# =========================
# Settings from environment
# =========================
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)

@dataclass
class MqttSettings:
    host: str = _env("PIC_MQTT_HOST", "mqtt-broker.edge.svc")
    port: int = int(_env("PIC_MQTT_PORT", "8883"))
    client_id: str = _env("PIC_MQTT_CLIENT_ID", f"pic-{uuid.uuid4().hex[:8]}")
    username: Optional[str] = _env("PIC_MQTT_USERNAME")
    password: Optional[str] = _env("PIC_MQTT_PASSWORD")
    keepalive: int = int(_env("PIC_MQTT_KEEPALIVE", "30"))
    clean_session: bool = _env("PIC_MQTT_CLEAN_SESSION", "true").lower() == "true"
    session_expiry: int = int(_env("PIC_MQTT_SESSION_EXPIRY", "3600"))  # used for MQTT v5; kept for future

    # TLS / mTLS
    tls_enabled: bool = _env("PIC_MQTT_TLS_ENABLED", "true").lower() == "true"
    tls_insecure: bool = _env("PIC_MQTT_TLS_INSECURE", "false").lower() == "true"
    tls_ca: Optional[str] = _env("PIC_MQTT_TLS_CA")                      # path to CA bundle
    tls_cert: Optional[str] = _env("PIC_MQTT_TLS_CERT")                  # client cert (for mTLS)
    tls_key: Optional[str] = _env("PIC_MQTT_TLS_KEY")                    # client key

    # OAuth2 (optional)
    oauth_token_url: Optional[str] = _env("PIC_MQTT_OAUTH_TOKEN_URL")
    oauth_client_id: Optional[str] = _env("PIC_MQTT_OAUTH_CLIENT_ID")
    oauth_client_secret: Optional[str] = _env("PIC_MQTT_OAUTH_CLIENT_SECRET")
    oauth_scope: str = _env("PIC_MQTT_OAUTH_SCOPE", "mqtt:publish mqtt:subscribe")
    oauth_audience: Optional[str] = _env("PIC_MQTT_OAUTH_AUDIENCE")

    # Topics
    subscribe: List[Tuple[str, int]] = None  # [("sensors/+/telemetry",1)]
    publish_birth: Optional[str] = _env("PIC_MQTT_BIRTH_TOPIC", "status/{client_id}")
    publish_lwt: Optional[str] = _env("PIC_MQTT_LWT_TOPIC", "status/{client_id}")

    # Limits
    max_payload_bytes: int = int(_env("PIC_MQTT_MAX_PAYLOAD_BYTES", "1048576"))  # 1 MiB
    recv_rps: int = int(_env("PIC_MQTT_RECV_RPS", "500"))
    recv_burst: int = int(_env("PIC_MQTT_RECV_BURST", "1000"))
    pub_rps: int = int(_env("PIC_MQTT_PUB_RPS", "500"))
    pub_burst: int = int(_env("PIC_MQTT_PUB_BURST", "1000"))
    idem_ttl_sec: float = float(_env("PIC_MQTT_IDEMPOTENCY_TTL_SEC", "300"))

    # Backoff
    backoff_min: float = float(_env("PIC_MQTT_BACKOFF_MIN", "0.5"))
    backoff_max: float = float(_env("PIC_MQTT_BACKOFF_MAX", "30"))
    backoff_factor: float = float(_env("PIC_MQTT_BACKOFF_FACTOR", "1.7"))

    def __post_init__(self) -> None:
        # Parse subscribe list like: "sensors/+/telemetry:1,alerts/#:1"
        subs = _env("PIC_MQTT_SUBSCRIBE", "")
        lst: List[Tuple[str, int]] = []
        if subs:
            for part in subs.split(","):
                part = part.strip()
                if not part:
                    continue
                if ":" in part:
                    t, qs = part.split(":", 1)
                    lst.append((t.strip(), max(0, min(2, int(qs)))))
                else:
                    lst.append((part, 1))
        self.subscribe = lst


# =========================
# OAuth2 client credentials provider (optional)
# =========================
class OAuth2TokenProvider:
    def __init__(self, settings: MqttSettings) -> None:
        self._settings = settings
        self._token: Optional[str] = None
        self._exp_ts: float = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self) -> Tuple[str, float]:
        async with self._lock:
            now = time.time()
            if self._token and (self._exp_ts - 60) > now:
                return self._token, self._exp_ts
            # fetch
            token, exp = await self._fetch_token()
            self._token, self._exp_ts = token, exp
            return token, exp

    async def _fetch_token(self) -> Tuple[str, float]:
        import httpx  # lazy import
        data = {
            "grant_type": "client_credentials",
            "scope": self._settings.oauth_scope,
        }
        if self._settings.oauth_audience:
            data["audience"] = self._settings.oauth_audience
        auth = (self._settings.oauth_client_id or "", self._settings.oauth_client_secret or "")
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(self._settings.oauth_token_url, data=data, auth=auth)
            r.raise_for_status()
            js = r.json()
            tok = js["access_token"]
            exp = time.time() + int(js.get("expires_in", 3600))
            return tok, exp


# =========================
# Token bucket (rate limit)
# =========================
@dataclass
class _Bucket:
    tokens: float
    last: float
    cap: float
    rate: float

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        if elapsed > 0:
            self.tokens = min(self.cap, self.tokens + elapsed * self.rate)
            self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# =========================
# Publish message
# =========================
@dataclass
class PublishMessage:
    topic: str
    payload: bytes
    qos: int = 1
    retain: bool = False

    @staticmethod
    def json(topic: str, obj: Any, qos: int = 1, retain: bool = False) -> "PublishMessage":
        return PublishMessage(topic=topic, payload=json_dumps(obj).encode("utf-8"), qos=qos, retain=retain)


# =========================
# MQTT Client
# =========================
class MqttClient:
    """
    Usage:
        client = MqttClient(settings=MqttSettings())
        client.set_message_handler(my_handler)   # async def my_handler(topic, payload, props) -> None
        await client.run_forever()
    """

    def __init__(self, settings: Optional[MqttSettings] = None) -> None:
        self.s = settings or MqttSettings()
        self._oauth = OAuth2TokenProvider(self.s) if self.s.oauth_token_url else None
        self._pub_queue: asyncio.Queue[PublishMessage] = asyncio.Queue(maxsize=10_000)
        self._recv_bucket = _Bucket(tokens=float(self.s.recv_burst), last=time.monotonic(),
                                    cap=float(self.s.recv_burst), rate=float(self.s.recv_rps))
        self._pub_bucket = _Bucket(tokens=float(self.s.pub_burst), last=time.monotonic(),
                                   cap=float(self.s.pub_burst), rate=float(self.s.pub_rps))
        self._idem_cache: Dict[str, float] = {}
        self._loop_task: Optional[asyncio.Task] = None
        self._handler: Optional[Callable[[str, Any, Dict[str, Any]], Awaitable[None]]] = None
        self._stopped = asyncio.Event()

    def set_message_handler(self, handler: Callable[[str, Any, Dict[str, Any]], Awaitable[None]]) -> None:
        self._handler = handler

    async def publish(self, msg: PublishMessage, *, timeout: float = 10.0) -> None:
        await self._pub_queue.put(msg)

    async def run_forever(self) -> None:
        """
        Connects and runs the client forever with resilient reconnection loop.
        """
        LOG.info("mqtt_start host=%s port=%s client_id=%s", self.s.host, self.s.port, self.s.client_id)
        self._stopped.clear()
        delay = self.s.backoff_min
        while not self._stopped.is_set():
            try:
                password = self.s.password
                if self._oauth:
                    token, exp = await self._oauth.get_token()
                    password = token
                    LOG.debug("oauth_token_acquired exp_in=%.1fs", exp - time.time())

                async with self._make_client(password=password) as client:
                    MQTT_CONNECTED.set(1)
                    LOG.info("mqtt_connected")
                    # Birth retained
                    await self._publish_birth(client)
                    # Subscribe
                    await self._subscribe_all(client)
                    # Start workers
                    publish_task = asyncio.create_task(self._publisher(client))
                    consume_task = asyncio.create_task(self._consumer(client))
                    # Wait until one finishes (or stop requested)
                    done, pending = await asyncio.wait(
                        {publish_task, consume_task, self._stopped.wait()},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    # If stop set — cancel workers
                    if self._stopped.is_set():
                        for t in (publish_task, consume_task):
                            t.cancel()
                            with contextlib.suppress(Exception):
                                await t
                        break
                    # Otherwise, some worker ended unexpectedly — raise to reconnect
                    for d in done:
                        if isinstance(d, asyncio.Task) and d.exception():
                            raise d.exception()
                # normally exiting context -> reconnect
            except asyncio.CancelledError:
                break
            except Exception as e:
                MQTT_ERRORS.labels("run_loop").inc()
                LOG.exception("mqtt_error: %s", e)
            finally:
                MQTT_CONNECTED.set(0)
                MQTT_RECONNECTS.inc()
                sleep_for = min(self.s.backoff_max, delay) * (0.5 + random.random())  # jitter
                LOG.warning("mqtt_reconnect_in %.2fs", sleep_for)
                await asyncio.sleep(sleep_for)
                delay *= self.s.backoff_factor

    async def stop(self) -> None:
        self._stopped.set()

    # ------------- internals -------------
    def _tls_context(self) -> Optional[ssl.SSLContext]:
        if not self.s.tls_enabled:
            return None
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.s.tls_ca)
        if self.s.tls_cert and self.s.tls_key:
            ctx.load_cert_chain(self.s.tls_cert, self.s.tls_key)
        if self.s.tls_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # modern ciphers only (can be adjusted)
        try:
            ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
        except Exception:
            pass
        return ctx

    def _make_client(self, *, password: Optional[str]) -> Client:
        # Configure LWT
        lwt_topic = None
        lwt_payload = None
        if self.s.publish_lwt:
            lwt_topic = self._fmt(self.s.publish_lwt)
            lwt_payload = json_dumps({"status": "offline", "ts": time.time()})
        client = Client(
            hostname=self.s.host,
            port=self.s.port,
            client_id=self.s.client_id,
            username=self.s.username,
            password=password,
            keepalive=self.s.keepalive,
            tls_context=self._tls_context(),
            will_message=(lwt_topic, lwt_payload, 1, True) if lwt_topic else None,
        )
        return client

    async def _publish_birth(self, client: Client) -> None:
        if not self.s.publish_birth:
            return
        topic = self._fmt(self.s.publish_birth)
        payload = json_dumps({
            "status": "online",
            "ts": time.time(),
            "client_id": self.s.client_id,
            "env": os.getenv("ENVIRONMENT", "prod")
        })
        await client.publish(topic, payload, qos=1, retain=True)
        MQTT_MESSAGES_OUT.labels(topic).inc()
        LOG.debug("birth_published topic=%s", topic)

    async def _subscribe_all(self, client: Client) -> None:
        if not self.s.subscribe:
            LOG.info("no_subscriptions_configured")
            return
        for topic, qos in self.s.subscribe:
            await client.subscribe((topic, qos))
            LOG.info("subscribed topic=%s qos=%d", topic, qos)

    async def _publisher(self, client: Client) -> None:
        while True:
            msg = await self._pub_queue.get()
            try:
                if not self._pub_bucket.allow():
                    # спим минимально для «выравнивания» ведра
                    await asyncio.sleep(0.01)
                if len(msg.payload) > self.s.max_payload_bytes:
                    MQTT_ERRORS.labels("publish_oversize").inc()
                    LOG.warning("publish_drop_oversize topic=%s bytes=%d", msg.topic, len(msg.payload))
                    continue
                started = time.perf_counter()
                await client.publish(msg.topic, msg.payload, qos=msg.qos, retain=msg.retain)
                MQTT_MESSAGES_OUT.labels(msg.topic).inc()
                MQTT_PUB_LAT.observe(time.perf_counter() - started)
            except MqttError as e:
                MQTT_ERRORS.labels("publish").inc()
                LOG.warning("publish_error topic=%s err=%s", msg.topic, e)
                # попытка вернуть в очередь (с небольшой задержкой)
                await asyncio.sleep(0.2)
                with contextlib.suppress(asyncio.QueueFull):
                    await self._pub_queue.put(msg)

    async def _consumer(self, client: Client) -> None:
        # Единый поток сообщений
        async with client.unfiltered_messages() as messages:
            # Подписки уже оформлены в _subscribe_all
            while True:
                msg = await messages.__anext__()  # raises StopAsyncIteration if channel closed
                topic = msg.topic
                payload = msg.payload  # bytes
                retain = msg.retain
                qos = msg.qos
                if not self._recv_bucket.allow():
                    MQTT_ERRORS.labels("recv_rate_limited").inc()
                    continue
                if len(payload) > self.s.max_payload_bytes:
                    MQTT_ERRORS.labels("recv_oversize").inc()
                    LOG.warning("recv_drop_oversize topic=%s bytes=%d", topic, len(payload))
                    continue
                started = time.perf_counter()
                MQTT_MESSAGES_IN.labels(topic).inc()
                try:
                    obj: Any
                    # Попытка распарсить JSON; иначе оставить bytes
                    try:
                        obj = json_loads(payload)
                    except Exception:
                        obj = payload
                    # Идемпотентность: по отпечатку (topic+payload)
                    if self._seen(topic, payload):
                        continue
                    if self._handler:
                        await self._handler(topic, obj, {"retain": retain, "qos": qos})
                except Exception as e:
                    MQTT_ERRORS.labels("handler").inc()
                    LOG.exception("handler_error topic=%s err=%s", topic, e)
                finally:
                    MQTT_RECV_LAT.observe(time.perf_counter() - started)

    def _fmt(self, tpl: str) -> str:
        return tpl.format(client_id=self.s.client_id)

    def _seen(self, topic: str, payload: bytes) -> bool:
        # 256-бит SHA отпечаток для окна идемпотентности
        fp = hashlib.sha256(topic.encode("utf-8") + b"|" + payload).hexdigest()
        now = time.time()
        # очистка протухших
        for k, ts in list(self._idem_cache.items()):
            if now - ts > self.s.idem_ttl_sec:
                self._idem_cache.pop(k, None)
        if fp in self._idem_cache:
            return True
        self._idem_cache[fp] = now
        return False


# =========================
# Example handler glue (optional)
# =========================
async def example_handler(topic: str, obj: Any, props: Dict[str, Any]) -> None:
    """
    Пример интеграции:
      - route telemetry -> internal bus
      - route alerts -> alerts bus
    Подключите сюда Kafka/AMQP продюсер.
    """
    if isinstance(obj, (dict, list)):
        LOG.debug("recv_json topic=%s keys=%s retain=%s", topic, (list(obj[0].keys()) if isinstance(obj, list) and obj else list(obj.keys()) if isinstance(obj, dict) else []), props.get("retain"))
    else:
        LOG.debug("recv_bytes topic=%s bytes=%d retain=%s", topic, len(obj) if isinstance(obj, (bytes, bytearray)) else -1, props.get("retain"))


# =========================
# Entrypoint for standalone run (optional)
# =========================
async def _main() -> None:
    s = MqttSettings()
    client = MqttClient(s)
    client.set_message_handler(example_handler)
    loop = asyncio.get_running_loop()
    stop_ev = asyncio.Event()

    def _graceful(*_: Any) -> None:
        LOG.info("stopping...")
        loop.create_task(client.stop())
        stop_ev.set()

    for sig in ("SIGINT", "SIGTERM"):
        with contextlib.suppress(AttributeError):
            loop.add_signal_handler(getattr(__import__("signal"), sig), _graceful)

    await asyncio.gather(client.run_forever(), stop_ev.wait())

if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass

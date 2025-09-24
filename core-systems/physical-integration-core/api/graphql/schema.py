from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import hashlib
import json
import os
import time
import typing as t
import uuid

import strawberry
from fastapi import Request
from graphql import GraphQLError
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info
from strawberry.schema.config import StrawberryConfig
from strawberry.subscriptions import GRAPHQL_TRANSPORT_WS_PROTOCOL

# =========================
# СКАЛЯРЫ
# =========================

@strawberry.scalar(description="UTC datetime in ISO-8601 format (e.g., 2025-08-22T12:34:56.789Z)")
def DateTime(value: t.Union[str, dt.datetime]) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    # валидация строки
    try:
        s = str(value)
        # допускаем Z-окончание
        if s.endswith("Z"):
            dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt.datetime.fromisoformat(s)
        return s
    except Exception:
        raise GraphQLError("Invalid DateTime format")

JSON = strawberry.scalar(
    serialize=lambda v: v,
    parse_value=lambda v: v,
    description="Arbitrary JSON object (PII-free).",
    name="JSON",
)
UUID = strawberry.scalar(
    serialize=lambda v: str(v),
    parse_value=lambda v: uuid.UUID(str(v)),
    description="UUID string.",
    name="UUID",
)

# =========================
# БАЗОВЫЕ МОДЕЛИ/КОНТЕКСТ
# =========================

class AuthMethod(str):
    bearer = "bearer"
    api_key = "api_key"
    anonymous = "anonymous"

@strawberry.type
class Principal:
    subject: str
    method: str

@dataclasses.dataclass
class Settings:
    region: str = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-north-1"))
    vod_ingest_bucket: str = os.getenv("VOD_INGEST_BUCKET", "")
    cdn_public_base: str = os.getenv("CDN_PUBLIC_BASE", "")
    idempotency_ttl: int = int(os.getenv("IDEMPOTENCY_TTL", "600"))
    allow_anonymous_read: bool = True

@dataclasses.dataclass
class Context:
    request: Request
    principal: Principal
    settings: Settings
    registry: StreamsRegistry
    idemp: IdempotencyStore
    s3: S3Facade
    pubsub: PubSub

# =========================
# IN-MEMORY СЕРВИСЫ (можно заменить на продовые)
# =========================

@dataclasses.dataclass
class StreamEntity:
    id: str
    name: str
    mode: str
    state: str
    created_at_ms: int
    ingest: t.Dict[str, t.Any]

class StreamsRegistry:
    def __init__(self) -> None:
        self._items: dict[str, StreamEntity] = {}
        self._lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue[dict]] = set()

    async def create(self, name: str, mode: str, ingest: dict) -> StreamEntity:
        async with self._lock:
            sid = uuid.uuid4().hex
            now = int(time.time() * 1000)
            st = StreamEntity(sid, name, mode, "starting", now, ingest)
            self._items[sid] = st
            # авто-переход в running
            st.state = "running"
            await self._publish({"type": "state", "id": sid, "state": st.state, "ts": now})
            return st

    async def stop(self, sid: str) -> bool:
        async with self._lock:
            st = self._items.get(sid)
            if not st:
                return False
            st.state = "stopped"
            await self._publish({"type": "state", "id": sid, "state": st.state, "ts": int(time.time() * 1000)})
            return True

    async def get(self, sid: str) -> t.Optional[StreamEntity]:
        return self._items.get(sid)

    async def list(self, offset: int, limit: int) -> tuple[list[StreamEntity], t.Optional[int]]:
        items = list(self._items.values())
        items.sort(key=lambda x: x.created_at_ms, reverse=True)
        slice_ = items[offset: offset + limit]
        next_off = offset + limit if offset + limit < len(items) else None
        return slice_, next_off

    async def subscribe(self) -> asyncio.Queue[dict]:
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[dict]) -> None:
        self._subscribers.discard(q)

    async def _publish(self, evt: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                # дроп при перегрузе подписчика
                pass

class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self.ttl = ttl_seconds
        self._mem: dict[str, tuple[int, bytes]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> t.Optional[bytes]:
        async with self._lock:
            rec = self._mem.get(key)
            if not rec:
                return None
            ts, data = rec
            if int(time.time()) - ts > self.ttl:
                self._mem.pop(key, None)
                return None
            return data

    async def set(self, key: str, payload: bytes) -> None:
        async with self._lock:
            self._mem[key] = (int(time.time()), payload)

class S3Facade:
    """Здесь только интерфейс для presign. Продовую реализацию подключите отдельно."""
    def __init__(self, region: str) -> None:
        self.region = region

    async def presign_put(self, bucket: str, key: str, content_type: str, expires: int) -> str:
        # В реальной системе используйте aioboto3/boto3; здесь — URL-заглушка для примеров.
        token = base64.urlsafe_b64encode(hashlib.sha256(f"{bucket}:{key}:{expires}".encode()).digest()).decode().rstrip("=")
        return f"https://s3.{os.getenv('AWS_REGION','eu-north-1')}.amazonaws.com/{bucket}/{key}?X-Amz-Signature={token}&X-Amz-Expires={expires}"

class PubSub:
    # фасад вокруг StreamsRegistry.subscribe() для подписки на события стримов
    pass

# =========================
# УТИЛИТЫ (Relay cursors, auth)
# =========================

def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def _unb64(s: str) -> str:
    return base64.b64decode(s.encode()).decode()

def _etag(obj: t.Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()

def _auth_read(ctx: Context, *, allow_anonymous: bool = True) -> None:
    if allow_anonymous and ctx.principal.method in (AuthMethod.bearer, AuthMethod.api_key, AuthMethod.anonymous):
        return
    if not allow_anonymous and ctx.principal.method not in (AuthMethod.bearer, AuthMethod.api_key):
        raise GraphQLError("Authentication required")

def _auth_write(ctx: Context) -> None:
    if ctx.principal.method not in (AuthMethod.bearer, AuthMethod.api_key):
        raise GraphQLError("Authentication required")

# =========================
# ENUMS / INPUTS / TYPES (Relay)
# =========================

@strawberry.enum
class StreamMode(str):
    live = "live"
    vod = "vod"

@strawberry.enum
class StreamState(str):
    starting = "starting"
    running = "running"
    stopping = "stopping"
    stopped = "stopped"
    failed = "failed"

@strawberry.input
class StreamCreateInput:
    name: strawberry.auto
    mode: StreamMode = StreamMode.live
    description: t.Optional[str] = None
    ingestProtocols: list[strawberry.enum("IngestProtocol", ["SRT", "RTMP", "KINESIS"])] = strawberry.field(
        default_factory=lambda: ["SRT"]  # type: ignore
    )

@strawberry.type
class Node:
    id: strawberry.ID

@strawberry.type
class Stream(Node):
    name: str
    mode: StreamMode
    state: StreamState
    createdAt: DateTime
    ingest: JSON
    etag: str

@strawberry.type
class StreamEdge:
    node: Stream
    cursor: str

@strawberry.type
class PageInfo:
    hasNextPage: bool
    endCursor: t.Optional[str]

@strawberry.type
class StreamConnection:
    edges: list[StreamEdge]
    pageInfo: PageInfo
    totalCount: int

@strawberry.input
class PresignInput:
    assetName: str
    contentType: str
    sizeBytes: int
    prefix: str = "incoming/"
    expiresSeconds: int = 900

@strawberry.type
class PresignPayload:
    method: str
    url: str
    headers: JSON
    key: str
    expiresAt: DateTime
    etag: str

@strawberry.input
class AssetFinalizeInput:
    assetId: str
    sourceKey: str
    metadata: JSON = strawberry.field(default_factory=dict)

@strawberry.type
class Asset(Node):
    assetId: str
    status: strawberry.enum("AssetStatus", ["queued", "accepted"])  # type: ignore
    locations: JSON
    etag: str

@strawberry.input
class ManifestInput:
    assetId: str
    variant: strawberry.enum("ManifestVariant", ["hls", "dash"]) = "hls"  # type: ignore
    expiresSeconds: int = 900

@strawberry.type
class ManifestPayload:
    url: str
    expiresAt: DateTime
    etag: str

# =========================
# DATALOADERS (упрощённо)
# =========================

class StreamLoader:
    def __init__(self, registry: StreamsRegistry) -> None:
        self.registry = registry

    async def load(self, sid: str) -> t.Optional[StreamEntity]:
        return await self.registry.get(sid)

# =========================
# РЕЗОЛВЕРЫ
# =========================

def _stream_to_gql(s: StreamEntity) -> Stream:
    created = dt.datetime.fromtimestamp(s.created_at_ms / 1000, tz=dt.timezone.utc)
    payload = {
        "id": s.id,
        "name": s.name,
        "mode": s.mode,
        "state": s.state,
        "createdAt": created.isoformat().replace("+00:00", "Z"),
    }
    return Stream(
        id=strawberry.ID(f"Stream:{s.id}"),
        name=s.name,
        mode=StreamMode(s.mode),
        state=StreamState(s.state),
        createdAt=created,
        ingest=s.ingest,
        etag=_etag(payload),
    )

async def _ensure_idempotent(ctx: Context, key: t.Optional[str]) -> t.Optional[dict]:
    if not key:
        raise GraphQLError("Idempotency-Key header is required")
    cached = await ctx.idemp.get(key)
    return json.loads(cached.decode()) if cached else None

# =========================
# QUERY
# =========================

@strawberry.type
class Query:

    @strawberry.field
    async def stream(self, info: Info, id: strawberry.ID) -> t.Optional[Stream]:
        ctx: Context = info.context
        _auth_read(ctx, allow_anonymous=ctx.settings.allow_anonymous_read)
        # ожидаем Relay: "Stream:<id>"
        raw = str(id)
        if not raw.startswith("Stream:"):
            raise GraphQLError("Invalid ID format")
        sid = raw.split(":", 1)[1]
        ent = await ctx.registry.get(sid)
        return _stream_to_gql(ent) if ent else None

    @strawberry.field
    async def streams(
        self,
        info: Info,
        first: int = 20,
        after: t.Optional[str] = None,
    ) -> StreamConnection:
        ctx: Context = info.context
        _auth_read(ctx, allow_anonymous=ctx.settings.allow_anonymous_read)
        if first < 1 or first > 100:
            raise GraphQLError("first must be in range 1..100")
        offset = 0
        if after:
            try:
                offset = int(_unb64(after))
            except Exception:
                raise GraphQLError("Invalid cursor")
        items, next_off = await ctx.registry.list(offset=offset, limit=first)
        edges = [
            StreamEdge(node=_stream_to_gql(s), cursor=_b64(str(offset + i + 1)))
            for i, s in enumerate(items)
        ]
        page_info = PageInfo(hasNextPage=next_off is not None, endCursor=edges[-1].cursor if edges else None)
        total = len((await ctx.registry.list(0, 10**9))[0])  # допускается, т.к. in-memory
        return StreamConnection(edges=edges, pageInfo=page_info, totalCount=total)

    @strawberry.field
    async def health(self) -> str:
        return "ok"

# =========================
# MUTATION
# =========================

@strawberry.type
class Mutation:

    @strawberry.mutation
    async def createStream(
        self,
        info: Info,
        input: StreamCreateInput,
        idempotency_key: t.Optional[str] = strawberry.argument("idempotencyKey", default=None),
    ) -> Stream:
        ctx: Context = info.context
        _auth_write(ctx)
        cached = await _ensure_idempotent(ctx, idempotency_key)
        if cached:
            return Stream(**cached)  # уже сериализованный dict структуры Stream

        ingest: dict[str, t.Any] = {}
        if "SRT" in input.ingestProtocols:
            ingest["srt_listener"] = f"srt://0.0.0.0:10{int(time.time())%100:02d}?mode=listener&latency=50"
        if "RTMP" in input.ingestProtocols:
            ingest["rtmp"] = f"rtmp://ingest.local/live/{input.name}"
        if "KINESIS" in input.ingestProtocols:
            ingest["kinesis_stream"] = f"arn:aws:kinesisvideo:{os.getenv('AWS_REGION','eu-north-1')}:000000000000:stream/{input.name}/123"

        ent = await ctx.registry.create(input.name, input.mode.value, ingest)
        res = _stream_to_gql(ent)

        await ctx.idemp.set(idempotency_key, json.dumps(strawberry.asdict(res)).encode())  # type: ignore
        return res

    @strawberry.mutation
    async def stopStream(
        self,
        info: Info,
        id: strawberry.ID,
        idempotency_key: t.Optional[str] = strawberry.argument("idempotencyKey", default=None),
    ) -> bool:
        ctx: Context = info.context
        _auth_write(ctx)
        cached = await _ensure_idempotent(ctx, idempotency_key)
        if cached:
            return bool(cached.get("ok", False))
        raw = str(id)
        if not raw.startswith("Stream:"):
            raise GraphQLError("Invalid ID format")
        sid = raw.split(":", 1)[1]
        ok = await ctx.registry.stop(sid)
        await ctx.idemp.set(idempotency_key, json.dumps({"ok": ok}).encode())
        return ok

    @strawberry.mutation
    async def createPresignedUpload(
        self,
        info: Info,
        input: PresignInput,
        idempotency_key: t.Optional[str] = strawberry.argument("idempotencyKey", default=None),
    ) -> PresignPayload:
        ctx: Context = info.context
        _auth_write(ctx)
        if not ctx.settings.vod_ingest_bucket:
            raise GraphQLError("VOD ingest bucket is not configured")
        cached = await _ensure_idempotent(ctx, idempotency_key)
        if cached:
            return PresignPayload(**cached)

        key = f"{input.prefix or ''}{input.assetName}-{uuid.uuid4().hex}.bin"
        url = await ctx.s3.presign_put(
            bucket=ctx.settings.vod_ingest_bucket,
            key=key,
            content_type=input.contentType,
            expires=input.expiresSeconds,
        )
        exp = dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(seconds=input.expiresSeconds)
        payload = PresignPayload(
            method="PUT",
            url=url,
            headers={"Content-Type": input.contentType, "x-amz-server-side-encryption": "aws:kms"},
            key=key,
            expiresAt=exp,
            etag=_etag({"url": url, "key": key, "exp": exp.isoformat()}),
        )
        await ctx.idemp.set(idempotency_key, json.dumps(strawberry.asdict(payload)).encode())  # type: ignore
        return payload

    @strawberry.mutation
    async def finalizeAsset(
        self,
        info: Info,
        input: AssetFinalizeInput,
        idempotency_key: t.Optional[str] = strawberry.argument("idempotencyKey", default=None),
    ) -> Asset:
        ctx: Context = info.context
        _auth_write(ctx)
        cached = await _ensure_idempotent(ctx, idempotency_key)
        if cached:
            return Asset(**cached)

        asset = Asset(
            id=strawberry.ID(f"Asset:{input.assetId}"),
            assetId=input.assetId,
            status="queued",  # type: ignore
            locations={"source": f"s3://{ctx.settings.vod_ingest_bucket}/{input.sourceKey}"},
            etag=_etag({"asset": input.assetId, "key": input.sourceKey}),
        )
        await ctx.idemp.set(idempotency_key, json.dumps(strawberry.asdict(asset)).encode())  # type: ignore
        return asset

    @strawberry.mutation
    async def manifestUrl(self, info: Info, input: ManifestInput) -> ManifestPayload:
        ctx: Context = info.context
        _auth_read(ctx, allow_anonymous=ctx.settings.allow_anonymous_read)
        if not ctx.settings.cdn_public_base:
            raise GraphQLError("CDN base is not configured")
        ext = "m3u8" if input.variant == "hls" else "mpd"
        path = f"/vod/{input.assetId}/master.{ext}"
        exp = int(time.time()) + int(input.expiresSeconds)
        token_raw = f"{input.assetId}:{exp}:{os.getenv('CDN_SIGNING_SECRET','')}".encode()
        sig = base64.urlsafe_b64encode(hashlib.sha256(token_raw).digest()).decode().rstrip("=")
        url = f"{ctx.settings.cdn_public_base}{path}?exp={exp}&sig={sig}"
        payload = ManifestPayload(
            url=url,
            expiresAt=dt.datetime.fromtimestamp(exp, tz=dt.timezone.utc),
            etag=_etag({"u": url, "exp": exp}),
        )
        return payload

# =========================
# SUBSCRIPTION
# =========================

@strawberry.type
class Subscription:

    @strawberry.subscription
    async def streamStateChanged(self, info: Info) -> JSON:
        ctx: Context = info.context
        q = await ctx.registry.subscribe()

        try:
            while True:
                evt = await q.get()
                if evt.get("type") == "state":
                    yield {
                        "streamId": evt["id"],
                        "state": evt["state"],
                        "ts": evt["ts"],
                    }
        finally:
            await ctx.registry.unsubscribe(q)

# =========================
# ОГРАНИЧЕНИЕ СЛОЖНОСТИ/ГЛУБИНЫ (простое расширение)
# =========================

class QueryComplexityExtension(strawberry.extensions.BaseExtension):
    def __init__(self, *, max_depth: int = 10, max_cost: int = 200) -> None:
        super().__init__()
        self.max_depth = max_depth
        self.max_cost = max_cost

    def on_validate_start(self):
        # Простейшая оценка глубины и стоимости: длина selection set и аргументы first/limit.
        try:
            doc = self.execution_context.query
            # глубина
            def depth(sel, d=0):
                if not hasattr(sel, "selection_set") or not sel.selection_set:
                    return d
                return max([depth(s, d + 1) for s in sel.selection_set.selections]) if sel.selection_set.selections else d
            depths = [depth(op) for op in doc.definitions if getattr(op, "selection_set", None)]
            max_d = max(depths) if depths else 0
            if max_d > self.max_depth:
                raise GraphQLError(f"Query depth {max_d} exceeds max {self.max_depth}")
            # стоимость (очень грубо): количество полей
            def cost(sel):
                if not hasattr(sel, "selection_set") or not sel.selection_set:
                    return 1
                return 1 + sum(cost(s) for s in sel.selection_set.selections)
            total_cost = sum(cost(op) for op in doc.definitions if getattr(op, "selection_set", None))
            if total_cost > self.max_cost:
                raise GraphQLError(f"Query cost {total_cost} exceeds max {self.max_cost}")
        except GraphQLError:
            raise
        except Exception:
            # Не блокируем при невозможности оценки
            return

# =========================
# СХЕМА И РОУТЕР
# =========================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=True),
    extensions=[
        lambda: QueryComplexityExtension(max_depth=10, max_cost=300),
    ],
)

def _principal_from_request(req: Request) -> Principal:
    # Демонстрационная аутентификация:
    # Bearer или X-API-Key; аноним для безопасных чтений (если разрешено настройкой)
    auth = req.headers.get("authorization", "")
    api_key = req.headers.get("x-api-key", "")
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if token and os.getenv("API_BEARER_TOKEN", "") and token == os.getenv("API_BEARER_TOKEN"):
        return Principal(subject="service:bearer", method=AuthMethod.bearer)
    if api_key and api_key in {k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()}:
        h = hashlib.sha256(api_key.encode()).hexdigest()[:12]
        return Principal(subject=f"api_key:{h}", method=AuthMethod.api_key)
    return Principal(subject="anonymous", method=AuthMethod.anonymous)

async def get_context(request: Request) -> Context:
    principal = _principal_from_request(request)
    settings = Settings()
    # Одиночные инстансы можно держать на уровне модуля; здесь создаем простые
    registry = getattr(request.app.state, "streams_registry", None)  # type: ignore[attr-defined]
    if registry is None:
        registry = request.app.state.streams_registry = StreamsRegistry()  # type: ignore[attr-defined]
    idemp = getattr(request.app.state, "idemp_store", None)  # type: ignore[attr-defined]
    if idemp is None:
        idemp = request.app.state.idemp_store = IdempotencyStore(ttl_seconds=settings.idempotency_ttl)  # type: ignore[attr-defined]
    s3 = getattr(request.app.state, "s3_facade", None)  # type: ignore[attr-defined]
    if s3 is None:
        s3 = request.app.state.s3_facade = S3Facade(region=settings.region)  # type: ignore[attr-defined]
    return Context(
        request=request,
        principal=principal,
        settings=settings,
        registry=registry,
        idemp=idemp,
        s3=s3,
        pubsub=PubSub(),
    )

# Экспортируем готовый ASGI-роутер для FastAPI:
graphql_app = GraphQLRouter(
    schema,
    context_getter=get_context,
    graphiql=True,
    subscription_protocols=[GRAPHQL_TRANSPORT_WS_PROTOCOL],
)

# security-core/security/workers/token_revoker.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

# ---------------------------
# Логирование (структурированное)
# ---------------------------

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("security_core.token_revoker")
    if not logger.handlers:
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        logger.setLevel(os.getenv("SEC_CORE_REVOKER_LOG_LEVEL", "INFO").upper())
    return logger

log = _get_logger()

def jlog(level: int, message: str, **fields: Any) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level),
        "message": message,
    }
    payload.update(fields)
    try:
        log.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        log.log(level, f"{message} | {fields}")

# ---------------------------
# Время/утилиты
# ---------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _ts(dt: datetime) -> int:
    return int(dt.timestamp())

def _from_ts(v: int | float) -> datetime:
    return datetime.fromtimestamp(int(v), tz=timezone.utc)

# ---------------------------
# Исключения
# ---------------------------

class RevokerError(Exception): ...
class StoreError(RevokerError): ...
class ConfigError(RevokerError): ...

# ---------------------------
# Модель токена и правил
# ---------------------------

@dataclass(frozen=True)
class TokenDescriptor:
    """
    Факты о токене, полученные ПОСЛЕ криптографической проверки (внешним слоем).
    """
    token_type: str                 # "jwt" | "paseto" | "opaque"
    iss: Optional[str]              # issuer
    aud: Optional[str]              # audience (строка; если у вас список — нормализуйте заранее)
    sub: Optional[str]
    jti: Optional[str]
    exp: Optional[int]              # unix seconds
    nbf: Optional[int]
    iat: Optional[int]
    kid: Optional[str]              # из заголовка (JWT) или метаданных
    cnf_x5t_s256: Optional[str]     # RFC 8705 — cnf["x5t#S256"]
    cnf_x5t: Optional[str]          # устаревший SHA-1 отпечаток
    sid: Optional[str]              # session id (например "sid" claim)
    client_id: Optional[str]        # OAuth/OIDC client_id (если есть)
    scope: Optional[str] = None     # space-separated

    def expires_at(self) -> Optional[datetime]:
        return _from_ts(self.exp) if self.exp else None

@dataclass(frozen=True)
class RevocationRule:
    """
    Правило отзыва. Совпадение — если все указанные поля совпали и попали в окно действия.
    """
    rule_id: str
    created_at: datetime
    created_by: str                 # నట (actor/service)
    reason: Optional[str]

    # Окно действия
    not_before: Optional[datetime]  # если None — сразу
    not_after: Optional[datetime]   # если None — до TTL/exp

    # Условия (любой из идентификаторов/атрибутов; пустые игнорируются)
    iss: Optional[str] = None
    aud: Optional[str] = None
    sub: Optional[str] = None
    jti: Optional[str] = None
    sid: Optional[str] = None
    kid: Optional[str] = None
    cnf_x5t_s256: Optional[str] = None
    cnf_x5t: Optional[str] = None
    client_id: Optional[str] = None
    token_type: Optional[str] = None  # если нужно ограничить тип

    # TTL (жизнь правила в хранилище)
    ttl_seconds: Optional[int] = None

    def matches(self, td: TokenDescriptor, now: Optional[datetime] = None) -> bool:
        n = now or _now()
        if self.not_before and n < self.not_before:
            return False
        if self.not_after and n > self.not_after:
            return False

        # Атрибутная проверка: только заданные поля
        if self.iss is not None and (td.iss or "") != self.iss:
            return False
        if self.aud is not None and (td.aud or "") != self.aud:
            return False
        if self.sub is not None and (td.sub or "") != self.sub:
            return False
        if self.jti is not None and (td.jti or "") != self.jti:
            return False
        if self.sid is not None and (td.sid or "") != self.sid:
            return False
        if self.kid is not None and (td.kid or "") != self.kid:
            return False
        if self.cnf_x5t_s256 is not None and (td.cnf_x5t_s256 or "") != self.cnf_x5t_s256:
            return False
        if self.cnf_x5t is not None and (td.cnf_x5t or "") != self.cnf_x5t:
            return False
        if self.client_id is not None and (td.client_id or "") != self.client_id:
            return False
        if self.token_type is not None and (td.token_type or "") != self.token_type:
            return False
        return True

# ---------------------------
# Интерфейс хранилища
# ---------------------------

class RevocationStore(Protocol):
    async def put_rule(self, rule: RevocationRule) -> None: ...
    async def get_rule(self, rule_id: str) -> Optional[RevocationRule]: ...
    async def list_candidates(self, td: TokenDescriptor) -> Iterable[RevocationRule]: ...
    async def purge_expired(self) -> int: ...

# ---------------------------
# Реализация: InMemory (для тестов)
# ---------------------------

class InMemoryStore(RevocationStore):
    def __init__(self) -> None:
        self._rules: Dict[str, RevocationRule] = {}

    async def put_rule(self, rule: RevocationRule) -> None:
        self._rules[rule.rule_id] = rule

    async def get_rule(self, rule_id: str) -> Optional[RevocationRule]:
        return self._rules.get(rule_id)

    async def list_candidates(self, td: TokenDescriptor) -> Iterable[RevocationRule]:
        # Для простоты — все правила; в проде используйте Redis/Postgres для индексации
        return list(self._rules.values())

    async def purge_expired(self) -> int:
        now = _now()
        to_del = []
        for r in self._rules.values():
            if r.ttl_seconds is None:
                continue
            if r.created_at + timedelta(seconds=r.ttl_seconds) < now:
                to_del.append(r.rule_id)
        for k in to_del:
            self._rules.pop(k, None)
        return len(to_del)

# ---------------------------
# Опционально: Redis store
# ---------------------------

_HAS_REDIS = False
try:  # pragma: no cover
    import redis.asyncio as aioredis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    pass

class RedisStore(RevocationStore):  # pragma: no cover
    """
    Схема:
      HSET rev:rule:{id} -> JSON(rule)
      ZADD rev:index:expiry score=epoch -> {id}  (для очистки)
      SADD rev:idx:iss:{iss} -> {id}
      SADD rev:idx:jti:{jti} -> {id}
      SADD rev:idx:sub:{sub} -> {id}
      SADD rev:idx:sid:{sid} -> {id}
      SADD rev:idx:kid:{kid} -> {id}
      SADD rev:idx:aud:{aud} -> {id}
      SADD rev:idx:cnf256:{x5tS256} -> {id}
      SADD rev:idx:client:{client_id} -> {id}
      SADD rev:idx:global -> {id}   (правила без конкретных ключей, но с iss/…)
    """
    def __init__(self, url: str = os.getenv("SEC_CORE_REDIS_URL", "redis://localhost:6379/0")) -> None:
        if not _HAS_REDIS:
            raise ConfigError("redis.asyncio not installed")
        self.r = aioredis.from_url(url, decode_responses=True)
        self.ns = os.getenv("SEC_CORE_REDIS_NS", "rev")

    def _k(self, *parts: str) -> str:
        return ":".join((self.ns, *parts))

    async def put_rule(self, rule: RevocationRule) -> None:
        rid = rule.rule_id
        j = json.dumps(_rule_to_json(rule), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        pipe = self.r.pipeline()
        pipe.hset(self._k("rule", rid), mapping={"json": j})
        # expiry индекс
        exp_at = _expiry_epoch(rule)
        if exp_at is not None:
            pipe.zadd(self._k("index", "expiry"), {rid: float(exp_at)})
        # индексы
        indexed = False
        for key, prefix in (
            (rule.jti, "jti"),
            (rule.sub, "sub"),
            (rule.sid, "sid"),
            (rule.kid, "kid"),
            (rule.aud, "aud"),
            (rule.cnf_x5t_s256, "cnf256"),
            (rule.client_id, "client"),
        ):
            if key:
                pipe.sadd(self._k("idx", prefix, key), rid)
                indexed = True
        if not indexed:
            pipe.sadd(self._k("idx", "global"), rid)
        if rule.iss:
            pipe.sadd(self._k("idx", "iss", rule.iss), rid)
        await pipe.execute()

    async def get_rule(self, rule_id: str) -> Optional[RevocationRule]:
        j = await self.r.hget(self._k("rule", rule_id), "json")
        if not j:
            return None
        return _rule_from_json(json.loads(j))

    async def list_candidates(self, td: TokenDescriptor) -> Iterable[RevocationRule]:
        # Собираем кандидатов по самым селективным индексам
        keys = [self._k("idx", "global")]
        if td.jti:
            keys.append(self._k("idx", "jti", td.jti))
        if td.sub:
            keys.append(self._k("idx", "sub", td.sub))
        if td.sid:
            keys.append(self._k("idx", "sid", td.sid))
        if td.kid:
            keys.append(self._k("idx", "kid", td.kid))
        if td.aud:
            keys.append(self._k("idx", "aud", td.aud))
        if td.cnf_x5t_s256:
            keys.append(self._k("idx", "cnf256", td.cnf_x5t_s256))
        if td.client_id:
            keys.append(self._k("idx", "client", td.client_id))
        # Пересечение с issuer, если задан
        ids: List[str] = []
        if td.iss:
            # объединяем правила по конкретным признакам и обязательно по iss (если есть)
            base = set()
            for k in keys:
                base |= set(await self.r.smembers(k))
            if base:
                iss_ids = set(await self.r.smembers(self._k("idx", "iss", td.iss)))
                ids = list(base & iss_ids) + list(base - base & iss_ids)  # оставляем и без iss (глобальные)
            else:
                ids = list(await self.r.smembers(self._k("idx", "iss", td.iss)))
            # плюс глобальные
            ids = list(set(ids) | set(await self.r.smembers(self._k("idx", "global"))))
        else:
            # без issuer — только глобальные/идентификаторы
            base = set()
            for k in keys:
                base |= set(await self.r.smembers(k))
            ids = list(base | set(await self.r.smembers(self._k("idx", "global"))))

        # Загружаем правила
        if not ids:
            return []
        pipe = self.r.pipeline()
        for rid in ids:
            pipe.hget(self._k("rule", rid), "json")
        raw = await pipe.execute()
        out = []
        for j in raw:
            if not j:
                continue
            try:
                out.append(_rule_from_json(json.loads(j)))
            except Exception:
                continue
        return out

    async def purge_expired(self) -> int:
        now = time.time()
        # Получаем истекшие id
        ids = await self.r.zrangebyscore(self._k("index", "expiry"), min=0, max=now)
        if not ids:
            return 0
        pipe = self.r.pipeline()
        for rid in ids:
            pipe.delete(self._k("rule", rid))
        pipe.zrem(self._k("index", "expiry"), *ids)
        # Чистим индексы (best-effort)
        for prefix in ("global","jti","sub","sid","kid","aud","cnf256","client","iss"):
            # Мы не знаем конкретные ключи — оставляем мусор до следующего обслуживания.
            # В реальном проекте храните обратные ссылки для точечного удаления.
            pass
        await pipe.execute()
        return len(ids)

# ---------------------------
# Опционально: Postgres store
# ---------------------------

_HAS_ASYNCPG = False
try:  # pragma: no cover
    import asyncpg  # type: ignore
    _HAS_ASYNCPG = True
except Exception:  # pragma: no cover
    pass

PG_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS revocation_rules (
  rule_id       TEXT PRIMARY KEY,
  created_at    TIMESTAMPTZ NOT NULL,
  created_by    TEXT NOT NULL,
  reason        TEXT,
  not_before    TIMESTAMPTZ,
  not_after     TIMESTAMPTZ,
  ttl_seconds   INTEGER,
  iss           TEXT,
  aud           TEXT,
  sub           TEXT,
  jti           TEXT,
  sid           TEXT,
  kid           TEXT,
  cnf_x5t_s256  TEXT,
  cnf_x5t       TEXT,
  client_id     TEXT,
  token_type    TEXT
);
CREATE INDEX IF NOT EXISTS idx_rev_rules_jti ON revocation_rules (jti);
CREATE INDEX IF NOT EXISTS idx_rev_rules_sub ON revocation_rules (sub);
CREATE INDEX IF NOT EXISTS idx_rev_rules_sid ON revocation_rules (sid);
CREATE INDEX IF NOT EXISTS idx_rev_rules_kid ON revocation_rules (kid);
CREATE INDEX IF NOT EXISTS idx_rev_rules_aud ON revocation_rules (aud);
CREATE INDEX IF NOT EXISTS idx_rev_rules_iss ON revocation_rules (iss);
CREATE INDEX IF NOT EXISTS idx_rev_rules_cnf ON revocation_rules (cnf_x5t_s256);
CREATE INDEX IF NOT EXISTS idx_rev_rules_client ON revocation_rules (client_id);
"""

class PostgresStore(RevocationStore):  # pragma: no cover
    def __init__(self, dsn: str) -> None:
        if not _HAS_ASYNCPG:
            raise ConfigError("asyncpg not installed")
        self._dsn = dsn
        self._pool: Optional[asyncpg.Pool] = None  # type: ignore

    async def _init(self) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(dsn=self._dsn, min_size=1, max_size=10)
            async with self._pool.acquire() as conn:
                await conn.execute(PG_SCHEMA_SQL)

    async def put_rule(self, rule: RevocationRule) -> None:
        await self._init()
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO revocation_rules(rule_id, created_at, created_by, reason, not_before, not_after, ttl_seconds,
                    iss, aud, sub, jti, sid, kid, cnf_x5t_s256, cnf_x5t, client_id, token_type)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                ON CONFLICT (rule_id) DO NOTHING
            """,
            rule.rule_id, rule.created_at, rule.created_by, rule.reason, rule.not_before, rule.not_after, rule.ttl_seconds,
            rule.iss, rule.aud, rule.sub, rule.jti, rule.sid, rule.kid, rule.cnf_x5t_s256, rule.cnf_x5t, rule.client_id, rule.token_type)

    async def get_rule(self, rule_id: str) -> Optional[RevocationRule]:
        await self._init()
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM revocation_rules WHERE rule_id=$1", rule_id)
            if not row:
                return None
            return _rule_from_json(dict(row))

    async def list_candidates(self, td: TokenDescriptor) -> Iterable[RevocationRule]:
        await self._init()
        assert self._pool is not None
        clauses = []
        params: List[Any] = []
        # Подбираем селективные условия
        for col, val in (("jti", td.jti), ("sub", td.sub), ("sid", td.sid), ("kid", td.kid), ("aud", td.aud), ("cnf_x5t_s256", td.cnf_x5t_s256), ("client_id", td.client_id), ("iss", td.iss)):
            if val:
                params.append(val)
                clauses.append(f"{col} = ${len(params)}")
        where = " OR ".join(clauses) if clauses else "TRUE"
        sql = f"SELECT * FROM revocation_rules WHERE {where}"
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
            return [_rule_from_json(dict(r)) for r in rows]

    async def purge_expired(self) -> int:
        await self._init()
        assert self._pool is not None
        now = _now()
        async with self._pool.acquire() as conn:
            res = await conn.execute("DELETE FROM revocation_rules WHERE ttl_seconds IS NOT NULL AND created_at + make_interval(secs := ttl_seconds) < $1", now)
            # res формата "DELETE <n>"
            try:
                return int(res.split()[-1])
            except Exception:
                return 0

# ---------------------------
# Сервис отзыва токенов
# ---------------------------

@dataclass
class CheckResult:
    revoked: bool
    rule_id: Optional[str] = None
    reason: Optional[str] = None

class TokenRevoker:
    """
    Высокоуровневый сервис: создание правил и проверка токенов.
    """
    def __init__(self, store: RevocationStore, *, default_issuer: Optional[str] = None) -> None:
        self.store = store
        self.default_issuer = default_issuer

    # ------ публичные методы "revoke *" ------

    async def revoke_jti(self, *, jti: str, iss: Optional[str], exp: Optional[int], reason: str, created_by: str) -> str:
        """
        Отзывает конкретный токен по JTI до его exp (или TTL).
        """
        rid = _rid()
        now = _now()
        not_after = _from_ts(exp) if exp else None
        ttl = max(0, (exp - _ts(now))) if exp else 24 * 3600
        rule = RevocationRule(
            rule_id=rid, created_at=now, created_by=created_by, reason=reason,
            not_before=now, not_after=not_after, ttl_seconds=ttl,
            iss=iss or self.default_issuer, jti=jti
        )
        await self.store.put_rule(rule)
        jlog(logging.INFO, "rev.rule.created", type="jti", rule_id=rid, jti=jti, iss=rule.iss, ttl=ttl)
        return rid

    async def revoke_subject(self, *, sub: str, iss: Optional[str], reason: str, created_by: str,
                             aud: Optional[str] = None, client_id: Optional[str] = None,
                             not_before: Optional[datetime] = None, not_after: Optional[datetime] = None,
                             ttl_seconds: Optional[int] = None) -> str:
        rid = _rid()
        rule = RevocationRule(
            rule_id=rid, created_at=_now(), created_by=created_by, reason=reason,
            not_before=not_before or _now(), not_after=not_after, ttl_seconds=ttl_seconds or 30*24*3600,
            iss=iss or self.default_issuer, sub=sub, aud=aud, client_id=client_id
        )
        await self.store.put_rule(rule)
        jlog(logging.INFO, "rev.rule.created", type="sub", rule_id=rid, sub=sub, iss=rule.iss)
        return rid

    async def revoke_session(self, *, sid: str, iss: Optional[str], reason: str, created_by: str,
                             not_after: Optional[datetime] = None, ttl_seconds: Optional[int] = None) -> str:
        rid = _rid()
        rule = RevocationRule(
            rule_id=rid, created_at=_now(), created_by=created_by, reason=reason,
            not_before=_now(), not_after=not_after, ttl_seconds=ttl_seconds or 30*24*3600,
            iss=iss or self.default_issuer, sid=sid
        )
        await self.store.put_rule(rule)
        jlog(logging.INFO, "rev.rule.created", type="sid", rule_id=rid, sid=sid, iss=rule.iss)
        return rid

    async def revoke_thumbprint(self, *, x5t_s256: Optional[str] = None, x5t: Optional[str] = None,
                                iss: Optional[str], reason: str, created_by: str,
                                not_after: Optional[datetime] = None, ttl_seconds: Optional[int] = None) -> str:
        rid = _rid()
        rule = RevocationRule(
            rule_id=rid, created_at=_now(), created_by=created_by, reason=reason,
            not_before=_now(), not_after=not_after, ttl_seconds=ttl_seconds or 30*24*3600,
            iss=iss or self.default_issuer, cnf_x5t_s256=x5t_s256, cnf_x5t=x5t
        )
        await self.store.put_rule(rule)
        jlog(logging.INFO, "rev.rule.created", type="cnf", rule_id=rid, x5t_s256=x5t_s256, x5t=x5t, iss=rule.iss)
        return rid

    async def revoke_kid(self, *, kid: str, iss: Optional[str], reason: str, created_by: str,
                         not_after: Optional[datetime] = None, ttl_seconds: Optional[int] = None) -> str:
        """
        Отзывает все токены, выпущенные ключом KID (мягкая защита при компрометации).
        """
        rid = _rid()
        rule = RevocationRule(
            rule_id=rid, created_at=_now(), created_by=created_by, reason=reason,
            not_before=_now(), not_after=not_after, ttl_seconds=ttl_seconds or 7*24*3600,
            iss=iss or self.default_issuer, kid=kid
        )
        await self.store.put_rule(rule)
        jlog(logging.INFO, "rev.rule.created", type="kid", rule_id=rid, kid=kid, iss=rule.iss)
        return rid

    async def put_rule(self, rule: RevocationRule) -> str:
        await self.store.put_rule(rule)
        jlog(logging.INFO, "rev.rule.created", type="custom", rule_id=rule.rule_id)
        return rule.rule_id

    # ------ проверка токена ------

    async def check(self, td: TokenDescriptor) -> CheckResult:
        """
        Возвращает CheckResult.revoked=True, если есть совпадающее правило.
        """
        # Кандидаты из хранилища
        candidates = await self.store.list_candidates(td)
        now = _now()
        for r in candidates:
            try:
                # TTL истечение
                if r.ttl_seconds is not None and r.created_at + timedelta(seconds=r.ttl_seconds) < now:
                    continue
                if r.matches(td, now=now):
                    return CheckResult(revoked=True, rule_id=r.rule_id, reason=r.reason)
            except Exception as e:
                jlog(logging.WARNING, "rev.rule.match.error", rule_id=r.rule_id, error=str(e))
                continue
        return CheckResult(revoked=False)

# ---------------------------
# Воркер событий (опционально, Redis Streams)
# ---------------------------

class RedisEventWorker:  # pragma: no cover
    """
    Читает поток XREAD из stream 'revocation-events' и создаёт правила.
    Формат события:
      {"type":"jti","jti":"...", "iss":"...", "exp": 1699999999, "reason":"...", "by":"svc"}
      {"type":"sub","sub":"...", "iss":"...", "reason":"...", "by":"svc", "aud":"...", "ttl": 2592000}
      {"type":"sid","sid":"...", ...}
      {"type":"cnf","x5t#S256":"...", ...}
      {"type":"kid","kid":"...", ...}
    """
    def __init__(self, store: RedisStore, revoker: TokenRevoker, stream: str = os.getenv("SEC_CORE_REDIS_STREAM","revocation-events")) -> None:
        self.store = store
        self.revoker = revoker
        self.stream = stream
        self._stopped = False
        self._group = os.getenv("SEC_CORE_REDIS_GROUP", "revoker")
        self._consumer = os.getenv("HOSTNAME", "consumer") + ":" + str(uuid.uuid4())[:8]

    async def run(self) -> None:
        r = self.store.r
        # Создаём consumer group (идемпотентно)
        try:
            await r.xgroup_create(name=self.stream, groupname=self._group, id="$", mkstream=True)
        except Exception:
            pass
        jlog(logging.INFO, "rev.worker.start", stream=self.stream, group=self._group, consumer=self._consumer)
        while not self._stopped:
            msgs = await r.xreadgroup(groupname=self._group, consumername=self._consumer, streams={self.stream: ">"}, count=50, block=5000)
            if not msgs:
                continue
            for _, entries in msgs:
                for msg_id, kv in entries:
                    try:
                        await self._handle_event(kv)
                        await r.xack(self.stream, self._group, msg_id)
                    except Exception as e:
                        jlog(logging.ERROR, "rev.worker.err", error=str(e), msg_id=msg_id)

    async def _handle_event(self, kv: Mapping[str, str]) -> None:
        # Значения в Redis Streams — строки; парсим известные поля
        typ = kv.get("type")
        iss = kv.get("iss") or self.revoker.default_issuer
        reason = kv.get("reason") or "revoked"
        by = kv.get("by") or "revoker"
        if typ == "jti":
            exp = _to_int(kv.get("exp"))
            await self.revoker.revoke_jti(jti=kv["jti"], iss=iss, exp=exp, reason=reason, created_by=by)
        elif typ == "sub":
            ttl = _to_int(kv.get("ttl"))
            await self.revoker.revoke_subject(sub=kv["sub"], iss=iss, reason=reason, created_by=by,
                                              aud=kv.get("aud"), client_id=kv.get("client_id"),
                                              ttl_seconds=ttl)
        elif typ == "sid":
            ttl = _to_int(kv.get("ttl"))
            await self.revoker.revoke_session(sid=kv["sid"], iss=iss, reason=reason, created_by=by,
                                              ttl_seconds=ttl)
        elif typ == "cnf":
            ttl = _to_int(kv.get("ttl"))
            await self.revoker.revoke_thumbprint(x5t_s256=kv.get("x5t#S256"), x5t=kv.get("x5t"), iss=iss,
                                                 reason=reason, created_by=by, ttl_seconds=ttl)
        elif typ == "kid":
            ttl = _to_int(kv.get("ttl"))
            await self.revoker.revoke_kid(kid=kv["kid"], iss=iss, reason=reason, created_by=by, ttl_seconds=ttl)
        else:
            jlog(logging.WARNING, "rev.worker.unknown_type", type=typ)

# ---------------------------
# Вспомогательные функции сериализации
# ---------------------------

def _rid() -> str:
    return str(uuid.uuid4())

def _expiry_epoch(rule: RevocationRule) -> Optional[int]:
    # Вычисляем момент удаления правила (для Redis ZSET)
    c = rule.created_at
    if rule.ttl_seconds is not None:
        return _ts(c + timedelta(seconds=rule.ttl_seconds))
    if rule.not_after is not None:
        return _ts(rule.not_after)
    return None

def _rule_to_json(r: RevocationRule) -> Dict[str, Any]:
    def dt(x: Optional[datetime]) -> Optional[str]:
        return x.astimezone(timezone.utc).isoformat() if x else None
    d = asdict(r)
    d["created_at"] = dt(r.created_at)
    d["not_before"] = dt(r.not_before)
    d["not_after"] = dt(r.not_after)
    return d

def _rule_from_json(d: Mapping[str, Any]) -> RevocationRule:
    def p(x: Any) -> Optional[datetime]:
        if not x:
            return None
        if isinstance(x, datetime):
            return x
        return datetime.fromisoformat(str(x)).astimezone(timezone.utc)
    return RevocationRule(
        rule_id=str(d["rule_id"]),
        created_at=p(d.get("created_at")) or _now(),
        created_by=str(d.get("created_by") or "unknown"),
        reason=d.get("reason"),
        not_before=p(d.get("not_before")),
        not_after=p(d.get("not_after")),
        ttl_seconds=int(d["ttl_seconds"]) if d.get("ttl_seconds") not in (None, "") else None,
        iss=d.get("iss"),
        aud=d.get("aud"),
        sub=d.get("sub"),
        jti=d.get("jti"),
        sid=d.get("sid"),
        kid=d.get("kid"),
        cnf_x5t_s256=d.get("cnf_x5t_s256"),
        cnf_x5t=d.get("cnf_x5t"),
        client_id=d.get("client_id"),
        token_type=d.get("token_type"),
    )

def _to_int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except Exception:
        return None

# ---------------------------
# Пример интеграции (для справки)
# ---------------------------
# async def _example():
#     # Выберите хранилище
#     store = InMemoryStore()
#     # либо RedisStore() / PostgresStore(dsn="postgres://...")
#     revoker = TokenRevoker(store, default_issuer="https://auth.example")
#
#     # Отозвать конкретный токен до его exp
#     await revoker.revoke_jti(jti="1b2c3d", iss=None, exp=int(time.time())+3600, reason="logout", created_by="api")
#
#     # Проверка токена (после вашей криптопроверки)
#     td = TokenDescriptor(token_type="jwt", iss="https://auth.example", aud="api://demo",
#                          sub="user123", jti="1b2c3d", exp=int(time.time())+300, nbf=None, iat=None,
#                          kid="k1", cnf_x5t_s256=None, cnf_x5t=None, sid="sess-42", client_id="webapp")
#     res = await revoker.check(td)
#     assert res.revoked
#
#     # Фоновая очистка (по расписанию)
#     await store.purge_expired()
#
# Особенности:
#  - Вставляйте проверку revoker.check(td) сразу после успешной криптографической валидации токена.
#  - Для JWT/PASETO дескриптор формируйте из проверенных claims и заголовков; этот модуль подпись НЕ проверяет.
#  - Для высокой нагрузки используйте RedisStore и подтягивайте события отзыва через Redis Streams.

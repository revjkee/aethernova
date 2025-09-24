# zero-trust-core/zero_trust/policy/translators/rego_adapter.py
from __future__ import annotations

import abc
import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union

from pydantic import BaseModel, Field, PositiveInt, root_validator

# --- Optional deps (HTTP client / WASM / Ed25519 verify) ---
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - optional
    httpx = None  # type: ignore

try:
    from opa_wasm import OPAPolicy  # type: ignore
except Exception:  # pragma: no cover - optional
    OPAPolicy = None  # type: ignore

try:
    from nacl.signing import VerifyKey  # type: ignore
    import nacl.exceptions  # type: ignore
except Exception:  # pragma: no cover - optional
    VerifyKey = None  # type: ignore

logger = logging.getLogger("zt.policy.rego")


# =========================
# Errors / Enums
# =========================

class RegoError(Exception):
    pass

class PolicyUnavailable(RegoError):
    pass

class DecisionTimeout(RegoError):
    pass

class DecisionBackend(str, Enum):
    http = "http"
    wasm = "wasm"

class FailMode(str, Enum):
    open = "open"
    closed = "closed"


# =========================
# Utilities
# =========================

REDACT_KEYS = ("authorization", "cookie", "set-cookie", "password", "secret", "token", "ssn", "pan")

def redact(obj: Any) -> Any:
    """
    Плоская редактция потенциально чувствительных полей/значений в логах.
    """
    try:
        if isinstance(obj, Mapping):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                lk = str(k).lower()
                if any(r in lk for r in REDACT_KEYS):
                    out[k] = "***"
                elif isinstance(v, (dict, list)):
                    out[k] = redact(v)
                elif isinstance(v, str):
                    # примитивные маски
                    v2 = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "***", v)
                    v2 = re.sub(r"\b(?:\d[ -]?){13,19}\b", "***", v2)
                    out[k] = v2
                else:
                    out[k] = v
            return out
        if isinstance(obj, list):
            return [redact(x) for x in obj]
    except Exception:
        pass
    return obj

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

class TTLCache:
    """
    Неблокирующий TTL-кэш для небольших нагрузок; используется для кэширования решений.
    """
    def __init__(self, max_items: int = 5000) -> None:
        self._data: Dict[str, Tuple[int, bytes]] = {}
        self._max = max_items

    def get(self, k: str) -> Optional[bytes]:
        item = self._data.get(k)
        if not item:
            return None
        exp, blob = item
        if time.time() >= exp:
            self._data.pop(k, None)
            return None
        return blob

    def set(self, k: str, blob: bytes, ttl_s: int) -> None:
        if len(self._data) >= self._max:
            # простая эвикция: удаляем ~10% старых
            for i, key in enumerate(list(self._data.keys())):
                self._data.pop(key, None)
                if i > self._max // 10:
                    break
        self._data[k] = (time.time() + max(1, ttl_s), blob)


class TokenBucket:
    def __init__(self, rate_per_s: float, burst: int) -> None:
        self.rate = rate_per_s
        self.capacity = burst
        self.tokens = burst
        self.ts = time.perf_counter()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.perf_counter()
            dt = now - self.ts
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + dt * self.rate)
            if self.tokens < 1:
                need = (1 - self.tokens) / self.rate
                await asyncio.sleep(max(0, need))
                self.tokens = 0
            else:
                self.tokens -= 1


class CircuitBreakerState(str, Enum):
    closed = "closed"
    open = "open"
    half_open = "half_open"

class CircuitBreaker:
    def __init__(self, failures: int = 5, reset_timeout_s: int = 30) -> None:
        self.failures = failures
        self.reset_timeout_s = reset_timeout_s
        self.count = 0
        self.state = CircuitBreakerState.closed
        self.opened_at = 0.0
        self._lock = asyncio.Lock()

    async def before(self) -> None:
        async with self._lock:
            if self.state == CircuitBreakerState.open:
                if time.time() - self.opened_at >= self.reset_timeout_s:
                    self.state = CircuitBreakerState.half_open
                else:
                    raise PolicyUnavailable("circuit open")

    async def success(self) -> None:
        async with self._lock:
            self.count = 0
            self.state = CircuitBreakerState.closed

    async def failure(self) -> None:
        async with self._lock:
            self.count += 1
            if self.count >= self.failures:
                self.state = CircuitBreakerState.open
                self.opened_at = time.time()


# =========================
# Config / Models
# =========================

class OPAHTTPConfig(BaseModel):
    base_url: str = Field(..., description="Напр. http://opa:8181")
    package: str = Field("zt.core", description="Rego package (без префикса data.)")
    entrypoint: str = Field("decision", description="Имя правила в пакете, обычно decision|allow")
    timeout_s: float = Field(0.6, gt=0)  # агрессивный таймаут
    headers: Dict[str, str] = Field(default_factory=dict)
    cache_ttl_s: PositiveInt = 5  # короткий TTL кэша решений
    rate_limit_rps: float = 100.0
    rate_limit_burst: int = 200
    fail_mode: FailMode = Field(FailMode.closed)
    decision_path_override: Optional[str] = Field(
        None, description="Если указан, полный путь вместо package/entrypoint, без префикса data."
    )

class OPAWASMConfig(BaseModel):
    wasm_path: Optional[str] = Field(
        None, description="Путь к скомпилированному OPA WASM (если используете wasm‑бэкенд)"
    )
    entrypoint: str = Field("decision", description="Entrypoint, соответствующий Rego")
    fail_mode: FailMode = Field(FailMode.closed)

class BundleSignature(BaseModel):
    enabled: bool = False
    pubkey_ed25519_hex: Optional[str] = None  # hex‑код публичного ключа
    keyid: Optional[str] = None

class RegoAdapterConfig(BaseModel):
    backend: DecisionBackend = Field(DecisionBackend.http)
    http: Optional[OPAHTTPConfig] = None
    wasm: Optional[OPAWASMConfig] = None
    bundle_sig: BundleSignature = Field(default_factory=BundleSignature)

    @root_validator
    def _validate_backend(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        b = v.get("backend")
        if b == DecisionBackend.http and not v.get("http"):
            raise ValueError("http config required for backend=http")
        if b == DecisionBackend.wasm and not v.get("wasm"):
            raise ValueError("wasm config required for backend=wasm")
        return v


# ==== Input / Output ====

@dataclass
class Decision:
    allow: bool
    obligations: Dict[str, Any]
    reason: Optional[str]
    raw_result: Any
    latency_ms: int
    cached: bool

    @classmethod
    def deny_fail_closed(cls, reason: str, elapsed_ms: int) -> "Decision":
        return cls(allow=False, obligations={}, reason=reason, raw_result=None, latency_ms=elapsed_ms, cached=False)


# =========================
# Translator abstraction (optional customization)
# =========================

class InputTranslator(abc.ABC):
    """
    Позволяет нормализовать вход Zero Trust в формат, ожидаемый Rego.
    """
    @abc.abstractmethod
    def translate(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        ...

class DefaultTranslator(InputTranslator):
    def translate(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Нормализуем вход до компактного и безопасного для Rego вида.
        """
        def pick(d: Mapping[str, Any], keys: Iterable[str]) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            for k in keys:
                if k in d:
                    out[k] = d[k]
            return out

        principal = pick(ctx.get("principal", {}), ("subject", "tenant", "roles", "groups", "attributes"))
        device = pick(ctx.get("device", {}), ("id", "trust", "signals"))
        network = pick(ctx.get("network", {}), ("ip", "zone", "country", "city", "user_agent"))
        resource = pick(ctx.get("resource", {}), ("id", "type", "tenant", "sensitivity", "labels"))
        action = ctx.get("action", "")
        risk = pick(ctx.get("risk", {}), ("score", "level"))

        return {
            "principal": principal,
            "device": device,
            "network": network,
            "resource": resource,
            "action": action,
            "risk": risk,
            # контекст окружения
            "env": pick(ctx.get("env", {}), ("name", "ts", "request_id")),
        }


# =========================
# Rego Adapter
# =========================

class RegoAdapter:
    def __init__(
        self,
        config: RegoAdapterConfig,
        translator: Optional[InputTranslator] = None,
    ) -> None:
        self.cfg = config
        self.translator = translator or DefaultTranslator()
        self.cache = TTLCache(max_items=10_000)
        self.bucket = TokenBucket(
            rate_per_s=(self.cfg.http.rate_limit_rps if self.cfg.backend == DecisionBackend.http and self.cfg.http else 100.0),
            burst=(self.cfg.http.rate_limit_burst if self.cfg.backend == DecisionBackend.http and self.cfg.http else 200),
        )
        self.cb = CircuitBreaker()
        self._wasm: Optional[Any] = None  # lazy

        if self.cfg.backend == DecisionBackend.wasm and self.cfg.wasm and self.cfg.wasm.wasm_path:
            if OPAPolicy is None:
                raise PolicyUnavailable("opa-wasm backend requested but opa_wasm package not installed")
            self._wasm = OPAPolicy(self.cfg.wasm.wasm_path)  # type: ignore

    # ---------- public API ----------

    async def evaluate(self, ctx: Mapping[str, Any], *, path: Optional[str] = None) -> Decision:
        """
        Выполняет оценку Rego и возвращает унифицированное решение.
        """
        start = now_ms()
        try:
            input_payload = self.translator.translate(ctx)
            input_safe = redact(input_payload)
            # короткий ключ кэша
            ckey = self._cache_key(path, input_payload)
            cached = self.cache.get(ckey)
            if cached is not None:
                try:
                    out = json.loads(cached)
                    return Decision(
                        allow=bool(out["allow"]),
                        obligations=out.get("obligations") or {},
                        reason=out.get("reason"),
                        raw_result=out.get("raw_result"),
                        latency_ms=max(1, now_ms() - start),
                        cached=True,
                    )
                except Exception:
                    # сломанный кэш игнорируем
                    pass

            # выполняем вызов
            if self.cfg.backend == DecisionBackend.http:
                result = await self._eval_http(input_payload, path=path)
            else:
                result = await self._eval_wasm(input_payload, path=path)

            # унифицируем
            decision = self._normalize_result(result, start)
            # кэшируем
            ttl = int(self.cfg.http.cache_ttl_s if self.cfg.backend == DecisionBackend.http and self.cfg.http else 5)
            self.cache.set(ckey, json.dumps({
                "allow": decision.allow,
                "obligations": decision.obligations,
                "reason": decision.reason,
                "raw_result": decision.raw_result,
            }, separators=(",", ":")).encode("utf-8"), ttl)
            return decision

        except DecisionTimeout as e:
            elapsed = now_ms() - start
            if self._fail_closed():
                logger.warning("rego timeout; fail-closed, denying: %s", e)
                return Decision.deny_fail_closed("timeout", elapsed)
            raise
        except Exception as e:
            elapsed = now_ms() - start
            if self._fail_closed():
                logger.warning("rego error; fail-closed, denying: %s", e)
                return Decision.deny_fail_closed("error", elapsed)
            raise

    async def health(self) -> Dict[str, Any]:
        if self.cfg.backend == DecisionBackend.http:
            if httpx is None:
                return {"ok": False, "reason": "httpx_not_installed"}
            url = self._url_health()
            try:
                await self.cb.before()
                async with httpx.AsyncClient(timeout=self.cfg.http.timeout_s) as client:
                    r = await client.get(url)
                    r.raise_for_status()
                await self.cb.success()
                return {"ok": True, "backend": "http", "url": url}
            except Exception as e:
                await self.cb.failure()
                return {"ok": False, "backend": "http", "url": url, "error": str(e)}
        else:
            ok = self._wasm is not None
            return {"ok": ok, "backend": "wasm"}

    # ---------- internals ----------

    def _fail_closed(self) -> bool:
        if self.cfg.backend == DecisionBackend.http and self.cfg.http:
            return self.cfg.http.fail_mode == FailMode.closed
        if self.cfg.backend == DecisionBackend.wasm and self.cfg.wasm:
            return self.cfg.wasm.fail_mode == FailMode.closed
        return True

    def _url_data(self, path: Optional[str]) -> str:
        assert self.cfg.http
        pp = path or self.cfg.http.decision_path_override
        if not pp:
            pp = f"{self.cfg.http.package}.{self.cfg.http.entrypoint}"
        # OPA API: /v1/data/<path> где path в виде data.pkg.rule без 'data.'
        return self.cfg.http.base_url.rstrip("/") + "/v1/data/" + pp.replace("data.", "").replace("/", ".")

    def _url_health(self) -> str:
        assert self.cfg.http
        return self.cfg.http.base_url.rstrip("/") + "/health"

    def _cache_key(self, path: Optional[str], input_payload: Mapping[str, Any]) -> str:
        h = hashlib.blake2b(digest_size=16)
        # минимальная нормализация для стабильности
        raw = json.dumps(input_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        h.update(raw)
        p = (path or self.cfg.http.decision_path_override or f"{self.cfg.http.package}.{self.cfg.http.entrypoint}").encode("utf-8")
        h.update(p)
        return f"rego:{h.hexdigest()}"

    async def _eval_http(self, input_payload: Mapping[str, Any], *, path: Optional[str]) -> Any:
        if httpx is None:
            raise PolicyUnavailable("httpx is not installed")
        await self.cb.before()
        await self.bucket.acquire()
        url = self._url_data(path)
        body = {"input": input_payload}
        try:
            async with httpx.AsyncClient(timeout=self.cfg.http.timeout_s, headers=self.cfg.http.headers) as client:
                r = await client.post(url, json=body)
                r.raise_for_status()
                out = r.json()
                await self.cb.success()
                # стандартный ответ OPA: {"result": <value>}
                return out.get("result", out)
        except httpx.TimeoutException as e:
            await self.cb.failure()
            raise DecisionTimeout(str(e))
        except Exception as e:
            await self.cb.failure()
            raise PolicyUnavailable(f"http eval failed: {e}")

    async def _eval_wasm(self, input_payload: Mapping[str, Any], *, path: Optional[str]) -> Any:
        if self._wasm is None:
            raise PolicyUnavailable("wasm policy not loaded")
        try:
            # Приведение: большинство OPA WASM экспонируют entrypoint по имени
            ep = (path or (self.cfg.wasm.entrypoint if self.cfg.wasm else "decision")).split(".")[-1]
            res = self._wasm.evaluate(entrypoint=ep, data={}, input=input_payload)  # type: ignore
            # ожидание формата [{"result": ...}]
            if isinstance(res, list) and res and "result" in res[0]:
                return res[0]["result"]
            return res
        except Exception as e:
            raise PolicyUnavailable(f"wasm eval failed: {e}")

    def _normalize_result(self, result: Any, start_ms: int) -> Decision:
        """
        Унифицировать возможные форматы:
          - bool -> allow/deny
          - {"allow": bool, "obligations": {...}, "reason": "..."} -> как есть
          - {"decision": "allow"/"deny", ...}
        """
        lat = max(1, now_ms() - start_ms)
        allow = False
        obligations: Dict[str, Any] = {}
        reason: Optional[str] = None

        try:
            if isinstance(result, bool):
                allow = bool(result)
            elif isinstance(result, Mapping):
                if "allow" in result:
                    allow = bool(result.get("allow"))
                elif "decision" in result:
                    dec = str(result.get("decision")).lower()
                    allow = dec in ("allow", "allowed", "true", "yes")
                obligations = result.get("obligations") or {}
                reason = result.get("reason") or result.get("rule") or None
            else:
                # неизвестный тип результата — трактуем строго
                reason = "unknown_result_type"
                allow = False
        except Exception:
            allow = False
            reason = "normalize_error"

        # финальный лог (без PII)
        logger.info("rego.decision allow=%s lat_ms=%d reason=%s", allow, lat, reason)
        return Decision(allow=allow, obligations=obligations, reason=reason, raw_result=result, latency_ms=lat, cached=False)

    # ---------- bundle signature (optional) ----------

    def verify_bundle_signature(self, payload: bytes, signature_hex: str) -> bool:
        """
        Проверяет подпись OPA bundle (Ed25519). Возвращает True/False, исключения не поднимает.
        """
        try:
            if not self.cfg.bundle_sig.enabled or not self.cfg.bundle_sig.pubkey_ed25519_hex:
                return True  # проверка отключена
            if VerifyKey is None:
                logger.warning("pynacl not available; cannot verify bundle signature")
                return False
            vk = VerifyKey(bytes.fromhex(self.cfg.bundle_sig.pubkey_ed25519_hex))  # type: ignore
            sig = bytes.fromhex(signature_hex)
            vk.verify(payload, sig)  # type: ignore
            return True
        except Exception as e:
            logger.warning("bundle signature verification failed: %s", e)
            return False


# =========================
# Sync wrapper (optional)
# =========================

class RegoAdapterSync:
    """
    Синхронная обертка для сред без asyncio.
    """
    def __init__(self, adapter: RegoAdapter) -> None:
        self._a = adapter

    def evaluate(self, ctx: Mapping[str, Any], *, path: Optional[str] = None) -> Decision:
        return asyncio.run(self._a.evaluate(ctx, path=path))

    def health(self) -> Dict[str, Any]:
        return asyncio.run(self._a.health())


# =========================
# Minimal self-test
# =========================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    # Пример конфигурации HTTP-бэкенда
    http_cfg = OPAHTTPConfig(
        base_url=os.getenv("OPA_URL", "http://localhost:8181"),
        package=os.getenv("OPA_PACKAGE", "zt.core"),
        entrypoint=os.getenv("OPA_ENTRYPOINT", "decision"),
        timeout_s=float(os.getenv("OPA_TIMEOUT_S", "0.6")),
        headers={"Authorization": os.getenv("OPA_BEARER", "")} if os.getenv("OPA_BEARER") else {},
        cache_ttl_s=int(os.getenv("OPA_CACHE_TTL_S", "5")),
        fail_mode=FailMode.closed,
    )
    cfg = RegoAdapterConfig(backend=DecisionBackend.http, http=http_cfg)

    adapter = RegoAdapter(cfg)

    async def _run():
        ctx = {
            "principal": {"subject": "user@example.com", "roles": ["developer"]},
            "device": {"id": "dev-123", "trust": "high"},
            "network": {"ip": "203.0.113.10", "zone": "internet", "user_agent": "curl/8.0"},
            "resource": {"id": "service:billing", "type": "service", "tenant": "prod", "sensitivity": "high"},
            "action": "read",
            "risk": {"score": 2.3, "level": "LOW"},
            "env": {"name": "prod", "ts": int(time.time() * 1000), "request_id": "req-1"},
        }
        dec = await adapter.evaluate(ctx)
        print("allow:", dec.allow, "latency_ms:", dec.latency_ms, "reason:", dec.reason)
        print("raw_result:", json.dumps(dec.raw_result, ensure_ascii=False))

    asyncio.run(_run())

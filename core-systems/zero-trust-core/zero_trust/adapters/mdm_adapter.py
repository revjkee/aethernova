# File: zero-trust-core/zero_trust/adapters/mdm_adapter.py
# Purpose: Унифицированный доступ к MDM/EMM провайдерам и нормализация позы устройства (device posture)
# Python: 3.10+

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Tuple

# httpx опционален (можно заменить), но рекомендуется
try:
    import httpx  # type: ignore
    _HAVE_HTTPX = True
except Exception:  # pragma: no cover
    httpx = None  # type: ignore
    _HAVE_HTTPX = False

__all__ = [
    "MDMAdapter",
    "BaseMDMProvider",
    "JamfProvider",
    "IntuneProvider",
    "StubProvider",
    "MDMSettings",
    "DeviceRecord",
    "AttestationResult",
    "DeviceCompliance",
    "MDMError",
    "MDMAuthError",
    "MDMRateLimitError",
    "MDMNotFound",
]

# =========================
# Логи и контекст
# =========================

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("zt_request_id", default="")

def get_request_id() -> str:
    return _request_id_ctx.get()

def set_request_id(value: str) -> None:
    _request_id_ctx.set(value)

def _logger(name: str = "zt.mdm") -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        log.addHandler(handler)
    if log.level == logging.NOTSET:
        log.setLevel(logging.INFO)
    return log


# =========================
# Ошибки
# =========================

class MDMError(RuntimeError): ...
class MDMAuthError(MDMError): ...
class MDMRateLimitError(MDMError): ...
class MDMNotFound(MDMError): ...


# =========================
# Настройки
# =========================

@dataclass
class MDMSettings:
    # Общие
    provider: str = "stub"             # "jamf" | "intune" | "stub"
    base_url: str = ""                 # API базовый URL провайдера
    tenant_id: str = ""                # Мультиарендность/тенант MDM, если применимо
    # Аутентификация (минимально необходимое)
    api_token: str = ""                # Bearer токен/пат от прокси/секрет-менеджера
    client_id: str = ""                # для OAuth клиентских учетных данных
    client_secret: str = ""            # секрета клиентских учетных данных
    scope: str = ""                    # если требуется (например, Graph scopes)
    # HTTP
    timeout_s: float = 10.0
    connect_timeout_s: float = 3.0
    retries: int = 3
    backoff_base_ms: int = 80          # экспоненциальный бэк-офф
    backoff_max_ms: int = 2000
    verify_tls: bool = True
    # Кэш
    cache_ttl_s: float = 3.0
    cache_max_entries: int = 5000
    # Политики
    require_encryption: bool = True
    require_firewall: bool = True
    max_patch_age_days: int = 30

    @classmethod
    def from_env(cls, prefix: str = "ZT_MDM_") -> "MDMSettings":
        def _get(name: str, default: str = "") -> str:
            return os.getenv(prefix + name, default)
        def _get_i(name: str, default: int) -> int:
            try:
                return int(os.getenv(prefix + name, str(default)))
            except Exception:
                return default
        def _get_f(name: str, default: float) -> float:
            try:
                return float(os.getenv(prefix + name, str(default)))
            except Exception:
                return default
        return cls(
            provider=_get("PROVIDER", "stub").lower(),
            base_url=_get("BASE_URL", ""),
            tenant_id=_get("TENANT_ID", ""),
            api_token=_get("API_TOKEN", ""),
            client_id=_get("CLIENT_ID", ""),
            client_secret=_get("CLIENT_SECRET", ""),
            scope=_get("SCOPE", ""),
            timeout_s=_get_f("TIMEOUT_S", 10.0),
            connect_timeout_s=_get_f("CONNECT_TIMEOUT_S", 3.0),
            retries=_get_i("RETRIES", 3),
            backoff_base_ms=_get_i("BACKOFF_BASE_MS", 80),
            backoff_max_ms=_get_i("BACKOFF_MAX_MS", 2000),
            verify_tls=os.getenv(prefix + "VERIFY_TLS", "true").lower() != "false",
            cache_ttl_s=_get_f("CACHE_TTL_S", 3.0),
            cache_max_entries=_get_i("CACHE_MAX_ENTRIES", 5000),
            require_encryption=os.getenv(prefix + "REQ_ENCRYPTION", "true").lower() != "false",
            require_firewall=os.getenv(prefix + "REQ_FIREWALL", "true").lower() != "false",
            max_patch_age_days=_get_i("MAX_PATCH_AGE_DAYS", 30),
        )


# =========================
# Модель данных
# =========================

@dataclass
class DeviceRecord:
    device_id: str
    platform: str                       # windows|macos|linux|ios|android
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    model: str = ""
    serial_number: str = ""
    disk_encryption: Optional[bool] = None
    firewall_enabled: Optional[bool] = None
    secure_boot: Optional[bool] = None
    tpm_present: Optional[bool] = None
    screen_lock_timeout_s: Optional[int] = None
    patch_age_days: Optional[int] = None
    edr_status: str = ""                # healthy|degraded|missing|unknown
    edr_vendor: str = ""
    av_enabled: Optional[bool] = None
    av_defs_age_days: Optional[int] = None
    mdm_managed: bool = True
    mdm_vendor: str = ""
    rooted: Optional[bool] = None
    jailbroken: Optional[bool] = None
    attest_ts: Optional[datetime] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_posture_dict(self) -> Dict[str, Any]:
        # Соответствует схеме, используемой в политике/сессиях
        return {
            "platform": self.platform,
            "os": {
                "name": self.os_name,
                "version": self.os_version,
                "patch_age_days": int(self.patch_age_days or 0),
                "build": self.os_build,
            },
            "disk_encryption": bool(self.disk_encryption) if self.disk_encryption is not None else False,
            "firewall_enabled": bool(self.firewall_enabled) if self.firewall_enabled is not None else False,
            "screen_lock_timeout_s": int(self.screen_lock_timeout_s or 0),
            "secure_boot": bool(self.secure_boot) if self.secure_boot is not None else False,
            "tpm_present": bool(self.tpm_present) if self.tpm_present is not None else False,
            "serial_number": self.serial_number,
            "model": self.model,
            "edr": {"status": (self.edr_status or "unknown"), "vendor": self.edr_vendor or ""},
            "av": {"enabled": bool(self.av_enabled) if self.av_enabled is not None else False,
                   "definitions_age_days": int(self.av_defs_age_days or 0)},
            "mdm": {"managed": bool(self.mdm_managed), "vendor": self.mdm_vendor or ""},
            "attest": {
                "mdm": {"valid": True if self.attest_ts else False,
                        "ts": self.attest_ts.astimezone(timezone.utc).isoformat() if self.attest_ts else None}
            },
            "rooted": bool(self.rooted) if self.rooted is not None else False,
            "jailbroken": bool(self.jailbroken) if self.jailbroken is not None else False,
            "extra": self.extra,
        }

@dataclass
class DeviceCompliance:
    compliant: bool
    violations: List[str] = field(default_factory=list)

@dataclass
class AttestationResult:
    valid: bool
    ts: datetime
    reasons: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


# =========================
# Клиент HTTP с бэк-оффом
# =========================

class _HttpClient:
    def __init__(self, settings: MDMSettings, log: logging.Logger) -> None:
        self.st = settings
        self.log = log
        self._client = None  # type: ignore

    async def __aenter__(self) -> "_HttpClient":
        if _HAVE_HTTPX:
            self._client = httpx.AsyncClient(
                base_url=self.st.base_url or None,
                timeout=httpx.Timeout(self.st.timeout_s, connect=self.st.connect_timeout_s),
                verify=self.st.verify_tls,
            )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if _HAVE_HTTPX and self._client:
            await self._client.aclose()

    async def request(self, method: str, url: str, *, headers: Mapping[str, str] | None = None, params: Mapping[str, Any] | None = None) -> Tuple[int, Dict[str, Any]]:
        if not _HAVE_HTTPX:
            raise MDMError("httpx is required for network access")
        h = dict(headers or {})
        # Корреляция
        rid = get_request_id()
        if rid:
            h.setdefault("x-request-id", rid)
        # Бэк-офф
        last_err: Optional[Exception] = None
        for attempt in range(self.st.retries + 1):
            try:
                resp = await self._client.request(method, url, headers=h, params=params)
                if resp.status_code in (429, 502, 503, 504):
                    raise MDMRateLimitError(f"MDM transient error {resp.status_code}")
                if resp.status_code == 401:
                    raise MDMAuthError("MDM auth failed")
                if resp.status_code == 404:
                    raise MDMNotFound("device not found")
                data = {}
                if resp.content:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"_raw": resp.text[:1024]}
                return resp.status_code, data
            except (MDMRateLimitError,) as e:
                last_err = e
                self._sleep_backoff(attempt)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.RemoteProtocolError) as e:  # type: ignore
                last_err = e
                self._sleep_backoff(attempt)
            except Exception as e:
                last_err = e
                break
        # Exhausted
        msg = f"MDM request failed after {self.st.retries} retries: {last_err}"
        self.log.error(msg)
        raise MDMError(msg)

    def _sleep_backoff(self, attempt: int) -> None:
        # асинхронная задержка с джиттером
        base = min(self.st.backoff_max_ms, self.st.backoff_base_ms * (2 ** attempt))
        delay = (base / 1000.0) * (0.5 + random.random())  # полуджиттер
        # спим в текущем цикле событий
        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.sleep(delay)) if loop.is_running() else time.sleep(delay)


# =========================
# Простой TTL-кэш
# =========================

class _TTLCache:
    __slots__ = ("ttl", "max_entries", "_store")

    def __init__(self, ttl: float, max_entries: int) -> None:
        self.ttl = ttl
        self.max_entries = max_entries
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        item = self._store.get(key)
        if not item:
            return None
        exp, val = item
        if exp < now:
            self._store.pop(key, None)
            return None
        return val

    def put(self, key: str, val: Any) -> None:
        if len(self._store) >= self.max_entries:
            self._store.pop(next(iter(self._store)), None)
        self._store[key] = (time.monotonic() + self.ttl, val)


# =========================
# Интерфейс провайдера
# =========================

class BaseMDMProvider(Protocol):
    async def get_device(self, *, device_id: str) -> DeviceRecord: ...
    async def attest(self, *, device_id: str) -> AttestationResult: ...
    async def compliance(self, *, device_id: str, policy: MDMSettings) -> DeviceCompliance: ...


# =========================
# Провайдер Jamf (заготовка)
# =========================

class JamfProvider:
    def __init__(self, settings: MDMSettings, log: logging.Logger) -> None:
        self.st = settings
        self.log = log

    def _headers(self) -> Dict[str, str]:
        # Не логировать и не возвращать «сырой» токен
        return {"authorization": f"Bearer {self.st.api_token}", "accept": "application/json"}

    async def get_device(self, *, device_id: str) -> DeviceRecord:
        # Пример запроса. Конкретные эндпоинты проверьте в вашей Jamf Pro (UI/API).
        async with _HttpClient(self.st, self.log) as http:
            status, data = await http.request("GET", f"/uapi/v1/computers-inventory-detail/id/{device_id}", headers=self._headers())
        # Маппинг полей (осторожно с ключами; защищаемся от отсутствия)
        inv = data.get("inventory", {})
        gen = inv.get("general", {})
        sec = inv.get("security", {})
        osx = inv.get("operatingSystem", {})
        hw = inv.get("hardware", {})
        # Нормализация
        record = DeviceRecord(
            device_id=str(device_id),
            platform="macos",
            os_name="macOS",
            os_version=str(osx.get("version") or ""),
            os_build=str(osx.get("build") or ""),
            model=str(hw.get("modelIdentifier") or ""),
            serial_number=str(gen.get("serialNumber") or ""),
            disk_encryption=bool(sec.get("fileVault2Enabled", False)),
            firewall_enabled=bool(sec.get("systemIntegrityProtectionEnabled", True)),
            secure_boot=None,
            tpm_present=None,
            screen_lock_timeout_s=None,
            patch_age_days=None,
            edr_status="unknown",
            edr_vendor="",
            av_enabled=None,
            av_defs_age_days=None,
            mdm_managed=True,
            mdm_vendor="jamf",
            rooted=False,
            jailbroken=False,
            attest_ts=datetime.now(timezone.utc),
            extra={"raw_inventory_id": inv.get("id")},
        )
        return record

    async def attest(self, *, device_id: str) -> AttestationResult:
        # Jamf обычно дает инвентарь как косвенную «аттестацию» управления
        return AttestationResult(valid=True, ts=datetime.now(timezone.utc), reasons=["jamf_inventory_present"])

    async def compliance(self, *, device_id: str, policy: MDMSettings) -> DeviceCompliance:
        rec = await self.get_device(device_id=device_id)
        violations: List[str] = []
        if policy.require_encryption and rec.disk_encryption is False:
            violations.append("disk_encryption_disabled")
        if policy.require_firewall and rec.firewall_enabled is False:
            violations.append("firewall_disabled")
        return DeviceCompliance(compliant=len(violations) == 0, violations=violations)


# =========================
# Провайдер Intune (заготовка)
# =========================

class IntuneProvider:
    def __init__(self, settings: MDMSettings, log: logging.Logger) -> None:
        self.st = settings
        self.log = log

    def _headers(self) -> Dict[str, str]:
        return {"authorization": f"Bearer {self.st.api_token}", "accept": "application/json"}

    async def get_device(self, *, device_id: str) -> DeviceRecord:
        # Пример запроса. Проверьте фактические Graph endpoints под вашу конфигурацию.
        async with _HttpClient(self.st, self.log) as http:
            # managedDevices или устройство по ID (пример; проверьте схему у себя)
            status, data = await http.request(
                "GET",
                f"/beta/deviceManagement/managedDevices/{device_id}",
                headers=self._headers(),
            )
        # Извлечение атрибутов с защитой от отсутствия полей
        platform = _normalize_platform(data.get("operatingSystem", "windows"))
        comp = data.get("complianceState", "unknown")
        sec = data.get("deviceHealthAttestationState", {}) or {}
        # Возраст патчей (эвристика)
        last_patch = data.get("lastSyncDateTime")
        patch_days = _age_days_from_iso(last_patch) if last_patch else None
        record = DeviceRecord(
            device_id=str(device_id),
            platform=platform,
            os_name=str(data.get("operatingSystem") or "").lower(),
            os_version=str(data.get("osVersion") or ""),
            os_build=str(data.get("osBuildNumber") or ""),
            model=str(data.get("model") or ""),
            serial_number=str(data.get("serialNumber") or ""),
            disk_encryption=_coerce_bool(data.get("isEncrypted")),
            firewall_enabled=_coerce_bool(None),   # intune специфичен: требуется отдельный провайдер сигнала
            secure_boot=_coerce_bool(sec.get("secureBoot")),
            tpm_present=_coerce_bool(sec.get("tpmVersion")),  # tpmVersion != None ~ признак наличия TPM
            screen_lock_timeout_s=None,
            patch_age_days=patch_days,
            edr_status="unknown",
            edr_vendor="",
            av_enabled=None,
            av_defs_age_days=None,
            mdm_managed=True,
            mdm_vendor="intune",
            rooted=False,
            jailbroken=data.get("jailBroken", "unknown") == "true",
            attest_ts=datetime.now(timezone.utc),
            extra={"compliance": comp},
        )
        return record

    async def attest(self, *, device_id: str) -> AttestationResult:
        return AttestationResult(valid=True, ts=datetime.now(timezone.utc), reasons=["intune_managed_device"])

    async def compliance(self, *, device_id: str, policy: MDMSettings) -> DeviceCompliance:
        rec = await self.get_device(device_id=device_id)
        violations: List[str] = []
        if policy.require_encryption and rec.disk_encryption is False:
            violations.append("disk_encryption_disabled")
        if policy.require_firewall and rec.firewall_enabled is False:
            violations.append("firewall_disabled")
        if rec.patch_age_days is not None and rec.patch_age_days > policy.max_patch_age_days:
            violations.append("patches_stale")
        return DeviceCompliance(compliant=len(violations) == 0, violations=violations)


# =========================
# Тестовый провайдер (offline)
# =========================

class StubProvider:
    def __init__(self, settings: MDMSettings, log: logging.Logger) -> None:
        self.st = settings
        self.log = log

    async def get_device(self, *, device_id: str) -> DeviceRecord:
        # Дет-данные для локальных тестов
        now = datetime.now(timezone.utc)
        return DeviceRecord(
            device_id=device_id,
            platform="macos",
            os_name="macOS",
            os_version="14.5",
            os_build="23F79",
            model="MacBookPro18,4",
            serial_number="STUB123456",
            disk_encryption=True,
            firewall_enabled=True,
            secure_boot=None,
            tpm_present=None,
            screen_lock_timeout_s=300,
            patch_age_days=5,
            edr_status="healthy",
            edr_vendor="StubEDR",
            av_enabled=True,
            av_defs_age_days=1,
            mdm_managed=True,
            mdm_vendor="stub",
            rooted=False,
            jailbroken=False,
            attest_ts=now,
            extra={"stub": True},
        )

    async def attest(self, *, device_id: str) -> AttestationResult:
        return AttestationResult(valid=True, ts=datetime.now(timezone.utc), reasons=["stub_ok"])

    async def compliance(self, *, device_id: str, policy: MDMSettings) -> DeviceCompliance:
        rec = await self.get_device(device_id=device_id)
        violations: List[str] = []
        if policy.require_encryption and rec.disk_encryption is False:
            violations.append("disk_encryption_disabled")
        return DeviceCompliance(compliant=len(violations) == 0, violations=violations)


# =========================
# Адаптер-агрегатор
# =========================

class MDMAdapter:
    """
    Универсальный адаптер, скрывающий различия провайдеров и предоставляющий:
      - fetch_posture(device_id) -> дикт позы устройства
      - attest(device_id) -> AttestationResult
      - compliance(device_id) -> DeviceCompliance
    С кэшированием решений на короткий TTL.
    """

    def __init__(self, settings: MDMSettings, *, logger: Optional[logging.Logger] = None) -> None:
        self.st = settings
        self.log = logger or _logger()
        self.cache = _TTLCache(ttl=settings.cache_ttl_s, max_entries=settings.cache_max_entries)
        self.provider = self._make_provider(settings)

    def _make_provider(self, st: MDMSettings) -> BaseMDMProvider:
        name = (st.provider or "stub").lower()
        if name == "jamf":
            return JamfProvider(st, self.log)
        if name == "intune":
            return IntuneProvider(st, self.log)
        if name == "stub":
            return StubProvider(st, self.log)
        raise ValueError(f"unsupported MDM provider: {name}")

    async def fetch_posture(self, *, device_id: str) -> Dict[str, Any]:
        cache_key = f"posture:{self.st.provider}:{device_id}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        rec = await self.provider.get_device(device_id=device_id)
        posture = rec.to_posture_dict()
        self.cache.put(cache_key, posture)
        return posture

    async def attest(self, *, device_id: str) -> AttestationResult:
        cache_key = f"attest:{self.st.provider}:{device_id}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        res = await self.provider.attest(device_id=device_id)
        self.cache.put(cache_key, res)
        return res

    async def compliance(self, *, device_id: str) -> DeviceCompliance:
        cache_key = f"compl:{self.st.provider}:{device_id}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        res = await self.provider.compliance(device_id=device_id, policy=self.st)
        self.cache.put(cache_key, res)
        return res


# =========================
# Утилиты
# =========================

def _normalize_platform(s: str) -> str:
    if not s:
        return "unknown"
    v = str(s).lower()
    if "win" in v:
        return "windows"
    if "mac" in v or "darwin" in v or "osx" in v:
        return "macos"
    if "linux" in v or "ubuntu" in v or "debian" in v or "rhel" in v:
        return "linux"
    if "ios" in v:
        return "ios"
    if "android" in v:
        return "android"
    return v

def _coerce_bool(x: Any) -> Optional[bool]:
    if x is None:
        return None
    if isinstance(x, bool):
        return x
    s = str(x).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    return None

def _age_days_from_iso(iso: str) -> Optional[int]:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days)
    except Exception:
        return None


# =========================
# Пример использования (комментарии)
# =========================
# from zero_trust.adapters.mdm_adapter import MDMAdapter, MDMSettings, set_request_id
#
# settings = MDMSettings.from_env()  # или вручную
# adapter = MDMAdapter(settings)
#
# async def get_device_posture(device_id: str):
#     set_request_id("req-123")  # для корреляции логов
#     posture = await adapter.fetch_posture(device_id=device_id)
#     return posture
#
# async def evaluate(device_id: str):
#     att = await adapter.attest(device_id=device_id)
#     comp = await adapter.compliance(device_id=device_id)
#     return {"attestation": {"valid": att.valid, "ts": att.ts.isoformat(), "reasons": att.reasons},
#             "compliance": {"compliant": comp.compliant, "violations": comp.violations}}

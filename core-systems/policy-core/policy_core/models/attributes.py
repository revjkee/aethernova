# -*- coding: utf-8 -*-
"""
policy_core.models.attributes
Промышленная модель атрибутов ABAC для policy-core / OPA (Rego).

Особенности:
- Строгие Pydantic-модели Principal/Resource/Action/Environment
- Нормализация (lowercase для ролей/тегов, дедупликация)
- Валидации полей (IP/ISO country/уровни классификации/границы)
- Стабильная сериализация в OPA input (stable JSON), safe redaction
- Фабрики из HTTP-заголовков/контекста/произвольных словарей
- Лимиты на размеры коллекций и глубину рекурсивных структур
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import string
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

try:
    # pydantic v1 API (наиболее совместимая база)
    from pydantic import BaseModel, Field, validator, root_validator
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic>=1 is required for policy_core.models.attributes") from e


# -------------------------------
# Константы и перечисления
# -------------------------------

MAX_LIST = 1024
MAX_LABELS = 2048
MAX_STR = 10_000

SENSITIVE_KEYS = {
    "authorization",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "password",
    "secret",
    "api_key",
    "x-api-key",
    "x-auth-token",
}

COUNTRY_ISO2_RE = re.compile(r"^[A-Z]{2}$")
TENANT_RE = re.compile(r"^[a-zA-Z0-9_\-:.]{1,128}$")
ID_RE = re.compile(r"^[a-zA-Z0-9_\-:.]{1,256}$")


class Classification(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    secret = "secret"
    top_secret = "top_secret"


class Channel(str, Enum):
    web = "web"
    mobile = "mobile"
    service = "service"
    cli = "cli"
    batch = "batch"
    partner = "partner"


# -------------------------------
# Утилиты
# -------------------------------

def _stable_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _now_ts_ms() -> int:
    return int(time.time() * 1000)

def _gen_request_id() -> str:
    return str(uuid.uuid4())

def _limit_str(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    if len(s) <= MAX_STR:
        return s
    return s[:MAX_STR]

def _norm_set(values: Optional[List[str] | Set[str]]) -> List[str]:
    if not values:
        return []
    # lowercase, strip, dedup, sort
    norm = {v.strip().lower() for v in values if v and isinstance(v, str)}
    return sorted(list(norm))[:MAX_LIST]

def _mask_secrets(data: Any) -> Any:
    if isinstance(data, dict):
        res = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_KEYS:
                res[k] = "***"
            else:
                res[k] = _mask_secrets(v)
        return res
    if isinstance(data, list):
        return [_mask_secrets(v) for v in data[:MAX_LIST]]
    if isinstance(data, str):
        return _limit_str(data)
    return data

def _parse_ip(ip: Optional[str]) -> Optional[str]:
    if not ip or not isinstance(ip, str):
        return None
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except Exception:
        return None

def _valid_iso2(country: Optional[str]) -> Optional[str]:
    if not country:
        return None
    c = country.strip().upper()
    if COUNTRY_ISO2_RE.match(c):
        return c
    return None

def _limit_labels(labels: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not labels:
        return {}
    out: Dict[str, Any] = {}
    for i, (k, v) in enumerate(labels.items()):
        if i >= MAX_LABELS:
            break
        key = str(k)[:128]
        # уплощаем вложенность и ограничиваем строки
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[key] = v if not isinstance(v, str) else _limit_str(v)
        else:
            out[key] = _limit_str(_stable_dumps(v))
    return out


# -------------------------------
# Модели атрибутов
# -------------------------------

class PrincipalAttributes(BaseModel):
    subject_id: Optional[str] = Field(None, description="Идентификатор субъекта (user/service)")
    subject_type: Optional[str] = Field(None, description="Тип субъекта: user|service|device|anon")
    tenant_id: Optional[str] = Field(None, description="Арендатор/организация")
    roles: List[str] = Field(default_factory=list, description="Нормализованные роли")
    groups: List[str] = Field(default_factory=list, description="Нормализованные группы")
    scopes: List[str] = Field(default_factory=list, description="OAuth/доступ")
    auth_strength: Optional[int] = Field(None, ge=0, le=10, description="Сила аутентификации 0..10")
    mfa: Optional[bool] = Field(None, description="Флаг MFA")
    device_id: Optional[str] = Field(None, description="Устройство")
    ip: Optional[str] = Field(None, description="IP субъекта (нормализованный)")
    asn: Optional[int] = Field(None, ge=0, description="ASN при наличии")
    country: Optional[str] = Field(None, description="ISO-3166-1 alpha-2")
    risk_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Риск 0.0..1.0")
    traits: Dict[str, Any] = Field(default_factory=dict, description="Произвольные признаки (ограниченные)")

    @validator("subject_id")
    def v_subject_id(cls, v):
        if v is None:
            return v
        if not ID_RE.match(v):
            raise ValueError("subject_id has invalid format")
        return v

    @validator("tenant_id")
    def v_tenant(cls, v):
        if v is None:
            return v
        if not TENANT_RE.match(v):
            raise ValueError("tenant_id has invalid format")
        return v

    @validator("roles", pre=True, always=True)
    def v_roles(cls, v):
        return _norm_set(v)

    @validator("groups", pre=True, always=True)
    def v_groups(cls, v):
        return _norm_set(v)

    @validator("scopes", pre=True, always=True)
    def v_scopes(cls, v):
        return _norm_set(v)

    @validator("ip", pre=True)
    def v_ip(cls, v):
        return _parse_ip(v)

    @validator("country", pre=True)
    def v_country(cls, v):
        return _valid_iso2(v)

    @validator("traits", pre=True)
    def v_traits(cls, v):
        return _limit_labels(v)


class ResourceAttributes(BaseModel):
    resource_id: Optional[str] = Field(None, description="Идентификатор ресурса")
    resource_type: Optional[str] = Field(None, description="Тип/класс ресурса")
    owner_id: Optional[str] = Field(None, description="Владелец ресурса")
    tenant_id: Optional[str] = Field(None, description="Арендатор ресурса")
    classification: Classification = Field(default=Classification.internal)
    tags: List[str] = Field(default_factory=list, description="Теги ресурса")
    created_at: Optional[int] = Field(None, description="UNIX ms")
    updated_at: Optional[int] = Field(None, description="UNIX ms")
    labels: Dict[str, Any] = Field(default_factory=dict, description="Ключ-значение по ресурсу")

    @validator("resource_id")
    def v_res_id(cls, v):
        if v is None:
            return v
        if not ID_RE.match(v):
            raise ValueError("resource_id has invalid format")
        return v

    @validator("owner_id")
    def v_owner(cls, v):
        if v is None:
            return v
        if not ID_RE.match(v):
            raise ValueError("owner_id has invalid format")
        return v

    @validator("tenant_id")
    def v_tenant(cls, v):
        if v is None:
            return v
        if not TENANT_RE.match(v):
            raise ValueError("tenant_id has invalid format")
        return v

    @validator("tags", pre=True, always=True)
    def v_tags(cls, v):
        return _norm_set(v)

    @validator("labels", pre=True)
    def v_labels(cls, v):
        return _limit_labels(v)

    @validator("created_at", "updated_at")
    def v_ts(cls, v):
        if v is None:
            return v
        if v < 0:
            raise ValueError("timestamps must be >= 0")
        return v


class ActionAttributes(BaseModel):
    action: str = Field(..., description="Действие: read|write|delete|approve|*")
    method: Optional[str] = Field(None, description="HTTP/gRPC метод при наличии")
    scope: Optional[str] = Field(None, description="Бизнес-область/namespace")
    labels: Dict[str, Any] = Field(default_factory=dict, description="Доп. сведения")

    @validator("action")
    def v_action(cls, v):
        v = v.strip().lower()
        if not v or len(v) > 128:
            raise ValueError("action is required and must be <=128 chars")
        return v

    @validator("method")
    def v_method(cls, v):
        if v is None:
            return v
        return v.strip().upper()[:32]

    @validator("scope")
    def v_scope(cls, v):
        if v is None:
            return v
        return v.strip().lower()[:128]

    @validator("labels", pre=True)
    def v_labels(cls, v):
        return _limit_labels(v)


class EnvironmentAttributes(BaseModel):
    ts_ms: int = Field(default_factory=_now_ts_ms, description="Время запроса (ms)")
    request_id: str = Field(default_factory=_gen_request_id, description="Корреляционный идентификатор")
    channel: Channel = Field(default=Channel.web)
    app_version: Optional[str] = Field(None, description="Версия клиента/сервиса")
    ip: Optional[str] = Field(None, description="IP источника запроса")
    country: Optional[str] = Field(None, description="ISO-3166-1 alpha-2")
    timezone: Optional[str] = Field(None, description="IANA TZ")
    labels: Dict[str, Any] = Field(default_factory=dict, description="Доп. сведения окружения")

    @validator("ip", pre=True)
    def v_ip(cls, v):
        return _parse_ip(v)

    @validator("country", pre=True)
    def v_country(cls, v):
        return _valid_iso2(v)

    @validator("labels", pre=True)
    def v_labels(cls, v):
        return _limit_labels(v)


# -------------------------------
# Композитный ввод для OPA
# -------------------------------

class ABACInput(BaseModel):
    principal: PrincipalAttributes = Field(default_factory=PrincipalAttributes)
    resource: ResourceAttributes = Field(default_factory=ResourceAttributes)
    action: ActionAttributes
    env: EnvironmentAttributes = Field(default_factory=EnvironmentAttributes)

    # ------------- Фабрики -------------

    @classmethod
    def from_context(
        cls,
        *,
        principal: Dict[str, Any] | PrincipalAttributes | None = None,
        resource: Dict[str, Any] | ResourceAttributes | None = None,
        action: Dict[str, Any] | ActionAttributes | None = None,
        env: Dict[str, Any] | EnvironmentAttributes | None = None,
    ) -> "ABACInput":
        def coerce(model_cls, v):
            if v is None:
                return model_cls()
            if isinstance(v, model_cls):
                return v
            if isinstance(v, dict):
                return model_cls(**v)
            raise TypeError(f"Unsupported type for {model_cls.__name__}")

        if action is None:
            raise ValueError("action is required for ABACInput")

        return cls(
            principal=coerce(PrincipalAttributes, principal),
            resource=coerce(ResourceAttributes, resource),
            action=coerce(ActionAttributes, action),
            env=coerce(EnvironmentAttributes, env),
        )

    @classmethod
    def from_headers(
        cls,
        *,
        headers: Dict[str, str],
        action: Dict[str, Any],
        resource: Optional[Dict[str, Any]] = None,
        extras: Optional[Dict[str, Any]] = None,
    ) -> "ABACInput":
        """
        Простая фабрика из HTTP-заголовков. Извлекает типичные поля:
        - Authorization (маскируется при сериализации)
        - X-User-Id / X-Subject-Type / X-Tenant-Id
        - X-Roles / X-Groups / X-Scopes (через запятую)
        - X-Forwarded-For / X-Real-IP
        - X-Country / X-Request-Id / X-App-Version / X-Channel
        """
        h = {k.lower(): v for k, v in (headers or {}).items()}

        def split_csv(name: str) -> List[str]:
            raw = h.get(name, "")
            return [x.strip() for x in raw.split(",") if x.strip()]

        principal = {
            "subject_id": h.get("x-user-id") or h.get("x-subject-id"),
            "subject_type": h.get("x-subject-type") or "user",
            "tenant_id": h.get("x-tenant-id"),
            "roles": split_csv("x-roles"),
            "groups": split_csv("x-groups"),
            "scopes": split_csv("x-scopes"),
            "ip": h.get("x-real-ip") or (h.get("x-forwarded-for") or "").split(",")[0].strip(),
            "country": h.get("x-country"),
            "traits": {},
        }

        env = {
            "request_id": h.get("x-request-id") or _gen_request_id(),
            "app_version": h.get("x-app-version"),
            "channel": (h.get("x-channel") or "web").lower(),
            "ip": principal["ip"],
            "country": principal["country"],
            "labels": {},
        }

        if extras and isinstance(extras, dict):
            # добросовестно ограничиваем по размерам
            env["labels"].update(_limit_labels(extras.get("env_labels")))
            principal["traits"].update(_limit_labels(extras.get("principal_traits", {})))

        return cls.from_context(
            principal=principal,
            resource=resource or {},
            action=action,
            env=env,
        )

    # ------------- Сериализация -------------

    def to_opa_input(self) -> Dict[str, Any]:
        """
        Структура строго соответствует input для OPA:
        {
          "principal": {...},
          "resource": {...},
          "action": {...},
          "env": {...}
        }
        """
        return {
            "principal": json.loads(self.principal.json()),
            "resource": json.loads(self.resource.json()),
            "action": json.loads(self.action.json()),
            "env": json.loads(self.env.json()),
        }

    def stable_json(self) -> str:
        """Стабильная JSON-кодировка для кэшей/хэшей."""
        return _stable_dumps(self.to_opa_input())

    def safe_dict(self) -> Dict[str, Any]:
        """Безопасный словарь для логов (секреты отредактированы)."""
        return _mask_secrets(self.to_opa_input())


# -------------------------------
# Примитивные самотесты (не выполняются автоматически)
# -------------------------------

if __name__ == "__main__":  # pragma: no cover
    # Базовый smoke-test
    abac = ABACInput.from_context(
        principal={
            "subject_id": "user:123",
            "tenant_id": "acme",
            "roles": ["Admin", "Viewer", "admin"],
            "ip": "192.168.1.10",
            "country": "se",
            "traits": {"authorization": "Bearer abc", "lvl": 3},
        },
        resource={
            "resource_id": "doc:42",
            "resource_type": "document",
            "owner_id": "user:1",
            "classification": "confidential",
            "tags": ["PII", "internal", "pii"],
            "labels": {"project": "atlas", "cost": 1.23},
        },
        action={"action": "read", "method": "get"},
        env={"channel": "web", "ip": "10.0.0.2", "country": "SE"},
    )
    print("OPA input:", abac.to_opa_input())
    print("Stable JSON:", abac.stable_json())
    print("Safe dict:", abac.safe_dict())

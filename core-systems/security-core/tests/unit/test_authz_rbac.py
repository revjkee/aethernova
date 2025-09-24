# security-core/tests/unit/test_authz_rbac.py
# -*- coding: utf-8 -*-
import ipaddress
import importlib
import inspect
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import pytest


# ==========================
# Адаптер к движку RBAC
# ==========================

@dataclass
class EngineFeatures:
    deny_overrides: bool = True
    role_hierarchy: bool = True
    resource_patterns: bool = True
    tenant_scope: bool = True
    conditions_time: bool = False
    conditions_ip: bool = False
    caching: bool = False
    decision_details: bool = False


class RbacAdapter:
    """
    Универсальный «мост» к вашему модулю security.security.iam.permissions.
    Требуется реализовать базовые методы: reset(), add_role(), grant(), revoke(), allow(), deny(), is_allowed().
    Автообнаружение популярных интерфейсов: PolicyEngine/RbacEngine/AuthorizationEngine/authorize().
    """
    def __init__(self) -> None:
        self.features = EngineFeatures()
        self._mod = importlib.import_module("security.security.iam.permissions")
        self._engine = None
        self._discover()

    def _discover(self) -> None:
        # Популярные имена движков
        for cname in ("PolicyEngine", "RbacEngine", "AuthorizationEngine", "PolicyEvaluator"):
            cls = getattr(self._mod, cname, None)
            if cls and inspect.isclass(cls):
                try:
                    self._engine = cls()
                    break
                except Exception:
                    # иногда нужен пустой/дефолтный конструктор
                    self._engine = cls  # фабрика; попробуем позже
                    break

        # Функциональный интерфейс
        self._fn_authorize = getattr(self._mod, "authorize", None) or getattr(self._mod, "is_allowed", None)

        # Эвристика наличия некоторых возможностей
        for maybe in ("Condition", "TimeBetween", "IpSubnet", "CIDR"):
            if hasattr(self._mod, maybe):
                self.features.conditions_time = self.features.conditions_time or maybe.lower().startswith("time")
                self.features.conditions_ip = self.features.conditions_ip or maybe.lower() in ("ipsubnet", "cidr")
        for maybe in ("Decision", "PolicyDecision"):
            if hasattr(self._mod, maybe):
                self.features.decision_details = True
        # Кэш: наличие LRU/TTL
        for maybe in ("LRU", "TTL", "cache", "Caching"):
            if any(maybe.lower() in n.lower() for n in dir(self._mod)):
                self.features.caching = True

        # Поддержка иерархии/deny-overrides/шаблонов — предполагаем True для промышленных реализаций
        # Если движок не найден — скипаем в set‑апе.

    def _ensure_engine(self) -> None:
        if self._engine and inspect.isclass(self._engine):
            self._engine = self._engine()  # фабрика → инстанс
        if not self._engine and not self._fn_authorize:
            pytest.skip("RBAC engine interface not found in security.security.iam.permissions")

    # ---------------- Public adapter API used by tests ----------------

    def reset(self) -> None:
        self._ensure_engine()
        if hasattr(self._engine, "reset"):
            self._engine.reset()  # type: ignore[attr-defined]
            return
        # иначе пытаемся пересоздать
        if self._engine:
            eng_cls = self._engine.__class__
            try:
                self._engine = eng_cls()
            except Exception:
                pass

    def add_role(self, name: str, parents: Optional[list] = None) -> None:
        if not self._engine:
            return
        for meth in ("add_role", "register_role", "define_role"):
            fn = getattr(self._engine, meth, None)
            if fn:
                try:
                    fn(name, parents=parents or [])
                    return
                except TypeError:
                    try:
                        fn(name)
                        return
                    except Exception:
                        pass
        # Если нет явной регистрации ролей — многие движки создают их on‑the‑fly в правилах.

    def allow(self, role: str, action: str, resource: str, **conds: Any) -> None:
        if not self._engine:
            return
        for meth in ("allow", "grant_permission", "add_permission", "add_rule"):
            fn = getattr(self._engine, meth, None)
            if fn:
                try:
                    fn(effect="allow", role=role, action=action, resource=resource, conditions=conds or None)
                    return
                except TypeError:
                    try:
                        fn(role, action, resource, **(conds or {}))
                        return
                    except Exception:
                        pass
        # Фоллбек: нет API — пропустим; для функционального интерфейса тесты будут использовать прямой вызов.

    def deny(self, role: str, action: str, resource: str, **conds: Any) -> None:
        if not self._engine:
            return
        for meth in ("deny", "add_rule"):
            fn = getattr(self._engine, meth, None)
            if fn:
                try:
                    fn(effect="deny", role=role, action=action, resource=resource, conditions=conds or None)
                    return
                except TypeError:
                    try:
                        fn(role, action, resource, effect="deny", **(conds or {}))
                        return
                    except Exception:
                        pass

    def grant(self, principal: str, role: str, *, scope: Optional[str] = None) -> None:
        if not self._engine:
            return
        for meth in ("assign_role", "grant_role", "bind_role"):
            fn = getattr(self._engine, meth, None)
            if fn:
                try:
                    fn(principal=principal, role=role, scope=scope)
                    return
                except TypeError:
                    try:
                        fn(principal, role, scope=scope)
                        return
                    except Exception:
                        pass

    def revoke(self, principal: str, role: str, *, scope: Optional[str] = None) -> None:
        if not self._engine:
            return
        for meth in ("revoke_role", "unbind_role", "remove_role"):
            fn = getattr(self._engine, meth, None)
            if fn:
                try:
                    fn(principal=principal, role=role, scope=scope)
                    return
                except TypeError:
                    try:
                        fn(principal, role, scope=scope)
                        return
                    except Exception:
                        pass

    def is_allowed(self, principal: str, action: str, resource: str, *, tenant: Optional[str] = None, now: Optional[int] = None, ip: Optional[str] = None) -> bool:
        ctx: Dict[str, Any] = {}
        if tenant is not None:
            ctx["tenant"] = tenant
        if now is not None:
            ctx["now"] = now
        if ip is not None:
            ctx["ip"] = ip

        # Классовый движок
        if self._engine and hasattr(self._engine, "authorize"):
            decision = self._engine.authorize(principal=principal, action=action, resource=resource, context=ctx or None)  # type: ignore[attr-defined]
            return self._decision_to_bool(decision)

        # Функциональный движок
        if hasattr(self, "_fn_authorize") and callable(self._fn_authorize):
            try:
                decision = self._fn_authorize(principal=principal, action=action, resource=resource, context=ctx or None)  # type: ignore[operator]
            except TypeError:
                decision = self._fn_authorize(principal, action, resource, ctx or None)  # type: ignore[operator]
            return self._decision_to_bool(decision)

        pytest.skip("No authorize/is_allowed entrypoint found")

    def _decision_to_bool(self, decision: Any) -> bool:
        if isinstance(decision, bool):
            return decision
        # Популярные поля: allowed/allow/effect
        for field in ("allowed", "allow", "is_allowed", "granted"):
            if hasattr(decision, field):
                return bool(getattr(decision, field))
        eff = getattr(decision, "effect", None)
        if eff is not None:
            return str(eff).lower() == "allow"
        # Последний шанс: truthiness
        return bool(decision)


@pytest.fixture(scope="module")
def rbac() -> RbacAdapter:
    return RbacAdapter()


@pytest.fixture(autouse=True)
def clean_engine(rbac: RbacAdapter):
    rbac.reset()
    # Базовые роли и права (минимальный набор, безопасен к отсутствию методов)
    rbac.add_role("viewer")
    rbac.add_role("editor", parents=["viewer"])
    rbac.add_role("admin", parents=["editor"])
    # Разрешения (если есть API)
    rbac.allow("viewer", "read", "doc:*")
    rbac.allow("editor", "write", "doc:*")
    rbac.deny("editor", "delete", "doc:safe/*")  # намеренно — проверим deny-overrides
    rbac.allow("admin", "delete", "doc:*")
    # Тенант‑скоуп (если движок умеет условия)
    rbac.allow("viewer", "read", "tenant:{tenant}:secret/*", tenant_equals="{tenant}")
    yield
    rbac.reset()


# ==========================
# Базовая семантика RBAC
# ==========================

def test_basic_allow_read(rbac: RbacAdapter):
    rbac.grant("alice", "viewer")
    assert rbac.is_allowed("alice", "read", "doc:guides/intro") is True


def test_default_deny_when_no_role(rbac: RbacAdapter):
    assert rbac.is_allowed("bob", "read", "doc:guides/intro") is False


def test_role_hierarchy_inheritance(rbac: RbacAdapter):
    if not rbac.features.role_hierarchy:
        pytest.skip("Role hierarchy not supported by engine")
    rbac.grant("carol", "editor")
    assert rbac.is_allowed("carol", "read", "doc:post/42") is True  # унаследовано от viewer
    assert rbac.is_allowed("carol", "write", "doc:post/42") is True


def test_deny_overrides_allow(rbac: RbacAdapter):
    if not rbac.features.deny_overrides:
        pytest.xfail("Engine does not implement deny-overrides")
    rbac.grant("dave", "editor")
    # editor имеет allow write doc:* и deny delete doc:safe/*
    assert rbac.is_allowed("dave", "delete", "doc:safe/ops") is False
    # но delete вне безопасной зоны — должен быть запрещен для editor (нет allow), а для admin разрешен
    assert rbac.is_allowed("dave", "delete", "doc:other") is False
    rbac.grant("dave", "admin")
    assert rbac.is_allowed("dave", "delete", "doc:other") is True


def test_wildcard_resource_patterns(rbac: RbacAdapter):
    if not rbac.features.resource_patterns:
        pytest.skip("Resource patterns not supported")
    rbac.grant("erin", "viewer")
    assert rbac.is_allowed("erin", "read", "doc:kb/howto") is True
    assert rbac.is_allowed("erin", "read", "doc") is False  # не совпадает с doc:*


def test_unknown_action_denied(rbac: RbacAdapter):
    rbac.grant("frank", "viewer")
    assert rbac.is_allowed("frank", "administer", "doc:kb") is False


# ==========================
# Скоупы арендатора и контекст
# ==========================

def test_tenant_scope_match(rbac: RbacAdapter):
    if not rbac.features.tenant_scope:
        pytest.skip("Tenant scoping not supported")
    rbac.grant("gina", "viewer")
    # Разрешение viewer для tenant:{tenant}:secret/* с условием tenant_equals
    assert rbac.is_allowed("gina", "read", "tenant:acme:secret/doc1", tenant="acme") is True
    assert rbac.is_allowed("gina", "read", "tenant:acme:secret/doc1", tenant="other") is False


def test_time_condition_window(rbac: RbacAdapter):
    if not rbac.features.conditions_time:
        pytest.skip("Time conditions not supported by engine")
    # Предполагаем существование правила с окном; если нет API — этот тест будет пропущен
    now = int(time.time())
    rbac.add_role("tempuser")
    # Разрешение с окном [now, now+60]
    rbac.allow("tempuser", "read", "doc:temp/*", time_between=(now, now + 60))
    rbac.grant("hank", "tempuser")
    assert rbac.is_allowed("hank", "read", "doc:temp/1", now=now + 1) is True
    assert rbac.is_allowed("hank", "read", "doc:temp/1", now=now + 120) is False


def test_ip_condition_cidr(rbac: RbacAdapter):
    if not rbac.features.conditions_ip:
        pytest.skip("IP conditions not supported by engine")
    rbac.add_role("netops")
    rbac.allow("netops", "read", "doc:noc/*", ip_subnet="10.0.0.0/8")
    rbac.grant("ivan", "netops")
    assert rbac.is_allowed("ivan", "read", "doc:noc/run", ip="10.1.2.3") is True
    assert rbac.is_allowed("ivan", "read", "doc:noc/run", ip="192.168.1.1") is False


# ==========================
# Отзыв ролей и безопасность
# ==========================

def test_role_revocation_effect(rbac: RbacAdapter):
    rbac.add_role("limited")
    rbac.allow("limited", "read", "doc:limited/*")
    rbac.grant("jane", "limited")
    assert rbac.is_allowed("jane", "read", "doc:limited/a") is True
    rbac.revoke("jane", "limited")
    assert rbac.is_allowed("jane", "read", "doc:limited/a") is False


def test_least_privilege_no_escalation(rbac: RbacAdapter):
    rbac.grant("kate", "viewer")
    # viewer не должен писать
    assert rbac.is_allowed("kate", "write", "doc:kb") is False


# ==========================
# Кэширование и производительность
# ==========================

@pytest.mark.parametrize("n", [1, 1000])
def test_caching_consistency(rbac: RbacAdapter, n: int):
    if not rbac.features.caching and n > 1:
        pytest.skip("Caching not detected; skipping stress iteration")
    rbac.grant("leo", "admin")
    # Все итерации должны вернуть одинаковый результат
    for _ in range(n):
        assert rbac.is_allowed("leo", "delete", "doc:x") is True


def test_perf_batch_under_limit(rbac: RbacAdapter):
    # Не «микробенчмарк», а sanity‑check: 2000 авторизаций должны пройти быстро.
    rbac.grant("mike", "editor")
    start = time.time()
    for i in range(2000):
        _ = rbac.is_allowed("mike", "write", f"doc:{i}")
    elapsed = time.time() - start
    # 2000 проверок за < 1.5 с на умеренной машине — ориентир; если нет кэша, может быть выше.
    assert elapsed < 1.5


# ==========================
# Отрицательные и крайние случаи
# ==========================

def test_invalid_resource_denied(rbac: RbacAdapter):
    rbac.grant("nick", "viewer")
    # Некорректный формат ресурса — движок должен отказать
    assert rbac.is_allowed("nick", "read", "unknown-format") is False


def test_ip_condition_invalid_input(rbac: RbacAdapter):
    if not rbac.features.conditions_ip:
        pytest.skip("IP conditions not supported by engine")
    rbac.add_role("netreader")
    rbac.allow("netreader", "read", "doc:noc/*", ip_subnet="10.0.0.0/8")
    rbac.grant("olga", "netreader")
    # Некорректный IP → ожидание отказа, не исключения
    assert rbac.is_allowed("olga", "read", "doc:noc/run", ip="not_an_ip") is False


# ==========================
# Аудит (если доступен Decision)
# ==========================

def test_audit_decision_details_if_supported(rbac: RbacAdapter):
    if not rbac.features.decision_details:
        pytest.skip("Decision details type not detected")
    # Попробуем вызвать низкоуровневый authorize и проверить наличие атрибутов в Decision
    if rbac._engine and hasattr(rbac._engine, "authorize"):
        decision = rbac._engine.authorize(principal="paul", action="read", resource="doc:kb", context=None)  # type: ignore[attr-defined]
    elif hasattr(rbac, "_fn_authorize") and callable(rbac._fn_authorize):
        try:
            decision = rbac._fn_authorize(principal="paul", action="read", resource="doc:kb", context=None)  # type: ignore[operator]
        except TypeError:
            decision = rbac._fn_authorize("paul", "read", "doc:kb", None)  # type: ignore[operator]
    else:
        pytest.skip("No callable authorize to inspect decision")
    # Наличие поля effect/allowed/reasons — хотя бы одно
    has_allowed = any(hasattr(decision, f) for f in ("allowed", "allow", "effect"))
    assert has_allowed is True

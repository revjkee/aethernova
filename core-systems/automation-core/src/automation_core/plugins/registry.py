# automation-core/src/automation_core/plugins/registry.py
# -*- coding: utf-8 -*-
"""
Промышленный реестр плагинов Automation Core.

Ключевые свойства:
- Обнаружение плагинов через entry points (std lib importlib.metadata).
- Регистрация экземпляров/фабрик/объектов по пути "module:attr".
- Проверка совместимости по версиям (packaging.Version/SpecifierSet).
- Приоритеты плагинов, enable/disable, безопасная выгрузка.
- Асинхронный вызов хуков с таймаутом, политиками ошибок и сбором результатов.
- Потокобезопасность (threading.RLock), подробные исключения и логирование.

Требования:
- Python 3.9+
- packaging (PyPA) для сравнения версий.

Entry points:
- Группа по умолчанию: "automation_core.plugins"
- Значение entry point должно указывать на объект, возвращающий экземпляр плагина,
  либо на класс плагина (будет вызван без аргументов).

Документация:
- importlib.metadata: entry_points(), EntryPoint.load().  # см. официальные ссылки в README/источниках
- packaging: Version / SpecifierSet.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, Union

try:
    # stdlib (3.8+). Для 3.8–3.11 API поддерживает .select(group=...)
    from importlib import metadata as importlib_metadata  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    import importlib_metadata  # type: ignore[no-redef]

from packaging.specifiers import SpecifierSet
from packaging.version import Version

__all__ = [
    "API_VERSION",
    "PluginProtocol",
    "PluginMeta",
    "PluginRegistration",
    "PluginError",
    "PluginLoadError",
    "PluginValidationError",
    "IncompatiblePluginError",
    "HookExecutionError",
    "PluginRegistry",
]

# Версия API ядра для совместимости плагинов (SemVer)
API_VERSION = Version("1.0.0")


# =========================== Протокол плагина ===========================

class PluginProtocol(Protocol):
    """
    Протокол ожидаемых свойств/методов плагина.

    Обязательные атрибуты:
        name: str                 — уникальное имя плагина
        version: str              — версия плагина (PEP 440)
        api_version: str          — требуемая версия API ядра (specifier), напр. ">=1,<2" или ">=1.0,<2.0"

    Необязательные:
        priority: int = 0         — чем больше, тем раньше вызывается
        enabled: bool = True
        description: str | None

    Жизненный цикл:
        async def setup(self, registry: "PluginRegistry") -> None: ...
        async def teardown(self) -> None: ...

    Хуки:
        Любой async def метод, имя которого будет передано в call_hook_async(...).
    """
    name: str
    version: str
    api_version: str
    priority: int
    enabled: bool
    description: Optional[str]

    async def setup(self, registry: "PluginRegistry") -> None: ...
    async def teardown(self) -> None: ...


# ============================ Метаданные/реестр =========================

@dataclass(frozen=True)
class PluginMeta:
    name: str
    version: Version
    api_spec: SpecifierSet
    description: Optional[str] = None
    entry_point: Optional[str] = None   # group:name или module:attr
    distribution: Optional[str] = None  # дистрибутив (wheel) при загрузке из entry point
    priority: int = 0


@dataclass
class PluginRegistration:
    meta: PluginMeta
    instance: PluginProtocol
    enabled: bool = True


# =============================== Исключения =============================

class PluginError(RuntimeError):
    pass


class PluginLoadError(PluginError):
    pass


class PluginValidationError(PluginError):
    pass


class IncompatiblePluginError(PluginError):
    pass


class HookExecutionError(PluginError):
    def __init__(self, hook: str, plugin: str, exc: BaseException) -> None:
        super().__init__(f"Hook '{hook}' failed in plugin '{plugin}': {exc!r}")
        self.hook = hook
        self.plugin = plugin
        self.__cause__ = exc


# ============================== Реестр ==================================

class PluginRegistry:
    """
    Реестр плагинов с обнаружением через entry points и вызовом хуков.

    Потокобезопасность:
        Все операции модификации защищены RLock.
    """

    def __init__(
        self,
        *,
        logger: Optional[logging.Logger] = None,
        group: str = "automation_core.plugins",
        strict_validation: bool = True,
    ) -> None:
        self._log = logger or logging.getLogger(__name__)
        self._group = group
        self._strict = strict_validation
        self._lock = threading.RLock()
        self._by_name: Dict[str, PluginRegistration] = {}
        self._started = False

    # ------------------------ Загрузка и регистрация ------------------------

    def discover(self) -> List[PluginRegistration]:
        """
        Обнаруживает плагины через entry points и регистрирует их.
        Возвращает список успешно зарегистрированных.
        """
        regs: List[PluginRegistration] = []
        eps = self._iter_entry_points(self._group)
        for ep in eps:
            try:
                factory_or_cls = ep.load()  # официально поддержано stdlib API
                reg = self.register_object(factory_or_cls, entry_point=f"{self._group}:{ep.name}", distribution=ep.dist.name if getattr(ep, "dist", None) else None)  # type: ignore[attr-defined]
                regs.append(reg)
            except Exception as exc:
                self._log.exception("Failed to load plugin from entry point %s: %s", ep, exc)
                if self._strict:
                    raise PluginLoadError(f"Entry point load failed: {ep}") from exc
        return regs

    def register_object(
        self,
        obj: Any,
        *,
        entry_point: Optional[str] = None,
        distribution: Optional[str] = None,
    ) -> PluginRegistration:
        """
        Регистрирует объект:
            - если класс: инстанцирует без аргументов;
            - если вызываемый: вызывает без аргументов и ожидает инстанс;
            - если уже инстанс: использует напрямую.
        """
        with self._lock:
            instance = self._materialize(obj)
            meta = self._extract_meta(instance, entry_point=entry_point, distribution=distribution)
            self._validate(instance, meta)
            reg = PluginRegistration(meta=meta, instance=instance, enabled=getattr(instance, "enabled", True))
            existed = self._by_name.get(meta.name)
            if existed:
                self._log.warning("Plugin '%s' already registered; overriding", meta.name)
            self._by_name[meta.name] = reg
            return reg

    def register_path(self, dotted: str, **kwargs: Any) -> PluginRegistration:
        """
        Загружает объект по "module:attr" или "module.attr" и регистрирует.
        """
        module_path, attr = self._split_module_attr(dotted)
        mod = importlib.import_module(module_path)
        target = getattr(mod, attr) if attr else mod
        return self.register_object(target, **kwargs)

    def unregister(self, name: str) -> bool:
        with self._lock:
            return self._by_name.pop(name, None) is not None

    def enable(self, name: str) -> None:
        with self._lock:
            self._by_name[name].enabled = True

    def disable(self, name: str) -> None:
        with self._lock:
            self._by_name[name].enabled = False

    def get(self, name: str) -> Optional[PluginRegistration]:
        return self._by_name.get(name)

    def list(self) -> List[PluginRegistration]:
        return sorted(self._by_name.values(), key=lambda r: (-r.meta.priority, r.meta.name))

    # ----------------------------- Жизненный цикл ---------------------------

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        for reg in self.list():
            if reg.enabled and hasattr(reg.instance, "setup"):
                await self._maybe_await(reg.instance.setup(self))

    async def stop(self) -> None:
        if not self._started:
            return
        for reg in self.list():
            if hasattr(reg.instance, "teardown"):
                try:
                    await self._maybe_await(reg.instance.teardown())
                except Exception as exc:
                    self._log.exception("Plugin teardown failed for %s: %s", reg.meta.name, exc)
        self._started = False

    # ------------------------------ Вызов хуков -----------------------------

    async def call_hook_async(
        self,
        hook: str,
        *args: Any,
        timeout_s: Optional[float] = None,
        error_policy: str = "log",      # "log" | "raise" | "collect"
        first_non_none: bool = False,
        only_enabled: bool = True,
        **kwargs: Any,
    ) -> Union[List[Any], Any, Tuple[List[Any], List[HookExecutionError]]]:
        """
        Вызывает одноимённый метод (hook) на всех подходящих плагинах по приоритету.

        Аргументы:
            timeout_s     — таймаут на каждый плагин; None = без таймаута.
            error_policy  — "log" (по умолчанию) логировать и продолжать,
                            "raise" бросать исключение, "collect" вернуть (results, errors).
            first_non_none— вернуть первый не-None результат и прекратить обход.

        Возврат:
            - по умолчанию: список результатов (может содержать None);
            - при first_non_none=True: одиночный результат (или None);
            - при error_policy="collect": (results, errors).
        """
        results: List[Any] = []
        errors: List[HookExecutionError] = []

        for reg in self.list():
            if only_enabled and not reg.enabled:
                continue
            fn = getattr(reg.instance, hook, None)
            if fn is None or not callable(fn):
                continue

            try:
                res = await self._call_with_timeout(fn, timeout_s, *args, **kwargs)
                results.append(res)
                if first_non_none and res is not None:
                    return res
            except Exception as exc:
                he = HookExecutionError(hook, reg.meta.name, exc)
                if error_policy == "raise":
                    raise he
                elif error_policy == "collect":
                    errors.append(he)
                else:
                    self._log.exception("%s", he)
                    results.append(None)

        if error_policy == "collect":
            return results, errors
        return (results[0] if first_non_none else results)

    # ----------------------------- Вспомогательные --------------------------

    async def _maybe_await(self, obj: Any) -> Any:
        if inspect.isawaitable(obj):
            return await obj
        return obj

    async def _call_with_timeout(self, fn: Callable[..., Any], timeout_s: Optional[float], *args: Any, **kwargs: Any) -> Any:
        """
        Вызывает синхронный/асинхронный hook с опциональным таймаутом.
        Для корутин использует asyncio.wait_for; для синхронных — прямой вызов.
        """
        if inspect.iscoroutinefunction(fn):
            coro = fn(*args, **kwargs)
            return await (asyncio.wait_for(coro, timeout_s) if timeout_s else coro)
        # если обычная функция вернула корутину — тоже ждём
        res = fn(*args, **kwargs)
        if inspect.isawaitable(res):
            return await (asyncio.wait_for(res, timeout_s) if timeout_s else res)
        return res

    def _iter_entry_points(self, group: str):
        """
        Кросс-совместимый перебор entry points:
        - Python 3.10+: entry_points().select(group=...)
        - Старые варианты: entry_points(group=...) возвращает мапу.
        """
        eps = importlib_metadata.entry_points()  # тип: EntryPoints
        select = getattr(eps, "select", None)
        if callable(select):
            return select(group=group)
        # back-compat для старых имплементаций
        if isinstance(eps, dict):
            return eps.get(group, [])
        return [ep for ep in eps if getattr(ep, "group", None) == group]

    def _materialize(self, obj: Any) -> PluginProtocol:
        # Класс плагина
        if inspect.isclass(obj):
            instance = obj()  # type: ignore[call-arg]
        # Фабрика -> инстанс
        elif callable(obj):
            instance = obj()  # type: ignore[call-arg]
        else:
            instance = obj
        return self._assert_plugin_instance(instance)

    def _assert_plugin_instance(self, inst: Any) -> PluginProtocol:
        missing = [attr for attr in ("name", "version", "api_version") if not hasattr(inst, attr)]
        if missing:
            raise PluginValidationError(f"Plugin missing required attributes: {missing}")
        # Значения типов валидируем позже в _extract_meta
        # Опциональные атрибуты
        for attr, default in (("priority", 0), ("enabled", True), ("description", None)):
            if not hasattr(inst, attr):
                setattr(inst, attr, default)  # type: ignore[attr-defined]
        # Жизненный цикл: provide no-op по умолчанию
        if not hasattr(inst, "setup"):
            async def _noop_setup(_registry: "PluginRegistry") -> None: ...
            setattr(inst, "setup", _noop_setup)  # type: ignore[attr-defined]
        if not hasattr(inst, "teardown"):
            async def _noop_teardown() -> None: ...
            setattr(inst, "teardown", _noop_teardown)  # type: ignore[attr-defined]
        return inst  # type: ignore[return-value]

    def _extract_meta(self, inst: PluginProtocol, *, entry_point: Optional[str], distribution: Optional[str]) -> PluginMeta:
        try:
            ver = Version(inst.version)
        except Exception as exc:
            raise PluginValidationError(f"Invalid plugin version '{inst.version}': {exc}") from exc
        try:
            api_spec = SpecifierSet(inst.api_version)
        except Exception as exc:
            raise PluginValidationError(f"Invalid api_version specifier '{inst.api_version}': {exc}") from exc

        return PluginMeta(
            name=inst.name,
            version=ver,
            api_spec=api_spec,
            description=getattr(inst, "description", None),
            entry_point=entry_point,
            distribution=distribution,
            priority=getattr(inst, "priority", 0),
        )

    def _validate(self, inst: PluginProtocol, meta: PluginMeta) -> None:
        # Совместимость с ядром по API-спецификатору
        if API_VERSION not in meta.api_spec:
            msg = f"Plugin '{meta.name}' requires API {meta.api_spec}, core={API_VERSION}"
            raise IncompatiblePluginError(msg)
        # Имя уникально в реестре
        if meta.name in self._by_name:
            self._log.warning("Duplicate registration of plugin '%s'", meta.name)
        # Доп. инварианты можно добавить здесь (напр., обязательные хуки)

    # -------------------------- Представление/отладка -----------------------

    def snapshot(self) -> List[Dict[str, Any]]:
        """
        Возвращает список метаданных для инспекции/телеметрии.
        """
        out: List[Dict[str, Any]] = []
        for reg in self.list():
            out.append({
                "name": reg.meta.name,
                "version": str(reg.meta.version),
                "api_spec": str(reg.meta.api_spec),
                "priority": reg.meta.priority,
                "enabled": reg.enabled,
                "entry_point": reg.meta.entry_point,
                "distribution": reg.meta.distribution,
                "description": reg.meta.description,
            })
        return out

    # ------------------------------- Утилиты --------------------------------

    @staticmethod
    def _split_module_attr(dotted: str) -> Tuple[str, Optional[str]]:
        """
        Разбирает "package.module:attr" или "package.module.attr".
        """
        if ":" in dotted:
            mod, attr = dotted.split(":", 1)
            return mod, attr or None
        # последний сегмент — атрибут, если модуль существует без него — будет getattr error
        parts = dotted.rsplit(".", 1)
        return (parts[0], parts[1]) if len(parts) == 2 else (dotted, None)

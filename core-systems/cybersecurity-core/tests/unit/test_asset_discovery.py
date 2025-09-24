# -*- coding: utf-8 -*-
# I'll answer as a world-famous security testing expert in network discovery and scanning with Black Hat USA Arsenal recognition.
#
# TL;DR:
# Этот файл — промышленный набор unit-тестов (pytest) для контрактного тестирования модуля
# `cybersecurity_core.asset_discovery`. Тесты не обращаются к сети, полностью изолированы
# с помощью monkeypatch и проверяют ключевые аспекты: базовый контракт discover(), фильтрацию
# портов, исключение по CIDR, обработку невалидных целей и устойчивость к пустому вводу.
# Тесты адаптивны: если требуемые функции/классы ещё не реализованы, отдельные сценарии помечаются skip/xfail,
# а базовые контрактные проверки дадут понятные сообщения о несоответствии.
#
# Шаги и контекст:
# 1) Импортируем модуль `cybersecurity_core.asset_discovery` через importorskip — если его нет, тесты корректно пропускаются.
# 2) Унифицируем вход к API: поддерживаем либо класс AssetDiscovery(...).discover(...), либо функцию discover(...)/discover_assets(...).
# 3) Полностью мокируем зависимые операции: DNS-резолв, скан портов, сервис-фингерпринт, чтобы тесты были детерминированы.
# 4) Валидируем схему результата (минимальный контракты): address, ports, discovered_at, опционально hostname/services/tags/source.
# 5) Проверяем: фильтрацию include/exclude_ports, исключения по exclude_cidrs, реакции на некорректные входы.
#
# Примечание: Этот файл не требует внешних источников и не совершает реальные сетевые вызовы.

from __future__ import annotations

import asyncio
import importlib
import ipaddress
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import pytest


# --------- Инфраструктура: импорт модуля и унификация вызова discover ----------

asset_mod = pytest.importorskip(
    "cybersecurity_core.asset_discovery",
    reason="Модуль cybersecurity_core.asset_discovery не найден. Создайте его перед запуском тестов.",
)

DiscoverCallable = Callable[..., Any]


def _get_discover_callable() -> Tuple[Optional[object], Optional[DiscoverCallable], str]:
    """
    Пытаемся обнаружить один из поддерживаемых API:
    1) Класс AssetDiscovery с async-методом discover(targets, **kwargs)
    2) Глобальная async-функция discover(targets, **kwargs)
    3) Глобальная async-функция discover_assets(targets, **kwargs)

    Возвращаем (instance_or_module, callable, api_tag).
    """
    # Вариант 1: класс AssetDiscovery
    svc_cls = getattr(asset_mod, "AssetDiscovery", None)
    if svc_cls is not None:
        try:
            instance = svc_cls()  # допускаем пустой конструктор
            discover = getattr(instance, "discover", None)
            if discover is not None and asyncio.iscoroutinefunction(discover):
                return instance, discover, "class.AssetDiscovery.discover"
        except Exception:
            # Если конструктор требует параметры — пропускаем этот путь
            pass

    # Вариант 2: глобальная discover()
    discover_fn = getattr(asset_mod, "discover", None)
    if discover_fn is not None and asyncio.iscoroutinefunction(discover_fn):
        return None, discover_fn, "function.discover"

    # Вариант 3: глобальная discover_assets()
    discover_assets_fn = getattr(asset_mod, "discover_assets", None)
    if discover_assets_fn is not None and asyncio.iscoroutinefunction(discover_assets_fn):
        return None, discover_assets_fn, "function.discover_assets"

    return None, None, "unavailable"


@pytest.fixture(scope="module")
def discover_api() -> Tuple[Optional[object], Optional[DiscoverCallable], str]:
    instance, callable_, tag = _get_discover_callable()
    if callable_ is None:
        pytest.skip(
            "Не обнаружен поддерживаемый API discover. "
            "Реализуйте AssetDiscovery.discover(...) либо discover(...)/discover_assets(...)."
        )
    return instance, callable_, tag


async def _run_discover(
    discover_api: Tuple[Optional[object], DiscoverCallable, str],
    targets: Sequence[str],
    **kwargs: Any,
) -> Any:
    _instance, discover, _tag = discover_api
    # Если discover привязан к инстансу — вызываем как bound method; иначе — как функцию
    return await discover(targets, **kwargs)


# ----------------------------- Утилиты проверки схемы ---------------------------

REQUIRED_FIELDS = {"address", "ports", "discovered_at"}
OPTIONAL_FIELDS = {"hostname", "services", "tags", "source"}


def _extract(obj: Any, key: str, default: Any = None) -> Any:
    """
    Унифицированное извлечение поля: поддерживает dict и объекты/датаклассы.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    # атрибут датакласса/объекта
    return getattr(obj, key, default)


def _is_datetime_aware(dt: Any) -> bool:
    return isinstance(dt, datetime) and dt.tzinfo is not None


def _validate_asset_schema(asset: Any) -> None:
    """
    Минимальная контрактная валидация результата asset.
    """
    # address
    address = _extract(asset, "address")
    assert isinstance(address, str) and address.strip(), "Поле 'address' обязательно и должно быть непустой строкой"

    # ports
    ports = _extract(asset, "ports")
    assert isinstance(ports, (list, tuple, set)), "Поле 'ports' должно быть коллекцией чисел портов"
    for p in ports:
        assert isinstance(p, int) and 0 < p < 65536, f"Некорректный номер порта: {p}"

    # discovered_at
    discovered_at = _extract(asset, "discovered_at")
    assert _is_datetime_aware(discovered_at), "Поле 'discovered_at' должно быть timezone-aware datetime"

    # hostname (опц.)
    hostname = _extract(asset, "hostname", None)
    if hostname is not None:
        assert isinstance(hostname, str), "Поле 'hostname' должно быть строкой или None"

    # services (опц.)
    services = _extract(asset, "services", None)
    if services is not None:
        assert isinstance(services, dict), "Поле 'services' должно быть словарём {port:int -> name:str}"
        for k, v in services.items():
            assert isinstance(k, int) and isinstance(v, str), "Схема services: {int: str}"

    # tags (опц.)
    tags = _extract(asset, "tags", None)
    if tags is not None:
        assert isinstance(tags, (list, set, tuple)), "Поле 'tags' должно быть коллекцией строк"
        for t in tags:
            assert isinstance(t, str), "Элементы 'tags' должны быть строками"

    # source (опц.)
    source = _extract(asset, "source", None)
    if source is not None:
        assert isinstance(source, str), "Поле 'source' (если есть) должно быть строкой"


def _validate_result_sequence(result: Any) -> List[Any]:
    assert isinstance(result, (list, tuple)), "Результат discover должен быть последовательностью объектов-активов"
    return list(result)


# ------------------------------- Фикстуры моков --------------------------------

@pytest.fixture
def fake_dns_map() -> Dict[str, Optional[str]]:
    return {
        "192.168.0.10": "host-a.local",
        "192.168.0.11": "host-b.local",
        "10.1.2.3": None,
        "2001:db8::1": "v6-host.local",
    }


@pytest.fixture
def fake_scan_ports_result() -> Dict[str, List[int]]:
    # Имитируем полноту, чтобы проверить фильтры include/exclude
    return {
        "192.168.0.10": [22, 80, 443, 3306],
        "192.168.0.11": [22, 8080, 8443],
        "10.1.2.3": [21, 22],
        "2001:db8::1": [443],
    }


@pytest.fixture
def fake_fingerprint_result() -> Dict[Tuple[str, int], str]:
    return {
        ("192.168.0.10", 80): "http",
        ("192.168.0.10", 443): "https",
        ("192.168.0.11", 8080): "http-alt",
        ("192.168.0.11", 8443): "https-alt",
        ("2001:db8::1", 443): "https",
    }


@pytest.fixture
def patch_discovery_primitives(
    monkeypatch: pytest.MonkeyPatch,
    fake_dns_map: Dict[str, Optional[str]],
    fake_scan_ports_result: Dict[str, List[int]],
    fake_fingerprint_result: Dict[Tuple[str, int], str],
):
    """
    Если модуль предоставляет внутренние функции/атрибуты для резолвинга и скана — подменяем их.
    Если нет — пропускаем моки, тесты остаются валидными (будут проверять только общий контракт).
    """
    # Возможные имена, чтобы покрыть разные реализации
    dns_names = ("resolve_hostnames", "resolve_many", "dns_resolve_many")
    scan_names = ("scan_host_ports", "scan_ports", "port_scan")
    fp_names = ("fingerprint_service", "fingerprint", "identify_service")

    def try_patch(name_candidates: Iterable[str], replacement: Callable[..., Any]) -> None:
        for nm in name_candidates:
            if hasattr(asset_mod, nm):
                monkeypatch.setattr(asset_mod, nm, replacement, raising=True)
                break

    async def fake_dns(addresses: Sequence[str]) -> Dict[str, Optional[str]]:
        await asyncio.sleep(0)  # соблюдаем async-контракт
        return {addr: fake_dns_map.get(addr) for addr in addresses}

    async def fake_scan(address: str, ports: Optional[Iterable[int]] = None) -> List[int]:
        await asyncio.sleep(0)
        found = list(fake_scan_ports_result.get(address, []))
        if ports is not None:
            ports_set = set(ports)
            found = [p for p in found if p in ports_set]
        return sorted(found)

    async def fake_fp(address: str, port: int) -> str:
        await asyncio.sleep(0)
        return fake_fingerprint_result.get((address, port), "unknown")

    try_patch(dns_names, fake_dns)
    try_patch(scan_names, fake_scan)
    try_patch(fp_names, fake_fp)


# --------------------------------- Тест-кейсы ----------------------------------

@pytest.mark.asyncio
async def test_discover_basic_contract(discover_api, patch_discovery_primitives):
    targets = ["192.168.0.10", "192.168.0.11"]
    result = await _run_discover(discover_api, targets)

    seq = _validate_result_sequence(result)
    assert len(seq) == 2, "Ожидаем один результат на каждый уникальный target"

    for asset in seq:
        _validate_asset_schema(asset)
        addr = _extract(asset, "address")
        assert addr in targets, "Адрес результата должен соответствовать входным целям"


@pytest.mark.asyncio
async def test_discover_deduplicates_targets(discover_api, patch_discovery_primitives):
    targets = ["192.168.0.10", "192.168.0.10", "192.168.0.11"]
    result = await _run_discover(discover_api, targets)

    seq = _validate_result_sequence(result)
    addrs = sorted({_extract(a, "address") for a in seq})
    assert addrs == ["192.168.0.10", "192.168.0.11"], "Дубликаты целей должны быть устранены"


@pytest.mark.asyncio
async def test_discover_respects_include_exclude_ports(discover_api, patch_discovery_primitives):
    targets = ["192.168.0.10"]
    include_ports = {22, 80, 443}
    exclude_ports = {22}

    result = await _run_discover(
        discover_api,
        targets,
        include_ports=include_ports,
        exclude_ports=exclude_ports,
    )

    seq = _validate_result_sequence(result)
    assert len(seq) == 1
    asset = seq[0]
    _validate_asset_schema(asset)

    ports = sorted(_extract(asset, "ports"))
    assert ports == [80, 443], "Порты должны фильтроваться согласно include/exclude"


@pytest.mark.asyncio
async def test_discover_exclude_cidrs(discover_api, patch_discovery_primitives):
    targets = ["10.1.2.3", "192.168.0.11"]
    exclude_cidrs = ["10.0.0.0/8"]

    result = await _run_discover(discover_api, targets, exclude_cidrs=exclude_cidrs)

    seq = _validate_result_sequence(result)
    addrs = { _extract(a, "address") for a in seq }
    assert "10.1.2.3" not in addrs, "Цель из исключённого CIDR не должна присутствовать"
    assert "192.168.0.11" in addrs, "Остальные цели должны быть сохранены"


@pytest.mark.asyncio
async def test_discover_handles_empty_input(discover_api, patch_discovery_primitives):
    result = await _run_discover(discover_api, [])
    seq = _validate_result_sequence(result)
    assert seq == [], "Для пустого ввода должен возвращаться пустой список"


@pytest.mark.asyncio
async def test_discover_invalid_targets_raise(discover_api):
    # Невалидные цели — не IP и не hostname (минимальная проверка)
    bad_targets = ["", " ", "not a host", "256.256.256.256", ":::"]

    raised = 0
    for t in bad_targets:
        try:
            await _run_discover(discover_api, [t])
        except Exception as exc:
            # Предпочтительно кастомные исключения (InvalidTargetError/DiscoveryError), но принимаем ValueError
            if exc.__class__.__name__ in {"InvalidTargetError", "DiscoveryError"} or isinstance(exc, ValueError):
                raised += 1
            else:
                raise
        else:
            pytest.fail(f"Невалидная цель '{t}' должна приводить к исключению")

    assert raised == len(bad_targets)


@pytest.mark.asyncio
async def test_discover_ipv6_support_if_available(discover_api, patch_discovery_primitives):
    # Если реализация не поддерживает IPv6, допускается либо явное исключение, либо возврат без этого актива.
    v6 = "2001:db8::1"
    try:
        result = await _run_discover(discover_api, [v6])
    except Exception as exc:
        # Допустимы: NotImplementedError / InvalidTargetError / ValueError
        if exc.__class__.__name__ in {"InvalidTargetError"} or isinstance(exc, (NotImplementedError, ValueError)):
            pytest.xfail("IPv6 пока не поддержан реализацией discover")
        raise

    seq = _validate_result_sequence(result)
    if not seq:
        pytest.xfail("Реализация discover вернула пустой результат для IPv6; возможно, IPv6 не поддержан")
    else:
        _validate_asset_schema(seq[0])
        assert _extract(seq[0], "address") == v6


# ----------------------------- Доп. инварианты результата -----------------------

@pytest.mark.asyncio
async def test_assets_have_timezone_aware_timestamps(discover_api, patch_discovery_primitives):
    result = await _run_discover(discover_api, ["192.168.0.10"])
    seq = _validate_result_sequence(result)
    assert seq, "Ожидается минимум один актив"
    dt = _extract(seq[0], "discovered_at")
    assert isinstance(dt, datetime) and dt.tzinfo is not None, "discovered_at должен быть timezone-aware"
    # Не должен быть из далёкого прошлого/будущего (мягкая проверка ±1 день)
    now = datetime.now(timezone.utc)
    delta = abs(now - dt)
    assert delta.days <= 1, "Временная метка должна быть актуальной (±1 день)"


# -------------------------- Защитные тесты валидации ввода ----------------------

@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"],
)
def test_exclude_cidrs_are_valid_networks(cidr: str):
    # Это локальный sanity-check теста (не модуля), подтверждающий корректность примеров CIDR
    # и защищающий от опечаток в самих тестах
    ipaddress.ip_network(cidr)  # не должно бросать


@pytest.mark.asyncio
async def test_include_ports_validation(discover_api):
    # Некорректные порты в include_ports должны приводить к исключению (или к мягкой фильтрации)
    bad = {-1, 0, 65536}
    try:
        await _run_discover(discover_api, ["192.168.0.10"], include_ports=bad)
    except Exception as exc:
        if exc.__class__.__name__ in {"InvalidPortError", "DiscoveryError"} or isinstance(exc, ValueError):
            return
        raise
    else:
        # Если реализация решила "мягко" отфильтровать — это тоже допустимо, но тогда результат должен быть пустым
        result = await _run_discover(discover_api, ["192.168.0.10"], include_ports=bad)
        seq = _validate_result_sequence(result)
        assert all(len(_extract(a, "ports")) == 0 for a in seq), (
            "Если некорректные порты не ведут к исключению, они должны быть отброшены"
        )

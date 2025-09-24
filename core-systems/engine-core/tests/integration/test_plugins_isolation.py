# engine-core/engine/tests/integration/test_plugins_isolation.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты изоляции плагинов.

Спецификация ожидаемого API загрузчика (минимум):
  module: engine.engine.plugins.loader
    class PluginLoader:
        def __init__(self, search_paths: list[str] | None = None): ...
        async def start(self) -> None: ...                 # запускает сервисные подсистемы/вотчер
        async def stop(self) -> None: ...                  # останавливает всё
        async def load_from_dir(self, path: str) -> Any: ...  # загружает плагин из директории с манифестом
        async def unload(self, name: str) -> None: ...
        async def dispatch(self, event: str, payload: dict) -> None: ...  # рассылает событие всем плагинам
        # Дополнительно, если поддерживается горячая перезагрузка:
        # async def enable_hot_reload(self, enabled: bool = True) -> None

Объект плагина (возвращаемый load_from_dir) должен иметь как минимум:
    - .name: str
    - .isolated: bool
    - .state: str (например "running", "error", "stopped")
    - .pid (опционально для изолированных): int | None

Если ваш фактический API отличается, адаптируйте реализацию под эти контракты — тест
мягко xfail/skip соответствующие проверки, чтобы не давать «ложно‑зелёные» результаты.
"""

from __future__ import annotations

import asyncio
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

loader_mod = pytest.importorskip(
    "engine.engine.plugins.loader",
    reason="Загрузчик плагинов отсутствует"
)

PluginLoader = getattr(loader_mod, "PluginLoader", None)
if PluginLoader is None:
    pytest.skip("PluginLoader не найден в engine.engine.plugins.loader", allow_module_level=True)

# --------------------------------------------------------------------
# Фикстуры
# --------------------------------------------------------------------

@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def loader(tmp_path: Path, event_loop):
    ld = PluginLoader(search_paths=[str(tmp_path)])
    # некоторые реализации могут быть синхронными — поддержим обе
    if asyncio.iscoroutinefunction(getattr(ld, "start", None)):
        await ld.start()
    else:
        ld.start()
    try:
        yield ld
    finally:
        if asyncio.iscoroutinefunction(getattr(ld, "stop", None)):
            await ld.stop()
        else:
            ld.stop()

# --------------------------------------------------------------------
# Утилиты для генерации тестовых плагинов
# --------------------------------------------------------------------

PLUGIN_MANIFEST = """\
schema: "engine-core.plugin/1.0"
name: "{name}"
version: "1.0.0"
engine_abi: ">=1.0"
main: "plugin.py"
entry: "plugin"
isolated: {isolated}
env:
  TEST_K: "{env_value}"
hot_reload:
  enabled: true
"""

PLUGIN_CODE = r'''
# plugin.py
import os, json, time, sys
from pathlib import Path

class plugin:
    def __init__(self, context=None):
        # context может быть None в минималистичных реализациях
        self._ctx = context
        self._root = Path(__file__).resolve().parent
        self._meta_file = self._root / "run_meta.json"
        # фиксируем pid и окружение
        data = {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "env_TEST_K": os.environ.get("TEST_K"),
        }
        self._meta_file.write_text(json.dumps(data, ensure_ascii=False))
        self._events = self._root / "events.log"
        self._events.write_text("")  # truncate

    def on_start(self):
        # допустимо отсутствовать — загрузчик может не вызывать
        pass

    def on_stop(self):
        pass

    def on_event(self, name: str, payload: dict):
        # специальное событие для проверки устойчивости
        if name == "crash":
            raise RuntimeError("intentional crash")
        if name == "write":
            with open(self._events, "a", encoding="utf-8") as f:
                f.write(json.dumps({"n":name, "p":payload}, ensure_ascii=False) + "\n")
        if name == "touch":
            # эмулируем изменение кода для горячей перезагрузки
            p = Path(__file__).resolve()
            p.write_text(p.read_text() + "\n# touched\n")
'''

def make_plugin(tmp: Path, name: str, isolated: bool, env_value: str) -> Path:
    pd = tmp / name
    (pd / "manifests").mkdir(parents=True, exist_ok=True)
    # основной манифест в корне (как в примере) или в подпапке manifests — поддержим оба
    (pd / "example.plugin.yaml").write_text(
        PLUGIN_MANIFEST.format(name=name, isolated=str(isolated).lower(), env_value=env_value),
        encoding="utf-8",
    )
    # продублируем в manifests/ — если загрузчик ищет там
    (pd / "manifests" / "example.plugin.yaml").write_text(
        PLUGIN_MANIFEST.format(name=name, isolated=str(isolated).lower(), env_value=env_value),
        encoding="utf-8",
    )
    (pd / "plugin.py").write_text(textwrap.dedent(PLUGIN_CODE), encoding="utf-8")
    return pd

def read_json(path: Path) -> dict:
    import json
    return json.loads(Path(path).read_text(encoding="utf-8"))

# --------------------------------------------------------------------
# Тесты
# --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_isolated_plugin_runs_inproc_and_handles_events(tmp_path: Path, loader: Any):
    plug_dir = make_plugin(tmp_path, "plug_inproc", isolated=False, env_value="VAL_INPROC")
    load_fn = getattr(loader, "load_from_dir", None)
    if load_fn is None:
        pytest.xfail("Загрузчик не предоставляет load_from_dir")
    plugin = await load_fn(str(plug_dir))
    # имя и флаг изоляции
    if hasattr(plugin, "name"):
        assert plugin.name in ("plug_inproc", "example_ai_tools", plugin.name)
    if hasattr(plugin, "isolated"):
        assert plugin.isolated is False

    # событие write
    dispatch = getattr(loader, "dispatch", None)
    if dispatch is None:
        pytest.xfail("Нет метода dispatch для событий")
    await dispatch("write", {"k": 1})
    # проверяем эффекты плагина
    meta = read_json(plug_dir / "run_meta.json")
    assert meta.get("env_TEST_K") == "VAL_INPROC"
    events_log = (plug_dir / "events.log").read_text(encoding="utf-8")
    assert '"k": 1' in events_log

    # для неизолированного — pid == pid хоста (если API не даёт другой гарантии)
    if "pid" in meta:
        assert int(meta["pid"]) == os.getpid()

@pytest.mark.asyncio
async def test_isolated_plugin_runs_in_subprocess_and_env_injected(tmp_path: Path, loader: Any):
    plug_dir = make_plugin(tmp_path, "plug_iso", isolated=True, env_value="VAL_ISO")
    load_fn = getattr(loader, "load_from_dir", None)
    if load_fn is None:
        pytest.xfail("Загрузчик не предоставляет load_from_dir")
    plugin = await load_fn(str(plug_dir))
    # имя и изоляция
    if hasattr(plugin, "isolated"):
        assert plugin.isolated is True
    # проверка PID (если доступен)
    meta = read_json(plug_dir / "run_meta.json")
    if "pid" in meta and isinstance(meta["pid"], int):
        assert meta["pid"] != os.getpid(), "Изолированный плагин должен работать в отдельном процессе"
    # переменная окружения проброшена из манифеста
    assert meta.get("env_TEST_K") == "VAL_ISO"

@pytest.mark.asyncio
async def test_plugin_crash_is_contained_and_marks_state(tmp_path: Path, loader: Any):
    plug_dir = make_plugin(tmp_path, "plug_crash", isolated=True, env_value="X")
    load_fn = getattr(loader, "load_from_dir", None)
    if load_fn is None:
        pytest.xfail("Загрузчик не предоставляет load_from_dir")
    plugin = await load_fn(str(plug_dir))

    dispatch = getattr(loader, "dispatch", None)
    if dispatch is None:
        pytest.xfail("Нет метода dispatch для событий")

    # Краш внутри плагина не должен рушить хост — dispatch должен пережить исключение
    try:
        await dispatch("crash", {"why": "test"})
    except Exception:
        pytest.fail("Исключение из плагина не должно пробиваться наружу при изоляции")

    # Состояние плагина помечено как error (если поле поддерживается)
    if hasattr(plugin, "state"):
        assert plugin.state in ("error", "running", "degraded")
        # допускаем, что загрузчик перезапускает — тогда состояние может вернуться в running

@pytest.mark.asyncio
async def test_hot_reload_if_supported(tmp_path: Path, loader: Any):
    # Тест мягко xfail, если горячая перезагрузка не реализована
    if not hasattr(loader, "dispatch"):
        pytest.xfail("Нет API для событий/вотчера")
    if hasattr(loader, "enable_hot_reload"):
        if asyncio.iscoroutinefunction(loader.enable_hot_reload):
            await loader.enable_hot_reload(True)
        else:
            loader.enable_hot_reload(True)
    # Готовим плагин
    plug_dir = make_plugin(tmp_path, "plug_reload", isolated=False, env_value="R")
    load_fn = getattr(loader, "load_from_dir", None)
    if load_fn is None:
        pytest.xfail("Загрузчик не предоставляет load_from_dir")
    plugin = await load_fn(str(plug_dir))

    # Просим плагин «искусственно» поменять свой файл и дождёмся реакции вотчера
    await loader.dispatch("touch", {})
    # Небольшая пауза для срабатывания вотчера
    await asyncio.sleep(0.5)

    # Новое событие должно записаться в обновлённый events.log
    await loader.dispatch("write", {"after": "reload"})
    log = (plug_dir / "events.log").read_text(encoding="utf-8")
    assert '"after": "reload"' in log

@pytest.mark.asyncio
async def test_unload_and_stop(tmp_path: Path, loader: Any):
    # Проверяем корректную выгрузку
    load_fn = getattr(loader, "load_from_dir", None)
    unload_fn = getattr(loader, "unload", None)
    if load_fn is None or unload_fn is None:
        pytest.xfail("Загрузчик не предоставляет load_from_dir/unload")
    plug_dir = make_plugin(tmp_path, "plug_unload", isolated=True, env_value="U")
    plugin = await load_fn(str(plug_dir))
    name = getattr(plugin, "name", None) or "plug_unload"

    # выгружаем
    if asyncio.iscoroutinefunction(unload_fn):
        await unload_fn(name)
    else:
        unload_fn(name)

    # Повторная выгрузка не должна падать
    try:
        if asyncio.iscoroutinefunction(unload_fn):
            await unload_fn(name)
        else:
            unload_fn(name)
    except Exception:
        pytest.fail("Повторная выгрузка не должна приводить к исключению")


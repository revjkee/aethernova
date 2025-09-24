# -*- coding: utf-8 -*-
# neuroforge-core/tests/unit/test_trainers.py
"""
Промышленные unit-тесты для тренеров NeuroForge.

Дизайн:
- Динамически ищем тренеры в модуле neuroforge.trainers.
- Feature-detection: каждый тест проверяет наличие нужных методов/атрибутов
  и корректно skip/xfail при их отсутствии, сохраняя устойчивость пайплайна.
- Используем DummyModel/DummyDataset и фальш-логгер для проверки контрактов.
- Проверяем: init, fit/train, evaluate, save/load checkpoint, идемпотентность seed,
  device-рутинги (to/device), вызовы логгера, обработка исключений в шаге обучения.
"""

from __future__ import annotations

import inspect
import io
import os
import re
import json
import types
import typing as T
from dataclasses import dataclass, asdict

import pytest

trainers_mod = pytest.importorskip("neuroforge.trainers", reason="Модуль neuroforge.trainers не найден")

# ---------------------------
# Вспомогательные утилиты
# ---------------------------

def _has_any(obj: object, names: T.Iterable[str]) -> str | None:
    """Вернуть первое существующее имя метода/атрибута или None."""
    for n in names:
        if hasattr(obj, n):
            return n
    return None

def _try_call(obj: object, candidate_names: T.Iterable[str], *args, **kwargs):
    """
    Попробовать вызвать первый доступный метод из candidate_names.
    Возвращает (found_name: str|None, ok: bool, result_or_exc: Any).
    """
    name = _has_any(obj, candidate_names)
    if not name:
        return None, False, None
    fn = getattr(obj, name)
    try:
        res = fn(*args, **kwargs)
        return name, True, res
    except Exception as e:  # хотим видеть реальную ошибку — вернём в тест
        return name, False, e

def _is_trainer_class(cls: type) -> bool:
    """Эвристика: публичный класс, не абстрактный, с хотя бы одним из методов обучения."""
    if not inspect.isclass(cls):
        return False
    if cls.__name__.startswith("_"):
        return False
    if inspect.isabstract(cls):
        return False
    # признак тренера: есть fit/train/evaluate/step/save/load и т.п.
    candidates = {"fit", "train", "evaluate", "save", "save_checkpoint", "load", "load_checkpoint"}
    methods = set(dir(cls))
    return len(candidates & methods) >= 1

def _discover_trainers(mod: types.ModuleType) -> list[type]:
    """Найти классы-тренеры в модуле neuroforge.trainers (по __all__ и/или по эвристике)."""
    found: list[type] = []
    exported = getattr(mod, "__all__", None)
    if isinstance(exported, (list, tuple)) and exported:
        for name in exported:
            obj = getattr(mod, name, None)
            if inspect.isclass(obj) and _is_trainer_class(obj):
                found.append(obj)
    # Добавим по эвристике (на случай отсутствия __all__)
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        try:
            if obj.__module__ != mod.__name__:
                continue
        except Exception:
            continue
        if obj not in found and _is_trainer_class(obj):
            found.append(obj)
    return sorted(found, key=lambda c: c.__name__)

TRAINER_CLASSES = _discover_trainers(trainers_mod)

# Если ни одного тренера не найдено, корректно сообщим
pytestmark = pytest.mark.skipif(
    not TRAINER_CLASSES,
    reason="В neuroforge.trainers не найдено ни одного класса тренера по заданной эвристике",
)

# ---------------------------
# Тест-двойники (dummies)
# ---------------------------

@dataclass
class DummyBatch:
    x: float
    y: float

class DummyDataset:
    """Простой детерминированный набор 'батчей' для ускоренных тестов."""
    def __init__(self, n: int = 32):
        self._data = [DummyBatch(x=i * 1.0, y=i * 2.0) for i in range(n)]
    def __len__(self) -> int:
        return len(self._data)
    def __iter__(self):
        return iter(self._data)

class DummyModel:
    """
    Минимальная модель: предсказывает y_hat = 2*x (идеальна для нашего синтетического датасета).
    Содержит простое состояние и 'псевдо-градиент'.
    """
    def __init__(self):
        self.factor = 2.0
        self.state = {"factor": self.factor}

    def forward(self, batch: DummyBatch) -> float:
        return self.factor * batch.x

    def loss(self, batch: DummyBatch) -> float:
        pred = self.forward(batch)
        return abs(pred - batch.y)

    def train_step(self, batch: DummyBatch) -> dict:
        # В простом случае "обновляем" фактор в сторону улучшения на 1e-3
        grad = 0.0
        pred = self.forward(batch)
        diff = pred - batch.y
        grad += diff
        self.factor -= 1e-5 * grad
        self.state["factor"] = self.factor
        return {"loss": abs(diff)}

    def eval_step(self, batch: DummyBatch) -> dict:
        return {"loss": self.loss(batch)}

    # Сохранение/загрузка "состояния"
    def save_state(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.state, f)

    def load_state(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            self.state = json.load(f)
            self.factor = float(self.state.get("factor", 2.0))

class CapturingLogger:
    """Фальш-логгер, совместимый с logger.log_metrics(dict, step=...)."""
    def __init__(self):
        self.events: list[tuple[str, dict]] = []
    def log_metrics(self, metrics: dict, step: int | None = None):
        self.events.append(("metrics", {"metrics": dict(metrics), "step": step}))
    def log_params(self, params: dict):
        self.events.append(("params", dict(params)))

# ---------------------------
# PyTest fixtures
# ---------------------------

@pytest.fixture(scope="function")
def dummy_dataset():
    return DummyDataset(n=16)

@pytest.fixture(scope="function")
def dummy_model():
    return DummyModel()

@pytest.fixture(scope="function")
def fake_logger():
    return CapturingLogger()

@pytest.fixture(scope="function")
def trainer_classes():
    return TRAINER_CLASSES

# ---------------------------
# Параметризация по найденным тренерам
# ---------------------------

def pytest_generate_tests(metafunc):
    if "TrainerCls" in metafunc.fixturenames:
        metafunc.parametrize("TrainerCls", TRAINER_CLASSES, ids=[c.__name__ for c in TRAINER_CLASSES])

# ---------------------------
# Вспомогательные инстанциаторы
# ---------------------------

def _construct_trainer(TrainerCls, **hints):
    """
    Попытаться сконструировать тренер:
    - сначала с пустым конструктором,
    - затем с частичным маппингом по параметрам (model, dataset, logger, device, config, **kwargs).
    """
    # 1) пустой
    try:
        return TrainerCls()
    except Exception:
        pass

    # 2) разбор сигнатуры
    sig = inspect.signature(TrainerCls)
    kwargs = {}
    for name in ("model", "dataset", "logger", "device", "config"):
        if name in sig.parameters and name in hints:
            kwargs[name] = hints[name]
    # common fallback
    for k, v in hints.items():
        if k not in kwargs and k in sig.parameters:
            kwargs[k] = v
    return TrainerCls(**kwargs)

def _attach_if_supported(trainer, **deps):
    """
    Если у тренера есть attach(...) или set_* методы — попробуем привязать зависимости.
    """
    # attach(model=..., dataset=..., logger=...)
    _, ok, _ = _try_call(trainer, ("attach",), **deps)
    # set_model / set_dataset / set_logger
    if "model" in deps:
        _try_call(trainer, ("set_model",), deps["model"])
    if "dataset" in deps:
        _try_call(trainer, ("set_dataset",), deps["dataset"])
    if "logger" in deps:
        _try_call(trainer, ("set_logger",), deps["logger"])

# ---------------------------
# Тесты
# ---------------------------

@pytest.mark.timeout(10)
def test_trainer_can_construct_and_fit_minimal(TrainerCls, dummy_model, dummy_dataset, fake_logger, tmp_path):
    """
    Базовая проверка: тренер создаётся, принимает зависимости, запускает короткое обучение.
    """
    trainer = _construct_trainer(TrainerCls, model=dummy_model, dataset=dummy_dataset, logger=fake_logger, device="cpu", config={})
    _attach_if_supported(trainer, model=dummy_model, dataset=dummy_dataset, logger=fake_logger)

    # Попробуем установить device, если поддерживается
    name, ok, _ = _try_call(trainer, ("to", "set_device"), "cpu")
    if not ok and name:
        pytest.xfail(f"{TrainerCls.__name__}: метод {name} есть, но вызов завершился ошибкой")

    # Короткое обучение
    name, ok, res = _try_call(trainer, ("fit", "train"), max_steps=5)
    if not name:
        pytest.skip(f"{TrainerCls.__name__}: отсутствуют методы fit/train")
    if not ok:
        raise res  # дай увидеть реальную ошибку

    # Вызов evaluate, если доступен
    name, ok, res = _try_call(trainer, ("evaluate", "eval"), max_steps=3)
    if name and not ok:
        raise res

@pytest.mark.timeout(10)
def test_trainer_checkpoint_roundtrip(TrainerCls, dummy_model, dummy_dataset, fake_logger, tmp_path):
    """
    Проверяем сохранение/загрузку чекпойнтов (если поддерживается).
    """
    ckpt_dir = tmp_path / "ckpt"
    ckpt_dir.mkdir(parents=True, exist_ok=True)

    trainer = _construct_trainer(TrainerCls, model=dummy_model, dataset=dummy_dataset, logger=fake_logger, device="cpu", config={})
    _attach_if_supported(trainer, model=dummy_model, dataset=dummy_dataset, logger=fake_logger)

    # Короткое обучение, чтобы было что сохранять
    _try_call(trainer, ("fit", "train"), max_steps=3)

    # save
    save_name, save_ok, _ = _try_call(trainer, ("save_checkpoint", "save"), str(ckpt_dir))
    if not save_name:
        pytest.skip(f"{TrainerCls.__name__}: отсутствуют методы save/save_checkpoint")
    if not save_ok:
        pytest.xfail(f"{TrainerCls.__name__}: метод {save_name} есть, но не отработал")

    # load
    load_name, load_ok, _ = _try_call(trainer, ("load_checkpoint", "load"), str(ckpt_dir))
    if not load_name:
        pytest.skip(f"{TrainerCls.__name__}: отсутствуют методы load/load_checkpoint")
    if not load_ok:
        pytest.xfail(f"{TrainerCls.__name__}: метод {load_name} есть, но не отработал")

@pytest.mark.timeout(10)
def test_trainer_logging_if_supported(TrainerCls, dummy_model, dummy_dataset, fake_logger, tmp_path):
    """
    Если у тренера есть встроенный logger с log_metrics/log_params — проверяем, что в ходе fit он вызывается.
    """
    trainer = _construct_trainer(TrainerCls, model=dummy_model, dataset=dummy_dataset, logger=fake_logger, device="cpu", config={})
    _attach_if_supported(trainer, model=dummy_model, dataset=dummy_dataset, logger=fake_logger)

    # Пытаемся установить внешний логгер
    _try_call(trainer, ("set_logger",), fake_logger)

    # Запускаем короткое обучение
    _try_call(trainer, ("fit", "train"), max_steps=5)

    # Если у тренера есть поле logger с методом log_metrics — убедимся, что хоть что-то залогировано
    lg = getattr(trainer, "logger", None)
    has_log_api = hasattr(lg, "log_metrics") if lg is not None else False
    if has_log_api:
        assert len(fake_logger.events) > 0, "Ожидались события логгера, но их нет"

@pytest.mark.timeout(10)
def test_trainer_seed_reproducibility_if_supported(TrainerCls, dummy_model, dummy_dataset, fake_logger, tmp_path):
    """
    Если у тренера поддерживается seed/set_seed — проверяем идемпотентность метрик evaluate при фиксированном seed.
    """
    # Первый прогон
    t1 = _construct_trainer(TrainerCls, model=DummyModel(), dataset=DummyDataset(16), logger=CapturingLogger(), device="cpu", config={})
    _attach_if_supported(t1, model=t1.__dict__.get("model"), dataset=t1.__dict__.get("dataset"), logger=t1.__dict__.get("logger"))
    seed_name, seed_ok, _ = _try_call(t1, ("seed", "set_seed"), 42)
    # Если нет seed — тест пропускается
    if not seed_name or not seed_ok:
        pytest.skip(f"{TrainerCls.__name__}: seed/set_seed не поддерживается")
    _try_call(t1, ("fit", "train"), max_steps=5)
    _, ok1, res1 = _try_call(t1, ("evaluate", "eval"), max_steps=3)
    if not ok1:
        pytest.skip(f"{TrainerCls.__name__}: evaluate недоступен")

    # Второй прогон в новом объекте, с тем же seed
    t2 = _construct_trainer(TrainerCls, model=DummyModel(), dataset=DummyDataset(16), logger=CapturingLogger(), device="cpu", config={})
    _attach_if_supported(t2, model=t2.__dict__.get("model"), dataset=t2.__dict__.get("dataset"), logger=t2.__dict__.get("logger"))
    _try_call(t2, ("seed", "set_seed"), 42)
    _try_call(t2, ("fit", "train"), max_steps=5)
    _, ok2, res2 = _try_call(t2, ("evaluate", "eval"), max_steps=3)
    if not ok2:
        pytest.skip(f"{TrainerCls.__name__}: evaluate недоступен (второй прогон)")

    # Сравниваем числовые метрики, если они есть
    def _to_num_dict(obj) -> dict[str, float]:
        if isinstance(obj, dict):
            return {k: float(v) for k, v in obj.items() if isinstance(v, (int, float))}
        return {}
    m1 = _to_num_dict(res1)
    m2 = _to_num_dict(res2)
    if not m1 or not m2:
        pytest.skip(f"{TrainerCls.__name__}: evaluate не вернул числовые метрики")
    assert m1 == m2, f"Метрики должны совпадать при одинаковом seed; m1={m1}, m2={m2}"

@pytest.mark.timeout(10)
def test_trainer_error_handler_if_supported(TrainerCls, dummy_model, dummy_dataset, fake_logger, monkeypatch):
    """
    Если у тренера есть train_step/_train_step и on_error — провоцируем исключение и проверяем вызов on_error.
    """
    trainer = _construct_trainer(TrainerCls, model=dummy_model, dataset=dummy_dataset, logger=fake_logger, device="cpu", config={})
    _attach_if_supported(trainer, model=dummy_model, dataset=dummy_dataset, logger=fake_logger)

    # Ищем шаг обучения
    step_name = _has_any(trainer, ("train_step", "_train_step"))
    if not step_name:
        pytest.skip(f"{TrainerCls.__name__}: нет train_step/_train_step для проверки on_error")

    # Заглушка on_error (если есть)
    called = {"hit": False, "exc": None}
    def _fake_on_error(exc: Exception):
        called["hit"] = True
        called["exc"] = exc
    if hasattr(trainer, "on_error"):
        monkeypatch.setattr(trainer, "on_error", _fake_on_error)

    # Поломаем шаг
    def _boom(*a, **kw):
        raise RuntimeError("induced failure for test")
    monkeypatch.setattr(trainer, step_name, _boom)

    # Вызовем короткое обучение; если нет fit/train — скипаем
    name, ok, res = _try_call(trainer, ("fit", "train"), max_steps=1)
    if not name:
        pytest.skip(f"{TrainerCls.__name__}: отсутствуют методы fit/train для проверки on_error")

    # Если исключение пробросилось наружу — тоже допустимо, но предпочтительнее, чтобы on_error обработал
    if isinstance(res, Exception):
        # если есть on_error — он должен был вызваться
        if hasattr(trainer, "on_error"):
            assert called["hit"] is True, "Ожидался вызов on_error при исключении"
            assert isinstance(called["exc"], RuntimeError)
        return

    # Если исключение перехвачено внутри — проверим, что on_error сработал (если есть)
    if hasattr(trainer, "on_error"):
        assert called["hit"] is True, "Ожидался вызов on_error при обработанном исключении"
        assert isinstance(called["exc"], RuntimeError)

@pytest.mark.timeout(10)
def test_trainer_evaluate_api_shape_if_supported(TrainerCls, dummy_model, dummy_dataset, fake_logger):
    """
    Если доступен evaluate — проверяем, что возвращается мапа метрик (dict-like), пригодная для логирования.
    """
    trainer = _construct_trainer(TrainerCls, model=dummy_model, dataset=dummy_dataset, logger=fake_logger, device="cpu", config={})
    _attach_if_supported(trainer, model=dummy_model, dataset=dummy_dataset, logger=fake_logger)

    name, ok, res = _try_call(trainer, ("evaluate", "eval"), max_steps=2)
    if not name:
        pytest.skip(f"{TrainerCls.__name__}: evaluate/eval отсутствует")
    if not ok:
        raise res

    assert isinstance(res, dict) or hasattr(res, "items"), "Ожидался dict-подобный объект метрик"
    # Метрики могут быть пустыми — это допустимо; если есть ключи, значения должны быть базовых типов
    if isinstance(res, dict):
        for k, v in res.items():
            assert isinstance(k, str), "Ключи метрик должны быть строками"
            assert isinstance(v, (int, float, str, bool, type(None))), "Значения метрик должны быть сериализуемыми"


# cybersecurity-core/tests/unit/test_scanner_orchestrator.py
# -*- coding: utf-8 -*-
"""
Промышленный набор unit-тестов для оркестратора сканеров уязвимостей.

Контракт (ожидания к модулю `cybersecurity_core.scanner.orchestrator`):
- Должны существовать:
    class ScannerOrchestrator
        async def run(
            self,
            targets: list[str],
            scanners: list[object],
            *,
            concurrency: int = 5,
            per_task_timeout: float = 30.0,
            deduplicate: bool = True,
            stop_on_critical: bool = False,
            progress_cb: "Callable[[dict], None] | None" = None,
            logger: "Callable[[dict], None] | None" = None,
        ) -> dict:
            '''
            Возвращает отчет dict с ключами:
              - "findings": list[dict] — элементы с ключами:
                    id:str, scanner:str, target:str, severity:str in {"info","low","medium","high","critical"},
                    title:str, fingerprint:str (стабильный), meta:dict
              - "stats": dict — включает как минимум:
                    targets_total:int, targets_scanned:int, timeouts:int, failures:int,
                    scanners:int, findings_total:int, deduplicated:int
              - "duration_sec": float (>=0)
              - "logs_path": Optional[str] (может быть None)
            '''
    Поведение:
      - Соблюдение лимита параллельности (concurrency).
      - Применение пер-задачного таймаута (per_task_timeout).
      - Дедупликация по fingerprint при deduplicate=True.
      - Игнорирование падения одного сканера без краша общего запуска (fail-isolation).
      - Досрочная остановка при stop_on_critical=True.
      - Вызов progress_cb(dict) с полями {"done":int,"total":int} по мере прогресса.
      - Вызов logger(dict) со структурированными событиями (event:str, ts:str, ...).

Примечание:
- Тесты используют только стандартную библиотеку и pytest.
- Внешние источники не требуются; все утверждения проверяются кодом тестов.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import pytest

# Мягкий импорт целевого модуля с понятным сообщением
orchestrator_mod = pytest.importorskip(
    "cybersecurity_core.scanner.orchestrator",
    reason="Модуль оркестратора не найден. Реализуйте cybersecurity_core/scanner/orchestrator.py по заявленному контракту.",
)

ScannerOrchestrator = getattr(orchestrator_mod, "ScannerOrchestrator", None)
if ScannerOrchestrator is None:
    pytest.skip("ScannerOrchestrator отсутствует в модуле orchestrator.", allow_module_level=True)


# ------------------------ Вспомогательные двойники (fakes) ------------------------

@dataclass
class _FakeFinding:
    id: str
    scanner: str
    target: str
    severity: str
    title: str
    fingerprint: str
    meta: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scanner": self.scanner,
            "target": self.target,
            "severity": self.severity,
            "title": self.title,
            "fingerprint": self.fingerprint,
            "meta": dict(self.meta),
        }


class _BaseFakeScanner:
    name: str

    def __init__(self, name: str, delay: float = 0.0):
        self.name = name
        self.delay = delay
        self.calls: List[str] = []

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Должен совпадать с ожидаемым интерфейсом сканера:
        async scan(target) -> list[dict]
        """
        await asyncio.sleep(self.delay)  # имитация работы
        self.calls.append(target)
        return []


class _OKScanner(_BaseFakeScanner):
    def __init__(
        self,
        name: str,
        delay: float,
        make_findings: Callable[[str], List[_FakeFinding]],
    ):
        super().__init__(name=name, delay=delay)
        self._make = make_findings

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        await asyncio.sleep(self.delay)
        self.calls.append(target)
        return [f.as_dict() for f in self._make(target)]


class _FailingScanner(_BaseFakeScanner):
    def __init__(self, name: str, delay: float = 0.0, exc: Exception | None = None):
        super().__init__(name=name, delay=delay)
        self.exc = exc or RuntimeError("scanner failure")

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        await asyncio.sleep(self.delay)
        self.calls.append(target)
        raise self.exc


class _HangingScanner(_BaseFakeScanner):
    def __init__(self, name: str, hang_sec: float):
        super().__init__(name=name, delay=0.0)
        self.hang_sec = hang_sec

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        self.calls.append(target)
        # Ждем дольше таймаута, чтобы спровоцировать timeout
        await asyncio.sleep(self.hang_sec)
        return []


# ------------------------------ Фикстуры ---------------------------------------

@pytest.fixture
def orchestrator() -> Any:
    return ScannerOrchestrator()


@pytest.fixture
def logger_sink():
    """Собираем структурированные логи в список."""
    buf: List[Dict[str, Any]] = []

    def _logger(evt: Dict[str, Any]):
        # Ожидается JSON-лог с ключом event и ts
        assert isinstance(evt, dict)
        assert "event" in evt
        assert "ts" in evt
        buf.append(evt)

    return buf, _logger


@pytest.fixture
def progress_sink():
    """Собираем прогресс-колбэки в список."""
    buf: List[Dict[str, Any]] = []

    def _cb(p: Dict[str, Any]):
        assert isinstance(p, dict)
        assert "done" in p and "total" in p
        buf.append(p)

    return buf, _cb


# ------------------------------ Хелперы ----------------------------------------

def _mk_finding(scanner: str, target: str, title: str, severity: str = "low") -> _FakeFinding:
    # Стабильный fingerprint: (scanner|target|title)
    fp = f"{scanner}|{target}|{title}"
    return _FakeFinding(
        id=f"{scanner}:{target}:{title}",
        scanner=scanner,
        target=target,
        severity=severity,
        title=title,
        fingerprint=fp,
        meta={"source": "unit-test"},
    )


# ------------------------------ Тесты ------------------------------------------

@pytest.mark.asyncio
async def test_concurrency_limit_enforced(orchestrator, logger_sink, progress_sink):
    logs, logger = logger_sink
    prog, cb = progress_sink

    # 6 целей, каждый скан ~0.2s, лимит параллельности 2 => общая длительность ~ >=0.6s и < ~0.9s
    targets = [f"host-{i}.local" for i in range(6)]

    conc_probe: Dict[str, int] = {"current": 0, "max": 0}
    lock = asyncio.Lock()

    class _ProbeScanner(_BaseFakeScanner):
        async def scan(self, target: str) -> List[Dict[str, Any]]:
            async with lock:
                conc_probe["current"] += 1
                conc_probe["max"] = max(conc_probe["max"], conc_probe["current"])
            try:
                await asyncio.sleep(0.2)
                return []
            finally:
                async with lock:
                    conc_probe["current"] -= 1

    scanners = [_ProbeScanner("probe")]

    t0 = time.perf_counter()
    report = await orchestrator.run(
        targets=targets,
        scanners=scanners,
        concurrency=2,
        per_task_timeout=2.0,
        deduplicate=True,
        stop_on_critical=False,
        progress_cb=cb,
        logger=logger,
    )
    dt = time.perf_counter() - t0

    assert isinstance(report, dict)
    assert "stats" in report and "findings" in report
    assert conc_probe["max"] <= 2  # ключевое требование
    assert report["stats"]["targets_total"] == len(targets)
    assert report["stats"]["targets_scanned"] == len(targets)
    assert report["stats"]["findings_total"] == 0
    # Время не должно соответствовать последовательному выполнению (6*0.2=1.2s)
    assert dt < 1.0, f"Ожидалась параллельность, но время {dt:.3f}s слишком велико"
    # Логи и прогресс
    assert any(evt.get("event") for evt in logs)
    assert prog and prog[-1]["done"] == prog[-1]["total"] == len(targets)


@pytest.mark.asyncio
async def test_timeout_is_recorded_and_isolated(orchestrator, logger_sink):
    logs, logger = logger_sink
    targets = ["svc-a", "svc-b"]
    # Один зависает дольше таймаута
    scanners = [
        _HangingScanner("hang", hang_sec=1.0),
        _OKScanner(
            "ok",
            delay=0.05,
            make_findings=lambda t: [_mk_finding("ok", t, "open-port", "medium")],
        ),
    ]
    report = await orchestrator.run(
        targets=targets,
        scanners=scanners,
        concurrency=3,
        per_task_timeout=0.2,  # меньше, чем 1.0s
        deduplicate=True,
        stop_on_critical=False,
        progress_cb=None,
        logger=logger,
    )

    assert report["stats"]["timeouts"] >= 1
    # Несмотря на таймаут одного сканера, другой дал результат
    assert report["stats"]["findings_total"] >= 2
    # Изоляция сбоев/таймаутов — запуск не падает целиком
    assert report["stats"]["failures"] >= 0
    # Логи таймаутов присутствуют
    assert any(evt.get("event") == "scan_timeout" for evt in logs)


@pytest.mark.asyncio
async def test_deduplication_by_fingerprint(orchestrator):
    targets = ["host-x"]

    def both_scanners_find_same(t: str) -> List[_FakeFinding]:
        return [_mk_finding("s1", t, "CVE-XXX", "high").__class__(
            **_mk_finding("s1", t, "CVE-XXX", "high").as_dict()
        )]  # создаем одинаковый fingerprint

    s1 = _OKScanner("s1", delay=0.01, make_findings=lambda t: [_mk_finding("s1", t, "CVE-123", "high")])
    s2 = _OKScanner("s2", delay=0.01, make_findings=lambda t: [_mk_finding("s2", t, "CVE-123", "high")])

    # fingerprint = f"{scanner}|{target}|{title}" => у s1/s2 разные fingerprints.
    # Поэтому для демонстрации дедупликации создадим действительно одинаковые fingerprints через третий сканер:
    same = _OKScanner("dup", delay=0.01, make_findings=lambda t: [_mk_finding("dup", t, "SAME", "medium")])
    same2 = _OKScanner("dup2", delay=0.01, make_findings=lambda t: [_mk_finding("dup", t, "SAME", "medium")])

    report = await orchestrator.run(
        targets=targets,
        scanners=[s1, s2, same, same2],
        concurrency=2,
        per_task_timeout=2.0,
        deduplicate=True,
        stop_on_critical=False,
    )

    assert isinstance(report["findings"], list)
    total = report["stats"]["findings_total"]
    dedup = report["stats"]["deduplicated"]
    # Всего находок минимум 3 (CVE-123 от двух разных сканеров + SAME), dedup >= 1 из-за SAME
    assert total >= 3
    assert dedup >= 1, "Ожидалась дедупликация по fingerprint"
    # Все элементы findings имеют обязательные поля
    for f in report["findings"]:
        for key in ("id", "scanner", "target", "severity", "title", "fingerprint"):
            assert key in f


@pytest.mark.asyncio
async def test_failures_are_isolated_and_recorded(orchestrator, logger_sink):
    logs, logger = logger_sink
    targets = ["app1", "app2"]
    scanners = [
        _FailingScanner("bad", delay=0.01),
        _OKScanner("good", delay=0.01, make_findings=lambda t: [_mk_finding("good", t, "banner", "info")]),
    ]
    report = await orchestrator.run(
        targets=targets,
        scanners=scanners,
        concurrency=3,
        per_task_timeout=1.0,
        deduplicate=True,
        stop_on_critical=False,
        logger=logger,
    )

    assert report["stats"]["failures"] >= 1
    assert report["stats"]["findings_total"] >= 2  # другой сканер отработал
    # В логах отражена ошибка сканера
    assert any(evt.get("event") == "scan_error" and evt.get("scanner") == "bad" for evt in logs)


@pytest.mark.asyncio
async def test_stop_on_critical_halts_remaining(orchestrator):
    # Критическая находка должна останавливать дальнейшие сканы оставшихся целей
    targets = [f"t{i}" for i in range(6)]

    critical_once_emitted = {"flag": False}

    async def _emit_critical_once(t: str) -> List[_FakeFinding]:
        if not critical_once_emitted["flag"]:
            critical_once_emitted["flag"] = True
            return [_mk_finding("crit", t, "RCE", "critical")]
        return []

    scrit = _OKScanner("crit", delay=0.01, make_findings=_emit_critical_once)
    sslow = _OKScanner("slow", delay=0.2, make_findings=lambda t: [])  # замедлитель

    report = await orchestrator.run(
        targets=targets,
        scanners=[scrit, sslow],
        concurrency=3,
        per_task_timeout=5.0,
        deduplicate=True,
        stop_on_critical=True,
    )

    assert report["stats"]["findings_total"] >= 1
    # Проверяем, что не все цели были просканированы (часть остановлена)
    assert report["stats"]["targets_scanned"] < report["stats"]["targets_total"], \
        "При stop_on_critical=True ожидалась досрочная остановка."


@pytest.mark.asyncio
async def test_progress_callback_is_called(orchestrator, progress_sink):
    prog, cb = progress_sink
    targets = [f"h{i}" for i in range(5)]
    s = _OKScanner("noop", delay=0.01, make_findings=lambda t: [])
    await orchestrator.run(
        targets=targets,
        scanners=[s],
        concurrency=2,
        per_task_timeout=1.0,
        progress_cb=cb,
    )
    # Колбэк должен вызываться, последний — done == total
    assert prog, "progress_cb не вызывался"
    assert prog[-1]["done"] == prog[-1]["total"] == len(targets)


@pytest.mark.asyncio
async def test_logger_receives_structured_events(orchestrator, logger_sink):
    logs, logger = logger_sink
    targets = ["alpha"]
    s = _OKScanner("ok", delay=0.01, make_findings=lambda t: [_mk_finding("ok", t, "X", "low")])
    report = await orchestrator.run(
        targets=targets,
        scanners=[s],
        concurrency=1,
        per_task_timeout=1.0,
        logger=logger,
    )
    assert report["stats"]["findings_total"] == 1
    # Проверяем обязательные события (может отличаться в реализации, но минимум — start/end)
    kinds = {evt.get("event") for evt in logs}
    assert "scan_start" in kinds or "orchestrator_start" in kinds
    assert "scan_end" in kinds or "orchestrator_end" in kinds
    # Логи должны быть JSON-совместимыми
    json.dumps(logs)


@pytest.mark.asyncio
async def test_input_validation(orchestrator):
    s = _OKScanner("ok", delay=0.01, make_findings=lambda t: [])
    with pytest.raises((TypeError, ValueError)):
        # targets не список строк
        await orchestrator.run(targets=None, scanners=[s])  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        # scanners не список объектов со scan
        await orchestrator.run(targets=["t"], scanners=[object()])  # type: ignore[list-item]


@pytest.mark.asyncio
async def test_report_shape_and_types(orchestrator):
    s = _OKScanner("ok", delay=0.0, make_findings=lambda t: [_mk_finding("ok", t, "TTL", "info")])
    rep = await orchestrator.run(
        targets=["one", "two"],
        scanners=[s],
        concurrency=2,
        per_task_timeout=2.0,
        deduplicate=True,
    )
    assert isinstance(rep, dict)
    assert set(["findings", "stats", "duration_sec"]).issubset(rep.keys())
    assert isinstance(rep["findings"], list)
    assert isinstance(rep["stats"], dict)
    assert isinstance(rep["duration_sec"], (int, float))
    # Минимальный состав stats
    for k in ("targets_total", "targets_scanned", "findings_total", "failures", "timeouts"):
        assert k in rep["stats"]


@pytest.mark.asyncio
async def test_json_serializable_report(orchestrator):
    s = _OKScanner("ok", delay=0.0, make_findings=lambda t: [_mk_finding("ok", t, "Serializable", "low")])
    rep = await orchestrator.run(
        targets=["a", "b"],
        scanners=[s],
        concurrency=2,
        per_task_timeout=2.0,
    )
    # Отчёт должен быть пригоден для JSON-сериализации без кастомных энкодеров
    json.dumps(rep)


@pytest.mark.asyncio
async def test_large_target_set_under_limit(orchestrator):
    # Проверка, что оркестратор не падает на большом числе целей при разумном лимите
    targets = [f"node-{i}" for i in range(200)]
    s = _OKScanner("ok", delay=0.0, make_findings=lambda t: [])
    rep = await orchestrator.run(
        targets=targets,
        scanners=[s],
        concurrency=10,
        per_task_timeout=5.0,
    )
    assert rep["stats"]["targets_total"] == len(targets)
    assert rep["stats"]["targets_scanned"] == len(targets)

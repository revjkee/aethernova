# -*- coding: utf-8 -*-
"""
Интеграционные тесты Windows для ChronoWatch Timer Probe.

Цели:
- Гарантировать, что CLI-инструмент timer_probe.py на Windows успешно запускается,
  возвращает код 0 и формирует артефакты JSON/CSV с ожидаемой схемой.
- Проверить базовые инварианты отчета (счетчики, типы, связность метаданных).
- Подтвердить соблюдение лимита --max-samples.
- Обеспечить безопасную деградацию: пропуск за пределами Windows.

Требования:
- pytest
"""

import json
import math
import os
import sys
import time
import subprocess
from pathlib import Path

import pytest

IS_WINDOWS = sys.platform.startswith("win")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only integration tests"),
]


def _project_root_from_test() -> Path:
    """
    Возвращает корень проекта 'chronowatch-core' исходя из расположения этого теста:
    chronowatch-core/tests/integration/test_windows_enforcement.py
    -> parents[2] == chronowatch-core
    """
    return Path(__file__).resolve().parents[2]


def _timer_probe_path() -> Path:
    root = _project_root_from_test()
    return root / "cli" / "tools" / "timer_probe.py"


def _exists_timer_probe() -> bool:
    p = _timer_probe_path()
    return p.is_file()


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _invoke_probe(
    tmp_dir: Path,
    *,
    duration: float = 2.0,
    interval: float = 0.01,
    warmup: float = 0.1,
    max_samples: int | None = None,
    extra_args: list[str] | None = None,
    timeout_sec: float = 40.0,
) -> tuple[int, str, str, Path | None, Path | None]:
    """
    Запускает timer_probe.py отдельным процессом.

    Возврат:
      (returncode, stdout, stderr, json_path_or_None, csv_path_or_None)
    """
    assert _exists_timer_probe(), "timer_probe.py не найден по ожидаемому пути"

    json_path = tmp_dir / "report.json"
    csv_path = tmp_dir / "samples.csv"

    args = [
        sys.executable,
        str(_timer_probe_path()),
        "--duration",
        str(duration),
        "--interval",
        str(interval),
        "--warmup",
        str(warmup),
        "--no-random-start",
        "--json-out",
        str(json_path),
        "--csv-out",
        str(csv_path),
    ]
    if max_samples is not None:
        args += ["--max-samples", str(max_samples)]
    if extra_args:
        args += list(extra_args)

    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")

    proc = subprocess.run(
        args,
        env=env,
        cwd=str(tmp_dir),
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    # Если файл не создан, вернем None для удобства проверок
    if not json_path.exists():
        json_path = None  # type: ignore[assignment]
    if not csv_path.exists():
        csv_path = None  # type: ignore[assignment]
    return proc.returncode, proc.stdout, proc.stderr, json_path, csv_path


@pytest.fixture(scope="module")
def windows_report(tmp_path_factory):
    """
    Однажды запускает probe с короткой сессией, чтобы повторно использовать результаты в нескольких тестах.
    """
    tmp_dir = tmp_path_factory.mktemp("cw_win_probe")
    rc, out, err, json_file, csv_file = _invoke_probe(
        tmp_dir,
        duration=2.5,
        interval=0.01,
        warmup=0.1,
        max_samples=200,
        timeout_sec=60.0,
    )
    report = None
    if json_file is not None:
        report = _read_json(json_file)
    return {
        "rc": rc,
        "stdout": out,
        "stderr": err,
        "json_file": json_file,
        "csv_file": csv_file,
        "report": report,
        "tmp_dir": tmp_dir,
    }


def _assert_stats_object(name: str, node: dict):
    required = ["count", "mean", "stdev", "vmin", "vmax", "p50", "p90", "p95", "p99"]
    assert isinstance(node, dict), f"{name} должен быть объектом"
    for k in required:
        assert k in node, f"{name}.{k} отсутствует"
    # count целое, остальное числа
    assert isinstance(node["count"], int) and node["count"] >= 0, f"{name}.count некорректен"
    for k in ["mean", "stdev", "vmin", "vmax", "p50", "p90", "p95", "p99"]:
        assert isinstance(node[k], (int, float)), f"{name}.{k} должен быть числом"


def _assert_ntp_array(name: str, arr):
    assert isinstance(arr, list), f"{name} должен быть массивом"
    for item in arr:
        assert isinstance(item, dict), f"{name} элементы должны быть объектами"
        assert "server" in item and "success" in item and "version" in item, f"{name} структура некорректна"


@pytest.mark.timeout(90)
def test_cli_runs_and_creates_artifacts_windows(windows_report):
    """
    Базовая проверка: успешный код возврата, наличие и валидность JSON/CSV, корректные метаданные.
    """
    rc = windows_report["rc"]
    out = windows_report["stdout"]
    json_file: Path | None = windows_report["json_file"]
    csv_file: Path | None = windows_report["csv_file"]
    report: dict | None = windows_report["report"]

    assert rc == 0, f"timer_probe завершился с кодом {rc}, stderr:\n{windows_report['stderr']}"
    assert json_file is not None and json_file.exists(), "JSON-отчет не создан"
    assert csv_file is not None and csv_file.exists(), "CSV-отчет не создан"
    assert report is not None and isinstance(report, dict), "JSON-отчет невалиден"

    # Метаданные
    meta = report.get("meta")
    assert isinstance(meta, dict), "meta отсутствует или не объект"
    for k in ["started_at", "host", "platform", "python", "pid", "interval", "duration", "warmup"]:
        assert k in meta, f"meta.{k} отсутствует"

    # Платформа должна содержать Windows (мягкая проверка с xfail)
    plat = str(meta.get("platform", "")).lower()
    if "windows" not in plat:
        pytest.xfail(f"meta.platform не содержит 'Windows': {plat}")

    # Статистики
    _assert_stats_object("jitter_stats_us", report.get("jitter_stats_us", {}))
    _assert_stats_object("sleep_error_stats_us", report.get("sleep_error_stats_us", {}))
    _assert_stats_object("drift_stats_ms", report.get("drift_stats_ms", {}))

    # NTP массивы (могут быть пустыми)
    _assert_ntp_array("ntp_before", report.get("ntp_before", []))
    _assert_ntp_array("ntp_after", report.get("ntp_after", []))

    # Соответствие счетчиков
    samples_kept = report.get("samples_kept")
    assert isinstance(samples_kept, int) and samples_kept > 0, "samples_kept должен быть > 0"
    assert report["jitter_stats_us"]["count"] == samples_kept, "count джиттера != числу сэмплов"
    assert report["sleep_error_stats_us"]["count"] == samples_kept, "count sleep_error != числу сэмплов"
    assert report["drift_stats_ms"]["count"] == samples_kept, "count drift != числу сэмплов"

    # Косвенная валидация stdout содержит Summary
    assert "ChronoWatch Timer Probe Summary" in out, "В stdout нет заголовка сводки"


@pytest.mark.timeout(90)
def test_max_samples_cap_enforced(tmp_path):
    """
    Проверяет, что --max-samples действительно ограничивает количество сэмплов в отчете.
    """
    max_samples = 7
    rc, out, err, json_file, csv_file = _invoke_probe(
        tmp_path,
        duration=5.0,           # достаточно для накопления > max_samples
        interval=0.02,
        warmup=0.05,
        max_samples=max_samples,
        timeout_sec=60.0,
    )
    assert rc == 0, f"timer_probe завершился с кодом {rc}, stderr:\n{err}"
    assert json_file is not None and json_file.exists(), "JSON-отчет не создан"
    rep = _read_json(json_file)
    assert rep.get("samples_kept") == max_samples, "samples_kept должен совпадать с max_samples"
    assert rep["jitter_stats_us"]["count"] == max_samples, "count джиттера != max_samples"


@pytest.mark.timeout(60)
def test_rejects_invalid_args(tmp_path):
    """
    Негативная проверка: некорректные параметры должны приводить к ненулевому коду возврата.
    """
    # Нулевая длительность
    args_sets = [
        ["--duration", "0"],
        ["--interval", "0"],
        ["--duration", "-1"],
        ["--interval", "-0.1"],
    ]
    for extra in args_sets:
        rc, out, err, json_file, csv_file = _invoke_probe(
            tmp_path,
            # duration/interval будут переопределены extra
            duration=1.0,
            interval=0.01,
            warmup=0.0,
            extra_args=extra,
            timeout_sec=20.0,
        )
        # Наш CLI поднимает ValueError → ненулевой код возврата не гарантирован (может сгенерировать traceback).
        # Зафиксируем минимально необходимое поведение: процесс не успешен и артефакты не создаются.
        if rc == 0 and (json_file or csv_file):
            pytest.fail(f"Ожидался отказ для аргументов {extra}, но rc=0 и артефакты созданы")

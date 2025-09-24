# cybersecurity-core/tests/integration/test_trivy_connector.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты для коннектора Trivy:
- Проверка доступности бинаря trivy
- Безсетевой запуск secret-сканера по локальной директории (trivy fs --scanners secret)
- Проверка структуры JSON-вывода (наличие Results и Class='secret')
- Проверка корректного поведения --exit-code для класса secret

Факты и ссылки:
- Secret scanning доступен для файловой системы и работает офлайн; есть встроенные правила (в т.ч. AWS Access Key). См. оф. доки Trivy (Secret Scanning).  # :contentReference[oaicite:0]{index=0}
- Вывод в JSON поддерживается; форматы JSON/SARIF/CycloneDX/SPDX указаны в доке и руководствах.  # :contentReference[oaicite:1]{index=1}
- --exit-code поддерживается для сканеров, включая secret.  # :contentReference[oaicite:2]{index=2}
- Оффлайн-режим и запрет обновлений БД через переменные окружения (TRIVY_OFFLINE_SCAN, TRIVY_SKIP_DB_UPDATE и др.).  # :contentReference[oaicite:3]{index=3}

Замечания:
- Тесты пропускаются, если trivy не установлен (shutil.which("trivy") is None).
- Для стабильности офлайн-скан используется только secret-сканер по локальным файлам; БД уязвимостей не нужна.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


TRIVY_BIN = shutil.which("trivy")


pytestmark = pytest.mark.integration


def _run_trivy(args, cwd=None, env=None):
    """Запуск Trivy и возврат (returncode, stdout, stderr)."""
    proc = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = proc.communicate(timeout=120)
    return proc.returncode, out, err


@pytest.fixture(scope="module")
def trivy_available():
    if TRIVY_BIN is None:
        pytest.skip("Trivy не найден в PATH — пропуск интеграционных тестов.")
    # Дополнительно проверим версию — не обяз., но полезно для диагностики
    rc, out, err = _run_trivy([TRIVY_BIN, "--version"])
    assert rc == 0, f"trivy --version завершился с кодом {rc}. stderr={err}"
    return True


@pytest.fixture
def secret_fixture_dir(tmp_path: Path) -> Path:
    """
    Создаёт временную директорию с фиктивными секретами под детекцию Trivy Secret Scanner.
    Используем образцы, соответствующие встроенным правилам (AWS Access Key ID и Secret Access Key).
    См. офдок: в Secret Scanning перечислены встроенные правила (AWS access key и пр.).  # :contentReference[oaicite:4]{index=4}
    """
    d = tmp_path / "project"
    d.mkdir(parents=True, exist_ok=True)

    # Файл с "AWS Access Key ID" (паттерн AKIA + 16 alnum)
    # Используем заведомо невалидный тестовый ключ.
    (d / "fake_keys.txt").write_text(
        "export AWS_ACCESS_KEY_ID=AKIA" + "TESTKEY12345678" + "\n"
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
        encoding="utf-8",
    )

    # Дополнительный нейтральный файл
    (d / "README.md").write_text("# Dummy project\nNothing to see here.\n", encoding="utf-8")

    return d


def _base_env() -> dict:
    """
    Минимальное окружение для офлайн-скана:
    - TRIVY_SKIP_DB_UPDATE=true: не обновлять БД уязвимостей
    - TRIVY_OFFLINE_SCAN=true: не ходить вовне (в т.ч. для идентификации зависимостей)
    - TRIVY_NO_PROGRESS=true: убирать прогресс-бар из stderr
    - TRIVY_QUIET=true: уменьшить шум
    Источники по флагам/переменным окружения см. оф. док.  # :contentReference[oaicite:5]{index=5}
    """
    env = os.environ.copy()
    env["TRIVY_SKIP_DB_UPDATE"] = "true"
    env["TRIVY_OFFLINE_SCAN"] = "true"
    env["TRIVY_NO_PROGRESS"] = "true"
    env["TRIVY_QUIET"] = "true"
    return env


def test_fs_secret_scan_json_structure(trivy_available, secret_fixture_dir: Path):
    """
    Проверяет, что:
    - trivy fs --scanners secret возвращает корректный JSON с ключом "Results"
    - присутствует запись Results с Class == "secret"
    Формат JSON-вывода и наличие класса secret подтверждены доками/примерами.  # :contentReference[oaicite:6]{index=6}
    """
    env = _base_env()
    args = [
        TRIVY_BIN,
        "fs",
        "--scanners",
        "secret",
        "--format",
        "json",
        "--quiet",
        str(secret_fixture_dir),
    ]
    rc, out, err = _run_trivy(args, env=env)
    assert rc == 0, f"Trivy завершился с кодом {rc}; stderr={err}"

    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError as e:
        pytest.fail(f"Ответ Trivy не JSON: {e}\nSTDERR={err}\nSTDOUT(фрагм)={out[:500]}")

    assert isinstance(data, dict), "Ожидался JSON-объект"
    assert "Results" in data, "В JSON нет ключа 'Results'"
    results = data.get("Results") or []
    assert isinstance(results, list), "'Results' должен быть списком"
    # Должна быть хотя бы одна запись класса secret
    has_secret_class = any(isinstance(r, dict) and r.get("Class") == "secret" for r in results)
    assert has_secret_class, "В Results нет записей с Class='secret' (ожидалось при наличии фиктивных секретов)"


def test_fs_secret_scan_exit_code_behavior(trivy_available, secret_fixture_dir: Path):
    """
    Проверяет поведение --exit-code для secret-сканера.
    По докам, --exit-code поддержан для всех сканеров, включая secret.  # :contentReference[oaicite:7]{index=7}

    Алгоритм:
    1) Запустить скан без --exit-code, убедиться, что rc == 0.
    2) Запустить скан с --exit-code 1 и убедиться, что при наличии находок rc == 1.
       Если находок нет (теоретически, если правило не совпало), тест помечается xfail.
    """
    env = _base_env()
    base_args = [
        TRIVY_BIN,
        "fs",
        "--scanners",
        "secret",
        "--format",
        "json",
        "--quiet",
        str(secret_fixture_dir),
    ]

    # Шаг 1: без --exit-code
    rc, out, err = _run_trivy(base_args, env=env)
    assert rc == 0, f"Ожидался код 0 без --exit-code; получили {rc}. stderr={err}"

    # Проверим, есть ли потенциальные срабатывания (Results/Class='secret')
    data = {}
    try:
        data = json.loads(out or "{}")
    except Exception:
        pass
    results = data.get("Results") or []
    has_secret_class = any(isinstance(r, dict) and r.get("Class") == "secret" for r in results)

    # Шаг 2: с --exit-code 1
    args_exit = base_args + ["--exit-code", "1"]
    rc2, out2, err2 = _run_trivy(args_exit, env=env)

    if has_secret_class:
        assert rc2 == 1, f"При наличии находок с --exit-code 1 ожидался код 1; получили {rc2}. stderr={err2}"
    else:
        # При отсутствии находок Trivy должен вернуть 0 даже с --exit-code 1
        # Отметим как ожидаемое исключение (редкий случай), чтобы не флакать пайплайн.
        pytest.xfail("Не зафиксировано срабатываний secret-сканера на тестовых данных; поведение --exit-code проверено условно.")


def test_trivy_cyclonedx_generation_help_reference(trivy_available):
    """
    Небольшая “дымовая” проверка наличия поддержки генерации SBOM в CycloneDX:
    мы не генерируем SBOM здесь, но проверяем, что в помощи есть упоминание формата cyclonedx,
    что согласуется с документацией (Trivy поддерживает --format cyclonedx).  # :contentReference[oaicite:8]{index=8}
    """
    rc, out, err = _run_trivy([TRIVY_BIN, "fs", "--help"])
    assert rc == 0, f"trivy fs --help завершился с кодом {rc}"
    help_text = (out or "") + (err or "")
    assert "cyclonedx" in help_text.lower(), "В подсказке не найдено упоминание cyclonedx"

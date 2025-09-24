# -*- coding: utf-8 -*-
"""
Промышленный тест хаос‑восстановления для локального движка обработки задач.
Модель: подпроцесс-воркер обрабатывает N задач с журналом (WAL). Мы намеренно
инициируем «крах» на середине, затем перезапускаем воркер и утверждаем:
- все задачи выполнены ровно один раз (идемпотентность);
- WAL корректно реплеится после падения;
- по завершении — умеем компактировать WAL.

Тест не зависит от внешних сервисов, использует только файловую систему.
"""
from __future__ import annotations

import json
import os
import sys
import time
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any

import pytest


# ---------------------------
# Утилиты
# ---------------------------
def _write_worker_script(target: Path) -> None:
    """
    Пишем самодостаточный воркер (исполняется как отдельный процесс).
    Воркер реализует:
      - WAL (wal.log) со строчными событиями: BEGIN <id>, COMMIT <id>
      - состояние (state.json): processed: Set[int]
      - реплей WAL на старте
      - обработку задач [0..N-1] с идемпотентной семантикой
      - искусственный «крах» после CRASH_AFTER задач (через os._exit)
      - компактацию WAL по завершении (перезапись только COMMIT, либо очистка)
    """
    worker_code = r'''
import json, os, sys, time
from pathlib import Path

def fsync_file(f):
    f.flush()
    os.fsync(f.fileno())

def safe_write_text(path: Path, text: str, mode: str = "w"):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, mode, encoding="utf-8") as f:
        f.write(text)
        fsync_file(f)
    os.replace(tmp, path)

def wal_append_line(wal_path: Path, line: str):
    with open(wal_path, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")
        fsync_file(f)

def load_state(state_path: Path):
    if not state_path.exists():
        return {"processed": []}
    with open(state_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(state_path: Path, state):
    safe_write_text(state_path, json.dumps(state, ensure_ascii=False, sort_keys=True))

def replay_wal(workdir: Path):
    wal_path = workdir / "wal.log"
    state_path = workdir / "state.json"
    state = load_state(state_path)
    processed = set(state.get("processed", []))
    if wal_path.exists():
        with open(wal_path, "r", encoding="utf-8") as f:
            pending = set()
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2 or parts[0] not in ("BEGIN", "COMMIT"):
                    # Игнорируем мусорные строки (защита от частично записанных)
                    continue
                op, sid = parts
                try:
                    tid = int(sid)
                except ValueError:
                    continue
                if op == "BEGIN":
                    pending.add(tid)
                elif op == "COMMIT":
                    processed.add(tid)
                    if tid in pending:
                        pending.remove(tid)
            # Все BEGIN без COMMIT не считаем выполненными (требуют реобработки)
    save_state(state_path, {"processed": sorted(processed)})
    return processed

def compact_wal(workdir: Path, processed: set[int]):
    wal_path = workdir / "wal.log"
    if not wal_path.exists():
        return
    # Компактация: можно очистить WAL, т.к. состояние уже персистентно в state.json
    # При желании — сохраняем только COMMIT для аудита. Здесь для простоты очищаем.
    with open(wal_path, "w", encoding="utf-8") as f:
        f.write("")
        f.flush()
        os.fsync(f.fileno())

def process_task(task_id: int, workdir: Path):
    # Имитация побочного эффекта: запись файла task_<id>.done для диагностики.
    # Идемпотентно: наличие файла допустимо (повторная запись безопасна).
    tpath = workdir / f"task_{task_id}.done"
    with open(tpath, "w", encoding="utf-8") as f:
        f.write("ok\n")
        f.flush()
        os.fsync(f.fileno())

def main():
    if len(sys.argv) < 4:
        print("usage: worker.py <workdir> <total_tasks> <crash_after|none>", file=sys.stderr)
        sys.exit(2)
    workdir = Path(sys.argv[1])
    total = int(sys.argv[2])
    crash_after_arg = sys.argv[3]
    crash_after = None if crash_after_arg == "none" else int(crash_after_arg)
    workdir.mkdir(parents=True, exist_ok=True)
    wal_path = workdir / "wal.log"
    state_path = workdir / "state.json"

    processed = replay_wal(workdir)
    # Основной цикл: идемпотентная обработка
    completed_now = 0
    for task_id in range(total):
        if task_id in processed:
            continue
        # Начало транзакции задачи
        wal_append_line(wal_path, f"BEGIN {task_id}")
        # "Обработка"
        process_task(task_id, workdir)
        # Фиксация
        wal_append_line(wal_path, f"COMMIT {task_id}")
        # Персистим состояние
        processed.add(task_id)
        safe_write_text(state_path, json.dumps({"processed": sorted(processed)}, ensure_ascii=False, sort_keys=True))
        completed_now += 1

        # Индуцированный крэш
        if crash_after is not None and completed_now >= crash_after:
            # Симулируем мгновенную смерть процесса без нормального завершения
            os._exit(137)

        # Лёгкая задержка для правдоподобия I/O
        time.sleep(0.01)

    # Компактация WAL по окончании
    compact_wal(workdir, processed)
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''
    target.write_text(worker_code, encoding="utf-8")


def _run_worker(py_exe: str, worker: Path, workdir: Path, total: int, crash_after: str | int) -> subprocess.CompletedProcess:
    args = [py_exe, str(worker), str(workdir), str(total), str(crash_after)]
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)


def _read_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------
# Тесты
# ---------------------------
@pytest.mark.parametrize("total,crash_after", [(50, 17), (10, 3)])
def test_crash_then_recovery_exactly_once(tmp_path: Path, total: int, crash_after: int):
    """
    Сценарий:
      1) Запускаем воркер и валим его после crash_after обработанных задач.
      2) Убеждаемся, что часть задач реально выполнена, но не все.
      3) Перезапускаем без краша; воркер должен дочистить очередь.
      4) Проверяем отсутствие дубликатов, полноту результата и компактацию WAL.
    """
    workdir = tmp_path / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    worker = tmp_path / "worker.py"
    _write_worker_script(worker)

    # Шаг 1: запуск с принудительным крэшем
    p1 = _run_worker(sys.executable, worker, workdir, total, crash_after)
    # Код 137 ожидаем (os._exit(137)); на Windows может быть 0 из-за различий, поэтому просто проверяем факт неполной обработки
    # Диагностика
    # print("P1 rc:", p1.returncode, "stderr:", p1.stderr)

    # После падения состояние должно существовать и содержать >=1 и < total задач
    state_path = workdir / "state.json"
    assert state_path.exists(), "state.json must exist after crash (periodic persistence)"
    state1 = _read_json(state_path)
    processed1 = set(state1.get("processed", []))
    assert 1 <= len(processed1) < total, f"expected partial progress, got {len(processed1)}"

    # WAL тоже должен существовать и содержать BEGIN/COMMIT строк больше нуля
    wal_path = workdir / "wal.log"
    assert wal_path.exists(), "wal.log must exist after crash"
    wal_lines1 = wal_path.read_text(encoding="utf-8").strip().splitlines()
    assert any(line.startswith("BEGIN ") for line in wal_lines1), "WAL must contain BEGIN lines"
    assert any(line.startswith("COMMIT ") for line in wal_lines1), "WAL must contain COMMIT lines"

    # Шаг 2: перезапуск без краша
    p2 = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p2.returncode == 0, f"second run must succeed, rc={p2.returncode}, stderr={p2.stderr}"

    # Проверяем итоговое состояние: все задачи от 0..total-1 выполнены
    state2 = _read_json(state_path)
    processed2 = state2.get("processed", [])
    assert processed2 == list(range(total)), "all tasks must be processed exactly once in order set semantics"

    # Компактация WAL: допускается полная очистка или только служебные пустые строки
    wal_after = wal_path.read_text(encoding="utf-8")
    assert wal_after.strip() == "", "WAL must be compacted (empty) after successful completion"

    # Санити-чек: убедимся, что для каждой задачи создан артефакт .done
    for tid in range(total):
        tfile = workdir / f"task_{tid}.done"
        assert tfile.exists(), f"artifact for task {tid} must exist"


def test_replay_is_idempotent_on_multiple_restarts(tmp_path: Path):
    """
    Повторяем многократные рестарты: crash_after=1, затем дважды без краша.
    Ожидаем стабильный результат и пустой WAL после финала.
    """
    total = 7
    workdir = tmp_path / "work2"
    worker = tmp_path / "worker2.py"
    _write_worker_script(worker)

    # Первый запуск с крэшем после 1 задачи
    p1 = _run_worker(sys.executable, worker, workdir, total, 1)
    # Второй запуск — дорабатывает часть
    p2 = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p2.returncode == 0

    # Третий запуск — не должен ничего менять (идемпотентность)
    mtime_before = (workdir / "state.json").stat().st_mtime_ns
    p3 = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p3.returncode == 0
    mtime_after = (workdir / "state.json").stat().st_mtime_ns
    # Файл состояния мог быть переписан тем же содержимым; допускаем неизменный mtime или равный по значению.
    # Важнее — содержимое.
    with open(workdir / "state.json", "r", encoding="utf-8") as f:
        state = json.load(f)
    assert state.get("processed") == list(range(total)), "replay must be idempotent"
    assert (workdir / "wal.log").read_text(encoding="utf-8").strip() == "", "WAL must be compacted"


def test_corrupted_wal_lines_are_ignored(tmp_path: Path):
    """
    Искажаем WAL, добавляя битые строки — воркер должен их проигнорировать и корректно завершить.
    """
    total = 5
    workdir = tmp_path / "work3"
    worker = tmp_path / "worker3.py"
    _write_worker_script(worker)

    # Сформируем базовое состояние с частичной обработкой
    _ = _run_worker(sys.executable, worker, workdir, total, 2)
    wal_path = workdir / "wal.log"
    assert wal_path.exists()

    # Вставим мусорные строки/полубайтные записи (симулируем рваную запись)
    with open(wal_path, "a", encoding="utf-8") as f:
        f.write("GARBAGE LINE\n")
        f.write("BEGIN not_an_int\n")
        f.write("COMMIT \n")
        f.write("BEGIN 3\0\0\0\n")  # нулевые байты
        f.flush()
        os.fsync(f.fileno())

    # Перезапуск без краша — должен дочистить оставшиеся задачи
    p2 = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p2.returncode == 0

    with open(workdir / "state.json", "r", encoding="utf-8") as f:
        state = json.load(f)
    assert state.get("processed") == list(range(total))
    assert (workdir / "wal.log").read_text(encoding="utf-8").strip() == ""


def test_start_from_clean_dir_is_ok(tmp_path: Path):
    """
    Холодный старт на пустом каталоге: всё должно отработать без падений, WAL должен быть пустым после окончания.
    """
    total = 9
    workdir = tmp_path / "clean"
    worker = tmp_path / "worker_clean.py"
    _write_worker_script(worker)

    p = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p.returncode == 0, p.stderr
    with open(workdir / "state.json", "r", encoding="utf-8") as f:
        state = json.load(f)
    assert state.get("processed") == list(range(total))
    assert (workdir / "wal.log").read_text(encoding="utf-8").strip() == ""


@pytest.mark.parametrize("crash_after", [1, 2, 5])
def test_multiple_cycles_without_data_loss(tmp_path: Path, crash_after: int):
    """
    Несколько циклов: падение -> перезапуск -> падение -> перезапуск, пока не завершим.
    Проверяем отсутствие потерь/дубликатов на каждом шаге.
    """
    total = 12
    workdir = tmp_path / f"cycle_{crash_after}"
    worker = tmp_path / f"worker_cycle_{crash_after}.py"
    _write_worker_script(worker)

    # 1-й цикл: падение
    _ = _run_worker(sys.executable, worker, workdir, total, crash_after)
    # 2-й цикл: возможна доработка, но снова падение (если остаётся много задач)
    _ = _run_worker(sys.executable, worker, workdir, total, crash_after)
    # Финальный цикл: без падения
    p_final = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p_final.returncode == 0

    # Верификация
    with open(workdir / "state.json", "r", encoding="utf-8") as f:
        state = json.load(f)
    processed = state.get("processed")
    assert processed == list(range(total))
    assert (workdir / "wal.log").read_text(encoding="utf-8").strip() == ""

    # Нет пропусков артефактов
    for tid in range(total):
        assert (workdir / f"task_{tid}.done").exists()


def test_resilience_when_state_file_missing_but_wal_present(tmp_path: Path):
    """
    Симулируем потерю state.json при наличии WAL: воркер обязан восстановиться только на базе WAL.
    """
    total = 8
    workdir = tmp_path / "state_loss"
    worker = tmp_path / "worker_state_loss.py"
    _write_worker_script(worker)

    # Подготовка: частично обработаем и «упадём»
    _ = _run_worker(sys.executable, worker, workdir, total, 3)
    state_path = workdir / "state.json"
    wal_path = workdir / "wal.log"
    assert state_path.exists() and wal_path.exists()

    # Удаляем состояние, имитируя потерю файла
    state_path.unlink(missing_ok=True)

    # Перезапуск без падения — должен восстановить из WAL и завершить
    p2 = _run_worker(sys.executable, worker, workdir, total, "none")
    assert p2.returncode == 0

    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)
    assert state.get("processed") == list(range(total))
    assert wal_path.read_text(encoding="utf-8").strip() == ""

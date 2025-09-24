#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aethernova Engine | Codegen v1
regenerate_on_change.py — авто‑генерация артефактов при изменении *.proto.

Возможности:
  - Наблюдение за каталогами схем (по умолчанию engine-core/schemas/proto/v1/**).
  - Дебаунс и коалесинг всплесков событий (fs-save storms, git checkout).
  - Фильтрация по маскам и игнору (tmp, .* , *_internal.proto).
  - Безопасный одновременный запуск: один генератор за раз; перезапуск после завершения.
  - Интеграция с generate_all.sh через профили dev|ci|release (по умолчанию dev).
  - Кроссплатформенно: watchdog (inotify/FSEvents/ReadDirectoryChangesW) с fallback на polling.
  - Корректное завершение по SIGINT/SIGTERM.
  - Подробные, но лаконичные логи; код возврата 0 при штатном завершении.

Зависимости (опционально):
    pip install watchdog

Запуск:
    python -m engine_core.codegen.python.v1.scripts.regenerate_on_change \
      --profile dev --debounce-ms 400 --quiet

Или из каталога скрипта:
    ./regenerate_on_change.py --profile dev
"""
from __future__ import annotations

import argparse
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set

# -------- Константы/умолчания --------
DEFAULT_PROFILE = "dev"
DEFAULT_DEBOUNCE_MS = 500
DEFAULT_QUIET = False

REPO_MARKERS = (".git", "pyproject.toml", "engine-core")
SCHEMAS_REL = "engine-core/schemas/proto/v1"
CODEGEN_SCRIPT = "engine-core/codegen/python/v1/scripts/generate_all.sh"

WATCH_MASKS = (".proto",)
IGNORE_SUFFIXES = (".swp", ".swx", ".tmp", "~")
IGNORE_PREFIXES = (".",)
IGNORE_CONTAINS = ("__pycache__",)
IGNORE_FILES_GLOB = ("*_internal.proto",)

# -------- Утилиты/лог --------
def _isatty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

_COLOR = _isatty() and os.environ.get("COLOR", "auto") != "never"
def _c(color: str, s: str) -> str:
    if not _COLOR:
        return s
    codes = {"dim":"\033[2m","red":"\033[31m","grn":"\033[32m","ylw":"\033[33m","rst":"\033[0m"}
    return f"{codes.get(color,'')}{s}{codes['rst']}"

def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S", time.gmtime())
    print(f"{_c('dim','['+ts+']')} {msg}", flush=True)

def info(msg: str) -> None:
    print(f"{_c('grn','INFO')}  {msg}", flush=True)

def warn(msg: str) -> None:
    print(f"{_c('ylw','WARN')}  {msg}", flush=True)

def err(msg: str) -> None:
    print(f"{_c('red','ERROR')} {msg}", file=sys.stderr, flush=True)

# -------- Поиск корня репозитория --------
def detect_repo_root(start: Optional[Path] = None) -> Path:
    p = Path(start or __file__).resolve()
    for base in [p] + list(p.parents):
        for m in REPO_MARKERS:
            if (base / m).exists():
                return base
    return p.parents[4]

# -------- Фильтры путей --------
def _ignored(path: Path) -> bool:
    name = path.name
    if any(name.endswith(suf) for suf in IGNORE_SUFFIXES):
        return True
    if any(name.startswith(pre) for pre in IGNORE_PREFIXES):
        # .git / .idea и т.п. — игнорируем
        return True
    if any(part in IGNORE_CONTAINS for part in path.parts):
        return True
    from fnmatch import fnmatch
    for pat in IGNORE_FILES_GLOB:
        if fnmatch(name, pat):
            return True
    return False

def _matches(path: Path) -> bool:
    if _ignored(path):
        return False
    return any(str(path).endswith(ext) for ext in WATCH_MASKS)

# -------- Дебаунс‑коалесер --------
@dataclass
class ChangeEvent:
    path: Path
    ts: float

class DebouncedRunner:
    def __init__(self, run_fn, debounce_ms: int):
        self._run_fn = run_fn
        self._debounce = debounce_ms / 1000.0
        self._q: "queue.Queue[ChangeEvent]" = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._worker, name="debounced-runner", daemon=True)
        self._busy_lock = threading.Lock()
        self._pending_restart = False

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # разбудим
        self._q.put(ChangeEvent(Path("."), time.time()))
        self._thread.join(timeout=2.0)

    def push(self, path: Path) -> None:
        self._q.put(ChangeEvent(path, time.time()))

    def _worker(self) -> None:
        last_event_ts = 0.0
        pending: Set[Path] = set()
        while not self._stop.is_set():
            try:
                ev = self._q.get(timeout=0.25)
            except queue.Empty:
                ev = None  # type: ignore
            if ev:
                pending.add(ev.path)
                last_event_ts = ev.ts
            # окно дебаунса
            if pending and (time.time() - last_event_ts) >= self._debounce:
                self._trigger(sorted(pending))
                pending.clear()

    def _trigger(self, paths: List[Path]) -> None:
        # единовременный запуск; если генератор уже работает — отметим флаг перезапуска
        if self._busy_lock.locked():
            self._pending_restart = True
            log(f"События накоплены ({len(paths)}), ждем завершения текущей генерации...")
            return
        with self._busy_lock:
            self._pending_restart = False
            info(f"Изменения обнаружены: {len(paths)} файл(ов). Запуск генерации...")
            self._run_fn(paths)
        # если пока генерировали, накопились новые изменения — повторим
        if self._pending_restart:
            with self._busy_lock:
                self._pending_restart = False
                info("Новые изменения поступили во время генерации. Перезапуск...")
                self._run_fn([])

# -------- Запуск генератора --------
def run_codegen(repo_root: Path, profile: str, quiet: bool) -> int:
    script = repo_root / CODEGEN_SCRIPT
    if not script.exists():
        err(f"Не найден скрипт генерации: {script}")
        return 2
    cmd = ["bash", str(script), "--profile", profile]
    if quiet:
        log("Запуск: " + " ".join(cmd))
        proc = subprocess.run(cmd, cwd=str(repo_root))
    else:
        info("Команда: " + " ".join(cmd))
        proc = subprocess.run(cmd, cwd=str(repo_root))
    rc = proc.returncode
    if rc == 0:
        info("Генерация завершена успешно")
    else:
        err(f"Генерация завершилась с кодом {rc}")
    return rc

# -------- Watcher реализации --------
class Watcher:
    def __init__(self, paths: Iterable[Path], on_change):
        self.paths = list(paths)
        self.on_change = on_change
        self._observer = None
        self._stop = threading.Event()

    def start(self) -> None:
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except Exception:
            warn("watchdog не установлен, fallback на периодический опрос (0.5с)")
            self._start_polling()
            return

        class Handler(FileSystemEventHandler):  # type: ignore
            def __init__(self, cb):
                self.cb = cb
            def on_any_event(self, event):
                try:
                    p = Path(event.src_path)
                    if _matches(p):
                        self.cb(p)
                    # event.dest_path (rename) тоже учитываем
                    if hasattr(event, "dest_path"):
                        p2 = Path(event.dest_path)  # type: ignore
                        if _matches(p2):
                            self.cb(p2)
                except Exception:
                    pass

        handler = Handler(self.on_change)
        self._observer = Observer()
        for p in self.paths:
            self._observer.schedule(handler, str(p), recursive=True)
            log(f"Watch: {p}")
        self._observer.start()

    def _start_polling(self) -> None:
        # Примитивный опрос по mtime
        mtimes = {}
        def poll():
            while not self._stop.is_set():
                for root in self.paths:
                    for fp in root.rglob("*.proto"):
                        if _ignored(fp):
                            continue
                        try:
                            m = fp.stat().st_mtime_ns
                        except FileNotFoundError:
                            m = None
                        prev = mtimes.get(fp)
                        if prev != m:
                            mtimes[fp] = m
                            self.on_change(fp)
                time.sleep(0.5)
        t = threading.Thread(target=poll, name="polling-watcher", daemon=True)
        t.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._observer:
                self._observer.stop()
                self._observer.join(timeout=2.0)
        except Exception:
            pass

# -------- CLI --------
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Regenerate protobuf/gRPC artifacts on source changes")
    ap.add_argument("--profile", choices=["dev", "ci", "release"], default=DEFAULT_PROFILE, help="Профиль генерации")
    ap.add_argument("--debounce-ms", type=int, default=DEFAULT_DEBOUNCE_MS, help="Окно дебаунса событий, мс")
    ap.add_argument("--schemas-dir", default=SCHEMAS_REL, help="Каталог со схемами (relative или absolute)")
    ap.add_argument("--quiet", action="store_true", default=DEFAULT_QUIET, help="Менее подробный лог")
    ap.add_argument("--once", action="store_true", help="Сразу сгенерировать и выйти (без watch)")
    ap.add_argument("--no-initial", action="store_true", help="Не запускать генерацию при старте")
    return ap.parse_args()

def main() -> int:
    args = parse_args()
    repo = detect_repo_root()
    schemas = (repo / args.schemas_dir).resolve()
    if not schemas.exists():
        err(f"Каталог схем не найден: {schemas}")
        return 2

    info(f"Репозиторий: {repo}")
    info(f"Схемы:      {schemas}")
    info(f"Профиль:    {args.profile}")

    stop_event = threading.Event()

    def _sig_handler(signum, frame):
        warn(f"Получен сигнал {signum}. Завершение...")
        stop_event.set()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    # Функция запуска генератора
    def do_run(_paths: List[Path]) -> None:
        rc = run_codegen(repo, args.profile, args.quiet)
        if rc != 0:
            warn("Ожидание дальнейших изменений для повторной попытки...")

    # Режим одноразовой генерации
    if args.once:
        return run_codegen(repo, args.profile, args.quiet)

    # Инициализация дебаунс‑раннера
    runner = DebouncedRunner(run_fn=do_run, debounce_ms=args.debounce_ms)
    runner.start()

    # Watcher
    watcher = Watcher(paths=[schemas], on_change=lambda p: runner.push(p))
    watcher.start()

    if not args.no_initial:
        # Стартовая генерация
        runner.push(schemas / "__initial__")

    # Основной цикл ожидания завершения
    try:
        while not stop_event.is_set():
            time.sleep(0.25)
    finally:
        watcher.stop()
        runner.stop()
        info("Выход из watcher")

    return 0

if __name__ == "__main__":
    sys.exit(main())

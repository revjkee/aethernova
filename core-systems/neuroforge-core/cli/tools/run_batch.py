#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
neuroforge-core/cli/tools/run_batch.py

Промышленный асинхронный батч-раннер:
- Конфигурация: JSON или TOML (Python 3.11+: tomllib).
- Встроенные исполнители задач:
    * type: "python" — исполнение callable по dotted-пути, поддержка sync/async.
    * type: "shell"  — исполнение подпроцесса (execvp/argv или shell-строка).
- DAG: зависимости, топологическое планирование, fail-fast/continue.
- Конкурентность: глобальный лимит, справедливое планирование.
- Надежность: retries с экспоненциальным backoff + jitter, timeout на задачу.
- Сигналы: SIGINT/SIGTERM — аккуратная отмена, завершение подпроцессов.
- Логирование: NDJSON (stdout и/или файл), уровни и корреляция run_id/job_id.
- Отчет: JSON summary в файл (по желанию) и человекочитаемое резюме.
- Без внешних зависимостей.

Схема конфигурации (JSON/TOML эквивалент):
{
  "version": 1,
  "options": {
    "concurrency": 4,
    "fail_fast": true,
    "max_failures": 0,          // 0 = не ограничено
    "default_timeout_s": 0,     // 0 = без таймаута
    "default_retries": 0,
    "default_backoff_s": 0.5,
    "default_backoff_factor": 2.0,
    "default_jitter_s": 0.1
  },
  "jobs": [
    {
      "id": "prepare",
      "type": "python",
      "callable": "package.module:function_name",
      "args": [],                // optional
      "kwargs": {},              // optional
      "timeout_s": 5,            // override default
      "retries": 2,
      "backoff_s": 0.5,
      "backoff_factor": 2.0,
      "jitter_s": 0.1,
      "depends_on": [],
      "tags": ["prep"],
      "skip_if_exists": ""       // optional: путь — если файл существует, задача SKIPPED
    },
    {
      "id": "compile",
      "type": "shell",
      "command": ["bash", "-lc", "echo compiling && sleep 1 && echo ok"],
      // либо: "command": "echo compiling && sleep 1 && echo ok",
      "env": {"ENV": "prod"},
      "cwd": ".",
      "timeout_s": 30,
      "retries": 1,
      "depends_on": ["prepare"],
      "tags": ["build"]
    }
  ]
}

Примеры запуска:
  python run_batch.py --config batch.json --log-file batch.log.ndjson --summary-file summary.json
  python run_batch.py --config batch.toml --concurrency 8 --no-fail-fast
  python run_batch.py --task package.module:function --kwargs '{"x":1}' --retries 2

Коды выхода:
  0 — успех
  1 — ошибки валидации/конфигурации
  2 — неуспешные задачи (failures/skips по правилам)
  130 — прерывание пользователем (SIGINT/SIGTERM)
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import datetime as dt
import functools
import importlib
import inspect
import io
import json
import os
import random
import signal
import sys
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, Callable

# tomllib доступен из стандартной библиотеки Python 3.11+
try:
    import tomllib  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    tomllib = None  # fallback: будем работать только с JSON

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow_iso() -> str:
    return dt.datetime.utcnow().strftime(ISO)


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return json.dumps(str(obj), ensure_ascii=False)


class NDJSONLogger:
    """
    Простой высоконадежный NDJSON-логгер (stdout + опционально файл).
    Не зависит от logging/structlog, чтобы избежать внешних конфигов.
    """
    def __init__(self, log_file: Optional[str] = None, level: str = "INFO") -> None:
        self.log_file = log_file
        self.level = level.upper()
        self._fp = open(log_file, "a", encoding="utf-8") if log_file else None
        self._levels = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}

    def _emit(self, record: Dict[str, Any]) -> None:
        line = _safe_json(record)
        print(line, file=sys.stdout, flush=True)
        if self._fp:
            print(line, file=self._fp, flush=True)

    def _enabled(self, level: str) -> bool:
        return self._levels.get(level, 20) >= self._levels.get(self.level, 20)

    def log(self, level: str, event: str, **fields: Any) -> None:
        if not self._enabled(level):
            return
        rec = {
            "ts": utcnow_iso(),
            "level": level,
            "event": event,
        }
        rec.update(fields)
        self._emit(rec)

    def debug(self, event: str, **fields: Any) -> None:
        self.log("DEBUG", event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self.log("INFO", event, **fields)

    def warn(self, event: str, **fields: Any) -> None:
        self.log("WARN", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self.log("ERROR", event, **fields)

    def close(self) -> None:
        if self._fp:
            try:
                self._fp.close()
            except Exception:
                pass


@dataclass
class RetryPolicy:
    retries: int = 0
    backoff_s: float = 0.0
    backoff_factor: float = 2.0
    jitter_s: float = 0.0


@dataclass
class JobSpec:
    id: str
    type: str  # "python" | "shell"
    # python
    callable: Optional[str] = None
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    # shell
    command: Optional[Union[str, List[str]]] = None
    env: Dict[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None

    timeout_s: float = 0.0  # 0 = no timeout
    retries: int = 0
    backoff_s: float = 0.0
    backoff_factor: float = 2.0
    jitter_s: float = 0.0

    depends_on: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    skip_if_exists: str = ""  # optional path

    # internal fields (runtime)
    attempts: int = 0


@dataclass
class Options:
    concurrency: int = 4
    fail_fast: bool = True
    max_failures: int = 0  # 0 = unlimited
    default_timeout_s: float = 0.0
    default_retries: int = 0
    default_backoff_s: float = 0.5
    default_backoff_factor: float = 2.0
    default_jitter_s: float = 0.1


@dataclass
class Config:
    version: int
    options: Options
    jobs: List[JobSpec]


class ValidationError(Exception):
    pass


class CancellationError(Exception):
    pass


class JobStatus:
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


@dataclass
class JobResult:
    job_id: str
    status: str
    attempts: int
    started_at: Optional[str]
    ended_at: Optional[str]
    duration_s: Optional[float]
    return_code: Optional[int] = None   # shell
    output: Optional[str] = None        # python result repr or captured stdout tail
    error: Optional[str] = None         # traceback or message


class GracefulExit(Exception):
    pass


class BatchRunner:
    def __init__(
        self,
        config: Config,
        logger: NDJSONLogger,
        run_id: str,
        selected_ids: Optional[set[str]] = None,
        include_tags: Optional[set[str]] = None,
        exclude_tags: Optional[set[str]] = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self.run_id = run_id
        self.selected_ids = selected_ids
        self.include_tags = include_tags
        self.exclude_tags = exclude_tags

        self._jobs: Dict[str, JobSpec] = {j.id: j for j in config.jobs}
        self._status: Dict[str, str] = {j.id: JobStatus.PENDING for j in config.jobs}
        self._results: Dict[str, JobResult] = {}
        self._deps_in: Dict[str, set[str]] = {j.id: set(j.depends_on) for j in config.jobs}
        self._deps_out: Dict[str, set[str]] = {j.id: set() for j in config.jobs}
        for j in config.jobs:
            for d in j.depends_on:
                self._deps_out.setdefault(d, set()).add(j.id)

        self._failures: int = 0
        self._cancel_event = asyncio.Event()
        self._semaphore = asyncio.Semaphore(self.config.options.concurrency)

    # ----------------- Validation & Filtering -----------------

    @staticmethod
    def _ensure_unique_ids(jobs: List[JobSpec]) -> None:
        seen = set()
        for j in jobs:
            if j.id in seen:
                raise ValidationError(f"Duplicate job id: '{j.id}'")
            seen.add(j.id)

    @staticmethod
    def _ensure_deps_exist(jobs: List[JobSpec]) -> None:
        ids = {j.id for j in jobs}
        for j in jobs:
            missing = [d for d in j.depends_on if d not in ids]
            if missing:
                raise ValidationError(f"Job '{j.id}' depends on unknown ids: {missing}")

    @staticmethod
    def _detect_cycles(jobs: List[JobSpec]) -> None:
        # Kahn's algorithm
        deps_in = {j.id: set(j.depends_on) for j in jobs}
        no_incoming = [j.id for j in jobs if not deps_in[j.id]]
        order = []
        while no_incoming:
            n = no_incoming.pop()
            order.append(n)
            for m in [x.id for x in jobs if n in deps_in[x.id]]:
                deps_in[m].remove(n)
                if not deps_in[m]:
                    no_incoming.append(m)
        if len(order) != len(jobs):
            raise ValidationError("Dependency cycle detected")

    def _apply_defaults(self) -> None:
        opt = self.config.options
        for j in self._jobs.values():
            if j.timeout_s <= 0:
                j.timeout_s = opt.default_timeout_s
            if j.retries <= 0:
                j.retries = opt.default_retries
            if j.backoff_s <= 0:
                j.backoff_s = opt.default_backoff_s
            if j.backoff_factor <= 0:
                j.backoff_factor = opt.default_backoff_factor
            if j.jitter_s < 0:
                j.jitter_s = opt.default_jitter_s

    def _filter_by_selectors(self) -> None:
        if not self.selected_ids and not self.include_tags and not self.exclude_tags:
            return
        keep: set[str] = set()

        # Первично: ID
        if self.selected_ids:
            keep |= set(self.selected_ids)
            # + все транзитивные зависимости выбранных
            queue = list(self.selected_ids)
            while queue:
                cur = queue.pop()
                job = self._jobs.get(cur)
                if not job:
                    continue
                for d in job.depends_on:
                    if d not in keep:
                        keep.add(d)
                        queue.append(d)
        else:
            keep = set(self._jobs.keys())

        # По тегам
        if self.include_tags:
            keep = {jid for jid in keep if set(self._jobs[jid].tags) & self.include_tags}
        if self.exclude_tags:
            keep = {jid for jid in keep if not (set(self._jobs[jid].tags) & self.exclude_tags)}

        # Сузим внутренние структуры
        self._jobs = {jid: self._jobs[jid] for jid in keep}
        self._status = {jid: self._status[jid] for jid in keep}
        self._deps_in = {jid: set(self._deps_in[jid]) & keep for jid in keep}
        self._deps_out = {jid: set(self._deps_out.get(jid, set())) & keep for jid in keep}
        for jid in list(self._deps_in.keys()):
            self._deps_in[jid] = self._deps_in[jid] & set(self._jobs.keys())

        # Повторная валидация DAG после фильтра
        self._ensure_deps_exist(list(self._jobs.values()))
        self._detect_cycles(list(self._jobs.values()))

    def validate(self) -> None:
        jobs = list(self._jobs.values())
        if not jobs:
            raise ValidationError("No jobs to run after filtering")
        self._ensure_unique_ids(jobs)
        self._ensure_deps_exist(jobs)
        self._detect_cycles(jobs)
        # Базовая проверка полей по типам задач
        for j in jobs:
            if j.type not in ("python", "shell"):
                raise ValidationError(f"Job '{j.id}' has unsupported type '{j.type}'")
            if j.type == "python" and not j.callable:
                raise ValidationError(f"Job '{j.id}': 'callable' is required for python type")
            if j.type == "shell" and not j.command:
                raise ValidationError(f"Job '{j.id}': 'command' is required for shell type")

        self._apply_defaults()
        self._filter_by_selectors()

    # ----------------- Signal Handling -----------------

    def install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, functools.partial(self._on_signal, sig))

    def _on_signal(self, sig: signal.Signals) -> None:
        self.logger.warn(
            "signal_received", run_id=self.run_id, signal=str(sig), msg="Graceful cancellation requested"
        )
        self._cancel_event.set()

    # ----------------- Execution Core -----------------

    async def run(self) -> Dict[str, JobResult]:
        self.install_signal_handlers()
        ready = [jid for jid, deps in self._deps_in.items() if not deps]
        for jid in ready:
            self._status[jid] = JobStatus.READY

        tasks = set()
        try:
            while True:
                if self._cancel_event.is_set():
                    await self._cancel_all_pending()
                    break

                # Запускаем READY до заполнения семафора
                while ready and self._semaphore.locked() is False:
                    jid = ready.pop()
                    if self._status.get(jid) != JobStatus.READY:
                        continue
                    tasks.add(asyncio.create_task(self._execute_job(jid)))

                if not tasks:
                    # Проверим, есть ли ещё READY (если семафор занят, сюда не попадём)
                    if any(st in (JobStatus.PENDING, JobStatus.READY, JobStatus.RUNNING) for st in self._status.values()):
                        # Подождать событий (кто-то завершится)
                        await asyncio.sleep(0.05)
                        # Пересчитать ready из-за возможных завершений
                        ready = [jid for jid, deps in self._deps_in.items() if not deps and self._status[jid] == JobStatus.PENDING]
                        for jid in ready:
                            self._status[jid] = JobStatus.READY
                        continue
                    else:
                        # Всё завершено
                        break

                done, pending = await asyncio.wait(tasks, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
                for d in done:
                    tasks.remove(d)
                    try:
                        jid_finished, success = d.result()
                    except Exception as e:
                        self.logger.error(
                            "job_task_crashed",
                            run_id=self.run_id,
                            error=str(e),
                            traceback="".join(traceback.format_exc()),
                        )
                        # Неизвестно какой именно job, поэтому продолжаем
                        continue

                    # Обновление следующих
                    if success:
                        for nxt in self._deps_out.get(jid_finished, set()):
                            self._deps_in[nxt].discard(jid_finished)
                            if not self._deps_in[nxt] and self._status[nxt] == JobStatus.PENDING:
                                self._status[nxt] = JobStatus.READY
                                ready.append(nxt)
                    else:
                        # Неуспех
                        self._failures += 1
                        if self.config.options.fail_fast:
                            await self._skip_remaining_due_to_fail_fast()
                        elif self.config.options.max_failures > 0 and self._failures >= self.config.options.max_failures:
                            await self._skip_remaining_due_to_fail_limit()

                # Обновим список ready после изменений
                ready = [jid for jid, deps in self._deps_in.items() if not deps and self._status[jid] == JobStatus.PENDING]
                for jid in ready:
                    self._status[jid] = JobStatus.READY

        finally:
            # Дожмем висящие
            for t in tasks:
                t.cancel()
                with contextlib.suppress(Exception):
                    await t

        return self._results

    async def _cancel_all_pending(self) -> None:
        # Переводим все PENDING/READY в CANCELLED
        for jid, st in list(self._status.items()):
            if st in (JobStatus.PENDING, JobStatus.READY):
                self._status[jid] = JobStatus.CANCELLED
                self._results[jid] = JobResult(
                    job_id=jid,
                    status=JobStatus.CANCELLED,
                    attempts=0,
                    started_at=None,
                    ended_at=utcnow_iso(),
                    duration_s=None,
                    error="Cancelled by signal",
                )

    async def _skip_remaining_due_to_fail_fast(self) -> None:
        for jid, st in list(self._status.items()):
            if st in (JobStatus.PENDING, JobStatus.READY):
                self._status[jid] = JobStatus.SKIPPED
                self._results[jid] = JobResult(
                    job_id=jid,
                    status=JobStatus.SKIPPED,
                    attempts=0,
                    started_at=None,
                    ended_at=utcnow_iso(),
                    duration_s=None,
                    error="Skipped due to fail_fast",
                )

    async def _skip_remaining_due_to_fail_limit(self) -> None:
        for jid, st in list(self._status.items()):
            if st in (JobStatus.PENDING, JobStatus.READY):
                self._status[jid] = JobStatus.SKIPPED
                self._results[jid] = JobResult(
                    job_id=jid,
                    status=JobStatus.SKIPPED,
                    attempts=0,
                    started_at=None,
                    ended_at=utcnow_iso(),
                    duration_s=None,
                    error="Skipped due to max_failures limit",
                )

    async def _execute_job(self, jid: str) -> Tuple[str, bool]:
        job = self._jobs[jid]
        # SKIP по маркеру файла
        if job.skip_if_exists and os.path.exists(job.skip_if_exists):
            self._status[jid] = JobStatus.SKIPPED
            self._results[jid] = JobResult(
                job_id=jid,
                status=JobStatus.SKIPPED,
                attempts=0,
                started_at=None,
                ended_at=utcnow_iso(),
                duration_s=None,
                error=f"skip_if_exists: {job.skip_if_exists}",
            )
            self.logger.info("job_skipped_existing", run_id=self.run_id, job_id=jid, path=job.skip_if_exists)
            return jid, True  # SKIP не считается неуспехом
        self._status[jid] = JobStatus.RUNNING

        start = dt.datetime.utcnow()
        started_iso = start.strftime(ISO)

        self.logger.info(
            "job_start",
            run_id=self.run_id,
            job_id=jid,
            type=job.type,
            deps=list(self._deps_in.get(jid, [])),
            retries=job.retries,
            timeout_s=job.timeout_s,
        )

        ok = False
        attempts = 0
        error_str = None
        ret_code = None
        output_repr = None

        try:
            async with self._semaphore:
                policy = RetryPolicy(job.retries, job.backoff_s, job.backoff_factor, job.jitter_s)
                while True:
                    attempts += 1
                    if self._cancel_event.is_set():
                        raise CancellationError("Cancelled before start attempt")

                    try:
                        if job.type == "python":
                            output_repr = await self._run_python(job, timeout_s=job.timeout_s)
                            ok = True
                        elif job.type == "shell":
                            ret_code, output_repr = await self._run_shell(job, timeout_s=job.timeout_s)
                            ok = (ret_code == 0)
                            if not ok:
                                raise RuntimeError(f"Shell non-zero exit: {ret_code}")
                        else:
                            raise RuntimeError(f"Unsupported type: {job.type}")
                        break
                    except CancellationError as ce:
                        error_str = str(ce)
                        ok = False
                        break
                    except Exception as e:
                        error_str = f"{e}\n{''.join(traceback.format_exc())}"
                        ok = False
                        if attempts > policy.retries:
                            break
                        # backoff
                        delay = policy.backoff_s * (policy.backoff_factor ** (attempts - 1))
                        if policy.jitter_s > 0:
                            delay += random.uniform(0, policy.jitter_s)
                        delay = max(0.0, delay)
                        self.logger.warn(
                            "job_retry",
                            run_id=self.run_id,
                            job_id=jid,
                            attempt=attempts,
                            next_delay_s=round(delay, 3),
                            error=str(e),
                        )
                        await asyncio.sleep(delay)
        finally:
            end = dt.datetime.utcnow()
            dur = (end - start).total_seconds()
            status = JobStatus.SUCCESS if ok else JobStatus.FAILED
            self._status[jid] = status
            self._results[jid] = JobResult(
                job_id=jid,
                status=status,
                attempts=attempts,
                started_at=started_iso,
                ended_at=end.strftime(ISO),
                duration_s=dur,
                return_code=ret_code,
                output=_safe_limit(output_repr, limit=8000),
                error=_safe_limit(error_str, limit=12000),
            )
            self.logger.info(
                "job_end",
                run_id=self.run_id,
                job_id=jid,
                status=status,
                attempts=attempts,
                duration_s=round(dur, 4),
                return_code=ret_code,
            )

        return jid, ok

    async def _run_python(self, job: JobSpec, timeout_s: float) -> str:
        assert job.callable
        func = resolve_callable(job.callable)
        async def _invoke() -> Any:
            if inspect.iscoroutinefunction(func):
                return await func(*job.args, **job.kwargs)
            else:
                # В sync-функции исполняем в default thread pool
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, functools.partial(func, *job.args, **job.kwargs))

        if timeout_s and timeout_s > 0:
            res = await asyncio.wait_for(_invoke(), timeout=timeout_s)
        else:
            res = await _invoke()
        return repr(res)

    async def _run_shell(self, job: JobSpec, timeout_s: float) -> Tuple[int, str]:
        cmd = job.command
        if isinstance(cmd, list):
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=job.cwd or None,
                env={**os.environ, **(job.env or {})},
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        elif isinstance(cmd, str):
            proc = await asyncio.create_subprocess_shell(
                cmd,
                cwd=job.cwd or None,
                env={**os.environ, **(job.env or {})},
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                executable=None,  # по умолчанию /bin/sh или cmd.exe
            )
        else:
            raise ValidationError(f"Job '{job.id}': 'command' must be list[str] or str")

        try:
            if timeout_s and timeout_s > 0:
                try:
                    out = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    raise RuntimeError(f"Shell timeout after {timeout_s}s")
            else:
                out = await proc.communicate()
        finally:
            pass

        stdout = out[0].decode("utf-8", errors="replace") if out and out[0] else ""
        return proc.returncode or 0, stdout


def _safe_limit(s: Optional[str], limit: int = 8000) -> Optional[str]:
    if s is None:
        return None
    if len(s) <= limit:
        return s
    return s[:limit] + f"... [truncated {len(s)-limit} chars]"


def resolve_callable(dotted: str) -> Callable[..., Any]:
    """
    Импортирует callable по dotted-пути: "pkg.mod:func" или "pkg.mod.func"
    """
    if ":" in dotted:
        module_name, attr = dotted.split(":", 1)
    else:
        parts = dotted.split(".")
        module_name, attr = ".".join(parts[:-1]), parts[-1]
    if not module_name or not attr:
        raise ValidationError(f"Invalid callable path: '{dotted}'")
    module = importlib.import_module(module_name)
    func = getattr(module, attr, None)
    if not callable(func):
        raise ValidationError(f"Resolved attribute is not callable: '{dotted}'")
    return func


# ----------------- Config Loading -----------------

def load_config_from_file(path: str) -> Config:
    with open(path, "rb") as f:
        data_raw = f.read()

    lower = path.lower()
    if lower.endswith(".json"):
        data = json.loads(data_raw.decode("utf-8"))
    elif lower.endswith(".toml"):
        if tomllib is None:
            raise ValidationError("TOML unsupported: Python < 3.11 or tomllib not available")
        data = tomllib.loads(data_raw.decode("utf-8"))
    else:
        # Попытка автоопределения: сначала JSON, потом TOML
        try:
            data = json.loads(data_raw.decode("utf-8"))
        except Exception:
            if tomllib is None:
                raise ValidationError("Unknown config format. Use .json or .toml")
            data = tomllib.loads(data_raw.decode("utf-8"))

    return parse_config(data)


def parse_config(data: Dict[str, Any]) -> Config:
    if not isinstance(data, dict):
        raise ValidationError("Config root must be a dict")
    version = int(data.get("version", 1))

    opt = data.get("options", {}) or {}
    options = Options(
        concurrency=int(opt.get("concurrency", 4)),
        fail_fast=bool(opt.get("fail_fast", True)),
        max_failures=int(opt.get("max_failures", 0)),
        default_timeout_s=float(opt.get("default_timeout_s", 0.0)),
        default_retries=int(opt.get("default_retries", 0)),
        default_backoff_s=float(opt.get("default_backoff_s", 0.5)),
        default_backoff_factor=float(opt.get("default_backoff_factor", 2.0)),
        default_jitter_s=float(opt.get("default_jitter_s", 0.1)),
    )

    jobs_raw = data.get("jobs", [])
    if not isinstance(jobs_raw, list) or not jobs_raw:
        raise ValidationError("'jobs' must be a non-empty list")

    jobs: List[JobSpec] = []
    for j in jobs_raw:
        if not isinstance(j, dict):
            raise ValidationError("Each job must be a dict")
        job = JobSpec(
            id=str(j.get("id") or "").strip(),
            type=str(j.get("type") or "").strip(),
            callable=j.get("callable"),
            args=list(j.get("args") or []),
            kwargs=dict(j.get("kwargs") or {}),
            command=j.get("command"),
            env=dict(j.get("env") or {}),
            cwd=j.get("cwd"),
            timeout_s=float(j.get("timeout_s") or 0.0),
            retries=int(j.get("retries") or 0),
            backoff_s=float(j.get("backoff_s") or 0.0),
            backoff_factor=float(j.get("backoff_factor") or 2.0),
            jitter_s=float(j.get("jitter_s") or 0.0),
            depends_on=list(j.get("depends_on") or []),
            tags=list(j.get("tags") or []),
            skip_if_exists=str(j.get("skip_if_exists") or "").strip(),
        )
        if not job.id:
            raise ValidationError("Job id is required and must be non-empty")
        jobs.append(job)

    cfg = Config(version=version, options=options, jobs=jobs)
    return cfg


# ----------------- CLI -----------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="NeuroForge Batch Runner (industrial-grade, async, no external deps)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    g_conf = p.add_argument_group("Configuration")
    g_conf.add_argument("--config", type=str, help="Path to JSON/TOML config file")
    g_conf.add_argument("--task", type=str, help="Dotted callable (python task) if config not provided")
    g_conf.add_argument("--args", type=str, default="[]", help="JSON array of args for --task")
    g_conf.add_argument("--kwargs", type=str, default="{}", help="JSON object of kwargs for --task")
    g_conf.add_argument("--command", type=str, help="Shell command (string) if config not provided (type=shell)")

    g_exec = p.add_argument_group("Execution")
    g_exec.add_argument("--concurrency", type=int, default=None, help="Override options.concurrency")
    g_exec.add_argument("--fail-fast", dest="fail_fast", action="store_true", help="Stop scheduling after first failure")
    g_exec.add_argument("--no-fail-fast", dest="fail_fast", action="store_false", help="Do not stop after first failure")
    g_exec.set_defaults(fail_fast=None)
    g_exec.add_argument("--max-failures", type=int, default=None, help="Stop scheduling after N failures (0 = unlimited)")
    g_exec.add_argument("--select", type=str, help="Comma-separated job IDs to run (deps auto-included)")
    g_exec.add_argument("--include-tags", type=str, help="Comma-separated tags to include")
    g_exec.add_argument("--exclude-tags", type=str, help="Comma-separated tags to exclude")

    g_defaults = p.add_argument_group("Defaults override")
    g_defaults.add_argument("--default-timeout", type=float, default=None, help="Default per-job timeout seconds")
    g_defaults.add_argument("--default-retries", type=int, default=None, help="Default per-job retries")
    g_defaults.add_argument("--default-backoff", type=float, default=None, help="Default backoff seconds")
    g_defaults.add_argument("--default-backoff-factor", type=float, default=None, help="Default backoff factor")
    g_defaults.add_argument("--default-jitter", type=float, default=None, help="Default jitter seconds")

    g_log = p.add_argument_group("Logging/Reporting")
    g_log.add_argument("--log-file", type=str, help="Write NDJSON logs to file")
    g_log.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARN", "ERROR"])
    g_log.add_argument("--summary-file", type=str, help="Write JSON summary to file")

    g_solo = p.add_argument_group("Solo job (no config)")
    g_solo.add_argument("--retries", type=int, default=0, help="Solo job retries")
    g_solo.add_argument("--timeout", type=float, default=0.0, help="Solo job timeout seconds")
    g_solo.add_argument("--backoff", type=float, default=0.5, help="Solo job backoff seconds")
    g_solo.add_argument("--backoff-factor", type=float, default=2.0, help="Solo job backoff factor")
    g_solo.add_argument("--jitter", type=float, default=0.1, help="Solo job jitter seconds")

    return p


def make_config_from_args(args: argparse.Namespace) -> Config:
    # Режим одиночной задачи (без файла конфигурации)
    if args.config:
        return load_config_from_file(args.config)

    if args.task:
        try:
            parsed_args = json.loads(args.args)
            parsed_kwargs = json.loads(args.kwargs)
        except Exception as e:
            raise ValidationError(f"Invalid JSON in --args/--kwargs: {e}")

        job = JobSpec(
            id="solo_python",
            type="python",
            callable=args.task,
            args=list(parsed_args or []),
            kwargs=dict(parsed_kwargs or {}),
            timeout_s=float(args.timeout or 0.0),
            retries=int(args.retries or 0),
            backoff_s=float(args.backoff or 0.5),
            backoff_factor=float(args.backoff_factor or 2.0),
            jitter_s=float(args.jitter or 0.1),
            depends_on=[],
        )
        cfg = Config(
            version=1,
            options=Options(
                concurrency=1,
                fail_fast=True,
                max_failures=1,
                default_timeout_s=0.0,
                default_retries=0,
                default_backoff_s=0.5,
                default_backoff_factor=2.0,
                default_jitter_s=0.1,
            ),
            jobs=[job],
        )
        return cfg

    if args.command:
        job = JobSpec(
            id="solo_shell",
            type="shell",
            command=args.command,
            timeout_s=float(args.timeout or 0.0),
            retries=int(args.retries or 0),
            backoff_s=float(args.backoff or 0.5),
            backoff_factor=float(args.backoff_factor or 2.0),
            jitter_s=float(args.jitter or 0.1),
            depends_on=[],
        )
        cfg = Config(
            version=1,
            options=Options(concurrency=1, fail_fast=True, max_failures=1),
            jobs=[job],
        )
        return cfg

    raise ValidationError("Either --config, or --task/--command must be provided")


def override_config_with_args(cfg: Config, args: argparse.Namespace) -> None:
    # Override execution options
    if args.concurrency is not None:
        cfg.options.concurrency = max(1, int(args.concurrency))
    if args.fail_fast is not None:
        cfg.options.fail_fast = bool(args.fail_fast)
    if args.max_failures is not None:
        cfg.options.max_failures = int(args.max_failures)

    if args.default_timeout is not None:
        cfg.options.default_timeout_s = float(args.default_timeout)
    if args.default_retries is not None:
        cfg.options.default_retries = int(args.default_retries)
    if args.default_backoff is not None:
        cfg.options.default_backoff_s = float(args.default_backoff)
    if args.default_backoff_factor is not None:
        cfg.options.default_backoff_factor = float(args.default_backoff_factor)
    if args.default_jitter is not None:
        cfg.options.default_jitter_s = float(args.default_jitter)


def compute_exit_code(results: Dict[str, JobResult], cancelled: bool) -> int:
    if cancelled:
        return 130
    failures = sum(1 for r in results.values() if r.status == JobStatus.FAILED)
    if failures > 0:
        return 2
    # если всё SUCCESS или SKIPPED — успех
    return 0


def build_summary(results: Dict[str, JobResult], run_id: str) -> Dict[str, Any]:
    counts = {}
    total = 0
    duration_total = 0.0
    for r in results.values():
        counts[r.status] = counts.get(r.status, 0) + 1
        total += 1
        if r.duration_s:
            duration_total += r.duration_s
    return {
        "run_id": run_id,
        "ts": utcnow_iso(),
        "total_jobs": total,
        "by_status": counts,
        "duration_total_s": round(duration_total, 4),
        "results": [dataclasses.asdict(r) for r in results.values()],
    }


async def async_main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    run_id = f"run_{dt.datetime.utcnow().strftime('%Y%m%dT%H%M%S')}_{os.getpid()}"
    logger = NDJSONLogger(log_file=args.log_file, level=args.log_level)

    try:
        cfg = make_config_from_args(args)
        override_config_with_args(cfg, args)

        selected_ids = set((args.select or "").split(",")) if args.select else None
        include_tags = set((args.include_tags or "").split(",")) if args.include_tags else None
        exclude_tags = set((args.exclude_tags or "").split(",")) if args.exclude_tags else None

        runner = BatchRunner(
            cfg,
            logger,
            run_id,
            selected_ids=selected_ids,
            include_tags=include_tags,
            exclude_tags=exclude_tags,
        )
        runner.validate()

        logger.info(
            "run_start",
            run_id=run_id,
            options=dataclasses.asdict(cfg.options),
            jobs=len(cfg.jobs),
            selected_ids=list(selected_ids) if selected_ids else [],
            include_tags=list(include_tags) if include_tags else [],
            exclude_tags=list(exclude_tags) if exclude_tags else [],
        )

        results = await runner.run()

        cancelled = any(r.status == JobStatus.CANCELLED for r in results.values())
        summary = build_summary(results, run_id)

        logger.info("run_summary", run_id=run_id, summary=summary)

        if args.summary_file:
            try:
                with open(args.summary_file, "w", encoding="utf-8") as fp:
                    json.dump(summary, fp, ensure_ascii=False, indent=2)
            except Exception as e:
                logger.error("summary_write_error", run_id=run_id, error=str(e))

        logger.info("run_end", run_id=run_id)
        return compute_exit_code(results, cancelled=cancelled)

    except ValidationError as ve:
        logger.error("validation_error", run_id=run_id, error=str(ve))
        return 1
    except (KeyboardInterrupt, GracefulExit):
        logger.warn("interrupted", run_id=run_id)
        return 130
    except Exception as e:
        logger.error("fatal_error", run_id=run_id, error=str(e), traceback="".join(traceback.format_exc()))
        return 2
    finally:
        logger.close()


def main() -> None:
    # Запуск event loop с безопасной политикой отмены
    try:
        exit_code = asyncio.run(async_main())
    except KeyboardInterrupt:
        # fallback для некоторых платформ
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

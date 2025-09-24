# -*- coding: utf-8 -*-
"""
DataFabric CLI: run_compaction
------------------------------

Запуск компакции мелких файлов с помощью CompactionExecutor.

Особенности:
- Источники конфигурации: CLI > ENV (DF_COMPACTION_*) > YAML/JSON > дефолты
- Логирование: текстовое или JSON (--log-format)
- Корректная обработка сигналов SIGINT/SIGTERM
- Коды возврата:
    0  — завершено успешно, без ошибок
    10 — выполнен dry-run/plan-only (без выполнения) — не ошибка
    20 — выполнено с частичными сбоями (failures > 0), но процесс завершён
    130 — прервано пользователем (KeyboardInterrupt/SIGINT)
    1  — фатальная ошибка/исключение
- Опциональная интеграция с adapters.observability_adapter (если доступен)

Примеры:
    python -m datafabric.cli.tools.run_compaction --root /data/dataset --include "**/*.csv" --partition-depth 1 --dry-run
    python -m datafabric.cli.tools.run_compaction --config compaction.yaml --log-format json --log-level INFO
    DF_COMPACTION_ROOT=/data ds python -m datafabric.cli.tools.run_compaction --plan-only

© DataFabric Core. MIT License.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Опциональный YAML
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # мягкая зависимость

# Опциональная наблюдаемость
try:
    from adapters.observability_adapter import ObservabilityAdapter, ObservabilityConfig  # type: ignore
except Exception:  # pragma: no cover
    ObservabilityAdapter = None  # type: ignore
    ObservabilityConfig = None  # type: ignore

# Основной исполнитель компакции
try:
    from datafabric.tasks.maintenance.compaction import (
        CompactionConfig,
        CompactionExecutor,
    )
except Exception as e:
    print("FATAL: cannot import datafabric.tasks.maintenance.compaction. Ensure package is available.", file=sys.stderr)
    raise


LOG = logging.getLogger("datafabric.cli.run_compaction")


# ---------------------------- Парсинг аргументов -----------------------------

def _comma_or_multi(values: Optional[List[str]]) -> Tuple[str, ...]:
    """
    Поддержка нескольких значений через повторение аргумента или один аргумент с запятыми.
    """
    if not values:
        return tuple()
    out: List[str] = []
    for v in values:
        if v is None:
            continue
        parts = [p.strip() for p in v.split(",") if p.strip()]
        out.extend(parts)
    return tuple(out)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_compaction",
        description="DataFabric: запуск компакции мелких файлов.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Основные
    p.add_argument("--root", help="Корневой каталог данных", required=False)
    p.add_argument("--include", action="append", help="Glob-паттерны включения (повторяемый/через запятую).", default=None)
    p.add_argument("--exclude", action="append", help="Glob-паттерны исключения (повторяемый/через запятую).", default=None)
    p.add_argument("--min-file-bytes", type=int, default=None, help="Порог малого файла (байты).")
    p.add_argument("--target-file-bytes", type=int, default=None, help="Целевой размер компакта (байты).")
    p.add_argument("--max-batch-files", type=int, default=None, help="Максимум файлов в батче.")
    p.add_argument("--min-file-age-seconds", type=int, default=None, help="Минимальный возраст файла (сек).")
    p.add_argument("--max-concurrency", type=int, default=None, help="Параллелизм.")
    p.add_argument("--dry-run", action="store_true", help="Только спланировать и вывести план, без записи.")
    p.add_argument("--plan-only", action="store_true", help="Сформировать план и выйти (без исполнения).")
    p.add_argument("--preserve-originals", action="store_true", help="Не удалять исходные файлы после компакции.")
    p.add_argument("--output-suffix", default=None, help="Суффикс имени выходного файла (перед расширением).")
    p.add_argument("--manifest-dirname", default=None, help="Системный каталог для манифестов.")
    p.add_argument("--lock-filename", default=None, help="Имя lock-файла.")
    p.add_argument("--job-id", default=None, help="Идентификатор задания (для трассировки/манифеста).")
    p.add_argument("--checkpoint-every-batches", type=int, default=None, help="Частота чекпоинтов манифеста.")
    p.add_argument("--fail-fast", action="store_true", help="Останавливать выполнение при первом сбое батча.")
    p.add_argument("--partition-depth", type=int, default=None, help="Глубина партиционирования по подкаталогам.")

    # Логирование/вывод
    p.add_argument("--log-level", default=os.getenv("DF_COMPACTION_LOG_LEVEL", "INFO"), choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--log-format", default=os.getenv("DF_COMPACTION_LOG_FORMAT", "text"), choices=["text", "json"])
    p.add_argument("--print-metrics-json", action="store_true", help="Печать итоговых метрик в JSON в stdout.")

    # Конфигурационные источники
    p.add_argument("--config", help="Путь к YAML/JSON файлу конфигурации.", default=None)

    # Наблюдаемость (опционально)
    p.add_argument("--obs-provider", default=os.getenv("DF_OBS_PROVIDER", None), help="otel|prom|statsd|noop (если доступно).")
    p.add_argument("--obs-service-name", default=os.getenv("DF_SERVICE_NAME", "datafabric"), help="Имя сервиса для телеметрии.")
    p.add_argument("--obs-endpoint", default=os.getenv("DF_OBS_ENDPOINT", None), help="OTLP endpoint (если otel).")

    return p


# ------------------------------ Конфиг/ENV -----------------------------------

ENV_PREFIX = "DF_COMPACTION_"

def load_config_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"Config file not found: {fp}")
    text = fp.read_text(encoding="utf-8")
    if fp.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML не установлен, а конфиг — YAML. Установите pyyaml или используйте JSON.")
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("YAML config must be a mapping at top-level.")
        return data
    # JSON по умолчанию
    data = json.loads(text or "{}")
    if not isinstance(data, dict):
        raise ValueError("JSON config must be an object at top-level.")
    return data


def env_config() -> Dict[str, Any]:
    """
    Считывает ENV переменные с префиксом DF_COMPACTION_ и упрощённо мапит на поля CompactionConfig.
    """
    get = os.getenv
    cfg: Dict[str, Any] = {}
    map_simple = {
        "ROOT": "root",
        "MIN_FILE_BYTES": "min_file_bytes",
        "TARGET_FILE_BYTES": "target_file_bytes",
        "MAX_BATCH_FILES": "max_batch_files",
        "MIN_FILE_AGE_SECONDS": "min_file_age_seconds",
        "MAX_CONCURRENCY": "max_concurrency",
        "OUTPUT_SUFFIX": "output_suffix",
        "MANIFEST_DIRNAME": "manifest_dirname",
        "LOCK_FILENAME": "lock_filename",
        "JOB_ID": "job_id",
        "CHECKPOINT_EVERY_BATCHES": "checkpoint_every_batches",
        "PARTITION_DEPTH": "partition_depth",
    }
    for k_env, k_cfg in map_simple.items():
        v = get(ENV_PREFIX + k_env)
        if v is None:
            continue
        try:
            if k_cfg in {"min_file_bytes", "target_file_bytes", "max_batch_files",
                         "min_file_age_seconds", "max_concurrency", "checkpoint_every_batches",
                         "partition_depth"}:
                cfg[k_cfg] = int(v)
            else:
                cfg[k_cfg] = v
        except Exception:
            continue

    # Булевы флаги
    for k_env, k_cfg in [("DRY_RUN", "dry_run"), ("PLAN_ONLY", "plan_only"),
                         ("PRESERVE_ORIGINALS", "preserve_originals"), ("FAIL_FAST", "fail_fast")]:
        v = get(ENV_PREFIX + k_env)
        if v is not None:
            cfg[k_cfg] = v.strip().lower() in ("1", "true", "yes", "y", "on")

    # Списки паттернов
    for k_env, k_cfg in [("INCLUDE", "include_glob"), ("EXCLUDE", "exclude_glob")]:
        v = get(ENV_PREFIX + k_env)
        if v:
            cfg[k_cfg] = _comma_or_multi([v])

    return cfg


def merge_configs(file_cfg: Dict[str, Any], env_cfg: Dict[str, Any], cli_ns: argparse.Namespace) -> Dict[str, Any]:
    """
    Приоритеты: CLI > ENV > FILE > дефолты CompactionConfig.
    """
    merged: Dict[str, Any] = {}
    # Базовые поля из файла/ENV
    for src in (file_cfg, env_cfg):
        for k, v in src.items():
            merged[k] = v

    # CLI перетирает
    def _set_if(name: str, value: Any):
        if value is not None:
            merged[name] = value

    _set_if("root", cli_ns.root)
    _set_if("include_glob", _comma_or_multi(cli_ns.include))
    _set_if("exclude_glob", _comma_or_multi(cli_ns.exclude))
    _set_if("min_file_bytes", cli_ns.min_file_bytes)
    _set_if("target_file_bytes", cli_ns.target_file_bytes)
    _set_if("max_batch_files", cli_ns.max_batch_files)
    _set_if("min_file_age_seconds", cli_ns.min_file_age_seconds)
    _set_if("max_concurrency", cli_ns.max_concurrency)
    _set_if("dry_run", True if cli_ns.dry_run else None)
    _set_if("plan_only", True if cli_ns.plan_only else None)
    _set_if("preserve_originals", True if cli_ns.preserve_originals else None)
    _set_if("output_suffix", cli_ns.output_suffix)
    _set_if("manifest_dirname", cli_ns.manifest_dirname)
    _set_if("lock_filename", cli_ns.lock_filename)
    _set_if("job_id", cli_ns.job_id)
    _set_if("checkpoint_every_batches", cli_ns.checkpoint_every_batches)
    _set_if("fail_fast", True if cli_ns.fail_fast else None)
    _set_if("partition_depth", cli_ns.partition_depth)

    return merged


# ------------------------------ Логирование ----------------------------------

def setup_logging(level: str, fmt: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        class JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                payload = {
                    "ts": int(time.time() * 1000),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                }
                if record.exc_info:
                    payload["exc_info"] = self.formatException(record.exc_info)
                return json.dumps(payload, ensure_ascii=False)
        h.setFormatter(JsonFormatter())
    else:
        h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    root.addHandler(h)
    root.setLevel(lvl)


# ------------------------------ Основная логика -------------------------------

def _make_config(merged: Dict[str, Any]) -> CompactionConfig:
    # Заполняем списки по умолчанию, если не заданы
    include_glob = tuple(merged.get("include_glob") or ("**/*.csv", "**/*.parquet", "**/*.bin"))
    exclude_glob = tuple(merged.get("exclude_glob") or ())
    # Удаляем пустые строки, если вдруг попали
    include_glob = tuple([g for g in include_glob if g])
    exclude_glob = tuple([g for g in exclude_glob if g])

    return CompactionConfig(
        root=str(merged.get("root") or "."),
        include_glob=include_glob,
        exclude_glob=exclude_glob,
        min_file_bytes=int(merged.get("min_file_bytes") or 64 * 1024),
        target_file_bytes=int(merged.get("target_file_bytes") or 256 * 1024 * 1024),
        max_batch_files=int(merged.get("max_batch_files") or 500),
        min_file_age_seconds=int(merged.get("min_file_age_seconds") or 5 * 60),
        max_concurrency=int(merged.get("max_concurrency") or 4),
        dry_run=bool(merged.get("dry_run") or False),
        plan_only=bool(merged.get("plan_only") or False),
        preserve_originals=bool(merged.get("preserve_originals") or False),
        output_suffix=str(merged.get("output_suffix") or ".compact"),
        manifest_dirname=str(merged.get("manifest_dirname") or "_compaction"),
        lock_filename=str(merged.get("lock_filename") or ".compaction.lock"),
        job_id=str(merged.get("job_id") or ""),
        checkpoint_every_batches=int(merged.get("checkpoint_every_batches") or 10),
        fail_fast=bool(merged.get("fail_fast") or False),
        partition_depth=int(merged.get("partition_depth") or 0),
    )


def _install_signal_handlers() -> None:
    def _handler(signum, frame):
        LOG.warning("Received signal %s, attempting graceful shutdown...", signum)
        raise KeyboardInterrupt()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except Exception:
            # Не во всех окружениях (Windows) разрешено переопределять обработчик
            pass


def _setup_observability(cli: argparse.Namespace):
    if ObservabilityAdapter is None:
        return None
    provider = (cli.obs_provider or "").strip().lower() or os.getenv("DF_OBS_PROVIDER", "noop")
    cfg = ObservabilityConfig(
        provider=provider,
        service_name=cli.obs_service_name,
        service_namespace="datafabric",
        service_version="cli-compaction",
        otel_endpoint=cli.obs_endpoint,
        prom_namespace="df",
    )
    try:
        return ObservabilityAdapter(cfg)
    except Exception:
        return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    setup_logging(args.log_level, args.log_format)
    _install_signal_handlers()

    # Загружаем конфиг: файл -> ENV -> CLI merge
    try:
        file_cfg = load_config_file(args.config)
    except Exception as e:
        LOG.error("Failed to read config file: %r", e)
        return 1
    env_cfg = env_config()
    merged = merge_configs(file_cfg, env_cfg, args)

    if not merged.get("root"):
        LOG.error("Root directory is not specified (use --root or DF_COMPACTION_ROOT or config file).")
        return 1

    cfg = _make_config(merged)

    LOG.info("Starting compaction: root=%s job_id=%s dry_run=%s plan_only=%s",
             cfg.root, cfg.job_id or "<auto>", cfg.dry_run, cfg.plan_only)

    obs = _setup_observability(args)
    if obs:
        c_errors = obs.counter("compaction_errors_total", tags={"component": "cli"})
        c_runs = obs.counter("compaction_runs_total", tags={"component": "cli"})
        h_dur = obs.histogram("compaction_duration_ms", unit="ms", tags={"component": "cli"})
    else:
        c_errors = lambda v, t=None: None  # noqa: E731
        c_runs = lambda v, t=None: None    # noqa: E731
        h_dur = lambda v, t=None: None     # noqa: E731

    t0 = time.time()
    try:
        exec_ = CompactionExecutor(cfg)
        # Выполнение (асинхронный executor)
        import asyncio
        metrics = asyncio.run(exec_.execute())
        duration_ms = (time.time() - t0) * 1000.0
        h_dur(duration_ms)
        c_runs(1)

        # Вывод метрик
        summary = {
            "planned_batches": metrics.planned_batches,
            "processed_batches": metrics.processed_batches,
            "failures": metrics.failures,
            "files_in": metrics.files_in,
            "files_out": metrics.files_out,
            "bytes_in": metrics.bytes_in,
            "bytes_out": metrics.bytes_out,
            "duration_seconds": round(metrics.duration_seconds, 3),
            "root": cfg.root,
            "job_id": cfg.job_id,
            "dry_run": cfg.dry_run,
            "plan_only": cfg.plan_only,
        }
        if args.print_metrics_json or args.log_format == "json":
            print(json.dumps(summary, ensure_ascii=False))
        else:
            LOG.info("Summary: %s", summary)

        # Коды возврата
        if cfg.plan_only or cfg.dry_run:
            return 10
        if metrics.failures > 0:
            return 20
        return 0

    except KeyboardInterrupt:
        LOG.error("Interrupted by user.")
        c_errors(1, {"reason": "interrupt"})
        return 130
    except Exception as e:
        LOG.exception("Fatal error: %s", e)
        c_errors(1, {"reason": "exception"})
        return 1
    finally:
        try:
            if obs:
                import asyncio
                asyncio.run(obs.shutdown())  # type: ignore
        except Exception:
            pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

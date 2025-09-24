# neuroforge-core/cli/tools/evaluate.py
# -*- coding: utf-8 -*-
"""
Промышленный асинхронный CLI для оценки моделей/агентов.

Возможности:
- Асинхронная параллельная инференция через внешний командный адаптер (stdin->stdout).
- Поддержка датасетов: .jsonl / .json / .csv  (поля: id, input, target; допускается header для CSV).
- Метрики: exact_match, f1, rouge_l, levenshtein_ratio, cer, wer, substr, regex.
- Таймауты/ретраи с экспоненциальной паузой, контроль concurrency.
- Детерминированные прогоны (seed), лимит на количество примеров (--limit), шифл.
- JSON-логирование (консоль + файл), артефакты: results.jsonl, summary.json, optional: results.csv, summary.md.
- Автоматическая директория запуска: runs/{ts}_{short_dataset_hash}.
- Без внешних зависимостей (PyYAML опционально для конфигов .yaml/.yml).

Примеры:
  1) Минимально:
     python -m neuroforge_core.cli.tools.evaluate \
       --dataset data/qa.jsonl --model-cmd "python my_model.py" --output ./runs

  2) С concurrency и таймаутом:
     python -m neuroforge_core.cli.tools.evaluate \
       --dataset data/qa.jsonl --model-cmd "python my_model.py --mode serve" \
       --max-concurrency 8 --timeout-sec 30

  3) С ретраями и лимитом примеров:
     python -m neuroforge_core.cli.tools.evaluate \
       --dataset data/qa.jsonl --model-cmd "./bin/infer" \
       --retries 2 --limit 100 --shuffle --seed 42

  4) С выбором метрик и regex-паттерном:
     python -m neuroforge_core.cli.tools.evaluate \
       --dataset data/cls.csv --model-cmd "python classify.py" \
       --metrics exact_match,f1,regex --regex-pattern "^[A-Z]{3}$"

  5) Из конфига:
     python -m neuroforge_core.cli.tools.evaluate --config eval.json

Формат датасета (JSONL):
  {"id":"q1", "input":"2+2=?", "target":"4"}
  {"id":"q2", "input":"Capital of France?", "target":"Paris"}

Выходные артефакты:
  results.jsonl   — по одному объекту на строку: {id, input, target, prediction, timings, metrics}
  summary.json    — агрегированные метрики и информация о прогоне
  results.csv     — опционально
  summary.md      — опционально

Запуск как модуль:
  python -m neuroforge_core.cli.tools.evaluate <args>
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import hashlib
import io
import json
import logging
import os
import random
import re
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, TypedDict, Callable

# Опционально поддержим YAML, если установлен PyYAML
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # noqa: N816


VERSION = "1.0.0"


# ---------------------- ЛОГИРОВАНИЕ ---------------------- #
class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "funcName": record.funcName,
            "lineNo": record.lineno,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(log_dir: Path, level: str = "INFO") -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "evaluate.log"

    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Консоль
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(JsonLogFormatter())
    sh.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(sh)

    # Файл
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(JsonLogFormatter())
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(fh)

    logging.getLogger(__name__).info("logging_initialized", extra={"log_path": str(log_path)})
    return log_path


# ---------------------- УТИЛИТЫ ---------------------- #
def now_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def short_hash(data: bytes, n: int = 8) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def normalize_text(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def tokenize(s: str) -> List[str]:
    s = normalize_text(s)
    return s.split(" ") if s else []


def lcs(a: List[str], b: List[str]) -> int:
    # Длина наибольшей общей подпоследовательности (для ROUGE-L)
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        for j in range(len(b) - 1, -1, -1):
            if a[i] == b[j]:
                dp[i][j] = 1 + dp[i + 1][j + 1]
            else:
                dp[i][j] = max(dp[i + 1][j], dp[i][j + 1])
    return dp[0][0]


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev = dp[0]
        dp[0] = i
        for j, cb in enumerate(b, 1):
            cur = dp[j]
            cost = 0 if ca == cb else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = cur
    return dp[-1]


# ---------------------- ТИПЫ ---------------------- #
class Sample(TypedDict):
    id: str
    input: str
    target: str


@dataclass
class Prediction:
    sample_id: str
    input: str
    target: str
    prediction: str
    started_at: str
    finished_at: str
    latency_sec: float
    metrics: Dict[str, float]


# ---------------------- ЗАГРУЗКА ДАННЫХ ---------------------- #
def load_dataset(path: Path) -> List[Sample]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    ext = path.suffix.lower()
    rows: List[Sample] = []
    if ext == ".jsonl":
        with path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                obj = json.loads(line)
                rows.append(normalize_sample(obj, line_num))
    elif ext == ".json":
        data = json.loads(read_text(path))
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            data = data["data"]
        if not isinstance(data, list):
            raise ValueError("JSON dataset must be a list or {data:[...]}")
        for idx, obj in enumerate(data, 1):
            rows.append(normalize_sample(obj, idx))
    elif ext == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, 1):
                obj = {"id": row.get("id") or f"row{idx}", "input": row.get("input", ""), "target": row.get("target", "")}
                rows.append(normalize_sample(obj, idx))
    else:
        raise ValueError(f"Unsupported dataset extension: {ext}")
    if not rows:
        raise ValueError("Dataset is empty")
    return rows


def normalize_sample(obj: Dict[str, Any], idx: int) -> Sample:
    try:
        sid = str(obj["id"]) if "id" in obj else f"row{idx}"
        inp = str(obj["input"])
        tgt = str(obj["target"])
        return Sample(id=sid, input=inp, target=tgt)
    except Exception as e:
        raise ValueError(f"Bad sample at index {idx}: {e}")


# ---------------------- МЕТРИКИ ---------------------- #
def metric_exact_match(pred: str, tgt: str) -> float:
    return 1.0 if normalize_text(pred) == normalize_text(tgt) else 0.0


def metric_substr(pred: str, tgt: str) -> float:
    return 1.0 if normalize_text(tgt) in normalize_text(pred) else 0.0


def metric_f1(pred: str, tgt: str) -> float:
    p_tokens, t_tokens = tokenize(pred), tokenize(tgt)
    if not p_tokens and not t_tokens:
        return 1.0
    if not p_tokens or not t_tokens:
        return 0.0
    common = 0
    t_counts: Dict[str, int] = {}
    for t in t_tokens:
        t_counts[t] = t_counts.get(t, 0) + 1
    for w in p_tokens:
        if t_counts.get(w, 0) > 0:
            common += 1
            t_counts[w] -= 1
    if common == 0:
        return 0.0
    precision = common / len(p_tokens)
    recall = common / len(t_tokens)
    return 2 * precision * recall / (precision + recall)


def metric_rouge_l(pred: str, tgt: str) -> float:
    p, t = tokenize(pred), tokenize(tgt)
    if not p and not t:
        return 1.0
    if not p or not t:
        return 0.0
    l = lcs(p, t)
    if l == 0:
        return 0.0
    prec = l / len(p)
    rec = l / len(t)
    return 0.0 if (prec + rec) == 0 else (2 * prec * rec / (prec + rec))


def metric_levenshtein_ratio(pred: str, tgt: str) -> float:
    # Нормированное сходство 1 - dist/max_len
    a, b = pred or "", tgt or ""
    d = levenshtein_distance(a, b)
    m = max(len(a), len(b))
    return 1.0 if m == 0 else 1.0 - d / m


def metric_cer(pred: str, tgt: str) -> float:
    # Character Error Rate (чем меньше, тем лучше) → конвертируем в качество (1 - CER)
    a, b = pred or "", tgt or ""
    d = levenshtein_distance(a, b)
    m = max(1, len(b))
    cer = d / m
    return max(0.0, 1.0 - cer)


def metric_wer(pred: str, tgt: str) -> float:
    # Word Error Rate (через левенштейн по словам) → качество 1 - WER
    a, b = tokenize(pred), tokenize(tgt)
    # восстановим строки с разделителем, чтобы переиспользовать левенштейн
    sa, sb = " ".join(a), " ".join(b)
    d = levenshtein_distance(sa, sb)
    m = max(1, len(sb.split(" "))) if sb else 1
    wer = d / m
    return max(0.0, 1.0 - wer)


def metric_regex(pred: str, pattern: str) -> float:
    try:
        return 1.0 if re.search(pattern, pred) else 0.0
    except re.error:
        return 0.0


ALL_METRICS: Dict[str, Callable[..., float]] = {
    "exact_match": metric_exact_match,
    "substr": metric_substr,
    "f1": metric_f1,
    "rouge_l": metric_rouge_l,
    "levenshtein_ratio": metric_levenshtein_ratio,
    "cer": metric_cer,
    "wer": metric_wer,
    "regex": metric_regex,  # требует pattern
}


# ---------------------- АДАПТЕР МОДЕЛИ ---------------------- #
class BaseModelAdapter:
    async def infer(self, prompt: str, sample: Sample) -> str:
        raise NotImplementedError


class CommandAdapter(BaseModelAdapter):
    """
    Запускает указанную команду для каждого примера.
    Передаёт prompt во stdin, читает stdout как предсказание.
    """
    def __init__(self, cmd: str, timeout_sec: int = 30) -> None:
        self.cmd = cmd
        self.timeout_sec = timeout_sec

    async def infer(self, prompt: str, sample: Sample) -> str:
        # Запускаем через оболочку для совместимости с пайпами/аргументами
        proc = await asyncio.create_subprocess_shell(
            self.cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=prompt.encode("utf-8")), timeout=self.timeout_sec)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise TimeoutError(f"Model command timeout after {self.timeout_sec}s for sample {sample['id']}")

        # Логируем stderr на уровень debug — оно попадёт в файл-лог
        if stderr:
            logging.getLogger(__name__).debug("model_stderr", extra={"sample_id": sample["id"], "stderr": stderr.decode("utf-8", "ignore")})

        pred = stdout.decode("utf-8", "ignore").strip()
        return pred


class EchoAdapter(BaseModelAdapter):
    """
    Бейзлайн: возвращает вход как есть (для отладки).
    """
    async def infer(self, prompt: str, sample: Sample) -> str:
        return prompt


# ---------------------- ОЦЕНКА ---------------------- #
@dataclass
class EvalConfig:
    dataset: Path
    output: Path
    model_cmd: Optional[str] = None
    adapter: str = "command"  # or "echo"
    max_concurrency: int = 4
    timeout_sec: int = 30
    retries: int = 0
    retry_backoff_base: float = 0.5  # секунды
    metrics: List[str] = dataclasses.field(default_factory=lambda: ["exact_match", "f1", "rouge_l", "levenshtein_ratio"])
    regex_pattern: Optional[str] = None
    limit: Optional[int] = None
    shuffle: bool = False
    seed: int = 42
    write_csv: bool = True
    write_md: bool = True
    log_level: str = "INFO"


def load_config_file(path: Path) -> Dict[str, Any]:
    text = read_text(path)
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed but YAML config was provided")
        return dict(yaml.safe_load(text) or {})
    return dict(json.loads(text))


def merge_cli_with_config(cli: argparse.Namespace) -> EvalConfig:
    cfg: Dict[str, Any] = {}
    if cli.config:
        cfg.update(load_config_file(Path(cli.config)))
    # CLI overrides
    if cli.dataset:
        cfg["dataset"] = str(cli.dataset)
    if cli.output:
        cfg["output"] = str(cli.output)
    if cli.model_cmd is not None:
        cfg["model_cmd"] = cli.model_cmd
    if cli.adapter is not None:
        cfg["adapter"] = cli.adapter
    if cli.max_concurrency is not None:
        cfg["max_concurrency"] = cli.max_concurrency
    if cli.timeout_sec is not None:
        cfg["timeout_sec"] = cli.timeout_sec
    if cli.retries is not None:
        cfg["retries"] = cli.retries
    if cli.retry_backoff_base is not None:
        cfg["retry_backoff_base"] = cli.retry_backoff_base
    if cli.metrics is not None:
        cfg["metrics"] = [m.strip() for m in cli.metrics.split(",")] if isinstance(cli.metrics, str) else cli.metrics
    if cli.regex_pattern is not None:
        cfg["regex_pattern"] = cli.regex_pattern
    if cli.limit is not None:
        cfg["limit"] = cli.limit
    if cli.shuffle is not None:
        cfg["shuffle"] = cli.shuffle
    if cli.seed is not None:
        cfg["seed"] = cli.seed
    if cli.write_csv is not None:
        cfg["write_csv"] = cli.write_csv
    if cli.write_md is not None:
        cfg["write_md"] = cli.write_md
    if cli.log_level is not None:
        cfg["log_level"] = cli.log_level

    # Валидация и нормализация
    dataset = Path(cfg.get("dataset"))
    output = Path(cfg.get("output", "./runs"))
    metrics = cfg.get("metrics") or []
    for m in metrics:
        if m not in ALL_METRICS:
            raise ValueError(f"Unknown metric: {m}")
    if cfg.get("adapter", "command") == "command" and not cfg.get("model_cmd"):
        raise ValueError("--model-cmd is required for adapter=command")

    return EvalConfig(
        dataset=dataset,
        output=output,
        model_cmd=cfg.get("model_cmd"),
        adapter=cfg.get("adapter", "command"),
        max_concurrency=int(cfg.get("max_concurrency", 4)),
        timeout_sec=int(cfg.get("timeout_sec", 30)),
        retries=int(cfg.get("retries", 0)),
        retry_backoff_base=float(cfg.get("retry_backoff_base", 0.5)),
        metrics=metrics,
        regex_pattern=cfg.get("regex_pattern"),
        limit=(int(cfg["limit"]) if cfg.get("limit") is not None else None),
        shuffle=bool(cfg.get("shuffle", False)),
        seed=int(cfg.get("seed", 42)),
        write_csv=bool(cfg.get("write_csv", True)),
        write_md=bool(cfg.get("write_md", True)),
        log_level=str(cfg.get("log_level", "INFO")),
    )


def pick_adapter(cfg: EvalConfig) -> BaseModelAdapter:
    if cfg.adapter == "echo":
        return EchoAdapter()
    return CommandAdapter(cfg.model_cmd or "", timeout_sec=cfg.timeout_sec)


# ---------------------- РАННЕР ---------------------- #
async def evaluate(cfg: EvalConfig) -> Dict[str, Any]:
    # Подготовка окружения
    rows = load_dataset(cfg.dataset)
    raw_bytes = b"".join(json.dumps(r, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n" for r in rows)
    d_hash = short_hash(raw_bytes)
    if cfg.shuffle:
        rnd = random.Random(cfg.seed)
        rnd.shuffle(rows)
    if cfg.limit is not None:
        rows = rows[: cfg.limit]

    run_dir = cfg.output / f"{time.strftime('%Y%m%d_%H%M%S')}_{d_hash}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = setup_logging(run_dir, cfg.log_level)

    logging.info(json.dumps({"event": "run_start", "version": VERSION, "dataset": str(cfg.dataset), "run_dir": str(run_dir)}, ensure_ascii=False))

    # Адаптер модели
    adapter = pick_adapter(cfg)

    # Артефакты
    results_path = run_dir / "results.jsonl"
    summary_path = run_dir / "summary.json"
    results_csv_path = run_dir / "results.csv"
    summary_md_path = run_dir / "summary.md"

    # Оценка
    sem = asyncio.Semaphore(cfg.max_concurrency)
    predictions: List[Prediction] = []
    total = len(rows)
    started = time.perf_counter()

    async def infer_with_retry(sample: Sample) -> Prediction:
        nonlocal adapter
        attempt = 0
        last_err: Optional[Exception] = None
        while attempt <= cfg.retries:
            started_at = now_utc_iso()
            t0 = time.perf_counter()
            try:
                async with sem:
                    pred = await adapter.infer(sample["input"], sample)
                latency = time.perf_counter() - t0
                finished_at = now_utc_iso()
                # Метрики
                metrics_res: Dict[str, float] = {}
                for m in cfg.metrics:
                    if m == "regex":
                        metrics_res[m] = ALL_METRICS[m](pred, cfg.regex_pattern or "")  # type: ignore[arg-type]
                    else:
                        metrics_res[m] = ALL_METRICS[m](pred, sample["target"])
                return Prediction(
                    sample_id=sample["id"],
                    input=sample["input"],
                    target=sample["target"],
                    prediction=pred,
                    started_at=started_at,
                    finished_at=finished_at,
                    latency_sec=latency,
                    metrics=metrics_res,
                )
            except Exception as e:
                last_err = e
                backoff = cfg.retry_backoff_base * (2 ** attempt)
                logging.warning(json.dumps({
                    "event": "infer_error",
                    "sample_id": sample["id"],
                    "attempt": attempt,
                    "error": str(e),
                    "backoff_sec": backoff
                }, ensure_ascii=False))
                if attempt == cfg.retries:
                    # Возвращаем пустое предсказание с нулевыми метриками
                    finished_at = now_utc_iso()
                    latency = time.perf_counter() - t0
                    metrics_res = {m: 0.0 for m in cfg.metrics}
                    return Prediction(
                        sample_id=sample["id"],
                        input=sample["input"],
                        target=sample["target"],
                        prediction="",
                        started_at=started_at,
                        finished_at=finished_at,
                        latency_sec=latency,
                        metrics=metrics_res,
                    )
                await asyncio.sleep(backoff)
                attempt += 1
        # Теоретически недостижимо
        raise RuntimeError(f"Unreachable retry loop for sample {sample['id']}: {last_err}")

    # Обработка сигналов
    stop_event = asyncio.Event()

    def _handle_sigint():
        logging.error(json.dumps({"event": "signal", "type": "SIGINT"}, ensure_ascii=False))
        stop_event.set()

    try:
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, _handle_sigint)
    except NotImplementedError:
        pass  # Windows/CI

    async def progress_printer():
        # Простой прогресс без сторонних зависимостей
        while not stop_event.is_set():
            done = len(predictions)
            elapsed = time.perf_counter() - started
            rate = done / elapsed if elapsed > 0 else 0.0
            eta = (total - done) / rate if rate > 0 else float("inf")
            info = {
                "event": "progress",
                "done": done,
                "total": total,
                "rate_it_s": round(rate, 2),
                "elapsed_s": round(elapsed, 2),
                "eta_s": None if eta == float("inf") else round(eta, 2),
            }
            logging.info(json.dumps(info, ensure_ascii=False))
            if done >= total:
                break
            await asyncio.sleep(2.0)

    # Запуск задач
    prog_task = asyncio.create_task(progress_printer())
    try:
        for fut in asyncio.as_completed([infer_with_retry(s) for s in rows]):
            if stop_event.is_set():
                break
            pred = await fut
            predictions.append(pred)
    finally:
        stop_event.set()
        with contextlib.suppress(Exception):
            await prog_task

    # Запись результатов
    with results_path.open("w", encoding="utf-8") as f:
        for p in predictions:
            f.write(json.dumps(dataclasses.asdict(p), ensure_ascii=False) + "\n")

    # Агрегация метрик
    agg: Dict[str, float] = {}
    if predictions:
        for m in cfg.metrics:
            vals = [p.metrics.get(m, 0.0) for p in predictions]
            agg[m] = sum(vals) / max(1, len(vals))
    latency_avg = sum(p.latency_sec for p in predictions) / max(1, len(predictions))
    duration = time.perf_counter() - started

    summary = {
        "version": VERSION,
        "started_at": now_utc_iso(),
        "dataset": str(cfg.dataset),
        "dataset_size": total,
        "evaluated": len(predictions),
        "run_dir": str(run_dir),
        "results_path": str(results_path),
        "metrics": agg,
        "latency_avg_sec": latency_avg,
        "duration_sec": duration,
        "adapter": cfg.adapter,
        "model_cmd": cfg.model_cmd,
        "regex_pattern": cfg.regex_pattern,
        "concurrency": cfg.max_concurrency,
        "retries": cfg.retries,
        "timeout_sec": cfg.timeout_sec,
        "seed": cfg.seed,
        "shuffle": cfg.shuffle,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # Доп. форматы (опционально)
    if cfg.write_csv:
        with results_csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            # Простая табличка
            writer.writerow(["id", "input", "target", "prediction", "latency_sec"] + cfg.metrics)
            for p in predictions:
                row = [p.sample_id, p.input, p.target, p.prediction, f"{p.latency_sec:.6f}"] + [f"{p.metrics.get(m, 0.0):.6f}" for m in cfg.metrics]
                writer.writerow(row)

    if cfg.write_md:
        md = io.StringIO()
        md.write(f"# Evaluation Summary\n\n")
        md.write(f"- Version: {VERSION}\n")
        md.write(f"- Dataset: `{cfg.dataset}`\n")
        md.write(f"- Samples: {total}\n")
        md.write(f"- Evaluated: {len(predictions)}\n")
        md.write(f"- Concurrency: {cfg.max_concurrency}\n")
        md.write(f"- Timeout (s): {cfg.timeout_sec}\n")
        md.write(f"- Retries: {cfg.retries}\n")
        md.write(f"- Duration (s): {duration:.2f}\n")
        md.write(f"- Avg latency (s): {latency_avg:.4f}\n")
        md.write(f"- Metrics: {', '.join(cfg.metrics)}\n")
        if agg:
            md.write("\n## Aggregated metrics\n\n")
            for k, v in agg.items():
                md.write(f"- **{k}**: {v:.6f}\n")
        summary_md_path.write_text(md.getvalue(), encoding="utf-8")

    logging.info(json.dumps({"event": "run_finish", "summary": str(summary_path)}, ensure_ascii=False))
    return summary


# ---------------------- CLI ---------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NeuroForge Evaluate CLI", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--config", type=str, default=None, help="Путь к конфигу (json|yaml)")
    p.add_argument("--dataset", type=str, required=False, help="Путь к датасету (.jsonl|.json|.csv)")
    p.add_argument("--output", type=str, default="./runs", help="Директория для артефактов")
    p.add_argument("--adapter", type=str, choices=["command", "echo"], default="command", help="Тип адаптера модели")
    p.add_argument("--model-cmd", type=str, default=None, help="Команда запуска модели (требуется для adapter=command)")
    p.add_argument("--max-concurrency", type=int, default=4, help="Максимум одновременных запросов")
    p.add_argument("--timeout-sec", type=int, default=30, help="Таймаут инференции, сек")
    p.add_argument("--retries", type=int, default=0, help="Количество ретраев")
    p.add_argument("--retry-backoff-base", type=float, default=0.5, help="Базовая задержка между ретраями (экспоненциально)")
    p.add_argument("--metrics", type=str, default="exact_match,f1,rouge_l,levenshtein_ratio", help="Список метрик через запятую")
    p.add_argument("--regex-pattern", type=str, default=None, help="Паттерн для метрики regex")
    p.add_argument("--limit", type=int, default=None, help="Ограничить число примеров")
    p.add_argument("--shuffle", action="store_true", help="Перемешать датасет перед прогоном")
    p.add_argument("--seed", type=int, default=42, help="Сид для детерминизма")
    p.add_argument("--write-csv", action="store_true", help="Сохранить также results.csv")
    p.add_argument("--no-write-csv", dest="write_csv", action="store_false", help="Не сохранять results.csv")
    p.add_argument("--write-md", action="store_true", help="Сохранить также summary.md")
    p.add_argument("--no-write-md", dest="write_md", action="store_false", help="Не сохранять summary.md")
    p.add_argument("--log-level", type=str, default="INFO", help="Уровень логирования")
    p.set_defaults(write_csv=True, write_md=True)
    return p


async def _amain(args: argparse.Namespace) -> int:
    cfg = merge_cli_with_config(args)
    await evaluate(cfg)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        logging.error(json.dumps({"event": "aborted_by_user"}, ensure_ascii=False))
        return 130
    except Exception as e:
        # Минимально структурируем ошибку, чтобы CI/оркестраторы могли парсить
        print(json.dumps({"event": "fatal", "error": str(e)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

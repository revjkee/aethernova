# path: veilmind-core/cli/tools/prompt_guard_eval.py
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

# Опциональные зависимости
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from pydantic import BaseModel, Field, StrictBool, StrictInt, StrictStr, field_validator
except Exception as e:  # pragma: no cover
    print(json.dumps({"level": "error", "msg": "pydantic v2 required", "err": str(e)}))
    sys.exit(1)

# -----------------------------
# Модели входа/выхода
# -----------------------------

class Sample(BaseModel):
    id: Union[StrictStr, StrictInt]
    text: StrictStr
    # Бинарная разметка (если доступна)
    allow: Optional[StrictBool] = None
    # Многоярлыкная разметка (список категорий нарушений)
    labels: List[StrictStr] = Field(default_factory=list)
    # Произвольные доп. поля
    meta: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("labels")
    @classmethod
    def _norm_labels(cls, v: List[str]) -> List[str]:
        return sorted(set([str(x).strip() for x in v if str(x).strip()]))


class Decision(BaseModel):
    sample_id: Union[str, int]
    allow: bool
    categories: List[str] = Field(default_factory=list)
    reason: Optional[str] = None
    latency_ms: float
    error: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class Metrics(BaseModel):
    total: int
    decided: int
    errors: int
    # Бинарные метрики (positive=deny)
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    # По категориям (micro/macro)
    micro_precision: Optional[float] = None
    micro_recall: Optional[float] = None
    micro_f1: Optional[float] = None
    macro_precision: Optional[float] = None
    macro_recall: Optional[float] = None
    macro_f1: Optional[float] = None
    confusion: Dict[str, int] = Field(default_factory=dict)  # TP, FP, TN, FN
    per_label: Dict[str, Dict[str, float]] = Field(default_factory=dict)


# -----------------------------
# Клиенты OPA
# -----------------------------

class OpaClientBase:
    async def evaluate(self, query_path: str, input_obj: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class OpaHttpClient(OpaClientBase):
    def __init__(self, base_url: str, timeout_s: float = 5.0, retries: int = 2, backoff_s: float = 0.25):
        if httpx is None:
            raise RuntimeError("httpx is not installed")
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.retries = retries
        self.backoff_s = backoff_s

    async def evaluate(self, query_path: str, input_obj: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/data/{query_path.lstrip('/')}"
        attempt = 0
        while True:
            attempt += 1
            t0 = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                    resp = await client.post(url, json={"input": input_obj})
                    resp.raise_for_status()
                    data = resp.json()
                    # Формат OPA: {"result": {...}}
                    out = data.get("result")
                    if out is None:
                        raise ValueError("OPA HTTP: missing 'result'")
                    return out
            except Exception as e:  # pragma: no cover
                if attempt > self.retries:
                    raise
                await asyncio.sleep(self.backoff_s * (2 ** (attempt - 1)))


class OpaLocalClient(OpaClientBase):
    """
    Локальный вызов 'opa eval' через subprocess.
    Требует установленный бинарь 'opa' в PATH.
    """
    def __init__(self, rego_paths: Sequence[str], query: str, timeout_s: float = 5.0):
        self.rego_paths = [str(Path(p)) for p in rego_paths]
        self.query = query  # например, 'data.prompt_safety.guard'
        self.timeout_s = timeout_s

    async def evaluate(self, query_path: str, input_obj: Dict[str, Any]) -> Dict[str, Any]:
        # query_path игнорируем: используем self.query
        import asyncio.subprocess as asp
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as f:
            json.dump(input_obj, f, ensure_ascii=False)
            f.flush()
            input_file = f.name
        cmd = ["opa", "eval", "-f", "json"]
        for p in self.rego_paths:
            cmd += ["-d", p]
        cmd += ["-i", input_file, self.query]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asp.PIPE, stderr=asp.PIPE)
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
            except asyncio.TimeoutError:
                proc.kill()
                raise TimeoutError("opa eval timeout")
            if proc.returncode != 0:
                raise RuntimeError(f"opa eval failed: {err_b.decode('utf-8', 'ignore')}")
            data = json.loads(out_b.decode("utf-8"))
            # Формат результата 'opa eval -f json':
            # {"result":[{"expressions":[{"value": <VAL>, "text": "..."}]}]}
            result_arr = data.get("result") or []
            if not result_arr:
                raise ValueError("opa eval: empty result")
            exprs = result_arr[0].get("expressions") or []
            if not exprs:
                raise ValueError("opa eval: missing expressions")
            val = exprs[0].get("value")
            if val is None:
                raise ValueError("opa eval: null value")
            return val
        finally:
            try:
                os.unlink(input_file)
            except Exception:
                pass


# -----------------------------
# Загрузка датасета
# -----------------------------

def load_dataset(path: Union[str, Path]) -> List[Sample]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))

    rows: List[Sample] = []

    if p.suffix.lower() == ".jsonl":
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                rows.append(_row_to_sample(obj))
        return rows

    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for obj in data:
                rows.append(_row_to_sample(obj))
            return rows
        raise ValueError("JSON must be a list of objects")

    # CSV
    with p.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for obj in reader:
            rows.append(_row_to_sample(obj))
    return rows


def _row_to_sample(obj: Dict[str, Any]) -> Sample:
    # Heuristics: поля id/text обязательны; allow в ['allow','label','y']; labels в ['labels','categories','violations']
    id_val = obj.get("id") or obj.get("sample_id") or obj.get("_id")
    text_val = obj.get("text") or obj.get("prompt") or obj.get("input")
    if id_val is None or text_val is None:
        raise ValueError("dataset row must have 'id' and 'text' (or aliases 'sample_id'/'prompt')")
    allow = obj.get("allow")
    if allow is None and "label" in obj:
        lab = obj.get("label")
        allow = True if str(lab).lower() in ("allow", "allowed", "1", "true", "safe") else (
            False if str(lab).lower() in ("deny", "blocked", "0", "false", "unsafe") else None
        )
    labels = obj.get("labels") or obj.get("categories") or obj.get("violations") or []
    if isinstance(labels, str):
        # поддержка "A;B;C" или "A,B,C" или JSON‑массива
        ls = labels.strip()
        if ls.startswith("["):
            try:
                labels = json.loads(ls)
            except Exception:
                labels = [x.strip() for x in ls.strip("[]").split(",") if x.strip()]
        else:
            sep = ";" if ";" in ls else ","
            labels = [x.strip() for x in ls.split(sep) if x.strip()]
    return Sample(id=id_val, text=str(text_val), allow=allow, labels=list(labels), meta={
        k: v for k, v in obj.items() if k not in {"id", "sample_id", "_id", "text", "prompt", "input", "allow", "label", "labels", "categories", "violations"}
    })


# -----------------------------
# Нормализация ответа политики
# -----------------------------

def normalize_policy_output(val: Any) -> Tuple[bool, List[str], Optional[str]]:
    """
    Ожидаемые формы:
      1) {"allow": bool, "categories": [...], "reason": "..."}  # рекомендовано
      2) {"decision": {"allow": bool, "categories": [...], "reason": "..."}}  # альтернативно
      3) bool  # только allow
    Возвращает (allow, categories, reason).
    """
    if isinstance(val, bool):
        return bool(val), [], None
    if isinstance(val, dict):
        if "allow" in val:
            allow = bool(val.get("allow"))
            cats = _ensure_str_list(val.get("categories", []))
            return allow, cats, _safe_str(val.get("reason"))
        if "decision" in val and isinstance(val["decision"], dict):
            d = val["decision"]
            allow = bool(d.get("allow"))
            cats = _ensure_str_list(d.get("categories", []))
            return allow, cats, _safe_str(d.get("reason"))
    # Нестандартный ответ — сериализуем как raw
    return False, [], f"unexpected policy output type={type(val).__name__}"


def _ensure_str_list(x: Any) -> List[str]:
    if isinstance(x, list):
        return [str(i) for i in x if str(i).strip()]
    return []


def _safe_str(x: Any) -> Optional[str]:
    return None if x is None else str(x)


# -----------------------------
# Метрики
# -----------------------------

def binary_metrics(gt: List[Optional[bool]], pr: List[Optional[bool]]) -> Tuple[Dict[str, int], Dict[str, float]]:
    # positive = deny (False=allow -> negative; True=deny -> positive). Для консистентности преобразуем.
    # Здесь мы считаем блокировку (deny) позитивным классом.
    TP = FP = TN = FN = 0
    used = 0
    for g, p in zip(gt, pr):
        if g is None or p is None:
            continue
        used += 1
        g_pos = (g is False)  # deny в разметке: False => позитивный (нужно блокировать)
        p_pos = (p is False)
        if p_pos and g_pos:
            TP += 1
        elif p_pos and not g_pos:
            FP += 1
        elif not p_pos and not g_pos:
            TN += 1
        else:
            FN += 1
    acc = (TP + TN) / used if used else None
    precision = TP / (TP + FP) if (TP + FP) else None
    recall = TP / (TP + FN) if (TP + FN) else None
    f1 = (2 * precision * recall) / (precision + recall) if precision not in (None, 0) and recall not in (None, 0) else None
    return {"TP": TP, "FP": FP, "TN": TN, "FN": FN}, {
        "accuracy": acc, "precision": precision, "recall": recall, "f1": f1
    }

def multilabel_metrics(gt_labels: List[List[str]], pr_labels: List[List[str]]) -> Tuple[Dict[str, float], Dict[str, Dict[str, float]]]:
    # micro- и macro‑ усреднение по ярлыкам
    # соберём множество всех меток
    labels = sorted(set([l for row in gt_labels for l in row] + [l for row in pr_labels for l in row]))
    if not labels:
        return {}, {}
    # per‑label
    per: Dict[str, Dict[str, float]] = {}
    micro_TP = micro_FP = micro_FN = 0
    for lab in labels:
        TP = FP = FN = 0
        for g, p in zip(gt_labels, pr_labels):
            gset = set(g)
            pset = set(p)
            if lab in pset and lab in gset:
                TP += 1
            elif lab in pset and lab not in gset:
                FP += 1
            elif lab not in pset and lab in gset:
                FN += 1
        prec = TP / (TP + FP) if (TP + FP) else None
        rec = TP / (TP + FN) if (TP + FN) else None
        f1 = (2 * prec * rec) / (prec + rec) if prec not in (None, 0) and rec not in (None, 0) else None
        per[lab] = {"precision": _n(prec), "recall": _n(rec), "f1": _n(f1)}
        micro_TP += TP
        micro_FP += FP
        micro_FN += FN
    micro_prec = micro_TP / (micro_TP + micro_FP) if (micro_TP + micro_FP) else None
    micro_rec = micro_TP / (micro_TP + micro_FN) if (micro_TP + micro_FN) else None
    micro_f1 = (2 * micro_prec * micro_rec) / (micro_prec + micro_rec) if micro_prec not in (None, 0) and micro_rec not in (None, 0) else None

    macro_prec = _avg([v["precision"] for v in per.values()])
    macro_rec = _avg([v["recall"] for v in per.values()])
    macro_f1 = _avg([v["f1"] for v in per.values()])
    return {
        "micro_precision": _n(micro_prec),
        "micro_recall": _n(micro_rec),
        "micro_f1": _n(micro_f1),
        "macro_precision": _n(macro_prec),
        "macro_recall": _n(macro_rec),
        "macro_f1": _n(macro_f1),
    }, per

def _n(x: Optional[float]) -> Optional[float]:
    if x is None or math.isnan(x):
        return None
    return float(x)

def compute_metrics(samples: List[Sample], decisions: List[Decision]) -> Metrics:
    dec_map = {d.sample_id: d for d in decisions}
    gtb = [s.allow if s.allow is not None else None for s in samples]
    prb = [dec_map.get(s.id).allow if s.id in dec_map and dec_map[s.id].error is None else None for s in samples]
    conf, binm = binary_metrics(gtb, prb)

    gtm = [s.labels for s in samples]
    prm = [dec_map.get(s.id).categories if s.id in dec_map and dec_map[s.id].error is None else [] for s in samples]
    mlm, per = multilabel_metrics(gtm, prm)

    errors = sum(1 for d in decisions if d.error)
    decided = sum(1 for d in decisions if not d.error)

    return Metrics(
        total=len(samples),
        decided=decided,
        errors=errors,
        accuracy=_n(binm["accuracy"]),
        precision=_n(binm["precision"]),
        recall=_n(binm["recall"]),
        f1=_n(binm["f1"]),
        micro_precision=mlm.get("micro_precision"),
        micro_recall=mlm.get("micro_recall"),
        micro_f1=mlm.get("micro_f1"),
        macro_precision=mlm.get("macro_precision"),
        macro_recall=mlm.get("macro_recall"),
        macro_f1=mlm.get("macro_f1"),
        confusion=conf,
        per_label=per,
    )


# -----------------------------
# Исполнение одного примера
# -----------------------------

async def eval_one(client: OpaClientBase, query_path: str, sample: Sample) -> Decision:
    t0 = time.perf_counter()
    try:
        inp = {"text": sample.text, "meta": sample.meta, "sample_id": sample.id}
        val = await client.evaluate(query_path, inp)
        allow, cats, reason = normalize_policy_output(val)
        return Decision(sample_id=sample.id, allow=allow, categories=sorted(set(cats)), reason=reason, latency_ms=(time.perf_counter() - t0) * 1000.0, raw=val if isinstance(val, dict) else None)
    except Exception as e:
        return Decision(sample_id=sample.id, allow=False, categories=[], reason=None, latency_ms=(time.perf_counter() - t0) * 1000.0, error=str(e))


# -----------------------------
# Основной процесс
# -----------------------------

@dataclass
class Settings:
    dataset: str
    output_dir: str
    opa_url: Optional[str]
    rego: List[str]
    query: str
    path: str  # для HTTP /v1/data/<path>
    concurrency: int
    timeout_s: float
    retries: int
    backoff_s: float
    fail_on_errors: bool
    print_report: bool

def parse_args(argv: Optional[Sequence[str]] = None) -> Settings:
    p = argparse.ArgumentParser(description="Evaluate prompt safety policy (OPA/Rego) on a dataset")
    p.add_argument("--dataset", required=True, help="Path to dataset (JSONL/JSON/CSV)")
    p.add_argument("--output-dir", default="eval_out", help="Directory for results")
    p.add_argument("--opa-url", default=os.getenv("OPA_URL"), help="OPA base URL (if set, use HTTP mode)")
    p.add_argument("--rego", action="append", default=[], help="Local .rego file(s) (if no OPA URL)")
    p.add_argument("--query", default="data.prompt_safety.guard", help="OPA query for local eval")
    p.add_argument("--path", default="prompt_safety/guard", help="OPA data path for HTTP (/v1/data/<path>)")
    p.add_argument("--concurrency", type=int, default=int(os.getenv("EVAL_CONCURRENCY", "8")))
    p.add_argument("--timeout-s", type=float, default=float(os.getenv("EVAL_TIMEOUT_S", "5.0")))
    p.add_argument("--retries", type=int, default=int(os.getenv("EVAL_RETRIES", "2")))
    p.add_argument("--backoff-s", type=float, default=float(os.getenv("EVAL_BACKOFF_S", "0.25")))
    p.add_argument("--fail-on-errors", action="store_true", help="Non-zero exit if there are evaluation errors")
    p.add_argument("--print-report", action="store_true", help="Also print brief report to stdout")
    args = p.parse_args(argv)

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    return Settings(
        dataset=args.dataset,
        output_dir=str(outdir),
        opa_url=args.opa_url,
        rego=args.rego,
        query=args.query,
        path=args.path,
        concurrency=max(1, min(256, args.concurrency)),
        timeout_s=args.timeout_s,
        retries=args.retries,
        backoff_s=args.backoff_s,
        fail_on_errors=args.fail_on_errors,
        print_report=args.print_report,
    )


async def run(settings: Settings) -> int:
    # Загрузка датасета
    samples = load_dataset(settings.dataset)

    # Клиент OPA
    if settings.opa_url:
        client: OpaClientBase = OpaHttpClient(settings.opa_url, timeout_s=settings.timeout_s, retries=settings.retries, backoff_s=settings.backoff_s)
        query_path = settings.path
        mode = "http"
    else:
        if not settings.rego:
            raise RuntimeError("No --opa-url and no --rego files provided")
        # Быстрая проверка наличия 'opa'
        from shutil import which
        if which("opa") is None:
            raise RuntimeError("Local mode requires 'opa' binary in PATH")
        client = OpaLocalClient(settings.rego, settings.query, timeout_s=settings.timeout_s)
        query_path = settings.path  # не используется в локальном режиме
        mode = "local"

    # Параллельная оценка
    sem = asyncio.Semaphore(settings.concurrency)
    decisions: List[Decision] = []

    async def worker(s: Sample):
        async with sem:
            d = await eval_one(client, query_path, s)
            decisions.append(d)

    tasks = [asyncio.create_task(worker(s)) for s in samples]
    await asyncio.gather(*tasks)

    # Метрики
    metrics = compute_metrics(samples, decisions)

    # Артефакты
    outdir = Path(settings.output_dir)
    (outdir / "results.jsonl").write_text("\n".join(json.dumps(d.model_dump(), ensure_ascii=False) for d in decisions) + "\n", encoding="utf-8")
    (outdir / "metrics.json").write_text(json.dumps(metrics.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(build_report_md(settings, samples, metrics), encoding="utf-8")

    # Краткий вывод (по требованию)
    if settings.print_report:
        print(build_report_md(settings, samples, metrics))

    # Код возврата
    if settings.fail_on_errors and metrics.errors > 0:
        return 2
    return 0


def build_report_md(settings: Settings, samples: List[Sample], m: Metrics) -> str:
    lines = []
    lines.append(f"# Prompt Guard Evaluation Report")
    lines.append("")
    lines.append(f"- Dataset: `{settings.dataset}`")
    lines.append(f"- Mode: `{'OPA HTTP' if settings.opa_url else 'OPA local'}`")
    lines.append(f"- Total: {m.total}, Decided: {m.decided}, Errors: {m.errors}")
    lines.append("")
    lines.append("## Binary (allow/deny)")
    lines.append(f"- Accuracy: {fmt(m.accuracy)}  Precision: {fmt(m.precision)}  Recall: {fmt(m.recall)}  F1: {fmt(m.f1)}")
    lines.append(f"- Confusion: TP={m.confusion.get('TP',0)} FP={m.confusion.get('FP',0)} TN={m.confusion.get('TN',0)} FN={m.confusion.get('FN',0)}")
    if m.micro_f1 is not None or m.macro_f1 is not None:
        lines.append("")
        lines.append("## Multi‑label categories")
        lines.append(f"- Micro: P={fmt(m.micro_precision)} R={fmt(m.micro_recall)} F1={fmt(m.micro_f1)}")
        lines.append(f"- Macro: P={fmt(m.macro_precision)} R={fmt(m.macro_recall)} F1={fmt(m.macro_f1)}")
        if m.per_label:
            lines.append("")
            lines.append("| Label | P | R | F1 |")
            lines.append("|---|---:|---:|---:|")
            for lab, sc in sorted(m.per_label.items()):
                lines.append(f"| {lab} | {fmt(sc.get('precision'))} | {fmt(sc.get('recall'))} | {fmt(sc.get('f1'))} |")
    lines.append("")
    lines.append("> Note: positive class = deny. Metrics are computed only for samples with ground truth `allow` present.")
    return "\n".join(lines)


def fmt(x: Optional[float]) -> str:
    return "-" if x is None else f"{x:.4f}"


def main(argv: Optional[Sequence[str]] = None) -> None:
    try:
        settings = parse_args(argv)
        rc = asyncio.run(run(settings))
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(json.dumps({"level": "error", "msg": "evaluation failed", "err": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()

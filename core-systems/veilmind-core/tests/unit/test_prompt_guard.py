# path: veilmind-core/tests/unit/test_prompt_guard.py
from __future__ import annotations

import asyncio
import csv
import json
import os
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Tuple

import pytest

# Опциональные зависимости для HTTP‑моков
try:
    import respx  # type: ignore
except Exception:  # pragma: no cover
    respx = None  # type: ignore

# ---- Робастный импорт тестируемого модуля ----
# Предпочитаем обычный импорт пакета, но поддерживаем прямую загрузку по пути.
def _import_eval_tool():
    try:
        from cli.tools import prompt_guard_eval as mod  # type: ignore
        return mod
    except Exception:
        import importlib.util as _ilu
        # вычислим корень репозитория относительно текущего файла
        here = Path(__file__).resolve()
        # предполагаем структуру veilmind-core/cli/tools/prompt_guard_eval.py
        candidates = [
            here.parents[3] / "cli" / "tools" / "prompt_guard_eval.py",
            here.parents[2] / "cli" / "tools" / "prompt_guard_eval.py",
            here.parents[1] / "cli" / "tools" / "prompt_guard_eval.py",
        ]
        for p in candidates:
            if p.exists():
                spec = _ilu.spec_from_file_location("prompt_guard_eval_fallback", str(p))
                assert spec and spec.loader, f"cannot load module from {p}"
                m = _ilu.module_from_spec(spec)
                spec.loader.exec_module(m)  # type: ignore[attr-defined]
                return m
        raise ImportError("cannot locate cli/tools/prompt_guard_eval.py")

E = _import_eval_tool()


# -----------------------------
# Помощники
# -----------------------------

@pytest.fixture(scope="session")
def event_loop():
    # Совместимость с pytest‑asyncio < 0.21/>= 0.21
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def _mk_jsonl(tmp_path: Path, rows: List[Dict[str, Any]]) -> Path:
    p = tmp_path / "data.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


def _mk_csv(tmp_path: Path, rows: List[Dict[str, Any]]) -> Path:
    p = tmp_path / "data.csv"
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return p


# -----------------------------
# normalize_policy_output
# -----------------------------

@pytest.mark.parametrize(
    "val,expect",
    [
        (True, (True, [], None)),
        (False, (False, [], None)),
        ({"allow": True, "categories": ["A", "B"], "reason": "ok"}, (True, ["A", "B"], "ok")),
        ({"decision": {"allow": False, "categories": ["X"], "reason": "bad"}}, (False, ["X"], "bad")),
        ({"unexpected": 1}, (False, [], "unexpected policy output type=dict")),
        (123, (False, [], "unexpected policy output type=int")),
    ],
)
def test_normalize_policy_output_variants(val, expect):
    out = E.normalize_policy_output(val)
    assert out == expect


# -----------------------------
# Бинарные метрики и матрица ошибок
# -----------------------------

def test_binary_metrics_confusion_and_scores():
    # Истина: [allow, allow, deny, deny, allow] -> [True, True, False, False, True]
    gt = [True, True, False, False, True]
    # Предсказания: [allow, deny, deny, allow, allow] -> [True, False, False, True, True]
    pr = [True, False, False, True, True]

    conf, m = E.binary_metrics(gt, pr)
    # positive = deny (False)
    # Сравнение по парам:
    # 1) T/T -> TN
    # 2) T/F -> FP (модель заблокировала allow)
    # 3) F/F -> TP
    # 4) F/T -> FN (модель пропустила deny)
    # 5) T/T -> TN
    assert conf == {"TP": 1, "FP": 1, "TN": 2, "FN": 1}
    # Проверим базовые метрики (без строгой точности из‑за делений)
    assert m["accuracy"] == pytest.approx(3 / 5, rel=1e-6)
    assert m["precision"] == pytest.approx(1 / 2, rel=1e-6)
    assert m["recall"] == pytest.approx(1 / 2, rel=1e-6)
    assert m["f1"] == pytest.approx(0.5, rel=1e-6)


# -----------------------------
# Multilabel метрики
# -----------------------------

def test_multilabel_metrics_micro_macro():
    gt = [["A", "B"], ["A"], [], ["C"], ["A", "C"]]
    pr = [["A"], ["B"], ["C"], ["C"], ["A"]]
    mlm, per = E.multilabel_metrics(gt, pr)

    # Базовые sanity‑проверки
    assert set(per.keys()) == {"A", "B", "C"}
    # Label C: TP на позициях 4 и 5? gt: [3]="C", [4]="A,C"; pr: [2]="C" (ложно), [3]="C"(верно), [4] не содержит C
    # Здесь главное — непротиворечивость: micro_f1 определена и в [0,1].
    for k in ("micro_precision", "micro_recall", "micro_f1", "macro_precision", "macro_recall", "macro_f1"):
        assert 0.0 <= (mlm[k] or 0.0) <= 1.0


# -----------------------------
# Загрузка датасета (JSONL/CSV)
# -----------------------------

def test_load_dataset_jsonl_and_csv(tmp_path: Path):
    rows = [
        {"id": "1", "text": "hello", "allow": True, "labels": ["A"]},
        {"id": "2", "prompt": "world", "label": "deny", "categories": "B,C"},
    ]
    p_jsonl = _mk_jsonl(tmp_path, rows)
    ds1 = E.load_dataset(p_jsonl)
    assert len(ds1) == 2
    assert ds1[0].id == "1" and ds1[0].text == "hello" and ds1[0].allow is True and ds1[0].labels == ["A"]
    assert ds1[1].id == "2" and ds1[1].text == "world" and ds1[1].allow is False and set(ds1[1].labels) == {"B", "C"}

    p_csv = _mk_csv(tmp_path, rows)
    ds2 = E.load_dataset(p_csv)
    assert len(ds2) == 2
    assert ds2[0].text in ("hello", "world")  # порядок колонок несущественен


# -----------------------------
# OpaLocalClient — локальная политика через opa eval
# -----------------------------

@pytest.mark.asyncio
@pytest.mark.skipif(which("opa") is None, reason="opa binary not available in PATH")
async def test_opa_local_client_eval(tmp_path: Path):
    # Создадим минимальную политику: запрет, если текст содержит "secret"
    rego = tmp_path / "policy.rego"
    rego.write_text(
        """
        package prompt_safety

        guard := {"allow": allow, "categories": cats, "reason": reason} {
          some t
          txt := input.text
          contains(lower(txt), "secret")
          allow := false
          cats := ["ILLEGAL_ACTIVITY"]
          reason := "contains secret"
        } else = {"allow": true, "categories": [], "reason": "ok"} {
          true
        }
        """,
        encoding="utf-8",
    )
    client = E.OpaLocalClient([str(rego)], query="data.prompt_safety.guard", timeout_s=3.0)

    # Позитивный случай (allow=true)
    out1 = await client.evaluate("ignored", {"text": "Hello"})
    allow1, cats1, reason1 = E.normalize_policy_output(out1)
    assert allow1 is True and cats1 == [] and reason1 == "ok"

    # Блокировка
    out2 = await client.evaluate("ignored", {"text": "my SECRET token"})
    allow2, cats2, reason2 = E.normalize_policy_output(out2)
    assert allow2 is False and "ILLEGAL_ACTIVITY" in cats2 and reason2 == "contains secret"


# -----------------------------
# OpaHttpClient — мок через respx
# -----------------------------

@pytest.mark.asyncio
@pytest.mark.skipif(E.httpx is None or respx is None, reason="httpx/respx not installed")
async def test_opa_http_client_mock(tmp_path: Path):
    base = "http://opa.local"
    client = E.OpaHttpClient(base_url=base, timeout_s=2.0, retries=0)

    with respx.mock:  # type: ignore[attr-defined]
        route = respx.post(f"{base}/v1/data/prompt_safety/guard").mock(
            return_value=E.httpx.Response(
                status_code=200,
                json={"result": {"allow": False, "categories": ["HATE_VIOLENCE"], "reason": "policy hit"}},
            )
        )
        out = await client.evaluate("prompt_safety/guard", {"text": "foo"})
        # убедимся, что произошёл вызов
        assert route.called  # type: ignore[attr-defined]
        allow, cats, reason = E.normalize_policy_output(out)
        assert allow is False and cats == ["HATE_VIOLENCE"] and reason == "policy hit"


# -----------------------------
# End‑to‑End run() с артефактами (HTTP‑мок)
# -----------------------------

@pytest.mark.asyncio
@pytest.mark.skipif(E.httpx is None or respx is None, reason="httpx/respx not installed")
async def test_run_end_to_end_with_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Датасет из трёх примеров, один «ошибочный» ответ политики
    dataset = [
        {"id": "1", "text": "clean text", "allow": True, "labels": []},
        {"id": "2", "text": "toxic text", "allow": False, "labels": ["HATE_VIOLENCE"]},
        {"id": "3", "text": "bad format", "allow": True, "labels": []},
    ]
    ds_path = _mk_jsonl(tmp_path, dataset)
    outdir = tmp_path / "out"
    outdir.mkdir(parents=True, exist_ok=True)

    # Настроим клиента: для id=3 вернём неожиданный формат для проверки error‑учёта
    base = "http://opa.local"
    settings = E.Settings(
        dataset=str(ds_path),
        output_dir=str(outdir),
        opa_url=base,
        rego=[],
        query="data.prompt_safety.guard",
        path="prompt_safety/guard",
        concurrency=4,
        timeout_s=2.0,
        retries=0,
        backoff_s=0.1,
        fail_on_errors=False,
        print_report=False,
    )

    with respx.mock:  # type: ignore[attr-defined]
        # id=1 -> allow
        respx.post(f"{base}/v1/data/prompt_safety/guard").mock(  # type: ignore[attr-defined]
            side_effect=[
                E.httpx.Response(200, json={"result": {"allow": True, "categories": [], "reason": "ok"}}),
                E.httpx.Response(200, json={"result": {"allow": False, "categories": ["HATE_VIOLENCE"], "reason": "denied"}}),
                E.httpx.Response(200, json={"result": 123}),  # неожиданный формат
            ]
        )
        rc = await E.run(settings)
        assert rc == 0

    # Проверим артефакты
    results = (outdir / "results.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(results) == 3
    metrics = json.loads((outdir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["total"] == 3
    assert metrics["decided"] == 3  # решения получены на все, но один с ошибкой нормализации учитывается в errors
    assert metrics["errors"] >= 1
    # Отчёт
    report_md = (outdir / "report.md").read_text(encoding="utf-8")
    assert "Prompt Guard Evaluation Report" in report_md
    assert "Binary (allow/deny)" in report_md


# -----------------------------
# Негативные кейсы и устойчивость
# -----------------------------

def test_dataset_row_validation_error(tmp_path: Path):
    # нет text/id
    bad = _mk_jsonl(tmp_path, [{"foo": 1}])
    with pytest.raises(Exception):
        E.load_dataset(bad)


@pytest.mark.asyncio
async def test_normalize_policy_output_unexpected_types():
    # Даже для мусора функция должна возвращать кортеж и не падать
    out = E.normalize_policy_output(object())  # type: ignore[arg-type]
    assert out[0] is False and isinstance(out[1], list) and isinstance(out[2], str)

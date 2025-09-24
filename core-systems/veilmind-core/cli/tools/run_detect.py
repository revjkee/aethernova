# veilmind-core/cli/tools/run_detect.py
# -*- coding: utf-8 -*-
"""
VeilMind — Zero Trust Detection CLI

Функции:
- Единичная и пакетная (NDJSON) оценка событий в режимах:
  * http — POST к /v1/detect/evaluate (совместим с veilmind-core/api/http/server.py)
  * cli  — локальный вызов risk_score.py (совместим с ранее описанным интерфейсом)
  * off  — "пустой" режим: всегда ALLOW с нулевым скором и порогами из ENV
- Ввод: JSON файл/STDIN или NDJSON (--ndjson).
- Вывод: json|ndjson|table.
- Конкуренция для HTTP батчей (--concurrency), ретраи с бэкоффом, таймаут.
- Request-ID (ULID), структурные JSON‑логи в stderr (по умолчанию).
- Генерация шаблона события (--template).

ENV (дефолты совместимы с сервером):
- ZT_RISK_SCORE_MODE=cli|http|off
- ZT_RISK_HTTP_URL=http://localhost:8080/v1/detect/evaluate
- ZT_RISK_SCORE_CLI_BIN=python3
- ZT_RISK_SCORE_CLI_SCRIPT=cli/tools/risk_score.py
- ZT_RISK_SCORE_STATE_PATH=/var/lib/veilmind/risk_state.sqlite
- ZT_RISK_WEIGHTS_PATH=   (опц.)
- ZT_RISK_THRESH_ALLOW=40  ZT_RISK_THRESH_MFA=70  ZT_RISK_THRESH_DENY=85  ZT_RISK_THRESH_QUARANTINE=95
- VEILMIND_TOKEN=          (Bearer для HTTP)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import math
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Опциональный httpx
try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore

# ULID генератор из veilmind (если есть), иначе безопасный fallback
def _ulid() -> str:
    try:
        from veilmind.utils.idgen import ulid_monotonic  # type: ignore
        return ulid_monotonic()
    except Exception:
        import uuid
        return uuid.uuid4().hex.upper()

# ----------------------------
# Конфиг
# ----------------------------

@dataclass(frozen=True)
class Config:
    mode: str = os.getenv("ZT_RISK_SCORE_MODE", "cli")
    http_url: str = os.getenv("ZT_RISK_HTTP_URL", "http://localhost:8080/v1/detect/evaluate")
    token: str = os.getenv("VEILMIND_TOKEN", "")

    cli_bin: str = os.getenv("ZT_RISK_SCORE_CLI_BIN", "python3")
    cli_script: str = os.getenv("ZT_RISK_SCORE_CLI_SCRIPT", "cli/tools/risk_score.py")
    cli_state: str = os.getenv("ZT_RISK_SCORE_STATE_PATH", "/var/lib/veilmind/risk_state.sqlite")
    cli_weights: Optional[str] = os.getenv("ZT_RISK_WEIGHTS_PATH", None)

    thr_allow: float = float(os.getenv("ZT_RISK_THRESH_ALLOW", "40"))
    thr_mfa: float = float(os.getenv("ZT_RISK_THRESH_MFA", "70"))
    thr_deny: float = float(os.getenv("ZT_RISK_THRESH_DENY", "85"))
    thr_quarantine: float = float(os.getenv("ZT_RISK_THRESH_QUARANTINE", "95"))

CFG = Config()

# ----------------------------
# Логи
# ----------------------------

def logj(level: str, msg: str, **extra: Any) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "msg": msg,
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    sys.stderr.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stderr.flush()

# ----------------------------
# Шаблон события
# ----------------------------

TEMPLATE_EVENT: Dict[str, Any] = {
    "correlation_id": None,
    "timestamp": None,
    "source": "CLI",
    "actor_id": "user-001",
    "device_id": "dev-001",
    "network_ip": "203.0.113.10",
    "geo": {"lat": 59.3293, "lon": 18.0686},
    "resource_id": "srv:payments",
    "resource_kind": "http",
    "resource_action": "access",
    "resource_path": "/payments/transfer",
    "signals": {
        "identity_risk": 15,
        "device_posture": 10,
        "network_risk": 20,
        "resource_sensitivity": 50,
        "behavior_risk": 5,
        "threat_intel": 0,
        "time_risk": 10,
        "extra": {},
    },
    "context": {},
}

# ----------------------------
# Нормализация
# ----------------------------

def normalize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    e = dict(ev)
    e.setdefault("correlation_id", _ulid())
    e.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    e.setdefault("source", "CLI")
    e.setdefault("signals", {})
    sig = e["signals"]
    for k in ("identity_risk","device_posture","network_risk","resource_sensitivity","behavior_risk","threat_intel","time_risk"):
        sig[k] = float(sig.get(k, 0) or 0)
    sig.setdefault("extra", {})
    # Ресурсные атрибуты
    e.setdefault("resource_kind", "http")
    e.setdefault("resource_action", "access")
    e.setdefault("resource_path", e.get("resource_id", "") or "")
    return e

# ----------------------------
# Backend: OFF (заглушка)
# ----------------------------

def backend_off(event: Dict[str, Any], explain: bool) -> Dict[str, Any]:
    return {
        "correlation_id": event.get("correlation_id"),
        "score_raw": 0.0,
        "score": 0.0,
        "decision": "ALLOW",
        "hard_rule_triggered": None,
        "thresholds": {
            "allow": CFG.thr_allow, "mfa": CFG.thr_mfa, "deny": CFG.thr_deny, "quarantine": CFG.thr_quarantine
        },
        "factors": [] if not explain else [],
        "ts": datetime.now(timezone.utc).isoformat(),
    }

# ----------------------------
# Backend: CLI (risk_score.py)
# ----------------------------

def backend_cli(event: Dict[str, Any], explain: bool, timeout: float = 5.0) -> Dict[str, Any]:
    args = [
        CFG.cli_bin,
        CFG.cli_script,
        "evaluate",
        "--format", "json",
        "--state", CFG.cli_state,
    ]
    if CFG.cli_weights:
        args.extend(["--weights", CFG.cli_weights])

    try:
        proc = subprocess.run(
            args,
            input=json.dumps(event).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("risk scorer timeout")
    if proc.returncode != 0:
        logj("ERROR", "risk cli error", exit=proc.returncode, stderr=proc.stderr.decode("utf-8", "ignore")[:500])
        raise RuntimeError("risk scorer cli error")
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except Exception:
        raise RuntimeError("invalid json from cli")

# ----------------------------
# Backend: HTTP
# ----------------------------

async def backend_http_single(client: "httpx.AsyncClient", url: str, event: Dict[str, Any], explain: bool, request_id: str, timeout: float, retries: int, backoff: float) -> Dict[str, Any]:
    payload = {"event": event, "explain": explain}
    headers = {"Content-Type": "application/json", "X-Request-ID": request_id}
    if CFG.token:
        headers["Authorization"] = f"Bearer {CFG.token}"

    attempt = 0
    while True:
        try:
            r = await client.post(url, json=payload, headers=headers, timeout=timeout)
            if r.status_code >= 200 and r.status_code < 300:
                return r.json()
            if r.status_code in (408, 429, 502, 503, 504) and attempt < retries:
                delay = backoff * (2 ** attempt)
                await asyncio.sleep(delay)
                attempt += 1
                continue
            # Ошибка прикладного уровня
            msg = r.text[:500]
            raise RuntimeError(f"http error {r.status_code}: {msg}")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:  # type: ignore
            if attempt < retries:
                delay = backoff * (2 ** attempt)
                await asyncio.sleep(delay)
                attempt += 1
                continue
            raise RuntimeError(f"http request failed: {e}")

# ----------------------------
# Ввод/вывод
# ----------------------------

def read_json_from(path: Optional[str]) -> Dict[str, Any]:
    data = sys.stdin.read() if not path or path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(data)

def read_ndjson_from(path: Optional[str]) -> List[Dict[str, Any]]:
    lines = (sys.stdin.read().splitlines() if not path or path == "-" else Path(path).read_text(encoding="utf-8").splitlines())
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            logj("WARN", "skip invalid json line")
    return out

def print_json(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.stdout.write("\n")

def print_ndjson(items: Iterable[Dict[str, Any]]) -> None:
    for it in items:
        sys.stdout.write(json.dumps(it, ensure_ascii=False) + "\n")

def print_table(items: List[Dict[str, Any]]) -> None:
    cols = ["decision", "score", "actor_id", "resource_action", "resource_id", "ts"]
    # Подготовим строки
    rows = []
    for it in items:
        ev = it.get("_event", {})
        rows.append([
            str(it.get("decision", "")),
            f'{it.get("score", it.get("score_raw", ""))}',
            str(ev.get("actor_id", "")),
            str(ev.get("resource_action", "")),
            str(ev.get("resource_id", "")),
            str(it.get("ts", "")),
        ])
    # Вычислим ширины
    w = [max(len(cols[i]), *(len(r[i]) for r in rows)) for i in range(len(cols))]
    # Шапка
    sys.stdout.write(" | ".join(cols[i].ljust(w[i]) for i in range(len(cols))) + "\n")
    sys.stdout.write("-+-".join("-" * w[i] for i in range(len(cols))) + "\n")
    for r in rows:
        sys.stdout.write(" | ".join(r[i].ljust(w[i]) for i in range(len(cols))) + "\n")

# ----------------------------
# Основные сценарии
# ----------------------------

def handle_single(args: argparse.Namespace) -> int:
    event = normalize_event(read_json_from(args.input))
    request_id = args.request_id or _ulid()
    mode = args.mode or CFG.mode

    try:
        if mode == "off":
            result = backend_off(event, args.explain)
        elif mode == "cli":
            result = backend_cli(event, args.explain, timeout=args.timeout)
        elif mode == "http":
            if httpx is None:
                raise RuntimeError("httpx is not installed; try: pip install httpx")
            async def _run():
                async with httpx.AsyncClient(http2=True) as client:  # type: ignore
                    return await backend_http_single(client, args.url or CFG.http_url, event, args.explain, request_id, args.timeout, args.retries, args.backoff)
            result = asyncio.run(_run())
        else:
            raise RuntimeError("unknown mode")
        # Для table режима прикрепим исходное событие
        if args.output == "table":
            result = {**result, "_event": event}
        # Вывод
        if args.output == "ndjson":
            print_ndjson([result])
        elif args.output == "table":
            print_table([result])
        else:
            print_json(result)
        return 0
    except KeyboardInterrupt:
        logj("WARN", "interrupted")
        return 130
    except Exception as e:
        logj("ERROR", "failed", error=str(e))
        return 1

def handle_batch(args: argparse.Namespace) -> int:
    events = [normalize_event(e) for e in read_ndjson_from(args.input)]
    if not events:
        logj("ERROR", "no events to process")
        return 2

    mode = args.mode or CFG.mode
    request_id = args.request_id or _ulid()

    try:
        results: List[Dict[str, Any]] = []
        if mode == "off":
            results = [backend_off(ev, args.explain) for ev in events]
        elif mode == "cli":
            # Последовательная обработка через локальный CLI (надёжно)
            for ev in events:
                results.append(backend_cli(ev, args.explain, timeout=args.timeout))
        elif mode == "http":
            if httpx is None:
                raise RuntimeError("httpx is not installed; try: pip install httpx")
            async def _run():
                async with httpx.AsyncClient(http2=True) as client:  # type: ignore
                    sem = asyncio.Semaphore(args.concurrency)
                    out: List[Dict[str, Any]] = [None] * len(events)  # type: ignore
                    async def worker(idx: int, ev: Dict[str, Any]):
                        rid = request_id  # можно использовать один на батч
                        async with sem:
                            res = await backend_http_single(client, args.url or CFG.http_url, ev, args.explain, rid, args.timeout, args.retries, args.backoff)
                            out[idx] = res
                    await asyncio.gather(*(worker(i, ev) for i, ev in enumerate(events)))
                    return out
            results = asyncio.run(_run())
        else:
            raise RuntimeError("unknown mode")

        # Для table режима прикрепим события
        if args.output == "table":
            results = [{**r, "_event": events[i]} for i, r in enumerate(results)]

        # Вывод
        if args.output == "json":
            print_json(results)
        elif args.output == "ndjson":
            print_ndjson(results)
        else:
            print_table(results)
        return 0
    except KeyboardInterrupt:
        logj("WARN", "interrupted")
        return 130
    except Exception as e:
        logj("ERROR", "batch failed", error=str(e))
        return 1

# ----------------------------
# CLI
# ----------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run-detect", description="VeilMind Zero-Trust Detection CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Общие аргументы
    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--mode", choices=["http", "cli", "off"], default=CFG.mode, help="backend mode")
        sp.add_argument("--url", default=CFG.http_url, help="HTTP URL for /v1/detect/evaluate")
        sp.add_argument("--explain", action="store_true", default=True, help="request explain data")
        sp.add_argument("--no-explain", dest="explain", action="store_false", help="disable explain")
        sp.add_argument("--timeout", type=float, default=5.0, help="request timeout seconds")
        sp.add_argument("--retries", type=int, default=2, help="retry attempts for HTTP")
        sp.add_argument("--backoff", type=float, default=0.25, help="initial backoff seconds for retries")
        sp.add_argument("--request-id", default=None, help="override X-Request-ID (ULID if omitted)")
        sp.add_argument("--output", choices=["json", "ndjson", "table"], default="json")
        sp.add_argument("--input", default="-", help="input file path or '-' for STDIN")

    sp_single = sub.add_parser("single", help="Evaluate single JSON event (file or STDIN)")
    common(sp_single)

    sp_batch = sub.add_parser("batch", help="Evaluate NDJSON stream (file or STDIN)")
    common(sp_batch)
    sp_batch.add_argument("--ndjson", action="store_true", default=True, help="treat input as NDJSON")
    sp_batch.add_argument("--concurrency", type=int, default=8, help="HTTP concurrency")

    sp_tpl = sub.add_parser("template", help="Print example JSON event")
    sp_tpl.add_argument("--pretty", action="store_true", help="pretty print")

    return p

def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.cmd == "template":
        data = dict(TEMPLATE_EVENT)
        data["correlation_id"] = _ulid()
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        if args.pretty:
            sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        else:
            print_json(data)
        return 0

    if args.cmd == "single":
        return handle_single(args)

    if args.cmd == "batch":
        return handle_batch(args)

    parser.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())

# SPDX-License-Identifier: MIT
"""
cybersecurity-core/cli/tools/adversary_emulation_pack.py

Промышленный CLI для запуска паков адверсарной эмуляции.

Возможности:
- Загрузка пака (JSON или YAML), схема с шагами/аргументами/ATT&CK-мэппингом
- Валидация пака и статический "план" выполнения
- Поиск и перечисление доступных пейлоадов в дереве
- Запуск шага/пака с поэтапными таймаутами, stop-on-error, dry-run
- Структурированные JSON-логи (подход совместим с practice cloud-structured-logging)
- Итоговый отчёт о выполнении (JSON) в файл/STDOUT

Точки расширения:
- Пейлоад — обычный Python-модуль, который предоставляет функцию:
    execute(config: dict) -> dict | объект с методом to_json()
  или (обратная совместимость с примером benign/no_op.py):
    execute_no_op(config: Any) -> ExecResult-подобный объект.
- Пак может ссылаться на модуль полным импортным путём:
    cybersecurity.adversary_emulation.attack_simulator.payloads.benign.no_op

Замечания по стандартам/практикам:
- Мэппинг на ATT&CK техники/тактики — отраслевой стандарт для адверсарной эмуляции.
- Профили/планы часто описываются в YAML (см. Caldera абилки/адверсари).
- Для CLI в стандартной библиотеке Python рекомендован argparse.
- JSON-структурирование логов упрощает машинный разбор и фильтрацию.

(Ссылки на источники приведены в конце файла/ответа.)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import importlib
import inspect
import json
import logging
import os
from pathlib import Path
import signal
import sys
import time
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

# YAML поддерживается опционально (если есть PyYAML), иначе принимаем только JSON
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

ISO = "%Y-%m-%dT%H:%M:%S.%f%z"

DEFAULT_SEARCH_ROOT = Path(__file__).resolve().parents[2]  # корень проекта: cybersecurity-core/
DEFAULT_PAYLOADS_SUBPATH = Path("cybersecurity") / "adversary_emulation" / "attack_simulator" / "payloads"

LOGGER = logging.getLogger("aethernova.adversary_pack")


# ------------------------------- Утилиты --------------------------------- #

def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(ts: dt.datetime) -> str:
    return ts.strftime(ISO)


def _j(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _setup_logging(json_logs: bool) -> None:
    root = logging.getLogger()
    if root.handlers:
        for h in list(root.handlers):
            root.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    if json_logs:
        fmt = "%(message)s"
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s :: %(message)s"
    h.setFormatter(logging.Formatter(fmt=fmt, datefmt="%Y-%m-%d %H:%M:%S%z"))
    root.addHandler(h)
    root.setLevel(logging.INFO)


def log_event(event: str, **kw: Any) -> None:
    LOGGER.info(_j({"event": event, **kw}))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ----------------------------- Загрузка пака ----------------------------- #

class PackError(Exception):
    pass


def load_pack(path: Path) -> Dict[str, Any]:
    """
    Загружает pack из JSON или YAML. Обязательные поля:
      version: str
      name: str
      steps: list[{
         id: str,
         title: str,
         module: str,              # import path to payload
         args: dict,               # передаются в payload.execute(...)
         timeout_ms: int,          # таймаут шага
         attack: {technique_id: str, tactic: str, name: str}   # мэппинг на ATT&CK
      }]
    """
    if not path.exists():
        raise PackError(f"Pack file not found: {path}")

    text = _read_text(path)
    data: Dict[str, Any]
    if path.suffix.lower() in (".yaml", ".yml"):
        if not _HAS_YAML:
            raise PackError("PyYAML не установлен; используйте JSON или установите PyYAML.")
        try:
            data = yaml.safe_load(text) or {}
        except Exception as e:
            raise PackError(f"YAML parse error: {e}") from e
    else:
        try:
            data = json.loads(text)
        except Exception as e:
            raise PackError(f"JSON parse error: {e}") from e
    if not isinstance(data, dict):
        raise PackError("Pack root must be an object/dict.")
    return data


def validate_pack(pack: Dict[str, Any]) -> Tuple[bool, Sequence[str]]:
    errors = []

    def req(root: Dict[str, Any], key: str, typ: type) -> None:
        if key not in root or not isinstance(root[key], typ):
            errors.append(f"Missing or invalid '{key}' ({typ.__name__})")

    req(pack, "version", str)
    req(pack, "name", str)
    if "steps" not in pack or not isinstance(pack["steps"], list) or not pack["steps"]:
        errors.append("Missing or invalid 'steps' (non-empty list)")

    seen_ids = set()
    for idx, step in enumerate(pack.get("steps", [])):
        if not isinstance(step, dict):
            errors.append(f"steps[{idx}] must be object")
            continue
        for k, t in [("id", str), ("title", str), ("module", str), ("args", dict), ("timeout_ms", int)]:
            if k not in step or not isinstance(step[k], t):
                errors.append(f"steps[{idx}].{k} must be {t.__name__}")
        if "id" in step:
            if step["id"] in seen_ids:
                errors.append(f"steps[{idx}].id is duplicated: {step['id']}")
            seen_ids.add(step["id"])
        attack = step.get("attack")
        if not isinstance(attack, dict):
            errors.append(f"steps[{idx}].attack must be object")
        else:
            for k, t in [("technique_id", str), ("tactic", str), ("name", str)]:
                if k not in attack or not isinstance(attack[k], t):
                    errors.append(f"steps[{idx}].attack.{k} must be {t.__name__}")

    return (len(errors) == 0, errors)


# -------------------------- Поиск пейлоад-модулей ------------------------ #

def discover_payloads(root: Path | None = None) -> Iterable[str]:
    """
    Ищет Python-модули-пейлоады под cybersecurity/adversary_emulation/attack_simulator/payloads
    и возвращает их импортные пути.
    """
    base = (root or DEFAULT_SEARCH_ROOT) / DEFAULT_PAYLOADS_SUBPATH
    if not base.exists():
        return []
    paths = []
    for p in base.rglob("*.py"):
        if p.name.startswith("_"):
            continue
        # строим импортный путь от корня проекта
        rel = p.relative_to((root or DEFAULT_SEARCH_ROOT))
        mod = ".".join(rel.with_suffix("").parts)
        paths.append(mod)
    return sorted(paths)


# -------------------------- Исполнение шагов/пака ------------------------ #

class StepTimeout(Exception):
    pass


def _call_payload(module_path: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Унифицированный вызов пейлоада. Ожидаем один из контрактов:
      - module.execute(dict) -> dict/Obj
      - module.execute_no_op(NoOpConfig) -> ExecResult-like
        (оборачиваем dataclass через dataclasses.asdict, если применимо)
    """
    mod = importlib.import_module(module_path)

    def normalize_result(x: Any) -> Dict[str, Any]:
        if x is None:
            return {"success": True, "message": "no result"}
        if isinstance(x, dict):
            return x
        if hasattr(x, "to_json") and callable(getattr(x, "to_json")):
            try:
                return json.loads(x.to_json())
            except Exception:
                pass
        if dataclasses.is_dataclass(x):
            return dataclasses.asdict(x)  # type: ignore
        # последний шанс — строка JSON
        if isinstance(x, str):
            with contextlib.suppress(Exception):
                return json.loads(x)
        # сделаем best-effort
        return {"success": bool(getattr(x, "success", True)), "result": str(x)}

    # первично пробуем execute(dict)
    if hasattr(mod, "execute") and callable(getattr(mod, "execute")):
        sig = inspect.signature(getattr(mod, "execute"))
        if len(sig.parameters) == 1:
            return normalize_result(mod.execute(args))  # type: ignore

    # совместимость: execute_no_op(config)
    if hasattr(mod, "execute_no_op") and callable(getattr(mod, "execute_no_op")):
        return normalize_result(mod.execute_no_op(args))  # type: ignore

    raise PackError(f"Payload contract not found in module '{module_path}'. "
                    f"Expected 'execute(dict)' or 'execute_no_op(config)'")


def run_step(step: Dict[str, Any], *, dry_run: bool = False) -> Dict[str, Any]:
    started = _now_utc()
    log_event("step_start",
              step_id=step.get("id"), title=step.get("title"),
              module=step.get("module"), attack=step.get("attack"))

    success = False
    error = None
    result: Dict[str, Any] | None = None

    def _exec() -> Dict[str, Any]:
        if dry_run:
            return {"success": True, "message": "dry-run", "args": step.get("args", {})}
        return _call_payload(step["module"], step.get("args", {}))

    timeout_ms = int(step.get("timeout_ms", 0))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = executor.submit(_exec)
    try:
        res = fut.result(timeout=None if timeout_ms <= 0 else timeout_ms / 1000.0)
        success = bool(res.get("success", True))
        result = res
    except concurrent.futures.TimeoutError:
        error = f"Step timed out after {timeout_ms} ms"
        fut.cancel()
    except Exception as ex:
        error = f"{type(ex).__name__}: {ex}"
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    finished = _now_utc()
    elapsed_ms = max(0, int((finished - started).total_seconds() * 1000))

    out = {
        "step_id": step.get("id"),
        "title": step.get("title"),
        "module": step.get("module"),
        "attack": step.get("attack"),
        "started_at": _iso(started),
        "finished_at": _iso(finished),
        "elapsed_ms": elapsed_ms,
        "success": success and error is None,
        "error": error,
        "result": result,
    }
    log_event("step_finish", **{k: out[k] for k in ("step_id", "success", "elapsed_ms", "error")})
    return out


def run_pack(pack: Dict[str, Any], *, dry_run: bool, stop_on_error: bool,
             max_duration_ms: Optional[int] = None) -> Dict[str, Any]:
    started = _now_utc()
    log_event("pack_start", name=pack.get("name"), version=pack.get("version"))

    steps_res = []
    total_success = True
    for step in pack.get("steps", []):
        sres = run_step(step, dry_run=dry_run)
        steps_res.append(sres)
        if not sres["success"]:
            total_success = False
            if stop_on_error:
                log_event("pack_abort_on_error", step_id=sres.get("step_id"))
                break
        if max_duration_ms:
            elapsed = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000)
            if elapsed > max_duration_ms:
                total_success = False
                log_event("pack_timed_out", elapsed_ms=elapsed, max_duration_ms=max_duration_ms)
                break

    finished = _now_utc()
    out = {
        "name": pack.get("name"),
        "version": pack.get("version"),
        "started_at": _iso(started),
        "finished_at": _iso(finished),
        "elapsed_ms": max(0, int((finished - started).total_seconds() * 1000)),
        "success": total_success,
        "steps": steps_res,
    }
    log_event("pack_finish", name=pack.get("name"), success=total_success, steps=len(steps_res))
    return out


# ------------------------------- CLI-команды ------------------------------ #

def cmd_list_payloads(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve() if args.root else DEFAULT_SEARCH_ROOT
    mods = list(discover_payloads(root))
    for m in mods:
        print(m)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    pack = load_pack(Path(args.pack).resolve())
    ok, errs = validate_pack(pack)
    print(_j({"valid": ok, "errors": errs}))
    return 0 if ok else 1


def cmd_plan(args: argparse.Namespace) -> int:
    pack = load_pack(Path(args.pack).resolve())
    ok, errs = validate_pack(pack)
    if not ok:
        print(_j({"valid": False, "errors": errs}))
        return 1
    plan = []
    for s in pack["steps"]:
        plan.append({
            "id": s["id"],
            "title": s["title"],
            "module": s["module"],
            "timeout_ms": s["timeout_ms"],
            "attack": s["attack"],
        })
    print(_j({"valid": True, "name": pack["name"], "version": pack["version"], "steps": plan}))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    json_logs = bool(args.json_logs)
    _setup_logging(json_logs=json_logs)

    try:
        pack = load_pack(Path(args.pack).resolve())
        ok, errs = validate_pack(pack)
        if not ok:
            log_event("validation_failed", errors=errs)
            print(_j({"valid": False, "errors": errs}))
            return 1
        report = run_pack(
            pack,
            dry_run=bool(args.dry_run),
            stop_on_error=bool(args.stop_on_error),
            max_duration_ms=args.max_duration_ms,
        )
        out = _j(report)
        if args.report:
            _write_text(Path(args.report), out)
        print(out)
        return 0 if report.get("success") else 2
    except Exception as ex:
        log_event("fatal", error=f"{type(ex).__name__}: {ex}")
        print(_j({"success": False, "error": f"{type(ex).__name__}: {ex}"}))
        return 3


def cmd_init(args: argparse.Namespace) -> int:
    skeleton = {
        "version": "1.0",
        "name": "example-pack",
        "steps": [
            {
                "id": "step-1",
                "title": "Benign no-op",
                "module": "cybersecurity.adversary_emulation.attack_simulator.payloads.benign.no_op",
                "args": {"duration_ms": 500, "label": "sample"},
                "timeout_ms": 2000,
                "attack": {"technique_id": "T0000", "tactic": "execution", "name": "Benign No-Op"},
            }
        ],
    }
    target = Path(args.output).resolve()
    if target.exists() and not args.force:
        print(f"Refusing to overwrite existing file: {target}", file=sys.stderr)
        return 2
    content: str
    if args.format == "json" or not _HAS_YAML:
        content = json.dumps(skeleton, ensure_ascii=False, indent=2)
    else:
        content = yaml.safe_dump(skeleton, sort_keys=False, allow_unicode=True)  # type: ignore
    _write_text(target, content)
    print(str(target))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adversary-emulation-pack",
        description="CLI для загрузки, валидации и запуска паков адверсарной эмуляции.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list-payloads", help="Перечислить доступные пейлоады (поиск по дереву проекта).")
    sp.add_argument("--root", type=str, default=None, help="Корень поиска (по умолчанию корень репозитория).")
    sp.set_defaults(func=cmd_list_payloads)

    sp = sub.add_parser("validate", help="Проверить структуру пака.")
    sp.add_argument("pack", type=str, help="Путь к файлу пакета (JSON/YAML).")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("plan", help="Показать план выполнения.")
    sp.add_argument("pack", type=str, help="Путь к файлу пакета (JSON/YAML).")
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("run", help="Запустить пак.")
    sp.add_argument("pack", type=str, help="Путь к файлу пакета (JSON/YAML).")
    sp.add_argument("--dry-run", action="store_true", help="Не выполнять пейлоады, только прогон аргументов.")
    sp.add_argument("--stop-on-error", action="store_true", help="Остановиться при первой ошибке шага.")
    sp.add_argument("--max-duration-ms", type=int, default=None, help="Глобальный таймаут на весь пак.")
    sp.add_argument("--report", type=str, default=None, help="Сохранить итоговый отчёт (JSON) в файл.")
    sp.add_argument("--json-logs", action="store_true", help="Логировать события как JSON-строки.")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("init", help="Сгенерировать скелет пака.")
    sp.add_argument("-o", "--output", type=str, required=True, help="Куда записать скелет.")
    sp.add_argument("--format", choices=["json", "yaml"], default="yaml", help="Формат файла.")
    sp.add_argument("--force", action="store_true", help="Перезаписать, если файл существует.")
    sp.set_defaults(func=cmd_init)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    # По умолчанию — не JSON-логи, но команды их включают (run --json-logs)
    _setup_logging(json_logs=False)

    # Корректная остановка по Ctrl+C и SIGTERM
    def _sig_exit(signum, _frame):
        log_event("signal", signum=signum)
        sys.exit(130)
    with contextlib.suppress(Exception):
        signal.signal(signal.SIGINT, _sig_exit)    # 2
        signal.signal(signal.SIGTERM, _sig_exit)   # 15

    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)  # type: ignore


if __name__ == "__main__":
    sys.exit(main())

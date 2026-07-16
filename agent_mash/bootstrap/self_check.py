# agent_mash/bootstrap/self_check.py
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import platform
import re
import shutil
import stat
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class CheckIssue:
    """
    Единица результата проверки.

    level:
      - "ERROR": критично, должно останавливать старт (в strict режиме)
      - "WARN" : предупреждение, не обязательно останавливает старт
      - "INFO" : справочная запись

    code: короткий стабильный код для машинной обработки
    message: человекочитаемое описание
    details: доп. данные (без секретов)
    """
    level: str
    code: str
    message: str
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    issues: Tuple[CheckIssue, ...]
    duration_ms: int


@dataclass(frozen=True)
class SelfCheckReport:
    """
    Итоговый отчёт self-check.
    """
    started_at: str
    finished_at: str
    duration_ms: int
    strict: bool
    results: Tuple[CheckResult, ...]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "strict": self.strict,
            "results": [
                {
                    "name": r.name,
                    "ok": r.ok,
                    "duration_ms": r.duration_ms,
                    "issues": [
                        {
                            "level": i.level,
                            "code": i.code,
                            "message": i.message,
                            "details": i.details,
                        }
                        for i in r.issues
                    ],
                }
                for r in self.results
            ],
            "summary": self.summary,
        }

    def to_json(self) -> str:
        # Детерминированная сериализация для CI.
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class SelfCheckError(RuntimeError):
    """
    Выбрасывается, если strict-проверка не пройдена.
    """


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(v: Any, max_len: int = 512) -> str:
    s = str(v)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _is_truthy_env(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _redact_env_value(key: str, value: str) -> str:
    """
    Не раскрываем секреты в отчёте.
    """
    k = key.lower()
    if any(t in k for t in ("secret", "token", "password", "passwd", "key", "private", "jwt", "bearer")):
        return "***REDACTED***"
    # Также редактируем очень длинные строки (часто это ключи/сертификаты).
    if len(value) > 128:
        return "***REDACTED***"
    return value


def _detect_container() -> Dict[str, Any]:
    """
    Эвристики контейнера. Это не гарантия, поэтому выдаём INFO.
    """
    info: Dict[str, Any] = {"in_container": False, "signals": []}
    try:
        cgroup = Path("/proc/1/cgroup")
        if cgroup.exists():
            txt = cgroup.read_text(errors="ignore")
            if any(x in txt for x in ("docker", "kubepods", "containerd", "podman")):
                info["in_container"] = True
                info["signals"].append("cgroup")
    except Exception:
        pass

    if Path("/.dockerenv").exists():
        info["in_container"] = True
        info["signals"].append("dockerenv")

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        info["in_container"] = True
        info["signals"].append("kubernetes_env")

    return info


def _perm_bits(path: Path) -> Optional[int]:
    try:
        st = path.stat()
        return stat.S_IMODE(st.st_mode)
    except Exception:
        return None


class SelfCheck:
    """
    Основной интерфейс.
    Добавляйте новые проверки через register().
    """

    def __init__(self) -> None:
        self._checks: List[Tuple[str, Callable[[], List[CheckIssue]]]] = []

    def register(self, name: str, fn: Callable[[], List[CheckIssue]]) -> "SelfCheck":
        if not name or not isinstance(name, str):
            raise ValueError("check name must be non-empty string")
        if not callable(fn):
            raise ValueError("check function must be callable")
        self._checks.append((name, fn))
        return self

    def run(self, strict: bool = True) -> SelfCheckReport:
        started = time.time()
        started_at = _utc_now_iso()

        results: List[CheckResult] = []
        counters = {"ERROR": 0, "WARN": 0, "INFO": 0}
        failed_checks: List[str] = []

        for name, fn in self._checks:
            t0 = time.time()
            issues: List[CheckIssue] = []
            ok = True
            try:
                issues = fn() or []
                for i in issues:
                    lvl = i.level.upper()
                    if lvl not in counters:
                        # нормализуем неизвестные уровни как WARN
                        lvl = "WARN"
                        issues = [
                            CheckIssue(
                                level="WARN",
                                code="SELF_CHECK_INVALID_LEVEL",
                                message="Обнаружен некорректный уровень issue; нормализовано в WARN",
                                details={"check": name},
                            )
                        ] + issues
                    counters[lvl] += 1
                    if lvl == "ERROR":
                        ok = False
            except Exception as e:
                ok = False
                counters["ERROR"] += 1
                issues = [
                    CheckIssue(
                        level="ERROR",
                        code="SELF_CHECK_EXCEPTION",
                        message="Исключение внутри self-check",
                        details={
                            "check": name,
                            "exception": e.__class__.__name__,
                            "message": _safe_str(e),
                            "traceback": _safe_str(traceback.format_exc(), max_len=4000),
                        },
                    )
                ]

            dt_ms = int((time.time() - t0) * 1000)
            if not ok:
                failed_checks.append(name)

            results.append(
                CheckResult(
                    name=name,
                    ok=ok,
                    issues=tuple(issues),
                    duration_ms=dt_ms,
                )
            )

        finished_at = _utc_now_iso()
        duration_ms = int((time.time() - started) * 1000)

        summary: Dict[str, Any] = {
            "ok": counters["ERROR"] == 0 if strict else True,
            "levels": counters,
            "failed_checks": failed_checks,
            "python": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "executable": sys.executable,
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "container": _detect_container(),
        }

        report = SelfCheckReport(
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            strict=strict,
            results=tuple(results),
            summary=summary,
        )

        if strict and counters["ERROR"] > 0:
            raise SelfCheckError(report.to_json())

        return report


def build_default_self_check(project_root: Optional[Path] = None) -> SelfCheck:
    """
    Формирует набор проверок по умолчанию.
    project_root: корень репозитория/сервиса; если не задан, берём 2 уровня вверх от текущего файла.
    """
    here = Path(__file__).resolve()
    root = project_root.resolve() if project_root else here.parents[2]

    sc = SelfCheck()

    sc.register("python_version", lambda: _check_python_version(min_version=(3, 11)))
    sc.register("encoding_and_locale", _check_encoding_and_locale)
    sc.register("environment_flags", lambda: _check_environment_flags())
    sc.register("required_env", lambda: _check_required_env(required=(
        # Набор сделан минимальным. Расширяйте в вашем проекте.
        # Важно: здесь нельзя требовать секреты (они часто доступны только в runtime).
        "AGENT_MASH_ENV",
    )))
    sc.register("filesystem_layout", lambda: _check_filesystem_layout(root))
    sc.register("permissions_hardening", lambda: _check_permissions_hardening(root))
    sc.register("imports_smoke", _check_imports_smoke)
    sc.register("external_binaries_optional", lambda: _check_external_binaries_optional(("git",)))
    sc.register("time_sanity", _check_time_sanity)

    return sc


def _check_python_version(min_version: Tuple[int, int]) -> List[CheckIssue]:
    major, minor = sys.version_info[:2]
    req_major, req_minor = min_version
    if (major, minor) < (req_major, req_minor):
        return [
            CheckIssue(
                level="ERROR",
                code="PYTHON_VERSION_TOO_OLD",
                message="Версия Python ниже минимально поддерживаемой",
                details={"current": f"{major}.{minor}", "required": f"{req_major}.{req_minor}"},
            )
        ]
    return [
        CheckIssue(
            level="INFO",
            code="PYTHON_VERSION_OK",
            message="Версия Python соответствует требованиям",
            details={"current": platform.python_version()},
        )
    ]


def _check_encoding_and_locale() -> List[CheckIssue]:
    issues: List[CheckIssue] = []
    enc = sys.getdefaultencoding()
    fsenc = sys.getfilesystemencoding()
    loc = os.environ.get("LC_ALL") or os.environ.get("LANG") or ""

    if enc.lower() != "utf-8":
        issues.append(
            CheckIssue(
                level="WARN",
                code="DEFAULT_ENCODING_NOT_UTF8",
                message="Default encoding не UTF-8",
                details={"defaultencoding": enc},
            )
        )
    if fsenc.lower() != "utf-8":
        issues.append(
            CheckIssue(
                level="WARN",
                code="FS_ENCODING_NOT_UTF8",
                message="Filesystem encoding не UTF-8",
                details={"filesystemencoding": fsenc},
            )
        )

    issues.append(
        CheckIssue(
            level="INFO",
            code="LOCALE_INFO",
            message="Информация о locale",
            details={"locale": loc or "unknown"},
        )
    )
    return issues


def _check_environment_flags() -> List[CheckIssue]:
    """
    Базовая защита: запрещаем debug в production режиме.
    """
    issues: List[CheckIssue] = []

    env = (os.environ.get("AGENT_MASH_ENV") or "").strip().lower()
    debug = _is_truthy_env(os.environ.get("DEBUG")) or _is_truthy_env(os.environ.get("AGENT_MASH_DEBUG"))
    testing = _is_truthy_env(os.environ.get("PYTEST_CURRENT_TEST")) or _is_truthy_env(os.environ.get("AGENT_MASH_TESTING"))

    if not env:
        issues.append(
            CheckIssue(
                level="WARN",
                code="ENV_NOT_SET",
                message="AGENT_MASH_ENV не задан; рекомендуется явно задавать окружение",
                details={},
            )
        )
        return issues

    # Нормализация: prod, production, stage, staging, dev, development, test
    if env in {"prod", "production"}:
        if debug:
            issues.append(
                CheckIssue(
                    level="ERROR",
                    code="DEBUG_IN_PROD",
                    message="Debug включён в production окружении",
                    details={"AGENT_MASH_ENV": env},
                )
            )
        if testing:
            issues.append(
                CheckIssue(
                    level="ERROR",
                    code="TESTING_IN_PROD",
                    message="Testing-флаги обнаружены в production окружении",
                    details={"AGENT_MASH_ENV": env},
                )
            )
        issues.append(
            CheckIssue(
                level="INFO",
                code="ENV_PROD_OK",
                message="Окружение production: базовые флаги в норме",
                details={"AGENT_MASH_ENV": env},
            )
        )
        return issues

    if env in {"stage", "staging"}:
        if testing:
            issues.append(
                CheckIssue(
                    level="WARN",
                    code="TESTING_IN_STAGING",
                    message="Testing-флаги обнаружены в staging окружении",
                    details={"AGENT_MASH_ENV": env},
                )
            )
        issues.append(
            CheckIssue(
                level="INFO",
                code="ENV_STAGING_INFO",
                message="Окружение staging",
                details={"AGENT_MASH_ENV": env, "debug": debug},
            )
        )
        return issues

    if env in {"dev", "development", "test"}:
        issues.append(
            CheckIssue(
                level="INFO",
                code="ENV_NON_PROD",
                message="Окружение не production",
                details={"AGENT_MASH_ENV": env, "debug": debug, "testing": testing},
            )
        )
        return issues

    issues.append(
        CheckIssue(
            level="WARN",
            code="ENV_UNKNOWN_VALUE",
            message="AGENT_MASH_ENV имеет неизвестное значение; используйте prod/staging/dev/test",
            details={"AGENT_MASH_ENV": env},
        )
    )
    return issues


def _check_required_env(required: Sequence[str]) -> List[CheckIssue]:
    issues: List[CheckIssue] = []
    for k in required:
        v = os.environ.get(k)
        if v is None or not str(v).strip():
            issues.append(
                CheckIssue(
                    level="ERROR",
                    code="REQUIRED_ENV_MISSING",
                    message="Отсутствует обязательная переменная окружения",
                    details={"key": k},
                )
            )
        else:
            issues.append(
                CheckIssue(
                    level="INFO",
                    code="ENV_PRESENT",
                    message="Переменная окружения присутствует",
                    details={"key": k, "value": _redact_env_value(k, v)},
                )
            )
    return issues


def _check_filesystem_layout(root: Path) -> List[CheckIssue]:
    issues: List[CheckIssue] = []

    if not root.exists():
        return [
            CheckIssue(
                level="ERROR",
                code="PROJECT_ROOT_NOT_FOUND",
                message="Корень проекта не найден",
                details={"project_root": str(root)},
            )
        ]

    # Минимальные ожидаемые элементы. Не делаем избыточно строгим, чтобы не ломать структуру.
    expected_any = [
        root / "agent_mash",
        root / "pyproject.toml",
    ]
    found_any = any(p.exists() for p in expected_any)
    if not found_any:
        issues.append(
            CheckIssue(
                level="WARN",
                code="PROJECT_LAYOUT_UNUSUAL",
                message="Структура проекта выглядит нестандартно (не найден agent_mash/ или pyproject.toml рядом с root)",
                details={"project_root": str(root), "checked": [str(p) for p in expected_any]},
            )
        )
    else:
        issues.append(
            CheckIssue(
                level="INFO",
                code="PROJECT_LAYOUT_OK",
                message="Базовые маркеры структуры проекта обнаружены",
                details={"project_root": str(root)},
            )
        )

    # Проверка записи в tmp (важно для runtime).
    tmp = Path(os.environ.get("TMPDIR") or "/tmp")
    if tmp.exists() and tmp.is_dir():
        testfile = tmp / f"agent_mash_selfcheck_{os.getpid()}.tmp"
        try:
            testfile.write_text("ok", encoding="utf-8")
            testfile.unlink(missing_ok=True)
            issues.append(
                CheckIssue(
                    level="INFO",
                    code="TMP_WRITE_OK",
                    message="Запись во временную директорию доступна",
                    details={"tmp": str(tmp)},
                )
            )
        except Exception as e:
            issues.append(
                CheckIssue(
                    level="WARN",
                    code="TMP_WRITE_FAILED",
                    message="Не удалось выполнить запись во временную директорию",
                    details={"tmp": str(tmp), "error": _safe_str(e)},
                )
            )
    else:
        issues.append(
            CheckIssue(
                level="WARN",
                code="TMP_NOT_FOUND",
                message="Временная директория не найдена или не является директорией",
                details={"tmp": str(tmp)},
            )
        )

    return issues


def _check_permissions_hardening(root: Path) -> List[CheckIssue]:
    """
    Проверяет очевидные риски прав доступа.
    """
    issues: List[CheckIssue] = []

    # Проверяем, что root не world-writable (частый анти-паттерн).
    perm = _perm_bits(root)
    if perm is not None:
        if perm & 0o002:
            issues.append(
                CheckIssue(
                    level="WARN",
                    code="ROOT_WORLD_WRITABLE",
                    message="Корень проекта доступен на запись всем (world-writable). Это риск саботажа",
                    details={"path": str(root), "mode_octal": oct(perm)},
                )
            )
        else:
            issues.append(
                CheckIssue(
                    level="INFO",
                    code="ROOT_PERMS_OK",
                    message="Права корня проекта выглядят нормально",
                    details={"path": str(root), "mode_octal": oct(perm)},
                )
            )
    else:
        issues.append(
            CheckIssue(
                level="INFO",
                code="ROOT_PERMS_UNKNOWN",
                message="Не удалось прочитать права корня проекта",
                details={"path": str(root)},
            )
        )

    # Запрещаем наличие .env с world-readable (утечка секретов).
    dotenv = root / ".env"
    if dotenv.exists() and dotenv.is_file():
        p = _perm_bits(dotenv)
        if p is not None and (p & 0o004):
            issues.append(
                CheckIssue(
                    level="WARN",
                    code="DOTENV_WORLD_READABLE",
                    message=".env доступен на чтение всем (world-readable). Это риск утечки секретов",
                    details={"path": str(dotenv), "mode_octal": oct(p)},
                )
            )
        else:
            issues.append(
                CheckIssue(
                    level="INFO",
                    code="DOTENV_PRESENT",
                    message=".env присутствует (проверьте управление секретами в продакшене)",
                    details={"path": str(dotenv), "mode_octal": oct(p) if p is not None else "unknown"},
                )
            )

    return issues


def _check_imports_smoke() -> List[CheckIssue]:
    """
    Smoke-проверка импортов критичных модулей bootstrap.
    Здесь не перечисляем весь проект: цель — раннее обнаружение поломок окружения.
    """
    issues: List[CheckIssue] = []

    critical_imports = [
        ("json", "stdlib"),
        ("pathlib", "stdlib"),
    ]

    for mod, kind in critical_imports:
        try:
            __import__(mod)
            issues.append(
                CheckIssue(
                    level="INFO",
                    code="IMPORT_OK",
                    message="Импорт модуля успешен",
                    details={"module": mod, "kind": kind},
                )
            )
        except Exception as e:
            issues.append(
                CheckIssue(
                    level="ERROR",
                    code="IMPORT_FAILED",
                    message="Не удалось импортировать модуль",
                    details={"module": mod, "kind": kind, "error": _safe_str(e)},
                )
            )

    # Опционально проверяем наличие typing_extensions в старых окружениях.
    try:
        import typing_extensions  # type: ignore  # noqa: F401

        issues.append(
            CheckIssue(
                level="INFO",
                code="TYPING_EXTENSIONS_PRESENT",
                message="typing_extensions доступен",
                details={},
            )
        )
    except Exception:
        issues.append(
            CheckIssue(
                level="INFO",
                code="TYPING_EXTENSIONS_ABSENT",
                message="typing_extensions отсутствует (это может быть нормально для вашей версии Python)",
                details={},
            )
        )

    return issues


def _check_external_binaries_optional(binaries: Sequence[str]) -> List[CheckIssue]:
    """
    Опциональные внешние зависимости. Не делаем ERROR, чтобы не ломать минимальные окружения.
    """
    issues: List[CheckIssue] = []
    for b in binaries:
        p = shutil.which(b)
        if p:
            issues.append(
                CheckIssue(
                    level="INFO",
                    code="BINARY_FOUND",
                    message="Внешний бинарь обнаружен",
                    details={"binary": b, "path": p},
                )
            )
        else:
            issues.append(
                CheckIssue(
                    level="WARN",
                    code="BINARY_MISSING",
                    message="Внешний бинарь не найден (может быть нормально для runtime окружения)",
                    details={"binary": b},
                )
            )
    return issues


def _check_time_sanity() -> List[CheckIssue]:
    """
    Проверка времени важна для токенов, TTL, аудит-цепочек.
    """
    issues: List[CheckIssue] = []
    now = datetime.now(timezone.utc)

    # Дата ниже 2020 часто означает сломанные часы.
    if now.year < 2020:
        issues.append(
            CheckIssue(
                level="ERROR",
                code="SYSTEM_TIME_SUSPECT",
                message="Системное время выглядит некорректным (слишком ранний год)",
                details={"utc_now": now.isoformat()},
            )
        )
    else:
        issues.append(
            CheckIssue(
                level="INFO",
                code="SYSTEM_TIME_OK",
                message="Системное время выглядит корректным",
                details={"utc_now": now.isoformat()},
            )
        )
    return issues


def _check_no_public_bindings_hint(env_keys: Sequence[str]) -> List[CheckIssue]:
    """
    Хелпер на будущее: если сервис слушает 0.0.0.0 в проде — это часто ошибка.
    В текущем файле не применяется по умолчанию, но оставлен как промышленная заготовка.
    """
    issues: List[CheckIssue] = []
    env = (os.environ.get("AGENT_MASH_ENV") or "").strip().lower()
    if env not in {"prod", "production"}:
        return issues

    for k in env_keys:
        v = (os.environ.get(k) or "").strip()
        if not v:
            continue
        if re.search(r"\b0\.0\.0\.0\b", v) or re.search(r"\b::\b", v):
            issues.append(
                CheckIssue(
                    level="WARN",
                    code="PUBLIC_BINDING_IN_PROD",
                    message="Обнаружена потенциально публичная привязка адреса в production",
                    details={"key": k, "value": _redact_env_value(k, v)},
                )
            )
    return issues


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-mash-self-check", add_help=True)
    parser.add_argument(
        "--project-root",
        type=str,
        default="",
        help="Абсолютный путь к корню проекта (если пусто, определяется автоматически)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Строгий режим: при ERROR возвращает ненулевой код",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="Мягкий режим: всегда 0, но отчёт содержит ошибки",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Печатать отчёт в JSON (детерминированно)",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    strict = True
    if args.no_strict:
        strict = False
    if args.strict:
        strict = True

    project_root: Optional[Path] = None
    if args.project_root:
        project_root = Path(args.project_root).resolve()

    sc = build_default_self_check(project_root=project_root)

    try:
        report = sc.run(strict=strict)
        if args.json:
            sys.stdout.write(report.to_json() + "\n")
        else:
            # Без спец-символов. Короткий текстовый вывод.
            sys.stdout.write("SELF_CHECK_OK\n")
        return 0
    except SelfCheckError as e:
        # e.args[0] содержит JSON отчёт.
        if args.json:
            sys.stdout.write(_safe_str(e.args[0], max_len=200000) + "\n")
        else:
            sys.stdout.write("SELF_CHECK_FAILED\n")
        return 2
    except Exception as e:
        # Неожиданная ошибка самопроверки.
        if args.json:
            payload = {
                "fatal": True,
                "error": {
                    "type": e.__class__.__name__,
                    "message": _safe_str(e),
                    "traceback": _safe_str(traceback.format_exc(), max_len=8000),
                },
                "utc_now": _utc_now_iso(),
            }
            sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        else:
            sys.stdout.write("SELF_CHECK_FATAL\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybersecurity-core/cli/tools/push_policy.py

Промышленный CLI-инструмент для безопасной отправки (push) политик безопасности
в удалённый Policy-Store / Policy-API с валидацией, подписью, идемпотентностью,
конкурентной загрузкой, журналированием в формате JSON и механизмом резюме/повтора.

Ключевые возможности:
- Поддержка директорий и одиночных файлов (JSON/YAML) с рекурсивным обходом.
- Опциональная валидация JSON Schema (если установлен пакет `jsonschema`).
- Опциональная поддержка YAML (если установлен пакет `PyYAML`).
- HMAC-SHA256 подпись полезной нагрузки (без внешних зависимостей).
- Идемпотентность через заголовок Idempotency-Key (на основе SHA256 контента).
- Заголовки целостности (Digest: SHA-256=...).
- Gzip-сжатие полезной нагрузки.
- Конкурентная отправка (ThreadPoolExecutor) с экспоненциальными повторами и джиттером.
- Строгое структурированное логирование (JSON) совместимое с ECS-подобной схемой.
- Файл состояния для резюме (skip уже успешно отправленных артефактов).
- Гибкие таймауты, ограничение попыток, верификация TLS, поддержка прокси через env.

Зависимости:
- Стандартная библиотека Python.
- Необязательные: `jsonschema`, `PyYAML` — будут автоматически задействованы, если доступны.

Примеры:
  $ python -m cybersecurity_core.cli.tools.push_policy \
      --src ./policies \
      --endpoint https://policy.example.com/api/v1 \
      --tenant acme --policy-type access \
      --api-key "$API_KEY" \
      --schema ./schema/policy.schema.json \
      --concurrency 6 --retries 5 --timeout 15 --dry-run

Формат ожидаемых документов:
- JSON или YAML объект, содержащий хотя бы одно поле для идентификатора политики.
  Порядок поиска идентификатора: explicit --id-field аргумент, иначе поля: ["id","policy_id","name","slug"].

Автор: Aethernova / NeuroCity
Лицензия: MIT (или по политике репозитория)
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import functools
import gzip
import hashlib
import hmac
import io
import json
import os
import random
import re
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from urllib import request, error, parse

# Опциональные зависимости
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    import jsonschema  # type: ignore
except Exception:  # pragma: no cover
    jsonschema = None  # type: ignore

# Константы
DEFAULT_ID_FIELDS = ("id", "policy_id", "name", "slug")
STATE_FILE_NAME = ".push_policy.state.json"
LOG_LOCK = threading.Lock()


# ========================= УТИЛИТЫ ЛОГИРОВАНИЯ ==============================

def log_json(level: str, message: str, **fields: Any) -> None:
    """
    Структурированное логирование в формате JSON, потокобезопасно.
    Поля совместимы с ECS-подобной схемой: "@timestamp", "log.level", "message", "event.*", "error.*"
    """
    record = {
        "@timestamp": dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
        "log.level": level.lower(),
        "message": message,
    }
    record.update(fields or {})
    with LOG_LOCK:
        sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def log_error(message: str, exc: Optional[BaseException] = None, **fields: Any) -> None:
    err = {
        "error.message": message,
    }
    if exc is not None:
        err.update({
            "error.type": exc.__class__.__name__,
            "error.stack_trace": "".join(traceback.format_exception(exc)).strip(),
        })
    log_json("error", message, **{**fields, **err})


# ========================= ЗАГРУЗКА/ПАРСИНГ ДОКУМЕНТОВ =====================

@dataclasses.dataclass(frozen=True)
class PolicyDoc:
    path: Path
    raw: bytes
    fmt: str                # "json" | "yaml"
    data: Dict[str, Any]
    sha256: str             # hex
    id: str
    content_encoding: str   # "gzip" | "identity"


def is_policy_file(p: Path) -> bool:
    if not p.is_file():
        return False
    return p.suffix.lower() in (".json", ".yaml", ".yml")


def load_bytes(p: Path) -> bytes:
    with p.open("rb") as f:
        return f.read()


def parse_doc(content: bytes, path: Path) -> Tuple[str, Dict[str, Any]]:
    # Попытка определить формат по расширению; fallback по эвристике
    suffix = path.suffix.lower()
    text: Optional[str] = None
    if suffix == ".json":
        return "json", json.loads(content.decode("utf-8"))
    if suffix in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("Для YAML требуется пакет PyYAML, который не установлен.")
        return "yaml", yaml.safe_load(content.decode("utf-8"))

    # Эвристика: пробуем как JSON, затем YAML (если доступен)
    try:
        return "json", json.loads(content.decode("utf-8"))
    except Exception:
        pass
    if yaml is not None:
        return "yaml", yaml.safe_load(content.decode("utf-8"))
    raise ValueError(f"Не удалось определить формат/распарсить документ: {path}")


def detect_policy_id(doc: Dict[str, Any], id_field: Optional[str]) -> str:
    if id_field:
        val = doc.get(id_field)
        if isinstance(val, (str, int)):
            return str(val).strip()
        raise ValueError(f"Поле идентификатора '{id_field}' отсутствует или имеет неподдерживаемый тип.")
    for key in DEFAULT_ID_FIELDS:
        val = doc.get(key)
        if isinstance(val, (str, int)):
            s = str(val).strip()
            if s:
                return s
    raise ValueError("Не найден идентификатор политики (попробуйте --id-field).")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def gzip_bytes(b: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b)
    return buf.getvalue()


def load_policy_docs(src: Path,
                     recursive: bool,
                     id_field: Optional[str],
                     gzip_payload: bool) -> Iterable[PolicyDoc]:
    if src.is_file():
        files = [src]
    else:
        if recursive:
            files = [p for p in src.rglob("*") if is_policy_file(p)]
        else:
            files = [p for p in src.iterdir() if is_policy_file(p)]

    for p in sorted(files):
        raw = load_bytes(p)
        fmt, data = parse_doc(raw, p)
        pid = detect_policy_id(data, id_field)
        digest = sha256_hex(raw)
        if gzip_payload:
            gz = gzip_bytes(raw)
            yield PolicyDoc(path=p, raw=gz, fmt=fmt, data=data, sha256=digest, id=pid, content_encoding="gzip")
        else:
            yield PolicyDoc(path=p, raw=raw, fmt=fmt, data=data, sha256=digest, id=pid, content_encoding="identity")


# ========================= СХЕМА/ВАЛИДАЦИЯ ==================================

def load_json_schema(schema_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if not schema_path:
        return None
    with schema_path.open("rb") as f:
        return json.loads(f.read().decode("utf-8"))


def validate_against_schema(obj: Dict[str, Any], schema: Optional[Dict[str, Any]]) -> None:
    if schema is None:
        return
    if jsonschema is None:
        raise RuntimeError("Указана схема, но пакет 'jsonschema' не установлен.")
    jsonschema.validate(obj, schema)  # type: ignore


# ========================= ПОДПИСЬ HMAC =====================================

def hmac_sign(secret: Optional[str], payload: bytes) -> Optional[str]:
    """
    Возвращает base64 подпись HMAC-SHA256 по секрету. Если секрета нет — None.
    """
    if not secret:
        return None
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("ascii")


# ========================= HTTP КЛИЕНТ (stdlib) =============================

@dataclasses.dataclass(frozen=True)
class HttpResult:
    ok: bool
    status: int
    body: Optional[str]
    headers: Dict[str, str]


def http_request(method: str,
                 url: str,
                 headers: Dict[str, str],
                 data: Optional[bytes],
                 timeout: int,
                 verify_tls: bool) -> HttpResult:
    # В stdlib urllib.request нет явной опции verify=False; используем контекст, если нужно
    ctx = None
    if not verify_tls:
        import ssl  # локальный импорт для ясности
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = request.Request(url=url, data=data, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body_bytes = resp.read()
            try:
                body = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body = None
            return HttpResult(
                ok=200 <= resp.status < 300,
                status=resp.status,
                body=body,
                headers={k.lower(): v for k, v in resp.getheaders()},
            )
    except error.HTTPError as e:
        body = None
        try:
            body_bytes = e.read()
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass
        return HttpResult(
            ok=False,
            status=e.code,
            body=body,
            headers={k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
        )
    except Exception as e:
        raise e


# ========================= СОСТОЯНИЕ РЕЗЮМЕ =================================

@dataclasses.dataclass
class PushState:
    path: Path
    data: Dict[str, Any]

    @classmethod
    def load(cls, root: Path) -> "PushState":
        p = root / STATE_FILE_NAME
        if not p.exists():
            return cls(path=p, data={"success": {}, "failed": {}})
        try:
            with p.open("r", encoding="utf-8") as f:
                return cls(path=p, data=json.load(f))
        except Exception:
            return cls(path=p, data={"success": {}, "failed": {}})

    def mark_success(self, policy: PolicyDoc) -> None:
        self.data.setdefault("success", {})
        self.data["success"][str(policy.path)] = {
            "id": policy.id,
            "sha256": policy.sha256,
            "ts": dt.datetime.utcnow().isoformat() + "Z",
        }

    def mark_failed(self, policy: PolicyDoc, status: int, body: Optional[str]) -> None:
        self.data.setdefault("failed", {})
        self.data["failed"][str(policy.path)] = {
            "id": policy.id,
            "sha256": policy.sha256,
            "status": status,
            "body": body,
            "ts": dt.datetime.utcnow().isoformat() + "Z",
        }

    def was_success(self, policy: PolicyDoc) -> bool:
        s = self.data.get("success", {})
        entry = s.get(str(policy.path))
        return bool(entry and entry.get("sha256") == policy.sha256)

    def save(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        tmp.replace(self.path)


# ========================= ОСНОВНАЯ ЛОГИКА PUSH =============================

@dataclasses.dataclass(frozen=True)
class PushConfig:
    endpoint: str
    tenant: Optional[str]
    policy_type: Optional[str]
    method: str
    api_key: Optional[str]
    bearer_token: Optional[str]
    hmac_secret: Optional[str]
    timeout: int
    retries: int
    retry_backoff: float
    retry_max_backoff: float
    verify_tls: bool
    dry_run: bool
    extra_headers: Dict[str, str]


def build_policy_url(base: str, policy_id: str, tenant: Optional[str], policy_type: Optional[str]) -> str:
    # Формируем endpoint: {base}/policies/{id}?tenant=...&type=...
    base = base.rstrip("/")
    path = f"{base}/policies/{parse.quote(policy_id, safe='')}"
    qs = {}
    if tenant:
        qs["tenant"] = tenant
    if policy_type:
        qs["type"] = policy_type
    if qs:
        return f"{path}?{parse.urlencode(qs)}"
    return path


def make_headers(cfg: PushConfig, policy: PolicyDoc) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "Content-Type": "application/json" if policy.fmt == "json" else "application/yaml",
        "Accept": "application/json, */*;q=0.1",
        "Content-Encoding": policy.content_encoding,
        "Digest": f"SHA-256={base64.b64encode(hashlib.sha256(policy.raw).digest()).decode('ascii')}",
        "Idempotency-Key": policy.sha256,
        "User-Agent": "aethernova-push-policy/1.0",
    }
    if cfg.api_key:
        headers["X-API-Key"] = cfg.api_key
    if cfg.bearer_token:
        headers["Authorization"] = f"Bearer {cfg.bearer_token}"
    sig = hmac_sign(cfg.hmac_secret, policy.raw)
    if sig:
        headers["X-Signature"] = sig
        headers["X-Signature-Alg"] = "HMAC-SHA256"
    if cfg.extra_headers:
        headers.update(cfg.extra_headers)
    return headers


def jittered_sleep(base: float, attempt: int, max_backoff: float) -> None:
    # Экспоненциальный бэкофф с джиттером
    delay = min(max_backoff, base * (2 ** (attempt - 1)))
    delay = delay * (0.5 + random.random())  # 50-150%
    time.sleep(delay)


def push_single(policy: PolicyDoc, cfg: PushConfig) -> Tuple[str, bool, int, Optional[str]]:
    """
    Возвращает: (policy_path, ok, status, body)
    """
    url = build_policy_url(cfg.endpoint, policy.id, cfg.tenant, cfg.policy_type)
    headers = make_headers(cfg, policy)

    if cfg.dry_run:
        log_json(
            "info",
            "DRY-RUN: пропуск отправки политики",
            event={"action": "dry_run", "category": "policy_push"},
            policy={"id": policy.id, "path": str(policy.path), "sha256": policy.sha256},
            http={"request": {"method": cfg.method, "url": url}, "response": {"status_code": 0}},
        )
        return str(policy.path), True, 0, None

    for attempt in range(1, cfg.retries + 2):  # первая попытка + retries
        try:
            res = http_request(cfg.method, url, headers, policy.raw, cfg.timeout, cfg.verify_tls)
            if res.ok:
                log_json(
                    "info",
                    "Политика отправлена",
                    event={"action": "push", "category": "policy", "outcome": "success"},
                    policy={"id": policy.id, "path": str(policy.path), "sha256": policy.sha256},
                    http={"request": {"method": cfg.method, "url": url},
                          "response": {"status_code": res.status}},
                )
                return str(policy.path), True, res.status, res.body
            else:
                # Ретрай только на 5xx/429
                retriable = res.status >= 500 or res.status == 429
                log_json(
                    "warning" if retriable else "error",
                    "Неуспешный ответ от Policy-API",
                    event={"action": "push", "category": "policy", "outcome": "failure"},
                    policy={"id": policy.id, "path": str(policy.path), "sha256": policy.sha256},
                    http={"request": {"method": cfg.method, "url": url},
                          "response": {"status_code": res.status, "body": res.body}},
                    attempt=attempt,
                    retriable=retriable,
                )
                if retriable and attempt <= cfg.retries:
                    jittered_sleep(cfg.retry_backoff, attempt, cfg.retry_max_backoff)
                    continue
                return str(policy.path), False, res.status, res.body
        except Exception as e:
            retriable = attempt <= cfg.retries
            log_error(
                "Исключение при отправке политики",
                e,
                event={"action": "push", "category": "policy", "outcome": "error"},
                policy={"id": policy.id, "path": str(policy.path), "sha256": policy.sha256},
                attempt=attempt,
                retriable=retriable,
            )
            if retriable:
                jittered_sleep(cfg.retry_backoff, attempt, cfg.retry_max_backoff)
                continue
            return str(policy.path), False, -1, str(e)
    # unreachable
    return str(policy.path), False, -1, "internal-error"


# ========================= CLI / main =======================================

def parse_kv_list(items: List[str]) -> Dict[str, str]:
    """
    Преобразует список вида ["Key: Val", "Foo=Bar"] в словарь заголовков.
    Разделители: ":", "=". Пробелы вокруг разделителя допускаются.
    """
    res: Dict[str, str] = {}
    for raw in items:
        if ":" in raw:
            k, v = raw.split(":", 1)
        elif "=" in raw:
            k, v = raw.split("=", 1)
        else:
            raise argparse.ArgumentTypeError(f"Неверный формат заголовка: {raw!r}")
        res[k.strip()] = v.strip()
    return res


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="push_policy",
        description="Отправка (push) политик безопасности в Policy-API с валидацией и подписью.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--src", type=Path, required=True, help="Файл или директория с политиками (JSON/YAML).")
    p.add_argument("--recursive", action="store_true", help="Рекурсивный обход директорий.")
    p.add_argument("--endpoint", type=str, required=True, help="Базовый URL Policy-API, напр. https://host/api/v1")
    p.add_argument("--tenant", type=str, default=os.getenv("POLICY_TENANT") or None, help="Идентификатор арендатора.")
    p.add_argument("--policy-type", type=str, default=os.getenv("POLICY_TYPE") or None, help="Тип политики (категория).")
    p.add_argument("--method", type=str, default="PUT", choices=["PUT", "POST"], help="HTTP-метод для отправки.")
    p.add_argument("--api-key", type=str, default=os.getenv("POLICY_API_KEY") or None, help="API ключ (X-API-Key).")
    p.add_argument("--bearer-token", type=str, default=os.getenv("POLICY_BEARER_TOKEN") or None,
                   help="Bearer-токен (Authorization).")
    p.add_argument("--hmac-secret", type=str, default=os.getenv("POLICY_HMAC_SECRET") or None,
                   help="Секрет для подписи HMAC-SHA256 (X-Signature).")
    p.add_argument("--schema", type=Path, default=None, help="Путь к JSON Schema для валидации.")
    p.add_argument("--id-field", type=str, default=None, help="Название поля идентификатора в документе.")
    p.add_argument("--gzip", dest="gzip_payload", action="store_true", help="Gzip-сжатие полезной нагрузки.")
    p.add_argument("--concurrency", type=int, default=max(4, os.cpu_count() or 4), help="Число параллельных воркеров.")
    p.add_argument("--retries", type=int, default=4, help="Число повторов при временных ошибках (5xx/429/исключения).")
    p.add_argument("--retry-backoff", type=float, default=0.8, help="Базовый бэкофф, сек.")
    p.add_argument("--retry-max-backoff", type=float, default=12.0, help="Макс. задержка бэкоффа, сек.")
    p.add_argument("--timeout", type=int, default=20, help="Таймаут HTTP-запроса, сек.")
    p.add_argument("--insecure-skip-tls-verify", action="store_true", help="Отключить проверку TLS сертификата.")
    p.add_argument("--dry-run", action="store_true", help="Только проверить/прологировать, без отправки.")
    p.add_argument("--header", dest="headers", action="append", default=[],
                   help='Доп. заголовки: "Key: Value" или "Key=Value". Можно указывать несколько раз.')
    p.add_argument("--resume-state-root", type=Path, default=None,
                   help="Каталог для файла состояния. По умолчанию — src для директорий или родитель файла.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.src.exists():
        log_error("Путь --src не существует", None, path=str(args.src))
        return 2

    # Файл состояния
    if args.resume_state_root:
        state_root = args.resume_state_root
    else:
        state_root = args.src if args.src.is_dir() else args.src.parent
    state = PushState.load(state_root)

    # Схема
    schema = None
    try:
        schema = load_json_schema(args.schema)
    except Exception as e:
        log_error("Ошибка загрузки схемы", e, schema_path=str(args.schema) if args.schema else None)
        return 2

    # Парсим заголовки
    try:
        extra_headers = parse_kv_list(args.headers) if args.headers else {}
    except Exception as e:
        log_error("Некорректные дополнительные заголовки", e, headers=args.headers)
        return 2

    # Загрузка документов
    try:
        docs = list(load_policy_docs(args.src, args.recursive, args.id_field, args.gzip_payload))
    except Exception as e:
        log_error("Ошибка загрузки/парсинга документов", e, src=str(args.src))
        return 2

    if not docs:
        log_json("warning", "Не найдено политик для отправки", src=str(args.src))
        return 0

    # Валидация
    for d in docs:
        try:
            validate_against_schema(d.data, schema)
        except Exception as e:
            log_error("Валидация не пройдена", e, policy={"id": d.id, "path": str(d.path)})
            return 3

    cfg = PushConfig(
        endpoint=args.endpoint,
        tenant=args.tenant,
        policy_type=args.policy_type,
        method=args.method.upper(),
        api_key=args.api_key,
        bearer_token=args.bearer_token,
        hmac_secret=args.hmac_secret,
        timeout=args.timeout,
        retries=args.retries,
        retry_backoff=float(args.retry_backoff),
        retry_max_backoff=float(args.retry_max_backoff),
        verify_tls=not args.insecure_skip_tls_verify,
        dry_run=args.dry_run,
        extra_headers=extra_headers,
    )

    # Фильтр уже отправленных (если контент не менялся)
    pending: List[PolicyDoc] = []
    skipped: List[PolicyDoc] = []
    for d in docs:
        if state.was_success(d):
            skipped.append(d)
        else:
            pending.append(d)

    if skipped:
        log_json(
            "info",
            "Пропущены ранее успешно отправленные политики с тем же контентом",
            count=len(skipped),
            items=[{"path": str(x.path), "id": x.id} for x in skipped[:25]],
        )

    # Параллельная отправка
    started = time.time()
    results: List[Tuple[str, bool, int, Optional[str], PolicyDoc]] = []

    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            fut_to_doc = {
                pool.submit(push_single, d, cfg): d for d in pending
            }
            for fut in concurrent.futures.as_completed(fut_to_doc):
                d = fut_to_doc[fut]
                try:
                    path_str, ok, status, body = fut.result()
                except Exception as e:
                    log_error("Необработанное исключение при отправке", e, policy={"id": d.id, "path": str(d.path)})
                    path_str, ok, status, body = str(d.path), False, -1, str(e)
                results.append((path_str, ok, status, body, d))
                if ok:
                    state.mark_success(d)
                else:
                    state.mark_failed(d, status, body)
                # Периодическое сохранение состояния для устойчивости
                with contextlib.suppress(Exception):
                    state.save()

    duration = time.time() - started
    total = len(docs)
    done = len([r for r in results if r[1]]) + len(skipped) if pending else len(skipped)
    failed = len([r for r in results if not r[1]])

    # Финальное сохранение состояния
    with contextlib.suppress(Exception):
        state.save()

    log_json(
        "info",
        "Завершено",
        event={"action": "push_batch", "category": "policy"},
        metrics={
            "total": total,
            "pending": len(pending),
            "skipped": len(skipped),
            "succeeded": done - failed,
            "failed": failed,
            "duration_seconds": round(duration, 3),
            "concurrency": args.concurrency,
        },
    )

    # Возвращаем код возврата, подходящий для CI
    if failed > 0:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

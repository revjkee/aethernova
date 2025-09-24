# security-core/cli/tools/assign_role.py
from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import json
import os
import re
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# -----------------------------
# Опциональная зависимость httpx
# -----------------------------
_HAS_HTTPX = False
try:  # pragma: no cover
    import httpx  # type: ignore
    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    _HAS_HTTPX = False

# -----------------------------
# Константы/валидация/утилиты
# -----------------------------

ROLE_RE = re.compile(r"^[A-Za-z0-9:_\-.]{1,128}$")
ID_RE = re.compile(r"^[A-Za-z0-9:_\-/\.@+]{1,256}$")
SCOPE_TYPE_ALLOWED = {"tenant", "project", "resource"}
PRINCIPAL_TYPE_ALLOWED = {"user", "group", "service"}

DEFAULT_TIMEOUT = float(os.getenv("SEC_CORE_CLI_HTTP_TIMEOUT", "10"))
DEFAULT_CONCURRENCY = int(os.getenv("SEC_CORE_CLI_CONCURRENCY", "8"))
DEFAULT_MAX_RETRIES = int(os.getenv("SEC_CORE_CLI_MAX_RETRIES", "4"))
DEFAULT_BASE_URL = os.getenv("SEC_CORE_CLI_IAM_BASE_URL", "http://127.0.0.1:8080")
DEFAULT_ENDPOINT = os.getenv("SEC_CORE_CLI_IAM_ENDPOINT", "/v1/iam/assignments")
DEFAULT_USER_AGENT = os.getenv("SEC_CORE_CLI_USER_AGENT", "security-core-assign-role/1.0")

# Ограничение на размер полезной нагрузки в одном назначении (страховка)
MAX_PAYLOAD_BYTES = int(os.getenv("SEC_CORE_CLI_MAX_PAYLOAD", "65536"))

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def parse_time(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    # unix seconds
    if s.isdigit():
        return datetime.fromtimestamp(int(s), tz=timezone.utc)
    # ISO 8601 / RFC3339
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except Exception:
        raise ValueError(f"invalid time: {s}")

def gen_idem_key() -> str:
    return str(uuid.uuid4())

def jlog(level: str, message: str, **fields: Any) -> None:
    payload = {"ts": iso(utcnow()), "level": level, "message": message}
    payload.update(fields)
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), file=sys.stdout)

# -----------------------------
# Модель данных
# -----------------------------

@dataclass
class Principal:
    type: str
    id: str

    def validate(self) -> None:
        if self.type not in PRINCIPAL_TYPE_ALLOWED:
            raise ValueError(f"principal.type must be one of {sorted(PRINCIPAL_TYPE_ALLOWED)}")
        if not ID_RE.match(self.id):
            raise ValueError("principal.id has invalid characters or length")

@dataclass
class Scope:
    type: str
    id: str

    def validate(self) -> None:
        if self.type not in SCOPE_TYPE_ALLOWED:
            raise ValueError(f"scope.type must be one of {sorted(SCOPE_TYPE_ALLOWED)}")
        if not ID_RE.match(self.id):
            raise ValueError("scope.id has invalid characters or length")

@dataclass
class Constraints:
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    condition: Optional[str] = None  # выражение политики (например CEL)

    def as_api(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.not_before:
            out["not_before"] = iso(self.not_before)
        if self.not_after:
            out["not_after"] = iso(self.not_after)
        if self.condition:
            out["condition"] = self.condition
        return out

@dataclass
class Assignment:
    principal: Principal
    roles: Tuple[str, ...]
    scope: Scope
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    constraints: Constraints = field(default_factory=Constraints)
    idempotency_key: Optional[str] = None  # если не указан — будет сгенерирован

    def validate(self) -> None:
        self.principal.validate()
        self.scope.validate()
        if not self.roles:
            raise ValueError("roles must not be empty")
        for r in self.roles:
            if not ROLE_RE.match(r):
                raise ValueError(f"invalid role name: {r}")
        # Временные окна
        if self.constraints.not_before and self.constraints.not_after:
            if self.constraints.not_before >= self.constraints.not_after:
                raise ValueError("not_before must be earlier than not_after")
        # Метаданные ограничим по размеру
        try:
            b = json.dumps(self.metadata, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except Exception:
            raise ValueError("metadata must be JSON-serializable")
        if len(b) > 8 * 1024:
            raise ValueError("metadata too large (>8KiB)")
        # Итоговый размер полезной нагрузки
        payload = self.as_payload()
        enc = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(enc) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload too large ({len(enc)} bytes)")

    def as_payload(self) -> Dict[str, Any]:
        return {
            "principal": dataclasses.asdict(self.principal),
            "roles": list(self.roles),
            "scope": dataclasses.asdict(self.scope),
            "reason": self.reason,
            "metadata": self.metadata or {},
            "constraints": self.constraints.as_api(),
        }

# -----------------------------
# HTTP клиент
# -----------------------------

class IamClient:
    def __init__(
        self,
        base_url: str,
        endpoint: str,
        token: Optional[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        verify: Union[bool, str, None] = True,
        qps: float = 10.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        dry_run: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        if not _HAS_HTTPX:
            raise RuntimeError("httpx is not installed. Please `pip install httpx`.")
        self.base_url = base_url.rstrip("/")
        self.endpoint = endpoint
        self.token = token
        self.client = httpx.AsyncClient(  # type: ignore
            base_url=self.base_url,
            timeout=timeout,
            headers=self._headers(user_agent),
            verify=verify if verify is not None else True,
            http2=True,
            limits=httpx.Limits(max_keepalive_connections=100, max_connections=100),  # type: ignore
            cert=(cert, key) if cert and key else (cert if cert else None),
        )
        self.qps = max(0.1, qps)
        self.min_interval = 1.0 / self.qps
        self._last_req = 0.0
        self.max_retries = max(0, int(max_retries))
        self.dry_run = dry_run

    def _headers(self, ua: str) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": ua,
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.dry_run:
            h["X-Dry-Run"] = "true"
        return h

    async def close(self) -> None:
        await self.client.aclose()

    async def assign(self, item: Assignment, *, idem_key: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        # Throttle QPS
        now = time.monotonic()
        delta = now - self._last_req
        if delta < self.min_interval:
            await asyncio.sleep(self.min_interval - delta)
        self._last_req = time.monotonic()

        payload = item.as_payload()
        idem = idem_key or item.idempotency_key or gen_idem_key()
        headers = {"Idempotency-Key": idem}

        # Ретраи на сетевые/5xx
        attempt = 0
        wait = 0.2
        while True:
            attempt += 1
            try:
                resp = await self.client.post(self.endpoint, headers=headers, json=payload)
                status = resp.status_code
                if status >= 500:
                    raise httpx.HTTPStatusError("server error", request=resp.request, response=resp)  # type: ignore
                data: Dict[str, Any] = {}
                if resp.headers.get("Content-Type", "").startswith("application/json"):
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text}
                else:
                    data = {"raw": resp.text}
                return status, data
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError, httpx.HTTPStatusError) as e:  # type: ignore
                if attempt > self.max_retries:
                    raise
                await asyncio.sleep(wait)
                wait = min(wait * 2, 2.0)

# -----------------------------
# Парсинг входных данных
# -----------------------------

def load_from_json(path: str) -> List[Assignment]:
    raw = json.loads(open(path, "r", encoding="utf-8").read())
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise ValueError("JSON must be an object or array of objects")
    return [assignment_from_dict(x) for x in raw]

def load_from_ndjson(path: str) -> List[Assignment]:
    out: List[Assignment] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            out.append(assignment_from_dict(obj))
    return out

def load_from_csv(path: str) -> List[Assignment]:
    out: List[Assignment] = []
    with open(path, newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            roles = parse_roles(row.get("roles"))
            principal = Principal(type=must(row.get("principal_type")), id=must(row.get("principal_id")))
            scope = Scope(type=must(row.get("scope_type")), id=must(row.get("scope_id")))
            constraints = Constraints(
                not_before=parse_time(row.get("not_before")),
                not_after=parse_time(row.get("not_after")),
                condition=row.get("condition") or None,
            )
            metadata = parse_json_maybe(row.get("metadata"))
            item = Assignment(
                principal=principal,
                roles=tuple(roles),
                scope=scope,
                reason=row.get("reason") or None,
                metadata=metadata,
                constraints=constraints,
                idempotency_key=row.get("idempotency_key") or None,
            )
            out.append(item)
    return out

def parse_json_maybe(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    s = s.strip()
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
        return {"value": obj}
    except Exception:
        # трактуем как строку
        return {"value": s}

def parse_roles(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [x for x in [p.strip() for p in s.split(",")] if x]

def must(v: Optional[str]) -> str:
    if not v or not v.strip():
        raise ValueError("required field is missing")
    return v.strip()

def assignment_from_dict(d: Mapping[str, Any]) -> Assignment:
    # допускаем ключи верхнего уровня (principal, scope, roles, reason, metadata, constraints)
    if "principal" in d and "scope" in d and "roles" in d:
        pr = d["principal"]; sc = d["scope"]
        item = Assignment(
            principal=Principal(type=pr["type"], id=pr["id"]),
            roles=tuple(d["roles"]),
            scope=Scope(type=sc["type"], id=sc["id"]),
            reason=d.get("reason"),
            metadata=d.get("metadata") or {},
            constraints=Constraints(
                not_before=parse_time((d.get("constraints") or {}).get("not_before")),
                not_after=parse_time((d.get("constraints") or {}).get("not_after")),
                condition=(d.get("constraints") or {}).get("condition"),
            ),
            idempotency_key=d.get("idempotency_key"),
        )
        return item
    # плоский формат
    roles = d.get("roles") or d.get("role")
    if isinstance(roles, str):
        roles = parse_roles(roles)
    principal = Principal(type=str(d["principal_type"]), id=str(d["principal_id"]))
    scope = Scope(type=str(d["scope_type"]), id=str(d["scope_id"]))
    constraints = Constraints(
        not_before=parse_time(d.get("not_before")),
        not_after=parse_time(d.get("not_after")),
        condition=d.get("condition"),
    )
    return Assignment(
        principal=principal,
        roles=tuple(roles or ()),
        scope=scope,
        reason=d.get("reason"),
        metadata=d.get("metadata") or {},
        constraints=constraints,
        idempotency_key=d.get("idempotency_key"),
    )

# -----------------------------
# Исполнитель
# -----------------------------

@dataclass
class ExecOptions:
    concurrency: int = DEFAULT_CONCURRENCY
    timeout: float = DEFAULT_TIMEOUT
    base_url: str = DEFAULT_BASE_URL
    endpoint: str = DEFAULT_ENDPOINT
    token: Optional[str] = None
    cert: Optional[str] = None
    key: Optional[str] = None
    ca: Optional[str] = None
    insecure: bool = False
    qps: float = 10.0
    max_retries: int = DEFAULT_MAX_RETRIES
    dry_run: bool = False
    exit_on_first_error: bool = False

@dataclass
class ItemResult:
    ok: bool
    status: int
    idempotency_key: str
    response: Dict[str, Any]
    error: Optional[str] = None
    assignment: Optional[Assignment] = None

async def execute(assignments: Sequence[Assignment], opts: ExecOptions) -> Tuple[List[ItemResult], Dict[str, Any]]:
    if not _HAS_HTTPX:
        print("ERROR: httpx is required. Install with `pip install httpx`.", file=sys.stderr)
        sys.exit(2)

    verify: Union[bool, str, None] = True
    if opts.insecure:
        verify = False
    elif opts.ca:
        verify = opts.ca

    client = IamClient(
        base_url=opts.base_url,
        endpoint=opts.endpoint,
        token=opts.token,
        timeout=opts.timeout,
        cert=opts.cert,
        key=opts.key,
        verify=verify,
        qps=opts.qps,
        max_retries=opts.max_retries,
        dry_run=opts.dry_run,
    )

    sem = asyncio.Semaphore(max(1, opts.concurrency))
    results: List[ItemResult] = []
    failures = 0

    async def worker(item: Assignment) -> None:
        nonlocal failures
        try:
            item.validate()
            idem = item.idempotency_key or gen_idem_key()
            async with sem:
                status, data = await client.assign(item, idem_key=idem)
            ok = 200 <= status < 300
            if not ok:
                failures += 1
            res = ItemResult(ok=ok, status=status, idempotency_key=idem, response=data, assignment=item)
            results.append(res)
            jlog("INFO" if ok else "ERROR", "assign_role.result", status=status, ok=ok, idem=idem, principal=item.principal.id, scope=item.scope.id, roles=list(item.roles))
            if opts.exit_on_first_error and not ok:
                raise RuntimeError("exit_on_first_error")
        except Exception as e:
            failures += 1
            idem = item.idempotency_key or gen_idem_key()
            err = str(e)
            results.append(ItemResult(ok=False, status=0, idempotency_key=idem, response={}, error=err, assignment=item))
            jlog("ERROR", "assign_role.exception", error=err, idem=idem)

    # Параллельный запуск
    for a in assignments:
        # ранняя валидация основных полей — чтобы не плодить задач с явными ошибками
        try:
            a.principal.validate()
            a.scope.validate()
            if not a.roles:
                raise ValueError("roles must not be empty")
            for r in a.roles:
                if not ROLE_RE.match(r):
                    raise ValueError(f"invalid role name: {r}")
        except Exception as e:
            failures += 1
            results.append(ItemResult(ok=False, status=0, idempotency_key=a.idempotency_key or gen_idem_key(), response={}, error=str(e), assignment=a))
            continue

    tasks = [asyncio.create_task(worker(a)) for a in assignments if any(t.assignment is None or t.assignment != a for t in results)]
    # Корректная отмена по Ctrl+C
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        for t in tasks:
            t.cancel()
        raise
    finally:
        await client.close()

    ok_count = sum(1 for r in results if r.ok)
    fail_count = sum(1 for r in results if not r.ok)
    summary = {
        "ok": ok_count,
        "failed": fail_count,
        "total": len(results),
        "dry_run": opts.dry_run,
        "concurrency": opts.concurrency,
    }
    jlog("INFO", "assign_role.summary", **summary)
    return results, summary

# -----------------------------
# CLI
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assign-role",
        description="Назначение ролей субъектам IAM (одиночное и массовое)."
    )
    io = p.add_argument_group("Входные данные")
    io.add_argument("--json", help="Файл JSON с одним объектом или массивом")
    io.add_argument("--ndjson", help="Файл NDJSON (по одному объекту в строке)")
    io.add_argument("--csv", help="CSV со столбцами: principal_type,principal_id,roles,scope_type,scope_id,[not_before,not_after,condition,reason,metadata,idempotency_key]")

    single = p.add_argument_group("Одиночное назначение (если не заданы файлы)")
    single.add_argument("--principal-type", choices=sorted(PRINCIPAL_TYPE_ALLOWED))
    single.add_argument("--principal-id")
    single.add_argument("--roles", help="Список ролей через запятую")
    single.add_argument("--scope-type", choices=sorted(SCOPE_TYPE_ALLOWED))
    single.add_argument("--scope-id")
    single.add_argument("--reason")
    single.add_argument("--metadata", help="JSON-объект метаданных")
    single.add_argument("--not-before", help="RFC3339 или unixtime")
    single.add_argument("--not-after", help="RFC3339 или unixtime")
    single.add_argument("--condition", help="Строковое выражение политики (например CEL)")
    single.add_argument("--idempotency-key", help="Идемпотентный ключ; если не задан — будет сгенерирован")

    net = p.add_argument_group("Сетевые настройки")
    net.add_argument("--base-url", default=DEFAULT_BASE_URL)
    net.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    net.add_argument("--token", default=os.getenv("SEC_CORE_CLI_TOKEN"), help="Bearer token или SEC_CORE_CLI_TOKEN")
    net.add_argument("--cert", help="Путь к клиентскому сертификату (PEM)")
    net.add_argument("--key", help="Путь к приватному ключу (PEM) для client cert")
    net.add_argument("--ca", help="Путь к CA bundle (PEM)")
    net.add_argument("--insecure", action="store_true", help="Не проверять сертификат сервера (не рекомендуется)")

    execg = p.add_argument_group("Исполнение")
    execg.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    execg.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    execg.add_argument("--qps", type=float, default=10.0, help="Ограничение запросов в секунду")
    execg.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    execg.add_argument("--dry-run", action="store_true", help="Не выполнять, только проверять/формировать запросы")
    execg.add_argument("--exit-on-first-error", action="store_true")

    return p

def load_assignments_from_args(args: argparse.Namespace) -> List[Assignment]:
    items: List[Assignment] = []
    if args.json:
        items = load_from_json(args.json)
    elif args.ndjson:
        items = load_from_ndjson(args.ndjson)
    elif args.csv:
        items = load_from_csv(args.csv)
    else:
        # одиночное назначение
        if not (args.principal_type and args.principal_id and args.roles and args.scope_type and args.scope_id):
            raise ValueError("single mode requires --principal-type --principal-id --roles --scope-type --scope-id")
        principal = Principal(type=args.principal_type, id=args.principal_id)
        scope = Scope(type=args.scope_type, id=args.scope_id)
        roles = parse_roles(args.roles)
        metadata = parse_json_maybe(args.metadata) if args.metadata else {}
        constraints = Constraints(
            not_before=parse_time(args.not_before),
            not_after=parse_time(args.not_after),
            condition=args.condition or None,
        )
        items = [
            Assignment(
                principal=principal,
                roles=tuple(roles),
                scope=scope,
                reason=args.reason or None,
                metadata=metadata,
                constraints=constraints,
                idempotency_key=args.idempotency_key or None,
            )
        ]
    # финальная валидация каждого элемента (размеры проверим уже при отправке)
    for it in items:
        it.validate()
    return items

def main(argv: Optional[Sequence[str]] = None) -> int:
    if not _HAS_HTTPX:
        print("ERROR: httpx is required. Install with `pip install httpx`.", file=sys.stderr)
        return 2

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        assignments = load_assignments_from_args(args)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 20

    opts = ExecOptions(
        concurrency=max(1, int(args.concurrency)),
        timeout=float(args.timeout),
        base_url=str(args.base_url),
        endpoint=str(args.endpoint),
        token=args.token,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        insecure=bool(args.insecure),
        qps=float(args.qps),
        max_retries=int(args.max_retries),
        dry_run=bool(args.dry_run),
        exit_on_first_error=bool(args.exit_on_first_error),
    )

    # Установка обработчиков SIGINT/SIGTERM для корректной отмены
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            pass

    try:
        results, summary = loop.run_until_complete(execute(assignments, opts))
    finally:
        try:
            loop.close()
        except Exception:
            pass

    # Отчёт
    report = {
        "summary": summary,
        "results": [
            {
                "ok": r.ok,
                "status": r.status,
                "idempotency_key": r.idempotency_key,
                "error": r.error,
                "response": r.response,
                "principal": dataclasses.asdict(r.assignment.principal) if r.assignment else None,
                "scope": dataclasses.asdict(r.assignment.scope) if r.assignment else None,
                "roles": list(r.assignment.roles) if r.assignment else None,
            }
            for r in results
        ],
    }
    print(json.dumps(report, ensure_ascii=False, separators=(",", ":"), indent=2))

    # Коды возврата:
    # 0 — все успешно
    # 10 — есть частичные ошибки
    # 20 — ошибка валидации входных данных
    # 2  — отсутствует зависимость httpx
    return 0 if summary["failed"] == 0 else 10

if __name__ == "__main__":
    sys.exit(main())

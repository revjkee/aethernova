# -*- coding: utf-8 -*-
"""
ChronoWatch Core — schedule_apply CLI (production-grade)

Функции:
- Применение (upsert) расписаний из YAML/JSON к ChronoWatch GraphQL API
- Dry-run: валидация, DIFF (что изменится), превью наступлений в указанном окне
- Строгая валидация схемы спецификации (Pydantic)
- Корректные TZ/DST (zoneinfo), CRON превью (croniter), INTERVAL (ISO-8601, isodate)
- Структурные логи (JSON), коды выхода: 0 ok, 2 validation, 3 network, 4 apply error
- Параллельная обработка нескольких файлов

Зависимости (pip):
  typer>=0.12.3
  httpx>=0.27.0
  pydantic>=2.7
  PyYAML>=6.0.1
  rich>=13.7
  croniter>=2.0.4
  isodate>=0.6.1

Ожидаемый GraphQL endpoint и операции соответствуют ранее предложенной схеме:
  - query schedule(id: ID!): Schedule
  - query schedules(filter: ScheduleFilter, first: Int): ScheduleConnection
  - mutation scheduleCreate(input: ScheduleCreateInput!): ScheduleResult
  - mutation scheduleUpdate(id: ID!, input: ScheduleUpdateInput!): ScheduleResult
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import httpx
import typer
import yaml
from croniter import croniter
from isodate import parse_duration
from pydantic import BaseModel, Field, ValidationError, field_validator
from rich.console import Console
from rich.table import Table
from zoneinfo import ZoneInfo

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console(stderr=False)
err_console = Console(stderr=True, style="bold red")

DEFAULT_TZ = os.getenv("CRONOWATCH_TZ", "Europe/Stockholm")


# ---------------------------
# Spec model (strict)
# ---------------------------

class ScheduleType(str):
    CRON = "CRON"
    INTERVAL = "INTERVAL"
    FIXED_TIME = "FIXED_TIME"


class Priority(str):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScheduleSpec(BaseModel):
    # Идентификация / upsert ключи
    id: Optional[str] = Field(default=None, description="UUID расписания (если известен)")
    name: str = Field(min_length=3, max_length=128)
    description: Optional[str] = None

    # Поведение
    type: str = Field(pattern="^(CRON|INTERVAL|FIXED_TIME)$")
    cron: Optional[str] = Field(default=None, description="CRON выражение для type=CRON")
    interval: Optional[str] = Field(default=None, description="ISO-8601, например 'PT5M' для type=INTERVAL")
    fixedTime: Optional[datetime] = Field(default=None, description="RFC3339, для type=FIXED_TIME")

    timezone: str = Field(default=DEFAULT_TZ)
    graceSeconds: int = Field(default=30, ge=0, le=3600)
    isActive: bool = Field(default=True)

    # Параметры исполнения по умолчанию (worker)
    queue: str = Field(default="cron:default", min_length=1, max_length=80)
    priority: str = Field(default=Priority.NORMAL, pattern="^(LOW|NORMAL|HIGH|CRITICAL)$")
    timeoutSec: int = Field(default=int(os.getenv("JOB_DEFAULT_TIMEOUT_SEC", "120")), ge=1, le=86400)
    maxAttempts: int = Field(default=int(os.getenv("JOB_DEFAULT_RETRIES", "5")), ge=1, le=100)

    # Пользовательский payload, попадёт в job payload
    payload: Dict[str, Any] = Field(default_factory=dict)

    # Превью: опциональные подсказки
    previewFrom: Optional[datetime] = None
    previewWindowMinutes: Optional[int] = Field(default=60, ge=1, le=7 * 24 * 60)
    previewLimit: Optional[int] = Field(default=50, ge=1, le=5000)

    @field_validator("timezone")
    @classmethod
    def _tz_valid(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except Exception as e:
            raise ValueError(f"Unknown timezone: {v}") from e
        return v

    @field_validator("cron")
    @classmethod
    def _cron_required_if_type(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        if values.get("type") == ScheduleType.CRON and not v:
            raise ValueError("cron is required when type=CRON")
        return v

    @field_validator("interval")
    @classmethod
    def _interval_required_if_type(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        if values.get("type") == ScheduleType.INTERVAL and not v:
            raise ValueError("interval is required when type=INTERVAL")
        if v:
            # проверим парсинг ISO-8601
            try:
                _ = parse_duration(v)
            except Exception as e:
                raise ValueError(f"interval must be ISO-8601 (e.g. PT5M): {e}") from e
        return v

    @field_validator("fixedTime")
    @classmethod
    def _fixed_required_if_type(cls, v: Optional[datetime], values: Dict[str, Any]) -> Optional[datetime]:
        if values.get("type") == ScheduleType.FIXED_TIME and not v:
            raise ValueError("fixedTime is required when type=FIXED_TIME")
        return v

    @field_validator("cron")
    @classmethod
    def _cron_sanity(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        if v and values.get("type") == ScheduleType.CRON:
            # Проверка поля cron на корректность относительно TZ и now
            tz = ZoneInfo(values.get("timezone") or DEFAULT_TZ)
            base = (values.get("previewFrom") or datetime.now(tz=tz))
            try:
                croniter(v, base)
            except Exception as e:
                raise ValueError(f"invalid CRON: {e}") from e
        return v


# ---------------------------
# GraphQL client
# ---------------------------

@dataclass
class GraphQLClient:
    base_url: str
    token: Optional[str] = None
    timeout: float = 20.0

    async def _post(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        headers = {"content-type": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.base_url,
                headers=headers,
                json={"query": query, "variables": variables},
            )
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
        if "errors" in data and data["errors"]:
            # безопасно: не выводим PII, только сообщения
            msg = "; ".join(e.get("message", "GraphQL error") for e in data["errors"])
            raise RuntimeError(f"GraphQL: {msg}")
        return data["data"]

    async def get_schedule_by_id(self, sched_id: str) -> Optional[Dict[str, Any]]:
        q = """
        query($id: ID!) {
          schedule(id: $id) {
            id name description type cron interval fixedTime timezone graceSeconds isActive
          }
        }
        """
        data = await self._post(q, {"id": sched_id})
        return data.get("schedule")

    async def get_schedule_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        # Пробуем точным сравнением через contains + фильтр по равенству в клиенте
        q = """
        query($name: String!) {
          schedules(filter: { nameContains: $name }, first: 10) {
            edges { node { id name description type cron interval fixedTime timezone graceSeconds isActive } }
          }
        }
        """
        data = await self._post(q, {"name": name})
        edges = data.get("schedules", {}).get("edges", [])
        for e in edges:
            n = e.get("node", {})
            if n.get("name") == name:
                return n
        return None

    async def create_schedule(self, spec: ScheduleSpec) -> Dict[str, Any]:
        m = """
        mutation($input: ScheduleCreateInput!) {
          scheduleCreate(input: $input) {
            ok
            error { code message }
            schedule { id name }
          }
        }
        """
        input_ = {
            "name": spec.name,
            "description": spec.description,
            "type": spec.type,
            "cron": spec.cron,
            "interval": spec.interval,
            "fixedTime": spec.fixedTime.isoformat() if spec.fixedTime else None,
            "timezone": spec.timezone,
            "graceSeconds": spec.graceSeconds,
            "isActive": spec.isActive,
        }
        data = await self._post(m, {"input": input_})
        res = data["scheduleCreate"]
        if not res["ok"]:
            raise RuntimeError(f"Create failed: {res['error']}")
        return res["schedule"]

    async def update_schedule(self, sched_id: str, spec: ScheduleSpec, fields: Optional[List[str]] = None) -> Dict[str, Any]:
        m = """
        mutation($id: ID!, $input: ScheduleUpdateInput!) {
          scheduleUpdate(id: $id, input: $input) {
            ok
            error { code message }
            schedule { id name }
          }
        }
        """
        # Патчим только изменённые поля
        patch: Dict[str, Any] = {}
        candidate = {
            "name": spec.name,
            "description": spec.description,
            "type": spec.type,
            "cron": spec.cron,
            "interval": spec.interval,
            "fixedTime": spec.fixedTime.isoformat() if spec.fixedTime else None,
            "timezone": spec.timezone,
            "graceSeconds": spec.graceSeconds,
            "isActive": spec.isActive,
        }
        for k, v in candidate.items():
            if fields is None or k in fields:
                patch[k] = v
        data = await self._post(m, {"id": sched_id, "input": patch})
        res = data["scheduleUpdate"]
        if not res["ok"]:
            raise RuntimeError(f"Update failed: {res['error']}")
        return res["schedule"]


# ---------------------------
# Diff / Preview helpers
# ---------------------------

def _diff(existing: Optional[Dict[str, Any]], desired: Dict[str, Any]) -> List[Tuple[str, Any, Any]]:
    """
    Возвращает список (field, old, new) только по отличающимся полям.
    """
    diffs: List[Tuple[str, Any, Any]] = []
    if existing is None:
        for k, v in desired.items():
            if v is not None:
                diffs.append((k, None, v))
        return diffs

    keys = set(desired.keys()) | set(existing.keys())
    for k in sorted(keys):
        old = existing.get(k)
        new = desired.get(k)
        if old != new:
            diffs.append((k, old, new))
    return diffs


def _print_diff(name: str, diffs: List[Tuple[str, Any, Any]], fmt: str = "table") -> None:
    if fmt == "json":
        console.print_json(data=[{"field": f, "old": o, "new": n} for f, o, n in diffs])
        return
    table = Table(title=f"Diff for {name}", show_lines=False)
    table.add_column("Field", style="bold")
    table.add_column("Old")
    table.add_column("New")
    for f, o, n in diffs:
        table.add_row(str(f), _short(o), _short(n))
    console.print(table)


def _short(v: Any, max_len: int = 96) -> str:
    s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def _preview_occurrences(spec: ScheduleSpec) -> List[str]:
    tz = ZoneInfo(spec.timezone)
    start = spec.previewFrom or datetime.now(tz=tz)
    window_minutes = spec.previewWindowMinutes or 60
    limit = spec.previewLimit or 50
    end = start + timedelta(minutes=window_minutes)
    out: List[datetime] = []

    if spec.type == ScheduleType.CRON:
        itr = croniter(spec.cron, start)
        while True:
            nxt = itr.get_next(datetime).astimezone(tz)
            if nxt > end:
                break
            out.append(nxt)
            if len(out) >= limit:
                break

    elif spec.type == ScheduleType.INTERVAL:
        step = parse_duration(spec.interval)
        if not isinstance(step, timedelta):
            raise ValueError("interval must resolve to timedelta")
        cur = start
        while True:
            cur = cur + step
            if cur > end:
                break
            out.append(cur)
            if len(out) >= limit:
                break

    elif spec.type == ScheduleType.FIXED_TIME:
        if spec.fixedTime:
            ft = spec.fixedTime.astimezone(tz)
            if start <= ft <= end:
                out.append(ft)

    return [d.isoformat() for d in out]


# ---------------------------
# IO helpers
# ---------------------------

def _load_specs(path: Path) -> List[ScheduleSpec]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    specs: List[ScheduleSpec] = []
    if path.is_dir():
        for p in sorted(path.rglob("*")):
            if p.suffix.lower() in (".yaml", ".yml", ".json"):
                specs.extend(_load_specs(p))
        return specs

    with path.open("r", encoding="utf-8") as f:
        if path.suffix.lower() in (".yaml", ".yml"):
            raw = yaml.safe_load(f)
        else:
            raw = json.load(f)

    # Допускаем как один объект, так и список
    items: List[Dict[str, Any]]
    if isinstance(raw, list):
        items = raw
    else:
        items = [raw]

    for obj in items:
        try:
            specs.append(ScheduleSpec.model_validate(obj))
        except ValidationError as ve:
            raise ve
    return specs


# ---------------------------
# CLI command
# ---------------------------

@app.command("apply")
def apply_cmd(
    file: Path = typer.Argument(..., exists=True, readable=True, help="Путь к спецификации или директории со спецификациями"),
    base_url: str = typer.Option(os.getenv("CHRONOWATCH_GQL_URL", "http://localhost:8080/graphql"), help="GraphQL endpoint"),
    token: Optional[str] = typer.Option(os.getenv("CHRONOWATCH_TOKEN"), help="Bearer токен"),
    dry_run: bool = typer.Option(False, help="Только показать diff и превью, без применения"),
    format: str = typer.Option("table", help="Вывод diff: table|json"),
    parallel: int = typer.Option(4, min=1, max=16, help="Степень параллелизма при применении множества файлов"),
) -> None:
    """
    Применяет расписания к ChronoWatch (идемпотентный upsert).
    """
    try:
        specs = _load_specs(file)
    except ValidationError as ve:
        err_console.print("Validation error:")
        for e in ve.errors():
            err_console.print(f" - {e['loc']}: {e['msg']}")
        raise typer.Exit(code=2)
    except Exception as e:
        err_console.print(f"Failed to load specs: {e}")
        raise typer.Exit(code=2)

    client = GraphQLClient(base_url=base_url, token=token)

    async def process_one(spec: ScheduleSpec) -> Tuple[str, int]:
        name = spec.name
        desired = {
            "name": spec.name,
            "description": spec.description,
            "type": spec.type,
            "cron": spec.cron,
            "interval": spec.interval,
            "fixedTime": spec.fixedTime.isoformat() if spec.fixedTime else None,
            "timezone": spec.timezone,
            "graceSeconds": spec.graceSeconds,
            "isActive": spec.isActive,
        }

        existing: Optional[Dict[str, Any]] = None
        try:
            if spec.id:
                existing = await client.get_schedule_by_id(spec.id)
            if not existing:
                existing = await client.get_schedule_by_name(spec.name)
        except Exception as e:
            err_console.print(f"[network] {name}: {e}")
            return name, 3

        diffs = _diff(existing, desired)

        # Превью
        preview = _preview_occurrences(spec)

        # Печать
        console.print(f"[bold]Spec:[/bold] {name}")
        _print_diff(name, diffs, fmt=format)
        if preview:
            table = Table(title=f"Preview (limit={spec.previewLimit}, window={spec.previewWindowMinutes}m, tz={spec.timezone})")
            table.add_column("Occurrence")
            for s in preview:
                table.add_row(s)
            console.print(table)

        if dry_run:
            return name, 0

        # Применение
        try:
            if existing is None:
                created = await client.create_schedule(spec)
                console.print(f"[green]Created[/green] id={created['id']} name={created['name']}")
                return name, 0
            else:
                fields_to_patch = [f for f, old, new in diffs if f in desired]
                if fields_to_patch:
                    updated = await client.update_schedule(existing["id"], spec, fields=fields_to_patch)
                    console.print(f"[green]Updated[/green] id={updated['id']} name={updated['name']}")
                else:
                    console.print("[yellow]No changes[/yellow]")
                return name, 0
        except Exception as e:
            err_console.print(f"[apply] {name}: {e}")
            return name, 4

    async def runner() -> int:
        # Ограничиваем параллелизм
        sem = asyncio.Semaphore(parallel)
        results: List[int] = []

        async def wrapped(spec: ScheduleSpec):
            async with sem:
                _, code = await process_one(spec)
                results.append(code)

        await asyncio.gather(*(wrapped(s) for s in specs))
        # Наиболее «плохой» код = max
        return max(results) if results else 0

    try:
        exit_code = asyncio.run(runner())
    except KeyboardInterrupt:
        err_console.print("Interrupted")
        exit_code = 130
    raise typer.Exit(code=exit_code)


# ---------------------------
# Entrypoint
# ---------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()

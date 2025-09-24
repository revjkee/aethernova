# mythos-core/cli/admin.py
# -*- coding: utf-8 -*-
"""
Mythos Core — административный CLI.

Зависимости:
  - typer>=0.12
  - httpx>=0.24 (как транзитивная зависимость SDK)
  - (опционально) pyyaml для чтения YAML

Охват:
  entities:
    - get, create, update, delete
    - list (пагинация), search
    - batch-upsert из файла (JSON/YAML), с прогресс-индикаторами
    - watch (SSE)
  admin:
    - ping (быстрая проверка доступности API)
    - gen-uuid

Конфигурация:
  ENV (по умолчанию):
    MYTHOS_BASE_URL, MYTHOS_TOKEN, MYTHOS_AUTH_TYPE (bearer|api_key|none),
    MYTHOS_TIMEOUT, MYTHOS_RATE_LIMIT_RPS, MYTHOS_VERIFY_SSL (true|false)
  Файл: --config <path> (JSON/YAML) с ключами как в ENV (snake_case допустим).
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer

# Импорт SDK (см. ранее предоставленный файл mythos-core/sdks/python/mythos_client.py)
try:
    from sdks.python.mythos_client import (
        ClientConfig,
        MythosClient,
        AsyncMythosClient,
        Entity,
        APIError,
        RateLimitError,
        build_sync_client,
    )
except Exception as e:  # pragma: no cover
    typer.secho(f"[FATAL] failed to import SDK: {e}", fg=typer.colors.RED, err=True)
    raise SystemExit(2)

app = typer.Typer(add_completion=False, no_args_is_help=True)
entities_app = typer.Typer(add_completion=False, no_args_is_help=True)
admin_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(entities_app, name="entities", help="Операции с сущностями Mythos")
app.add_typer(admin_app, name="admin", help="Вспомогательные административные операции")

# --------------------------
# Конфигурация/контекст
# --------------------------

@dataclass
class Ctx:
    base_url: str
    auth_type: str
    token: Optional[str]
    timeout: float
    timeout_connect: float
    timeout_read: float
    timeout_write: float
    verify_ssl: bool
    rate_limit_rps: Optional[float]
    verbose: bool

    client: Optional[MythosClient] = None

    def ensure_client(self) -> MythosClient:
        if self.client:
            return self.client
        cfg = ClientConfig(
            base_url=self.base_url,
            auth_type=self.auth_type,  # 'bearer'|'api_key'|'none'
            token=self.token,
            timeout=self.timeout,
            timeout_connect=self.timeout_connect,
            timeout_read=self.timeout_read,
            timeout_write=self.timeout_write,
            verify_ssl=self.verify_ssl,
            rate_limit_rps=self.rate_limit_rps,
        )
        self.client = MythosClient(cfg)
        return self.client

ctx_obj = Ctx(
    base_url=os.getenv("MYTHOS_BASE_URL", "http://localhost:8080"),
    auth_type=os.getenv("MYTHOS_AUTH_TYPE", "none"),
    token=os.getenv("MYTHOS_TOKEN"),
    timeout=float(os.getenv("MYTHOS_TIMEOUT", "35")),
    timeout_connect=float(os.getenv("MYTHOS_TIMEOUT_CONNECT", "5")),
    timeout_read=float(os.getenv("MYTHOS_TIMEOUT_READ", "30")),
    timeout_write=float(os.getenv("MYTHOS_TIMEOUT_WRITE", "30")),
    verify_ssl=os.getenv("MYTHOS_VERIFY_SSL", "true").lower() in {"1", "true", "yes", "on"},
    rate_limit_rps=float(os.getenv("MYTHOS_RATE_LIMIT_RPS")) if os.getenv("MYTHOS_RATE_LIMIT_RPS") else None,
    verbose=os.getenv("MYTHOS_VERBOSE", "false").lower() in {"1", "true", "yes", "on"},
)

def _load_file(path: Path) -> Any:
    data = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as e:
            typer.secho(f"PyYAML is required for YAML: {e}", fg="red", err=True)
            raise typer.Exit(code=2)
        return yaml.safe_load(data)
    # JSON по умолчанию
    return json.loads(data)

def _dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)

def _echo(obj: Any) -> None:
    typer.echo(_dump_json(obj))

def _err(msg: str, code: int = 1) -> None:
    typer.secho(msg, fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)

def _warn(msg: str) -> None:
    typer.secho(msg, fg=typer.colors.YELLOW, err=True)

def _ok(msg: str) -> None:
    typer.secho(msg, fg=typer.colors.GREEN)

def _apply_config_file(path: Optional[Path]) -> None:
    if not path:
        return
    if not path.exists():
        _err(f"Config file not found: {path}", 2)
    loaded = _load_file(path)
    if not isinstance(loaded, dict):
        _err("Config must be a mapping/dict", 2)
    # Поддержим и SCREAMING/KEBAB/SNAKE варианты
    def _get(*keys: str, default=None):
        for k in keys:
            if k in loaded:
                return loaded[k]
        return default
    ctx_obj.base_url = _get("MYTHOS_BASE_URL", "base_url", "base-url", default=ctx_obj.base_url)
    ctx_obj.auth_type = _get("MYTHOS_AUTH_TYPE", "auth_type", default=ctx_obj.auth_type)
    ctx_obj.token = _get("MYTHOS_TOKEN", "token", default=ctx_obj.token)
    ctx_obj.timeout = float(_get("MYTHOS_TIMEOUT", "timeout", default=ctx_obj.timeout))
    ctx_obj.timeout_connect = float(_get("MYTHOS_TIMEOUT_CONNECT", "timeout_connect", default=ctx_obj.timeout_connect))
    ctx_obj.timeout_read = float(_get("MYTHOS_TIMEOUT_READ", "timeout_read", default=ctx_obj.timeout_read))
    ctx_obj.timeout_write = float(_get("MYTHOS_TIMEOUT_WRITE", "timeout_write", default=ctx_obj.timeout_write))
    vs = str(_get("MYTHOS_VERIFY_SSL", "verify_ssl", default=ctx_obj.verify_ssl)).lower()
    ctx_obj.verify_ssl = vs in {"1", "true", "yes", "on"}
    rps = _get("MYTHOS_RATE_LIMIT_RPS", "rate_limit_rps", default=ctx_obj.rate_limit_rps)
    ctx_obj.rate_limit_rps = float(rps) if rps is not None else None

# --------------------------
# Общие опции
# --------------------------

@app.callback()
def main(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Путь к JSON/YAML конфигу"),
    base_url: Optional[str] = typer.Option(None, envvar="MYTHOS_BASE_URL", help="Базовый URL Mythos API"),
    token: Optional[str] = typer.Option(None, envvar="MYTHOS_TOKEN", help="Bearer/API key"),
    auth_type: Optional[str] = typer.Option(None, envvar="MYTHOS_AUTH_TYPE", help="bearer|api_key|none"),
    timeout: Optional[float] = typer.Option(None, envvar="MYTHOS_TIMEOUT", help="Общий таймаут, сек"),
    verify_ssl: Optional[bool] = typer.Option(None, envvar="MYTHOS_VERIFY_SSL", help="Проверять SSL"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Подробный вывод"),
):
    """
    Mythos Core — административный CLI.
    """
    _apply_config_file(config)
    if base_url: ctx_obj.base_url = base_url
    if token is not None: ctx_obj.token = token
    if auth_type: ctx_obj.auth_type = auth_type
    if timeout is not None: ctx_obj.timeout = float(timeout)
    if verify_ssl is not None: ctx_obj.verify_ssl = verify_ssl
    ctx_obj.verbose = ctx_obj.verbose or verbose


# --------------------------
# ADMIN
# --------------------------

@admin_app.command("ping")
def admin_ping() -> None:
    """
    Быстрая проверка доступности API. Делает HEAD на / или GET /v1/entities:list (легкий).
    """
    cli = ctx_obj.ensure_client()
    try:
        # Легкий вызов: пустой листинг с page_size=1 (если метод доступен)
        body = {"page": {"page_size": 1, "page_token": ""}}
        resp = cli._request("POST", "/v1/entities:list", json_body=body)  # type: ignore[attr-defined]
        if resp.status_code == 200:
            _ok("OK: Mythos API is reachable")
            return
    except APIError as e:
        _warn(f"API responded with error: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        _err(f"Failed to reach API: {e}", 1)


@admin_app.command("gen-uuid")
def admin_gen_uuid(n: int = typer.Argument(1, min=1, help="Сколько UUID сгенерировать")) -> None:
    out = [str(uuid.uuid4()) for _ in range(n)]
    _echo(out if n > 1 else out[0])


# --------------------------
# ENTITIES — CRUD
# --------------------------

@entities_app.command("get")
def entities_get(
    entity_id: str = typer.Argument(..., help="ID сущности"),
    view: Optional[str] = typer.Option(None, "--view", help="Вариант представления на сервере"),
) -> None:
    cli = ctx_obj.ensure_client()
    try:
        e = cli.get_entity(entity_id, view=view)
        _echo(e.to_json())
    except APIError as e:
        _err(f"GET failed: {e}", 1)


@entities_app.command("create")
def entities_create(
    file: Path = typer.Argument(..., help="JSON/YAML с сущностью"),
    validate_only: bool = typer.Option(False, "--validate-only", help="Только валидация на сервере"),
    idempotency_key: Optional[str] = typer.Option(None, "--idem-key", help="Idempotency-Key"),
) -> None:
    cli = ctx_obj.ensure_client()
    data = _load_file(file)
    if not isinstance(data, dict):
        _err("Input must be a single entity object", 2)
    entity = Entity.from_json(data)
    try:
        e = cli.create_entity(entity, validate_only=validate_only, idempotency_key=idempotency_key or str(uuid.uuid4()))
        _echo(e.to_json())
    except RateLimitError as e:
        _err(f"Rate limited: {e}", 1)
    except APIError as e:
        _err(f"CREATE failed: {e}", 1)


@entities_app.command("update")
def entities_update(
    file: Path = typer.Argument(..., help="JSON/YAML с сущностью (id обязателен)"),
    update_mask: Optional[str] = typer.Option(None, "--update-mask", help="Список полей через запятую"),
    allow_missing: bool = typer.Option(False, "--allow-missing", help="Создать при отсутствии"),
    validate_only: bool = typer.Option(False, "--validate-only"),
    expected_etag: Optional[str] = typer.Option(None, "--if-match", help="Заголовок If-Match"),
) -> None:
    cli = ctx_obj.ensure_client()
    data = _load_file(file)
    if not isinstance(data, dict):
        _err("Input must be a single entity object", 2)
    entity = Entity.from_json(data)
    try:
        e = cli.update_entity(
            entity,
            update_mask=[s.strip() for s in update_mask.split(",")] if update_mask else None,
            allow_missing=allow_missing,
            validate_only=validate_only,
            expected_etag=expected_etag,
        )
        _echo(e.to_json())
    except APIError as e:
        _err(f"UPDATE failed: {e}", 1)


@entities_app.command("delete")
def entities_delete(
    entity_id: str = typer.Argument(..., help="ID сущности"),
    allow_missing: bool = typer.Option(False, "--allow-missing"),
    hard_delete: bool = typer.Option(False, "--hard-delete"),
    expected_etag: Optional[str] = typer.Option(None, "--if-match"),
) -> None:
    cli = ctx_obj.ensure_client()
    try:
        res = cli.delete_entity(entity_id, allow_missing=allow_missing, expected_etag=expected_etag, hard_delete=hard_delete)
        _echo(res)
    except APIError as e:
        _err(f"DELETE failed: {e}", 1)


# --------------------------
# ENTITIES — LIST/SEARCH
# --------------------------

@entities_app.command("list")
def entities_list(
    kind: Optional[str] = typer.Option(None, "--kind"),
    namespace: Optional[str] = typer.Option(None, "--namespace"),
    owner: Optional[str] = typer.Option(None, "--owner"),
    page_size: int = typer.Option(100, "--page-size", min=1, max=1000),
    limit: Optional[int] = typer.Option(None, "--limit", help="Ограничить количество выводимых записей"),
    labels: List[str] = typer.Option([], "--label", help="label=k=v (многоразово)"),
    tags: List[str] = typer.Option([], "--tag", help="тег (многоразово)"),
    output: str = typer.Option("json", "--output", "-o", help="json|ids"),
) -> None:
    cli = ctx_obj.ensure_client()
    lab_map: Dict[str, str] = {}
    for item in labels:
        if "=" in item:
            k, v = item.split("=", 1)
            lab_map[k] = v
    count = 0
    try:
        gen = cli.list_entities(
            kind=kind, namespace=namespace, owner=owner, page_size=page_size, labels=lab_map or None, tags=tags or None
        )
        if output == "ids":
            for e in gen:
                typer.echo(e.id)
                count += 1
                if limit and count >= limit:
                    break
            return
        # JSON массив построчно (stream-friendly)
        typer.echo("[")
        first = True
        for e in gen:
            if limit and count >= limit:
                break
            if not first:
                typer.echo(",")
            typer.echo(_dump_json(e.to_json()))
            first = False
            count += 1
        typer.echo("]")
    except APIError as e:
        _err(f"LIST failed: {e}", 1)


@entities_app.command("search")
def entities_search(
    query: str = typer.Argument(..., help="Поисковая строка"),
    page_size: int = typer.Option(50, "--page-size", min=1, max=1000),
    limit: Optional[int] = typer.Option(None, "--limit"),
) -> None:
    cli = ctx_obj.ensure_client()
    count = 0
    try:
        gen = cli.search_entities(query, page_size=page_size)
        typer.echo("[")
        first = True
        for e in gen:
            if limit and count >= limit:
                break
            if not first:
                typer.echo(",")
            typer.echo(_dump_json(e.to_json()))
            first = False
            count += 1
        typer.echo("]")
    except APIError as e:
        _err(f"SEARCH failed: {e}", 1)


# --------------------------
# ENTITIES — BATCH UPSERT
# --------------------------

@entities_app.command("batch-upsert")
def entities_batch_upsert(
    file: Path = typer.Argument(..., help="JSON/YAML: {entities:[...] } или просто список сущностей"),
    validate_only: bool = typer.Option(False, "--validate-only"),
    idempotency_key: Optional[str] = typer.Option(None, "--idem-key"),
    chunk_size: int = typer.Option(200, "--chunk", min=1, max=1000, help="Размер батча при разбиении"),
) -> None:
    cli = ctx_obj.ensure_client()
    payload = _load_file(file)
    entities_data: List[Dict[str, Any]]
    if isinstance(payload, dict) and "entities" in payload:
        entities_data = payload["entities"]
    elif isinstance(payload, list):
        entities_data = payload
    else:
        _err("Input must be list of entities or object with 'entities' array", 2)
        return
    entities = [Entity.from_json(d) for d in entities_data]
    total = len(entities)
    if total == 0:
        _warn("No entities to upsert")
        return

    # Разбиение и загрузка
    done = 0
    results: List[Dict[str, Any]] = []
    try:
        for i in range(0, total, chunk_size):
            batch = entities[i : i + chunk_size]
            idem = (idempotency_key or str(uuid.uuid4())) + f"-{i//chunk_size}"
            res = cli.batch_upsert_entities(batch, validate_only=validate_only, idempotency_key=idem)
            results.extend(res)
            done += len(batch)
            typer.secho(f"Batch {i//chunk_size+1}: {len(batch)} processed ({done}/{total})", fg=typer.colors.BLUE)
        _echo({"results": results, "total": total})
    except APIError as e:
        _err(f"BATCH UPSERT failed: {e}", 1)


# --------------------------
# ENTITIES — WATCH (SSE)
# --------------------------

_stop_flag = False

def _install_signal_handlers():
    global _stop_flag
    def _sigint(sig, frame):
        typer.secho("Stopping stream ...", fg=typer.colors.YELLOW, err=True)
        globals()["_stop_flag"] = True
    try:
        signal.signal(signal.SIGINT, _sigint)
        signal.signal(signal.SIGTERM, _sigint)
    except Exception:
        pass

@entities_app.command("watch")
def entities_watch(
    filter_expr: Optional[str] = typer.Option(None, "--filter", help="Серверный фильтр"),
    since: Optional[str] = typer.Option(None, "--since", help="ISO8601, откуда начинать"),
    max_events: Optional[int] = typer.Option(None, "--max-events", help="Остановиться после N событий"),
) -> None:
    cli = ctx_obj.ensure_client()
    _install_signal_handlers()
    count = 0
    try:
        for ev in cli.watch_entities(filter_expr=filter_expr, since=since):
            typer.echo(_dump_json(ev))
            count += 1
            if max_events and count >= max_events:
                break
            if _stop_flag:
                break
    except APIError as e:
        _err(f"WATCH failed: {e}", 1)


# --------------------------
# ENTRY POINT
# --------------------------

def _cleanup():
    try:
        if ctx_obj.client:
            ctx_obj.client.close()
    except Exception:
        pass

def run():
    try:
        app()
    finally:
        _cleanup()

if __name__ == "__main__":
    run()

# SPDX-License-Identifier: Apache-2.0
"""
Omnimind Core — Admin CLI

Особенности:
- Typer + Rich: удобный UX, цветной вывод, таблицы
- Конфигурация через ENV/флаги; корреляция запросов (X-Correlation-Id)
- Безопасные дефолты: таймауты, ретраи с экспоненциальным бэкоффом, dry-run
- Подкоманды:
  • health http/ws         — проверка здоровья сервисов (параллельно)
  • rbac load|test         — загрузка и валидация RBAC-политик
  • token gen              — генерация криптостойких токенов
  • k8s secret render|apply— генерация/применение Secret (kubectl опционально)
  • milvus health|reindex  — опциональные операции вокруг Milvus (если pymilvus доступен)
- Мягкие зависимости: httpx/pyyaml/pymilvus подгружаются при необходимости
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import secrets
import string
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import typer
from rich import box
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Внутренние зависимости (ваши модули)
try:
    # Используем движок авторизации из репозитория
    from omnimind.security.rbac import RbacEngine, Principal, Resource  # type: ignore
except Exception:
    RbacEngine = None  # type: ignore
    Principal = None  # type: ignore
    Resource = None  # type: ignore

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

# ------------------------------ Конфигурация ------------------------------ #

@dataclass
class AdminConfig:
    api_base: Optional[str] = os.getenv("OMNI_API_BASE")             # напр. https://api.example.com
    ws_url: Optional[str] = os.getenv("OMNI_WS_URL")                 # напр. wss://api.example.com/ws
    admin_token: Optional[str] = os.getenv("OMNI_ADMIN_TOKEN")       # bearer для админ-эндпоинтов
    timeout: float = float(os.getenv("OMNI_HTTP_TIMEOUT", "15.0"))
    connect_timeout: float = float(os.getenv("OMNI_CONNECT_TIMEOUT", "5.0"))
    retries: int = int(os.getenv("OMNI_HTTP_RETRIES", "3"))
    backoff_base: float = float(os.getenv("OMNI_HTTP_BACKOFF_BASE", "0.3"))
    backoff_max: float = float(os.getenv("OMNI_HTTP_BACKOFF_MAX", "5.0"))
    json_logs: bool = os.getenv("OMNI_JSON_LOGS", "false").lower() == "true"
    # RBAC
    rbac_endpoint: str = os.getenv("OMNI_RBAC_ENDPOINT", "/admin/rbac/policies")  # relative
    # Kubernetes
    kubectl: str = os.getenv("KUBECTL_BIN", "kubectl")

    def headers(self, *, correlation_id: Optional[str] = None) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "omnimind-admin/1.0",
        }
        if self.admin_token:
            h["Authorization"] = f"Bearer {self.admin_token}"
        if correlation_id:
            h["X-Correlation-Id"] = correlation_id
        return h


# ------------------------------ Утилиты ------------------------------ #

def _cid() -> str:
    return str(uuid.uuid4())

def _err(msg: str) -> None:
    console.print(f"[bold red]ERROR[/bold red] {msg}", highlight=False)

def _info(msg: str) -> None:
    console.print(f"[bold]INFO[/bold] {msg}", highlight=False)

def _ok(msg: str) -> None:
    console.print(f"[bold green]OK[/bold green] {msg}", highlight=False)

def _warn(msg: str) -> None:
    console.print(f"[bold yellow]WARN[/bold yellow] {msg}", highlight=False)

def _load_json_or_yaml(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except Exception:
            _err("Для YAML необходим пакет pyyaml. Установите его или используйте JSON.")
            raise typer.Exit(2)
        return yaml.safe_load(text) or {}
    return json.loads(text)

def _http_client(cfg: AdminConfig):
    try:
        import httpx  # type: ignore
    except Exception:
        _err("Для HTTP функций необходим пакет httpx (pip install httpx).")
        raise typer.Exit(2)

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
    client = httpx.Client(
        timeout=httpx.Timeout(cfg.timeout, connect=cfg.connect_timeout),
        limits=limits,
        transport=httpx.HTTPTransport(retries=0),
    )
    return client

def _retry_delays(cfg: AdminConfig) -> Iterable[float]:
    for attempt in range(cfg.retries):
        base = min(cfg.backoff_max, cfg.backoff_base * (2 ** attempt))
        yield round(base * (0.7 + 0.6 * random.random()), 3)

def _request_with_retries(client, method: str, url: str, *, headers: Mapping[str, str], json_body: Any, cfg: AdminConfig):
    import httpx  # type: ignore
    last_exc = None
    for delay in list(_retry_delays(cfg)) + [None]:
        try:
            resp = client.request(method, url, headers=headers, json=json_body)
            if 200 <= resp.status_code < 300:
                return resp
            if resp.status_code in (408, 409, 429) or 500 <= resp.status_code < 600:
                _warn(f"HTTP {resp.status_code} {method} {url} — ретрай")
            else:
                # не ретраим
                return resp
        except (httpx.TimeoutException, httpx.RemoteProtocolError) as e:
            last_exc = e
            _warn(f"HTTP ошибка: {e} — ретрай")
        if delay is None:
            break
        time.sleep(delay)
    if last_exc:
        raise last_exc
    raise RuntimeError("HTTP запрос не удался после ретраев")

def _print_kv(title: str, data: Mapping[str, Any]) -> None:
    table = Table(title=title, show_header=True, header_style="bold", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Key")
    table.add_column("Value")
    for k, v in data.items():
        table.add_row(str(k), json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v))
    console.print(table)

# ------------------------------ Команда: версия ------------------------------ #

@app.command("version")
def version():
    """
    Показать версию CLI и среду.
    """
    env = {
        "python": sys.version.split()[0],
        "api_base": os.getenv("OMNI_API_BASE"),
        "ws_url": os.getenv("OMNI_WS_URL"),
        "http_timeout": os.getenv("OMNI_HTTP_TIMEOUT", "15.0"),
    }
    _print_kv("omnimind-admin", env)

# ------------------------------ health -------------------------------------- #

health_app = typer.Typer(help="Проверка здоровья HTTP/WS сервисов")
app.add_typer(health_app, name="health")

@health_app.command("http")
def health_http(
    urls: List[str] = typer.Argument(..., help="HTTP(S) URL для проверки"),
    timeout: float = typer.Option(None, help="Таймаут запроса, сек"),
):
    """
    Проверить список HTTP URL (код 200..399 считается ОК).
    """
    cfg = AdminConfig()
    if timeout:
        cfg.timeout = timeout
    client = _http_client(cfg)
    ok = 0
    for u in urls:
        cid = _cid()
        headers = cfg.headers(correlation_id=cid)
        try:
            resp = _request_with_retries(client, "GET", u, headers=headers, json_body=None, cfg=cfg)
            if 200 <= resp.status_code < 400:
                _ok(f"{u} -> {resp.status_code}")
                ok += 1
            else:
                _err(f"{u} -> {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            _err(f"{u} error: {e}")
    client.close()
    if ok != len(urls):
        raise typer.Exit(1)

@health_app.command("ws")
def health_ws(
    url: str = typer.Argument(..., help="ws:// или wss:// адрес"),
    ping_timeout: float = typer.Option(5.0, help="Таймаут PING/PONG"),
):
    """
    Проверить простое подключение по WebSocket (ожидается PING/PONG совместимый сервер).
    """
    try:
        import websockets  # type: ignore
    except Exception:
        _err("Для проверки WS требуется пакет websockets (pip install websockets).")
        raise typer.Exit(2)

    async def _run():
        cid = _cid()
        try:
            async with websockets.connect(url, extra_headers={"X-Correlation-Id": cid}) as ws:  # type: ignore
                await ws.send(json.dumps({"type": "ping"}))
                ws_rcv = await asyncio.wait_for(ws.recv(), timeout=ping_timeout)
                if isinstance(ws_rcv, (bytes, bytearray)):
                    ws_rcv = ws_rcv.decode("utf-8", "ignore")
                try:
                    data = json.loads(ws_rcv)
                    if (isinstance(data, dict) and data.get("type") in ("pong", "ping")) or ws_rcv:
                        _ok(f"WS OK {url}")
                        return 0
                except Exception:
                    pass
                _err(f"WS ответ некорректен: {ws_rcv[:200]}")
                return 1
        except Exception as e:
            _err(f"WS ошибка: {e}")
            return 1

    rc = asyncio.run(_run())
    raise typer.Exit(rc)

# ------------------------------ RBAC ---------------------------------------- #

rbac_app = typer.Typer(help="Управление RBAC-политиками")
app.add_typer(rbac_app, name="rbac")

@rbac_app.command("load")
def rbac_load(
    policy_file: Path = typer.Argument(..., exists=True, readable=True, help="JSON/YAML файл политик"),
    target: str = typer.Option("http", help="Куда загрузить: http | fs"),
    out_path: Optional[Path] = typer.Option(None, help="Куда записать (для target=fs)"),
    api_base: Optional[str] = typer.Option(None, help="Переопределить OMNI_API_BASE"),
    dry_run: bool = typer.Option(False, help="Проверить и показать сводку, без записи/отправки"),
    yes: bool = typer.Option(False, help="Подтвердить опасные операции"),
):
    """
    Загрузить политики RBAC в сервис или на диск (после полной валидации).
    """
    if RbacEngine is None:
        _err("Модуль omnimind.security.rbac недоступен. Проверьте PYTHONPATH.")
        raise typer.Exit(2)

    data = _load_json_or_yaml(policy_file)
    # Валидация через RbacEngine
    eng = RbacEngine()
    try:
        eng.load_policies(data)
    except Exception as e:
        _err(f"Ошибка валидации политик: {e}")
        raise typer.Exit(1)

    # Краткая сводка
    roles = data.get("roles", {})
    pols = data.get("policies", [])
    table = Table(title="RBAC summary", box=box.MINIMAL, show_header=True, header_style="bold")
    table.add_column("Roles")
    table.add_column("Policies")
    table.add_row(str(len(roles)), str(len(pols)))
    console.print(table)

    if dry_run:
        _ok("Валидация пройдена (dry-run)")
        return

    if not yes:
        if not Confirm.ask("Подтвердить загрузку политик?"):
            _warn("Операция отменена пользователем.")
            raise typer.Exit(0)

    if target == "fs":
        if not out_path:
            _err("Для target=fs требуется --out-path.")
            raise typer.Exit(2)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        _ok(f"Политики сохранены: {out_path}")
        return

    if target == "http":
        cfg = AdminConfig()
        if api_base:
            cfg.api_base = api_base
        if not cfg.api_base:
            _err("OMNI_API_BASE не задан и не передан через --api-base.")
            raise typer.Exit(2)
        client = _http_client(cfg)
        url = cfg.api_base.rstrip("/") + cfg.rbac_endpoint
        cid = _cid()
        headers = cfg.headers(correlation_id=cid)
        resp = _request_with_retries(client, "PUT", url, headers=headers, json_body=data, cfg=cfg)
        if 200 <= resp.status_code < 300:
            _ok(f"Политики загружены: {url}")
            client.close()
            return
        _err(f"Ошибка API {resp.status_code}: {resp.text[:400]}")
        client.close()
        raise typer.Exit(1)

    _err(f"Неизвестный target: {target}")
    raise typer.Exit(2)

@rbac_app.command("test")
def rbac_test(
    policy_file: Path = typer.Argument(..., exists=True, readable=True, help="JSON/YAML файл политик"),
    principal_id: str = typer.Option(..., "--pid", help="ID субъекта"),
    roles: List[str] = typer.Option([], "--role", help="Роли субъекта (multi)"),
    tenant: Optional[str] = typer.Option(None, help="Tenant ID"),
    action: str = typer.Option(..., help="Действие (read/write/…)"),
    resource_type: str = typer.Option(..., help="Тип ресурса"),
    resource_id: str = typer.Option(..., help="ID ресурса"),
    when_hour: Optional[int] = typer.Option(None, help="Час (UTC) для теста"),
):
    """
    Локальная проверка решения авторизации по политикам.
    """
    if RbacEngine is None:
        _err("Модуль omnimind.security.rbac недоступен. Проверьте PYTHONPATH.")
        raise typer.Exit(2)

    data = _load_json_or_yaml(policy_file)
    eng = RbacEngine()
    eng.load_policies(data)
    p = Principal(id=principal_id, roles=tuple(roles), tenant_id=tenant, attributes={})
    r = Resource(type=resource_type, id=resource_id, tenant_id=tenant, attributes={})
    env = {}
    if when_hour is not None:
        env["now_hour"] = int(when_hour)
    decision = eng.check(p, action, r, env=env, explain=True)

    _print_kv("RBAC decision", {
        "allowed": decision.allowed,
        "effect": decision.effect,
        "policy_id": decision.policy_id,
        "reason": decision.reason,
        "matched": decision.matched,
        "audit": decision.audit,
    })
    raise typer.Exit(0 if decision.allowed else 1)

# ------------------------------ Tokens -------------------------------------- #

token_app = typer.Typer(help="Операции с токенами/секретами")
app.add_typer(token_app, name="token")

@token_app.command("gen")
def token_gen(
    length: int = typer.Option(40, min=16, max=512, help="Длина токена"),
    alphabet: str = typer.Option("urlsafe", help="alphabet: urlsafe | hex | base64"),
    prefix: Optional[str] = typer.Option(None, help="Необязательный префикс, например 'omni_'"),
):
    """
    Сгенерировать токен (криптостойкий).
    """
    if alphabet == "hex":
        raw = secrets.token_hex(length // 2)
    elif alphabet == "base64":
        raw = base64.urlsafe_b64encode(secrets.token_bytes(length)).decode("utf-8").rstrip("=")
    else:
        # urlsafe: A-Za-z0-9-_
        raw = base64.urlsafe_b64encode(secrets.token_bytes(length)).decode("utf-8").rstrip("=")
    token = f"{prefix}{raw}" if prefix else raw
    console.print(token, highlight=False)

# ------------------------------ Kubernetes Secret --------------------------- #

k8s_app = typer.Typer(help="Генерация/применение Kubernetes Secret")
app.add_typer(k8s_app, name="k8s")

@k8s_app.command("secret")
def k8s_secret(
    name: str = typer.Option(..., help="Имя Secret"),
    namespace: str = typer.Option("default", help="Namespace"),
    data: List[str] = typer.Option([], "--data", help="key=value; можно повторять"),
    type_: str = typer.Option("Opaque", "--type", help="Тип Secret"),
    apply: bool = typer.Option(False, help="Сразу применить через kubectl"),
    yes: bool = typer.Option(False, help="Подтверждение на применение"),
):
    """
    Сгенерировать манифест Secret, опционально применить (kubectl).
    """
    kv: Dict[str, str] = {}
    for item in data:
        if "=" not in item:
            _err(f"Некорректная пара: {item}")
            raise typer.Exit(2)
        k, v = item.split("=", 1)
        kv[k] = v

    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": type_,
        "stringData": kv,
    }
    yaml_text = None
    try:
        import yaml  # type: ignore
        yaml_text = yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True)
    except Exception:
        yaml_text = json.dumps(manifest, ensure_ascii=False, indent=2)

    console.print(yaml_text)

    if apply:
        cfg = AdminConfig()
        if not yes and not Confirm.ask("Применить Secret через kubectl?"):
            _warn("Отменено.")
            return
        try:
            proc = subprocess.run([cfg.kubectl, "apply", "-f", "-"], input=yaml_text.encode("utf-8"))
            if proc.returncode == 0:
                _ok("Secret применён.")
            else:
                _err(f"kubectl завершился с кодом {proc.returncode}")
                raise typer.Exit(proc.returncode)
        except FileNotFoundError:
            _err(f"kubectl не найден (ожидался '{cfg.kubectl}')")
            raise typer.Exit(2)

# ------------------------------ Milvus (optional) --------------------------- #

milvus_app = typer.Typer(help="Операции с Milvus (опционально)")
app.add_typer(milvus_app, name="milvus")

@milvus_app.command("health")
def milvus_health(
    uri: Optional[str] = typer.Option(None, help="URI Milvus (http://host:19530) или host/port через ENV"),
):
    """
    Простой healthcheck Milvus через pymilvus (если установлен).
    """
    try:
        from omnimind.memory.stores.milvus_store import MilvusStore, MilvusConfig  # type: ignore
    except Exception:
        _err("Модуль MilvusStore недоступен. Установите pymilvus и проверьте PYTHONPATH.")
        raise typer.Exit(2)

    cfg = MilvusConfig(
        uri=uri or os.getenv("MILVUS_URI"),
        host=os.getenv("MILVUS_HOST"),
        port=int(os.getenv("MILVUS_PORT", "19530")) if os.getenv("MILVUS_PORT") else None,
        user=os.getenv("MILVUS_USER"),
        password=os.getenv("MILVUS_PASSWORD"),
        token=os.getenv("MILVUS_TOKEN"),
        secure=os.getenv("MILVUS_SECURE", "false").lower() == "true",
        collection=os.getenv("MILVUS_COLLECTION", "omnimind_memory"),
        dim=int(os.getenv("MILVUS_DIM", "1536")),
    )
    store = MilvusStore(cfg)
    ok = store.health()
    _ok("Milvus OK") if ok else _err("Milvus недоступен")
    raise typer.Exit(0 if ok else 1)

@milvus_app.command("reindex")
def milvus_reindex():
    """
    Переcоздать индекс в текущей коллекции (опасно). Требует подтверждения.
    """
    try:
        from omnimind.memory.stores.milvus_store import MilvusStore, MilvusConfig  # type: ignore
    except Exception:
        _err("Модуль MilvusStore недоступен.")
        raise typer.Exit(2)

    if not Confirm.ask("[red]ОПАСНО:[/red] Пересоздать индекс?"):
        _warn("Отменено пользователем.")
        return

    cfg = MilvusConfig(
        uri=os.getenv("MILVUS_URI"),
        host=os.getenv("MILVUS_HOST"),
        port=int(os.getenv("MILVUS_PORT", "19530")) if os.getenv("MILVUS_PORT") else None,
        user=os.getenv("MILVUS_USER"),
        password=os.getenv("MILVUS_PASSWORD"),
        token=os.getenv("MILVUS_TOKEN"),
        secure=os.getenv("MILVUS_SECURE", "false").lower() == "true",
        collection=os.getenv("MILVUS_COLLECTION", "omnimind_memory"),
        dim=int(os.getenv("MILVUS_DIM", "1536")),
    )
    store = MilvusStore(cfg)
    store.ensure_collection()
    _ok("Индекс присутствует/обновлён.")

# ------------------------------ Точка входа --------------------------------- #

def main():
    try:
        app()
    except KeyboardInterrupt:
        _warn("Операция прервана пользователем.")
        raise SystemExit(130)

if __name__ == "__main__":
    main()

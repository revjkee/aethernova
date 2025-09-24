# cybersecurity-core/cli/main.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# -------- Optional pretty output --------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.json import JSON as RichJSON
    from rich import box
    HAS_RICH = True
    console = Console()
except Exception:
    HAS_RICH = False
    console = None  # type: ignore

# -------- CLI framework --------
try:
    import typer
    from typer import Option, Argument
except Exception as e:
    print("Typer is required: pip install typer[all] rich pydantic httpx cryptography PyYAML", file=sys.stderr)
    sys.exit(4)

# -------- Config/YAML --------
try:
    import yaml  # type: ignore
    HAS_YAML = True
except Exception:
    HAS_YAML = False

from pydantic import BaseModel, BaseSettings, Field, ValidationError

# -------- Project imports (internal) --------
# Crypto/signatures
from cybersecurity.crypto.signatures import (
    generate_ed25519_key,
    generate_ec_key,
    generate_rsa_key,
    serialize_private_key_pem,
    serialize_public_key_pem,
    sign_detached,
    verify_detached,
    sign_envelope,
    verify_envelope,
    SignatureAlg,
    kid_from_public_key,
    load_private_key_pem,
    load_public_key_pem,
)

# Policy enforcer
from cybersecurity.policy.enforcer import (
    Enforcer,
    PolicyStore,
    Subject,
    Resource,
    Action,
    Environment,
)

# Nessus
from cybersecurity.vuln.connectors.nessus import NessusClient, NessusError

# SilentLink-like adapter
from cybersecurity.adapters.silentlink_adapter import (
    SilentLinkAdapter,
    SilentLinkSettings,
    SilentLinkError,
)

APP_NAME = "cybersecurity-core"
DEFAULT_CONFIG = Path.home() / ".config" / "cybersecurity-core" / "config.yaml"

app = typer.Typer(add_completion=False, help=f"{APP_NAME} CLI")
crypto_app = typer.Typer(add_completion=False, help="Криптографические операции")
policy_app = typer.Typer(add_completion=False, help="Оценка политик доступа")
nessus_app = typer.Typer(add_completion=False, help="Интеграция с Nessus/Tenable")
silentlink_app = typer.Typer(add_completion=False, help="Интеграция с SilentLink-класс провайдера")

app.add_typer(crypto_app, name="crypto")
app.add_typer(policy_app, name="policy")
app.add_typer(nessus_app, name="nessus")
app.add_typer(silentlink_app, name="silentlink")

# ------------------------------ Logging ------------------------------

def setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

# ------------------------------ Config models ------------------------------

class NessusCfg(BaseModel):
    base_url: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True
    timeout: float = 30.0

class SilentLinkCfg(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    auth_mode: str = "bearer"
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    proxies: Optional[Dict[str, str]] = None
    user_agent: Optional[str] = None

class RootConfig(BaseSettings):
    nessus: NessusCfg = NessusCfg()
    silentlink: SilentLinkCfg = SilentLinkCfg()

    class Config:
        env_prefix = "CSC_"
        env_nested_delimiter = "__"

# ------------------------------ Config loader ------------------------------

def load_config(path: Optional[Path]) -> RootConfig:
    # Precedence: explicit path -> default path -> env-only
    if path:
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        data = _load_structured_file(path)
        return RootConfig(**(data or {}))
    if DEFAULT_CONFIG.exists():
        data = _load_structured_file(DEFAULT_CONFIG)
        return RootConfig(**(data or {}))
    # Env-only
    return RootConfig()

def _load_structured_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        if not HAS_YAML:
            raise RuntimeError("PyYAML is not installed to read YAML config")
        return yaml.safe_load(text) or {}
    try:
        return json.loads(text)
    except Exception:
        # best effort YAML even if suffix json
        if HAS_YAML:
            return yaml.safe_load(text) or {}
        raise

# ------------------------------ Utils ------------------------------

def _echo_json(obj: Any) -> None:
    if HAS_RICH:
        console.print(RichJSON.from_data(obj))  # type: ignore
    else:
        print(json.dumps(obj, ensure_ascii=False, indent=2))

def _read_json_data(arg: Optional[str]) -> Any:
    """
    Accepts:
      - None
      - "@path/to/file.json|.yaml"
      - raw JSON string
    """
    if not arg:
        return None
    if arg.startswith("@"):
        p = Path(arg[1:])
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() in {".yaml", ".yml"} and HAS_YAML:
            return yaml.safe_load(text)
        try:
            return json.loads(text)
        except Exception:
            # try yaml as fallback
            if HAS_YAML:
                return yaml.safe_load(text)
            raise ValueError("Invalid JSON and YAML support not installed")
    # raw json
    return json.loads(arg)

def _write_bytes(path: Path, data: bytes, *, force: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(f"File exists: {path}")
    path.write_bytes(data)

def _exit(code: int, msg: Optional[str] = None) -> None:
    if msg:
        print(msg, file=sys.stderr)
    raise typer.Exit(code)

# =====================================================================
#                               ROOT
# =====================================================================

@app.callback()
def _root(
    ctx: typer.Context,
    config: Optional[Path] = Option(None, "--config", "-c", help=f"Путь к файлу конфигурации (по умолчанию {DEFAULT_CONFIG})"),
    log_level: str = Option("INFO", "--log-level", help="Уровень логирования: DEBUG/INFO/WARN/ERROR"),
):
    """
    {app_name} — универсальный CLI для задач кибербезопасности.
    """.format(app_name=APP_NAME)
    setup_logging(log_level)
    try:
        ctx.obj = {"config": load_config(config)}
    except Exception as e:
        _exit(4, f"Config error: {e}")

@app.command("version")
def version():
    """Печать версии и окружения."""
    info = {
        "app": APP_NAME,
        "python": sys.version.split()[0],
        "rich": HAS_RICH,
        "yaml": HAS_YAML,
    }
    _echo_json(info)

# =====================================================================
#                               CRYPTO
# =====================================================================

@crypto_app.command("keygen")
def crypto_keygen(
    kind: str = Argument(..., help="Тип ключа: ed25519 | rsa | ec"),
    out_dir: Path = Option(Path("./keys"), "--out-dir", "-o", help="Каталог для сохранения ключей"),
    rsa_bits: int = Option(3072, "--rsa-bits", help="Размер RSA ключа"),
    ec_curve: str = Option("P-256", "--ec-curve", help="Кривая для ECDSA: P-256|P-384"),
    password: Optional[str] = Option(None, "--password", help="Пароль для приватного ключа (PEM PKCS#8)"),
    force: bool = Option(False, "--force", help="Перезаписывать файлы"),
):
    """Генерация ключевой пары и вывод KID."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        if kind.lower() == "ed25519":
            priv = generate_ed25519_key()
        elif kind.lower() == "rsa":
            priv = generate_rsa_key(bits=rsa_bits)
        elif kind.lower() == "ec":
            priv = generate_ec_key(ec_curve)
        else:
            _exit(4, "Unsupported key kind")

        pub = priv.public_key()
        kid = kid_from_public_key(pub)

        priv_pem = serialize_private_key_pem(priv, password=password)
        pub_pem = serialize_public_key_pem(pub)

        _write_bytes(out_dir / "private.pem", priv_pem, force=force)
        _write_bytes(out_dir / "public.pem", pub_pem, force=force)

        result = {"kind": kind.lower(), "kid": kid, "private_pem": str(out_dir / "private.pem"), "public_pem": str(out_dir / "public.pem")}
        _echo_json(result)
    except Exception as e:
        _exit(5, f"Keygen error: {e}")

@crypto_app.command("sign-file")
def crypto_sign_file(
    key_path: Path = Argument(..., help="PEM приватный ключ"),
    in_path: Path = Argument(..., help="Файл для подписи"),
    alg: SignatureAlg = Option(SignatureAlg.ED25519, "--alg", help="Алгоритм подписи"),
    context: Optional[str] = Option(None, "--ctx", help="Строка контекста для доменной изоляции"),
    out_sig: Path = Option(Path("./signature.bin"), "--out", "-o", help="Путь к подписи"),
    password: Optional[str] = Option(None, "--password", help="Пароль к приватному ключу"),
    envelope: bool = Option(False, "--envelope", help="Записать JSON-конверт вместо сырой подписи"),
):
    """Подписать файл (detached) или создать JSON-конверт."""
    try:
        data = in_path.read_bytes()
        priv = load_private_key_pem(key_path.read_bytes(), password=password)
        if envelope:
            env = sign_envelope(priv, data, alg, ctx=context)
            _write_bytes(out_sig, env.to_json().encode("utf-8"), force=True)
        else:
            sig = sign_detached(priv, data, alg, context=context)
            _write_bytes(out_sig, sig, force=True)
        _echo_json({"status": "ok", "out": str(out_sig)})
    except Exception as e:
        _exit(5, f"Sign error: {e}")

@crypto_app.command("verify-file")
def crypto_verify_file(
    pub_path: Path = Argument(..., help="PEM публичный ключ"),
    in_path: Path = Argument(..., help="Файл для проверки"),
    signature: Path = Argument(..., help="Файл подписи или конверта"),
    alg: SignatureAlg = Option(SignatureAlg.ED25519, "--alg", help="Алгоритм (для сырой подписи)"),
    context: Optional[str] = Option(None, "--ctx", help="Контекст доменной изоляции"),
    envelope: bool = Option(False, "--envelope", help="Подпись в формате JSON-конверта"),
):
    """Проверить подпись/конверт. Код выхода 0/2."""
    try:
        data = in_path.read_bytes()
        pub = load_public_key_pem(pub_path.read_bytes())
        ok = False
        if envelope:
            env_json = signature.read_bytes()
            ok = verify_envelope(pub, data, env_json, expected_ctx=context)
        else:
            sig = signature.read_bytes()
            ok = verify_detached(pub, data, sig, alg, context=context)
        _echo_json({"verified": ok})
        if not ok:
            _exit(2)
    except Exception as e:
        _exit(5, f"Verify error: {e}")

# =====================================================================
#                               POLICY
# =====================================================================

@policy_app.command("eval")
def policy_eval(
    policy_files: List[Path] = Argument(..., help="Один или несколько файлов политик (YAML/JSON)"),
    subject_json: str = Option(..., "--subject", help='JSON или @file: {"id":"u1","roles":["admin"],"attributes":{"device_trust":"high"}}'),
    resource_json: str = Option(..., "--resource", help='JSON или @file: {"id":"doc1","type":"doc","path":"doc/fin/q1.pdf"}'),
    action: str = Option(..., "--action", help='Напр. "read"|"write"'),
    environment_json: str = Option("{}", "--env", help='JSON или @file: {"ip":"10.0.0.5","country":"SE"}'),
    tenant: Optional[str] = Option(None, "--tenant", help="Ограничить политиками арендатора"),
):
    """Оценка политик через Enforcer с объяснимостью."""
    try:
        store = PolicyStore()
        # Загрузка политик
        for pf in policy_files:
            data = _read_json_data(f"@{pf}")
            if isinstance(data, list):
                for obj in data:
                    store.upsert(_coerce_policy(obj))
            else:
                store.upsert(_coerce_policy(data))

        subj = Subject(**_read_json_data(subject_json))
        res = Resource(**_read_json_data(resource_json))
        act = Action(action=action)
        env = Environment(**_read_json_data(environment_json))

        enf = Enforcer(store)
        decision = enf.decide(subj, res, act, env, tenant=tenant)
        _echo_json(decision.dict())
        if decision.outcome != "permit":
            _exit(2)
    except ValidationError as ve:
        _exit(4, f"Validation error: {ve}")
    except Exception as e:
        _exit(5, f"Policy eval error: {e}")

def _coerce_policy(obj: Dict[str, Any]):
    # Deferred import to avoid heavy coupling
    from cybersecurity.policy.enforcer import Policy
    return Policy(**obj)

# =====================================================================
#                               NESSUS
# =====================================================================

def _nessus_from_cfg(cfg: RootConfig) -> NessusClient:
    n = cfg.nessus
    url = os.getenv("NESSUS_URL", n.base_url or "")
    if not url:
        raise RuntimeError("NESSUS_URL is required")
    access_key = os.getenv("NESSUS_ACCESS_KEY", n.access_key or "")
    secret_key = os.getenv("NESSUS_SECRET_KEY", n.secret_key or "")
    username = os.getenv("NESSUS_USERNAME", n.username or "")
    password = os.getenv("NESSUS_PASSWORD", n.password or "")
    verify_ssl = (os.getenv("NESSUS_VERIFY_SSL", "true").lower() == "true") if n.verify_ssl is None else n.verify_ssl  # type: ignore
    timeout = float(os.getenv("NESSUS_TIMEOUT", str(n.timeout)))
    return NessusClient(
        base_url=url,
        access_key=access_key or None,
        secret_key=secret_key or None,
        username=username or None,
        password=password or None,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )

@nessus_app.command("list-scans")
def nessus_list_scans(ctx: typer.Context):
    """Список сканов Nessus."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            async with _nessus_from_cfg(cfg) as cli:
                scans = await cli.list_scans()
                if HAS_RICH:
                    table = Table(title="Nessus Scans", box=box.SIMPLE_HEAVY)
                    for c in ("id", "name", "status", "owner", "last_modification_date"):
                        table.add_column(c)
                    for s in scans:
                        table.add_row(str(s.id), s.name, str(s.status or ""), str(s.owner or ""), str(s.last_modification_date or ""))
                    console.print(table)
                else:
                    _echo_json([s.dict() for s in scans])
        except NessusError as e:
            _exit(3, f"Nessus error: {e}")
    asyncio.run(_run())

@nessus_app.command("export-scan")
def nessus_export_scan(
    ctx: typer.Context,
    scan_id: int = Argument(..., help="ID скана"),
    fmt: str = Option("csv", "--format", help="nessus|csv|html|pdf|db"),
    history_id: Optional[int] = Option(None, "--history-id", help="Конкретная итерация скана"),
):
    """Инициировать экспорт результатов скана и дождаться готовности."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            async with _nessus_from_cfg(cfg) as cli:
                file_id, export_meta = await cli.export_scan(scan_id, fmt=fmt, history_id=history_id)
                _echo_json({"scan_id": scan_id, "file_id": file_id, "meta": export_meta})
        except NessusError as e:
            _exit(3, f"Nessus error: {e}")
    asyncio.run(_run())

@nessus_app.command("download-export")
def nessus_download_export(
    ctx: typer.Context,
    scan_id: int = Argument(..., help="ID скана"),
    file_id: int = Argument(..., help="ID файла экспорта"),
    out_path: Path = Option(Path("./nessus_export.bin"), "--out", "-o", help="Путь сохранения"),
):
    """Скачать готовый экспорт."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            async with _nessus_from_cfg(cfg) as cli:
                path = await cli.download_export(scan_id, file_id, dest_path=str(out_path))
                _echo_json({"saved": path})
        except NessusError as e:
            _exit(3, f"Nessus error: {e}")
    asyncio.run(_run())

# =====================================================================
#                             SILENTLINK
# =====================================================================

def _silentlink_settings(cfg: RootConfig) -> SilentLinkSettings:
    s = cfg.silentlink
    base_url = os.getenv("SL_BASE_URL", s.base_url or "")
    if not base_url:
        raise RuntimeError("SL_BASE_URL is required")
    api_key = os.getenv("SL_API_KEY", s.api_key or "")
    api_secret = os.getenv("SL_API_SECRET", s.api_secret or None)
    auth_mode = os.getenv("SL_AUTH_MODE", s.auth_mode or "bearer")
    verify_ssl = (os.getenv("SL_VERIFY_SSL", "true").lower() == "true") if s.verify_ssl is None else s.verify_ssl  # type: ignore
    timeout = float(os.getenv("SL_TIMEOUT", str(s.timeout_seconds)))
    user_agent = os.getenv("SL_USER_AGENT", s.user_agent or "Aethernova-SilentLinkAdapter/1.0")
    return SilentLinkSettings(
        base_url=base_url,
        api_key=api_key,
        api_secret=api_secret,
        auth_mode=auth_mode,  # type: ignore
        verify_ssl=verify_ssl,
        timeout_seconds=timeout,
        user_agent=user_agent,
        proxies=s.proxies,
    )

@silentlink_app.command("balance")
def sl_balance(ctx: typer.Context):
    """Показать баланс провайдера."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                bal = await sl.get_balance()
                _echo_json(bal.dict())
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

@silentlink_app.command("products")
def sl_products(
    ctx: typer.Context,
    country: Optional[str] = Option(None, "--country", help="Фильтр по стране"),
    region: Optional[str] = Option(None, "--region", help="Фильтр по региону"),
    limit: Optional[int] = Option(None, "--limit", help="Ограничение кол-ва"),
):
    """Список продуктов (eSIM/номера)."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                products = await sl.list_products(country=country, region=region, limit=limit)
                _echo_json([p.dict() for p in products])
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

@silentlink_app.command("order")
def sl_order(
    ctx: typer.Context,
    product_id: str = Argument(..., help="ID продукта"),
    quantity: int = Option(1, "--qty", help="Количество"),
    options_json: Optional[str] = Option(None, "--options", help='Опции заказа как JSON или @file'),
    idempotency_key: Optional[str] = Option(None, "--idempotency-key", help="Ключ идемпотентности"),
):
    """Создать заказ на продукт."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                options = _read_json_data(options_json) if options_json else None
                order = await sl.create_order(product_id, quantity=quantity, options=options, idempotency_key=idempotency_key)
                _echo_json(order.dict())
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

@silentlink_app.command("order-get")
def sl_order_get(
    ctx: typer.Context,
    order_id: str = Argument(..., help="ID заказа"),
):
    """Получить данные заказа."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                order = await sl.get_order(order_id)
                _echo_json(order.dict())
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

@silentlink_app.command("activate-esim")
def sl_activate(
    ctx: typer.Context,
    order_id: str = Argument(..., help="ID заказа"),
    idempotency_key: Optional[str] = Option(None, "--idempotency-key", help="Ключ идемпотентности"),
):
    """Активировать eSIM по заказу."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                act = await sl.activate_esim(order_id, idempotency_key=idempotency_key)
                _echo_json(act.dict())
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

@silentlink_app.command("inbox")
def sl_inbox(
    ctx: typer.Context,
    resource_id: str = Argument(..., help="MSISDN/ресурс"),
    limit: Optional[int] = Option(None, "--limit", help="Кол-во сообщений"),
    page_token: Optional[str] = Option(None, "--page-token", help="Токен страницы"),
):
    """Получить SMS-инбокс ресурса."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                page = await sl.get_inbox(resource_id, limit=limit, page_token=page_token)
                _echo_json(page.dict())
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

@silentlink_app.command("release")
def sl_release(
    ctx: typer.Context,
    resource_id: str = Argument(..., help="MSISDN/ресурс"),
):
    """Освободить ресурс (номер/eSIM)."""
    cfg: RootConfig = ctx.ensure_object(dict).get("config")
    async def _run():
        try:
            settings = _silentlink_settings(cfg)
            async with SilentLinkAdapter(settings) as sl:
                ok = await sl.release_resource(resource_id)
                _echo_json({"released": ok})
                if not ok:
                    _exit(2)
        except SilentLinkError as e:
            _exit(3, f"SilentLink error: {e}")
    asyncio.run(_run())

# =====================================================================
#                               ENTRY
# =====================================================================

if __name__ == "__main__":
    app()

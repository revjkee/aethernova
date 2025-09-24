# neuroforge-core/cli/admin.py
"""
NeuroForge Admin CLI (stdlib only).

Features:
- health: среда, версии, пути, доступность GPG/Alembic.
- config: get/set/list для JSON/TOML (read-only для TOML).
- flags: enable/disable/list фичей.
- users: локальное управление пользователями (json), scrypt-хэш пароля.
- roles: add/remove/list ролей.
- secrets: set/get/list/rm с приоритетом GPG (subprocess), иначе file-safe (0600) с предупреждением.
- keys: generate случайных токенов.
- db: migrate через Alembic при наличии конфигов.
- backup: create/restore целевого каталога данных/конфигов.

Глобальные опции:
  --json          JSON вывод.
  --yes           Подтверждение без вопросов.
  --home PATH     Переопределить базовый каталог (иначе XDG/NEUROFORGE_HOME).
  --audit PATH    Путь к аудит-логу JSONL (по умолчанию <home>/logs/admin_audit.log).

Коды выхода:
  0 OK, 2 неверные аргументы, 3 операция отменена, 4 не найдено, 5 внешняя ошибка, 6 ошибка ввода/вывода.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import hmac
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, TypedDict, List, Union

try:
    import tomllib  # py311+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore

# ----------------------------- Constants & helpers ----------------------------------------------

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ABORTED = 3
EXIT_NOT_FOUND = 4
EXIT_EXTERNAL = 5
EXIT_IO = 6

JSON_INDENT = None  # компактный вывод по умолчанию

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def getenv_path(*names: str) -> Optional[Path]:
    for n in names:
        v = os.getenv(n)
        if v:
            p = Path(v).expanduser()
            if p.exists():
                return p
    return None

def detect_home(arg_home: Optional[str]) -> Path:
    if arg_home:
        return Path(arg_home).expanduser()
    if os.getenv("NEUROFORGE_HOME"):
        return Path(os.getenv("NEUROFORGE_HOME", "")).expanduser()
    xdg = os.getenv("XDG_STATE_HOME") or os.getenv("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(xdg) / "neuroforge"

def ensure_dir(p: Path, mode: int = 0o700) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, mode)
    except Exception:
        pass  # best effort (Windows)

def safe_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except Exception:
        pass

def safe_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    safe_write_bytes(path, text.encode("utf-8"), mode=mode)

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=JSON_INDENT, ensure_ascii=False))

def print_kv(kv: Dict[str, Any]) -> None:
    width = max(len(k) for k in kv.keys()) if kv else 0
    for k, v in kv.items():
        print(f"{k.rjust(width)} : {v}")

def which(cmd: str) -> Optional[str]:
    for p in os.getenv("PATH", "").split(os.pathsep):
        cand = Path(p) / cmd
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return None

# ----------------------------- File lock (cross-platform) ---------------------------------------

@contextmanager
def file_lock(lock_path: Path, timeout: float = 10.0):
    """
    Простой межпроцессный файл-лок. На Windows/Unix — через os.O_EXCL.
    """
    start = time.monotonic()
    lock_file = lock_path
    ensure_dir(lock_file.parent)
    while True:
        try:
            fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, str(os.getpid()).encode())
            finally:
                os.close(fd)
            break
        except FileExistsError:
            if (time.monotonic() - start) > timeout:
                raise TimeoutError(f"Failed to acquire lock {lock_file}")
            time.sleep(0.1)
    try:
        yield
    finally:
        try:
            lock_file.unlink(missing_ok=True)
        except Exception:
            pass

# ----------------------------- Audit log --------------------------------------------------------

def audit_log(audit_path: Path, action: str, ok: bool, **fields: Any) -> None:
    ensure_dir(audit_path.parent)
    rec = {
        "ts": utc_now_iso(),
        "pid": os.getpid(),
        "action": action,
        "ok": ok,
        **fields,
    }
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# ----------------------------- Config Manager ---------------------------------------------------

class ConfigManager:
    """
    Управляет чтением/записью конфигурации.
    JSON (read/write) и TOML (read-only, если доступен tomllib).
    """
    def __init__(self, home: Path):
        self.home = home
        self.cfg_dir = home / "config"
        ensure_dir(self.cfg_dir)

    def _resolve(self, name: str) -> Path:
        base = Path(name)
        if base.suffix in (".json", ".toml"):
            return base if base.is_absolute() else (self.cfg_dir / base.name)
        # По умолчанию .json
        return self.cfg_dir / f"{name}.json"

    def get(self, name: str) -> Dict[str, Any]:
        path = self._resolve(name)
        if not path.exists():
            raise FileNotFoundError(str(path))
        if path.suffix == ".json":
            return json.loads(read_text(path) or "{}")
        if path.suffix == ".toml":
            if not tomllib:
                raise RuntimeError("TOML unsupported on this Python (need 3.11+)")
            with open(path, "rb") as f:
                return tomllib.load(f)  # type: ignore
        raise ValueError("Unsupported config format")

    def set(self, name: str, key: str, value: Any) -> Dict[str, Any]:
        path = self._resolve(name)
        if path.suffix != ".json":
            raise RuntimeError("Write supported only for JSON configs")
        cur = {}
        if path.exists():
            cur = json.loads(read_text(path) or "{}")
        # nested dot keys: a.b.c
        target = cur
        parts = key.split(".")
        for p in parts[:-1]:
            target = target.setdefault(p, {})
            if not isinstance(target, dict):
                raise ValueError(f"Intermediate key {p} is not an object")
        target[parts[-1]] = value
        safe_write_text(path, json.dumps(cur, indent=2, ensure_ascii=False))
        return cur

    def list_configs(self) -> List[str]:
        if not self.cfg_dir.exists():
            return []
        items = sorted([p.name for p in self.cfg_dir.glob("*.*") if p.suffix in (".json", ".toml")])
        return items

# ----------------------------- Users / Roles / Flags -------------------------------------------

@dataclass
class UserRecord:
    id: str
    name: str
    roles: List[str]
    disabled: bool
    created_at: str
    password_scrypt: Optional[str] = None  # base64(salt|digest)

class RBACStore:
    def __init__(self, home: Path):
        self.home = home
        self.dir = home / "rbac"
        ensure_dir(self.dir)
        self.users_path = self.dir / "users.json"
        self.roles_path = self.dir / "roles.json"
        self.flags_path = self.dir / "flags.json"
        for p in (self.users_path, self.roles_path, self.flags_path):
            if not p.exists():
                safe_write_text(p, "{}" if p.name != "roles.json" else "[]")

    def _load_json(self, path: Path) -> Any:
        try:
            return json.loads(read_text(path) or "{}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Corrupt JSON: {path}: {e}")

    def _dump_json(self, path: Path, obj: Any) -> None:
        safe_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False))

    # Users
    def users(self) -> Dict[str, Any]:
        return self._load_json(self.users_path)

    def set_users(self, data: Dict[str, Any]) -> None:
        self._dump_json(self.users_path, data)

    # Roles
    def roles(self) -> List[str]:
        data = self._load_json(self.roles_path)
        return list(data) if isinstance(data, list) else []

    def set_roles(self, roles: List[str]) -> None:
        self._dump_json(self.roles_path, roles)

    # Flags
    def flags(self) -> Dict[str, bool]:
        data = self._load_json(self.flags_path)
        return data if isinstance(data, dict) else {}

    def set_flags(self, flags: Dict[str, bool]) -> None:
        self._dump_json(self.flags_path, flags)

# Password hashing with scrypt (stdlib)
def scrypt_hash(password: str, *, n: int = 2**14, r: int = 8, p: int = 1) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return base64.b64encode(salt + digest).decode("ascii")

def verify_password(password: str, stored: str, *, n: int = 2**14, r: int = 8, p: int = 1) -> bool:
    raw = base64.b64decode(stored.encode("ascii"))
    salt, digest = raw[:16], raw[16:]
    cand = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return hmac.compare_digest(digest, cand)

# ----------------------------- Secrets Manager --------------------------------------------------

class SecretBackend:
    def __init__(self, home: Path):
        self.home = home
        self.sec_dir = home / "secrets"
        ensure_dir(self.sec_dir, mode=0o700)
        self.gpg = which("gpg")

    def _path_for(self, name: str) -> Path:
        # По умолчанию .enc при GPG, иначе .secret
        suffix = ".gpg" if self.gpg else ".secret"
        return self.sec_dir / f"{name}{suffix}"

    def set(self, name: str, data: bytes, *, gpg_recipient: Optional[str] = None) -> Path:
        path = self._path_for(name)
        if self.gpg:
            cmd = [self.gpg, "--batch", "--yes", "--quiet", "--output", str(path), "--symmetric", "--cipher-algo", "AES256", "--pinentry-mode", "loopback"]
            # Попросим Passphrase интерактивно
            passwd = getpass.getpass("GPG passphrase: ")
            env = os.environ.copy()
            env["GPG_PASSPHRASE"] = passwd
            # Подадим через --passphrase
            cmd.insert(1, f"--passphrase={passwd}")
            try:
                p = subprocess.run(cmd, input=data, capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"GPG failed: {e.stderr.decode('utf-8', 'ignore') or e}") from e
        else:
            # Без GPG — запись в 0600. ВАЖНО: не шифруется. Предупреждение вызывающей стороне.
            safe_write_bytes(path, data, mode=0o600)
        return path

    def get(self, name: str) -> bytes:
        # Пытаемся открыть по обоим суффиксам
        path = self.sec_dir / f"{name}.gpg"
        if path.exists() and self.gpg:
            passwd = getpass.getpass("GPG passphrase: ")
            cmd = [self.gpg, "--quiet", "--batch", "--yes", "--decrypt", f"--passphrase={passwd}", str(path)]
            try:
                p = subprocess.run(cmd, capture_output=True, check=True)
                return p.stdout
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"GPG failed: {e.stderr.decode('utf-8', 'ignore') or e}") from e
        path_f = self.sec_dir / f"{name}.secret"
        if path_f.exists():
            return path_f.read_bytes()
        raise FileNotFoundError(f"secret not found: {name}")

    def list(self) -> List[str]:
        if not self.sec_dir.exists():
            return []
        out: List[str] = []
        for p in sorted(self.sec_dir.iterdir()):
            if p.suffix in (".gpg", ".secret"):
                out.append(p.stem)
        return out

    def remove(self, name: str) -> bool:
        removed = False
        for suf in (".gpg", ".secret"):
            p = self.sec_dir / f"{name}{suf}"
            if p.exists():
                p.unlink()
                removed = True
        return removed

# ----------------------------- DB/Alembic -------------------------------------------------------

def alembic_available(cwd: Path) -> bool:
    if which("alembic") and (cwd / "alembic.ini").exists():
        return True
    return False

def alembic_upgrade_head(cwd: Path) -> Tuple[bool, str]:
    if not alembic_available(cwd):
        return False, "Alembic not available or alembic.ini not found"
    try:
        p = subprocess.run(["alembic", "upgrade", "head"], cwd=str(cwd), capture_output=True, text=True, check=True)
        return True, p.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or str(e))

# ----------------------------- Backup -----------------------------------------------------------

def make_backup(src: Path, dst_tar_gz: Path) -> None:
    ensure_dir(dst_tar_gz.parent)
    with tarfile.open(dst_tar_gz, "w:gz") as tar:
        tar.add(str(src), arcname=src.name)

def restore_backup(dst_root: Path, src_tar_gz: Path) -> None:
    with tarfile.open(src_tar_gz, "r:gz") as tar:
        tar.extractall(path=str(dst_root))

# ----------------------------- Runtime & command registry ---------------------------------------

@dataclass
class Runtime:
    home: Path
    json_out: bool
    yes: bool
    audit_path: Path

CommandFn = Callable[[argparse.Namespace, Runtime], int]

class CommandRegistry:
    def __init__(self):
        self._commands: Dict[str, Tuple[str, Callable[[argparse._SubParsersAction], argparse.ArgumentParser], CommandFn]] = {}

    def register(self, name: str, help_text: str):
        def deco(builder: Callable[[argparse._SubParsersAction], argparse.ArgumentParser]):
            def inner(fn: CommandFn):
                self._commands[name] = (help_text, builder, fn)
                return fn
            return inner
        return deco

    def build(self, subparsers: argparse._SubParsersAction) -> None:
        for name, (help_text, builder, _) in self._commands.items():
            parser = builder(subparsers)
            parser.set_defaults(_cmd=name, _fn=self._commands[name][2])

    def get(self, name: str) -> Tuple[str, CommandFn]:
        help_text, _, fn = self._commands[name]
        return help_text, fn

REG = CommandRegistry()

# ----------------------------- Command builders & handlers --------------------------------------

def add_common(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--yes", action="store_true", help="Assume yes for prompts")
    parser.add_argument("--home", type=str, default=None, help="Override NeuroForge home directory")
    parser.add_argument("--audit", type=str, default=None, help="Path to audit log (JSONL)")
    return parser

# health -----------------------------------------------------------------------------------------
@REG.register("health", "Show environment, tools and paths")
def _build_health(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("health", help="Show environment, tools and paths")
    return p

@REG.register("config", "Manage configuration")
def _build_config(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("config", help="Manage configuration")
    sp = p.add_subparsers(dest="op", required=True)
    p_get = sp.add_parser("get", help="Get config object as JSON")
    p_get.add_argument("name", help="Config name or file (json/toml)")
    p_set = sp.add_parser("set", help="Set config key (JSON only)")
    p_set.add_argument("name")
    p_set.add_argument("key", help="Dot path (e.g. service.port)")
    p_set.add_argument("value", help="JSON value (parsed)")
    p_list = sp.add_parser("list", help="List known configs")
    return p

@REG.register("flags", "Feature flags management")
def _build_flags(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("flags", help="Feature flags management")
    sp = p.add_subparsers(dest="op", required=True)
    p_en = sp.add_parser("enable", help="Enable feature flag")
    p_en.add_argument("name")
    p_dis = sp.add_parser("disable", help="Disable feature flag")
    p_dis.add_argument("name")
    sp.add_parser("list", help="List flags")
    return p

@REG.register("roles", "Roles management")
def _build_roles(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("roles", help="Roles management")
    sp = p.add_subparsers(dest="op", required=True)
    p_add = sp.add_parser("add", help="Add role")
    p_add.add_argument("role")
    p_rm = sp.add_parser("remove", help="Remove role")
    p_rm.add_argument("role")
    sp.add_parser("list", help="List roles")
    return p

@REG.register("users", "Users management")
def _build_users(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("users", help="Users management")
    sp = p.add_subparsers(dest="op", required=True)
    p_add = sp.add_parser("add", help="Add user")
    p_add.add_argument("user_id")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--role", action="append", default=[])
    sp.add_parser("list", help="List users")
    p_dis = sp.add_parser("disable", help="Disable user")
    p_dis.add_argument("user_id")
    p_en = sp.add_parser("enable", help="Enable user")
    p_en.add_argument("user_id")
    p_pwd = sp.add_parser("set-password", help="Set user password (scrypt)")
    p_pwd.add_argument("user_id")
    p_as = sp.add_parser("assign-role", help="Assign role to user")
    p_as.add_argument("user_id")
    p_as.add_argument("role")
    return p

@REG.register("secrets", "Secrets management (GPG preferred)")
def _build_secrets(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("secrets", help="Secrets management")
    sp = p.add_subparsers(dest="op", required=True)
    p_set = sp.add_parser("set", help="Set secret from stdin")
    p_set.add_argument("name")
    p_get = sp.add_parser("get", help="Get secret to stdout")
    p_get.add_argument("name")
    sp.add_parser("list", help="List secrets")
    p_rm = sp.add_parser("rm", help="Remove secret")
    p_rm.add_argument("name")
    return p

@REG.register("keys", "Generate random keys/tokens")
def _build_keys(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("keys", help="Generate random keys/tokens")
    p.add_argument("--bytes", type=int, default=32, help="Number of random bytes (default 32)")
    return p

@REG.register("db", "Database operations")
def _build_db(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("db", help="Database operations")
    sp = p.add_subparsers(dest="op", required=True)
    sp.add_parser("migrate", help="Run Alembic upgrade head (if available)")
    return p

@REG.register("backup", "Create and restore backups")
def _build_backup(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = sub.add_parser("backup", help="Create and restore backups")
    sp = p.add_subparsers(dest="op", required=True)
    p_cr = sp.add_parser("create", help="Create backup of home")
    p_cr.add_argument("--output", required=True, help="Path to .tar.gz")
    p_rs = sp.add_parser("restore", help="Restore backup into target root")
    p_rs.add_argument("--input", required=True, help="Path to .tar.gz")
    p_rs.add_argument("--target", required=True, help="Directory where to restore")
    return p

# -------------------------------- Handlers ------------------------------------------------------

def handle_health(ns: argparse.Namespace, rt: Runtime) -> int:
    info = {
        "ts": utc_now_iso(),
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "home": str(rt.home),
        "audit": str(rt.audit_path),
        "gpg": bool(which("gpg")),
        "alembic": bool(which("alembic")),
        "alembic_ini": (Path.cwd() / "alembic.ini").exists(),
    }
    audit_log(rt.audit_path, "health", True, info=info)
    if rt.json_out:
        print_json(info)
    else:
        print_kv(info)
    return EXIT_OK

def handle_config(ns: argparse.Namespace, rt: Runtime) -> int:
    cm = ConfigManager(rt.home)
    with file_lock(rt.home / ".lock"):
        if ns.op == "get":
            try:
                data = cm.get(ns.name)
                audit_log(rt.audit_path, "config.get", True, name=ns.name)
                if rt.json_out:
                    print_json(data)
                else:
                    print(json.dumps(data, indent=2, ensure_ascii=False))
                return EXIT_OK
            except FileNotFoundError:
                audit_log(rt.audit_path, "config.get", False, name=ns.name)
                print("Config not found", file=sys.stderr)
                return EXIT_NOT_FOUND
        elif ns.op == "set":
            try:
                value = json.loads(ns.value)
            except json.JSONDecodeError as e:
                print(f"Invalid JSON value: {e}", file=sys.stderr)
                return EXIT_USAGE
            try:
                data = cm.set(ns.name, ns.key, value)
                audit_log(rt.audit_path, "config.set", True, name=ns.name, key=ns.key)
                if rt.json_out:
                    print_json({"ok": True, "name": ns.name, "key": ns.key})
                else:
                    print("OK")
                return EXIT_OK
            except Exception as e:
                audit_log(rt.audit_path, "config.set", False, name=ns.name, key=ns.key, error=str(e))
                print(f"Error: {e}", file=sys.stderr)
                return EXIT_IO
        elif ns.op == "list":
            items = cm.list_configs()
            audit_log(rt.audit_path, "config.list", True, count=len(items))
            if rt.json_out:
                print_json(items)
            else:
                for it in items:
                    print(it)
            return EXIT_OK
    return EXIT_OK

def handle_flags(ns: argparse.Namespace, rt: Runtime) -> int:
    store = RBACStore(rt.home)
    with file_lock(rt.home / ".lock"):
        flags = store.flags()
        if ns.op == "enable":
            flags[ns.name] = True
            store.set_flags(flags)
            audit_log(rt.audit_path, "flags.enable", True, name=ns.name)
            if rt.json_out: print_json({"ok": True}); else: print("ENABLED")
            return EXIT_OK
        elif ns.op == "disable":
            flags[ns.name] = False
            store.set_flags(flags)
            audit_log(rt.audit_path, "flags.disable", True, name=ns.name)
            if rt.json_out: print_json({"ok": True}); else: print("DISABLED")
            return EXIT_OK
        else:  # list
            audit_log(rt.audit_path, "flags.list", True, count=len(flags))
            if rt.json_out: print_json(flags)
            else:
                for k, v in sorted(flags.items()):
                    print(f"{k} = {v}")
            return EXIT_OK

def handle_roles(ns: argparse.Namespace, rt: Runtime) -> int:
    store = RBACStore(rt.home)
    with file_lock(rt.home / ".lock"):
        roles = set(store.roles())
        if ns.op == "add":
            roles.add(ns.role)
            store.set_roles(sorted(roles))
            audit_log(rt.audit_path, "roles.add", True, role=ns.role)
            if rt.json_out: print_json({"ok": True}); else: print("OK")
            return EXIT_OK
        elif ns.op == "remove":
            if ns.role in roles:
                roles.remove(ns.role)
                store.set_roles(sorted(roles))
                audit_log(rt.audit_path, "roles.remove", True, role=ns.role)
                if rt.json_out: print_json({"ok": True}); else: print("OK")
                return EXIT_OK
            audit_log(rt.audit_path, "roles.remove", False, role=ns.role)
            print("Role not found", file=sys.stderr)
            return EXIT_NOT_FOUND
        else:  # list
            audit_log(rt.audit_path, "roles.list", True, count=len(roles))
            if rt.json_out: print_json(sorted(roles))
            else:
                for r in sorted(roles):
                    print(r)
            return EXIT_OK

def handle_users(ns: argparse.Namespace, rt: Runtime) -> int:
    store = RBACStore(rt.home)
    with file_lock(rt.home / ".lock"):
        users = store.users()
        roles = set(store.roles())
        if ns.op == "add":
            if ns.user_id in users:
                print("User already exists", file=sys.stderr)
                return EXIT_USAGE
            for r in ns.role:
                if r not in roles:
                    print(f"Unknown role: {r}", file=sys.stderr)
                    return EXIT_USAGE
            rec = UserRecord(
                id=ns.user_id,
                name=ns.name,
                roles=list(ns.role),
                disabled=False,
                created_at=utc_now_iso(),
                password_scrypt=None,
            )
            users[ns.user_id] = dataclasses.asdict(rec)
            store.set_users(users)
            audit_log(rt.audit_path, "users.add", True, user_id=ns.user_id)
            if rt.json_out: print_json({"ok": True}); else: print("OK")
            return EXIT_OK

        elif ns.op == "list":
            audit_log(rt.audit_path, "users.list", True, count=len(users))
            if rt.json_out:
                print_json(users)
            else:
                for uid, rec in users.items():
                    print(f"{uid}  {rec['name']}  roles={','.join(rec.get('roles', []))}  disabled={rec.get('disabled')}")
            return EXIT_OK

        elif ns.op == "disable":
            if ns.user_id not in users:
                print("User not found", file=sys.stderr); return EXIT_NOT_FOUND
            users[ns.user_id]["disabled"] = True
            store.set_users(users)
            audit_log(rt.audit_path, "users.disable", True, user_id=ns.user_id)
            if rt.json_out: print_json({"ok": True}); else: print("OK")
            return EXIT_OK

        elif ns.op == "enable":
            if ns.user_id not in users:
                print("User not found", file=sys.stderr); return EXIT_NOT_FOUND
            users[ns.user_id]["disabled"] = False
            store.set_users(users)
            audit_log(rt.audit_path, "users.enable", True, user_id=ns.user_id)
            if rt.json_out: print_json({"ok": True}); else: print("OK")
            return EXIT_OK

        elif ns.op == "set-password":
            if ns.user_id not in users:
                print("User not found", file=sys.stderr); return EXIT_NOT_FOUND
            pwd1 = getpass.getpass("New password: ")
            pwd2 = getpass.getpass("Repeat password: ")
            if pwd1 != pwd2:
                print("Passwords mismatch", file=sys.stderr); return EXIT_USAGE
            users[ns.user_id]["password_scrypt"] = scrypt_hash(pwd1)
            store.set_users(users)
            audit_log(rt.audit_path, "users.set_password", True, user_id=ns.user_id)
            if rt.json_out: print_json({"ok": True}); else: print("OK")
            return EXIT_OK

        elif ns.op == "assign-role":
            if ns.user_id not in users:
                print("User not found", file=sys.stderr); return EXIT_NOT_FOUND
            if ns.role not in roles:
                print("Role not found", file=sys.stderr); return EXIT_NOT_FOUND
            rec = users[ns.user_id]
            rs = set(rec.get("roles", []))
            rs.add(ns.role)
            rec["roles"] = sorted(rs)
            store.set_users(users)
            audit_log(rt.audit_path, "users.assign_role", True, user_id=ns.user_id, role=ns.role)
            if rt.json_out: print_json({"ok": True}); else: print("OK")
            return EXIT_OK

    return EXIT_OK

def handle_secrets(ns: argparse.Namespace, rt: Runtime) -> int:
    sb = SecretBackend(rt.home)
    if ns.op == "set":
        data = sys.stdin.buffer.read()
        if not data:
            print("No data on stdin", file=sys.stderr); return EXIT_USAGE
        with file_lock(rt.home / ".lock"):
            p = sb.set(ns.name, data)
            audit_log(rt.audit_path, "secrets.set", True, name=ns.name, path=str(p), gpg=bool(sb.gpg))
        if not sb.gpg:
            msg = "WARNING: GPG not found, secret stored unencrypted with 0600 permissions."
            if rt.json_out: print_json({"ok": True, "warning": msg})
            else: print(msg, file=sys.stderr)
        else:
            if rt.json_out: print_json({"ok": True})
            else: print("OK")
        return EXIT_OK

    elif ns.op == "get":
        try:
            data = sb.get(ns.name)
            sys.stdout.buffer.write(data)
            audit_log(rt.audit_path, "secrets.get", True, name=ns.name)
            return EXIT_OK
        except FileNotFoundError:
            audit_log(rt.audit_path, "secrets.get", False, name=ns.name)
            print("Secret not found", file=sys.stderr); return EXIT_NOT_FOUND
        except Exception as e:
            audit_log(rt.audit_path, "secrets.get", False, name=ns.name, error=str(e))
            print(f"Error: {e}", file=sys.stderr); return EXIT_EXTERNAL

    elif ns.op == "list":
        items = sb.list()
        audit_log(rt.audit_path, "secrets.list", True, count=len(items))
        if rt.json_out: print_json(items)
        else:
            for it in items:
                print(it)
        return EXIT_OK

    elif ns.op == "rm":
        with file_lock(rt.home / ".lock"):
            ok = sb.remove(ns.name)
            audit_log(rt.audit_path, "secrets.rm", ok, name=ns.name)
        if not ok:
            print("Secret not found", file=sys.stderr); return EXIT_NOT_FOUND
        if rt.json_out: print_json({"ok": True}); else: print("OK")
        return EXIT_OK

    return EXIT_USAGE

def handle_keys(ns: argparse.Namespace, rt: Runtime) -> int:
    n = max(1, int(ns.bytes))
    token = base64.urlsafe_b64encode(os.urandom(n)).decode("ascii").rstrip("=")
    audit_log(rt.audit_path, "keys.generate", True, bytes=n)
    if rt.json_out:
        print_json({"token": token, "bytes": n})
    else:
        print(token)
    return EXIT_OK

def handle_db(ns: argparse.Namespace, rt: Runtime) -> int:
    if ns.op == "migrate":
        ok, msg = alembic_upgrade_head(Path.cwd())
        audit_log(rt.audit_path, "db.migrate", ok, msg=msg)
        if ok:
            if rt.json_out: print_json({"ok": True, "output": msg})
            else: print("OK")
            return EXIT_OK
        else:
            print(msg, file=sys.stderr)
            return EXIT_EXTERNAL
    return EXIT_USAGE

def handle_backup(ns: argparse.Namespace, rt: Runtime) -> int:
    if ns.op == "create":
        out = Path(ns.output).expanduser()
        try:
            make_backup(rt.home, out)
            audit_log(rt.audit_path, "backup.create", True, path=str(out))
            if rt.json_out: print_json({"ok": True, "path": str(out)})
            else: print("OK")
            return EXIT_OK
        except Exception as e:
            audit_log(rt.audit_path, "backup.create", False, path=str(out), error=str(e))
            print(f"Error: {e}", file=sys.stderr); return EXIT_IO

    if ns.op == "restore":
        targ = Path(ns.target).expanduser()
        inp = Path(ns.input).expanduser()
        if not rt.yes:
            print(f"This will extract {inp} into {targ}. Proceed? [y/N]: ", end="", flush=True)
            ans = sys.stdin.readline().strip().lower()
            if ans not in ("y", "yes"):
                audit_log(rt.audit_path, "backup.restore", False, input=str(inp), target=str(targ), reason="aborted")
                print("Aborted", file=sys.stderr)
                return EXIT_ABORTED
        try:
            ensure_dir(targ)
            restore_backup(targ, inp)
            audit_log(rt.audit_path, "backup.restore", True, input=str(inp), target=str(targ))
            if rt.json_out: print_json({"ok": True})
            else: print("OK")
            return EXIT_OK
        except Exception as e:
            audit_log(rt.audit_path, "backup.restore", False, input=str(inp), target=str(targ), error=str(e))
            print(f"Error: {e}", file=sys.stderr); return EXIT_IO

    return EXIT_USAGE

# ----------------------------- Parser & Main ----------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="neuroforge-admin", add_help=True, description="NeuroForge Admin CLI")
    add_common(parser)
    subs = parser.add_subparsers(dest="cmd", required=True)
    REG.build(subs)
    return parser

def dispatch(ns: argparse.Namespace) -> int:
    home = detect_home(ns.home)
    ensure_dir(home)
    audit_path = Path(ns.audit).expanduser() if ns.audit else (home / "logs" / "admin_audit.log")
    rt = Runtime(home=home, json_out=ns.json, yes=ns.yes, audit_path=audit_path)

    # map commands
    handlers = {
        "health": handle_health,
        "config": handle_config,
        "flags": handle_flags,
        "roles": handle_roles,
        "users": handle_users,
        "secrets": handle_secrets,
        "keys": handle_keys,
        "db": handle_db,
        "backup": handle_backup,
    }
    if ns.cmd not in handlers:
        print("Unknown command", file=sys.stderr)
        return EXIT_USAGE
    return handlers[ns.cmd](ns, rt)

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    try:
        return dispatch(ns)
    except TimeoutError as e:
        print(str(e), file=sys.stderr); return EXIT_EXTERNAL
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr); return EXIT_ABORTED

if __name__ == "__main__":
    sys.exit(main())

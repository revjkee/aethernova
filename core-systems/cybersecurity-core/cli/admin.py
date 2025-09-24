# cybersecurity-core/cli/admin.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure, dependency-free administrative CLI for cybersecurity-core.

Features:
- Argparse-based subcommands (no external deps).
- Users stored in JSON with atomic writes and 0600 permissions.
- Password hashing via hashlib.scrypt with per-user random salt.
- Password policy checks (length/charset/entropy hints).
- Role management (admin, auditor, ops; extensible).
- Secrets rotation (e.g., jwt, api) with length/entropy, 0600 JSON.
- Structured JSON audit logging to file and stderr.
- Simple interprocess lock using atomic lockfile (best-effort, cross-plat).
- UTC timestamps (RFC 3339-like ISO format).
- Defensive coding: fail-closed defaults, exhaustive error handling.

NOTE:
This CLI uses local JSON storage for portability. In production,
replace StorageBackend with an implementation backed by your DB/KMS.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import io
import json
import os
import secrets
import string
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------- Constants & Defaults ----------------------------

ENV_HOME = "CYBERSEC_CORE_HOME"
DEFAULT_HOME = Path.home() / ".aethernova" / "cybersecurity-core"
USERS_FILE = "users.json"
SECRETS_FILE = "secrets.json"
AUDIT_LOG = "audit.log"
LOCKFILE = ".admin.lock"

# scrypt parameters (moderate by default; tune for your environment)
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SALT_LEN = 16

PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 256

DEFAULT_ROLES = {"admin", "auditor", "ops"}

# ---------------------------- Utilities --------------------------------------


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def home_dir() -> Path:
    root = Path(os.environ.get(ENV_HOME, DEFAULT_HOME))
    root.mkdir(parents=True, exist_ok=True)
    return root


def file_path(name: str) -> Path:
    return home_dir() / name


def set_file_mode_600(p: Path) -> None:
    try:
        os.chmod(p, 0o600)
    except Exception:
        # On some platforms (e.g., Windows), chmod may be limited.
        pass


def atomic_write_json(p: Path, data: Any) -> None:
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=p.name + ".", dir=str(p.parent))
    try:
        with io.open(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, p)
        set_file_mode_600(p)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


def read_json(p: Path, default: Any) -> Any:
    if not p.exists():
        return default
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


@contextmanager
def lockfile(path: Path, timeout_sec: int = 30):
    """
    Best-effort interprocess lock using atomic file creation.
    Cross-platform: relies on O_EXCL semantics.
    """
    lock = path / LOCKFILE
    start = time.time()
    while True:
        try:
            # O_CREAT|O_EXCL ensures atomicity: fail if exists.
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode("ascii"))
            finally:
                os.close(fd)
            set_file_mode_600(lock)
            break
        except FileExistsError:
            if time.time() - start > timeout_sec:
                raise TimeoutError(f"Lock timeout on {lock}")
            time.sleep(0.1)
    try:
        yield
    finally:
        try:
            os.unlink(lock)
        except FileNotFoundError:
            pass
        except Exception:
            pass


def json_log(event: str, **fields: Any) -> None:
    rec = {"ts": now_utc(), "event": event, "v": 1, **fields}
    line = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    # stderr for immediate visibility
    sys.stderr.write(line + "\n")
    sys.stderr.flush()
    # file for audit trail
    p = file_path(AUDIT_LOG)
    with p.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    set_file_mode_600(p)


# ---------------------------- Crypto & Secrets -------------------------------


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def scrypt_hash(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(SALT_LEN)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64e(salt)}${b64e(dk)}"


def scrypt_verify(password: str, encoded: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = encoded.split("$", 5)
        if algo != "scrypt":
            return False
        n = int(n)
        r = int(r)
        p = int(p)
        salt = b64d(salt_b64)
        expected = b64d(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False


def strong_random_token(length_bytes: int = 48) -> str:
    return b64e(secrets.token_bytes(length_bytes))


# ---------------------------- Models & Storage -------------------------------

@dataclasses.dataclass
class User:
    username: str
    email: str
    roles: List[str]
    password_hash: str
    disabled: bool
    created_at: str
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "User":
        return User(
            username=d["username"],
            email=d["email"],
            roles=list(d.get("roles", [])),
            password_hash=d["password_hash"],
            disabled=bool(d.get("disabled", False)),
            created_at=d.get("created_at", now_utc()),
            updated_at=d.get("updated_at", now_utc()),
        )


class StorageBackend:
    """
    Replace with DB-backed implementation in production.
    """

    def __init__(self, base: Path):
        self.base = base
        self.users_path = file_path(USERS_FILE)
        self.secrets_path = file_path(SECRETS_FILE)

    # Users
    def load_users(self) -> Dict[str, Dict[str, Any]]:
        return read_json(self.users_path, default={})

    def save_users(self, data: Dict[str, Dict[str, Any]]) -> None:
        atomic_write_json(self.users_path, data)

    # Secrets
    def load_secrets(self) -> Dict[str, Any]:
        return read_json(self.secrets_path, default={})

    def save_secrets(self, data: Dict[str, Any]) -> None:
        atomic_write_json(self.secrets_path, data)


# ---------------------------- Password Policy --------------------------------

def assess_password_strength(pw: str) -> Tuple[bool, List[str]]:
    issues: List[str] = []
    if not (PASSWORD_MIN_LEN <= len(pw) <= PASSWORD_MAX_LEN):
        issues.append(f"Длина пароля должна быть от {PASSWORD_MIN_LEN} до {PASSWORD_MAX_LEN} символов.")
    charset_checks = [
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in string.punctuation for c in pw),
    ]
    if sum(charset_checks) < 3:
        issues.append("Пароль должен содержать как минимум три класса символов: строчные, ПРОПИСНЫЕ, цифры, спецсимволы.")
    if any(ch.isspace() for ch in pw):
        issues.append("Пароль не должен содержать пробелы/переводы строк.")
    if pw.lower() in {"password", "qwerty", "123456", "letmein", "admin"}:
        issues.append("Слишком распространённый пароль.")
    return (len(issues) == 0, issues)


def prompt_password(confirm: bool = True) -> str:
    while True:
        pw = getpass.getpass("Введите пароль: ")
        ok, issues = assess_password_strength(pw)
        if not ok:
            for i in issues:
                print(f"Ошибка: {i}", file=sys.stderr)
            continue
        if confirm:
            pw2 = getpass.getpass("Повторите пароль: ")
            if pw != pw2:
                print("Пароли не совпадают.", file=sys.stderr)
                continue
        return pw


# ---------------------------- User Operations --------------------------------

def user_add(args: argparse.Namespace, storage: StorageBackend) -> int:
    with lockfile(home_dir()):
        users = storage.load_users()
        if args.username in users:
            print(f"Пользователь '{args.username}' уже существует.", file=sys.stderr)
            return 2
        password = prompt_password(confirm=True)
        ph = scrypt_hash(password)
        roles = set(DEFAULT_ROLES if args.admin else (args.roles or []))
        user = User(
            username=args.username,
            email=args.email,
            roles=sorted(roles),
            password_hash=ph,
            disabled=False,
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        users[args.username] = user.to_dict()
        storage.save_users(users)
        json_log("user_add", username=args.username, email=args.email, roles=user.roles)
        print(f"Создан пользователь '{args.username}'.")
        return 0


def user_list(args: argparse.Namespace, storage: StorageBackend) -> int:
    users = storage.load_users()
    out = []
    for u in sorted(users.values(), key=lambda d: d["username"]):
        out.append(
            {
                "username": u["username"],
                "email": u["email"],
                "roles": u.get("roles", []),
                "disabled": bool(u.get("disabled", False)),
                "created_at": u.get("created_at"),
                "updated_at": u.get("updated_at"),
            }
        )
    print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def user_set_password(args: argparse.Namespace, storage: StorageBackend) -> int:
    with lockfile(home_dir()):
        users = storage.load_users()
        u = users.get(args.username)
        if not u:
            print(f"Пользователь '{args.username}' не найден.", file=sys.stderr)
            return 3
        password = prompt_password(confirm=True)
        u["password_hash"] = scrypt_hash(password)
        u["updated_at"] = now_utc()
        storage.save_users(users)
        json_log("user_set_password", username=args.username)
        print(f"Пароль пользователя '{args.username}' обновлён.")
        return 0


def user_disable(args: argparse.Namespace, storage: StorageBackend) -> int:
    with lockfile(home_dir()):
        users = storage.load_users()
        u = users.get(args.username)
        if not u:
            print(f"Пользователь '{args.username}' не найден.", file=sys.stderr)
            return 3
        u["disabled"] = True
        u["updated_at"] = now_utc()
        storage.save_users(users)
        json_log("user_disable", username=args.username)
        print(f"Пользователь '{args.username}' отключён.")
        return 0


def user_enable(args: argparse.Namespace, storage: StorageBackend) -> int:
    with lockfile(home_dir()):
        users = storage.load_users()
        u = users.get(args.username)
        if not u:
            print(f"Пользователь '{args.username}' не найден.", file=sys.stderr)
            return 3
        u["disabled"] = False
        u["updated_at"] = now_utc()
        storage.save_users(users)
        json_log("user_enable", username=args.username)
        print(f"Пользователь '{args.username}' включён.")
        return 0


def user_set_roles(args: argparse.Namespace, storage: StorageBackend) -> int:
    with lockfile(home_dir()):
        users = storage.load_users()
        u = users.get(args.username)
        if not u:
            print(f"Пользователь '{args.username}' не найден.", file=sys.stderr)
            return 3
        roles = sorted(set(args.roles or []))
        u["roles"] = roles
        u["updated_at"] = now_utc()
        storage.save_users(users)
        json_log("user_set_roles", username=args.username, roles=roles)
        print(f"Роли пользователя '{args.username}' обновлены: {roles}")
        return 0


# ---------------------------- Secrets Operations -----------------------------

def secrets_rotate(args: argparse.Namespace, storage: StorageBackend) -> int:
    with lockfile(home_dir()):
        secrets_data = storage.load_secrets()
        name = args.name
        length = args.bytes
        if length < 32:
            print("Минимальная длина секрета — 32 байта.", file=sys.stderr)
            return 4
        value = strong_random_token(length)
        entry = {
            "value": value,
            "rotated_at": now_utc(),
            "note": args.note or "",
        }
        secrets_data[name] = entry
        storage.save_secrets(secrets_data)
        json_log("secret_rotate", name=name, length=length)
        # Output only a short preview to avoid shoulder-surfing in logs/term
        print(f"Секрет '{name}' обновлён. Префикс: {value[:8]}...")
        return 0


def secrets_list(args: argparse.Namespace, storage: StorageBackend) -> int:
    secrets_data = storage.load_secrets()
    # Do NOT print secret values; only metadata for safety.
    safe = {
        name: {k: v for k, v in meta.items() if k != "value"}
        for name, meta in secrets_data.items()
    }
    print(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


# ---------------------------- CLI Wiring -------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cybersecurity-admin",
        description="Administrative CLI for cybersecurity-core",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # user group
    user = sub.add_parser("user", help="Операции с пользователями")
    user_sub = user.add_subparsers(dest="user_cmd", required=True)

    add = user_sub.add_parser("add", help="Создать пользователя")
    add.add_argument("--username", required=True)
    add.add_argument("--email", required=True)
    add.add_argument("--roles", nargs="*", help="Список ролей")
    add.add_argument("--admin", action="store_true", help="Назначить роли по умолчанию для администратора")
    add.set_defaults(func=user_add)

    lst = user_sub.add_parser("list", help="Список пользователей")
    lst.set_defaults(func=user_list)

    pw = user_sub.add_parser("set-password", help="Сменить пароль пользователя")
    pw.add_argument("--username", required=True)
    pw.set_defaults(func=user_set_password)

    dis = user_sub.add_parser("disable", help="Отключить пользователя")
    dis.add_argument("--username", required=True)
    dis.set_defaults(func=user_disable)

    ena = user_sub.add_parser("enable", help="Включить пользователя")
    ena.add_argument("--username", required=True)
    ena.set_defaults(func=user_enable)

    roles = user_sub.add_parser("set-roles", help="Задать роли пользователя")
    roles.add_argument("--username", required=True)
    roles.add_argument("--roles", nargs="+", required=True)
    roles.set_defaults(func=user_set_roles)

    # secrets group
    sec = sub.add_parser("secrets", help="Операции с секретами")
    sec_sub = sec.add_subparsers(dest="sec_cmd", required=True)

    rot = sec_sub.add_parser("rotate", help="Ротация/создание секрета")
    rot.add_argument("--name", required=True, help="Имя секрета (например, jwt, api, webhook)")
    rot.add_argument("--bytes", type=int, default=48, help="Длина секрета в байтах (min 32)")
    rot.add_argument("--note", help="Произвольная заметка")
    rot.set_defaults(func=secrets_rotate)

    secl = sec_sub.add_parser("list", help="Список секретов (без значений)")
    secl.set_defaults(func=secrets_list)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    # Ensure base dir and audit log exist with proper mode.
    base = home_dir()
    set_file_mode_600(file_path(AUDIT_LOG))
    storage = StorageBackend(base)

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if hasattr(args, "func"):
            return int(args.func(args, storage))
        parser.print_help()
        return 0
    except TimeoutError as e:
        json_log("error", error="lock_timeout", detail=str(e))
        print(f"Ошибка: {e}", file=sys.stderr)
        return 10
    except KeyboardInterrupt:
        json_log("error", error="keyboard_interrupt")
        print("Операция прервана пользователем.", file=sys.stderr)
        return 130
    except Exception as e:
        # Avoid leaking secrets; only minimal info.
        json_log("error", error="unhandled_exception", type=type(e).__name__)
        print("Внутренняя ошибка. Подробности записаны в журнал.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

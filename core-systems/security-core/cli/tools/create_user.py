#!/usr/bin/env python3
# security-core/cli/tools/create_user.py
from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import string
import sys
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib import request, error as urlerror

# ========================= Утилиты =========================

USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")
# Упрощенная, но строгая проверка RFC5322 для практики
EMAIL_RE = re.compile(
    r"^(?P<local>[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64})@(?P<domain>[A-Za-z0-9.-]{1,255})$"
)

def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)

def normalize_username(raw: str) -> str:
    s = nfc(raw).strip().lower()
    s = s.replace(" ", "_")
    if not USERNAME_RE.match(s):
        raise ValueError("username must be 3-64 chars: [a-z0-9._-]")
    return s

def normalize_email(raw: str) -> str:
    s = nfc(raw).strip()
    m = EMAIL_RE.match(s)
    if not m:
        raise ValueError("invalid email format")
    local = m.group("local")
    domain = m.group("domain").lower()
    # punycode для домена при необходимости
    try:
        domain_idna = domain.encode("idna").decode("ascii")
    except Exception:
        raise ValueError("invalid email domain (IDNA)")
    return f"{local}@{domain_idna}"

# ========================= Пароли (scrypt) =========================

@dataclass
class PasswordPolicy:
    length: int = 16
    min_upper: int = 1
    min_lower: int = 1
    min_digits: int = 1
    min_symbols: int = 1
    allowed_symbols: str = "!@#$%^&*()-_=+[]{};:,.?/"

def generate_password(policy: PasswordPolicy) -> str:
    upper = [secrets.choice(string.ascii_uppercase) for _ in range(policy.min_upper)]
    lower = [secrets.choice(string.ascii_lowercase) for _ in range(policy.min_lower)]
    digits = [secrets.choice(string.digits) for _ in range(policy.min_digits)]
    symbols = [secrets.choice(policy.allowed_symbols) for _ in range(policy.min_symbols)]
    remaining_len = max(policy.length, policy.min_upper + policy.min_lower + policy.min_digits + policy.min_symbols) - (
        policy.min_upper + policy.min_lower + policy.min_digits + policy.min_symbols
    )
    pool = string.ascii_letters + string.digits + policy.allowed_symbols
    rest = [secrets.choice(pool) for _ in range(remaining_len)]
    pwd_list = upper + lower + digits + symbols + rest
    secrets.SystemRandom().shuffle(pwd_list)
    return "".join(pwd_list)

def validate_password_strength(pwd: str, policy: PasswordPolicy) -> None:
    if len(pwd) < policy.length:
        raise ValueError(f"password must be at least {policy.length} characters")
    if sum(c.isupper() for c in pwd) < policy.min_upper:
        raise ValueError("password must contain uppercase letters")
    if sum(c.islower() for c in pwd) < policy.min_lower:
        raise ValueError("password must contain lowercase letters")
    if sum(c.isdigit() for c in pwd) < policy.min_digits:
        raise ValueError("password must contain digits")
    if sum(c in policy.allowed_symbols for c in pwd) < policy.min_symbols:
        raise ValueError("password must contain symbols")

@dataclass
class ScryptParams:
    n: int = 2 ** 15  # 32768
    r: int = 8
    p: int = 1
    salt_len: int = 16
    dk_len: int = 32

def hash_password_scrypt(password: str, params: ScryptParams = ScryptParams()) -> str:
    salt = secrets.token_bytes(params.salt_len)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=params.n, r=params.r, p=params.p, dklen=params.dk_len)
    return "scrypt${}${}${}${}${}".format(
        params.n,
        params.r,
        params.p,
        base64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii"),
        base64.urlsafe_b64encode(dk).rstrip(b"=").decode("ascii"),
    )

def verify_password_scrypt(password: str, stored: str) -> bool:
    try:
        scheme, n_s, r_s, p_s, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        n = int(n_s)
        r = int(r_s)
        p = int(p_s)
        salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
        expected = base64.urlsafe_b64decode(dk_b64 + "=" * (-len(dk_b64) % 4))
        calc = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(calc, expected)
    except Exception:
        return False

# ========================= TOTP =========================

def gen_totp_secret(bytes_len: int = 20) -> str:
    raw = secrets.token_bytes(bytes_len)
    # base32 без паддинга
    return base64.b32encode(raw).decode("ascii").replace("=", "")

def totp_uri(secret_b32: str, account_name: str, issuer: Optional[str] = None, period: int = 30, digits: int = 6) -> str:
    # otpauth://totp/Issuer:account?secret=XYZ&issuer=Issuer&period=30&digits=6&algorithm=SHA1
    label = f"{issuer}:{account_name}" if issuer else account_name
    from urllib.parse import quote, urlencode
    params = {"secret": secret_b32, "period": str(period), "digits": str(digits), "algorithm": "SHA1"}
    if issuer:
        params["issuer"] = issuer
    return f"otpauth://totp/{quote(label)}?{urlencode(params)}"

# ========================= Модель пользователя =========================

@dataclass
class UserRecord:
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    password_hash: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    totp_secret: Optional[str] = None
    created_at: int = field(default_factory=lambda: int(time.time()))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_public(self, include_generated_password: Optional[str] = None, totp_uri_str: Optional[str] = None) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("password_hash", None)
        if include_generated_password is not None:
            data["generated_password"] = include_generated_password
        if totp_uri_str:
            data["totp_uri"] = totp_uri_str
        return data

# ========================= Бэкенды =========================

class BackendError(Exception):
    pass

class BackendBase:
    def create_user(self, rec: UserRecord, idempotency_key: Optional[str] = None) -> Mapping[str, Any]:
        raise NotImplementedError

class HttpBackend(BackendBase):
    def __init__(self, base_url: str, token: Optional[str], timeout: int = 7) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def create_user(self, rec: UserRecord, idempotency_key: Optional[str] = None) -> Mapping[str, Any]:
        url = f"{self.base}/api/v1/users"
        payload = dataclasses.asdict(rec)
        # Никогда не отправляем пустые поля
        payload = {k: v for k, v in payload.items() if v not in (None, [], {})}
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, method="POST", data=data, headers={
            "content-type": "application/json",
            "accept": "application/json",
            "x-correlation-id": str(uuid.uuid4()),
        })
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        if idempotency_key:
            req.add_header("idempotency-key", idempotency_key)
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                if resp.status not in (200, 201):
                    raise BackendError(f"http_status:{resp.status}")
        except urlerror.HTTPError as e:
            msg = e.read().decode("utf-8", errors="ignore")
            if e.code in (409,):  # конфликт (существует)
                raise BackendError(f"conflict:{msg}")
            raise BackendError(f"http_error:{e.code}:{msg}")
        except Exception as e:
            raise BackendError(f"http_failure:{e}")
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {"status": "created"}

class SqliteBackend(BackendBase):
    def __init__(self, db_path: str) -> None:
        self.path = db_path
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("""
                create table if not exists users (
                    id text primary key,
                    username text unique not null,
                    email text unique not null,
                    full_name text,
                    password_hash text,
                    roles text,
                    groups text,
                    scopes text,
                    totp_secret text,
                    created_at integer not null,
                    metadata text
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def create_user(self, rec: UserRecord, idempotency_key: Optional[str] = None) -> Mapping[str, Any]:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "insert into users (id, username, email, full_name, password_hash, roles, groups, scopes, totp_secret, created_at, metadata) "
                "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rec.id,
                    rec.username,
                    rec.email,
                    rec.full_name,
                    rec.password_hash,
                    json.dumps(rec.roles, ensure_ascii=False),
                    json.dumps(rec.groups, ensure_ascii=False),
                    json.dumps(rec.scopes, ensure_ascii=False),
                    rec.totp_secret,
                    rec.created_at,
                    json.dumps(rec.metadata, ensure_ascii=False),
                ),
            )
            conn.commit()
            return {"status": "created", "id": rec.id, "username": rec.username}
        except sqlite3.IntegrityError as e:
            raise BackendError(f"conflict:{e}")
        finally:
            conn.close()

# ========================= CLI =========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="create_user",
        description="Create user in security-core via HTTP API or SQLite backend."
    )
    p.add_argument("--backend", choices=["http", "sqlite"], required=True, help="Storage backend.")
    p.add_argument("--id", help="User ID (UUID). If omitted, generated.")
    p.add_argument("--username", required=True, help="Username (3-64 chars, [a-z0-9._-]).")
    p.add_argument("--email", required=True, help="User email.")
    p.add_argument("--full-name", help="Full name.")
    p.add_argument("--role", dest="roles", action="append", default=[], help="Role (repeatable).")
    p.add_argument("--group", dest="groups", action="append", default=[], help="Group (repeatable).")
    p.add_argument("--scope", dest="scopes", action="append", default=[], help="Scope (repeatable).")
    p.add_argument("--meta", dest="metadata", action="append", default=[], help="Metadata key=value (repeatable).")

    # Пароль
    p.add_argument("--password", help="Password (discouraged, prefer --password-stdin or prompt).")
    p.add_argument("--password-stdin", action="store_true", help="Read password from stdin (single line).")
    p.add_argument("--prompt-password", action="store_true", help="Prompt for password interactively.")
    p.add_argument("--generate-password", action="store_true", help="Generate strong password and return it in output only.")
    p.add_argument("--pw-length", type=int, default=16)
    p.add_argument("--pw-min-upper", type=int, default=1)
    p.add_argument("--pw-min-lower", type=int, default=1)
    p.add_argument("--pw-min-digits", type=int, default=1)
    p.add_argument("--pw-min-symbols", type=int, default=1)

    # TOTP
    p.add_argument("--enroll-totp", action="store_true", help="Generate TOTP secret and include otpauth URI in output.")
    p.add_argument("--totp-issuer", default=None, help="Issuer for TOTP label.")

    # Бэкенды
    p.add_argument("--api-base", help="[http] Base URL, e.g., https://iam.internal")
    p.add_argument("--token", help="[http] Bearer token. Or set SEC_CORE_TOKEN env var.")
    p.add_argument("--db", help="[sqlite] Path to SQLite DB file.")

    # Прочее
    p.add_argument("--idempotency-key", help="Idempotency key to avoid duplicates (HTTP header).")
    p.add_argument("--output", choices=["json", "text"], default="json")
    p.add_argument("--dry-run", action="store_true", help="Do not persist, just print intended record.")
    return p

def parse_metadata(pairs: Sequence[str]) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    for kv in pairs:
        if "=" not in kv:
            raise ValueError(f"bad meta '{kv}', expected key=value")
        k, v = kv.split("=", 1)
        k = k.strip()
        v = v.strip()
        # Попытка распарсить JSON-значение, иначе строка
        try:
            meta[k] = json.loads(v)
        except Exception:
            meta[k] = v
    return meta

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # Валидация/нормализация
    try:
        username = normalize_username(args.username)
        email = normalize_email(args.email)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    full_name = nfc(args.full_name) if args.full_name else None
    roles = sorted({nfc(r).strip() for r in args.roles if r})
    groups = sorted({nfc(g).strip() for g in args.groups if g})
    scopes = sorted({nfc(s).strip() for s in args.scopes if s})
    metadata = {}
    try:
        metadata = parse_metadata(args.metadata)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # Пароль
    policy = PasswordPolicy(
        length=max(8, int(args.pw_length)),
        min_upper=max(0, args.pw_min_upper),
        min_lower=max(0, args.pw_min_lower),
        min_digits=max(0, args.pw_min_digits),
        min_symbols=max(0, args.pw_min_symbols),
    )
    password_raw: Optional[str] = None
    generated_password: Optional[str] = None

    if args.generate_password:
        generated_password = generate_password(policy)
        password_raw = generated_password
    elif args.password_stdin:
        line = sys.stdin.readline()
        password_raw = line.rstrip("\r\n")
    elif args.prompt_password:
        pw1 = getpass.getpass("Enter password: ")
        pw2 = getpass.getpass("Repeat password: ")
        if pw1 != pw2:
            print("error: passwords do not match", file=sys.stderr)
            return 2
        password_raw = pw1
    elif args.password:
        password_raw = args.password

    password_hash = None
    if password_raw:
        try:
            validate_password_strength(password_raw, policy)
        except Exception as e:
            print(f"error: weak password: {e}", file=sys.stderr)
            return 2
        password_hash = hash_password_scrypt(password_raw)

    # TOTP
    totp_secret = None
    totp_uri_str = None
    if args.enroll_totp:
        totp_secret = gen_totp_secret()
        totp_uri_str = totp_uri(totp_secret, account_name=username, issuer=args.totp_issuer)

    # ID
    user_id = args.id or str(uuid.uuid4())

    rec = UserRecord(
        id=user_id,
        username=username,
        email=email,
        full_name=full_name,
        password_hash=password_hash,
        roles=list(roles),
        groups=list(groups),
        scopes=list(scopes),
        totp_secret=totp_secret,
        metadata=metadata,
    )

    # Dry-run
    if args.dry_run:
        out = rec.to_public(include_generated_password=generated_password, totp_uri_str=totp_uri_str)
        return _emit(out, args.output)

    # Бэкенд
    try:
        if args.backend == "http":
            token = args.token or os.getenv("SEC_CORE_TOKEN")
            if not args.api_base:
                print("error: --api-base required for http backend", file=sys.stderr)
                return 2
            backend: BackendBase = HttpBackend(args.api_base, token)
        elif args.backend == "sqlite":
            if not args.db:
                print("error: --db required for sqlite backend", file=sys.stderr)
                return 2
            backend = SqliteBackend(args.db)
        else:
            print("error: unsupported backend", file=sys.stderr)
            return 2
    except Exception as e:
        print(f"error: backend init failed: {e}", file=sys.stderr)
        return 1

    # Создание
    try:
        _ = backend.create_user(rec, idempotency_key=args.idempotency_key or f"cu-{user_id}")
    except BackendError as e:
        print(f"error: backend: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: unexpected backend error: {e}", file=sys.stderr)
        return 1

    out = rec.to_public(include_generated_password=generated_password, totp_uri_str=totp_uri_str)
    return _emit(out, args.output)

def _emit(obj: Mapping[str, Any], mode: str) -> int:
    if mode == "json":
        print(json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    else:
        # Короткий текстовый вывод
        print(f"id: {obj.get('id')}")
        print(f"username: {obj.get('username')}")
        print(f"email: {obj.get('email')}")
        if obj.get("full_name"):
            print(f"full_name: {obj.get('full_name')}")
        if obj.get("generated_password"):
            print("generated_password: [REDACTED IN TEXT MODE]")
        if obj.get("totp_uri"):
            print(f"totp_uri: {obj.get('totp_uri')}")
        print(f"roles: {', '.join(obj.get('roles', []))}")
        print(f"groups: {', '.join(obj.get('groups', []))}")
        print(f"scopes: {', '.join(obj.get('scopes', []))}")
        if obj.get("metadata"):
            print(f"metadata: {json.dumps(obj.get('metadata'), ensure_ascii=False)}")
        print(f"created_at: {obj.get('created_at')}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

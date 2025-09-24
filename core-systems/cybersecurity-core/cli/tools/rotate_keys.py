#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybersecurity-core/cli/tools/rotate_keys.py

Промышленный CLI-инструмент ротации ключевых пар:
- Поддержка алгоритмов: ed25519 (по умолчанию), rsa (3072/4096), ecdsa (secp256r1/secp384r1).
- Шифрование приватного ключа с помощью BestAvailableEncryption (требует пароль).
- Атомарная запись файлов и строгие права доступа (0600 для ключей, 0700 для директорий).
- Структура keystore:
    <keystore>/<name>/
      ├── private/ key-<ts>-<alg>.pem
      ├── public/  key-<ts>-<alg>.pub      (OpenSSH)
      ├── pem/     key-<ts>-<alg>.pem.pub  (PEM public)
      ├── current  (symlink на basename)   (fallback: current.txt)
      ├── manifest.json                    (история ротаций)
      └── audit.jsonl                      (цепочка HMAC-аудита, опционально)
- Управление жизненным циклом:
    * Порог по возрасту (--age-days) или принудительная ротация (--force).
    * Хранение N предыдущих версий (--keep).
    * Обновление "current" на новую пару (--set-current).
    * Журналирование манифеста и аудита (с HMAC при наличии ключа).
- Режимы: rotate (по умолчанию), status, list.

Примеры:
    rotate:  python rotate_keys.py --keystore ./keys --name app1 --algo ed25519 --passphrase-env KEY_PASS --set-current --keep 5
    status:  python rotate_keys.py status --keystore ./keys --name app1
    list:    python rotate_keys.py list --keystore ./keys --name app1

Зависимости:
    pip install cryptography

Автор: Aethernova / cybersecurity-core
Лицензия: MIT (или ваша корпоративная)
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import getpass
import hashlib
import hmac
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
    from cryptography.hazmat.backends import default_backend
except Exception as e:  # pragma: no cover
    sys.stderr.write(
        "Не найдена библиотека 'cryptography'. Установите: pip install cryptography\n"
    )
    raise

# ==========================
# Конфигурация и константы
# ==========================

DEFAULT_ALGO = "ed25519"
SUPPORTED_ALGOS = ("ed25519", "rsa", "ecdsa")
DEFAULT_RSA_BITS = 3072
DEFAULT_ECDSA_CURVE = "secp256r1"  # вариант: secp384r1
CURRENT_LINK_NAME = "current"
CURRENT_FALLBACK_FILE = "current.txt"

PRIVATE_DIR = "private"
PUBLIC_DIR = "public"
PEM_DIR = "pem"
MANIFEST_FILE = "manifest.json"
AUDIT_FILE = "audit.jsonl"

# ==========================
# Исключения
# ==========================

class RotationError(Exception):
    pass

# ==========================
# Утилиты ФС и безопасность
# ==========================

def secure_mkdir(p: Path, mode: int = 0o700) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, mode)
    except Exception:
        # На некоторых ОС (Windows) режимы не применимы — пропускаем
        pass

def atomic_write_bytes(target: Path, data: bytes, mode: int = 0o600) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_path, mode)
        except Exception:
            pass
        os.replace(tmp_path, target)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

def enforce_permissions(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except Exception:
        pass

def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

def ts_compact(dtobj: dt.datetime) -> str:
    return dtobj.strftime("%Y%m%dT%H%M%SZ")

# ==========================
# Пароли/секреты
# ==========================

def load_passphrase(env: Optional[str], file: Optional[str], prompt: bool, confirm: bool) -> Optional[bytes]:
    if env:
        val = os.getenv(env)
        if val is None:
            raise RotationError(f"Переменная окружения {env} не установлена.")
        return val.encode("utf-8")
    if file:
        p = Path(file)
        if not p.exists():
            raise RotationError(f"Файл пароля не найден: {file}")
        return p.read_text(encoding="utf-8").strip().encode("utf-8")
    if prompt:
        pw1 = getpass.getpass("Введите пароль для шифрования приватного ключа: ")
        if confirm:
            pw2 = getpass.getpass("Повторите пароль: ")
            if pw1 != pw2:
                raise RotationError("Пароли не совпадают.")
        return pw1.encode("utf-8")
    return None

# ==========================
# Генерация ключей
# ==========================

@dataclasses.dataclass
class KeyMeta:
    algorithm: str
    bits: Optional[int]
    curve: Optional[str]
    created_at: str
    fingerprint: str
    basename: str

def generate_keypair(
    algo: str,
    rsa_bits: int = DEFAULT_RSA_BITS,
    ecdsa_curve: str = DEFAULT_ECDSA_CURVE,
):
    if algo == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
    elif algo == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits, backend=default_backend())
    elif algo == "ecdsa":
        curve_obj = {"secp256r1": ec.SECP256R1(), "secp384r1": ec.SECP384R1()}.get(ecdsa_curve)
        if not curve_obj:
            raise RotationError(f"Неподдерживаемая кривая ECDSA: {ecdsa_curve}")
        priv = ec.generate_private_key(curve_obj, backend=default_backend())
    else:
        raise RotationError(f"Неподдерживаемый алгоритм: {algo}")
    pub = priv.public_key()
    return priv, pub

def serialize_private_encrypted(priv, passphrase: bytes) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )

def serialize_private_unencrypted(priv) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def serialize_public_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def serialize_public_openssh(pub, comment: str = "") -> bytes:
    data = pub.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    if comment:
        return data + b" " + comment.encode("utf-8")
    return data

def fingerprint_ssh_sha256(openssh_pub: bytes) -> str:
    # OpenSSH-style fingerprint: "SHA256:<b64(sha256(pub_bytes))>"
    # Убираем комментарий перед хэшем
    key_part = openssh_pub.split(b" ")[0]
    digest = hashlib.sha256(key_part).digest()
    b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64}"

# ==========================
# Манифест и аудит
# ==========================

def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise RotationError(f"Некорректный JSON: {path}")

def dump_json_atomic(path: Path, data: Any) -> None:
    payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    atomic_write_bytes(path, payload, mode=0o600)

def append_audit(audit_path: Path, record: Dict[str, Any], hmac_key: Optional[bytes]) -> None:
    # Реализуем хэш-цепочку: prev_hash -> HMAC(current_record)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = b""
    if audit_path.exists():
        # Читаем последний валидный HMAC-отпечаток
        with audit_path.open("rb") as f:
            try:
                last = None
                for line in f:
                    last = line
                if last:
                    obj = json.loads(last.decode("utf-8"))
                    prev_hash = base64.b64decode(obj.get("record_hash_b64", "")) if obj.get("record_hash_b64") else b""
            except Exception:
                prev_hash = b""
    wire = json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8")
    chained = prev_hash + wire
    if hmac_key:
        mac = hmac.new(hmac_key, chained, hashlib.sha256).digest()
        rec_hash = mac
        method = "HMAC-SHA256"
    else:
        rec_hash = hashlib.sha256(chained).digest()
        method = "SHA256"
    out = {
        "ts": record.get("ts"),
        "event": record.get("event"),
        "data": record.get("data"),
        "prev_present": bool(prev_hash),
        "hash_method": method,
        "record_hash_b64": base64.b64encode(rec_hash).decode("ascii"),
    }
    with audit_path.open("ab") as f:
        f.write((json.dumps(out, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))

# ==========================
# Логика ротации
# ==========================

@dataclasses.dataclass
class RotateConfig:
    keystore: Path
    name: str
    algo: str = DEFAULT_ALGO
    rsa_bits: int = DEFAULT_RSA_BITS
    ecdsa_curve: str = DEFAULT_ECDSA_CURVE
    age_days: Optional[int] = None
    force: bool = False
    set_current: bool = False
    keep: int = 5
    passphrase: Optional[bytes] = None
    allow_unencrypted: bool = False
    comment: str = ""
    audit_key: Optional[bytes] = None
    dry_run: bool = False
    verbose: bool = False

def key_dirs(base: Path) -> Dict[str, Path]:
    return {
        "private": base / PRIVATE_DIR,
        "public": base / PUBLIC_DIR,
        "pem": base / PEM_DIR,
    }

def current_indicator_path(base: Path) -> Tuple[Path, Path]:
    return base / CURRENT_LINK_NAME, base / CURRENT_FALLBACK_FILE

def find_current_basename(base: Path) -> Optional[str]:
    link, fallback = current_indicator_path(base)
    if link.exists() and link.is_symlink():
        target = os.readlink(str(link))
        return Path(target).name
    if fallback.exists():
        return fallback.read_text(encoding="utf-8").strip()
    return None

def write_current_indicator(base: Path, basename: str) -> None:
    link, fallback = current_indicator_path(base)
    # удаляем старые
    for p in (link, fallback):
        try:
            if p.is_symlink() or p.exists():
                p.unlink()
        except Exception:
            pass
    try:
        os.symlink(basename, str(link))
    except Exception:
        # Fallback, если symlink недоступен (Windows без привилегий)
        atomic_write_bytes(fallback, (basename + "\n").encode("utf-8"), mode=0o600)

def list_key_files(d: Path) -> List[Path]:
    if not d.exists():
        return []
    return sorted([p for p in d.iterdir() if p.is_file()], key=lambda p: p.name)

def parse_ts_from_basename(basename: str) -> Optional[dt.datetime]:
    # Формат: key-<ts>-<alg>....
    try:
        ts = basename.split("-")[1]
        return dt.datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None

def rotation_needed(base: Path, age_days: Optional[int], force: bool) -> bool:
    if force:
        return True
    if age_days is None:
        return True  # Если критерий возраста не задан — ротация по запросу
    cur = find_current_basename(base)
    if not cur:
        return True
    ts = parse_ts_from_basename(cur)
    if not ts:
        return True
    age = (now_utc() - ts).days
    return age >= age_days

def prune_old(keys_dir: Path, keep: int, verbose: bool = False, dry_run: bool = False) -> None:
    files = list_key_files(keys_dir)
    if len(files) <= keep:
        return
    to_delete = files[0 : len(files) - keep]
    for p in to_delete:
        if verbose:
            print(f"[prune] remove {p}")
        if not dry_run:
            try:
                p.unlink()
            except Exception as e:
                print(f"[warn] cannot remove {p}: {e}", file=sys.stderr)

def rotate(cfg: RotateConfig) -> KeyMeta:
    base = cfg.keystore / cfg.name
    # Подготовка директорий
    for d in key_dirs(base).values():
        secure_mkdir(d)
    manifest_path = base / MANIFEST_FILE
    audit_path = base / AUDIT_FILE

    # Проверка необходимости ротации
    if not rotation_needed(base, cfg.age_days, cfg.force):
        raise RotationError("Ротация не требуется по заданным критериям. Используйте --force для принудительной.")

    # Генерация ключей
    priv, pub = generate_keypair(cfg.algo, cfg.rsa_bits, cfg.ecdsa_curve)

    # Сериализация
    if cfg.passphrase:
        priv_bytes = serialize_private_encrypted(priv, cfg.passphrase)
    else:
        if not cfg.allow_unencrypted:
            raise RotationError("Пароль шифрования не задан. Укажите --passphrase-env/--passphrase-file/--prompt или --allow-unencrypted.")
        priv_bytes = serialize_private_unencrypted(priv)

    pub_ssh = serialize_public_openssh(pub, comment=cfg.comment)
    pub_pem = serialize_public_pem(pub)

    # Метаданные и имена
    created = now_utc()
    ts = ts_compact(created)
    basename = f"key-{ts}-{cfg.algo}"
    priv_path = base / PRIVATE_DIR / f"{basename}.pem"
    pub_ssh_path = base / PUBLIC_DIR / f"{basename}.pub"
    pub_pem_path = base / PEM_DIR / f"{basename}.pem.pub"

    fp = fingerprint_ssh_sha256(pub_ssh)

    # Запись атомарно
    if cfg.verbose:
        print(f"[write] {priv_path}")
        print(f"[write] {pub_ssh_path}")
        print(f"[write] {pub_pem_path}")
    if not cfg.dry_run:
        atomic_write_bytes(priv_path, priv_bytes, mode=0o600)
        enforce_permissions(priv_path, 0o600)
        atomic_write_bytes(pub_ssh_path, pub_ssh + b"\n", mode=0o644)
        atomic_write_bytes(pub_pem_path, pub_pem, mode=0o644)

    # Обновление current
    if cfg.set_current:
        if cfg.verbose:
            print(f"[current] -> {basename}")
        if not cfg.dry_run:
            write_current_indicator(base, basename)

    # Очистка старых файлов
    prune_old(base / PRIVATE_DIR, keep=cfg.keep, verbose=cfg.verbose, dry_run=cfg.dry_run)
    prune_old(base / PUBLIC_DIR, keep=cfg.keep, verbose=cfg.verbose, dry_run=cfg.dry_run)
    prune_old(base / PEM_DIR, keep=cfg.keep, verbose=cfg.verbose, dry_run=cfg.dry_run)

    # Обновление манифеста
    entry = {
        "ts": created.isoformat(),
        "name": cfg.name,
        "basename": basename,
        "algorithm": cfg.algo,
        "rsa_bits": cfg.rsa_bits if cfg.algo == "rsa" else None,
        "ecdsa_curve": cfg.ecdsa_curve if cfg.algo == "ecdsa" else None,
        "fingerprint": fp,
        "paths": {
            "private_pem": str(priv_path),
            "public_openssh": str(pub_ssh_path),
            "public_pem": str(pub_pem_path),
        },
        "set_current": bool(cfg.set_current),
        "keep": cfg.keep,
    }

    if not cfg.dry_run:
        manifest = load_json(manifest_path) or {"name": cfg.name, "entries": []}
        manifest.setdefault("entries", []).append(entry)
        dump_json_atomic(manifest_path, manifest)

        # Аудит
        append_audit(
            audit_path,
            record={
                "ts": created.isoformat(),
                "event": "rotate",
                "data": {
                    "name": cfg.name,
                    "basename": basename,
                    "fingerprint": fp,
                    "algorithm": cfg.algo,
                    "set_current": bool(cfg.set_current),
                },
            },
            hmac_key=cfg.audit_key,
        )

    return KeyMeta(
        algorithm=cfg.algo,
        bits=cfg.rsa_bits if cfg.algo == "rsa" else None,
        curve=cfg.ecdsa_curve if cfg.algo == "ecdsa" else None,
        created_at=created.isoformat(),
        fingerprint=fp,
        basename=basename,
    )

# ==========================
# Команды: status, list
# ==========================

def cmd_status(keystore: Path, name: str) -> None:
    base = keystore / name
    manifest_path = base / MANIFEST_FILE
    current = find_current_basename(base)
    manifest = load_json(manifest_path) or {"entries": []}
    print(json.dumps({"name": name, "current": current, "manifest_entries": len(manifest.get("entries", []))}, ensure_ascii=False, indent=2, sort_keys=True))

def cmd_list(keystore: Path, name: str) -> None:
    base = keystore / name
    priv = list_key_files(base / PRIVATE_DIR)
    pub = list_key_files(base / PUBLIC_DIR)
    pem = list_key_files(base / PEM_DIR)
    out = {
        "name": name,
        "private": [p.name for p in priv],
        "public_ssh": [p.name for p in pub],
        "public_pem": [p.name for p in pem],
        "current": find_current_basename(base),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))

# ==========================
# CLI
# ==========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rotate_keys",
        description="Ротация ключей (RSA/ECDSA/Ed25519) с безопасной генерацией и журналированием.",
    )
    sub = p.add_subparsers(dest="cmd")

    # rotate
    r = sub.add_parser("rotate", help="Выполнить ротацию (по умолчанию)")
    add_common_rotate_args(r)

    # status
    s = sub.add_parser("status", help="Показать статус keyset")
    s.add_argument("--keystore", required=True, type=Path, help="Путь к каталогу keystore")
    s.add_argument("--name", required=True, help="Имя keyset")

    # list
    l = sub.add_parser("list", help="Список ключей")
    l.add_argument("--keystore", required=True, type=Path, help="Путь к каталогу keystore")
    l.add_argument("--name", required=True, help="Имя keyset")

    # По умолчанию команда rotate
    p.add_argument("--keystore", type=Path, help=argparse.SUPPRESS)
    p.add_argument("--name", help=argparse.SUPPRESS)
    p.add_argument("--algo", help=argparse.SUPPRESS)
    return p

def add_common_rotate_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--keystore", required=True, type=Path, help="Путь к каталогу keystore")
    ap.add_argument("--name", required=True, help="Имя keyset (подкаталог в keystore)")

    ap.add_argument("--algo", choices=SUPPORTED_ALGOS, default=DEFAULT_ALGO, help="Алгоритм ключа")
    ap.add_argument("--rsa-bits", type=int, default=DEFAULT_RSA_BITS, help="Размер ключа RSA")
    ap.add_argument("--ecdsa-curve", choices=["secp256r1", "secp384r1"], default=DEFAULT_ECDSA_CURVE, help="Кривая ECDSA")

    ap.add_argument("--age-days", type=int, help="Минимальный возраст текущего ключа (в днях) для ротации")
    ap.add_argument("--force", action="store_true", help="Принудительная ротация независимо от возраста")
    ap.add_argument("--set-current", action="store_true", help="Назначить новую пару как текущую")
    ap.add_argument("--keep", type=int, default=5, help="Число версий, которые необходимо хранить")

    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--passphrase-env", help="Имя переменной окружения с паролем шифрования приватного ключа")
    grp.add_argument("--passphrase-file", help="Путь к файлу с паролем шифрования приватного ключа")
    ap.add_argument("--prompt", action="store_true", help="Запросить пароль интерактивно")
    ap.add_argument("--no-confirm", action="store_true", help="Не запрашивать подтверждение пароля (для автоматизации)")
    ap.add_argument("--allow-unencrypted", action="store_true", help="Разрешить незашифрованный приватный ключ (не рекомендуется)")

    ap.add_argument("--comment", default="", help="Комментарий, добавляемый к OpenSSH-ключу")
    ap.add_argument("--audit-key-env", help="Имя переменной окружения с ключом HMAC для аудита")
    ap.add_argument("--dry-run", action="store_true", help="Пробный запуск без записи на диск")
    ap.add_argument("--verbose", action="store_true", help="Подробный вывод")

def parse_args_and_exec(argv: List[str]) -> int:
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)

    # Сахар: если команда не указана, считаем rotate
    cmd = args.cmd or ("rotate" if args.keystore or args.name else None)

    if cmd == "status":
        cmd_status(args.keystore, args.name)
        return 0
    if cmd == "list":
        cmd_list(args.keystore, args.name)
        return 0
    if cmd == "rotate":
        # Собираем параметры ротации
        passphrase = load_passphrase(
            env=getattr(args, "passphrase_env", None),
            file=getattr(args, "passphrase_file", None),
            prompt=getattr(args, "prompt", False),
            confirm=not getattr(args, "no_confirm", False),
        )
        audit_key_env = getattr(args, "audit_key_env", None)
        audit_key = os.getenv(audit_key_env).encode("utf-8") if audit_key_env and os.getenv(audit_key_env) else None

        cfg = RotateConfig(
            keystore=args.keystore,
            name=args.name,
            algo=args.algo,
            rsa_bits=args.rsa_bits,
            ecdsa_curve=args.ecdsa_curve,
            age_days=args.age_days,
            force=args.force,
            set_current=args.set_current,
            keep=args.keep,
            passphrase=passphrase,
            allow_unencrypted=args.allow_unencrypted,
            comment=args.comment,
            audit_key=audit_key,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )
        try:
            meta = rotate(cfg)
            # Краткий вывод JSON для автоматизации
            print(json.dumps(dataclasses.asdict(meta), ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        except RotationError as re:
            print(f"[error] {re}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print("[abort] Interrupted", file=sys.stderr)
            return 130
        except Exception as e:
            print(f"[fatal] {e}", file=sys.stderr)
            return 1

    parser.print_help()
    return 0

def main() -> None:
    sys.exit(parse_args_and_exec(sys.argv[1:]))

if __name__ == "__main__":
    main()

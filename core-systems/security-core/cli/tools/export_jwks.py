# security-core/cli/tools/export_jwks.py
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
from dataclasses import dataclass
from hashlib import sha1, sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519

# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------
log = logging.getLogger("security_core.cli.export_jwks")
if not log.handlers:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    log.addHandler(h)
log.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Утилиты base64url / числа
# -----------------------------------------------------------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_int(n: int) -> str:
    if n == 0:
        return b64u(b"\x00")
    # big-endian без знака
    blen = (n.bit_length() + 7) // 8
    return b64u(n.to_bytes(blen, "big"))

def der_spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def kid_from_spki(public_key) -> str:
    return b64u(sha256(der_spki(public_key)).digest())

# EC curve name mapping -> JOSE "crv"
_EC_CRV: Dict[str, str] = {
    "secp256r1": "P-256",
    "prime256v1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}

# -----------------------------------------------------------------------------
# Входные сущности
# -----------------------------------------------------------------------------
@dataclass
class LoadedKey:
    kind: str  # "RSA" | "EC" | "OKP"
    public_key: Any
    private: bool  # True если из приватного ключа (для проверки, приватные параметры не экспортируем)
    source: str    # путь файла или пометка
    alg_hint: Optional[str] = None
    use: str = "sig"  # sig|enc (по умолчанию подпись)
    key_ops: List[str] = None  # по умолчанию только verify для публичного JWKS
    kid: Optional[str] = None  # если задан пользователем
    # Связанные сертификаты (leaf-first chain)
    x5c: List[str] = None
    x5t: Optional[str] = None
    x5tS256: Optional[str] = None

    def __post_init__(self):
        if self.key_ops is None:
            self.key_ops = ["verify"]

@dataclass
class LoadedCert:
    cert: x509.Certificate
    der_b64: str  # DER в base64 (не urlsafe)
    pub_der: bytes
    pub_fingerprint: bytes  # SHA-256 от SPKI для сопоставления

# -----------------------------------------------------------------------------
# Загрузка PEM/CRT
# -----------------------------------------------------------------------------
def load_pem_or_cert(path: Path, passphrase: Optional[bytes]) -> List[Union[LoadedKey, LoadedCert]]:
    """
    Возвращает список LoadedKey/LoadedCert, найденных в файле.
    Поддерживает объединённые PEM (несколько объектов).
    """
    out: List[Union[LoadedKey, LoadedCert]] = []
    data = path.read_bytes()
    # Попытка как приватный ключ
    try:
        priv = serialization.load_pem_private_key(data, password=passphrase)
        pub = priv.public_key()
        kind = "RSA" if isinstance(pub, rsa.RSAPublicKey) else "EC" if isinstance(pub, ec.EllipticCurvePublicKey) else "OKP" if isinstance(pub, ed25519.Ed25519PublicKey) else None
        if kind:
            out.append(LoadedKey(kind=kind, public_key=pub, private=True, source=str(path)))
            # продолжаем — файл может содержать и сертификаты
    except Exception:
        pass

    # Попытка как публичный ключ
    try:
        pub = serialization.load_pem_public_key(data)
        kind = "RSA" if isinstance(pub, rsa.RSAPublicKey) else "EC" if isinstance(pub, ec.EllipticCurvePublicKey) else "OKP" if isinstance(pub, ed25519.Ed25519PublicKey) else None
        if kind:
            out.append(LoadedKey(kind=kind, public_key=pub, private=False, source=str(path)))
    except Exception:
        pass

    # Попытка как сертификат(ы)
    # В файле может быть несколько PEM сертификатов подряд
    def _split_pem_blocks(raw: bytes) -> List[bytes]:
        blocks: List[bytes] = []
        start = 0
        while True:
            s = raw.find(b"-----BEGIN CERTIFICATE-----", start)
            if s == -1:
                break
            e = raw.find(b"-----END CERTIFICATE-----", s)
            if e == -1:
                break
            e += len(b"-----END CERTIFICATE-----")
            blocks.append(raw[s:e])
            start = e
        return blocks

    blocks = _split_pem_blocks(data)
    for b in blocks:
        try:
            c = x509.load_pem_x509_certificate(b)
            der = c.public_bytes(serialization.Encoding.DER)
            pub_der = der_spki(c.public_key())
            out.append(
                LoadedCert(
                    cert=c,
                    der_b64=base64.b64encode(der).decode("ascii"),
                    pub_der=pub_der,
                    pub_fingerprint=sha256(pub_der).digest(),
                )
            )
        except Exception:
            pass

    # Попытка как DER сертификат, если PEM не обнаружен
    if not blocks:
        try:
            c = x509.load_der_x509_certificate(data)
            der = c.public_bytes(serialization.Encoding.DER)
            pub_der = der_spki(c.public_key())
            out.append(
                LoadedCert(
                    cert=c,
                    der_b64=base64.b64encode(der).decode("ascii"),
                    pub_der=pub_der,
                    pub_fingerprint=sha256(pub_der).digest(),
                )
            )
        except Exception:
            pass

    if not out:
        log.warning("Ничего не распознано в файле: %s", path)
    return out

def scan_dir_for_inputs(d: Path) -> List[Path]:
    exts = {".pem", ".crt", ".cer", ".der", ".key", ".pub"}
    return [p for p in d.rglob("*") if p.is_file() and p.suffix.lower() in exts]

# -----------------------------------------------------------------------------
# Соответствие сертификатов ключам
# -----------------------------------------------------------------------------
def match_certs_to_keys(keys: List[LoadedKey], certs: List[LoadedCert], include_chain: bool) -> None:
    """
    Для каждого ключа ищем соответствующий сертификат(ы) по SHA-256 от SPKI.
    Если найден, добавляем x5c (leaf-first), x5t/x5t#S256.
    """
    # Группируем по SPKI fingerprint
    certs_by_fp: Dict[bytes, List[LoadedCert]] = {}
    for lc in certs:
        certs_by_fp.setdefault(lc.pub_fingerprint, []).append(lc)

    # Строим простые цепочки leaf-first (если в списке присутствуют и leaf, и issuer)
    # Упрощённо: упорядочим по NotAfter (возрастающей), что часто даёт leaf->issuer
    for fp, lst in certs_by_fp.items():
        certs_by_fp[fp] = sorted(lst, key=lambda c: c.cert.not_valid_after)

    # Назначение x5c по совпадению SPKI
    for k in keys:
        fp = sha256(der_spki(k.public_key)).digest()
        if fp in certs_by_fp:
            chain = certs_by_fp[fp]
            leaf = chain[0]
            x5t = b64u(sha1(leaf.cert.tbs_certificate_bytes).digest())
            x5tS256 = b64u(sha256(leaf.cert.tbs_certificate_bytes).digest())
            k.x5t = x5t
            k.x5tS256 = x5tS256
            if include_chain:
                k.x5c = [c.der_b64 for c in chain]
            else:
                k.x5c = [leaf.der_b64]

# -----------------------------------------------------------------------------
# Преобразование ключей в JWK
# -----------------------------------------------------------------------------
def jwk_from_loaded_key(k: LoadedKey, kid_strategy: str, alg: Optional[str], use: str, key_ops: List[str]) -> Dict[str, Any]:
    pub = k.public_key
    jwk: Dict[str, Any] = {}
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": b64u_int(nums.n),
            "e": b64u_int(nums.e),
        }
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        x = nums.x.to_bytes(size, "big")
        y = nums.y.to_bytes(size, "big")
        crv = _EC_CRV.get(getattr(pub.curve, "name", "").lower())
        if not crv:
            raise ValueError(f"Неизвестная кривая EC: {getattr(pub.curve, 'name', '')}")
        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": b64u(x),
            "y": b64u(y),
        }
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64u(raw),
        }
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {type(pub)}")

    # kid
    if k.kid:
        jwk["kid"] = k.kid
    else:
        if kid_strategy == "spki":
            jwk["kid"] = kid_from_spki(pub)
        elif kid_strategy == "x5tS256" and k.x5tS256:
            jwk["kid"] = k.x5tS256
        elif kid_strategy == "none":
            pass
        elif kid_strategy == "filename":
            jwk["kid"] = Path(k.source).stem
        else:
            jwk["kid"] = kid_from_spki(pub)

    # alg/use/key_ops
    if alg:
        jwk["alg"] = alg
    if use:
        jwk["use"] = use
    if key_ops:
        jwk["key_ops"] = key_ops

    # сертификатная информация
    if k.x5c:
        jwk["x5c"] = k.x5c
    if k.x5t:
        jwk["x5t"] = k.x5t
    if k.x5tS256:
        jwk["x5t#S256"] = k.x5tS256

    return jwk

# -----------------------------------------------------------------------------
# Основная функция CLI
# -----------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="export_jwks",
        description="Экспорт публичного JWKS из PEM ключей и/или X.509 сертификатов.",
    )
    p.add_argument("-k", "--key", action="append", default=[], help="Путь к PEM файлу (private/public key). Можно несколько.")
    p.add_argument("-c", "--cert", action="append", default=[], help="Путь к PEM/DER сертификату. Можно несколько.")
    p.add_argument("-d", "--dir", action="append", default=[], help="Каталог для сканирования ключей/сертификатов (рекурсивно).")
    p.add_argument("--include-chain", action="store_true", help="Включать x5c как цепочку (leaf-first), если доступны сертификаты.")
    p.add_argument("--alg", choices=["RS256","RS512","PS256","PS512","ES256","ES384","ES512","EdDSA"], help="Установить общий alg для всех JWK (по умолчанию не указывать).")
    p.add_argument("--use", choices=["sig","enc"], default="sig", help="Поле 'use' в JWK (по умолчанию sig).")
    p.add_argument("--key-ops", default=None, help="Список операций через запятую (например, verify,encrypt). По умолчанию только verify.")
    p.add_argument("--kid-strategy", choices=["spki","x5tS256","filename","none"], default="spki", help="Стратегия вычисления 'kid' (по умолчанию spki).")
    p.add_argument("--set-kid", default=None, help="Принудительно установить одинаковый kid для всех ключей (не рекомендуется).")
    p.add_argument("--passphrase", default=None, help="Пароль для приватных ключей (строка/окружение).")
    p.add_argument("--out", "-o", default="-", help="Путь для JWKS (или '-' для stdout).")
    p.add_argument("--pretty", action="store_true", help="Красивое форматирование JSON.")
    p.add_argument("--sort", action="store_true", help="Отсортировать ключи по kid.")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Уровень подробности логов (-v, -vv).")
    return p

def configure_logging(verbosity: int) -> None:
    if verbosity >= 2:
        log.setLevel(logging.DEBUG)
    elif verbosity == 1:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.WARNING)

def collect_inputs(args: argparse.Namespace) -> Tuple[List[LoadedKey], List[LoadedCert]]:
    # Соберем пути
    paths: List[Path] = []
    for k in args.key:
        paths.append(Path(k))
    for c in args.cert:
        paths.append(Path(c))
    for d in args.dir:
        paths.extend(scan_dir_for_inputs(Path(d)))

    if not paths:
        log.error("Не указаны входные файлы/каталоги. Используйте --key/--cert/--dir.")
        sys.exit(2)

    passphrase_bytes: Optional[bytes] = None
    if args.passphrase:
        # Разрешаем ссылку на переменную окружения: pass:ENV:NAME
        if args.passphrase.startswith("env:"):
            env_name = args.passphrase.split("env:", 1)[1]
            passphrase_bytes = os.getenv(env_name, "").encode()
        else:
            passphrase_bytes = args.passphrase.encode()

    loaded_keys: List[LoadedKey] = []
    loaded_certs: List[LoadedCert] = []

    for p in paths:
        if not p.exists() or not p.is_file():
            log.debug("Пропуск: %s (не файл)", p)
            continue
        try:
            items = load_pem_or_cert(p, passphrase_bytes)
            for it in items:
                if isinstance(it, LoadedKey):
                    loaded_keys.append(it)
                elif isinstance(it, LoadedCert):
                    loaded_certs.append(it)
        except Exception as e:
            log.warning("Не удалось обработать %s: %s", p, e)

    if not loaded_keys and not loaded_certs:
        log.error("Не найдено ключей или сертификатов в указанных путях.")
        sys.exit(3)

    return loaded_keys, loaded_certs

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    keys, certs = collect_inputs(args)

    # Если ключей нет, но есть сертификаты — экспортируем JWK из сертификатов
    if not keys and certs:
        log.info("Ключи не найдены, экспортируем JWK из сертификатов (по публичным ключам).")
        for lc in certs:
            pub = lc.cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                kind = "RSA"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                kind = "EC"
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                kind = "OKP"
            else:
                log.warning("Сертификат с неподдерживаемым публичным ключом пропущен: %s", lc.cert.subject.rfc4514_string())
                continue
            lk = LoadedKey(kind=kind, public_key=pub, private=False, source="cert:" + lc.cert.subject.rfc4514_string())
            # Привяжем cert как leaf
            lk.x5c = [lc.der_b64]
            lk.x5t = b64u(sha1(lc.cert.tbs_certificate_bytes).digest())
            lk.x5tS256 = b64u(sha256(lc.cert.tbs_certificate_bytes).digest())
            keys.append(lk)

    # Сопоставим сертификаты с ключами (добавим x5c/x5t)
    if certs and keys:
        match_certs_to_keys(keys, certs, include_chain=args.include_chain)

    # Применим глобальные опции
    if args.set_kid:
        for k in keys:
            k.kid = args.set_kid

    # Сформируем JWKs
    jwks: Dict[str, Any] = {"keys": []}
    key_ops_list: Optional[List[str]] = None
    if args.key_ops:
        key_ops_list = [x.strip() for x in args.key_ops.split(",") if x.strip()]

    for k in keys:
        try:
            jwk = jwk_from_loaded_key(
                k=k,
                kid_strategy=args.kid_strategy,
                alg=args.alg,
                use=args.use,
                key_ops=key_ops_list or ["verify"],
            )
            jwks["keys"].append(jwk)
        except Exception as e:
            log.warning("Пропущен ключ из %s: %s", k.source, e)

    if not jwks["keys"]:
        log.error("Не удалось сформировать ни одного JWK.")
        return 4

    # Сортировка по kid для стабильности
    if args.sort:
        jwks["keys"].sort(key=lambda j: j.get("kid", ""))

    # Вывод
    data = json.dumps(jwks, ensure_ascii=False, indent=2 if args.pretty else None, separators=(",", ":") if not args.pretty else None)
    if args.out == "-" or args.out == "/dev/stdout":
        sys.stdout.write(data + ("\n" if not data.endswith("\n") else ""))
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(data, encoding="utf-8")
        log.info("JWKS записан в %s", out_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())

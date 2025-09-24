# ledger-core/ledger/adapters/kms/local_hsm.py
from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

# --- криптография ---
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
        load_pem_private_key,
        load_pem_public_key,
    )
    _HAS_CRYPTO = True
except Exception as e:  # pragma: no cover
    _HAS_CRYPTO = False
    _IMPORT_ERROR = e

# --- простая кроссплатформенная файловая блокировка без внешних зависимостей ---
if os.name == "nt":  # pragma: no cover - упрощённо
    import msvcrt

    class _Flock:
        def __init__(self, path: Path) -> None:
            self._path = path
            self._fh = None

        def __enter__(self):
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self._path, "a+b")
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
            return self

        def __exit__(self, exc_type, exc, tb):
            try:
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                self._fh.close()
else:
    import fcntl

    class _Flock:
        def __init__(self, path: Path) -> None:
            self._path = path
            self._fh = None

        def __enter__(self):
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self._path, "a+b")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
            return self

        def __exit__(self, exc_type, exc, tb):
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()


# ====================== Доменные типы и вспомогательные ======================

class KeyAlgorithm(str, Enum):
    ED25519 = "ED25519"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_SECP256K1 = "ECDSA_SECP256K1"


class HashAlgorithm(str, Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"


class KeyOperation(str, Enum):
    SIGN = "sign"


@dataclass(frozen=True)
class KeyPolicy:
    allowed_ops: Tuple[KeyOperation, ...] = (KeyOperation.SIGN,)
    allowed_hashes: Tuple[HashAlgorithm, ...] = (HashAlgorithm.SHA256,)
    allowed_scopes: Tuple[str, ...] = tuple()  # произвольные ярлыки доступа (например, "payments", "audit")
    usage_limit: Optional[int] = None          # максимум подписей на версию; None = без лимита
    not_before_utc: Optional[str] = None
    not_after_utc: Optional[str] = None


@dataclass
class KeyVersionMeta:
    version: int
    created_at_utc: str
    usage_count: int = 0
    disabled: bool = False


@dataclass
class KeyRecord:
    key_id: str
    algorithm: KeyAlgorithm
    active_version: int
    created_at_utc: str
    label: Optional[str] = None
    policy: KeyPolicy = field(default_factory=KeyPolicy)
    versions: Dict[int, KeyVersionMeta] = field(default_factory=dict)


# ====================== Исключения ======================

class HSMError(Exception):
    pass


class CryptoUnavailableError(HSMError):
    pass


class PolicyViolation(HSMError):
    pass


class KeyNotFound(HSMError):
    pass


class VersionNotFound(HSMError):
    pass


# ====================== Утилиты кодирования/времени ======================

def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def _derive_master_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)  # сильные, но разумные параметры
    return kdf.derive(passphrase.encode("utf-8"))


# ====================== Шифрование приватных ключей ======================

def _seal(plaintext: bytes, master_key: bytes, aad: bytes) -> Dict[str, str]:
    """
    AES‑GCM( master_key, nonce, plaintext, aad ) -> {nonce, ct}
    master_key должен быть 32 байта.
    """
    if len(master_key) != 32:
        raise HSMError("master_key must be 32 bytes")
    nonce = _random_bytes(12)
    aead = AESGCM(master_key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return {"nonce_b64": _b64e(nonce), "ct_b64": _b64e(ct)}


def _unseal(blob: Dict[str, str], master_key: bytes, aad: bytes) -> bytes:
    if len(master_key) != 32:
        raise HSMError("master_key must be 32 bytes")
    nonce = _b64d(blob["nonce_b64"])
    ct = _b64d(blob["ct_b64"])
    aead = AESGCM(master_key)
    return aead.decrypt(nonce, ct, aad)


# ====================== Класс LocalHSM ======================

class LocalHSM:
    """
    Локальный HSM/KMS‑адаптер с файловым хранилищем и шифрованием ключей.

    Структура на диске:
      root/
        .lock
        index.json                             — метаданные ключей (KeyRecord без приватных частей)
        keys/<key_id>/meta.json                — запись KeyRecord (дублирование для устойчивости)
        keys/<key_id>/v<version>.bin           — зашифрованный PKCS#8 DER приватный ключ
        keys/<key_id>/pub.pem                  — публичный ключ (SPKI PEM, активной версии)
        backups/*.tar                          — при бэкапах

    Мастер‑ключ:
      - передаётся как bytes (32 байта) или
      - берётся из env HSM_MASTER_KEY_B64 (base64 32 байт) или
      - выводится из пароля (scrypt), если передан passphrase.
    """

    def __init__(
        self,
        root_dir: str | Path,
        *,
        master_key: Optional[bytes] = None,
        passphrase: Optional[str] = None,
        policy_default: Optional[KeyPolicy] = None,
        create_if_missing: bool = True,
        require_scopes: bool = False,
    ) -> None:
        if not _HAS_CRYPTO:
            raise CryptoUnavailableError(f"cryptography is not available: {_IMPORT_ERROR}")
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True) if create_if_missing else None
        self._lock_path = self.root / ".lock"
        self._keys_dir = self.root / "keys"
        self._keys_dir.mkdir(parents=True, exist_ok=True) if create_if_missing else None
        self._index_path = self.root / "index.json"
        self._require_scopes = require_scopes

        if master_key is None and passphrase is None:
            env_b64 = os.getenv("HSM_MASTER_KEY_B64")
            if env_b64:
                mk = base64.b64decode(env_b64.encode("ascii"))
                master_key = mk
        if master_key is None and passphrase is not None:
            # соль хранится в корне
            salt_path = self.root / ".salt"
            if not salt_path.exists():
                salt = _random_bytes(16)
                salt_path.write_bytes(salt)
            else:
                salt = salt_path.read_bytes()
            master_key = _derive_master_key_from_passphrase(passphrase, salt)
        if master_key is None:
            # новый мастер‑ключ — только если пустой каталог (иначе потеряем доступ)
            if any(self._keys_dir.iterdir()):
                raise HSMError("master_key is required to access existing keystore")
            master_key = _random_bytes(32)
            os.environ["HSM_MASTER_KEY_B64"] = _b64e(master_key)  # удобный способ «вывести» ключ наверх

        if len(master_key) != 32:
            raise HSMError("master_key must be 32 bytes")
        self._mk = master_key

        # индекс
        self._index: Dict[str, KeyRecord] = {}
        self._load_index()

    # ---------------------- публичный API ----------------------

    def health(self) -> bool:
        try:
            self.root.exists() and self._keys_dir.exists()
            # проверка блокировки файла
            with _Flock(self._lock_path):
                pass
            return True
        except Exception:
            return False

    def list_keys(self) -> List[KeyRecord]:
        return list(self._index.values())

    def get_key(self, key_id: str) -> KeyRecord:
        try:
            return self._index[key_id]
        except KeyError:
            raise KeyNotFound(key_id)

    def get_public_key_pem(self, key_id: str, version: Optional[int] = None) -> bytes:
        rec = self.get_key(key_id)
        ver = version or rec.active_version
        pub_path = self._key_dir(key_id) / "pub.pem"
        if pub_path.exists() and ver == rec.active_version:
            return pub_path.read_bytes()
        # иначе — получить из приватного и перезаписать
        priv = self._load_private_key(key_id, ver)
        pub = priv.public_key()
        pem = pub.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        if ver == rec.active_version:
            pub_path.write_bytes(pem)
        return pem

    def create_key(
        self,
        *,
        algorithm: KeyAlgorithm,
        label: Optional[str] = None,
        policy: Optional[KeyPolicy] = None,
        scopes: Optional[Iterable[str]] = None,
    ) -> KeyRecord:
        """
        Создаёт key с первой версией v1, ставит active_version=1.
        scopes — необязательный набор ярлыков доступа, которые попадут в policy.allowed_scopes,
        если включён режим require_scopes.
        """
        key_id = self._gen_key_id(algorithm)
        rec = KeyRecord(
            key_id=key_id,
            algorithm=algorithm,
            active_version=1,
            created_at_utc=_utc_now(),
            label=label,
            policy=policy or (KeyPolicy(allowed_scopes=tuple(scopes or ())) if self._require_scopes else KeyPolicy()),
            versions={},
        )
        self._persist_new_version(rec, version=1)
        self._index[rec.key_id] = rec
        self._save_index()
        return rec

    def rotate_key(self, key_id: str) -> KeyRecord:
        rec = self.get_key(key_id)
        new_ver = max(rec.versions) + 1 if rec.versions else 1
        self._persist_new_version(rec, version=new_ver)
        rec.active_version = new_ver
        self._save_record(rec)
        self._save_index()
        return rec

    def disable_version(self, key_id: str, version: int, disabled: bool = True) -> KeyRecord:
        rec = self.get_key(key_id)
        try:
            rec.versions[version].disabled = disabled
        except KeyError:
            raise VersionNotFound(f"{key_id}:v{version}")
        self._save_record(rec)
        self._save_index()
        return rec

    def sign_digest(
        self,
        *,
        key_id: str,
        digest: bytes,
        hash_alg: HashAlgorithm,
        require_scope: Optional[str] = None,
        version: Optional[int] = None,
    ) -> bytes:
        """
        Подписывает уже вычисленный digest по активной или указанной версии ключа.
        Политики: allowed_ops, allowed_hashes, usage_limit, allowed_scopes.
        """
        rec = self.get_key(key_id)
        ver = version or rec.active_version
        meta = rec.versions.get(ver)
        if not meta:
            raise VersionNotFound(f"{key_id}:v{ver}")
        if meta.disabled:
            raise PolicyViolation("version is disabled")
        pol = rec.policy
        if KeyOperation.SIGN not in pol.allowed_ops:
            raise PolicyViolation("operation not allowed")
        if hash_alg not in pol.allowed_hashes:
            raise PolicyViolation("hash not allowed")
        if self._require_scopes and pol.allowed_scopes and require_scope and require_scope not in pol.allowed_scopes:
            raise PolicyViolation("scope not allowed")
        if pol.usage_limit is not None and meta.usage_count >= pol.usage_limit:
            raise PolicyViolation("usage limit exceeded")

        priv = self._load_private_key(rec.key_id, ver)

        if rec.algorithm == KeyAlgorithm.ED25519:
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                raise HSMError("key is not Ed25519")
            signature = priv.sign(digest)  # Ed25519: подписываем digest как сообщение
        elif rec.algorithm in (KeyAlgorithm.ECDSA_P256, KeyAlgorithm.ECDSA_SECP256K1):
            if not isinstance(priv, ec.EllipticCurvePrivateKey):
                raise HSMError("key is not ECDSA")
            if hash_alg == HashAlgorithm.SHA256:
                chosen = hashes.SHA256()
            elif hash_alg == HashAlgorithm.SHA512:
                chosen = hashes.SHA512()
            else:
                raise PolicyViolation("unsupported hash for ECDSA")
            signature = priv.sign(digest, ec.ECDSA(chosen))  # DER подпись
        else:
            raise HSMError(f"unsupported algorithm: {rec.algorithm}")

        meta.usage_count += 1
        self._save_record(rec)
        return signature

    def import_private_key(
        self,
        *,
        key_id: str,
        private_key_pem: bytes,
        algorithm: Optional[KeyAlgorithm] = None,
        set_active: bool = True,
    ) -> KeyRecord:
        """
        Импортирует приватный ключ как новую версию. Определяет алгоритм по ключу, если не задан.
        """
        rec = self.get_key(key_id)
        ver = max(rec.versions) + 1 if rec.versions else 1
        priv = load_pem_private_key(private_key_pem, password=None)
        algo = algorithm or self._detect_algorithm(priv)
        if algo != rec.algorithm:
            raise HSMError(f"algorithm mismatch: expected {rec.algorithm}, got {algo}")
        self._store_private_key(rec.key_id, ver, priv)
        rec.versions[ver] = KeyVersionMeta(version=ver, created_at_utc=_utc_now())
        if set_active:
            rec.active_version = ver
        self._save_record(rec)
        self._save_index()
        return rec

    def backup(self, out_path: str | Path) -> Path:
        """
        Делает криптоназависимый бэкап каталога keys и index.json в один файл .hbk.
        Файл просто tar‑подобный JSON‑контейнер; приватные части уже зашифрованы AES‑GCM.
        """
        out = Path(out_path)
        snapshot = {
            "created_at_utc": _utc_now(),
            "index": [self._record_to_json(r) for r in self._index.values()],
            "files": {},
        }
        for p in self._keys_dir.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(self.root))
                snapshot["files"][rel] = _b64e(p.read_bytes())
        out.write_text(json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
        return out

    def restore(self, backup_path: str | Path) -> None:
        """
        Восстанавливает из backup() поверх текущего каталога (idempotent по файлам).
        """
        data = json.loads(Path(backup_path).read_text())
        for rel, b64 in data.get("files", {}).items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():
                p.write_bytes(_b64d(b64))
        # перезагрузим индекс
        self._load_index()

    # ---------------------- внутренние методы ----------------------

    def _gen_key_id(self, alg: KeyAlgorithm) -> str:
        # Формат: loc-hsm:{ALG}:{12h-рандом}
        rnd = binascii.hexlify(secrets.token_bytes(6)).decode("ascii")
        return f"loc-hsm:{alg.value}:{rnd}"

    def _key_dir(self, key_id: str) -> Path:
        return self._keys_dir / key_id.replace(":", "_")

    def _detect_algorithm(self, priv) -> KeyAlgorithm:
        if isinstance(priv, ed25519.Ed25519PrivateKey):
            return KeyAlgorithm.ED25519
        if isinstance(priv, ec.EllipticCurvePrivateKey):
            if isinstance(priv.curve, ec.SECP256R1):
                return KeyAlgorithm.ECDSA_P256
            if isinstance(priv.curve, ec.SECP256K1):
                return KeyAlgorithm.ECDSA_SECP256K1
        raise HSMError("unsupported private key type")

    def _persist_new_version(self, rec: KeyRecord, version: int) -> None:
        # генерируем приватный ключ
        if rec.algorithm == KeyAlgorithm.ED25519:
            priv = ed25519.Ed25519PrivateKey.generate()
        elif rec.algorithm == KeyAlgorithm.ECDSA_P256:
            priv = ec.generate_private_key(ec.SECP256R1())
        elif rec.algorithm == KeyAlgorithm.ECDSA_SECP256K1:
            priv = ec.generate_private_key(ec.SECP256K1())
        else:  # pragma: no cover
            raise HSMError("unsupported algorithm")
        # сохраняем
        self._store_private_key(rec.key_id, version, priv)
        rec.versions[version] = KeyVersionMeta(version=version, created_at_utc=_utc_now())
        rec.active_version = version
        self._save_record(rec)

    def _store_private_key(self, key_id: str, version: int, priv) -> None:
        kdir = self._key_dir(key_id)
        kdir.mkdir(parents=True, exist_ok=True)
        # публичный сразу обновим для активной версии позднее
        # сериализация приватного в PKCS#8 DER
        der = priv.private_bytes(encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        aad = f"{key_id}|v{version}".encode("utf-8")
        sealed = _seal(der, self._mk, aad)
        # сохраняем файл версии
        (kdir / f"v{version}.bin").write_text(json.dumps(sealed, separators=(",", ":"), sort_keys=True))
        # при необходимости обновим pub.pem (активная версия меняется снаружи)
        pub = priv.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        (kdir / "pub.pem").write_bytes(pub)

    def _load_private_key(self, key_id: str, version: int):
        path = self._key_dir(key_id) / f"v{version}.bin"
        if not path.exists():
            raise VersionNotFound(f"{key_id}:v{version}")
        sealed = json.loads(path.read_text())
        aad = f"{key_id}|v{version}".encode("utf-8")
        der = _unseal(sealed, self._mk, aad)
        return serialization.load_der_private_key(der, password=None)

    # -------- индекс/метаданные --------

    def _record_to_json(self, rec: KeyRecord) -> Dict[str, Any]:
        j = {
            "key_id": rec.key_id,
            "algorithm": rec.algorithm.value,
            "active_version": rec.active_version,
            "created_at_utc": rec.created_at_utc,
            "label": rec.label,
            "policy": {
                "allowed_ops": [op.value for op in rec.policy.allowed_ops],
                "allowed_hashes": [h.value for h in rec.policy.allowed_hashes],
                "allowed_scopes": list(rec.policy.allowed_scopes),
                "usage_limit": rec.policy.usage_limit,
                "not_before_utc": rec.policy.not_before_utc,
                "not_after_utc": rec.policy.not_after_utc,
            },
            "versions": {str(v): asdict(meta) for v, meta in rec.versions.items()},
        }
        return j

    def _record_from_json(self, j: Dict[str, Any]) -> KeyRecord:
        policy = j.get("policy", {})
        rec = KeyRecord(
            key_id=j["key_id"],
            algorithm=KeyAlgorithm(j["algorithm"]),
            active_version=int(j["active_version"]),
            created_at_utc=j["created_at_utc"],
            label=j.get("label"),
            policy=KeyPolicy(
                allowed_ops=tuple(KeyOperation(x) for x in policy.get("allowed_ops", ["sign"])),
                allowed_hashes=tuple(HashAlgorithm(x) for x in policy.get("allowed_hashes", ["SHA256"])),
                allowed_scopes=tuple(policy.get("allowed_scopes", [])),
                usage_limit=policy.get("usage_limit"),
                not_before_utc=policy.get("not_before_utc"),
                not_after_utc=policy.get("not_after_utc"),
            ),
            versions={},
        )
        vers = {}
        for k, meta in j.get("versions", {}).items():
            m = KeyVersionMeta(
                version=int(meta["version"]),
                created_at_utc=meta["created_at_utc"],
                usage_count=int(meta.get("usage_count", 0)),
                disabled=bool(meta.get("disabled", False)),
            )
            vers[m.version] = m
        rec.versions = vers
        return rec

    def _save_record(self, rec: KeyRecord) -> None:
        kdir = self._key_dir(rec.key_id)
        kdir.mkdir(parents=True, exist_ok=True)
        (kdir / "meta.json").write_text(json.dumps(self._record_to_json(rec), separators=(",", ":"), sort_keys=True))

    def _load_record(self, key_id: str) -> KeyRecord:
        meta_path = self._key_dir(key_id) / "meta.json"
        if not meta_path.exists():
            raise KeyNotFound(key_id)
        j = json.loads(meta_path.read_text())
        return self._record_from_json(j)

    def _save_index(self) -> None:
        with _Flock(self._lock_path):
            self._index_path.write_text(
                json.dumps([self._record_to_json(r) for r in self._index.values()], separators=(",", ":"), sort_keys=True)
            )

    def _load_index(self) -> None:
        with _Flock(self._lock_path):
            if self._index_path.exists():
                try:
                    arr = json.loads(self._index_path.read_text())
                except Exception:
                    arr = []
            else:
                # Попробуем собрать из каталога keys (восстановление после аварии)
                arr = []
                for meta in self._keys_dir.rglob("meta.json"):
                    try:
                        arr.append(json.loads(meta.read_text()))
                    except Exception:
                        continue
            recs = {}
            for j in arr:
                try:
                    rec = self._record_from_json(j)
                    recs[rec.key_id] = rec
                except Exception:
                    continue
            self._index = recs


# ====================== Пример использования (doctest‑подобно) ======================

if __name__ == "__main__":  # pragma: no cover
    if not _HAS_CRYPTO:
        print("cryptography not installed", file=sys.stderr)
        sys.exit(2)

    hsm = LocalHSM("./.hsm_dev", passphrase="changeit", create_if_missing=True, require_scopes=True)
    if not hsm.list_keys():
        r = hsm.create_key(algorithm=KeyAlgorithm.ED25519, label="payments-signing", scopes=["payments"])
        print("created", r.key_id)
    rec = hsm.list_keys()[0]
    pub = hsm.get_public_key_pem(rec.key_id)
    print("public:\n", pub.decode())

    digest = b"\x00" * 32  # пример; обычно это SHA‑256(payload)
    sig = hsm.sign_digest(key_id=rec.key_id, digest=digest, hash_alg=HashAlgorithm.SHA256, require_scope="payments")
    print("signature b64:", base64.b64encode(sig).decode())

    # ротация
    rec = hsm.rotate_key(rec.key_id)
    print("rotated to v", rec.active_version)

    # бэкап/рестор
    bk = hsm.backup("./.hsm_dev/backup.hbk")
    print("backup ->", bk)

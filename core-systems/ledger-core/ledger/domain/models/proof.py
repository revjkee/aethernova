# ledger-core/ledger/domain/models/proof.py
from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Опциональные зависимости для криптографии
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.exceptions import InvalidSignature
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


# =============== УТИЛИТЫ ХЕШИРОВАНИЯ/СЕРИАЛИЗАЦИИ ===================

class HashAlgorithm(str, Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    BLAKE2B_256 = "BLAKE2B_256"
    BLAKE2B_512 = "BLAKE2B_512"


def _digest(data: bytes, alg: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    if alg == HashAlgorithm.SHA256:
        return hashlib.sha256(data).digest()
    if alg == HashAlgorithm.SHA512:
        return hashlib.sha512(data).digest()
    if alg == HashAlgorithm.BLAKE2B_256:
        return hashlib.blake2b(data, digest_size=32).digest()
    if alg == HashAlgorithm.BLAKE2B_512:
        return hashlib.blake2b(data, digest_size=64).digest()
    raise ValueError(f"Unsupported hash algorithm: {alg}")


def _canonical_json(obj: Any) -> bytes:
    """
    Каноничная сериализация JSON для детерминированного хеша/подписи.
    - сортировка ключей
    - отсутствие пробелов
    - запрет NaN/Infinity
    """
    try:
        return json.dumps(
            obj,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ValueError(f"Object is not JSON-serializable: {e}") from e


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except binascii.Error as e:
        raise ValueError("Invalid base64") from e


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


# ===================== ИСКЛЮЧЕНИЯ ДОМЕНА =============================

class ProofError(Exception):
    """Базовая ошибка модели доказательств."""


class VerificationError(ProofError):
    """Ошибка верификации доказательства."""


class CryptoUnavailableError(ProofError):
    """Нет криптографической библиотеки cryptography."""


# ===================== МОДЕЛЬ: МЕРКЛОВО ДОКАЗАТЕЛЬСТВО ================

class MerklePosition(str, Enum):
    LEFT = "left"
    RIGHT = "right"


@dataclass(frozen=True)
class MerkleStep:
    pos: MerklePosition
    hash_hex: str  # hex без префикса

    def bytes(self) -> bytes:
        try:
            return binascii.unhexlify(self.hash_hex)
        except binascii.Error as e:
            raise ValueError("Invalid hex in MerkleStep.hash_hex") from e


@dataclass(frozen=True)
class MerkleProof:
    """
    Доказательство включения листа в корень Меркла.
    - leaf_hash_hex: hex(хеш(leaf))
    - path: последовательность шагов (левый/правый соседний узел)
    - root_hash_hex: ожидаемый корень
    - alg: алгоритм хеширования
    """
    leaf_hash_hex: str
    path: Tuple[MerkleStep, ...]
    root_hash_hex: str
    alg: HashAlgorithm = HashAlgorithm.SHA256

    @staticmethod
    def hash_leaf(leaf: bytes, *, alg: HashAlgorithm = HashAlgorithm.SHA256, salt: Optional[bytes] = None) -> str:
        """
        Рекомендуется хешировать листья как H(0x00 || salt? || leaf), чтобы отличать листья от промежуточных узлов.
        """
        prefix = b"\x00"
        data = prefix + (salt or b"") + leaf
        return _hex(_digest(data, alg))

    def verify(self, *, leaf: Optional[bytes] = None) -> bool:
        """
        Верифицирует доказательство. Если передан leaf, сначала вычисляет leaf_hash по hash_leaf и сравнивает.
        Затем сверяет путь и корень.
        """
        try:
            current = binascii.unhexlify(self.leaf_hash_hex)
        except binascii.Error as e:
            raise VerificationError("Invalid leaf hash hex") from e

        if leaf is not None:
            expected = binascii.unhexlify(MerkleProof.hash_leaf(leaf, alg=self.alg))
            if not hmac.compare_digest(current, expected):
                raise VerificationError("Leaf hash mismatch")

        for step in self.path:
            sibling = step.bytes()
            if step.pos == MerklePosition.LEFT:
                node = b"\x01" + sibling + current  # префикс для ветвления
            else:
                node = b"\x01" + current + sibling
            current = _digest(node, self.alg)

        try:
            root = binascii.unhexlify(self.root_hash_hex)
        except binascii.Error as e:
            raise VerificationError("Invalid root hash hex") from e

        if not hmac.compare_digest(current, root):
            raise VerificationError("Merkle root mismatch")
        return True


# ===================== МОДЕЛЬ: ПОДПИСЬ СООБЩЕНИЯ ======================

class SignatureAlgorithm(str, Enum):
    ED25519 = "ED25519"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_SECP256K1 = "ECDSA_SECP256K1"


@dataclass(frozen=True)
class SignatureProof:
    """
    Подтверждение целостности/аутентичности через цифровую подпись.
    - public_key_pem_b64: base64(PKCS#8 или SubjectPublicKeyInfo PEM)
    - signature_b64: base64(raw подписи: Ed25519=64 байт; ECDSA=DER)
    - message_hash_hex: hex(h(message)) — хеш каноничного сообщения
    - hash_alg: алгоритм хеширования message
    - alg: алгоритм подписи
    """
    public_key_pem_b64: str
    signature_b64: str
    message_hash_hex: str
    hash_alg: HashAlgorithm = HashAlgorithm.SHA256
    alg: SignatureAlgorithm = SignatureAlgorithm.ED25519

    @staticmethod
    def hash_message(message: Any, *, alg: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        return _hex(_digest(_canonical_json(message), alg))

    def verify(self, message: Any) -> bool:
        if not _HAS_CRYPTO:
            raise CryptoUnavailableError("Install 'cryptography' to verify signatures")
        computed = SignatureProof.hash_message(message, alg=self.hash_alg)
        if computed != self.message_hash_hex:
            raise VerificationError("Message hash mismatch")

        pub_pem = _b64d(self.public_key_pem_b64)
        signature = _b64d(self.signature_b64)

        # Загружаем публичный ключ
        try:
            pub = serialization.load_pem_public_key(pub_pem)
        except Exception as e:
            raise VerificationError(f"Invalid public key PEM: {e}") from e

        data = binascii.unhexlify(self.message_hash_hex)

        try:
            if self.alg == SignatureAlgorithm.ED25519:
                if not isinstance(pub, ed25519.Ed25519PublicKey):
                    # Возможна загрузка как generic, пробуем преобразовать
                    pub = ed25519.Ed25519PublicKey.from_public_bytes(pub.public_bytes(  # type: ignore[attr-defined]
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    ))
                pub.verify(signature, data)  # type: ignore[arg-type]
                return True

            if self.alg in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_SECP256K1):
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    raise VerificationError("Public key is not ECDSA key")

                # DER ECDSA -> (r,s)
                try:
                    r, s = decode_dss_signature(signature)
                except Exception as e:
                    raise VerificationError(f"Invalid ECDSA signature DER: {e}") from e
                sig_bytes = signature  # cryptography принимает DER напрямую

                if self.hash_alg == HashAlgorithm.SHA256:
                    chosen = hashes.SHA256()
                elif self.hash_alg == HashAlgorithm.SHA512:
                    chosen = hashes.SHA512()
                else:
                    # Для ECDSA используем SHA‑256/512. Остальные не поддерживаем.
                    raise VerificationError(f"Hash {self.hash_alg} not supported for ECDSA")

                pub.verify(sig_bytes, data, ec.ECDSA(chosen))  # type: ignore[arg-type]
                return True

            raise VerificationError(f"Unsupported signature algorithm: {self.alg}")
        except InvalidSignature as e:
            raise VerificationError("Invalid signature") from e


# ===================== ОБЩЕЕ ДОКАЗАТЕЛЬСТВО/АТТЕСТАЦИЯ ======================

class ProofType(str, Enum):
    MERKLE = "MERKLE"
    SIGNATURE = "SIGNATURE"


@dataclass(frozen=True)
class ProofEnvelope:
    """
    Универсальный контейнер доказательства.
    """
    type: ProofType
    created_at_utc: str  # ISO‑8601 UTC
    attestor: str        # кто сформировал доказательство (например, 'ledger-core@node-1')
    merkle: Optional[MerkleProof] = None
    signature: Optional[SignatureProof] = None
    comment: Optional[str] = None

    def verify(self, *, message: Optional[Any] = None, leaf: Optional[bytes] = None) -> bool:
        if self.type == ProofType.MERKLE:
            if not self.merkle:
                raise VerificationError("Missing merkle section")
            return self.merkle.verify(leaf=leaf)
        if self.type == ProofType.SIGNATURE:
            if not self.signature:
                raise VerificationError("Missing signature section")
            if message is None:
                raise VerificationError("Message required for signature verification")
            return self.signature.verify(message)
        raise VerificationError(f"Unsupported proof type: {self.type}")

    def to_dict(self) -> Dict[str, Any]:
        def _mp(p: Optional[MerkleProof]) -> Optional[Dict[str, Any]]:
            if not p:
                return None
            return {
                "leaf_hash_hex": p.leaf_hash_hex,
                "path": [{"pos": s.pos.value, "hash_hex": s.hash_hex} for s in p.path],
                "root_hash_hex": p.root_hash_hex,
                "alg": p.alg.value,
            }

        def _sp(p: Optional[SignatureProof]) -> Optional[Dict[str, Any]]:
            if not p:
                return None
            return {
                "public_key_pem_b64": p.public_key_pem_b64,
                "signature_b64": p.signature_b64,
                "message_hash_hex": p.message_hash_hex,
                "hash_alg": p.hash_alg.value,
                "alg": p.alg.value,
            }

        return {
            "type": self.type.value,
            "created_at_utc": self.created_at_utc,
            "attestor": self.attestor,
            "comment": self.comment,
            "merkle": _mp(self.merkle),
            "signature": _sp(self.signature),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> ProofEnvelope:
        t = ProofType(d.get("type"))
        merkle = None
        signature = None
        if d.get("merkle"):
            m = d["merkle"]
            merkle = MerkleProof(
                leaf_hash_hex=m["leaf_hash_hex"],
                path=tuple(MerkleStep(MerklePosition(s["pos"]), s["hash_hex"]) for s in m.get("path", [])),
                root_hash_hex=m["root_hash_hex"],
                alg=HashAlgorithm(m.get("alg", HashAlgorithm.SHA256)),
            )
        if d.get("signature"):
            s = d["signature"]
            signature = SignatureProof(
                public_key_pem_b64=s["public_key_pem_b64"],
                signature_b64=s["signature_b64"],
                message_hash_hex=s["message_hash_hex"],
                hash_alg=HashAlgorithm(s.get("hash_alg", HashAlgorithm.SHA256)),
                alg=SignatureAlgorithm(s.get("alg", SignatureAlgorithm.ED25519)),
            )
        return ProofEnvelope(
            type=t,
            created_at_utc=d["created_at_utc"],
            attestor=d["attestor"],
            comment=d.get("comment"),
            merkle=merkle,
            signature=signature,
        )


# ===================== ЦЕПОЧКА ДОВЕРИЯ (COMPOSITE) ===========================

@dataclass
class ChainOfTrust:
    """
    Набор независимых или взаимодополняющих доказательств (например, подпись + меркло‑включение).
    Верификация успешна, если все активные доказательства проходят проверку.
    """
    proofs: List[ProofEnvelope] = field(default_factory=list)

    def verify_all(
        self,
        *,
        message: Optional[Any] = None,
        leaf: Optional[bytes] = None,
    ) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        for i, p in enumerate(self.proofs):
            try:
                p.verify(message=message, leaf=leaf)
            except Exception as e:
                errors.append(f"proof[{i}] {p.type.value}: {e}")
        return (len(errors) == 0), errors

    def to_json(self) -> str:
        return json.dumps(
            {"proofs": [p.to_dict() for p in self.proofs]},
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        )

    @staticmethod
    def from_json(s: str) -> ChainOfTrust:
        try:
            d = json.loads(s)
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON for ChainOfTrust") from e
        proofs = [ProofEnvelope.from_dict(x) for x in d.get("proofs", [])]
        return ChainOfTrust(proofs=proofs)


# ===================== ХЕЛПЕРЫ ДЛЯ ПРИМЕНЕНИЯ В ЛЕДЖЕРЕ =====================

def build_merkle_proof_for_leaf(
    *,
    leaf: bytes,
    path: Sequence[Tuple[MerklePosition, bytes]],
    root_hash: bytes,
    alg: HashAlgorithm = HashAlgorithm.SHA256,
    attestor: str = "ledger-core",
    comment: Optional[str] = None,
) -> ProofEnvelope:
    mp = MerkleProof(
        leaf_hash_hex=MerkleProof.hash_leaf(leaf, alg=alg),
        path=tuple(MerkleStep(pos, _hex(h)) for (pos, h) in path),
        root_hash_hex=_hex(root_hash),
        alg=alg,
    )
    return ProofEnvelope(
        type=ProofType.MERKLE,
        created_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        attestor=attestor,
        merkle=mp,
        comment=comment,
    )


def build_signature_proof(
    *,
    message: Any,
    public_key_pem: bytes,
    signature: bytes,
    alg: SignatureAlgorithm = SignatureAlgorithm.ED25519,
    hash_alg: HashAlgorithm = HashAlgorithm.SHA256,
    attestor: str = "ledger-core",
    comment: Optional[str] = None,
) -> ProofEnvelope:
    """
    Создаёт конверт подписи, используя уже готовые public_key_pem и signature.
    Подпись должна быть над hash(message) в каноничной форме (_canonical_json).
    """
    mh = SignatureProof.hash_message(message, alg=hash_alg)
    sp = SignatureProof(
        public_key_pem_b64=_b64e(public_key_pem),
        signature_b64=_b64e(signature),
        message_hash_hex=mh,
        hash_alg=hash_alg,
        alg=alg,
    )
    return ProofEnvelope(
        type=ProofType.SIGNATURE,
        created_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        attestor=attestor,
        signature=sp,
        comment=comment,
    )


# ===================== ПРИМЕР ИСПОЛЬЗОВАНИЯ (ДОКТЕСТ) ========================

if __name__ == "__main__":  # pragma: no cover
    # Пример данных (сообщение транзакции в каноничном JSON)
    tx = {
        "schemaVersion": "1.0.0",
        "id": "8f6f4b9f-7b1c-4a30-b6a4-0d0f3c0e1abc",
        "type": "charge",
        "status": "posted",
        "occurredAt": "2025-08-15T09:12:33.123Z",
        "recordedAt": "2025-08-15T09:12:34.001Z",
        "currency": "EUR",
        "amount": "100.00",
        "amountNet": "98.50",
        "payer": {"id": "cust_001", "type": "customer"},
        "payee": {"id": "mrc_007", "type": "merchant"},
    }

    # 1) Проверка подписи (демо — без фактической подписи, покажем структуру)
    if _HAS_CRYPTO:
        # Генерируем временную пару Ed25519 (только для демонстрации)
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        msg_hash = SignatureProof.hash_message(tx)
        signature = private.sign(binascii.unhexlify(msg_hash))
        env_sig = build_signature_proof(
            message=tx,
            public_key_pem=public,
            signature=signature,
            alg=SignatureAlgorithm.ED25519,
        )
        assert env_sig.verify(message=tx) is True

    # 2) Мерклово доказательство (игрушечный путь)
    leaf = _canonical_json(tx)
    # Имитация дерева из одного листа: корень=hash(0x00||leaf)
    leaf_hash = _digest(b"\x00" + leaf)
    env_m = build_merkle_proof_for_leaf(
        leaf=leaf,
        path=[],  # один лист — нет пути
        root_hash=leaf_hash,
    )
    assert env_m.verify(leaf=leaf) is True

    chain = ChainOfTrust(proofs=[env_m])
    ok, errs = chain.verify_all(leaf=leaf)
    print("verified:", ok, "errors:", errs)

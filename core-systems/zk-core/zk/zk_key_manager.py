import os
import hashlib
import json
import shutil
from pathlib import Path
from typing import Literal, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from intel_core.utils.crypto_utils import verify_crs_signature, secure_erase
from intel_core.zk.zk_schemes import SupportedZkScheme, load_proving_key, load_verification_key

ZK_KEY_DIR = Path("/var/intel-core/zk_keys")
ZK_KEY_DIR.mkdir(parents=True, exist_ok=True)

class ZkKeyManager:
    """
    Управление ключами ZK-схем: загрузка, проверка, ротация, secure delete.
    Поддерживаются схемы Groth16, PLONK, Marlin.
    """

    def __init__(self, scheme: SupportedZkScheme):
        self.scheme = scheme
        self.scheme_dir = ZK_KEY_DIR / scheme.value
        self.scheme_dir.mkdir(exist_ok=True)

    def _key_path(self, key_type: Literal["proving", "verifying", "crs"]) -> Path:
        return self.scheme_dir / f"{key_type}_key.bin"

    def _meta_path(self, key_type: str) -> Path:
        return self.scheme_dir / f"{key_type}_meta.json"

    def _hash_file(self, path: Path) -> str:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def load_key(self, key_type: Literal["proving", "verifying"]) -> bytes:
        path = self._key_path(key_type)
        if not path.exists():
            raise FileNotFoundError(f"{key_type} key not found for scheme: {self.scheme}")
        return path.read_bytes()

    def load_crs(self) -> bytes:
        path = self._key_path("crs")
        if not path.exists():
            raise FileNotFoundError(f"CRS not found for scheme: {self.scheme}")
        return path.read_bytes()

    def store_key(self, key_type: Literal["proving", "verifying", "crs"], data: bytes, meta: Optional[dict] = None):
        path = self._key_path(key_type)
        path.write_bytes(data)

        if meta:
            meta_path = self._meta_path(key_type)
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2)

    def verify_crs_integrity(self, trusted_pubkey_pem: bytes) -> bool:
        """
        Проверяет цифровую подпись CRS-файла с использованием trusted public key.
        """
        crs = self.load_crs()
        meta_path = self._meta_path("crs")
        if not meta_path.exists():
            raise RuntimeError("CRS metadata file missing")
        with open(meta_path, "r") as f:
            meta = json.load(f)
        signature = bytes.fromhex(meta["signature"])
        return verify_crs_signature(crs, signature, trusted_pubkey_pem)

    def rotate_key(self, key_type: Literal["proving", "verifying", "crs"], new_data: bytes, meta: Optional[dict] = None):
        """
        Безопасно заменяет ключ, удаляя старую копию.
        """
        old_path = self._key_path(key_type)
        if old_path.exists():
            secure_erase(old_path)
        self.store_key(key_type, new_data, meta)

    def get_key_metadata(self, key_type: Literal["proving", "verifying", "crs"]) -> Optional[dict]:
        path = self._meta_path(key_type)
        if not path.exists():
            return None
        with open(path, "r") as f:
            return json.load(f)

    def list_available_keys(self) -> dict:
        """
        Возвращает хэши всех доступных ключей схемы.
        """
        result = {}
        for key_type in ["proving", "verifying", "crs"]:
            path = self._key_path(key_type)
            if path.exists():
                result[key_type] = self._hash_file(path)
        return result

    def delete_all_keys(self):
        """
        Безвозвратно удаляет все ключи и метаинформацию ZK-схемы.
        """
        for item in self.scheme_dir.iterdir():
            secure_erase(item)


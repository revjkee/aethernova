import os
import hashlib
import json
import shutil
import logging
import tempfile
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from blackvault_core.shared.audit import audit_log_event
from blackvault_core.shared.trust.signature import sign_payload_gpg
from blackvault_core.config import settings

logger = logging.getLogger("forensic_storage")
logger.setLevel(logging.DEBUG)

FORCE_STORAGE_ROOT = Path(settings.FORENSIC_STORAGE_DIR or "/var/lib/blackvault/forensics").resolve()
FORCE_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

class ForensicStorageError(Exception):
    pass

class ForensicStorage:
    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.storage_dir = FORCE_STORAGE_ROOT / incident_id
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Forensic storage directory prepared: {self.storage_dir}")

    def _hash_file(self, file_path: Path) -> str:
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _encrypt_file(self, file_path: Path, key: bytes) -> Path:
        encrypted_path = file_path.with_suffix(file_path.suffix + ".enc")
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with file_path.open("rb") as fin, encrypted_path.open("wb") as fout:
            fout.write(iv)
            while chunk := fin.read(4096):
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())

        return encrypted_path

    def _store_metadata(self, artifact_path: Path, hash_value: str, encrypted_path: Path, metadata: dict):
        meta_file = self.storage_dir / f"{artifact_path.stem}.meta.json"
        metadata.update({
            "original_file": artifact_path.name,
            "encrypted_file": encrypted_path.name,
            "hash": hash_value,
            "timestamp": datetime.utcnow().isoformat(),
        })
        with meta_file.open("w") as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Metadata stored: {meta_file}")

    def store_artifact(self, artifact_path: Path, classification: str, source: str, encryption_key: bytes):
        if not artifact_path.exists():
            raise ForensicStorageError(f"Artifact not found: {artifact_path}")
        try:
            hash_value = self._hash_file(artifact_path)
            encrypted_path = self._encrypt_file(artifact_path, encryption_key)

            metadata = {
                "classification": classification,
                "source": source,
                "incident_id": self.incident_id,
            }

            self._store_metadata(artifact_path, hash_value, encrypted_path, metadata)
            audit_log_event(
                actor="forensic_storage",
                action="artifact_stored",
                resource=str(encrypted_path),
                metadata=metadata
            )

            logger.info(f"Artifact securely stored and logged: {artifact_path}")
            return encrypted_path.name, hash_value

        except Exception as e:
            logger.error(f"Failed to store artifact {artifact_path}: {e}")
            raise ForensicStorageError(str(e)) from e

    def sign_evidence_set(self):
        try:
            evidence_manifest = {
                "incident_id": self.incident_id,
                "artifacts": [],
                "timestamp": datetime.utcnow().isoformat()
            }

            for meta_file in self.storage_dir.glob("*.meta.json"):
                with meta_file.open("r") as f:
                    metadata = json.load(f)
                evidence_manifest["artifacts"].append(metadata)

            manifest_path = self.storage_dir / "manifest.json"
            with manifest_path.open("w") as f:
                json.dump(evidence_manifest, f, indent=2)

            signature_path = sign_payload_gpg(manifest_path)
            logger.info(f"Manifest signed: {signature_path}")

            audit_log_event(
                actor="forensic_storage",
                action="manifest_signed",
                resource=str(signature_path),
                metadata={"incident_id": self.incident_id}
            )

            return signature_path

        except Exception as e:
            logger.error(f"Failed to sign evidence set: {e}")
            raise ForensicStorageError(str(e)) from e

    def purge_after_verdict(self, retain_hashes=True):
        try:
            if retain_hashes:
                for meta_file in self.storage_dir.glob("*.meta.json"):
                    continue  # Preserve hashes
            shutil.rmtree(self.storage_dir)
            logger.warning(f"Forensic data purged for incident: {self.incident_id}")
        except Exception as e:
            logger.error(f"Failed to purge forensic data: {e}")
            raise ForensicStorageError(str(e)) from e

# redteam_toolkit/payloads/binaries/payload_generator.py

import os
import shutil
import uuid
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from redteam_toolkit.core.signature_evasion import EvasionEngine
from redteam_toolkit.core.cross_platform_compiler import CrossCompiler
from redteam_toolkit.core.integrity_signer import BinarySigner

logger = logging.getLogger("PayloadGenerator")
logging.basicConfig(level=logging.INFO)

class PayloadGenerator:
    def __init__(self, output_dir: str = "dist/binaries"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.compiler = CrossCompiler()
        self.evasion_engine = EvasionEngine()
        self.signer = BinarySigner()
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

    def _generate_unique_filename(self, platform: str) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        uid = uuid.uuid4().hex[:8]
        return f"payload_{platform}_{timestamp}_{uid}.bin"

    def _compile_source(self, platform: str, source_path: Path, output_path: Path) -> bool:
        try:
            logger.info(f"Compiling source for platform: {platform}")
            self.compiler.compile(platform, source_path, output_path)
            return True
        except Exception as e:
            logger.error(f"Compilation failed: {e}")
            return False

    def _apply_evasion(self, binary_path: Path) -> None:
        logger.info(f"Applying signature evasion techniques to {binary_path}")
        self.evasion_engine.obfuscate(binary_path)

    def _encrypt_binary(self, binary_path: Path) -> None:
        logger.info(f"Encrypting binary: {binary_path}")
        original_data = binary_path.read_bytes()
        encrypted_data = self.fernet.encrypt(original_data)
        binary_path.write_bytes(encrypted_data)

    def _sign_binary(self, binary_path: Path) -> None:
        logger.info(f"Digitally signing the binary")
        self.signer.sign(binary_path)

    def generate_payload(self, source_code_path: str, platform: str) -> Path:
        source_path = Path(source_code_path)
        assert source_path.exists(), f"Source code not found: {source_code_path}"
        output_filename = self._generate_unique_filename(platform)
        output_path = self.output_dir / output_filename

        if not self._compile_source(platform, source_path, output_path):
            raise RuntimeError("Payload compilation failed")

        self._apply_evasion(output_path)
        self._encrypt_binary(output_path)
        self._sign_binary(output_path)

        logger.info(f"Payload generated successfully: {output_path}")
        return output_path

    def get_encryption_key(self) -> str:
        return self.encryption_key.decode()

# Example: CI/CD integration would invoke generate_payload during redteam pipeline

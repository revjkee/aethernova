# Верификация ZK-доказательств
# zk_verifier.py
# Верификация zkSNARK-доказательств для TeslaAI Genesis

import subprocess
import os
import logging

logger = logging.getLogger("zk_verifier")
logger.setLevel(logging.INFO)

class ZKVerifier:
    def __init__(self, circuits_dir: str):
        """
        :param circuits_dir: Путь к директории с цепями (circuits)
        """
        self.circuits_dir = circuits_dir

    def verify_proof(self, proof_file: str, verification_key_file: str) -> bool:
        """
        Проверяет zkSNARK доказательство.
        :param proof_file: путь к proof.json
        :param verification_key_file: путь к verification.key
        :return: True, если доказательство валидно, иначе False
        """
        if not os.path.isfile(proof_file):
            logger.error(f"Файл доказательства не найден: {proof_file}")
            return False
        if not os.path.isfile(verification_key_file):
            logger.error(f"Файл verification key не найден: {verification_key_file}")
            return False

        try:
            result = subprocess.run(
                ["zokrates", "verify", "-p", proof_file, "-v", verification_key_file],
                capture_output=True, text=True, check=True
            )
            logger.info(f"Верификация доказательства успешна: {proof_file}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Верификация доказательства не удалась: {e.stderr}")
            return False

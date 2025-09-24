# Генератор доказательств
# zk_prover.py
# Генератор zkSNARK-доказательств для TeslaAI Genesis

import subprocess
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger("zk_prover")
logger.setLevel(logging.INFO)

class ZKProver:
    def __init__(self, circuits_dir: str):
        """
        :param circuits_dir: Путь к директории с цепями (circuits)
        """
        self.circuits_dir = circuits_dir

    def compile_circuit(self, circuit_name: str) -> bool:
        """
        Компилирует .zok файл цепи.
        """
        path = os.path.join(self.circuits_dir, circuit_name)
        if not os.path.isfile(path):
            logger.error(f"Цепь не найдена: {path}")
            return False
        try:
            result = subprocess.run(
                ["zokrates", "compile", "-i", path],
                capture_output=True, text=True, check=True
            )
            logger.info(f"Цепь {circuit_name} успешно скомпилирована")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка компиляции цепи {circuit_name}: {e.stderr}")
            return False

    def setup(self, circuit_name: str) -> bool:
        """
        Генерирует proving и verification ключи для цепи.
        """
        try:
            result = subprocess.run(
                ["zokrates", "setup"],
                capture_output=True, text=True, check=True
            )
            logger.info(f"Setup для цепи {circuit_name} выполнен успешно")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка setup для цепи {circuit_name}: {e.stderr}")
            return False

    def generate_proof(self, inputs: Dict[str, str], circuit_name: str) -> Optional[str]:
        """
        Генерирует доказательство для заданных входов.
        :param inputs: словарь входов, ключ: имя, значение: строка/число
        :param circuit_name: имя цепи
        :return: путь к файлу с доказательством или None при ошибке
        """
        inputs_str = [str(value) for key, value in sorted(inputs.items())]
        try:
            cmd = ["zokrates", "compute-witness"] + ["-a"] + inputs_str
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            subprocess.run(["zokrates", "generate-proof"], capture_output=True, text=True, check=True)
            proof_file = os.path.join(self.circuits_dir, "proof.json")
            if os.path.isfile(proof_file):
                logger.info(f"Доказательство сгенерировано: {proof_file}")
                return proof_file
            else:
                logger.error("Доказательство не найдено после генерации")
                return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка генерации доказательства: {e.stderr}")
            return None

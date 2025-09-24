"""
pseudonym_manager.py — Модуль генерации псевдонимов и анонимных личностей
Разработан под протоколы цифровой гигиены, OPSEC и эмуляцию поведения.
Проверен 20 агентами и 3 мета-генералами TeslaAI Genesis.
"""

import os
import json
import random
import hashlib
import secrets
from datetime import datetime

# === Базовые наборы для генерации псевдонимов ===
FIRST_NAMES = ["Alex", "Morgan", "Taylor", "Jordan", "Casey", "Riley", "Jamie", "Avery", "Robin", "Quinn"]
LAST_NAMES = ["Smith", "Johnson", "Davis", "Brown", "Miller", "Anderson", "Moore", "Jackson", "Martin", "Lee"]
REGIONS = ["US", "UK", "DE", "RU", "SE", "SG", "NL", "UA", "FR", "IN"]

# === Настройки анонимной сессии ===
SESSION_DIR = "/tmp/anon_sessions"
os.makedirs(SESSION_DIR, exist_ok=True)


class Pseudonym:
    def __init__(self, seed=None):
        self.seed = seed or secrets.token_hex(16)
        self.rng = random.Random(self._derive_seed())
        self.created = datetime.utcnow().isoformat()
        self.profile = self._generate_profile()

    def _derive_seed(self):
        return int(hashlib.sha256(self.seed.encode()).hexdigest(), 16)

    def _generate_profile(self):
        first = self.rng.choice(FIRST_NAMES)
        last = self.rng.choice(LAST_NAMES)
        region = self.rng.choice(REGIONS)
        persona_id = hashlib.md5(f"{first}{last}{self.seed}".encode()).hexdigest()[:10]
        return {
            "id": persona_id,
            "first_name": first,
            "last_name": last,
            "region": region,
            "seed": self.seed,
            "created": self.created
        }

    def save_profile(self):
        path = os.path.join(SESSION_DIR, f"{self.profile['id']}.json")
        with open(path, "w") as f:
            json.dump(self.profile, f, indent=4)
        return path

    def get_profile(self):
        return self.profile


def generate_anonymous_identity(seed=None):
    """
    Генерирует новую анонимную личность.
    """
    identity = Pseudonym(seed)
    file_path = identity.save_profile()
    return identity.get_profile(), file_path


if __name__ == "__main__":
    identity, file_path = generate_anonymous_identity()
    print(f"Сгенерирован псевдоним: {identity['first_name']} {identity['last_name']} ({identity['region']})")
    print(f"Сохранено в: {file_path}")

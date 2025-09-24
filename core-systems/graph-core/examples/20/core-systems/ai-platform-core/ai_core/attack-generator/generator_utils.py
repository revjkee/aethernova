import random
import string
import yaml
from typing import Any, Dict, List, Optional


class AttackGeneratorUtils:
    @staticmethod
    def load_attack_db(file_path: str) -> List[Dict[str, Any]]:
        """
        Загружает базу известных атак из YAML файла.

        :param file_path: Путь к файлу базы атак.
        :return: Список атак в формате словарей.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return data.get('attacks', [])

    @staticmethod
    def get_attack_by_id(attacks: List[Dict[str, Any]], attack_id: str) -> Optional[Dict[str, Any]]:
        """
        Возвращает атаку по её ID из списка атак.

        :param attacks: Список всех атак.
        :param attack_id: Идентификатор атаки.
        :return: Словарь с данными атаки или None, если не найдено.
        """
        for attack in attacks:
            if attack.get('id') == attack_id:
                return attack
        return None

    @staticmethod
    def random_string(length: int = 12, chars: str = string.ascii_letters + string.digits) -> str:
        """
        Генерирует случайную строку заданной длины.

        :param length: Длина строки.
        :param chars: Набор символов для генерации.
        :return: Случайная строка.
        """
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def fuzz_payload(base_payload: str, fuzz_chars: Optional[List[str]] = None, count: int = 5) -> List[str]:
        """
        Генерирует список мутированных payload для тестирования уязвимостей.

        :param base_payload: Исходная полезная нагрузка.
        :param fuzz_chars: Символы для вставки/замены.
        :param count: Количество вариантов.
        :return: Список мутированных payload.
        """
        if fuzz_chars is None:
            fuzz_chars = ['\'', '"', ';', '--', '<', '>', '%', '\\']

        fuzzed_payloads = []
        for _ in range(count):
            pos = random.randint(0, len(base_payload))
            char = random.choice(fuzz_chars)
            fuzzed = base_payload[:pos] + char + base_payload[pos:]
            fuzzed_payloads.append(fuzzed)
        return fuzzed_payloads

    @staticmethod
    def generate_attack_vector(attack: Dict[str, Any]) -> str:
        """
        Генерирует пример вектора атаки на основе данных из описания.

        :param attack: Данные атаки.
        :return: Пример строки вектора атаки.
        """
        vectors = attack.get('vectors', [])
        if not vectors:
            return ""

        base_vector = random.choice(vectors)
        # Простейшая генерация для примера:
        if attack['id'] == "SQL_INJECTION":
            payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT NULL --"]
            payload = random.choice(payloads)
            return f"{base_vector}: {payload}"
        elif attack['id'] == "XSS_REFLECTED":
            payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
            payload = random.choice(payloads)
            return f"{base_vector}: {payload}"
        else:
            # По умолчанию просто возвращаем вектор + случайную строку
            rand_str = AttackGeneratorUtils.random_string(8)
            return f"{base_vector}: {rand_str}"

    @staticmethod
    def sanitize_input(user_input: str) -> str:
        """
        Простейшая санитизация входных данных для защиты от инъекций.

        :param user_input: Входные данные.
        :return: Санитизированная строка.
        """
        replacements = {
            "'": "''",
            '"': '\\"',
            ";": "",
            "--": "",
            "<": "&lt;",
            ">": "&gt;"
        }
        sanitized = user_input
        for old, new in replacements.items():
            sanitized = sanitized.replace(old, new)
        return sanitized


# Пример использования (удалять при интеграции)
if __name__ == "__main__":
    utils = AttackGeneratorUtils()
    attacks = utils.load_attack_db("attack_db.yaml")
    sql_attack = utils.get_attack_by_id(attacks, "SQL_INJECTION")
    vector = utils.generate_attack_vector(sql_attack)
    fuzzed = utils.fuzz_payload("SELECT * FROM users WHERE username='admin'")
    sanitized = utils.sanitize_input("admin'; DROP TABLE users; --")

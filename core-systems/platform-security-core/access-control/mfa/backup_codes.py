# /security/mfa-guard/backup_codes.py

import os
import secrets
import hashlib
from typing import List, Optional


class BackupCodesManager:
    """
    Управление резервными кодами для MFA.
    Генерация, хранение и проверка одноразовых резервных кодов.
    """

    CODE_LENGTH = 10
    CODE_COUNT = 10
    HASH_ALGORITHM = 'sha256'

    def __init__(self, storage_path: str):
        """
        :param storage_path: Путь к файлу для хранения хешей кодов (JSON, например)
        """
        self.storage_path = storage_path
        self._codes_hashes: List[str] = []
        self._load()

    def _load(self):
        if not os.path.exists(self.storage_path):
            self._codes_hashes = []
            return
        with open(self.storage_path, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
            self._codes_hashes = lines

    def _save(self):
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self._codes_hashes))

    @staticmethod
    def _hash_code(code: str) -> str:
        h = hashlib.new(BackupCodesManager.HASH_ALGORITHM)
        h.update(code.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def _generate_code(length: int) -> str:
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # исключены похожие символы
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def generate_codes(self, count: Optional[int] = None) -> List[str]:
        """
        Генерирует новый набор резервных кодов, сохраняет их хеши.
        :param count: Кол-во кодов, по умолчанию CODE_COUNT
        :return: Список кодов в открытом виде (разовый вывод)
        """
        if count is None:
            count = self.CODE_COUNT
        codes = [self._generate_code(self.CODE_LENGTH) for _ in range(count)]
        self._codes_hashes = [self._hash_code(code) for code in codes]
        self._save()
        return codes

    def verify_and_consume(self, code: str) -> bool:
        """
        Проверяет валидность кода и удаляет его после использования.
        :param code: Введённый резервный код
        :return: True если код валиден и был удалён, иначе False
        """
        hashed = self._hash_code(code)
        if hashed in self._codes_hashes:
            self._codes_hashes.remove(hashed)
            self._save()
            return True
        return False

    def remaining_count(self) -> int:
        """
        Возвращает количество оставшихся неиспользованных кодов.
        """
        return len(self._codes_hashes)


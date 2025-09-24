# quantum-lab/utils/file_manager.py

import os
import shutil
import hashlib
from datetime import datetime

class FileManager:
    """
    Класс для управления файлами с поддержкой версионирования.
    Обеспечивает сохранение копий файлов с метками времени и хешами для контроля целостности.
    """

    def __init__(self, base_dir: str = "versions"):
        """
        Инициализация менеджера с базовой директорией для версий.

        :param base_dir: папка для хранения версий файлов
        """
        self.base_dir = base_dir
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)

    def _get_file_hash(self, file_path: str, chunk_size: int = 8192) -> str:
        """
        Вычисление SHA256 хеша файла для проверки целостности.

        :param file_path: путь к файлу
        :param chunk_size: размер блока для чтения
        :return: хеш в шестнадцатеричном формате
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()

    def save_version(self, file_path: str) -> str:
        """
        Сохраняет копию файла в версионной папке с отметкой времени и хешем.

        :param file_path: исходный файл
        :return: путь к сохранённой версии
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Файл не найден: {file_path}")

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        file_hash = self._get_file_hash(file_path)
        filename = os.path.basename(file_path)
        version_name = f"{filename}_{timestamp}_{file_hash[:8]}"
        version_path = os.path.join(self.base_dir, version_name)

        shutil.copy2(file_path, version_path)
        return version_path

    def list_versions(self) -> list[str]:
        """
        Возвращает список всех сохранённых версий файлов.

        :return: список путей к версиям
        """
        if not os.path.exists(self.base_dir):
            return []
        return sorted(os.listdir(self.base_dir))

    def restore_version(self, version_name: str, target_path: str) -> None:
        """
        Восстанавливает файл из версии.

        :param version_name: имя файла версии
        :param target_path: путь для восстановления
        """
        version_path = os.path.join(self.base_dir, version_name)
        if not os.path.isfile(version_path):
            raise FileNotFoundError(f"Версия не найдена: {version_path}")
        shutil.copy2(version_path, target_path)


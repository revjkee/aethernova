# autopwn-framework/services/storage_service.py

import os
import aiofiles
import asyncio
from typing import Optional

class StorageService:
    """
    Сервис для асинхронного управления файловым хранилищем.
    Поддерживает сохранение, чтение и удаление файлов с учётом безопасности и масштабируемости.
    """

    def __init__(self, base_path: str):
        self.base_path = base_path
        if not os.path.exists(base_path):
            os.makedirs(base_path, exist_ok=True)

    def _get_full_path(self, filename: str) -> str:
        # Предотвращение directory traversal атак
        safe_name = os.path.basename(filename)
        return os.path.join(self.base_path, safe_name)

    async def save_file(self, filename: str, content: bytes) -> None:
        path = self._get_full_path(filename)
        async with aiofiles.open(path, 'wb') as f:
            await f.write(content)

    async def read_file(self, filename: str) -> Optional[bytes]:
        path = self._get_full_path(filename)
        if not os.path.exists(path):
            return None
        async with aiofiles.open(path, 'rb') as f:
            return await f.read()

    async def delete_file(self, filename: str) -> bool:
        path = self._get_full_path(filename)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    async def file_exists(self, filename: str) -> bool:
        path = self._get_full_path(filename)
        return os.path.exists(path)

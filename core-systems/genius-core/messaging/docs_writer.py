import asyncio
from typing import Dict, Optional, Any
from datetime import datetime

class DocsWriter:
    """
    Модуль асинхронной записи и управления документами.
    Поддерживает создание, обновление и хранение текстовых документов в памяти.
    """

    def __init__(self):
        # Хранилище документов: ключ — ID документа, значение — словарь с данными
        self._documents: Dict[str, Dict[str, Any]] = {}

        # Блокировка для защиты от гонок при записи
        self._lock = asyncio.Lock()

    async def create_document(self, doc_id: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Создает новый документ с уникальным ID.
        """
        async with self._lock:
            if doc_id in self._documents:
                raise ValueError(f"Document with id '{doc_id}' already exists.")
            self._documents[doc_id] = {
                "content": content,
                "metadata": metadata or {},
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }

    async def update_document(self, doc_id: str, content: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Обновляет содержимое и/или метаданные документа.
        """
        async with self._lock:
            if doc_id not in self._documents:
                raise ValueError(f"Document with id '{doc_id}' does not exist.")
            if content is not None:
                self._documents[doc_id]["content"] = content
            if metadata is not None:
                self._documents[doc_id]["metadata"].update(metadata)
            self._documents[doc_id]["updated_at"] = datetime.utcnow()

    async def get_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """
        Получить документ по ID. Возвращает словарь с данными или None.
        """
        async with self._lock:
            return self._documents.get(doc_id)

    async def delete_document(self, doc_id: str) -> None:
        """
        Удаляет документ по ID.
        """
        async with self._lock:
            if doc_id in self._documents:
                del self._documents[doc_id]

    async def list_documents(self) -> Dict[str, Dict[str, Any]]:
        """
        Возвращает копию всех документов.
        """
        async with self._lock:
            return dict(self._documents)

# quantum-lab/experiments/metadata_manager.py

import json
from typing import Dict, Any, Optional

class MetadataManager:
    """
    Класс для управления метаданными экспериментов.
    Метаданные — структурированные описания параметров, условий и результатов экспериментов.
    """

    def __init__(self):
        self._metadata_store: Dict[str, Dict[str, Any]] = {}

    def add_metadata(self, experiment_id: str, metadata: Dict[str, Any]) -> None:
        """
        Добавляет или обновляет метаданные для конкретного эксперимента.

        :param experiment_id: Уникальный идентификатор эксперимента.
        :param metadata: Словарь с метаданными.
        """
        self._metadata_store[experiment_id] = metadata

    def get_metadata(self, experiment_id: str) -> Optional[Dict[str, Any]]:
        """
        Возвращает метаданные по идентификатору эксперимента.

        :param experiment_id: Уникальный идентификатор эксперимента.
        :return: Метаданные или None, если не найдены.
        """
        return self._metadata_store.get(experiment_id)

    def delete_metadata(self, experiment_id: str) -> bool:
        """
        Удаляет метаданные эксперимента по идентификатору.

        :param experiment_id: Уникальный идентификатор эксперимента.
        :return: True если удалено, False если отсутствовало.
        """
        if experiment_id in self._metadata_store:
            del self._metadata_store[experiment_id]
            return True
        return False

    def export_metadata(self, experiment_id: str, filepath: str) -> bool:
        """
        Экспортирует метаданные эксперимента в JSON файл.

        :param experiment_id: Уникальный идентификатор эксперимента.
        :param filepath: Путь к файлу для сохранения.
        :return: True если успешно, False если метаданные не найдены.
        """
        metadata = self.get_metadata(experiment_id)
        if metadata is None:
            return False
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4, ensure_ascii=False)
        return True

    def import_metadata(self, experiment_id: str, filepath: str) -> bool:
        """
        Импортирует метаданные из JSON файла и сохраняет под заданным идентификатором.

        :param experiment_id: Уникальный идентификатор эксперимента.
        :param filepath: Путь к JSON файлу с метаданными.
        :return: True если успешно, False при ошибках.
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            self.add_metadata(experiment_id, metadata)
            return True
        except Exception:
            return False

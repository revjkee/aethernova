import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from llmops.eval.validators.schema_validator import TaskConfigSchema
from llmops.eval.constants import TASK_PROMPT_PATH

log = logging.getLogger("eval_loader")

class TaskLoadingError(Exception):
    pass


class TaskLoader:
    """
    Отвечает за загрузку заданий и конфигураций для eval-задач.
    """

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or TASK_PROMPT_PATH
        self.cache: Dict[str, Any] = {}

    def load_task_config(self, task_name: str) -> Dict[str, Any]:
        """
        Загружает конфигурацию задания из JSON и валидирует.
        """
        if task_name in self.cache:
            return self.cache[task_name]

        file_path = self.base_path / f"{task_name}.json"
        if not file_path.exists():
            raise TaskLoadingError(f"Task config file not found: {file_path}")

        try:
            with file_path.open("r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as e:
            raise TaskLoadingError(f"Error reading JSON for task {task_name}: {e}")

        try:
            validated = TaskConfigSchema(**raw_data)
            self.cache[task_name] = validated.dict()
            return self.cache[task_name]
        except Exception as e:
            raise TaskLoadingError(f"Schema validation failed for {task_name}: {e}")

    def list_available_tasks(self) -> List[str]:
        """
        Возвращает список доступных eval-заданий по наличию .json файлов.
        """
        return [p.stem for p in self.base_path.glob("*.json") if p.is_file()]

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Загружает все конфигурации задач.
        """
        configs = {}
        for task in self.list_available_tasks():
            try:
                configs[task] = self.load_task_config(task)
            except TaskLoadingError as e:
                log.warning(f"Skipping task {task}: {e}")
        return configs

    def reload_task(self, task_name: str) -> Dict[str, Any]:
        """
        Принудительно перезагружает задание (игнорирует кеш).
        """
        if task_name in self.cache:
            del self.cache[task_name]
        return self.load_task_config(task_name)


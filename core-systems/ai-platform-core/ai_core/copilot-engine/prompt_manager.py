import threading
import time
from typing import List, Dict, Optional, Any
import logging

class PromptManager:
    """
    Класс управления подсказками для AI Copilot Engine.
    Отвечает за формирование, обновление и хранение контекстных подсказок,
    обеспечивая максимальную релевантность и эффективность генерации.
    """

    def __init__(self, max_context_length: int = 2048):
        self.max_context_length = max_context_length
        self.prompts: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.last_update_timestamp = 0.0
        self.update_interval = 10.0  # секунд, интервал обновления подсказок

    def add_prompt(self, role: str, content: str) -> None:
        """
        Добавляет новую подсказку с указанием роли ('system', 'user', 'assistant').
        Автоматически вызывает обрезку контекста, если превышен лимит.
        """
        with self.lock:
            self.prompts.append({"role": role, "content": content})
            self._trim_prompts()
            self.last_update_timestamp = time.time()
            logging.debug(f"Added prompt: role={role}, content_len={len(content)}")

    def get_context(self) -> List[Dict[str, str]]:
        """
        Возвращает текущий контекст подсказок для передачи в модель.
        """
        with self.lock:
            logging.debug(f"Getting context with {len(self.prompts)} prompts")
            return list(self.prompts)

    def update_prompt(self, index: int, content: str) -> bool:
        """
        Обновляет содержимое подсказки по индексу.
        Возвращает True при успешном обновлении, False при ошибке.
        """
        with self.lock:
            if 0 <= index < len(self.prompts):
                old_len = len(self.prompts[index]["content"])
                self.prompts[index]["content"] = content
                self.last_update_timestamp = time.time()
                logging.debug(f"Updated prompt index={index}, old_len={old_len}, new_len={len(content)}")
                self._trim_prompts()
                return True
            logging.warning(f"Update failed: invalid index {index}")
            return False

    def clear_prompts(self) -> None:
        """
        Полностью очищает все подсказки.
        """
        with self.lock:
            count = len(self.prompts)
            self.prompts.clear()
            self.last_update_timestamp = time.time()
            logging.debug(f"Cleared all {count} prompts")

    def _trim_prompts(self) -> None:
        """
        Внутренний метод для обрезки подсказок по длине, чтобы не превышать max_context_length.
        Удаляет старые подсказки, начиная с начала списка, пока суммарная длина не станет приемлемой.
        """
        total_length = sum(len(p["content"]) for p in self.prompts)
        while total_length > self.max_context_length and self.prompts:
            removed = self.prompts.pop(0)
            total_length -= len(removed["content"])
            logging.debug(f"Trimmed prompt with length {len(removed['content'])}, new total length {total_length}")

    def refresh_if_needed(self) -> None:
        """
        Проверяет, прошло ли достаточно времени с последнего обновления, и, если да,
        инициирует обновление (placeholder для реальной логики обновления подсказок).
        """
        with self.lock:
            elapsed = time.time() - self.last_update_timestamp
            if elapsed >= self.update_interval:
                logging.info(f"Refreshing prompts after {elapsed:.1f}s")
                # Пример обновления - можно расширять под логику генерации или очистки
                self._trim_prompts()
                self.last_update_timestamp = time.time()

# Внедрение логгера (конфигурация по необходимости)
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

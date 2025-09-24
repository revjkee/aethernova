# llmops/eval/eval_on_tasks/base_evaluator.py

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseEvaluator(ABC):
    """
    Абстрактный базовый класс для всех оценщиков задач.
    Определяет общий интерфейс и базовую логику для запуска
    и сбора результатов оценки моделей.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Инициализация оценщика с настройками.
        :param config: опциональный словарь конфигурации
        """
        self.config = config or {}

    @abstractmethod
    def evaluate(self, predictions: List[Any], references: List[Any]) -> Dict[str, float]:
        """
        Основной метод оценки.
        Должен возвращать словарь метрик (название -> значение).
        :param predictions: список предсказаний модели
        :param references: список эталонных ответов
        :return: словарь с метриками оценки
        """
        pass

    def reset(self) -> None:
        """
        Сбросить внутренние состояния (если есть).
        Полезно при повторных запусках.
        """
        pass

    def get_config(self) -> Dict[str, Any]:
        """
        Получить текущую конфигурацию оценщика.
        """
        return self.config


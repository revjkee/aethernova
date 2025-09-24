# quantum-lab/experiments/experiment_runner.py

import asyncio
from typing import Callable, List, Dict, Any

class ExperimentRunner:
    """
    Класс для оркестрации и параллельного запуска квантовых экспериментов.
    Позволяет управлять списком экспериментов, запускать их асинхронно,
    собирать результаты и обрабатывать ошибки.
    """

    def __init__(self):
        self.experiments: List[Callable[[], Any]] = []
        self.results: Dict[int, Any] = {}
        self.errors: Dict[int, Exception] = {}

    def add_experiment(self, experiment: Callable[[], Any]) -> None:
        """
        Добавить эксперимент (функцию без аргументов), который вернёт результат.
        """
        self.experiments.append(experiment)

    async def _run_single(self, idx: int, experiment: Callable[[], Any]) -> None:
        """
        Асинхронный запуск одного эксперимента с обработкой исключений.
        """
        try:
            result = await asyncio.to_thread(experiment)
            self.results[idx] = result
        except Exception as e:
            self.errors[idx] = e

    async def run_all(self) -> Dict[int, Any]:
        """
        Запускает все эксперименты параллельно и ждёт их завершения.

        :return: Словарь с результатами экспериментов по их индексам.
        """
        tasks = [self._run_single(idx, exp) for idx, exp in enumerate(self.experiments)]
        await asyncio.gather(*tasks)
        return self.results

    def get_errors(self) -> Dict[int, Exception]:
        """
        Возвращает словарь ошибок, произошедших при выполнении экспериментов.
        """
        return self.errors


# autopwn-framework/scanners/custom_scanners/utils/helper.py

import asyncio
import logging
from typing import List, Any, Dict

logger = logging.getLogger(__name__)

async def run_concurrent_tasks(tasks: List[asyncio.Task], limit: int = 10) -> List[Any]:
    """
    Запускает асинхронные задачи с ограничением по количеству одновременных.

    :param tasks: список asyncio.Task
    :param limit: максимальное количество параллельных задач
    :return: результаты всех задач в виде списка
    """
    semaphore = asyncio.Semaphore(limit)

    async def sem_task(task: asyncio.Task):
        async with semaphore:
            try:
                return await task
            except Exception as e:
                logger.error(f"Ошибка выполнения задачи: {e}")
                return None

    wrapped_tasks = [sem_task(task) for task in tasks]
    results = await asyncio.gather(*wrapped_tasks)
    return results

def normalize_target(target: str) -> str:
    """
    Нормализует строку таргета (например, IP, URL).

    :param target: исходная строка
    :return: нормализованная строка
    """
    target = target.strip()
    if not target:
        raise ValueError("Пустой таргет")
    # Дополнительная логика нормализации, например, проверка формата IP или URL
    return target.lower()

def parse_ports(ports_str: str) -> List[int]:
    """
    Парсит строку с портами и диапазонами в список портов.

    Пример: "80,443,8000-8010" -> [80, 443, 8000, 8001, ..., 8010]

    :param ports_str: строка с портами
    :return: список портов
    """
    ports = set()
    parts = ports_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def format_scan_result(result: Dict) -> str:
    """
    Форматирует результат сканирования для удобного вывода.

    :param result: словарь с результатами
    :return: строка с форматированным результатом
    """
    lines = []
    for key, value in result.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines)

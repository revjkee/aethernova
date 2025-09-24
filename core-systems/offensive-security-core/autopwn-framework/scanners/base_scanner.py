# autopwn-framework/scanners/base_scanner.py

import abc
import logging
from typing import List, Dict, Optional, Any, Union
import asyncio
import datetime

logger = logging.getLogger("autopwn.scanner")
logger.setLevel(logging.DEBUG)


class ScanResult:
    def __init__(
        self,
        target: str,
        vulnerable: bool,
        evidence: Optional[Union[str, Dict[str, Any]]] = None,
        scanner_name: Optional[str] = None,
        timestamp: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.target = target
        self.vulnerable = vulnerable
        self.evidence = evidence
        self.scanner_name = scanner_name
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()
        self.extra = extra or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "scanner_name": self.scanner_name,
            "timestamp": self.timestamp,
            "extra": self.extra,
        }


class BaseScanner(abc.ABC):
    """
    Абстрактный базовый класс для всех сканеров в autopwn.
    Поддерживает асинхронную обработку, логирование, и расширяемость.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.validate_config(self.config)
        self.logger = logger.getChild(self.__class__.__name__)
        self.name = self.__class__.__name__
        self.timeout = self.config.get("timeout", 10)

    @staticmethod
    def validate_config(config: Dict[str, Any]):
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")

    async def scan(self, targets: List[str]) -> List[ScanResult]:
        """
        Асинхронный метод сканирования нескольких целей.
        Возвращает список результатов.
        """
        self.logger.debug(f"Запуск сканирования: {self.name} на {len(targets)} целях")
        tasks = [self.scan_target(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        final_results = []
        for result, target in zip(results, targets):
            if isinstance(result, Exception):
                self.logger.error(f"Ошибка сканирования {target}: {result}")
                continue
            final_results.append(result)
        return final_results

    async def scan_target(self, target: str) -> ScanResult:
        """
        Обработка одной цели. Может быть переопределена для специализированного поведения.
        """
        try:
            result = await self.run(target)
            if not isinstance(result, ScanResult):
                raise ValueError("Сканер должен возвращать объект ScanResult")
            return result
        except Exception as e:
            self.logger.exception(f"Ошибка при сканировании {target}")
            return ScanResult(
                target=target,
                vulnerable=False,
                evidence=str(e),
                scanner_name=self.name,
                extra={"error": True},
            )

    @abc.abstractmethod
    async def run(self, target: str) -> ScanResult:
        """
        Метод, реализуемый в потомках, который выполняет реальное сканирование цели.
        """
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """
        Возвращает метаданные сканера.
        """
        return {
            "name": self.name,
            "description": getattr(self, "description", "No description provided."),
            "version": getattr(self, "version", "1.0"),
            "author": getattr(self, "author", "Unknown"),
        }

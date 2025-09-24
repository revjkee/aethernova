# Подключение к ловушкам и внешним сенсорам
# honeypot_signals.py
# Сбор и обработка сигналов от honeypot-сетей и внешних сенсоров

import logging
import requests
import json
from datetime import datetime
from typing import Optional

logger = logging.getLogger("honeypot_signals")
logger.setLevel(logging.INFO)


class HoneypotSignalProcessor:
    def __init__(self, sources: list[dict]):
        """
        Инициализирует процессор сигналов от ловушек
        :param sources: список источников вида {"name": str, "url": str, "auth": Optional[str]}
        """
        self.sources = sources
        self.last_fetched = {}

    def fetch_signals(self) -> list[dict]:
        """
        Получает последние сигналы с honeypot-источников.
        :return: список сигналов
        """
        all_signals = []
        for source in self.sources:
            try:
                headers = {"Authorization": f"Bearer {source['auth']}"} if source.get("auth") else {}
                response = requests.get(source["url"], headers=headers, timeout=10)
                response.raise_for_status()
                signals = response.json()
                filtered = self._filter_new_signals(source["name"], signals)
                logger.info(f"[{source['name']}] получено сигналов: {len(filtered)}")
                all_signals.extend(filtered)
            except Exception as e:
                logger.warning(f"Ошибка получения сигналов из {source['name']}: {e}")
        return all_signals

    def _filter_new_signals(self, source_name: str, signals: list[dict]) -> list[dict]:
        """
        Убирает уже обработанные сигналы на основе времени.
        """
        last_time = self.last_fetched.get(source_name)
        new_signals = []
        for signal in signals:
            try:
                timestamp = datetime.fromisoformat(signal["timestamp"])
                if not last_time or timestamp > last_time:
                    new_signals.append(signal)
            except Exception as e:
                logger.debug(f"Неверный формат времени в сигнале: {e}")
        if new_signals:
            self.last_fetched[source_name] = datetime.fromisoformat(new_signals[-1]["timestamp"])
        return new_signals

    def analyze_signal(self, signal: dict) -> dict:
        """
        Базовый анализ сигнала. Может быть расширен при интеграции с threat_graph.
        :param signal: словарь сигнала
        :return: проанализированный результат
        """
        src_ip = signal.get("src_ip")
        vector = signal.get("attack_vector", "unknown")
        logger.info(f"Анализ атаки: IP={src_ip}, vector={vector}")
        return {
            "timestamp": signal.get("timestamp"),
            "src_ip": src_ip,
            "attack_vector": vector,
            "severity": self._estimate_severity(vector),
            "raw": signal,
        }

    def _estimate_severity(self, vector: str) -> str:
        """
        Примитивная оценка критичности.
        """
        high_risk_vectors = {"rce", "lfi", "priv_esc", "credentials"}
        if vector.lower() in high_risk_vectors:
            return "high"
        elif vector.lower() in {"scan", "ping", "connect"}:
            return "low"
        return "medium"

# risk_memory.py

import logging
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
import json

logger = logging.getLogger("risk_memory")
logger.setLevel(logging.INFO)


class RiskMemory:
    """
    Хранилище риск-событий:
    - Стоп-лоссы
    - Ошибки исполнения
    - Аномалии
    Используется для корректировки поведения торгового агента.
    """

    def __init__(self, storage_path: str = "logs/risk_events.jsonl"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: List[Dict[str, Any]] = []

    def log_event(self,
                  event_type: str,
                  symbol: str,
                  reason: str,
                  details: Optional[Dict[str, Any]] = None,
                  severity: str = "medium"):
        """
        Логирует риск-событие.
        """
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": event_type,
            "symbol": symbol,
            "reason": reason,
            "severity": severity,
            "details": details or {}
        }
        self._buffer.append(entry)
        self._persist(entry)
        logger.warning(f"[RISK] {event_type.upper()} @ {symbol} | {reason} | severity: {severity}")

    def _persist(self, entry: Dict[str, Any]):
        with self.storage_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def load_all(self) -> List[Dict[str, Any]]:
        if not self.storage_path.exists():
            return []
        with self.storage_path.open("r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def get_events_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.load_all() if e["type"] == event_type]

    def get_recent_events(self, count: int = 10) -> List[Dict[str, Any]]:
        return self.load_all()[-count:]

    def has_recent_stoploss(self, symbol: str, cooldown_seconds: int = 1800) -> bool:
        """
        Проверяет, был ли недавно срабатывающий стоп-лосс по символу.
        """
        cutoff = time.time() - cooldown_seconds
        events = self.get_events_by_type("stoploss")
        for e in reversed(events):
            if e["symbol"] == symbol:
                ts = time.mktime(time.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
                if ts >= cutoff:
                    return True
        return False

# trade_history.py

import json
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("trade_history")
logger.setLevel(logging.INFO)


class TradeHistory:
    """
    Хранилище истории торговых действий.
    Поддерживает запись, поиск, фильтрацию, экспорт и восстановление.
    """

    def __init__(self, storage_path: str = "logs/trade_log.jsonl"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: List[Dict[str, Any]] = []

    def log_trade(
        self,
        trade_id: str,
        timestamp: Optional[str],
        symbol: str,
        action: str,
        amount: float,
        price: float,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Запись одной сделки.
        """
        entry = {
            "id": trade_id,
            "timestamp": timestamp or datetime.utcnow().isoformat(),
            "symbol": symbol,
            "action": action,
            "amount": round(amount, 6),
            "price": round(price, 2),
            "confidence": round(confidence, 4),
            "metadata": metadata or {}
        }
        self._buffer.append(entry)
        self._persist(entry)
        logger.info(f"[TRADE] {action.upper()} {symbol} x{amount} @ {price} | conf: {confidence:.2f}")

    def _persist(self, entry: Dict[str, Any]):
        """
        Сохраняет одну запись в файл.
        """
        with self.storage_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def load_all(self) -> List[Dict[str, Any]]:
        """
        Загружает всю историю сделок.
        """
        if not self.storage_path.exists():
            return []

        with self.storage_path.open("r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def filter_by_symbol(self, symbol: str) -> List[Dict[str, Any]]:
        return [t for t in self.load_all() if t["symbol"] == symbol]

    def recent(self, n: int = 10) -> List[Dict[str, Any]]:
        return self.load_all()[-n:]

    def export_csv(self, output_path: str):
        """
        Экспортирует журнал в CSV.
        """
        import csv
        rows = self.load_all()
        if not rows:
            logger.warning("[TRADE HISTORY] Нет данных для экспорта.")
            return

        fieldnames = list(rows[0].keys())
        with open(output_path, mode="w", newline='', encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"[TRADE HISTORY] Экспортировано в CSV: {output_path}")

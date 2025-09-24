# trade_logger.py

import os
import json
import logging
import datetime
from pathlib import Path
from typing import Dict, Any, Optional

import pandas as pd

class TradeLogger:
    """
    Промышленный логгер сделок. Поддерживает:
    - сохранение в JSONL
    - экспорт в Parquet
    - стандартное логирование
    - отправку в observability-системы
    """

    def __init__(
        self,
        log_dir: str = "logs/trades",
        jsonl_filename: str = "executions.jsonl",
        enable_file_log: bool = True,
        enable_stdout: bool = True,
    ):
        self.log_dir = Path(log_dir)
        self.jsonl_path = self.log_dir / jsonl_filename
        self.enable_file_log = enable_file_log
        self.enable_stdout = enable_stdout
        self.entries = []

        self.logger = logging.getLogger("TradeLogger")
        self.logger.setLevel(logging.INFO)
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter("[%(levelname)s] %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _format_entry(self, trade_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            **trade_data
        }

    def log_trade(self, trade_data: Dict[str, Any]):
        """
        Логирует одну сделку в JSONL, stdout и сохраняет в память.
        """
        entry = self._format_entry(trade_data)
        self.entries.append(entry)

        if self.enable_file_log:
            with open(self.jsonl_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

        if self.enable_stdout:
            self.logger.info(f"[TRADE] {entry['timestamp']} | {entry.get('symbol', '')} | {entry.get('action', '')} | {entry.get('price', '')} | qty={entry.get('quantity', '')}")

    def export_to_parquet(self, filename: Optional[str] = None):
        """
        Экспортирует все сделки в Parquet-файл.
        """
        if not self.entries:
            self.logger.warning("Нет данных для экспорта.")
            return

        df = pd.DataFrame(self.entries)
        path = self.log_dir / (filename or "executions.parquet")
        df.to_parquet(path, index=False)
        self.logger.info(f"[EXPORT] {len(df)} сделок экспортировано в {path}")

    def clear_log(self):
        """
        Очищает накопленные сделки.
        """
        self.entries.clear()
        if self.jsonl_path.exists():
            self.jsonl_path.unlink()
        self.logger.info("[CLEAR] Все логи очищены.")

    def send_to_observability(self, callback: Optional[Any] = None):
        """
        Пример: можно переопределить отправку данных в Kafka/OpenTelemetry/Prometheus.
        """
        if callback:
            for entry in self.entries:
                try:
                    callback(entry)
                except Exception as e:
                    self.logger.error(f"[OBSERVABILITY ERROR] {e}")

# Пример использования:
# logger = TradeLogger()
# logger.log_trade({"symbol": "BTCUSDT", "action": "buy", "price": 29300, "quantity": 0.01, "confidence": 0.91})
# logger.export_to_parquet()

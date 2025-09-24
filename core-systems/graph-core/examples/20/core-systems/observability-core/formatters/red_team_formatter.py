# observability/dashboards/formatters/red_team_formatter.py

import logging
import json
from typing import Optional


class RedTeamFormatter(logging.Formatter):
    """
    Лог-форматтер для Red Team-операций.
    Включает поля: tactic, technique_id, signal, result, operator_id.
    """

    def __init__(self, use_json: bool = True):
        super().__init__()
        self.use_json = use_json

    def format(self, record: logging.LogRecord) -> str:
        log = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Red Team поля
        for key in [
            "experiment_id",
            "operator_id",
            "technique_id",
            "tactic",
            "signal",
            "result",
            "source",
            "target",
            "phase"
        ]:
            value = getattr(record, key, None)
            if value:
                log[key] = value

        if record.exc_info:
            log["exception"] = self.formatException(record.exc_info)

        return json.dumps(log, ensure_ascii=False) if self.use_json else self._format_human(log)

    def _format_human(self, log: dict) -> str:
        base = f"[{log['timestamp']}] [{log['level']}] [{log['logger']}]"
        base += f" [tactic={log.get('tactic')}] [technique={log.get('technique_id')}]"
        base += f" [result={log.get('result', '-')}] {log['message']}"
        if "operator_id" in log:
            base += f" [operator={log['operator_id']}]"
        if "signal" in log:
            base += f" [signal={log['signal']}]"
        return base

# trading_hours_policy.py

import pytz
import logging
from datetime import datetime, time
from typing import List, Tuple, Optional

logger = logging.getLogger("trading_hours_policy")
logger.setLevel(logging.INFO)


class TradingHoursPolicy:
    """
    Контролирует, разрешено ли в данный момент торговать:
    - по дням недели,
    - по времени суток,
    - с учётом таймзоны,
    - с учётом исключений (выходные, праздники).
    """

    def __init__(self,
                 allowed_weekdays: Optional[List[int]] = None,
                 allowed_time_ranges: Optional[List[Tuple[str, str]]] = None,
                 timezone: str = "UTC",
                 custom_blackouts: Optional[List[str]] = None):
        """
        allowed_weekdays: дни недели [0=Пн ... 6=Вс]
        allowed_time_ranges: интервалы в формате ("HH:MM", "HH:MM")
        timezone: строка таймзоны, напр. "Europe/Berlin"
        custom_blackouts: даты исключений, напр. ["2025-01-01", "2025-12-25"]
        """
        self.allowed_weekdays = allowed_weekdays or list(range(0, 5))  # по умолчанию: Пн–Пт
        self.allowed_time_ranges = allowed_time_ranges or [("00:00", "23:59")]
        self.timezone = pytz.timezone(timezone)
        self.custom_blackouts = set(custom_blackouts or [])

    def is_trading_allowed(self, current_dt: Optional[datetime] = None) -> bool:
        now = current_dt.astimezone(self.timezone) if current_dt else datetime.now(self.timezone)

        date_str = now.strftime("%Y-%m-%d")
        weekday = now.weekday()
        current_time = now.time()

        if date_str in self.custom_blackouts:
            logger.warning(f"[TRADING HOURS] День запрещён вручную: {date_str}")
            return False

        if weekday not in self.allowed_weekdays:
            logger.info(f"[TRADING HOURS] День недели запрещён: {weekday}")
            return False

        for start_str, end_str in self.allowed_time_ranges:
            start = self._parse_time(start_str)
            end = self._parse_time(end_str)
            if start <= current_time <= end:
                return True

        logger.info(f"[TRADING HOURS] Время вне допустимого интервала: {current_time}")
        return False

    def _parse_time(self, s: str) -> time:
        hour, minute = map(int, s.split(":"))
        return time(hour=hour, minute=minute)

    def describe(self) -> str:
        return (f"Торговые дни: {self.allowed_weekdays}, "
                f"Часы: {self.allowed_time_ranges}, "
                f"Чёрные даты: {sorted(self.custom_blackouts)}")


from datetime import datetime, timezone, timedelta

class TimeUtils:
    """
    Утилитарный класс для работы со временем в формате UTC с поддержкой таймзон и интервалов.
    Обеспечивает универсальные функции для конвертации, вычисления и форматирования времени.
    """

    @staticmethod
    def now_utc() -> datetime:
        """
        Текущее время в UTC с точностью до микросекунд.
        """
        return datetime.now(timezone.utc)

    @staticmethod
    def to_utc(dt: datetime) -> datetime:
        """
        Конвертация локального времени в UTC.
        Если передан уже UTC объект, возвращается без изменений.
        """
        if dt.tzinfo is None:
            raise ValueError("Datetime object must be timezone-aware")
        return dt.astimezone(timezone.utc)

    @staticmethod
    def from_iso8601(iso_str: str) -> datetime:
        """
        Парсинг строки в формате ISO 8601 в объект datetime с учетом часового пояса.
        """
        return datetime.fromisoformat(iso_str)

    @staticmethod
    def to_iso8601(dt: datetime) -> str:
        """
        Преобразование datetime в строку ISO 8601 с указанием UTC времени.
        """
        return dt.astimezone(timezone.utc).isoformat()

    @staticmethod
    def add_seconds(dt: datetime, seconds: int) -> datetime:
        """
        Добавить к дате указанное количество секунд.
        """
        return dt + timedelta(seconds=seconds)

    @staticmethod
    def diff_seconds(dt1: datetime, dt2: datetime) -> int:
        """
        Разница во времени между двумя datetime в секундах.
        """
        delta = dt1 - dt2
        return int(delta.total_seconds())

    @staticmethod
    def start_of_day(dt: datetime) -> datetime:
        """
        Возвращает начало дня (00:00:00) в той же временной зоне.
        """
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    @staticmethod
    def end_of_day(dt: datetime) -> datetime:
        """
        Возвращает конец дня (23:59:59.999999) в той же временной зоне.
        """
        return dt.replace(hour=23, minute=59, second=59, microsecond=999999)

from abc import ABC, abstractmethod

class BaseParser(ABC):
    """
    Абстрактный базовый класс для всех парсеров в системе OSINT.
    Определяет обязательный интерфейс и общие методы.
    """

    def __init__(self, source_url: str):
        """
        Инициализация парсера с исходным URL.
        :param source_url: URL ресурса для парсинга
        """
        self.source_url = source_url

    @abstractmethod
    def fetch_data(self) -> str:
        """
        Метод для получения сырых данных с ресурса.
        Возвращает данные в виде строки.
        """
        pass

    @abstractmethod
    def parse(self, raw_data: str) -> dict:
        """
        Метод для обработки и извлечения структурированной информации из сырых данных.
        Возвращает словарь с результатами парсинга.
        :param raw_data: Сырые данные для парсинга
        """
        pass

    def run(self) -> dict:
        """
        Общий метод для запуска парсинга: получает данные и парсит их.
        :return: Результат парсинга в виде словаря
        """
        raw = self.fetch_data()
        return self.parse(raw)

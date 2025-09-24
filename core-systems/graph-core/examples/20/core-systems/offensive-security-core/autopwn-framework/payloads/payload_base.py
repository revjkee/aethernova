# File: exploits/payloads/payload_base.py

from abc import ABC, abstractmethod


class PayloadBase(ABC):
    """
    Базовый класс для всех payload'ов эксплойтов.

    Определяет интерфейс и основные методы, которые должны быть реализованы
    в конкретных классах payload.
    """

    def __init__(self, target: str, port: int = 80, **kwargs):
        """
        Инициализация полезной нагрузки.

        :param target: адрес цели (IP или URL)
        :param port: порт цели
        :param kwargs: дополнительные параметры, зависящие от типа payload
        """
        self.target = target
        self.port = port
        self.params = kwargs

    @abstractmethod
    def prepare(self) -> bool:
        """
        Подготовка payload перед запуском.

        Например, генерация shellcode, подготовка команд и т.п.

        :return: True, если подготовка прошла успешно, иначе False
        """
        pass

    @abstractmethod
    def execute(self) -> bool:
        """
        Выполнение payload.

        Реализация конкретного способа доставки и запуска payload на цели.

        :return: True, если выполнение прошло успешно, иначе False
        """
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """
        Очистка следов payload после выполнения.

        По необходимости реализуется в наследниках.
        """
        pass

    def run(self) -> bool:
        """
        Основной метод для запуска payload: подготовка, выполнение и очистка.

        :return: True, если все шаги прошли успешно, иначе False
        """
        if not self.prepare():
            return False
        if not self.execute():
            return False
        self.cleanup()
        return True

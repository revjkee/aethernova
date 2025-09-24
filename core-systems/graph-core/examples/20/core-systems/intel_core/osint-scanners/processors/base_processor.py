class BaseProcessor:
    """
    Базовый класс для процессоров обработки данных OSINT.
    Служит шаблоном для реализации конкретных классов обработки,
    таких как фильтрация, нормализация, парсинг контента.
    """

    def __init__(self):
        pass

    def process(self, data):
        """
        Основной метод для обработки данных.

        :param data: Входные данные (например, сырой HTML, JSON, текст)
        :return: Обработанные данные
        """
        raise NotImplementedError("Метод process должен быть реализован в подклассе")

    def validate(self, data) -> bool:
        """
        Проверка корректности данных перед обработкой.

        :param data: Входные данные
        :return: True если данные валидны, иначе False
        """
        return data is not None

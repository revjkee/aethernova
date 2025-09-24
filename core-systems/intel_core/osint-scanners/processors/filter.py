from .base_processor import BaseProcessor

class DataFilter(BaseProcessor):
    """
    Класс для фильтрации данных в OSINT системе.
    Фильтрует входные данные по заданным правилам и критериям.
    """

    def __init__(self, filter_rules=None):
        """
        Инициализация фильтра с правилами.

        :param filter_rules: Список функций или лямбда, которые принимают данные и возвращают True/False
        """
        super().__init__()
        self.filter_rules = filter_rules or []

    def add_rule(self, rule):
        """
        Добавить новое правило фильтрации.

        :param rule: функция или лямбда, принимающая данные и возвращающая bool
        """
        self.filter_rules.append(rule)

    def process(self, data):
        """
        Применить фильтрацию ко входным данным.

        :param data: Список элементов данных для фильтрации
        :return: Отфильтрованный список данных
        """
        if not self.validate(data):
            return []

        filtered_data = []
        for item in data:
            if all(rule(item) for rule in self.filter_rules):
                filtered_data.append(item)
        return filtered_data

    def validate(self, data) -> bool:
        """
        Проверка корректности данных перед фильтрацией.

        :param data: Входные данные
        :return: True если данные - итерируемый список, иначе False
        """
        if data is None:
            return False
        try:
            iter(data)
            return True
        except TypeError:
            return False

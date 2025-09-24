from collections import Counter
from typing import List, Dict

class TokenizerStats:
    """
    Класс для сбора и анализа статистики токенизации текстов.
    Позволяет вычислять частоты токенов, среднюю длину токена и распределение.
    """

    def __init__(self):
        self.token_counts = Counter()
        self.total_tokens = 0

    def update_stats(self, tokens: List[str]) -> None:
        """
        Обновляет статистику, учитывая переданный список токенов.

        :param tokens: Список токенов, полученных при токенизации текста
        """
        self.token_counts.update(tokens)
        self.total_tokens += len(tokens)

    def most_common(self, n: int = 10) -> List[tuple]:
        """
        Возвращает n наиболее часто встречающихся токенов.

        :param n: Количество токенов для вывода
        :return: Список кортежей (токен, количество)
        """
        return self.token_counts.most_common(n)

    def average_token_length(self) -> float:
        """
        Вычисляет среднюю длину токена на основе имеющихся данных.

        :return: Средняя длина токена
        """
        total_length = sum(len(token) * count for token, count in self.token_counts.items())
        if self.total_tokens == 0:
            return 0.0
        return total_length / self.total_tokens

    def token_distribution(self) -> Dict[int, int]:
        """
        Возвращает распределение токенов по длинам.

        :return: Словарь {длина токена: количество токенов такой длины}
        """
        distribution = Counter(len(token) for token in self.token_counts)
        return dict(distribution)

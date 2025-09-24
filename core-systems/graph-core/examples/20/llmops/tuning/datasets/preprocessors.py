"""
llmops.tuning.datasets.preprocessors

Модуль трансформаций и предобработки датасетов:
- Токенизация с учётом разных токенизаторов
- Аугментация текстов (синтаксическая, лексическая)
- Нормализация и очистка данных
"""

from typing import List, Callable, Optional, Union
import random
import re
import logging

logger = logging.getLogger(__name__)

class TextPreprocessor:
    """
    Основной класс для последовательной обработки текста:
    нормализация, токенизация, аугментации.
    """

    def __init__(
        self,
        tokenizer: Callable[[str], List[str]],
        augmentations: Optional[List[Callable[[str], str]]] = None,
        lowercase: bool = True,
        remove_punctuation: bool = True,
    ):
        """
        :param tokenizer: функция токенизации текста в список токенов
        :param augmentations: список функций для аугментации текста
        :param lowercase: приводить ли текст к нижнему регистру
        :param remove_punctuation: удалять ли знаки препинания
        """
        self.tokenizer = tokenizer
        self.augmentations = augmentations or []
        self.lowercase = lowercase
        self.remove_punctuation = remove_punctuation

    def preprocess(self, text: str) -> List[str]:
        """
        Выполняет полный цикл обработки текста: 
        аугментация, очистка, токенизация.
        """
        original_text = text
        if self.lowercase:
            text = text.lower()
        if self.remove_punctuation:
            text = self._remove_punctuation(text)
        for aug in self.augmentations:
            text = aug(text)
        tokens = self.tokenizer(text)
        logger.debug(f"Preprocessed text: '{original_text}' -> tokens: {tokens}")
        return tokens

    @staticmethod
    def _remove_punctuation(text: str) -> str:
        return re.sub(r'[^\w\s]', '', text)


# Примеры простых аугментаций

def synonym_replacement(text: str, synonyms_dict: dict = None, p: float = 0.1) -> str:
    """
    Замена слов на синонимы с вероятностью p.
    :param synonyms_dict: словарь синонимов {слово: [синонимы]}
    :param p: вероятность замены каждого слова
    """
    if synonyms_dict is None:
        synonyms_dict = {}

    words = text.split()
    for i, word in enumerate(words):
        if word in synonyms_dict and random.random() < p:
            synonyms = synonyms_dict[word]
            if synonyms:
                words[i] = random.choice(synonyms)
    return ' '.join(words)


def random_deletion(text: str, p: float = 0.05) -> str:
    """
    Случайное удаление слов с вероятностью p.
    """
    words = text.split()
    if len(words) == 1:
        return text
    filtered = [w for w in words if random.random() > p]
    if not filtered:
        return random.choice(words)
    return ' '.join(filtered)


# Пример токенизатора (можно заменить на любой другой, например, HuggingFace tokenizer)

def simple_whitespace_tokenizer(text: str) -> List[str]:
    return text.strip().split()


if __name__ == "__main__":
    # Демонстрация использования
    synonyms = {
        'quick': ['fast', 'speedy'],
        'brown': ['dark', 'chocolate'],
        'fox': ['wolf', 'dog']
    }

    preprocessor = TextPreprocessor(
        tokenizer=simple_whitespace_tokenizer,
        augmentations=[
            lambda t: synonym_replacement(t, synonyms, p=0.3),
            random_deletion
        ],
        lowercase=True,
        remove_punctuation=True
    )

    sample_text = "The quick brown fox jumps over the lazy dog."
    tokens = preprocessor.preprocess(sample_text)
    print(tokens)

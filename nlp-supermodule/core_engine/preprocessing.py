"""
AetherNova NLP Supermodule - Text Preprocessing
Продвинутая предобработка текста для NLP задач
"""

import re
import unicodedata
import logging
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum


class NormalizationLevel(Enum):
    """Уровень нормализации текста"""
    LIGHT = "light"  # Минимальная нормализация
    MEDIUM = "medium"  # Стандартная нормализация
    AGGRESSIVE = "aggressive"  # Агрессивная нормализация


@dataclass
class PreprocessingConfig:
    """Конфигурация предобработки"""
    # Нормализация
    normalize_unicode: bool = True
    lowercase: bool = False
    remove_accents: bool = False
    
    # Очистка
    remove_urls: bool = True
    remove_emails: bool = True
    remove_phone_numbers: bool = False
    remove_numbers: bool = False
    remove_punctuation: bool = False
    remove_extra_whitespace: bool = True
    
    # HTML и разметка
    remove_html_tags: bool = True
    decode_html_entities: bool = True
    
    # Специальные символы
    remove_emojis: bool = False
    remove_special_chars: bool = False
    
    # Токенизация
    tokenize: bool = False
    
    # Стоп-слова
    remove_stopwords: bool = False
    stopwords_language: str = "english"
    custom_stopwords: List[str] = None
    
    # Расширенная обработка
    expand_contractions: bool = True
    correct_spelling: bool = False
    
    # Максимальная длина
    max_length: Optional[int] = None
    truncate_strategy: str = "end"  # "start", "end", "middle"


class TextPreprocessor:
    """
    Универсальный препроцессор текста для NLP задач
    
    Возможности:
    - Unicode нормализация
    - Удаление URL, email, телефонов
    - HTML очистка
    - Нормализация пробелов
    - Удаление специальных символов
    - Раскрытие сокращений
    - Удаление стоп-слов
    """
    
    # Регулярные выражения
    URL_PATTERN = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    PHONE_PATTERN = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
    HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
    EXTRA_WHITESPACE_PATTERN = re.compile(r'\s+')
    
    # Словарь сокращений (английский)
    CONTRACTIONS = {
        "ain't": "am not", "aren't": "are not", "can't": "cannot",
        "can't've": "cannot have", "could've": "could have",
        "couldn't": "could not", "didn't": "did not",
        "doesn't": "does not", "don't": "do not",
        "hadn't": "had not", "hasn't": "has not",
        "haven't": "have not", "he'd": "he would",
        "he'll": "he will", "he's": "he is",
        "i'd": "i would", "i'll": "i will",
        "i'm": "i am", "i've": "i have",
        "isn't": "is not", "it'd": "it would",
        "it'll": "it will", "it's": "it is",
        "let's": "let us", "shouldn't": "should not",
        "that's": "that is", "there's": "there is",
        "they'd": "they would", "they'll": "they will",
        "they're": "they are", "they've": "they have",
        "wasn't": "was not", "we'd": "we would",
        "we'll": "we will", "we're": "we are",
        "we've": "we have", "weren't": "were not",
        "what'll": "what will", "what're": "what are",
        "what's": "what is", "what've": "what have",
        "where's": "where is", "who'd": "who would",
        "who'll": "who will", "who're": "who are",
        "who's": "who is", "who've": "who have",
        "won't": "will not", "wouldn't": "would not",
        "you'd": "you would", "you'll": "you will",
        "you're": "you are", "you've": "you have"
    }
    
    # Emoji pattern
    EMOJI_PATTERN = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+",
        flags=re.UNICODE
    )
    
    def __init__(self, config: Optional[PreprocessingConfig] = None):
        self.config = config or PreprocessingConfig()
        self.logger = logging.getLogger(__name__)
        
        # Загрузка стоп-слов (если нужно)
        self.stopwords = set()
        if self.config.remove_stopwords:
            self._load_stopwords()
    
    def _load_stopwords(self):
        """Загрузка стоп-слов"""
        try:
            # Попытка использовать NLTK
            import nltk
            from nltk.corpus import stopwords
            
            try:
                self.stopwords = set(stopwords.words(self.config.stopwords_language))
            except LookupError:
                nltk.download('stopwords', quiet=True)
                self.stopwords = set(stopwords.words(self.config.stopwords_language))
            
            # Добавление кастомных стоп-слов
            if self.config.custom_stopwords:
                self.stopwords.update(self.config.custom_stopwords)
                
        except ImportError:
            self.logger.warning("NLTK не установлен, стоп-слова не будут удалены")
            self.stopwords = set(self.config.custom_stopwords or [])
    
    def preprocess(self, text: Union[str, List[str]]) -> Union[str, List[str]]:
        """
        Предобработка текста
        
        Args:
            text: Текст или список текстов
            
        Returns:
            Обработанный текст/тексты
        """
        if isinstance(text, list):
            return [self.preprocess_single(t) for t in text]
        return self.preprocess_single(text)
    
    def preprocess_single(self, text: str) -> str:
        """Предобработка одного текста"""
        if not text or not isinstance(text, str):
            return ""
        
        # Unicode нормализация
        if self.config.normalize_unicode:
            text = self._normalize_unicode(text)
        
        # HTML
        if self.config.remove_html_tags:
            text = self._remove_html_tags(text)
        
        if self.config.decode_html_entities:
            text = self._decode_html_entities(text)
        
        # URLs
        if self.config.remove_urls:
            text = self.URL_PATTERN.sub('', text)
        
        # Emails
        if self.config.remove_emails:
            text = self.EMAIL_PATTERN.sub('', text)
        
        # Телефоны
        if self.config.remove_phone_numbers:
            text = self.PHONE_PATTERN.sub('', text)
        
        # Раскрытие сокращений
        if self.config.expand_contractions:
            text = self._expand_contractions(text)
        
        # Lowercase
        if self.config.lowercase:
            text = text.lower()
        
        # Удаление акцентов
        if self.config.remove_accents:
            text = self._remove_accents(text)
        
        # Emojis
        if self.config.remove_emojis:
            text = self.EMOJI_PATTERN.sub('', text)
        
        # Числа
        if self.config.remove_numbers:
            text = re.sub(r'\d+', '', text)
        
        # Пунктуация
        if self.config.remove_punctuation:
            text = re.sub(r'[^\w\s]', '', text)
        
        # Специальные символы
        if self.config.remove_special_chars:
            text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        
        # Стоп-слова
        if self.config.remove_stopwords and self.stopwords:
            words = text.split()
            text = ' '.join([w for w in words if w.lower() not in self.stopwords])
        
        # Нормализация пробелов
        if self.config.remove_extra_whitespace:
            text = self.EXTRA_WHITESPACE_PATTERN.sub(' ', text).strip()
        
        # Обрезка по длине
        if self.config.max_length:
            text = self._truncate(text, self.config.max_length, self.config.truncate_strategy)
        
        return text
    
    def _normalize_unicode(self, text: str) -> str:
        """Unicode нормализация (NFC)"""
        return unicodedata.normalize('NFC', text)
    
    def _remove_html_tags(self, text: str) -> str:
        """Удаление HTML тегов"""
        return self.HTML_TAG_PATTERN.sub('', text)
    
    def _decode_html_entities(self, text: str) -> str:
        """Декодирование HTML сущностей"""
        import html
        return html.unescape(text)
    
    def _remove_accents(self, text: str) -> str:
        """Удаление акцентов (диакритических знаков)"""
        nfd = unicodedata.normalize('NFD', text)
        return ''.join(char for char in nfd if unicodedata.category(char) != 'Mn')
    
    def _expand_contractions(self, text: str) -> str:
        """Раскрытие английских сокращений"""
        # Сохраняем регистр
        words = text.split()
        expanded = []
        
        for word in words:
            lower_word = word.lower()
            if lower_word in self.CONTRACTIONS:
                # Сохраняем заглавные буквы
                expansion = self.CONTRACTIONS[lower_word]
                if word[0].isupper():
                    expansion = expansion.capitalize()
                expanded.append(expansion)
            else:
                expanded.append(word)
        
        return ' '.join(expanded)
    
    def _truncate(self, text: str, max_length: int, strategy: str) -> str:
        """Обрезка текста до максимальной длины"""
        if len(text) <= max_length:
            return text
        
        if strategy == "start":
            return text[:max_length]
        elif strategy == "end":
            return text[-max_length:]
        elif strategy == "middle":
            half = max_length // 2
            return text[:half] + text[-half:]
        else:
            return text[:max_length]
    
    def batch_preprocess(self, texts: List[str], batch_size: int = 32) -> List[str]:
        """Пакетная обработка текстов"""
        results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            results.extend([self.preprocess_single(text) for text in batch])
        return results


def create_light_preprocessor() -> TextPreprocessor:
    """Легкий препроцессор (минимальная обработка)"""
    config = PreprocessingConfig(
        normalize_unicode=True,
        remove_urls=True,
        remove_emails=True,
        remove_extra_whitespace=True,
        remove_html_tags=True,
        lowercase=False,
        remove_punctuation=False
    )
    return TextPreprocessor(config)


def create_standard_preprocessor() -> TextPreprocessor:
    """Стандартный препроцессор"""
    config = PreprocessingConfig(
        normalize_unicode=True,
        lowercase=True,
        remove_urls=True,
        remove_emails=True,
        remove_extra_whitespace=True,
        remove_html_tags=True,
        expand_contractions=True
    )
    return TextPreprocessor(config)


def create_aggressive_preprocessor() -> TextPreprocessor:
    """Агрессивный препроцессор (максимальная очистка)"""
    config = PreprocessingConfig(
        normalize_unicode=True,
        lowercase=True,
        remove_accents=True,
        remove_urls=True,
        remove_emails=True,
        remove_phone_numbers=True,
        remove_numbers=True,
        remove_punctuation=True,
        remove_extra_whitespace=True,
        remove_html_tags=True,
        remove_emojis=True,
        expand_contractions=True,
        remove_stopwords=True
    )
    return TextPreprocessor(config)


# Пример использования
def main():
    """Примеры использования препроцессора"""
    
    # Тестовый текст
    test_text = """
    <p>Hello! Check out this link: https://example.com 
    I can't believe it's already 2024! 😀
    Contact me at: test@example.com or call (555) 123-4567</p>
    """
    
    print("Исходный текст:")
    print(test_text)
    print("\n" + "="*60 + "\n")
    
    # Легкая обработка
    print("LIGHT preprocessing:")
    light_processor = create_light_preprocessor()
    print(light_processor.preprocess(test_text))
    print("\n" + "="*60 + "\n")
    
    # Стандартная обработка
    print("STANDARD preprocessing:")
    standard_processor = create_standard_preprocessor()
    print(standard_processor.preprocess(test_text))
    print("\n" + "="*60 + "\n")
    
    # Агрессивная обработка
    print("AGGRESSIVE preprocessing:")
    aggressive_processor = create_aggressive_preprocessor()
    print(aggressive_processor.preprocess(test_text))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()

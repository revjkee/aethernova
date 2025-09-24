# -*- coding: utf-8 -*-
"""
Wapiti scanner - reports utility functions
Author: Wapiti Team
License: GPLv2
"""

import json
import datetime
import os
import re
from html import escape

def format_datetime(dt):
    """
    Форматирует datetime объект в строку ISO 8601
    """
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def sanitize_filename(filename):
    """
    Удаляет или заменяет недопустимые символы из имени файла
    """
    filename = re.sub(r'[\\/:"*?<>|]+', '_', filename)
    return filename

def json_serialize(data):
    """
    Сериализация данных в JSON с отступами и сортировкой ключей
    """
    return json.dumps(data, indent=4, sort_keys=True, ensure_ascii=False)

def read_file(file_path, encoding='utf-8'):
    """
    Чтение файла с обработкой ошибок
    """
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except (IOError, OSError) as e:
        return None

def write_file(file_path, content, encoding='utf-8'):
    """
    Запись содержимого в файл с обработкой ошибок
    """
    try:
        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except (IOError, OSError) as e:
        return False

def ensure_dir_exists(path):
    """
    Проверяет наличие директории, если нет - создает
    """
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def escape_html(text):
    """
    Экранирует HTML символы в тексте для безопасного вывода в HTML отчетах
    """
    if text is None:
        return ''
    return escape(str(text), quote=True)

def truncate_text(text, length=100):
    """
    Обрезает текст до заданной длины с добавлением многоточия
    """
    if not text:
        return ''
    if len(text) <= length:
        return text
    return text[:length].rstrip() + '...'

def parse_severity(severity_str):
    """
    Преобразует строковое представление уровня уязвимости в числовой приоритет
    """
    mapping = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Info': 0
    }
    return mapping.get(severity_str, -1)

def sort_vulnerabilities(vulns):
    """
    Сортирует список уязвимостей по приоритету и имени
    """
    return sorted(vulns, key=lambda v: (-parse_severity(v.get('severity', 'Info')), v.get('name', '')))

def merge_dicts(a, b):
    """
    Рекурсивно объединяет два словаря
    """
    result = a.copy()
    for k, v in b.items():
        if (k in result and isinstance(result[k], dict) and isinstance(v, dict)):
            result[k] = merge_dicts(result[k], v)
        else:
            result[k] = v
    return result

def normalize_url(url):
    """
    Приводит URL к стандартному виду (без лишних пробелов и параметров)
    """
    if not url:
        return ''
    url = url.strip()
    url = re.sub(r'\s+', '', url)
    return url

def extract_domain(url):
    """
    Извлекает домен из URL
    """
    match = re.match(r'https?://([^/]+)', url)
    if match:
        return match.group(1)
    return ''

def generate_report_filename(base_name, extension='html'):
    """
    Генерирует безопасное имя файла отчета с расширением
    """
    base_name = sanitize_filename(base_name)
    return f"{base_name}.{extension}"

def convert_bytes_to_human_readable(num_bytes):
    """
    Конвертирует количество байт в удобочитаемый формат
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"

def is_valid_url(url):
    """
    Проверяет, является ли строка валидным URL
    """
    regex = re.compile(
        r'^(https?://)?'  # протокол http или https (необязательно)
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6})'  # доменное имя
        r'(:\d+)?'  # порт (необязательно)
        r'(/.*)?$',  # путь (необязательно)
        re.IGNORECASE)
    return re.match(regex, url) is not None


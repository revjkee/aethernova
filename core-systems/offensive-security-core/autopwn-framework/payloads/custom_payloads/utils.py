import os
import logging
from pathlib import Path
import stat

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

def is_executable(file_path: Path) -> bool:
    """
    Проверяет, имеет ли файл права на исполнение.
    """
    if not file_path.exists():
        logging.warning(f"Файл не существует: {file_path}")
        return False
    mode = file_path.stat().st_mode
    executable = bool(mode & stat.S_IXUSR)
    logging.debug(f"Проверка исполняемости для {file_path}: {executable}")
    return executable

def make_executable(file_path: Path):
    """
    Делает файл исполняемым (добавляет права на выполнение для владельца).
    """
    if not file_path.exists():
        logging.error(f"Файл не найден для установки прав: {file_path}")
        return
    mode = file_path.stat().st_mode
    file_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    logging.info(f"Права на выполнение установлены для файла: {file_path}")

def read_file(file_path: Path) -> str:
    """
    Читает содержимое файла и возвращает как строку.
    """
    if not file_path.exists():
        logging.error(f"Файл не найден для чтения: {file_path}")
        return ''
    try:
        with file_path.open('r', encoding='utf-8') as f:
            content = f.read()
        logging.debug(f"Файл успешно прочитан: {file_path}")
        return content
    except Exception as e:
        logging.error(f"Ошибка при чтении файла {file_path}: {e}")
        return ''

def write_file(file_path: Path, data: str):
    """
    Записывает данные в файл.
    """
    try:
        with file_path.open('w', encoding='utf-8') as f:
            f.write(data)
        logging.debug(f"Данные успешно записаны в файл: {file_path}")
    except Exception as e:
        logging.error(f"Ошибка при записи в файл {file_path}: {e}")

def safe_path_join(base_path: Path, *paths) -> Path:
    """
    Безопасно соединяет пути, предотвращая выход за пределы базового каталога.
    """
    combined_path = base_path.joinpath(*paths).resolve()
    if not str(combined_path).startswith(str(base_path.resolve())):
        raise ValueError(f"Попытка выхода за пределы базового каталога: {combined_path}")
    return combined_path

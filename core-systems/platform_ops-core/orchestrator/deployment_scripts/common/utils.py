import subprocess
import logging
import os
import sys
import json
from datetime import datetime

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_FILE = os.path.join(os.path.dirname(__file__), 'deployment.log')

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

def run_command(command, check=True, capture_output=True, shell=False):
    """
    Выполнить команду в shell или без него, вернуть stdout или выбросить исключение.
    """
    logging.info(f"Executing command: {' '.join(command) if isinstance(command, list) else command}")
    try:
        result = subprocess.run(
            command,
            shell=shell,
            check=check,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True
        )
        if capture_output:
            logging.info(f"Command output: {result.stdout.strip()}")
            if result.stderr:
                logging.warning(f"Command error output: {result.stderr.strip()}")
            return result.stdout.strip()
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}: {e.stderr.strip() if e.stderr else e}")
        if check:
            raise
        return None

def load_json_config(filepath):
    """
    Загрузить JSON конфиг из файла, вернуть словарь.
    """
    if not os.path.isfile(filepath):
        logging.error(f"Config file not found: {filepath}")
        raise FileNotFoundError(f"Config file not found: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Loaded config file: {filepath}")
        return data
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in config file {filepath}: {e}")
        raise

def save_json_config(filepath, data):
    """
    Сохранить словарь в JSON файл с отступами.
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"Saved config file: {filepath}")
    except Exception as e:
        logging.error(f"Failed to save config file {filepath}: {e}")
        raise

def ensure_directory(path):
    """
    Создать директорию, если её нет.
    """
    try:
        os.makedirs(path, exist_ok=True)
        logging.info(f"Directory ensured: {path}")
    except Exception as e:
        logging.error(f"Failed to create directory {path}: {e}")
        raise

def timestamp():
    """
    Возвращает текущую временную метку в формате YYYY-MM-DD_HH-MM-SS
    """
    return datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

def write_log(message, level='info'):
    """
    Записать сообщение в лог с указанным уровнем.
    """
    level = level.lower()
    if level == 'debug':
        logging.debug(message)
    elif level == 'warning':
        logging.warning(message)
    elif level == 'error':
        logging.error(message)
    else:
        logging.info(message)

def validate_path(path):
    """
    Проверка существования пути, выбрасывает исключение если нет.
    """
    if not os.path.exists(path):
        logging.error(f"Path does not exist: {path}")
        raise FileNotFoundError(f"Path does not exist: {path}")
    logging.info(f"Validated path exists: {path}")

def read_file(filepath):
    """
    Чтение файла и возврат содержимого.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        logging.info(f"Read file: {filepath}")
        return content
    except Exception as e:
        logging.error(f"Failed to read file {filepath}: {e}")
        raise

def write_file(filepath, content):
    """
    Запись контента в файл.
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        logging.info(f"Wrote file: {filepath}")
    except Exception as e:
        logging.error(f"Failed to write file {filepath}: {e}")
        raise

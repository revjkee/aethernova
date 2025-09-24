import os
import yaml
import json
from typing import Any, Dict, Optional

class ConfigLoaderError(Exception):
    pass

class ConfigLoader:
    def __init__(self, config_paths: Optional[list] = None):
        """
        Инициализация загрузчика с возможностью указания списка путей для поиска конфигурации.
        Последовательность загрузки: первый существующий файл из списка.
        """
        if config_paths is None:
            config_paths = [
                './config.yaml',
                './config.yml',
                './config.json',
                '/etc/deployment/config.yaml',
                '/etc/deployment/config.json',
            ]
        self.config_paths = config_paths
        self.config: Dict[str, Any] = {}

    def load(self) -> Dict[str, Any]:
        """
        Загрузка конфигурации из первого доступного файла.
        Поддержка YAML и JSON форматов.
        """
        for path in self.config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        if path.endswith(('.yaml', '.yml')):
                            self.config = yaml.safe_load(f)
                        elif path.endswith('.json'):
                            self.config = json.load(f)
                        else:
                            raise ConfigLoaderError(f"Unsupported config file format: {path}")
                    self._override_with_env_vars()
                    return self.config
                except Exception as e:
                    raise ConfigLoaderError(f"Failed to load config from {path}: {e}")
        raise ConfigLoaderError("No configuration file found in paths: " + ", ".join(self.config_paths))

    def _override_with_env_vars(self):
        """
        Переопределение настроек из переменных окружения.
        Поддерживается вложенный формат с разделителем '__', например:
        DEPLOY__TIMEOUT=30 -> config['deploy']['timeout'] = 30
        """
        for env_key, env_val in os.environ.items():
            if '__' in env_key:
                keys = env_key.lower().split('__')
                self._set_nested_config_value(self.config, keys, env_val)

    def _set_nested_config_value(self, d: Dict[str, Any], keys: list, value: Any):
        for key in keys[:-1]:
            if key not in d or not isinstance(d[key], dict):
                d[key] = {}
            d = d[key]
        d[keys[-1]] = self._parse_value(value)

    def _parse_value(self, val: str) -> Any:
        """
        Преобразование строкового значения из env в bool, int, float или оставляем строкой.
        """
        val_lower = val.lower()
        if val_lower in ('true', 'yes', 'on'):
            return True
        if val_lower in ('false', 'no', 'off'):
            return False
        try:
            if '.' in val:
                return float(val)
            return int(val)
        except ValueError:
            return val

    def get(self, key: str, default: Any = None) -> Any:
        """
        Получение значения по ключу с поддержкой вложенности через точку:
        e.g. 'deploy.timeout'
        """
        keys = key.split('.')
        current = self.config
        for k in keys:
            if not isinstance(current, dict) or k not in current:
                return default
            current = current[k]
        return current

# Глобальный экземпляр для использования в скриптах
config_loader = ConfigLoader()

def load_config() -> Dict[str, Any]:
    return config_loader.load()

def get_config(key: str, default: Any = None) -> Any:
    return config_loader.get(key, default)

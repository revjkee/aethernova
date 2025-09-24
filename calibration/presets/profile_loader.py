import os
import yaml
from typing import Any, Dict
from pathlib import Path

from calibration.core.validator import validate_profile
from calibration.rbac.policy_enforcer import enforce_profile_permissions

class ProfileLoaderError(Exception):
    pass

class ProfileValidationError(ProfileLoaderError):
    pass

class ProfilePermissionError(ProfileLoaderError):
    pass

class ProfileLoader:
    """
    Загрузчик YAML-профилей пресетов с полной валидацией и контролем доступа.
    Используется для загрузки параметров калибровки в систему CI/CD и runtime-ядро.
    """

    def __init__(self, presets_dir: Path):
        if not presets_dir.exists() or not presets_dir.is_dir():
            raise FileNotFoundError(f"Directory {presets_dir} not found or invalid")
        self.presets_dir = presets_dir.resolve()

    def load(self, filename: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Загружает и валидирует YAML-файл пресета по имени
        :param filename: имя файла (например: default_presets.yaml)
        :param context: контекст пользователя или CI-системы (для RBAC)
        :return: валидированные данные
        """
        filepath = self.presets_dir / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Preset file {filepath} not found")

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ProfileLoaderError(f"Failed to parse YAML: {e}")

        try:
            validate_profile(data)
        except Exception as e:
            raise ProfileValidationError(f"Validation failed: {e}")

        try:
            enforce_profile_permissions(data, context)
        except Exception as e:
            raise ProfilePermissionError(f"RBAC rejection: {e}")

        return data

    def list_available_profiles(self) -> list[str]:
        """
        Возвращает список всех YAML-профилей в директории
        """
        return [
            f.name for f in self.presets_dir.glob("*.yaml")
            if f.is_file()
        ]

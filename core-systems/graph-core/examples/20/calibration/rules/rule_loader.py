import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Union

from calibration.core.validator import validate_rule_schema
from calibration.rbac.policy_enforcer import enforce_rule_permissions


class RuleLoaderError(Exception):
    pass


class RuleValidationError(RuleLoaderError):
    pass


class RulePermissionError(RuleLoaderError):
    pass


class RuleLoader:
    """
    Надёжный загрузчик и валидатор калибровочных правил из .yaml и .json файлов.
    Обеспечивает полную проверку целостности, схемы и допуска (RBAC).
    """

    def __init__(self, rules_dir: Union[str, Path]):
        self.rules_dir = Path(rules_dir).resolve()
        if not self.rules_dir.exists() or not self.rules_dir.is_dir():
            raise FileNotFoundError(f"Invalid rules directory: {self.rules_dir}")

    def _read_file(self, filepath: Path) -> Dict[str, Any]:
        if not filepath.exists():
            raise FileNotFoundError(f"Rule file not found: {filepath}")

        try:
            if filepath.suffix in [".yaml", ".yml"]:
                with open(filepath, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            elif filepath.suffix == ".json":
                with open(filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                raise RuleLoaderError(f"Unsupported file format: {filepath.suffix}")
        except Exception as e:
            raise RuleLoaderError(f"Failed to read rule file: {e}")

    def load(self, filename: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Загружает правило и проводит его валидацию по схеме и RBAC
        :param filename: Имя правила (например: limits.yaml)
        :param context: Контекст безопасности (пользователь, роль, среда)
        :return: Структура правила
        """
        filepath = self.rules_dir / filename
        data = self._read_file(filepath)

        try:
            validate_rule_schema(data)
        except Exception as e:
            raise RuleValidationError(f"Schema validation failed: {e}")

        try:
            enforce_rule_permissions(data, context)
        except Exception as e:
            raise RulePermissionError(f"Access denied by RBAC: {e}")

        return data

    def list_rules(self) -> list[str]:
        """
        Возвращает список всех правил в директории
        """
        return sorted([
            f.name for f in self.rules_dir.glob("*")
            if f.suffix in [".yaml", ".yml", ".json"]
        ])

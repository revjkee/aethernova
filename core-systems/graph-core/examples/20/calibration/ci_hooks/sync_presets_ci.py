import os
import json
import logging
from pathlib import Path
from typing import Dict, Any

from calibration.core.parameter_space import ParameterSpace
from calibration.core.validator import Validator

logger = logging.getLogger("calibration.ci.sync")

PRESET_DIR = Path(__file__).parent.parent / "presets"
CI_ENV = os.getenv("CI", "false").lower() == "true"


def load_presets() -> Dict[str, Dict[str, Any]]:
    """
    Загружает все пресеты калибровки из папки presets
    """
    presets = {}
    for file in PRESET_DIR.glob("*.json"):
        with open(file, "r", encoding="utf-8") as f:
            try:
                preset = json.load(f)
                presets[file.stem] = preset
                logger.debug(f"Загружен пресет: {file.name}")
            except Exception as e:
                logger.error(f"Ошибка чтения {file.name}: {e}")
    return presets


def sync_presets(presets: Dict[str, Dict[str, Any]]) -> None:
    """
    Синхронизирует пресеты в CI/CD: валидирует и записывает в актуальное состояние
    """
    for name, config in presets.items():
        try:
            space = ParameterSpace.from_dict(config)
            Validator.validate_parameter_space(space)
            output_file = PRESET_DIR / f"{name}.validated.json"

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(space.to_dict(), f, indent=2, ensure_ascii=False)
                logger.info(f"[CI-SYNC] Обновлён пресет: {name}")
        except Exception as e:
            logger.warning(f"[CI-SYNC] Ошибка в пресете {name}: {e}")


def run_ci_sync():
    """
    Основной CI-хук. Запускается только при CI/CD окружении.
    """
    if not CI_ENV:
        logger.info("Пропуск CI-синхронизации: переменная CI не установлена")
        return

    logger.info("Запуск CI-синхронизации пресетов...")
    presets = load_presets()
    sync_presets(presets)
    logger.info("CI-синхронизация завершена")


if __name__ == "__main__":
    run_ci_sync()

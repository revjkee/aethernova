import json
import logging
import os
from typing import Any, Dict, List, Union
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from functools import wraps

from rich.logging import RichHandler


# ──────────────── [ Advanced Logger Setup ] ────────────────

def setup_logger(
    name: str = "eval-core",
    level: Union[int, str] = logging.INFO,
    use_rich: bool = True
) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        return logger

    logger.setLevel(level)
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

    if use_rich:
        handler = RichHandler(rich_tracebacks=True, show_time=False)
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = setup_logger()


# ──────────────── [ Safe JSON Helpers ] ────────────────

def load_json(path: Union[str, Path]) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON from {path}: {e}")
        return None


def save_json(data: Any, path: Union[str, Path], indent: int = 2) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
        logger.debug(f"Saved JSON to {path}")
    except Exception as e:
        logger.error(f"Error saving JSON to {path}: {e}")


# ──────────────── [ Dict Merge / Deep Merge ] ────────────────

def deep_merge(dict1: Dict, dict2: Dict) -> Dict:
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ──────────────── [ Aggregators ] ────────────────

def average_scores(results: List[Dict[str, float]]) -> Dict[str, float]:
    aggregator = defaultdict(list)
    for result in results:
        for key, value in result.items():
            aggregator[key].append(value)

    return {k: sum(v) / len(v) if v else 0.0 for k, v in aggregator.items()}


# ──────────────── [ Decorators ] ────────────────

def safe_exec(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Exception in {func.__name__}: {e}")
            return None
    return wrapper


# ──────────────── [ Path Utils ] ────────────────

def ensure_dir(path: Union[str, Path]) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def timestamped_filename(base: str, ext: str = "json") -> str:
    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{base}_{now}.{ext}"

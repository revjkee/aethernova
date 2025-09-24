# utils/path_utils.py

import os
from pathlib import Path
from typing import Optional, Union


ALIAS_ROOTS = {
    "@root": Path(__file__).resolve().parent.parent,
    "@data": Path(__file__).resolve().parent.parent / "data",
    "@models": Path(__file__).resolve().parent.parent / "mlops" / "registry",
    "@logs": Path(__file__).resolve().parent.parent / "logs"
}


class UnsafePathError(Exception):
    pass


def expand_path(alias_path: str) -> Path:
    """
    Заменяет алиасы на абсолютные пути

    Args:
        alias_path (str): путь с alias, например '@data/model.json'

    Returns:
        Path: абсолютный безопасный путь
    """
    for alias, base in ALIAS_ROOTS.items():
        if alias_path.startswith(alias):
            sub_path = alias_path[len(alias):].lstrip("/\\")
            return (base / sub_path).resolve()

    return Path(alias_path).resolve()


def is_safe_path(base: Union[str, Path], target: Union[str, Path]) -> bool:
    """
    Проверка, что target находится внутри base (без выхода за пределы)

    Returns:
        bool
    """
    base = Path(base).resolve()
    target = Path(target).resolve()
    return str(target).startswith(str(base))


def safe_join(base: Union[str, Path], *paths: str) -> Path:
    """
    Безопасное объединение путей с защитой от выхода вверх

    Returns:
        Path
    """
    base = Path(base).resolve()
    result = base.joinpath(*paths).resolve()

    if not is_safe_path(base, result):
        raise UnsafePathError(f"Unsafe path traversal detected: {result}")
    return result


def rel_path(target: Union[str, Path], start: Optional[Union[str, Path]] = None) -> str:
    """
    Относительный путь от start до target

    Returns:
        str
    """
    target = Path(target).resolve()
    start = Path(start).resolve() if start else Path.cwd()
    return os.path.relpath(str(target), str(start))


def ensure_dir(path: Union[str, Path]):
    """
    Создаёт директорию, если её нет

    Args:
        path: путь к директории
    """
    Path(path).mkdir(parents=True, exist_ok=True)

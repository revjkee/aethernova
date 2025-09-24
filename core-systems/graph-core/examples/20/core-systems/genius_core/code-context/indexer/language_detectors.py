# genius-core/code-context/indexer/language_detectors.py

import re
from pathlib import Path

EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".html": "html",
    ".css": "css",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".xml": "xml",
    ".swift": "swift",
    ".kt": "kotlin",
    ".sql": "sql",
    ".scala": "scala",
    ".sh": "shell",
    ".bat": "batch",
    ".dockerfile": "docker",
    ".r": "r",
    ".lua": "lua"
}

# Эвристика по содержимому файла
LANGUAGE_KEYWORDS = {
    "python": ["def ", "import ", "self", "from ", "async ", "await"],
    "javascript": ["function", "console.log", "var ", "let ", "const "],
    "java": ["public class", "void main", "System.out"],
    "cpp": ["#include", "std::", "int main("],
    "go": ["func ", "package ", "import "],
    "rust": ["fn ", "let ", "::", "mod "],
    "php": ["<?php", "$_GET", "$_POST"],
    "csharp": ["using System", "namespace", "public class"]
}


def detect_language(file_name: str, code_snippet: str = "") -> str:
    ext = Path(file_name).suffix.lower()

    # Попытка по расширению
    if ext in EXTENSION_LANGUAGE_MAP:
        return EXTENSION_LANGUAGE_MAP[ext]

    # Попытка по названию (Dockerfile, Makefile)
    base = Path(file_name).name.lower()
    if "dockerfile" in base:
        return "docker"
    if "makefile" in base:
        return "make"

    # Эвристика по содержимому
    for lang, keywords in LANGUAGE_KEYWORDS.items():
        if any(kw in code_snippet for kw in keywords):
            return lang

    # Попытка fallback через guesslang (если установлен)
    try:
        from guesslang import Guess
        guess = Guess()
        return guess.language_name(code_snippet).lower()
    except Exception:
        return "unknown"

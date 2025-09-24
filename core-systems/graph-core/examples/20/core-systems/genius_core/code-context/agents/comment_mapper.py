# genius-core/code-context/agents/comment_mapper.py

import ast
import re
from pathlib import Path
from typing import Dict, List, Tuple


class CommentMapper:
    def __init__(self):
        self.comment_pattern = re.compile(r"^\s*#(.*)")

    def extract_comments(self, lines: List[str]) -> List[Tuple[int, str]]:
        """
        Возвращает список кортежей (номер строки, текст комментария)
        """
        comments = []
        for idx, line in enumerate(lines):
            match = self.comment_pattern.match(line)
            if match:
                comments.append((idx, match.group(1).strip()))
        return comments

    def parse_code_entities(self, source: str) -> List[Dict]:
        """
        AST-анализ: возвращает все функции и классы с координатами
        """
        result = []
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    result.append({
                        "type": type(node).__name__,
                        "name": node.name,
                        "start": node.lineno - 1,
                        "end": getattr(node, "end_lineno", node.lineno + 5),
                        "doc": ast.get_docstring(node)
                    })
        except Exception as e:
            result.append({"error": f"AST Parse error: {e}"})
        return result

    def associate_comments(self, filepath: Path) -> Dict[str, List[str]]:
        """
        Сопоставляет комментарии с функциями/классами
        """
        code = filepath.read_text(encoding="utf-8")
        lines = code.splitlines()
        comments = self.extract_comments(lines)
        entities = self.parse_code_entities(code)
        mapping = {}

        for entity in entities:
            name = f"{entity['type']}::{entity['name']}"
            entity_comments = []
            for lineno, comment in comments:
                if entity["start"] - 3 <= lineno <= entity["start"]:
                    entity_comments.append(comment)
            if entity["doc"]:
                entity_comments.append(entity["doc"])
            mapping[name] = entity_comments

        return mapping

    def generate_comment_map(self, project_root: Path) -> Dict[str, Dict[str, List[str]]]:
        """
        Обрабатывает все Python-файлы в проекте и строит карту комментариев
        """
        all_maps = {}
        for py_file in project_root.rglob("*.py"):
            if "test" in py_file.parts:
                continue
            result = self.associate_comments(py_file)
            all_maps[str(py_file)] = result
        return all_maps

# genius-core/code-enhancement/syntax-autofix/cve_fixer.py

import ast
import astor
from typing import List, Tuple

class CVEFixer(ast.NodeTransformer):
    """
    Класс для автоматического исправления известных уязвимостей (CVE) в Python-коде.
    На основе анализа AST вносит корректировки для устранения уязвимых паттернов.
    """

    def __init__(self):
        super().__init__()
        self.fixes_applied: List[str] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST:
        # Пример фикса: запрет импорта небезопасных модулей (например, deprecated модули)
        if node.module == "pickle":
            self.fixes_applied.append("Removed import from pickle module (unsafe)")
            return None  # Удаляем импорт pickle (примитивный пример)
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        # Пример фикса: замена вызовов eval на ast.literal_eval
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.fixes_applied.append("Replaced eval call with ast.literal_eval")
            node.func.id = "literal_eval"
            return node
        return self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        # Пример фикса: запрет использования os.system, заменить на subprocess.run
        if (
            isinstance(node.value, ast.Name) and
            node.value.id == "os" and
            node.attr == "system"
        ):
            self.fixes_applied.append("Flagged use of os.system (consider replacing with subprocess.run)")
            # Можно сделать замену, но для безопасности оставим флаг
        return node

    def fix_code(self, source_code: str) -> Tuple[str, List[str]]:
        """
        Применяет фиксы к исходному коду и возвращает исправленный код и список изменений.
        """
        tree = ast.parse(source_code)
        fixed_tree = self.visit(tree)
        fixed_code = astor.to_source(fixed_tree)
        return fixed_code, self.fixes_applied




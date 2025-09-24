# genius-core/code-enhancement/lint-learners/learner_v2.py

import ast
from typing import List, Dict, Any, Optional

class LintLearnerV2:
    """
    Улучшенный обучающий модуль для анализа Python кода с использованием AST.
    Обнаруживает проблемы, даёт рекомендации, собирает статистику и обучается на найденных ошибках.
    Сохраняет все старые проверки, добавляет новые.
    """

    def __init__(self):
        self.issues: List[Dict[str, Any]] = []
        self.function_lengths: List[int] = []
        self.docstring_missing_count: int = 0
        self.imports_warned: List[str] = []

    def analyze_code(self, code: str) -> List[Dict[str, Any]]:
        """
        Анализирует исходный код и возвращает список найденных проблем.
        """
        self.issues.clear()
        self.function_lengths.clear()
        self.docstring_missing_count = 0
        self.imports_warned.clear()

        try:
            tree = ast.parse(code)
            self._visit_nodes(tree)
            self._learn_from_analysis()
        except SyntaxError as e:
            self.issues.append({
                "type": "SyntaxError",
                "message": str(e),
                "lineno": e.lineno,
                "offset": e.offset,
                "recommendation": "Проверьте синтаксис кода."
            })
        return self.issues

    def _visit_nodes(self, node: ast.AST):
        """
        Рекурсивный обход AST с проверками узлов.
        """
        for child in ast.iter_child_nodes(node):
            self._check_node(child)
            self._visit_nodes(child)

    def _check_node(self, node: ast.AST):
        """
        Проверяет отдельный AST-узел.
        """
        if isinstance(node, ast.FunctionDef):
            self._check_function(node)
        elif isinstance(node, ast.Import):
            self._check_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._check_import_from(node)
        elif isinstance(node, ast.Assign):
            self._check_assignment(node)
        elif isinstance(node, ast.Call):
            self._check_call(node)
        # Можно добавить дополнительные проверки

    def _check_function(self, node: ast.FunctionDef):
        """
        Проверка функции:
        - слишком длинное тело
        - отсутствие docstring
        """
        body_len = len(node.body)
        self.function_lengths.append(body_len)

        if body_len > 50:
            self.issues.append({
                "type": "LongFunction",
                "message": f"Функция '{node.name}' слишком длинная ({body_len} строк).",
                "lineno": node.lineno,
                "recommendation": "Разбейте функцию на более мелкие."
            })

        # Проверка docstring: в Python 3.8+ docstring - это ast.Constant, в старых версиях ast.Str
        first_stmt = node.body[0] if node.body else None
        if not (first_stmt and isinstance(first_stmt, ast.Expr) and 
                (isinstance(first_stmt.value, ast.Str) or 
                 (hasattr(ast, 'Constant') and isinstance(first_stmt.value, ast.Constant) and isinstance(first_stmt.value.value, str)))):
            self.docstring_missing_count += 1
            self.issues.append({
                "type": "MissingDocstring",
                "message": f"В функции '{node.name}' отсутствует docstring.",
                "lineno": node.lineno,
                "recommendation": "Добавьте описание функции в docstring."
            })

    def _check_import(self, node: ast.Import):
        """
        Проверка импортов: предупреждение по потенциально неиспользуемым модулям.
        """
        for alias in node.names:
            mod_name = alias.name
            if mod_name not in self.imports_warned:
                self.imports_warned.append(mod_name)
                self.issues.append({
                    "type": "ImportWarning",
                    "message": f"Проверьте использование модуля '{mod_name}'.",
                    "lineno": node.lineno,
                    "recommendation": "Удалите неиспользуемые импорты."
                })

    def _check_import_from(self, node: ast.ImportFrom):
        """
        Аналогично проверка для from ... import ...
        """
        mod_name = node.module if node.module else ""
        if mod_name and mod_name not in self.imports_warned:
            self.imports_warned.append(mod_name)
            self.issues.append({
                "type": "ImportWarning",
                "message": f"Проверьте использование модуля '{mod_name}'.",
                "lineno": node.lineno,
                "recommendation": "Удалите неиспользуемые импорты."
            })

    def _check_assignment(self, node: ast.Assign):
        """
        Можно расширить для выявления неиспользуемых переменных, дублирующих имен и т.п.
        Пока не реализовано.
        """
        pass

    def _check_call(self, node: ast.Call):
        """
        Предупреждения для опасных функций, например eval.
        """
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.issues.append({
                "type": "EvalUsage",
                "message": "Использование 'eval' - потенциальный риск безопасности.",
                "lineno": node.lineno,
                "recommendation": "Избегайте использования eval или применяйте с осторожностью."
            })

    def _learn_from_analysis(self):
        """
        Пример функции обучения: может собирать статистику, обновлять модели и т.п.
        Пока просто выводит базовую статистику.
        """
        if self.function_lengths:
            avg_len = sum(self.function_lengths) / len(self.function_lengths)
            self.issues.append({
                "type": "Statistics",
                "message": f"Средняя длина функции: {avg_len:.2f} строк."
            })
        if self.docstring_missing_count > 0:
            self.issues.append({
                "type": "Statistics",
                "message": f"Функций без docstring: {self.docstring_missing_count}."
            })


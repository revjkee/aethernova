# genius-core/code-context/indexer/symbol_graph_builder.py

import ast
from typing import Any, Dict, List


class SymbolNode:
    def __init__(self, name: str, type_: str, lineno: int, parent: str = None):
        self.name = name
        self.type = type_
        self.lineno = lineno
        self.parent = parent
        self.calls: List[str] = []
        self.children: List["SymbolNode"] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "lineno": self.lineno,
            "parent": self.parent,
            "calls": self.calls,
            "children": [child.to_dict() for child in self.children]
        }


class SymbolGraphBuilder(ast.NodeVisitor):
    def __init__(self):
        self.graph: Dict[str, SymbolNode] = {}
        self.current_parent: str = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        fn_name = node.name
        symbol = SymbolNode(name=fn_name, type_="function", lineno=node.lineno, parent=self.current_parent)
        if self.current_parent:
            self.graph[self.current_parent].children.append(symbol)
        self.graph[fn_name] = symbol

        previous_parent = self.current_parent
        self.current_parent = fn_name
        self.generic_visit(node)
        self.current_parent = previous_parent

    def visit_ClassDef(self, node: ast.ClassDef):
        cls_name = node.name
        symbol = SymbolNode(name=cls_name, type_="class", lineno=node.lineno, parent=self.current_parent)
        symbol.base_classes = [b.id for b in node.bases if isinstance(b, ast.Name)]

        if self.current_parent:
            self.graph[self.current_parent].children.append(symbol)
        self.graph[cls_name] = symbol

        previous_parent = self.current_parent
        self.current_parent = cls_name
        self.generic_visit(node)
        self.current_parent = previous_parent

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            imp_node = SymbolNode(name=alias.name, type_="import", lineno=node.lineno)
            self.graph[f"import::{alias.name}"] = imp_node

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            full_name = f"{module}.{alias.name}"
            imp_node = SymbolNode(name=full_name, type_="import_from", lineno=node.lineno)
            self.graph[f"import::{full_name}"] = imp_node

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        else:
            call_name = "unknown"

        if self.current_parent and call_name != "unknown":
            self.graph[self.current_parent].calls.append(call_name)
        self.generic_visit(node)


def build_symbol_graph(ast_tree: ast.AST) -> Dict[str, Any]:
    builder = SymbolGraphBuilder()
    builder.visit(ast_tree)
    return {k: v.to_dict() for k, v in builder.graph.items()}

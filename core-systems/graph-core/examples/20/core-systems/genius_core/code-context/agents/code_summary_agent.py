# genius-core/code-context/agents/code_summary_agent.py

import ast
import os
from pathlib import Path
from typing import List, Dict, Union, Optional
from rich import print
from genius_core.code_context.agents.context_expander import ContextExpander
from genius_core.code_context.plugins.claude_plugin import ClaudeClient


class CodeSummaryAgent:
    def __init__(
        self,
        model: str = "claude-3-opus",
        index_path: Path = Path("data/code_context_index.json"),
        max_chunk_len: int = 1500,
        fallback_llm: Optional[str] = "gpt-4"
    ):
        self.context_expander = ContextExpander(index_path)
        self.llm = ClaudeClient(model=model)
        self.fallback_model = fallback_llm
        self.max_chunk_len = max_chunk_len

    def _parse_ast(self, source: str) -> List[Dict]:
        """
        Собирает все classes/functions с их docstring и началом-концом блока.
        """
        result = []
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = node.lineno - 1
                    end = getattr(node, 'end_lineno', start + 1)
                    doc = ast.get_docstring(node) or ""
                    name = getattr(node, 'name', 'unknown')
                    result.append({
                        "type": node.__class__.__name__,
                        "name": name,
                        "start": start,
                        "end": end,
                        "doc": doc
                    })
        except Exception as e:
            print(f"[red]AST parse error:[/] {e}")
        return result

    def _summarize_block(self, block: str, name: str, type_: str) -> str:
        prompt = (
            f"Ты — агент автодокументирования. Проанализируй этот фрагмент Python кода типа {type_} "
            f"под названием `{name}` и опиши его кратко: назначение, входные данные, результат. "
            f"Добавь описание поведения, если возможно.\n\n"
            f"```python\n{block}\n```"
        )
        try:
            return self.llm.query(prompt)
        except Exception as e:
            print(f"[yellow]Claude fallback error:[/] {e}")
            if self.fallback_model:
                from openai import ChatCompletion
                return ChatCompletion.create(
                    model=self.fallback_model,
                    messages=[{"role": "user", "content": prompt}]
                )["choices"][0]["message"]["content"]
            return f"[LLM ERROR] {e}"

    def summarize_file(self, filepath: Path) -> Dict[str, str]:
        lines = filepath.read_text(encoding="utf-8").splitlines()
        source = "\n".join(lines)
        summary = {}
        for block in self._parse_ast(source):
            code_chunk = "\n".join(lines[block["start"]:block["end"] + 1])
            key = f"{block['type']}::{block['name']}"
            summary[key] = self._summarize_block(code_chunk, block['name'], block['type'])
        return summary

    def summarize_symbol(self, symbol_name: str) -> str:
        expanded = self.context_expander.expand(symbol_name)
        code = self.context_expander.extract_code_context(expanded)
        return self._summarize_block(code, symbol_name, "semantic block")

    def batch(self, root: Path) -> Dict[str, Dict[str, str]]:
        summaries = {}
        for py_file in root.rglob("*.py"):
            if "test" in py_file.parts or "venv" in py_file.parts:
                continue
            summaries[str(py_file)] = self.summarize_file(py_file)
        return summaries

# genius-core/code-context/indexer/index_engine.py

import os
import ast
import json
import hashlib
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List

from genius_core.code_context.indexer.language_detectors import detect_language
from genius_core.code_context.indexer.symbol_graph_builder import build_symbol_graph
from genius_core.code_context.sync.dag_tracker import compute_merkle_hash
from genius_core.code_context.search.semantic_search import embed_code_snippet

INDEX_PATH = Path("genius-core/code-context/data/code_context_index.json")


class CodeIndexer:
    def __init__(self, root_dir: str, index_path: Path = INDEX_PATH):
        self.root_dir = Path(root_dir)
        self.index_path = index_path
        self.index_data: Dict[str, Any] = {}

    def index_project(self):
        source_files = list(self.root_dir.rglob("*.py"))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = executor.map(self.process_file, source_files)
        for item in results:
            if item:
                self.index_data[item["path"]] = item

        self.save_index()
        print(f"[✓] Indexed {len(self.index_data)} files")

    def process_file(self, file_path: Path) -> Dict[str, Any] | None:
        try:
            code = file_path.read_text(encoding="utf-8")
            lang = detect_language(file_path.name)
            ast_tree = ast.parse(code)

            symbol_graph = build_symbol_graph(ast_tree)
            merkle_hash = compute_merkle_hash(code)
            embedding = embed_code_snippet(code)

            return {
                "path": str(file_path),
                "language": lang,
                "hash": merkle_hash,
                "symbols": symbol_graph,
                "embedding": embedding,
                "lines": len(code.splitlines())
            }
        except Exception as e:
            print(f"[x] Failed to index {file_path}: {str(e)}")
            return None

    def save_index(self):
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump(self.index_data, f, indent=2)

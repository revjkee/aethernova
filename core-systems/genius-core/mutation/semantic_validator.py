# genius_core/mutation/semantic_validator.py

import ast
import json
import logging
from typing import Dict, List, Any, Tuple

from genius_core.mutation.mutation_observer import MutationObserver
from genius_core.mutation.memory_archive import SemanticMemory

logger = logging.getLogger("SemanticValidator")


class SemanticValidator:
    def __init__(self, memory: SemanticMemory = None, strict_mode: bool = True):
        self.observer = MutationObserver()
        self.memory = memory or SemanticMemory()
        self.strict_mode = strict_mode
        self.rule_set = self._load_semantic_rules()

    def _load_semantic_rules(self) -> List[Dict[str, Any]]:
        try:
            with open("genius_core/mutation/semantic_rules.json", "r") as f:
                rules = json.load(f)
                logger.info(f"Semantic rules loaded: {len(rules)}")
                return rules
        except Exception as e:
            logger.error(f"Failed to load semantic rules: {str(e)}")
            return []

    def validate(self, file_path: str, mutation_id: str) -> Dict[str, Any]:
        try:
            with open(file_path, "r") as f:
                source = f.read()
            tree = ast.parse(source)
        except Exception as e:
            logger.error(f"AST parsing failed for {file_path}: {str(e)}")
            return self._report(mutation_id, "syntax_error", passed=False, extra={"error": str(e)})

        rule_violations = self._check_rules(tree)
        memory_conflicts = self._check_semantic_memory(tree)

        if rule_violations or memory_conflicts:
            all_issues = rule_violations + memory_conflicts
            self.observer.flag_violation(mutation_id, all_issues)
            logger.warning(f"[{mutation_id}] Semantic violations detected: {len(all_issues)}")
            return self._report(mutation_id, "semantic_violation", passed=False, extra={"issues": all_issues})

        logger.info(f"[{mutation_id}] Semantic validation passed.")
        return self._report(mutation_id, "validated", passed=True)

    def _check_rules(self, tree: ast.AST) -> List[Dict[str, Any]]:
        violations = []
        for rule in self.rule_set:
            node_type = getattr(ast, rule.get("node_type", ""), None)
            if node_type is None:
                continue
            for node in ast.walk(tree):
                if isinstance(node, node_type):
                    if "name_must_not_contain" in rule and hasattr(node, "name"):
                        if any(substr in node.name for substr in rule["name_must_not_contain"]):
                            violations.append({
                                "rule": rule,
                                "node": getattr(node, "name", "<unknown>")
                            })
        return violations

    def _check_semantic_memory(self, tree: ast.AST) -> List[Dict[str, Any]]:
        if not self.memory.enabled:
            return []
        return self.memory.validate_ast(tree)

    def _report(self, mutation_id: str, tag: str, passed: bool, extra: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {
            "mutation_id": mutation_id,
            "status": "passed" if passed else "failed",
            "tag": tag,
            "strict_mode": self.strict_mode,
        }
        if extra:
            result.update(extra)
        return result

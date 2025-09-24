# AI-platform-core/genius-core/symbolic-reasoning/concept_mapper.py

import logging
from typing import Dict, Any, List, Optional

from genius_core.symbolic_reasoning.symbol_graph import SymbolGraph

logger = logging.getLogger("ConceptMapper")

class ConceptMapper:
    """
    Модуль преобразования наблюдаемых сущностей, событий и сигналов в абстрактные концепты для SymbolGraph.
    Используется для формализации восприятия, интерпретации текстов, обобщений и логических выводов.
    """

    def __init__(self, graph: SymbolGraph):
        self.graph = graph
        self.mapping_rules: List[Dict[str, Any]] = []

    def define_mapping_rule(self, trigger_keywords: List[str], concept_name: str, concept_type: str, relations: Optional[Dict[str, str]] = None):
        rule = {
            "keywords": trigger_keywords,
            "concept": concept_name,
            "type": concept_type,
            "relations": relations or {}
        }
        self.mapping_rules.append(rule)
        logger.info(f"[ConceptMapper] Новое правило: {concept_name} <- {trigger_keywords}")

    def map_input(self, text: str) -> List[str]:
        """
        Извлекает концепты из текста или описания события
        """
        detected_concepts = []

        for rule in self.mapping_rules:
            if any(kw.lower() in text.lower() for kw in rule["keywords"]):
                if rule["concept"] not in self.graph.nodes:
                    self.graph.add_node(rule["concept"], rule["type"])
                for rel, target in rule["relations"].items():
                    self.graph.add_node(target, "concept")
                    self.graph.add_relation(rule["concept"], rel, target)
                detected_concepts.append(rule["concept"])
                logger.debug(f"[ConceptMapper] Обнаружен концепт: {rule['concept']} из текста: '{text}'")

        return detected_concepts

    def batch_map_inputs(self, inputs: List[str]) -> List[List[str]]:
        return [self.map_input(inp) for inp in inputs]

    def load_rules(self, rules: List[Dict[str, Any]]):
        for rule in rules:
            self.define_mapping_rule(
                trigger_keywords=rule.get("keywords", []),
                concept_name=rule.get("concept", ""),
                concept_type=rule.get("type", "abstract"),
                relations=rule.get("relations", {})
            )

    def export_rules(self) -> List[Dict[str, Any]]:
        return self.mapping_rules.copy()

# genius-core/generative-defense/mitre-mapper/mitre_map.py

import json
from typing import Dict, List, Optional

class MitreMapper:
    """
    Класс для работы с данными MITRE ATT&CK:
    - загрузка базы техник и тактик
    - поиск техник по ID
    - генерация связей между тактиками и техниками
    """

    def __init__(self, mitre_json_path: str):
        self.data = self._load_mitre_data(mitre_json_path)
        self.techniques = self._extract_techniques()
        self.tactics = self._extract_tactics()

    def _load_mitre_data(self, path: str) -> Dict:
        """
        Загружает JSON с MITRE ATT&CK в формате STIX.
        """
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _extract_techniques(self) -> Dict[str, Dict]:
        """
        Извлекает техники из данных MITRE по их ID.
        """
        techniques = {}
        for obj in self.data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                techniques[obj["id"]] = obj
        return techniques

    def _extract_tactics(self) -> Dict[str, Dict]:
        """
        Извлекает тактики из данных MITRE.
        """
        tactics = {}
        for obj in self.data.get("objects", []):
            if obj.get("type") == "x-mitre-tactic":
                tactics[obj["id"]] = obj
        return tactics

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """
        Возвращает данные техники по ID.
        """
        return self.techniques.get(technique_id)

    def map_tactic_to_techniques(self, tactic_id: str) -> List[Dict]:
        """
        Возвращает список техник, относящихся к заданной тактике.
        """
        related_techniques = []
        for tech in self.techniques.values():
            if "x_mitre_tactics" in tech:
                if tactic_id in tech["x_mitre_tactics"]:
                    related_techniques.append(tech)
        return related_techniques

    def get_tactic_name(self, tactic_id: str) -> Optional[str]:
        """
        Возвращает название тактики по её ID.
        """
        tactic = self.tactics.get(tactic_id)
        if tactic:
            return tactic.get("name")
        return None


# Пример использования
if __name__ == "__main__":
    mitre_path = "data/mitre_attack.json"
    mapper = MitreMapper(mitre_path)

    tactic_id = "x-mitre-tactic-defense-evasion"
    techniques = mapper.map_tactic_to_techniques(tactic_id)

    print(f"Техники для тактики {mapper.get_tactic_name(tactic_id)}:")
    for tech in techniques:
        print(f"- {tech.get('name')} ({tech.get('id')})")

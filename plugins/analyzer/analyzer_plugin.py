from typing import Any, Dict, List, Optional
from plugins.core.base_plugin import BasePlugin
from plugins.utils.plugin_logger import plugin_logger as logger


class AnalyzerPlugin(BasePlugin):
    """
    Продвинутый плагин анализа входящих данных и генерации отчётов.
    Поддерживает кастомные правила и адаптивные стратегии обработки.
    """

    plugin_name = "AdvancedAnalyzer"
    plugin_version = "2.0.0"
    plugin_author = "TeslaAI Genesis"
    plugin_description = "Анализирует входные данные, выявляет аномалии и формирует отчёт."
    plugin_dependencies = {
        "pandas": ">=1.5.0",
        "scikit-learn": ">=1.3.0"
    }

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = []
        self.sandbox_mode = True  # включена изоляция

    def load_rules(self, rules: List[Dict[str, Any]]):
        """
        Загружает кастомные правила анализа.
        """
        self.rules = rules
        logger.info(f"[{self.plugin_name}] Загружено правил: {len(rules)}")

    def analyze(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Основной метод анализа. Использует загруженные правила.
        """
        results = []
        for record in data:
            issues = self.apply_rules(record)
            results.append({
                "input": record,
                "issues": issues
            })
        return {
            "plugin": self.plugin_name,
            "total": len(results),
            "findings": results
        }

    def apply_rules(self, record: Dict[str, Any]) -> List[str]:
        """
        Применяет правила к одной записи.
        """
        findings = []
        for rule in self.rules:
            field = rule.get("field")
            condition = rule.get("condition")
            threshold = rule.get("threshold")
            value = record.get(field)

            if condition == "gt" and value > threshold:
                findings.append(f"{field} > {threshold}")
            elif condition == "lt" and value < threshold:
                findings.append(f"{field} < {threshold}")
            elif condition == "eq" and value == threshold:
                findings.append(f"{field} == {threshold}")
        return findings

    def generate_report(self, findings: Dict[str, Any]) -> str:
        """
        Формирует строковый отчёт по результатам анализа.
        """
        report_lines = [f"Plugin: {self.plugin_name} — Findings Report"]
        for entry in findings["findings"]:
            issues = entry["issues"]
            if issues:
                report_lines.append(f"- Entry: {entry['input']}")
                for issue in issues:
                    report_lines.append(f"  ⚠ {issue}")
        return "\n".join(report_lines)

    def run(self, input_data: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Точка входа. Принимает входные данные, выполняет анализ, возвращает отчёт.
        """
        logger.info(f"[{self.plugin_name}] Начало анализа...")
        findings = self.analyze(input_data)
        report = self.generate_report(findings)
        logger.info(f"[{self.plugin_name}] Завершение анализа")
        return report

# ai-core/defense-suggester/suggest_defense_v2.py

from typing import List, Dict, Any, Optional
import datetime

class DefenseSuggesterV2:
    """
    Улучшенный модуль генерации рекомендаций по защите на основе анализа угроз и поведения атак.
    Включает контекстный анализ, приоритизацию рисков и адаптивные меры.
    """

    def __init__(self, threat_database: Optional[List[Dict[str, Any]]] = None):
        """
        :param threat_database: База известных угроз и уязвимостей с рекомендациями
        """
        self.threat_database = threat_database if threat_database else self._load_default_threats()
        self.recommendations_history: List[Dict[str, Any]] = []

    def _load_default_threats(self) -> List[Dict[str, Any]]:
        """
        Загружает базовые угрозы с типовыми рекомендациями.
        """
        return [
            {
                "threat": "phishing",
                "severity": 7,
                "recommendations": [
                    "Внедрить многофакторную аутентификацию",
                    "Проводить регулярное обучение сотрудников",
                    "Использовать фильтры спама и антифишинговые решения"
                ]
            },
            {
                "threat": "ransomware",
                "severity": 9,
                "recommendations": [
                    "Регулярно создавать резервные копии данных",
                    "Обновлять ПО и патчи безопасности",
                    "Ограничивать права пользователей"
                ]
            },
            {
                "threat": "sql_injection",
                "severity": 8,
                "recommendations": [
                    "Использовать параметризированные запросы",
                    "Проводить аудит кода и тестирование безопасности",
                    "Применять WAF"
                ]
            },
            {
                "threat": "ddos",
                "severity": 6,
                "recommendations": [
                    "Внедрить системы фильтрации и балансировки нагрузки",
                    "Использовать CDN с защитой от DDoS",
                    "Мониторить сетевой трафик"
                ]
            }
        ]

    def suggest_defenses(
        self,
        detected_threats: List[str],
        system_profile: Optional[Dict[str, Any]] = None,
        max_recommendations: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Генерирует список рекомендаций по защите на основе обнаруженных угроз и профиля системы.

        :param detected_threats: Список идентификаторов угроз (строки)
        :param system_profile: Профиль системы с параметрами защиты и критичности
        :param max_recommendations: Максимальное число рекомендаций в ответе
        :return: Список рекомендаций с приоритетом и описанием
        """

        if system_profile is None:
            system_profile = {}

        recommendations = []

        for threat_name in detected_threats:
            threat_info = self._find_threat_info(threat_name)
            if not threat_info:
                continue

            severity = threat_info.get("severity", 5)
            adjusted_severity = self._adjust_severity(severity, system_profile)

            for rec in threat_info.get("recommendations", []):
                recommendations.append({
                    "threat": threat_name,
                    "recommendation": rec,
                    "severity": adjusted_severity,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                })

        # Сортировка по убыванию важности (severity)
        recommendations.sort(key=lambda x: x["severity"], reverse=True)

        # Уникализация рекомендаций по тексту
        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec["recommendation"] not in seen:
                seen.add(rec["recommendation"])
                unique_recs.append(rec)
            if len(unique_recs) >= max_recommendations:
                break

        self.recommendations_history.extend(unique_recs)

        return unique_recs

    def _find_threat_info(self, threat_name: str) -> Optional[Dict[str, Any]]:
        """
        Поиск информации об угрозе по имени.
        """
        for threat in self.threat_database:
            if threat["threat"] == threat_name:
                return threat
        return None

    def _adjust_severity(self, base_severity: int, system_profile: Dict[str, Any]) -> int:
        """
        Корректировка важности угрозы с учетом параметров системы.
        Например, повышаем при отсутствии определенных защит.

        :param base_severity: Базовый уровень угрозы
        :param system_profile: Параметры системы (например, {"mfa_enabled": True, "backup_policy": False})
        :return: Скорректированный уровень важности
        """
        severity = base_severity

        if not system_profile.get("mfa_enabled", True) and base_severity >= 7:
            severity += 1

        if not system_profile.get("backup_policy", True) and base_severity >= 8:
            severity += 1

        if system_profile.get("network_monitoring", False) is False and base_severity >= 6:
            severity += 1

        return min(severity, 10)

    def reset_history(self):
        """
        Очистить историю рекомендаций.
        """
        self.recommendations_history.clear()

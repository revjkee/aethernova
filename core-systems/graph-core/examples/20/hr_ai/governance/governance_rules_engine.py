# onchain/dao-governance/governance_rules_engine.py

from typing import Dict, List, Any, Callable, Optional
import datetime

class GovernanceRulesEngine:
    """
    Новый: расширенный движок управления правилами DAO.
    Обрабатывает правила голосований, кворумов, временных ограничений, ролей и условий.
    Позволяет добавлять, изменять и проверять правила динамически.
    """

    def __init__(self):
        # Хранилище правил: rule_name -> rule_definition
        self.rules: Dict[str, Dict[str, Any]] = {}

        # Хранилище пользовательских проверок (callback)
        self.custom_checks: Dict[str, Callable[..., bool]] = {}

    def add_rule(self, name: str, definition: Dict[str, Any]) -> None:
        """
        Добавляет или обновляет правило по имени.
        Определение должно содержать ключи, описывающие логику.
        Пример: {"type": "quorum", "min_votes": 100, "time_limit_hours": 24}
        """
        self.rules[name] = definition

    def remove_rule(self, name: str) -> None:
        """
        Удаляет правило по имени, если оно существует.
        """
        if name in self.rules:
            del self.rules[name]

    def register_custom_check(self, name: str, func: Callable[..., bool]) -> None:
        """
        Регистрирует пользовательскую функцию проверки.
        """
        self.custom_checks[name] = func

    def evaluate_rule(self, name: str, context: Dict[str, Any]) -> bool:
        """
        Оценивает правило по имени в заданном контексте.
        Возвращает True, если правило выполнено, иначе False.
        """
        if name not in self.rules:
            raise ValueError(f"Rule '{name}' not found")

        rule = self.rules[name]
        rule_type = rule.get("type")

        if rule_type == "quorum":
            return self._check_quorum(rule, context)
        elif rule_type == "time_limit":
            return self._check_time_limit(rule, context)
        elif rule_type == "role_required":
            return self._check_role_required(rule, context)
        elif rule_type == "custom":
            return self._evaluate_custom(rule, context)
        else:
            raise NotImplementedError(f"Rule type '{rule_type}' not implemented")

    def _check_quorum(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Проверка кворума голосования.
        context должен содержать 'votes_count' (int).
        """
        min_votes = rule.get("min_votes", 1)
        votes_count = context.get("votes_count", 0)
        return votes_count >= min_votes

    def _check_time_limit(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Проверка ограничения по времени голосования.
        rule должен содержать 'time_limit_hours'.
        context должен содержать 'start_time' (datetime).
        """
        time_limit_hours = rule.get("time_limit_hours")
        start_time = context.get("start_time")
        if not start_time or not isinstance(start_time, datetime.datetime):
            return False
        now = datetime.datetime.utcnow()
        elapsed = now - start_time
        return elapsed.total_seconds() <= time_limit_hours * 3600

    def _check_role_required(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Проверка, что пользователь имеет нужную роль.
        rule должен содержать 'roles' - список разрешённых ролей.
        context должен содержать 'user_role' (str).
        """
        allowed_roles = rule.get("roles", [])
        user_role = context.get("user_role")
        return user_role in allowed_roles

    def _evaluate_custom(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Выполнение пользовательской проверки.
        rule должен содержать 'check_name' - имя зарегистрированной функции.
        """
        check_name = rule.get("check_name")
        if check_name not in self.custom_checks:
            raise ValueError(f"Custom check '{check_name}' not registered")
        return self.custom_checks[check_name](context)

    def evaluate_all(self, context: Dict[str, Any]) -> Dict[str, bool]:
        """
        Оценивает все правила и возвращает словарь результатов.
        """
        results = {}
        for name in self.rules:
            try:
                results[name] = self.evaluate_rule(name, context)
            except Exception as e:
                results[name] = False
        return results



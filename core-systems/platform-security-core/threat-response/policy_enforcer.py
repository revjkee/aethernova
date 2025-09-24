import logging
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class PolicyDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # MFA, biometric etc.


class AccessContext:
    """
    Контекст запроса доступа. Передаётся из API/бота/модуля.
    """
    def __init__(self, user_id: str, resource: str, action: str, role: str,
                 metadata: Optional[Dict[str, Any]] = None):
        self.user_id = user_id
        self.resource = resource
        self.action = action
        self.role = role
        self.timestamp = datetime.utcnow()
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "resource": self.resource,
            "action": self.action,
            "role": self.role,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


class PolicyRule:
    def __init__(self, roles: List[str], resources: List[str], actions: List[str],
                 conditions: Optional[List[str]] = None,
                 enforcement: PolicyDecision = PolicyDecision.DENY):
        self.roles = roles
        self.resources = resources
        self.actions = actions
        self.conditions = conditions or []
        self.enforcement = enforcement


class PolicyEnforcer:
    """
    Главный компонент контроля выполнения политик доступа.
    """

    def __init__(self):
        self.rules: List[PolicyRule] = []
        self._load_default_policies()

    def _load_default_policies(self):
        """
        Базовые политики безопасности. Можно заменить загрузкой из DB/Redis.
        """
        self.rules.append(PolicyRule(
            roles=["admin"],
            resources=["*"],
            actions=["*"],
            enforcement=PolicyDecision.ALLOW
        ))

        self.rules.append(PolicyRule(
            roles=["user"],
            resources=["/secure/upload", "/internal/audit"],
            actions=["POST", "DELETE"],
            enforcement=PolicyDecision.DENY
        ))

        self.rules.append(PolicyRule(
            roles=["auditor"],
            resources=["/internal/audit"],
            actions=["GET"],
            enforcement=PolicyDecision.ALLOW
        ))

    def enforce(self, context: AccessContext) -> PolicyDecision:
        """
        Выполняет проверку доступа по текущему контексту.
        """
        for rule in self.rules:
            if context.role not in rule.roles:
                continue
            if not self._match_resource(context.resource, rule.resources):
                continue
            if context.action not in rule.actions and "*" not in rule.actions:
                continue
            if not self._evaluate_conditions(rule.conditions, context):
                continue

            logger.info(f"Access decision: {rule.enforcement.value} for {context.user_id} to {context.resource}")
            return rule.enforcement

        logger.warning(f"No matching policy. DENY access to {context.user_id} for {context.resource}")
        return PolicyDecision.DENY

    def _match_resource(self, res: str, patterns: List[str]) -> bool:
        for p in patterns:
            if p == "*" or res.startswith(p):
                return True
        return False

    def _evaluate_conditions(self, conditions: List[str], context: AccessContext) -> bool:
        """
        Условия в стиле DSL: "ip == 127.0.0.1", "country != RU"
        """
        for cond in conditions:
            try:
                key, op, value = re.split(r"\s*(==|!=)\s*", cond)
                actual = str(context.metadata.get(key.strip()))
                expected = value.strip()
                if op == "==" and actual != expected:
                    return False
                if op == "!=" and actual == expected:
                    return False
            except Exception as e:
                logger.error(f"Condition parse error: {cond} - {e}")
                return False
        return True

    def add_rule(self, rule: PolicyRule):
        self.rules.append(rule)

    def clear_rules(self):
        self.rules.clear()

    def list_rules(self) -> List[Dict[str, Any]]:
        return [{
            "roles": r.roles,
            "resources": r.resources,
            "actions": r.actions,
            "enforcement": r.enforcement.value,
            "conditions": r.conditions
        } for r in self.rules]


# Экспорт
__all__ = ["PolicyEnforcer", "PolicyDecision", "AccessContext", "PolicyRule"]

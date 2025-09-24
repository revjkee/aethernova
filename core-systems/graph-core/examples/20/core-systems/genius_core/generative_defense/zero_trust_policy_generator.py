# genius-core/generative-defense/zero_trust_policy_generator.py

from typing import List, Dict, Optional
import json

class ZeroTrustPolicyGenerator:
    """
    Генератор политик нулевого доверия (Zero Trust),
    основанных на входных данных о пользователях, ресурсах и сетевых событиях.
    """

    def __init__(self):
        self.policies: List[Dict] = []

    def generate_policy(self, user_id: str, resource_id: str, context: Dict) -> Dict:
        """
        Создаёт политику доступа с минимальными правами, основанную на контексте.
        
        Args:
            user_id: Идентификатор пользователя.
            resource_id: Идентификатор ресурса.
            context: Контекст доступа (время, устройство, гео и т.п.)
        
        Returns:
            Политика в виде словаря.
        """
        policy = {
            "user": user_id,
            "resource": resource_id,
            "permissions": self._determine_permissions(context),
            "conditions": self._extract_conditions(context),
            "enforce": True
        }
        self.policies.append(policy)
        return policy

    def _determine_permissions(self, context: Dict) -> List[str]:
        """
        Определяет минимально необходимые права доступа на основе контекста.
        """
        perms = []
        if context.get("role") == "admin":
            perms = ["read", "write", "delete"]
        elif context.get("role") == "user":
            perms = ["read"]
        else:
            perms = []
        # Можно расширять логику под условия контекста
        return perms

    def _extract_conditions(self, context: Dict) -> Dict:
        """
        Извлекает условия для политики (например, время суток, IP, устройство).
        """
        conditions = {}
        if "time" in context:
            conditions["time"] = context["time"]
        if "ip" in context:
            conditions["ip"] = context["ip"]
        if "device" in context:
            conditions["device"] = context["device"]
        return conditions

    def export_policies(self, path: Optional[str] = None) -> str:
        """
        Экспортирует все сгенерированные политики в JSON.
        Если указан путь — сохраняет в файл.
        """
        policies_json = json.dumps(self.policies, indent=2)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(policies_json)
        return policies_json


# Пример использования
if __name__ == "__main__":
    generator = ZeroTrustPolicyGenerator()
    policy = generator.generate_policy(
        user_id="user123",
        resource_id="server01",
        context={"role": "user", "time": "09:00-18:00", "ip": "192.168.1.10", "device": "laptop"}
    )
    print("Сгенерированная политика:")
    print(policy)

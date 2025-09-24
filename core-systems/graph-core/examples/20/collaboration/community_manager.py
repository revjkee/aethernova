# path: backend/collaboration/community_manager.py

import logging
import datetime
from security.rbac import enforce_policy
from security.trust_index import update_trust_score
from utils.alerting import notify_guard
from storage import reputation_db, activity_log
from ai_guard.analysis import detect_sabotage, detect_sybil_attack

# === Конфигурация ===
LOG_FILE = "/var/log/teslaai/community_manager.log"
TRUST_THRESHOLD_BAN = 0.2
TRUST_THRESHOLD_ALERT = 0.4

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s"
)

class CommunityManager:
    def __init__(self):
        self.trust_db = reputation_db
        self.activity_log = activity_log

    def register_contribution(self, user_id: str, action: str, context: dict):
        try:
            if not enforce_policy(user_id, "contribute", action):
                raise PermissionError(f"User {user_id} not allowed to perform {action}")

            timestamp = datetime.datetime.utcnow().isoformat()
            self.activity_log.append({
                "user_id": user_id,
                "action": action,
                "context": context,
                "timestamp": timestamp
            })

            trust_delta = self.evaluate_action(action, context)
            update_trust_score(user_id, trust_delta)

            new_score = self.trust_db.get(user_id, 0.5)
            self.react_to_score(user_id, new_score)

            logging.info(f"[REGISTER] {user_id} | {action} | Δ={trust_delta:.2f} | new={new_score:.2f}")

        except Exception as e:
            logging.error(f"[ERROR] register_contribution: {e}")
            notify_guard("community_exception", str(e), user=user_id, critical=True)

    def evaluate_action(self, action: str, context: dict) -> float:
        """Оценка действия по вкладности, полезности, манипуляции."""
        if detect_sybil_attack(context):
            return -1.0
        if detect_sabotage(context):
            return -0.7
        if action in ("code_push", "patch_review"):
            return +0.3
        if action in ("spam", "self_promote"):
            return -0.4
        return 0.0

    def react_to_score(self, user_id: str, score: float):
        if score < TRUST_THRESHOLD_BAN:
            notify_guard("user_ban", f"Trust score too low: {score}", user=user_id, critical=True)
            self.trust_db.set_flag(user_id, "banned", True)
        elif score < TRUST_THRESHOLD_ALERT:
            notify_guard("user_alert", f"Low trust warning: {score}", user=user_id, critical=False)

    def get_trust_score(self, user_id: str) -> float:
        return self.trust_db.get(user_id, 0.5)

    def is_banned(self, user_id: str) -> bool:
        return self.trust_db.get_flag(user_id, "banned", False)

# === Пример вызова интерфейса ===
if __name__ == "__main__":
    cm = CommunityManager()
    cm.register_contribution(
        user_id="user_x321",
        action="code_push",
        context={"lines_added": 142, "project": "anon-core"}
    )

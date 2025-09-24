# zk-core/zk/zk_policy_enforcer.py

import logging
from functools import wraps
from typing import Callable, Dict, Any

from zk.zk_proof_verifier import ZKProofVerifier
from zk.zk_registry import ActionRegistry
from zk.zk_intent_verifier import verify_intent_proof
from zk.zk_access_control import check_zk_access
from zk.zk_utils import hash_action_payload

logger = logging.getLogger("zk_policy_enforcer")
logger.setLevel(logging.INFO)


class ZKPolicyEnforcer:
    def __init__(self):
        self.verifier = ZKProofVerifier()
        self.registry = ActionRegistry()
        self.intent_enabled = True
        self.enforced_actions_cache: Dict[str, bool] = {}

    def enforce(self, action_name: str) -> Callable:
        """
        Decorator that enforces ZK proof validation on the specified action.
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                request_context = kwargs.get("context", {})
                proof = request_context.get("zk_proof")
                user_id = request_context.get("user_id")

                # Step 1: Check if action is registered
                if not self.registry.is_registered(action_name):
                    logger.warning(f"Unregistered action attempted: {action_name}")
                    raise PermissionError("Action not authorized")

                # Step 2: Validate proof using verifier
                payload_hash = hash_action_payload(args, kwargs)
                if not self.verifier.verify(proof=proof, expected_hash=payload_hash):
                    logger.error(f"ZK proof failed for action: {action_name}")
                    raise PermissionError("Invalid ZK proof")

                # Step 3: Optional AI intent verification
                if self.intent_enabled and not verify_intent_proof(user_id, action_name, proof):
                    logger.error(f"AI intent verification failed for user {user_id}")
                    raise PermissionError("Invalid intent")

                # Step 4: Optional access check (e.g., DAO role / NFT)
                if not check_zk_access(user_id, action_name):
                    logger.warning(f"ZK access denied for user {user_id} on {action_name}")
                    raise PermissionError("Access denied via ZK")

                # Step 5: Log successful enforcement
                self._cache_enforcement(action_name)
                logger.info(f"ZK policy enforcement passed for {action_name} by user {user_id}")
                return func(*args, **kwargs)

            return wrapper
        return decorator

    def _cache_enforcement(self, action_name: str) -> None:
        if action_name not in self.enforced_actions_cache:
            self.enforced_actions_cache[action_name] = True

    def is_enforced(self, action_name: str) -> bool:
        return self.enforced_actions_cache.get(action_name, False)


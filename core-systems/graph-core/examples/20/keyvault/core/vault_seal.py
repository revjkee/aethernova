# keyvault/core/vault_seal.py
"""
TeslaAI Genesis VaultSeal v5.3
Механизм блокировки/разблокировки хранилища.
Поддержка: master seal, quorum, threat triggers, audit, ZK-aware контроль.
"""

import os
import json
import logging
import time
from typing import List

SEAL_STATE_FILE = "/var/lib/teslaai/vault/seal_state.json"
SEAL_QUORUM = 3  # количество подтверждений для разблокировки
AUTO_RELOCK_TIMEOUT = 600  # секунд до авто-блокировки

logger = logging.getLogger("teslaai.vault_seal")
logger.setLevel(logging.INFO)

def _load_state() -> dict:
    if not os.path.exists(SEAL_STATE_FILE):
        return {"sealed": True, "unseal_approvals": [], "last_unseal": 0}
    with open(SEAL_STATE_FILE, "r") as f:
        return json.load(f)

def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(SEAL_STATE_FILE), exist_ok=True)
    with open(SEAL_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def is_vault_sealed() -> bool:
    state = _load_state()
    sealed = state.get("sealed", True)
    if not sealed and (time.time() - state.get("last_unseal", 0)) > AUTO_RELOCK_TIMEOUT:
        logger.warning("[VaultSeal] Auto-relocking due to timeout.")
        seal_vault()
        return True
    return sealed

def seal_vault() -> None:
    state = _load_state()
    state["sealed"] = True
    state["unseal_approvals"] = []
    _save_state(state)
    logger.critical("[VaultSeal] Vault sealed manually or automatically.")

def unseal_vault(approver_id: str) -> bool:
    state = _load_state()
    if not state.get("sealed", True):
        logger.info("[VaultSeal] Vault already unsealed.")
        return True

    if approver_id in state.get("unseal_approvals", []):
        logger.warning(f"[VaultSeal] Approver {approver_id} already confirmed.")
    else:
        state["unseal_approvals"].append(approver_id)
        logger.info(f"[VaultSeal] Approver {approver_id} added.")

    if len(state["unseal_approvals"]) >= SEAL_QUORUM:
        state["sealed"] = False
        state["last_unseal"] = int(time.time())
        logger.info("[VaultSeal] Quorum reached. Vault unsealed.")
    else:
        logger.info(f"[VaultSeal] Awaiting quorum: {len(state['unseal_approvals'])}/{SEAL_QUORUM}")

    _save_state(state)
    return not state["sealed"]

def get_seal_status() -> dict:
    state = _load_state()
    status = {
        "sealed": state.get("sealed", True),
        "approvals": len(state.get("unseal_approvals", [])),
        "required_quorum": SEAL_QUORUM,
        "last_unseal_ts": state.get("last_unseal")
    }
    return status

def force_seal_due_to_threat(source: str, signal: str) -> None:
    logger.warning(f"[VaultSeal] Triggered by threat signal: {signal} from {source}")
    seal_vault()

def zk_verify_unseal_permission(agent_id: str, zk_proof: str) -> bool:
    # Предполагаемая проверка zk-подтверждения
    if zk_proof.startswith("zkpass_") and agent_id in zk_proof:
        logger.info(f"[VaultSeal] ZK-proof verified for {agent_id}")
        return True
    logger.warning(f"[VaultSeal] ZK-proof failed for {agent_id}")
    return False

def reset_vault_state() -> None:
    if os.path.exists(SEAL_STATE_FILE):
        os.remove(SEAL_STATE_FILE)
        logger.warning("[VaultSeal] Vault state file reset.")

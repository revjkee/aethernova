import logging
import threading
import time
from uuid import uuid4
from datetime import datetime
from typing import Dict, Optional

from genesisops_core.telemetry.pulse import update_node_status
from genesisops_core.ai.contextual_ranking import rank_recovery_priority
from genesisops_core.recovery.engines import (
    restart_service,
    reset_node,
    rebind_cluster_role,
    restore_from_snapshot
)
from genesisops_core.recovery.rollback_guard import start_transaction, commit_transaction, abort_transaction
from genesisops_core.control.audit import log_recovery_action
from genesisops_core.core.errors import RecoveryDispatchError

logger = logging.getLogger("infra.auto_recovery_dispatcher")
logging.basicConfig(level=logging.INFO)

DISPATCH_INTERVAL_SEC = 4

class RecoveryTask:
    def __init__(self, node_id: str, failure_type: str, severity: float):
        self.task_id = str(uuid4())
        self.node_id = node_id
        self.failure_type = failure_type
        self.severity = severity
        self.created_at = datetime.utcnow()
        self.attempts = 0

class AutoRecoveryDispatcher:
    def __init__(self):
        self.active = True
        self.recovery_queue: Dict[str, RecoveryTask] = {}

    def add_task(self, node_id: str, failure_type: str, severity: float):
        task = RecoveryTask(node_id, failure_type, severity)
        self.recovery_queue[task.task_id] = task
        logger.info(f"Recovery task queued: {task.task_id} for node {node_id}")

    def _dispatch_task(self, task: RecoveryTask):
        try:
            logger.info(f"Dispatching recovery task {task.task_id} for {task.node_id}")

            tx_id = start_transaction(task.task_id)
            ranked_action = rank_recovery_priority(task.node_id, task.failure_type, task.severity)

            if ranked_action == "restart_service":
                restart_service(task.node_id)
            elif ranked_action == "reset_node":
                reset_node(task.node_id)
            elif ranked_action == "rebind_cluster_role":
                rebind_cluster_role(task.node_id)
            elif ranked_action == "restore_from_snapshot":
                restore_from_snapshot(task.node_id)
            else:
                raise RecoveryDispatchError(f"Unknown recovery action: {ranked_action}")

            update_node_status(task.node_id, status="recovering")
            commit_transaction(tx_id)

            log_recovery_action({
                "task_id": task.task_id,
                "node_id": task.node_id,
                "action": ranked_action,
                "severity": task.severity,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "completed"
            })

            del self.recovery_queue[task.task_id]

        except Exception as e:
            logger.error(f"Recovery failed for task {task.task_id}: {e}")
            abort_transaction(task.task_id)
            task.attempts += 1
            if task.attempts >= 3:
                log_recovery_action({
                    "task_id": task.task_id,
                    "node_id": task.node_id,
                    "action": "aborted",
                    "severity": task.severity,
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "permanently_failed"
                })

    def _loop(self):
        while self.active:
            for task_id, task in list(self.recovery_queue.items()):
                self._dispatch_task(task)
            time.sleep(DISPATCH_INTERVAL_SEC)

    def start(self):
        logger.info("Starting AutoRecoveryDispatcher loop")
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        logger.info("Stopping AutoRecoveryDispatcher loop")
        self.active = False

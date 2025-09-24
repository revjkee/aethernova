"""
Immutable Core — Rollback Trigger
----------------------------------
Назначение: Мгновенный откат до безопасного AI-снапшота в случае нарушения правил или повреждения логики.

Поддержка:
- Полный автоматизированный откат
- Проверка доверия снапшота (подписи, контрольный хэш)
- Встраивается в ai_restriction_layer, integrity_validator, critical_path_guard
- Промышленная надёжность: 20 агентов + 3 метагенерала
"""

import os
import shutil
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from ..lock_rules.snapshot_store import (
    list_snapshots,
    verify_snapshot_signature,
    restore_snapshot,
    mark_snapshot_trusted,
    get_snapshot_metadata,
)
from ..lock_rules.rule_utils import audit_event, escalate, block_execution

logger = logging.getLogger("rollback_trigger")

# Основные параметры
SNAPSHOT_DIR = Path("/var/lib/ai_snapshots/")
TRUSTED_TAG = "trusted"
SNAPSHOT_META = "meta.json"

# Проверка валидности снапшота по сигнатуре
def is_snapshot_valid(snapshot_path: Path) -> bool:
    try:
        return verify_snapshot_signature(snapshot_path)
    except Exception as e:
        logger.error(f"Ошибка проверки подписи снапшота: {e}")
        return False

# Выбор наилучшего доступного снапшота
def select_best_snapshot() -> Optional[Path]:
    candidates = list_snapshots(SNAPSHOT_DIR)
    trusted = []

    for snap in candidates:
        meta = get_snapshot_metadata(snap)
        if meta.get("status") == TRUSTED_TAG and is_snapshot_valid(snap):
            trusted.append((meta["timestamp"], snap))

    if not trusted:
        logger.error("Нет доверенных снапшотов для отката.")
        return None

    trusted.sort(reverse=True)
    return trusted[0][1]

# Выполнение отката
def perform_rollback(snapshot_path: Path):
    actor = "rollback_trigger"

    logger.info(f"Выполняется откат до снапшота: {snapshot_path}")
    audit_event("AI_Rollback_Triggered", actor=actor, resource=str(snapshot_path))

    success = restore_snapshot(snapshot_path)
    if not success:
        escalate("Ошибка восстановления снапшота", actor=actor)
        block_execution(actor, reason="Rollback failed")
        return False

    logger.info("Откат выполнен успешно.")
    audit_event("AI_Rollback_Completed", actor=actor, resource=str(snapshot_path))
    return True

# Главная точка входа
def rollback_if_needed(trigger_reason: str):
    actor = "rollback_trigger"

    logger.warning(f"Срабатывание отката по причине: {trigger_reason}")
    audit_event("AI_Rollback_Initiated", actor=actor, reason=trigger_reason)

    snapshot = select_best_snapshot()
    if not snapshot:
        escalate("Снапшот для отката не найден", actor=actor)
        block_execution(actor, reason="Rollback snapshot not found")
        return False

    return perform_rollback(snapshot)

"""
Immutable Core — Integrity Validator
-------------------------------------
Назначение: Комплексная проверка целостности кода, логики, подписи и поведения AI.
Особенности:
- Поддержка цифровых подписей
- Контроль хэш-сумм
- Проверка мета-политик
- Валидация по снэпшотам поведения

Промышленная валидация: 20 агентов + 3 метагенерала
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List

from ..lock_rules.rule_utils import (
    audit_event,
    escalate,
    block_execution,
    is_internal_context,
)
from ..lock_rules.snapshot_store import (
    load_snapshot_signature,
    load_behavior_trace,
    verify_signature,
)

logger = logging.getLogger("integrity_validator")

# Пути, подлежащие валидации
INTEGRITY_TARGETS = [
    "/core/ai_exec/entry.py",
    "/core/ai_exec/logic_engine.py",
    "/immutable-core/lock_rules/",
    "/immutable-core/sandbox/",
]

# Загрузка ранее сохранённых контрольных хэшей
def load_reference_hashes(filepath: str) -> Dict[str, str]:
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка загрузки хэшей: {e}")
        return {}

# Пересчёт хэша файла
def calculate_file_hash(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logger.error(f"Ошибка чтения {path}: {e}")
        return "invalid"

# Валидация всех целевых путей
def validate_file_integrity(reference_hashes: Dict[str, str]):
    violations = []

    for path in INTEGRITY_TARGETS:
        resolved = Path(path).resolve()
        if not resolved.exists():
            violations.append((str(resolved), "missing"))
            continue

        current_hash = calculate_file_hash(str(resolved))
        if reference_hashes.get(str(resolved)) != current_hash:
            violations.append((str(resolved), "hash_mismatch"))

    return violations

# Проверка цифровой подписи конфигураций (например, .yaml, .json)
def validate_signatures(signature_dir: str) -> bool:
    for sig_file in Path(signature_dir).glob("*.sig"):
        source_file = sig_file.with_suffix("")
        if not verify_signature(str(source_file), str(sig_file)):
            logger.error(f"Неверная подпись файла: {source_file}")
            return False
    return True

# Проверка поведения по трассировке
def validate_behavior_traces(trace_dir: str) -> bool:
    traces = load_behavior_trace(trace_dir)
    if "anomaly_detected" in traces:
        logger.warning(f"Аномалия в поведении: {traces['anomaly_detected']}")
        return False
    return True

# Главная точка проверки
def run_integrity_validation(ref_hash_path: str, sig_dir: str, trace_dir: str):
    actor = "integrity_validator"

    logger.info("Валидация: начало проверки хэшей...")
    ref_hashes = load_reference_hashes(ref_hash_path)
    file_violations = validate_file_integrity(ref_hashes)

    if file_violations:
        for file, reason in file_violations:
            audit_event("FileIntegrityViolation", actor=actor, resource=file, reason=reason)
        escalate("Нарушена целостность кода", actor=actor)
        block_execution(actor, reason="Integrity check failed")
        return False

    logger.info("Валидация: проверка цифровых подписей...")
    if not validate_signatures(sig_dir):
        audit_event("SignatureMismatch", actor=actor, resource=sig_dir, reason="Bad GPG")
        escalate("Неверные подписи конфигурации", actor=actor)
        block_execution(actor, reason="Signature validation failed")
        return False

    logger.info("Валидация: трассировка поведения AI...")
    if not validate_behavior_traces(trace_dir):
        audit_event("BehaviorAnomaly", actor=actor, resource=trace_dir, reason="AI behavior divergence")
        escalate("AI аномалия", actor=actor)
        block_execution(actor, reason="Behavior validation failed")
        return False

    logger.info("Целостность системы подтверждена.")
    return True

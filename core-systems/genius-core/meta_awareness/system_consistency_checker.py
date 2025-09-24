import hashlib
import logging
from datetime import datetime
from genius_core.meta_awareness.models import CognitiveMap, ExecutionLog, PolicyRules
from genius_core.meta_awareness.validators import validate_logical_consistency, check_contradictions
from genius_core.meta_awareness.alerts import raise_anomaly_flag, notify_guardian
from genius_core.shared.memory import LongTermMemory, EphemeralBuffer

logger = logging.getLogger("SystemConsistencyChecker")

class SystemConsistencyChecker:
    """
    Основной модуль самоконтроля метасознания.
    Проверяет:
    - соответствие текущих целей правилам
    - непротиворечивость памяти
    - отсутствие логических конфликтов в цепочках рассуждений
    - сигнатуры намерений и действия на subjective-hash сходство
    """

    def __init__(self):
        self.memory = LongTermMemory()
        self.buffer = EphemeralBuffer()
        self.policy = PolicyRules()
        self.history_log = ExecutionLog()
        self.last_hash = None

    def run_full_check(self):
        logger.info("Запуск полной проверки целостности системы...")
        
        self._check_policy_violations()
        self._check_cognitive_map_integrity()
        self._verify_temporal_consistency()
        self._hash_consistency_signature()

        logger.info("Полная проверка завершена успешно.")

    def _check_policy_violations(self):
        current_goals = self.buffer.get_current_goals()
        violations = self.policy.check_against_goals(current_goals)
        if violations:
            for v in violations:
                logger.warning(f"Нарушение политики: {v}")
                raise_anomaly_flag("policy_violation", v)
                notify_guardian("PolicyViolation", v)

    def _check_cognitive_map_integrity(self):
        map_snapshot = CognitiveMap.capture()
        contradictions = check_contradictions(map_snapshot)
        if contradictions:
            for contradiction in contradictions:
                logger.error(f"Обнаружено противоречие: {contradiction}")
                raise_anomaly_flag("cognitive_inconsistency", contradiction)
                notify_guardian("CognitiveContradiction", contradiction)

        logical_valid = validate_logical_consistency(map_snapshot)
        if not logical_valid:
            logger.critical("Логическая непротиворечивость нарушена")
            raise_anomaly_flag("logic_failure", "Global logical contradiction")
            notify_guardian("LogicBreach", "Critical logic breach")

    def _verify_temporal_consistency(self):
        timestamps = self.history_log.get_recent_timestamps()
        if not all(t1 <= t2 for t1, t2 in zip(timestamps, timestamps[1:])):
            logger.warning("Обнаружена временная несогласованность в действиях")
            raise_anomaly_flag("temporal_shift", "Non-monotonic execution timeline")
            notify_guardian("TemporalInconsistency", "Time desync")

    def _hash_consistency_signature(self):
        snapshot = self.memory.get_recent_state_hash_input()
        current_hash = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()

        if self.last_hash and self.last_hash == current_hash:
            logger.debug("Повторная идентичность хэш-состояния обнаружена — возможно зацикливание.")
            raise_anomaly_flag("state_loop", "Identical hash recurrence")
            notify_guardian("HashStagnation", "No change detected in cognitive signature")

        self.last_hash = current_hash
        logger.info(f"Новая сигнатура системы: {current_hash} @ {datetime.utcnow().isoformat()}")


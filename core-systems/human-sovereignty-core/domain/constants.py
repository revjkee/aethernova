# human-sovereignty-core/domain/constants.py
from __future__ import annotations

from enum import Enum, IntEnum
from typing import Final


"""
DOMAIN CONSTANTS
================
Этот модуль содержит канонические, неизменяемые константы доменного уровня
для ядра Human Sovereignty.

Правила:
- никаких runtime-конфигураций
- никаких инфраструктурных деталей
- только смысловые инварианты предметной области
"""


# ---------------------------------------------------------------------------
# Sovereignty Levels
# ---------------------------------------------------------------------------

class SovereigntyLevel(IntEnum):
    """
    Уровень суверенного контроля человека над системой.
    """
    HUMAN_ABSOLUTE = 0
    HUMAN_SUPERVISED = 1
    HUMAN_IN_THE_LOOP = 2
    HUMAN_ON_THE_LOOP = 3
    AUTONOMOUS_LIMITED = 4
    AUTONOMOUS_RESTRICTED = 5


# ---------------------------------------------------------------------------
# Human Roles
# ---------------------------------------------------------------------------

class HumanRole(str, Enum):
    """
    Роли человека в контуре управления.
    """
    HUMAN_GOVERNOR = "human_governor"
    INCIDENT_COMMANDER = "incident_commander"
    PLATFORM_OWNER = "platform_owner"
    SECURITY_OFFICER = "security_officer"
    ONCALL_PRIMARY = "oncall_primary"
    ONCALL_SECONDARY = "oncall_secondary"
    AUDITOR = "auditor"


# ---------------------------------------------------------------------------
# Decision Lifecycle States
# ---------------------------------------------------------------------------

class DecisionStatus(str, Enum):
    """
    Статусы жизненного цикла решений и управляющих пакетов.
    """
    DRAFT = "draft"
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    RESOLVED = "resolved"
    CLOSED = "closed"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Incident Severity
# ---------------------------------------------------------------------------

class SeverityLevel(IntEnum):
    """
    Критичность события или решения.
    Чем меньше число — тем выше приоритет.
    """
    SEV0 = 0  # existential or safety critical
    SEV1 = 1  # critical outage or integrity loss
    SEV2 = 2  # major degradation or elevated risk
    SEV3 = 3  # minor degradation
    SEV4 = 4  # informational


# ---------------------------------------------------------------------------
# Risk Classification
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """
    Классификация риска.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Autonomy Control Flags
# ---------------------------------------------------------------------------

class AutonomyControl(str, Enum):
    """
    Управляющие флаги автономии системы.
    """
    ALLOW_AUTONOMY = "allow_autonomy"
    FREEZE_AUTONOMY = "freeze_autonomy"
    REQUIRE_HUMAN_APPROVAL = "require_human_approval"
    EMERGENCY_MODE = "emergency_mode"


# ---------------------------------------------------------------------------
# Audit Events
# ---------------------------------------------------------------------------

class AuditEvent(str, Enum):
    """
    События, подлежащие обязательному аудиту.
    """
    INCIDENT_CREATED = "incident_created"
    DECISION_PROPOSED = "decision_proposed"
    DECISION_APPROVED = "decision_approved"
    DECISION_REJECTED = "decision_rejected"
    ACTION_EXECUTED = "action_executed"
    ESCALATION_TRIGGERED = "escalation_triggered"
    ACK_RECEIVED = "ack_received"
    STATUS_CHANGED = "status_changed"
    AUTONOMY_FROZEN = "autonomy_frozen"


# ---------------------------------------------------------------------------
# Domain Invariants
# ---------------------------------------------------------------------------

MAX_ESCALATION_DEPTH: Final[int] = 6
MAX_TTL_SECONDS: Final[int] = 60 * 60 * 24 * 30  # 30 days
MIN_ACK_TIMEOUT_SECONDS: Final[int] = 60
MAX_ACK_TIMEOUT_SECONDS: Final[int] = 3600


# ---------------------------------------------------------------------------
# Reserved Tags
# ---------------------------------------------------------------------------

TAG_SECURITY: Final[str] = "security"
TAG_SAFETY: Final[str] = "safety"
TAG_INTEGRITY: Final[str] = "integrity"
TAG_HUMAN_SOVEREIGNTY: Final[str] = "human-sovereignty"


# ---------------------------------------------------------------------------
# Domain Assertions (semantic reference only)
# ---------------------------------------------------------------------------

"""
Инварианты домена (документально):

1. Любое событие SEV0 всегда требует участия HUMAN_GOVERNOR.
2. Решения со статусом APPROVED не могут быть изменены без нового PROPOSED.
3. FREEZE_AUTONOMY имеет приоритет над любыми автоматическими действиями.
4. HUMAN_ABSOLUTE — финальная точка ответственности, не может быть переопределена.
5. Все CRITICAL риски подлежат обязательному аудиту.
"""

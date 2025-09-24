# cybersecurity-core/cybersecurity/compliance/mapper_gdpr.py
"""
GDPR Mapper для кибербезопасности.
Назначение:
- Выделяет категории персональных данных (в т.ч. специальные категории) из событий/артефактов.
- Сопоставляет контекст обработки с обязанностями по GDPR (без внешних зависимостей).
- Оценивает необходимость уведомления надзорного органа/субъектов (Art. 33/34) и рассчитывает дедлайн 72 часа.
- Проверяет принципы (минимизация, ограничение цели, ограничение хранения) и правовые основания (Art. 6; Art. 9).
- Выявляет трансграничные передачи (EEA/адекватность/прочее) и рекомендует меры (SCC/DTIA).

ВНИМАНИЕ:
- Модуль предоставляет инженерные проверки и ссылки на статьи GDPR в комментариях/полях, но не является юридическим советом.
- Списки EEA/адекватности и локальные правила должны быть прокинуты через контекст (см. GDPRContext).
"""

from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _get(event: Mapping[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = event
    for p in path.split("."):
        if isinstance(cur, Mapping) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _as_set(v: Optional[Iterable[str]]) -> Set[str]:
    return set(v or ())


# --------------------------------------------------------------------------------------
# Справочники/типы
# --------------------------------------------------------------------------------------

class Role(str, Enum):
    CONTROLLER = "controller"
    PROCESSOR = "processor"


class LegalBasis(str, Enum):
    # Art. 6(1) GDPR — правовые основания
    CONSENT = "consent"                      # a
    CONTRACT = "contract"                    # b
    LEGAL_OBLIGATION = "legal_obligation"    # c
    VITAL_INTERESTS = "vital_interests"      # d
    PUBLIC_TASK = "public_task"              # e
    LEGITIMATE_INTERESTS = "legitimate_interests"  # f

    # Для специальных категорий (Art. 9(2)) используйте gdpr_special_basis в контексте.


class DataCategory(str, Enum):
    # Базовые категории персональных данных
    IDENTIFIERS = "identifiers"             # имя, e-mail, телефон, username, аккаунты
    ONLINE_IDENTIFIERS = "online_identifiers"  # IP, cookies, device IDs
    CONTACT = "contact"                     # адрес, e-mail, телефон
    FINANCIAL = "financial"                 # карты, IBAN, счета
    AUTH = "auth"                           # логины, хэши паролей (не хранить в событиях)
    LOCATION = "location"                   # точные координаты, адреса
    EMPLOYMENT = "employment"               # должность, отдел
    EDUCATION = "education"
    IMAGE = "image"
    MINOR = "minor"                         # данные несовершеннолетних (контекстный флаг)
    # Специальные категории (Art. 9(1))
    HEALTH = "health"
    BIOMETRIC = "biometric"
    GENETIC = "genetic"
    RELIGION = "religion"
    POLITICAL = "political"
    TRADE_UNION = "trade_union"
    SEX_LIFE = "sex_life"
    RACIAL_ETHNIC = "racial_ethnic"
    # Судимости и правонарушения (Art. 10)
    CRIMINAL_OFFENCE = "criminal_offence"


class DSR(str, Enum):
    # Права субъектов данных
    ACCESS = "access"                # Art. 15
    RECTIFICATION = "rectification"  # Art. 16
    ERASURE = "erasure"              # Art. 17
    RESTRICTION = "restriction"      # Art. 18
    PORTABILITY = "portability"      # Art. 20
    OBJECTION = "objection"          # Art. 21
    WITHDRAW_CONSENT = "withdraw_consent"  # Art. 7(3)


class ObligationCode(str, Enum):
    ROPA = "art30_record_of_processing"                  # Art. 30
    DPIA = "art35_dpia"                                  # Art. 35
    BREACH_NOTIFY_SA = "art33_breach_notify_supervisory" # Art. 33 (72 часа)
    BREACH_NOTIFY_DATA_SUBJECTS = "art34_breach_notify_data_subjects"  # Art. 34
    MINIMIZATION = "art5_1_c_data_minimization"          # Art. 5(1)(c)
    PURPOSE_LIMITATION = "art5_1_b_purpose_limitation"   # Art. 5(1)(b)
    STORAGE_LIMITATION = "art5_1_e_storage_limitation"   # Art. 5(1)(e)
    LAWFULNESS = "art6_lawfulness"                       # Art. 6
    SPECIAL_CATEGORY_BASIS = "art9_special_category_basis"  # Art. 9
    ART10_OFFENCE_CONDITION = "art10_offence_condition"  # Art. 10
    TRANSFER_GUARDS = "art44_49_transfers"               # Art. 44–49 (SCC/адекватность/исключения)
    CONSENT_REQUIREMENTS = "art7_consent_requirements"   # Art. 7
    SECURITY_OF_PROCESSING = "art32_security_of_processing"  # Art. 32


@dataclass
class Obligation:
    code: ObligationCode
    articles: Tuple[str, ...]
    required: bool
    rationale: str
    due_at: Optional[datetime] = None
    severity: str = "info"  # info | warn | high | critical
    recommendations: Tuple[str, ...] = tuple()


@dataclass
class BreachPlan:
    required: bool
    notify_sa_by: Optional[datetime] = None
    notify_subjects: bool = False
    rationale: str = ""


@dataclass
class GDPRContext:
    """
    Контекст обработки на уровне продукта/организации/инцидента.
    Все поля опциональны; чем больше — тем точнее вывод.
    """
    tenant_id: str
    role: Role = Role.CONTROLLER
    legal_basis: Optional[LegalBasis] = None                # для обычных данных (Art. 6)
    special_category_basis: Optional[str] = None            # ссылка на пп. Art. 9(2) при наличии спец.категорий
    purposes: Set[str] = field(default_factory=set)         # явные цели обработки (добавляйте из каталога целей)
    retention_days: Optional[int] = None                    # политика хранения (дней)
    consent_record_present: bool = False                    # есть зафиксированное согласие (если основание — consent)
    dpia_done: bool = False                                 # проведена оценка влияния (Art. 35)
    breach_detected: bool = False
    breach_discovered_at: Optional[datetime] = None         # время «узнали» (начало 72ч окна; Art. 33(1))
    high_risk_to_rights: Optional[bool] = None              # оценка риска для Art. 34
    data_subjects_in_eu: bool = True                        # затронуты субъекты в ЕС/ЕЭЗ
    transfers_to: Set[str] = field(default_factory=set)     # ISO country codes (куда передаём/хостим)
    eea_countries: Set[str] = field(default_factory=set)    # прокиньте актуальный список ЕЭЗ
    adequacy_countries: Set[str] = field(default_factory=set)  # страны с действующей адекватностью
    scc_in_place: bool = False                              # заключены ли Стандартные договорные положения (SCC)
    dtia_done: bool = False                                 # data transfer impact assessment выполнена
    technical_measures: Set[str] = field(default_factory=set)  # примеры: {'encryption_at_rest','pseudonymization'}
    organizational_measures: Set[str] = field(default_factory=set)  # примеры: {'dpa_signed','access_control'}


@dataclass
class MappingReport:
    tenant_id: str
    risk_score: int
    data_categories: Set[DataCategory]
    dsr_relevant: Set[DSR]
    obligations: List[Obligation]
    breach_plan: BreachPlan
    lawful_basis_ok: bool
    issues: List[str]
    fingerprint: str


# --------------------------------------------------------------------------------------
# Детекторы PII (минимальные, быстрые, без внешних зависимостей)
# --------------------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_PHONE_RE = re.compile(r"\b\+?[0-9][0-9\-\s()]{6,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b[0-9A-Fa-f:]{2,}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
# Примитивный PAN (Luhn верификация ниже)
_PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    checksum = (checksum * 9) % 10
    return checksum == digits[-1]


def _collect_text_fields(event: Mapping[str, Any]) -> str:
    """
    Собирает потенциальные строки для быстрого детекта PII.
    Не разворачивает большие бинарные поля.
    """
    buf: List[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 5:  # ограничение глубины
            return
        if isinstance(node, Mapping):
            for v in node.values():
                walk(v, depth + 1)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v, depth + 1)
        elif isinstance(node, str):
            if len(node) <= 2000:
                buf.append(node)

    walk(event)
    return "\n".join(buf)


def detect_data_categories(event: Mapping[str, Any]) -> Set[DataCategory]:
    cats: Set[DataCategory] = set()

    # Очевидные поля
    if _get(event, "user.email"): cats.add(DataCategory.CONTACT); cats.add(DataCategory.IDENTIFIERS)
    if _get(event, "user.username"): cats.add(DataCategory.IDENTIFIERS)
    if _get(event, "auth.username"): cats.add(DataCategory.AUTH); cats.add(DataCategory.IDENTIFIERS)
    if _get(event, "host.ip_addresses"): cats.add(DataCategory.ONLINE_IDENTIFIERS)
    if _get(event, "network_connection.remote_ip") or _get(event, "network_connection.local_ip"):
        cats.add(DataCategory.ONLINE_IDENTIFIERS)

    blob = _collect_text_fields(event)
    if _EMAIL_RE.search(blob):
        cats.add(DataCategory.CONTACT); cats.add(DataCategory.IDENTIFIERS)
    if _PHONE_RE.search(blob):
        cats.add(DataCategory.CONTACT); cats.add(DataCategory.IDENTIFIERS)
    if _IPV4_RE.search(blob) or _IPV6_RE.search(blob):
        cats.add(DataCategory.ONLINE_IDENTIFIERS)
    if _IBAN_RE.search(blob):
        cats.add(DataCategory.FINANCIAL)
    for m in _PAN_RE.findall(blob):
        if _luhn_ok(m):
            cats.add(DataCategory.FINANCIAL)

    # Специальные категории — простые эвристики по ключам/меткам
    keys = " ".join(event.keys()).lower()
    text = (blob[:20000]).lower()
    special_markers = {
        DataCategory.HEALTH: ("diagnos", "icd", "medical", "health", "пациент", "диагноз"),
        DataCategory.BIOMETRIC: ("fingerprint", "faceid", "iris", "biometric"),
        DataCategory.GENETIC: ("genetic", "dna"),
        DataCategory.RELIGION: ("religion", "религ"),
        DataCategory.POLITICAL: ("party", "полит"),
        DataCategory.TRADE_UNION: ("union", "профсоюз"),
        DataCategory.SEX_LIFE: ("sexual", "sex life", "интим"),
        DataCategory.RACIAL_ETHNIC: ("race", "ethnic", "этнич", "раса"),
        DataCategory.CRIMINAL_OFFENCE: ("criminal", "offence", "судим", "уголов"),
    }
    for cat, markers in special_markers.items():
        if any(t in keys or t in text for t in markers):
            cats.add(cat)

    return cats


# --------------------------------------------------------------------------------------
# Основные проверки/оценки
# --------------------------------------------------------------------------------------

def _assess_lawful_basis(cats: Set[DataCategory], ctx: GDPRContext, issues: List[str]) -> bool:
    ok = True
    # Базовые данные требуют одного из оснований Art. 6
    if ctx.legal_basis is None:
        issues.append("Не указано правовое основание обработки (Art. 6).")
        ok = False

    # Специальные категории (Art. 9) требуют отдельного основания
    if any(c in cats for c in {
        DataCategory.HEALTH, DataCategory.BIOMETRIC, DataCategory.GENETIC, DataCategory.RELIGION,
        DataCategory.POLITICAL, DataCategory.TRADE_UNION, DataCategory.SEX_LIFE, DataCategory.RACIAL_ETHNIC
    }):
        if not ctx.special_category_basis:
            issues.append("Обнаружены специальные категории, но отсутствует основание по Art. 9(2).")
            ok = False

    # Судимости/правонарушения (Art. 10) — особые условия
    if DataCategory.CRIMINAL_OFFENCE in cats:
        issues.append("Обработка сведений о правонарушениях требует соответствия Art. 10 (национальное право/надзор).")

    # Основание «consent» требует наличия записи о согласии (Art. 7)
    if ctx.legal_basis == LegalBasis.CONSENT and not ctx.consent_record_present:
        issues.append("Правовое основание — согласие, но не подтверждена запись согласия (Art. 7).")
        ok = False

    return ok


def _assess_principles(event: Mapping[str, Any], cats: Set[DataCategory], ctx: GDPRContext) -> List[Obligation]:
    obligations: List[Obligation] = []

    # Минимизация данных — если в событии присутствуют поля, не нужные для цели безопасности
    # (проверка эвристическая: e-mail/телефон в телеметрии EDR чаще избыточны)
    if any(c in cats for c in (DataCategory.CONTACT, DataCategory.FINANCIAL)):
        obligations.append(Obligation(
            code=ObligationCode.MINIMIZATION,
            articles=("Art.5(1)(c)",),
            required=True,
            severity="warn",
            rationale="Содержатся потенциально избыточные поля (contact/financial) для целей кибербезопасности.",
            recommendations=("Ограничить поля в телеметрии/логах", "Маскирование/псевдонимизация")
        ))

    # Ограничение цели (Art. 5(1)(b)) — если «purposes» пуст или не содержит «security»
    if not ctx.purposes or ("security" not in {p.lower() for p in ctx.purposes}):
        obligations.append(Obligation(
            code=ObligationCode.PURPOSE_LIMITATION,
            articles=("Art.5(1)(b)",),
            required=True,
            severity="info",
            rationale="Не указана цель 'security' в контексте обработки.",
            recommendations=("Уточнить цели обработки и закрепить их в RoPA",)
        ))

    # Ограничение хранения (Art. 5(1)(e))
    if ctx.retention_days is None:
        obligations.append(Obligation(
            code=ObligationCode.STORAGE_LIMITATION,
            articles=("Art.5(1)(e)",),
            required=True,
            severity="info",
            rationale="Не задан срок хранения событий/артефактов.",
            recommendations=("Определить и применить политику ретенции",)
        ))

    # Безопасность обработки (Art. 32) — общая рекомендация для событий безопасности
    obligations.append(Obligation(
        code=ObligationCode.SECURITY_OF_PROCESSING,
        articles=("Art.32",),
        required=True,
        severity="info",
        rationale="События безопасности требуют адекватных технических/организационных мер.",
        recommendations=tuple(sorted(ctx.technical_measures | ctx.organizational_measures)) or
                        ("Encryption at rest", "Access Control", "Least Privilege")
    ))

    return obligations


def _assess_transfers(ctx: GDPRContext, cats: Set[DataCategory]) -> Optional[Obligation]:
    if not ctx.transfers_to:
        return None
    # Определяем, есть ли передачи вне ЕЭЗ и вне стран адекватности
    non_eea = [c for c in ctx.transfers_to if c not in ctx.eea_countries]
    if not non_eea:
        return None
    not_adequate = [c for c in non_eea if c not in ctx.adequacy_countries]
    required = len(not_adequate) > 0
    recs: List[str] = []
    if required:
        if not ctx.scc_in_place:
            recs.append("Заключить Standard Contractual Clauses (SCC)")
        if not ctx.dtia_done:
            recs.append("Выполнить Data Transfer Impact Assessment (DTIA)")
        if "encryption_in_transit" not in ctx.technical_measures:
            recs.append("Внедрить шифрование в транзите")
        if "pseudonymization" not in ctx.technical_measures:
            recs.append("Псевдонимизация/минимизация передаваемых данных")
    return Obligation(
        code=ObligationCode.TRANSFER_GUARDS,
        articles=("Art.44-49",),
        required=required,
        severity="warn" if required else "info",
        rationale="Обнаружены трансграничные передачи за пределы ЕЭЗ; требуется правовой механизм и меры.",
        recommendations=tuple(recs) if recs else ("Проверить механизмы трансфера",)
    )


def _breach_plan(ctx: GDPRContext, cats: Set[DataCategory]) -> BreachPlan:
    """
    План уведомлений при нарушении безопасности персональных данных.
    - Art. 33: уведомление надзорного органа без необоснованной задержки и, где осуществимо, не позднее 72 часов.
    - Art. 34: уведомление субъектов при высоком риске для прав и свобод.
    """
    if not ctx.breach_detected or not ctx.data_subjects_in_eu:
        return BreachPlan(required=False, rationale="Нет признаков инцидента, требующего уведомлений Art. 33/34.")
    discovered = ctx.breach_discovered_at or _now_utc()
    deadline = discovered + timedelta(hours=72)
    high_risk = bool(ctx.high_risk_to_rights)
    # Наличие специальных категорий/финансовых данных повышает вероятность high risk
    if ctx.high_risk_to_rights is None and any(c in cats for c in (
        DataCategory.HEALTH, DataCategory.BIOMETRIC, DataCategory.GENETIC,
        DataCategory.FINANCIAL, DataCategory.CRIMINAL_OFFENCE, DataCategory.MINOR
    )):
        high_risk = True
    return BreachPlan(
        required=True,
        notify_sa_by=deadline,
        notify_subjects=high_risk,
        rationale="Инцидент безопасности персональных данных обнаружен; применимы Art. 33/34."
    )


def _dsr_set(ctx: GDPRContext, cats: Set[DataCategory]) -> Set[DSR]:
    rights: Set[DSR] = {
        DSR.ACCESS, DSR.RECTIFICATION, DSR.RESTRICTION, DSR.OBJECTION
    }
    # Переносимость актуальнее при контракте/согласии
    if ctx.legal_basis in (LegalBasis.CONSENT, LegalBasis.CONTRACT):
        rights.add(DSR.PORTABILITY)
    # Право на удаление — зависит от цели и законных оснований; включаем как релевантное по умолчанию
    rights.add(DSR.ERASURE)
    if ctx.legal_basis == LegalBasis.CONSENT:
        rights.add(DSR.WITHDRAW_CONSENT)
    return rights


def _risk_score(cats: Set[DataCategory], breach: BreachPlan, ctx: GDPRContext) -> int:
    """
    Простой детерминированный скоринг (0–100) для приоритизации комплаенс-работ.
    """
    base = 20 if cats else 0
    weights = {
        DataCategory.IDENTIFIERS: 5,
        DataCategory.CONTACT: 5,
        DataCategory.ONLINE_IDENTIFIERS: 5,
        DataCategory.FINANCIAL: 25,
        DataCategory.HEALTH: 25,
        DataCategory.BIOMETRIC: 25,
        DataCategory.GENETIC: 25,
        DataCategory.CRIMINAL_OFFENCE: 25,
        DataCategory.MINOR: 20,
        DataCategory.LOCATION: 10,
    }
    score = base + sum(weights.get(c, 3) for c in cats)
    if breach.required:
        score += 20
        if breach.notify_subjects:
            score += 10
    if _assess_transfers(ctx, cats) and any(c not in ctx.eea_countries for c in ctx.transfers_to):
        score += 10
    return min(100, score)


# --------------------------------------------------------------------------------------
# Публичная функция сопоставления
# --------------------------------------------------------------------------------------

def map_event_to_gdpr(event: Mapping[str, Any], ctx: GDPRContext) -> MappingReport:
    """
    Главная точка входа.
    На вход: событие (лог/алерт/артефакт) и GDPRContext.
    На выход: MappingReport с риском, обязательствами и планом уведомлений.
    """
    issues: List[str] = []
    cats = detect_data_categories(event)

    lawful_ok = _assess_lawful_basis(cats, ctx, issues)

    obligations: List[Obligation] = []

    # Art. 30: RoPA — вести реестр обработки (для большинства организаций это требуется)
    obligations.append(Obligation(
        code=ObligationCode.ROPA,
        articles=("Art.30",),
        required=True,
        severity="info",
        rationale="Реестр операций обработки (RoPA) должен отражать соответствующие цели/категории/сроки хранения."
    ))

    # Art. 6 / Art. 9 / Art. 10
    obligations.append(Obligation(
        code=ObligationCode.LAWFULNESS,
        articles=("Art.6",),
        required=not lawful_ok,
        severity="warn" if not lawful_ok else "info",
        rationale="Проверка правовых оснований (Art. 6) и специальных категорий (Art. 9)."
    ))
    if any(c in cats for c in {
        DataCategory.HEALTH, DataCategory.BIOMETRIC, DataCategory.GENETIC, DataCategory.RELIGION,
        DataCategory.POLITICAL, DataCategory.TRADE_UNION, DataCategory.SEX_LIFE, DataCategory.RACIAL_ETHNIC
    }):
        obligations.append(Obligation(
            code=ObligationCode.SPECIAL_CATEGORY_BASIS,
            articles=("Art.9",),
            required=ctx.special_category_basis is None,
            severity="high" if ctx.special_category_basis is None else "info",
            rationale="Обработка специальных категорий требует законного основания по Art. 9(2)."
        ))
    if DataCategory.CRIMINAL_OFFENCE in cats:
        obligations.append(Obligation(
            code=ObligationCode.ART10_OFFENCE_CONDITION,
            articles=("Art.10",),
            required=True,
            severity="warn",
            rationale="Обработка сведений о правонарушениях регулируется Art. 10 и национальным правом."
        ))

    # Принципы Art. 5 и Art. 32
    obligations.extend(_assess_principles(event, cats, ctx))

    # Трансграничные передачи Art. 44–49
    tr = _assess_transfers(ctx, cats)
    if tr:
        obligations.append(tr)

    # DPIA (Art. 35) — эвристические триггеры высокого риска
    high_risk_triggers = any(c in cats for c in (
        DataCategory.HEALTH, DataCategory.BIOMETRIC, DataCategory.GENETIC,
        DataCategory.MINOR, DataCategory.LOCATION
    ))
    if high_risk_triggers and not ctx.dpia_done:
        obligations.append(Obligation(
            code=ObligationCode.DPIA,
            articles=("Art.35",),
            required=True,
            severity="warn",
            rationale="Обработка потенциально высокого риска (спец.категории/дети/слежение). DPIA рекомендуется."
        ))

    # План уведомлений при нарушении (Art. 33/34)
    breach = _breach_plan(ctx, cats)
    if breach.required:
        obligations.append(Obligation(
            code=ObligationCode.BREACH_NOTIFY_SA,
            articles=("Art.33",),
            required=True,
            severity="critical",
            rationale="Уведомление надзорного органа 'где осуществимо — не позднее 72 часов'.",
            due_at=breach.notify_sa_by
        ))
        if breach.notify_subjects:
            obligations.append(Obligation(
                code=ObligationCode.BREACH_NOTIFY_DATA_SUBJECTS,
                articles=("Art.34",),
                required=True,
                severity="high",
                rationale="Высокий риск для прав и свобод; уведомление субъектов может потребоваться."
            ))

    # Права субъектов (DSR)
    dsr = _dsr_set(ctx, cats)

    # Итоговый риск
    risk = _risk_score(cats, breach, ctx)

    # Специфика ролей (controller vs processor)
    if ctx.role == Role.PROCESSOR and breach.required:
        issues.append("Роль: процессор. Уведомлять контролера без необоснованной задержки (Art. 33(2)).")

    # Отпечаток для аудита/идемпотентности
    fp_payload = f"{ctx.tenant_id}|{sorted(cats)}|{sorted(dsr)}|{risk}|{ctx.role.value}"
    report = MappingReport(
        tenant_id=ctx.tenant_id,
        risk_score=risk,
        data_categories=cats,
        dsr_relevant=dsr,
        obligations=obligations,
        breach_plan=breach,
        lawful_basis_ok=lawful_ok,
        issues=issues,
        fingerprint=_sha256_hex(fp_payload),
    )
    return report


# --------------------------------------------------------------------------------------
# Расширяемость: валидаторы и форматтеры
# --------------------------------------------------------------------------------------

class ReportFormatter:
    """
    Утилита для преобразования MappingReport к плоскому словарю для логов/алертов.
    """
    @staticmethod
    def to_flat_dict(rep: MappingReport) -> Dict[str, Any]:
        return {
            "tenant_id": rep.tenant_id,
            "risk_score": rep.risk_score,
            "data_categories": sorted([c.value for c in rep.data_categories]),
            "dsr_relevant": sorted([d.value for d in rep.dsr_relevant]),
            "lawful_basis_ok": rep.lawful_basis_ok,
            "issues": rep.issues,
            "obligations": [
                {
                    "code": o.code.value,
                    "articles": list(o.articles),
                    "required": o.required,
                    "severity": o.severity,
                    "rationale": o.rationale,
                    "due_at": o.due_at.isoformat() if o.due_at else None,
                    "recommendations": list(o.recommendations),
                }
                for o in rep.obligations
            ],
            "breach_plan": {
                "required": rep.breach_plan.required,
                "notify_sa_by": rep.breach_plan.notify_sa_by.isoformat() if rep.breach_plan.notify_sa_by else None,
                "notify_subjects": rep.breach_plan.notify_subjects,
                "rationale": rep.breach_plan.rationale,
            },
            "fingerprint": rep.fingerprint,
        }


# --------------------------------------------------------------------------------------
# Пример интеграции (можно удалить в продакшене)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    # Демонстрационный пример: событие EDR/аутентификации с данными пользователя и IP
    sample_event = {
        "event_type": "security_incident",
        "detected_at": "2025-09-03T08:30:00Z",
        "user": {"email": "john.doe@example.com", "username": "j.doe"},
        "auth": {"status": "failed", "username": "j.doe"},
        "network_connection": {"remote_ip": "203.0.113.10"},
        "host": {"ip_addresses": ["10.0.0.5"]},
        "notes": "PAN 4111 1111 1111 1111 used; FromBase64String('...') observed",
    }

    ctx = GDPRContext(
        tenant_id="acme",
        role=Role.CONTROLLER,
        legal_basis=LegalBasis.LEGITIMATE_INTERESTS,
        purposes={"security", "fraud_detection"},
        retention_days=90,
        consent_record_present=False,
        dpia_done=False,
        breach_detected=True,
        breach_discovered_at=_now_utc(),
        high_risk_to_rights=None,
        data_subjects_in_eu=True,
        transfers_to={"US"},
        eea_countries={"AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IS","IE","IT","LV","LI","LT","LU","MT","NL","NO","PL","PT","RO","SK","SI","ES","SE"},
        adequacy_countries=set(),  # прокидывайте актуальный список
        scc_in_place=False,
        dtia_done=False,
        technical_measures={"encryption_at_rest","encryption_in_transit","access_control"},
        organizational_measures={"dpa_signed","policy_logs_minimization"},
    )

    rep = map_event_to_gdpr(sample_event, ctx)
    flat = ReportFormatter.to_flat_dict(rep)
    # Печать для быстрой проверки
    import json as _json
    print(_json.dumps(flat, ensure_ascii=False, indent=2))

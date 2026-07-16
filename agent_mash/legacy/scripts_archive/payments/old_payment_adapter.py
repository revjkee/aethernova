# agent_mash/legacy/scripts_archive/payments/old_payment_adapter.py
"""
LEGACY PAYMENT ADAPTER

Статус:
    ARCHIVED / READ-ONLY

Назначение:
    Поддержка устаревших платёжных сценариев и форматов данных,
    использовавшихся до перехода на новую платёжную архитектуру.

ВАЖНО:
- Модуль не должен изменяться без крайней необходимости.
- Модуль не должен импортироваться в новый payment core.
- Модуль не выполняет сетевые вызовы.
- Вся логика детерминирована и синхронна.
"""

from __future__ import annotations

import datetime as _dt
import decimal
from dataclasses import dataclass
from typing import Any, Dict, Optional


# Явный контекст legacy
LEGACY_ADAPTER_VERSION = "1.0"
LEGACY_CURRENCY = "USD"


class LegacyPaymentError(Exception):
    """
    Базовое исключение legacy-платежей.
    """
    pass


@dataclass(frozen=True)
class LegacyPaymentRequest:
    """
    Входные данные legacy-платежа.
    """
    user_id: str
    amount: decimal.Decimal
    currency: str
    reference: str
    created_at: _dt.datetime


@dataclass(frozen=True)
class LegacyPaymentResult:
    """
    Результат обработки legacy-платежа.
    """
    success: bool
    normalized_amount: decimal.Decimal
    currency: str
    reference: str
    processed_at: _dt.datetime
    adapter_version: str
    error: Optional[str] = None


def _normalize_amount(value: Any) -> decimal.Decimal:
    """
    Приведение суммы к Decimal с фиксированной точностью.

    Legacy-системы могли передавать:
    - строки
    - float
    - int
    """
    try:
        amount = decimal.Decimal(str(value))
    except Exception as exc:
        raise LegacyPaymentError(f"Invalid amount format: {value}") from exc

    if amount <= 0:
        raise LegacyPaymentError("Amount must be positive")

    return amount.quantize(decimal.Decimal("0.01"), rounding=decimal.ROUND_HALF_UP)


def _normalize_currency(value: str) -> str:
    """
    Legacy-валидация валюты.
    """
    if not value or not isinstance(value, str):
        raise LegacyPaymentError("Currency must be a non-empty string")

    value = value.upper().strip()

    # Legacy ограничивался одной валютой
    if value != LEGACY_CURRENCY:
        raise LegacyPaymentError(f"Unsupported legacy currency: {value}")

    return value


def parse_legacy_request(payload: Dict[str, Any]) -> LegacyPaymentRequest:
    """
    Преобразует legacy payload в структурированный запрос.
    """
    try:
        user_id = str(payload["user_id"])
        reference = str(payload["reference"])
    except KeyError as exc:
        raise LegacyPaymentError(f"Missing required field: {exc}") from exc

    amount = _normalize_amount(payload.get("amount"))
    currency = _normalize_currency(payload.get("currency"))

    created_at_raw = payload.get("created_at")
    if isinstance(created_at_raw, _dt.datetime):
        created_at = created_at_raw
    else:
        created_at = _dt.datetime.utcnow()

    return LegacyPaymentRequest(
        user_id=user_id,
        amount=amount,
        currency=currency,
        reference=reference,
        created_at=created_at,
    )


def process_legacy_payment(payload: Dict[str, Any]) -> LegacyPaymentResult:
    """
    Основная точка входа legacy-адаптера.

    Никаких внешних вызовов.
    Только нормализация и валидация.
    """
    processed_at = _dt.datetime.utcnow()

    try:
        request = parse_legacy_request(payload)
    except LegacyPaymentError as exc:
        return LegacyPaymentResult(
            success=False,
            normalized_amount=decimal.Decimal("0.00"),
            currency=LEGACY_CURRENCY,
            reference=str(payload.get("reference", "")),
            processed_at=processed_at,
            adapter_version=LEGACY_ADAPTER_VERSION,
            error=str(exc),
        )

    return LegacyPaymentResult(
        success=True,
        normalized_amount=request.amount,
        currency=request.currency,
        reference=request.reference,
        processed_at=processed_at,
        adapter_version=LEGACY_ADAPTER_VERSION,
        error=None,
    )


__all__ = [
    "LEGACY_ADAPTER_VERSION",
    "LegacyPaymentError",
    "LegacyPaymentRequest",
    "LegacyPaymentResult",
    "process_legacy_payment",
]

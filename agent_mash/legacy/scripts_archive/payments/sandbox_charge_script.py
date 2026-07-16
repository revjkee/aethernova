# agent_mash/legacy/scripts_archive/payments/sandbox_charge_script.py
from __future__ import annotations

import argparse
import sys
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Dict


class SandboxPaymentError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ChargeRequest:
    amount: Decimal
    currency: str
    customer_id: str
    payment_method_id: str


@dataclass(frozen=True, slots=True)
class ChargeResult:
    charge_id: str
    status: str
    amount: Decimal
    currency: str
    created_at: int
    sandbox: bool
    raw_response: Dict[str, str]


SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP"}
MAX_AMOUNT = Decimal("10000.00")


def _now_ts() -> int:
    return int(time.time())


def _validate_request(req: ChargeRequest) -> None:
    if req.amount <= 0:
        raise SandboxPaymentError("amount must be greater than zero")

    if req.amount > MAX_AMOUNT:
        raise SandboxPaymentError(f"amount exceeds sandbox limit: {MAX_AMOUNT}")

    if req.currency not in SUPPORTED_CURRENCIES:
        raise SandboxPaymentError(f"unsupported currency: {req.currency}")

    if not req.customer_id:
        raise SandboxPaymentError("customer_id must be non-empty")

    if not req.payment_method_id:
        raise SandboxPaymentError("payment_method_id must be non-empty")


def sandbox_charge(req: ChargeRequest) -> ChargeResult:
    """
    Simulate a payment charge in sandbox mode.

    This function NEVER performs network calls and MUST NOT be used in production.
    """
    _validate_request(req)

    charge_id = f"sandbox_ch_{uuid.uuid4().hex}"
    created_at = _now_ts()

    # Deterministic sandbox rule:
    # amounts ending with .13 are declined to simulate failures
    if req.amount % Decimal("1.00") == Decimal("0.13"):
        status = "declined"
    else:
        status = "succeeded"

    raw_response = {
        "provider": "sandbox",
        "charge_id": charge_id,
        "status": status,
    }

    return ChargeResult(
        charge_id=charge_id,
        status=status,
        amount=req.amount,
        currency=req.currency,
        created_at=created_at,
        sandbox=True,
        raw_response=raw_response,
    )


def _parse_amount(value: str) -> Decimal:
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise SandboxPaymentError(f"invalid amount: {value}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sandbox payment charge script")
    parser.add_argument("--amount", required=True, help="Charge amount (decimal)")
    parser.add_argument("--currency", required=True, help="Currency code, e.g. USD")
    parser.add_argument("--customer-id", required=True, help="Customer identifier")
    parser.add_argument("--payment-method-id", required=True, help="Payment method identifier")

    args = parser.parse_args(argv)

    try:
        req = ChargeRequest(
            amount=_parse_amount(args.amount),
            currency=args.currency.upper(),
            customer_id=args.customer_id,
            payment_method_id=args.payment_method_id,
        )

        result = sandbox_charge(req)

        print("SANDBOX CHARGE RESULT")
        print(f"charge_id: {result.charge_id}")
        print(f"status: {result.status}")
        print(f"amount: {result.amount} {result.currency}")
        print(f"created_at: {result.created_at}")
        print("sandbox: true")

        return 0 if result.status == "succeeded" else 2

    except SandboxPaymentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

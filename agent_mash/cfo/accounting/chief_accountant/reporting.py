# agent_mash/cfo/accounting/chief_accountant/reporting.py
from __future__ import annotations

import csv
import dataclasses
import datetime as dt
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class AccountingError(Exception):
    pass


class ValidationError(AccountingError):
    pass


class ReportingError(AccountingError):
    pass


class AccountType(str, Enum):
    ASSET = "asset"
    LIABILITY = "liability"
    EQUITY = "equity"
    REVENUE = "revenue"
    EXPENSE = "expense"


class NormalBalance(str, Enum):
    DEBIT = "debit"
    CREDIT = "credit"


@dataclass(frozen=True)
class Money:
    """
    Денежная сумма в валюте с нормализацией масштаба.
    По умолчанию 2 знака после запятой (как в большинстве валют).
    """
    amount: Decimal
    currency: str = "USD"
    scale: int = 2

    def normalized(self) -> "Money":
        if not self.currency or not str(self.currency).strip():
            raise ValidationError("currency_required")
        q = Decimal(10) ** (-int(self.scale))
        a = self.amount.quantize(q, rounding=ROUND_HALF_UP)
        return Money(amount=a, currency=str(self.currency).upper().strip(), scale=int(self.scale))

    @staticmethod
    def zero(currency: str = "USD", scale: int = 2) -> "Money":
        return Money(amount=Decimal("0"), currency=currency, scale=scale).normalized()

    def __add__(self, other: "Money") -> "Money":
        a = self.normalized()
        b = other.normalized()
        if a.currency != b.currency or a.scale != b.scale:
            raise ValidationError("money_mismatch")
        return Money(amount=(a.amount + b.amount), currency=a.currency, scale=a.scale).normalized()

    def __sub__(self, other: "Money") -> "Money":
        a = self.normalized()
        b = other.normalized()
        if a.currency != b.currency or a.scale != b.scale:
            raise ValidationError("money_mismatch")
        return Money(amount=(a.amount - b.amount), currency=a.currency, scale=a.scale).normalized()

    def is_zero(self) -> bool:
        return self.normalized().amount == Decimal("0")


@dataclass(frozen=True)
class Account:
    account_id: str
    tenant_id: str
    code: str
    name: str
    type: AccountType
    normal_balance: NormalBalance
    tags: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "Account":
        if not self.account_id or not self.tenant_id:
            raise ValidationError("account_id_and_tenant_required")
        if not self.code or not self.name:
            raise ValidationError("account_code_and_name_required")
        return Account(
            account_id=str(self.account_id),
            tenant_id=str(self.tenant_id),
            code=str(self.code).strip(),
            name=str(self.name).strip(),
            type=AccountType(str(self.type.value)),
            normal_balance=NormalBalance(str(self.normal_balance.value)),
            tags=tuple(sorted({str(x).strip() for x in (self.tags or ()) if str(x).strip()})),
            metadata=dict(self.metadata or {}),
        )


@dataclass(frozen=True)
class JournalLine:
    account_id: str
    debit: Money
    credit: Money
    memo: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "JournalLine":
        if not self.account_id:
            raise ValidationError("line_account_required")
        d = self.debit.normalized()
        c = self.credit.normalized()
        if d.currency != c.currency or d.scale != c.scale:
            raise ValidationError("line_money_mismatch")
        if d.amount < 0 or c.amount < 0:
            raise ValidationError("negative_amount_not_allowed")
        if not d.is_zero() and not c.is_zero():
            raise ValidationError("line_both_debit_and_credit_set")
        if d.is_zero() and c.is_zero():
            raise ValidationError("line_empty_amount")
        return JournalLine(
            account_id=str(self.account_id),
            debit=d,
            credit=c,
            memo=str(self.memo or ""),
            metadata=dict(self.metadata or {}),
        )


@dataclass(frozen=True)
class JournalEntry:
    entry_id: str
    tenant_id: str
    posted_at: dt.datetime
    lines: Tuple[JournalLine, ...]
    reference: str = ""
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "JournalEntry":
        if not self.entry_id or not self.tenant_id:
            raise ValidationError("entry_id_and_tenant_required")
        if not isinstance(self.posted_at, dt.datetime):
            raise ValidationError("posted_at_required")
        if self.posted_at.tzinfo is None:
            raise ValidationError("posted_at_must_be_timezone_aware")
        if not self.lines:
            raise ValidationError("entry_lines_required")

        nl = tuple(line.normalized() for line in self.lines)
        cur = nl[0].debit.currency
        scale = nl[0].debit.scale

        total_debit = Money.zero(cur, scale)
        total_credit = Money.zero(cur, scale)
        for ln in nl:
            if ln.debit.currency != cur or ln.credit.currency != cur or ln.debit.scale != scale or ln.credit.scale != scale:
                raise ValidationError("entry_currency_inconsistent")
            total_debit = total_debit + ln.debit
            total_credit = total_credit + ln.credit

        if total_debit.amount != total_credit.amount:
            raise ValidationError("entry_not_balanced")

        return JournalEntry(
            entry_id=str(self.entry_id),
            tenant_id=str(self.tenant_id),
            posted_at=self.posted_at,
            lines=nl,
            reference=str(self.reference or ""),
            description=str(self.description or ""),
            metadata=dict(self.metadata or {}),
        )


@dataclass(frozen=True)
class Period:
    """
    Период включительно по start и end.
    """
    start: dt.datetime
    end: dt.datetime

    def normalized(self) -> "Period":
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValidationError("period_must_be_timezone_aware")
        if self.end < self.start:
            raise ValidationError("period_end_before_start")
        return self

    def contains(self, ts: dt.datetime) -> bool:
        if ts.tzinfo is None:
            raise ValidationError("timestamp_must_be_timezone_aware")
        p = self.normalized()
        return p.start <= ts <= p.end


@dataclass(frozen=True)
class Balance:
    debit: Money
    credit: Money

    @staticmethod
    def zero(currency: str, scale: int) -> "Balance":
        z = Money.zero(currency, scale)
        return Balance(debit=z, credit=z)

    def normalized(self) -> "Balance":
        d = self.debit.normalized()
        c = self.credit.normalized()
        if d.currency != c.currency or d.scale != c.scale:
            raise ValidationError("balance_money_mismatch")
        return Balance(debit=d, credit=c)

    def add_line(self, line: JournalLine) -> "Balance":
        b = self.normalized()
        ln = line.normalized()
        return Balance(
            debit=(b.debit + ln.debit),
            credit=(b.credit + ln.credit),
        ).normalized()

    def net(self, normal: NormalBalance) -> Money:
        b = self.normalized()
        if normal == NormalBalance.DEBIT:
            return (b.debit - b.credit).normalized()
        return (b.credit - b.debit).normalized()


@dataclass(frozen=True)
class TrialBalanceRow:
    account_id: str
    code: str
    name: str
    type: AccountType
    debit: Money
    credit: Money
    net: Money


@dataclass(frozen=True)
class TrialBalanceReport:
    tenant_id: str
    period: Period
    currency: str
    scale: int
    rows: Tuple[TrialBalanceRow, ...]
    total_debit: Money
    total_credit: Money

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "period": {"start": self.period.start.isoformat(), "end": self.period.end.isoformat()},
            "currency": self.currency,
            "scale": self.scale,
            "totals": {"debit": str(self.total_debit.amount), "credit": str(self.total_credit.amount)},
            "rows": [
                {
                    "account_id": r.account_id,
                    "code": r.code,
                    "name": r.name,
                    "type": r.type.value,
                    "debit": str(r.debit.amount),
                    "credit": str(r.credit.amount),
                    "net": str(r.net.amount),
                }
                for r in self.rows
            ],
        }

    def to_csv_rows(self) -> List[List[str]]:
        header = ["account_id", "code", "name", "type", "debit", "credit", "net"]
        rows = [header]
        for r in self.rows:
            rows.append(
                [
                    r.account_id,
                    r.code,
                    r.name,
                    r.type.value,
                    str(r.debit.amount),
                    str(r.credit.amount),
                    str(r.net.amount),
                ]
            )
        rows.append(["", "", "TOTAL", "", str(self.total_debit.amount), str(self.total_credit.amount), ""])
        return rows


@dataclass(frozen=True)
class IncomeStatementReport:
    tenant_id: str
    period: Period
    currency: str
    scale: int
    revenue_total: Money
    expense_total: Money
    net_income: Money
    breakdown: Mapping[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "period": {"start": self.period.start.isoformat(), "end": self.period.end.isoformat()},
            "currency": self.currency,
            "scale": self.scale,
            "revenue_total": str(self.revenue_total.amount),
            "expense_total": str(self.expense_total.amount),
            "net_income": str(self.net_income.amount),
            "breakdown": dict(self.breakdown),
        }


@dataclass(frozen=True)
class BalanceSheetReport:
    tenant_id: str
    as_of: dt.datetime
    currency: str
    scale: int
    assets_total: Money
    liabilities_total: Money
    equity_total: Money
    check_assets_eq_liab_plus_equity: bool
    breakdown: Mapping[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "as_of": self.as_of.isoformat(),
            "currency": self.currency,
            "scale": self.scale,
            "assets_total": str(self.assets_total.amount),
            "liabilities_total": str(self.liabilities_total.amount),
            "equity_total": str(self.equity_total.amount),
            "assets_eq_liab_plus_equity": bool(self.check_assets_eq_liab_plus_equity),
            "breakdown": dict(self.breakdown),
        }


@dataclass(frozen=True)
class CashFlowReport:
    tenant_id: str
    period: Period
    currency: str
    scale: int
    net_cash_change: Money
    cash_begin: Money
    cash_end: Money
    breakdown: Mapping[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "period": {"start": self.period.start.isoformat(), "end": self.period.end.isoformat()},
            "currency": self.currency,
            "scale": self.scale,
            "cash_begin": str(self.cash_begin.amount),
            "cash_end": str(self.cash_end.amount),
            "net_cash_change": str(self.net_cash_change.amount),
            "breakdown": dict(self.breakdown),
        }


@dataclass
class Ledger:
    """
    Леджер как контейнер проводок и план счетов.
    Встроенная изоляция по tenant_id при формировании отчётов.
    """
    accounts: Dict[str, Account] = field(default_factory=dict)
    entries: List[JournalEntry] = field(default_factory=list)

    def add_account(self, account: Account) -> None:
        a = account.normalized()
        if a.account_id in self.accounts:
            raise ValidationError("duplicate_account_id")
        self.accounts[a.account_id] = a

    def post(self, entry: JournalEntry) -> None:
        e = entry.normalized()
        for ln in e.lines:
            if ln.account_id not in self.accounts:
                raise ValidationError("unknown_account_in_entry")
        self.entries.append(e)

    def _entries_for(self, tenant_id: str, period: Optional[Period] = None) -> List[JournalEntry]:
        if not tenant_id:
            raise ValidationError("tenant_id_required")
        out: List[JournalEntry] = []
        for e in self.entries:
            if e.tenant_id != tenant_id:
                continue
            if period is not None and not period.contains(e.posted_at):
                continue
            out.append(e)
        return out

    def _currency_and_scale_for_tenant(self, tenant_id: str) -> Tuple[str, int]:
        es = self._entries_for(tenant_id, None)
        if es:
            first = es[0].lines[0].debit.normalized()
            return first.currency, first.scale
        return "USD", 2


class ReportingService:
    """
    Сервис построения отчётов. Детерминирован и проверяем.
    """

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    def trial_balance(self, *, tenant_id: str, period: Period) -> TrialBalanceReport:
        p = period.normalized()
        currency, scale = self._ledger._currency_and_scale_for_tenant(tenant_id)

        balances: Dict[str, Balance] = {}
        for acc_id, acc in self._ledger.accounts.items():
            if acc.tenant_id != tenant_id:
                continue
            balances[acc_id] = Balance.zero(currency, scale)

        for e in self._ledger._entries_for(tenant_id, p):
            for ln in e.lines:
                if ln.account_id not in balances:
                    acc = self._ledger.accounts.get(ln.account_id)
                    if acc is None or acc.tenant_id != tenant_id:
                        raise ReportingError("tenant_isolation_violation")
                    balances[ln.account_id] = Balance.zero(currency, scale)
                balances[ln.account_id] = balances[ln.account_id].add_line(ln)

        rows: List[TrialBalanceRow] = []
        total_debit = Money.zero(currency, scale)
        total_credit = Money.zero(currency, scale)

        for acc_id, bal in sorted(balances.items(), key=lambda x: self._ledger.accounts[x[0]].code):
            acc = self._ledger.accounts[acc_id]
            b = bal.normalized()
            d = b.debit.normalized()
            c = b.credit.normalized()
            net = b.net(acc.normal_balance)
            rows.append(
                TrialBalanceRow(
                    account_id=acc_id,
                    code=acc.code,
                    name=acc.name,
                    type=acc.type,
                    debit=d,
                    credit=c,
                    net=net,
                )
            )
            total_debit = total_debit + d
            total_credit = total_credit + c

        if total_debit.amount != total_credit.amount:
            raise ReportingError("trial_balance_not_balanced")

        return TrialBalanceReport(
            tenant_id=tenant_id,
            period=p,
            currency=currency,
            scale=scale,
            rows=tuple(rows),
            total_debit=total_debit.normalized(),
            total_credit=total_credit.normalized(),
        )

    def income_statement(self, *, tenant_id: str, period: Period) -> IncomeStatementReport:
        tb = self.trial_balance(tenant_id=tenant_id, period=period)
        currency, scale = tb.currency, tb.scale

        revenue_total = Money.zero(currency, scale)
        expense_total = Money.zero(currency, scale)

        by_account: List[Dict[str, Any]] = []

        for r in tb.rows:
            if r.type == AccountType.REVENUE:
                amt = r.net
                revenue_total = revenue_total + amt
                by_account.append({"code": r.code, "name": r.name, "type": r.type.value, "amount": str(amt.amount)})
            elif r.type == AccountType.EXPENSE:
                amt = r.net
                expense_total = expense_total + amt
                by_account.append({"code": r.code, "name": r.name, "type": r.type.value, "amount": str(amt.amount)})

        net_income = (revenue_total - expense_total).normalized()

        breakdown = {
            "accounts": by_account,
        }

        return IncomeStatementReport(
            tenant_id=tenant_id,
            period=period.normalized(),
            currency=currency,
            scale=scale,
            revenue_total=revenue_total.normalized(),
            expense_total=expense_total.normalized(),
            net_income=net_income,
            breakdown=breakdown,
        )

    def balance_sheet(self, *, tenant_id: str, as_of: dt.datetime) -> BalanceSheetReport:
        if as_of.tzinfo is None:
            raise ValidationError("as_of_must_be_timezone_aware")

        # Balance sheet as of date: include entries up to as_of
        period = Period(
            start=dt.datetime.min.replace(tzinfo=as_of.tzinfo),
            end=as_of,
        ).normalized()

        tb = self.trial_balance(tenant_id=tenant_id, period=period)
        currency, scale = tb.currency, tb.scale

        assets_total = Money.zero(currency, scale)
        liabilities_total = Money.zero(currency, scale)
        equity_total = Money.zero(currency, scale)

        assets: List[Dict[str, Any]] = []
        liabilities: List[Dict[str, Any]] = []
        equity: List[Dict[str, Any]] = []

        for r in tb.rows:
            amt = r.net
            if r.type == AccountType.ASSET:
                assets_total = assets_total + amt
                assets.append({"code": r.code, "name": r.name, "amount": str(amt.amount)})
            elif r.type == AccountType.LIABILITY:
                liabilities_total = liabilities_total + amt
                liabilities.append({"code": r.code, "name": r.name, "amount": str(amt.amount)})
            elif r.type == AccountType.EQUITY:
                equity_total = equity_total + amt
                equity.append({"code": r.code, "name": r.name, "amount": str(amt.amount)})

        check = assets_total.amount == (liabilities_total.amount + equity_total.amount)

        breakdown = {
            "assets": assets,
            "liabilities": liabilities,
            "equity": equity,
        }

        return BalanceSheetReport(
            tenant_id=tenant_id,
            as_of=as_of,
            currency=currency,
            scale=scale,
            assets_total=assets_total.normalized(),
            liabilities_total=liabilities_total.normalized(),
            equity_total=equity_total.normalized(),
            check_assets_eq_liab_plus_equity=check,
            breakdown=breakdown,
        )

    def cash_flow_indirect(
        self,
        *,
        tenant_id: str,
        period: Period,
        cash_account_ids: Sequence[str],
    ) -> CashFlowReport:
        """
        Cash Flow косвенным методом:
        cash_change = cash_end - cash_begin
        Здесь cash_begin/cash_end берутся по выбранным cash_account_ids (обычно касса/банк).
        Разложение:
        - net_income из PnL
        - delta_working_capital как изменения балансовых статей (активы/обязательства кроме cash)
        Важно: это управленческая оценка. Для точного CF по прямому методу нужны классификаторы cash-движений.
        """
        p = period.normalized()
        if not cash_account_ids:
            raise ValidationError("cash_accounts_required")

        is_report = self.income_statement(tenant_id=tenant_id, period=p)
        bs_begin = self.balance_sheet(tenant_id=tenant_id, as_of=p.start)
        bs_end = self.balance_sheet(tenant_id=tenant_id, as_of=p.end)

        currency, scale = is_report.currency, is_report.scale

        def _sum_cash(bs: BalanceSheetReport) -> Money:
            total = Money.zero(currency, scale)
            # rebuild balances from tb to extract specific accounts
            tb = self.trial_balance(tenant_id=tenant_id, period=Period(start=dt.datetime.min.replace(tzinfo=bs.as_of.tzinfo), end=bs.as_of))
            by_id = {row.account_id: row for row in tb.rows}
            for acc_id in cash_account_ids:
                row = by_id.get(acc_id)
                if row is None:
                    continue
                total = total + row.net
            return total.normalized()

        cash_begin = _sum_cash(bs_begin)
        cash_end = _sum_cash(bs_end)
        net_cash_change = (cash_end - cash_begin).normalized()

        # Working capital delta approximation:
        # delta_non_cash_assets - delta_liabilities (excluding equity), excluding cash accounts
        tb_begin = self.trial_balance(
            tenant_id=tenant_id,
            period=Period(start=dt.datetime.min.replace(tzinfo=p.start.tzinfo), end=p.start),
        )
        tb_end = self.trial_balance(
            tenant_id=tenant_id,
            period=Period(start=dt.datetime.min.replace(tzinfo=p.end.tzinfo), end=p.end),
        )

        begin_map = {r.account_id: r for r in tb_begin.rows}
        end_map = {r.account_id: r for r in tb_end.rows}

        delta_non_cash_assets = Money.zero(currency, scale)
        delta_liabilities = Money.zero(currency, scale)

        cash_set = set(str(x) for x in cash_account_ids)

        for acc_id, acc in self._ledger.accounts.items():
            if acc.tenant_id != tenant_id:
                continue
            if acc_id in cash_set:
                continue

            b = begin_map.get(acc_id)
            e = end_map.get(acc_id)
            b_amt = b.net if b is not None else Money.zero(currency, scale)
            e_amt = e.net if e is not None else Money.zero(currency, scale)
            delta = (e_amt - b_amt).normalized()

            if acc.type == AccountType.ASSET:
                delta_non_cash_assets = delta_non_cash_assets + delta
            elif acc.type == AccountType.LIABILITY:
                delta_liabilities = delta_liabilities + delta

        # Indirect:
        # cash_change ~= net_income - increase_in_non_cash_assets + increase_in_liabilities
        computed = (is_report.net_income - delta_non_cash_assets + delta_liabilities).normalized()

        breakdown = {
            "net_income": str(is_report.net_income.amount),
            "delta_non_cash_assets": str(delta_non_cash_assets.amount),
            "delta_liabilities": str(delta_liabilities.amount),
            "computed_net_cash_change": str(computed.amount),
            "reported_net_cash_change": str(net_cash_change.amount),
            "note": "computed is an approximation by indirect method without direct cash classification",
        }

        return CashFlowReport(
            tenant_id=tenant_id,
            period=p,
            currency=currency,
            scale=scale,
            net_cash_change=net_cash_change,
            cash_begin=cash_begin,
            cash_end=cash_end,
            breakdown=breakdown,
        )

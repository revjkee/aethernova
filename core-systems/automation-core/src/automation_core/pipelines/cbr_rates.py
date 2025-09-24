# -*- coding: utf-8 -*-
"""
CBR (Bank of Russia) official exchange rates pipeline.

This module fetches and parses official exchange rates published by
the Bank of Russia via documented XML endpoints.

Verified sources (official Bank of Russia pages):
- "Получение данных, используя XML" (XML endpoints and parameters):
  * XML_daily.asp?date_req=dd/mm/yyyy  — daily rates on a selected date
  * XML_dynamic.asp?date_req1=...&date_req2=...&VAL_NM_RQ=... — time series per currency
  The page describes parameters (date_req, date_req1/date_req2, VAL_NM_RQ) and examples.
  https://www.cbr.ru/development/sxml/  # :contentReference[oaicite:2]{index=2}
- Daily base page (English): https://www.cbr.ru/eng/currency_base/daily/  # :contentReference[oaicite:3]{index=3}
- Dynamics page (English):   https://www.cbr.ru/eng/currency_base/dynamics/  # :contentReference[oaicite:4]{index=4}

Notes:
- Official XML responses use Windows-1251 encoding as indicated in XML prolog (<?xml ... encoding="windows-1251"?>).
  The code respects this by honoring response.apparent_encoding and falling back to "windows-1251".
- Monetary values in XML ("Value") use comma as decimal separator; we convert them to Decimal using a safe replace.

Unverified (environment-specific): your network/proxy settings and desired persistence layer. In-memory cache is provided.

Public API:
- CBRClient.get_daily(date: datetime.date | None) -> DailyRates
- CBRClient.get_dynamic(char_code: str, start: date, end: date) -> list[tuple[date, Decimal]]
- CBRClient.convert(amount: Decimal, from_code: str, to_code: str, date: date | None) -> Decimal
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP, getcontext
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlencode

import requests
import xml.etree.ElementTree as ET
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__all__ = [
    "Rate",
    "DailyRates",
    "CBRClient",
    "CBRClientError",
]

# Set a sensible global precision for financial conversions (can be tuned by caller)
getcontext().prec = 28

_LOG = logging.getLogger(__name__)


# --------------------------- Data models ---------------------------

@dataclass(frozen=True)
class Rate:
    """Official rate entry for a currency against RUB on a given date."""
    id: str          # CBR VAL_NM_RQ identifier (e.g., "R01235" for USD)
    num_code: str    # ISO numeric (e.g., "840")
    char_code: str   # ISO alpha (e.g., "USD")
    nominal: int     # units count the value applies to (e.g., 1, 10, 100)
    name: str        # currency display name (RU or EN, depends on endpoint)
    value: Decimal   # value in RUB per <nominal> units


@dataclass(frozen=True)
class DailyRates:
    """Container for a day's official rates."""
    as_of: date
    rates: Mapping[str, Rate]  # keyed by char_code (e.g., "USD")

    def get(self, char_code: str) -> Optional[Rate]:
        return self.rates.get(char_code.upper())


# --------------------------- Exceptions ----------------------------

class CBRClientError(RuntimeError):
    pass


# --------------------------- Utilities -----------------------------

def _ddmmyyyy(d: date) -> str:
    return f"{d:%d/%m/%Y}"


def _parse_decimal_ru(text: str) -> Decimal:
    # CBR XML uses comma decimal separator, e.g., "92,3456"
    return Decimal(text.replace(",", ".")).quantize(Decimal("0.0001"))


def _as_int(text: str) -> int:
    return int(text.strip())


def _ensure_encoding(resp: requests.Response) -> None:
    # Respect server-declared encoding; default to windows-1251 per XML prolog on CBR endpoints.
    if not resp.encoding:
        # requests may auto-detect; if not, set explicitly
        resp.encoding = resp.apparent_encoding or "windows-1251"


# --------------------------- Client -------------------------------

class CBRClient:
    """
    Industrial client for Bank of Russia XML rates.

    Endpoints (documented by Bank of Russia):
      - /scripts/XML_daily.asp?date_req=dd/mm/yyyy       — daily rates on selected date
      - /scripts/XML_dynamic.asp?date_req1=...&date_req2=...&VAL_NM_RQ=... — time series for currency
    Parameters and examples are described on: https://www.cbr.ru/development/sxml/  # :contentReference[oaicite:5]{index=5}
    """

    BASE = "https://www.cbr.ru"

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        retries: int = 5,
        backoff_factor: float = 0.5,
        user_agent: str = "automation-core/CBRClient (+https://www.cbr.ru/development/sxml/)",
        session: Optional[requests.Session] = None,
    ) -> None:
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

        retry = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        # simple in-memory cache: {(endpoint, params_tuple): (etag, payload)}
        self._cache: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], Any] = {}

    # ----------------------- HTTP helpers -----------------------

    def _get(self, path: str, params: Mapping[str, str]) -> str:
        url = f"{self.BASE}{path}"
        # caching key
        key = (path, tuple(sorted(params.items())))
        if key in self._cache:
            return self._cache[key]

        resp = self._session.get(url, params=params, timeout=self._timeout)
        _ensure_encoding(resp)
        if resp.status_code != 200:
            raise CBRClientError(f"CBR HTTP {resp.status_code}: {resp.text[:200]}")
        text = resp.text
        # cache
        self._cache[key] = text
        return text

    # ----------------------- Public API ------------------------

    def get_daily(self, on_date: Optional[date] = None, *, english: bool = False) -> DailyRates:
        """
        Fetch official daily rates for a given date (or latest available if on_date is None).

        Endpoint:
          /scripts/XML_daily.asp?date_req=dd/mm/yyyy      (or XML_daily_eng.asp for EN)
          If date_req is absent, the latest registered date is returned (per docs).  # :contentReference[oaicite:6]{index=6}
        """
        path = "/scripts/XML_daily_eng.asp" if english else "/scripts/XML_daily.asp"
        params: Dict[str, str] = {}
        if on_date is not None:
            params["date_req"] = _ddmmyyyy(on_date)

        xml_text = self._get(path, params)
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            raise CBRClientError(f"Failed to parse CBR XML_daily: {e}")

        # Example root: <ValCurs Date="27.08.2025" name="Foreign Currency Market">
        as_of_str = root.attrib.get("Date") or ""
        try:
            # ValCurs Date is dd.mm.yyyy
            as_of = datetime.strptime(as_of_str, "%d.%m.%Y").date()
        except ValueError:
            # Fallback: use requested date if provided, else today's date (best-effort)
            as_of = on_date or date.today()

        rates: Dict[str, Rate] = {}
        for val in root.findall("./Valute"):
            rid = val.attrib.get("ID", "")
            num_code = (val.findtext("NumCode") or "").strip()
            char_code = (val.findtext("CharCode") or "").strip().upper()
            nominal = _as_int(val.findtext("Nominal") or "1")
            name = (val.findtext("Name") or "").strip()
            value = _parse_decimal_ru(val.findtext("Value") or "0")
            rates[char_code] = Rate(
                id=rid,
                num_code=num_code,
                char_code=char_code,
                nominal=nominal,
                name=name,
                value=value,
            )

        return DailyRates(as_of=as_of, rates=rates)

    def resolve_currency_id(self, char_code: str, on_date: Optional[date] = None) -> str:
        """
        Resolve CBR currency identifier (VAL_NM_RQ) by ISO char code (e.g., USD -> R01235).
        According to docs, VAL_NM_RQ can be obtained from the daily XML (Example 1).  # :contentReference[oaicite:7]{index=7}
        """
        daily = self.get_daily(on_date)
        rate = daily.get(char_code)
        if not rate or not rate.id:
            raise CBRClientError(f"Currency {char_code!r} not found in CBR daily rates")
        return rate.id

    def get_dynamic(self, char_code: str, start: date, end: date) -> List[Tuple[date, Decimal]]:
        """
        Fetch time series for a currency (against RUB) over [start, end], inclusive.

        Endpoint and parameters per official docs:
          /scripts/XML_dynamic.asp?date_req1=dd/mm/yyyy&date_req2=dd/mm/yyyy&VAL_NM_RQ=<id>  # :contentReference[oaicite:8]{index=8}
        """
        if start > end:
            raise ValueError("start date must be <= end date")

        currency_id = self.resolve_currency_id(char_code, on_date=end)
        params = {
            "date_req1": _ddmmyyyy(start),
            "date_req2": _ddmmyyyy(end),
            "VAL_NM_RQ": currency_id,
        }
        xml_text = self._get("/scripts/XML_dynamic.asp", params)
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            raise CBRClientError(f"Failed to parse CBR XML_dynamic: {e}")

        series: List[Tuple[date, Decimal]] = []
        # Structure: <ValCurs ID="R01235" DateRange1="..." DateRange2="..." name="Foreign Currency Market">
        # Values are under <Record Date="dd.mm.yyyy"><Nominal>..</Nominal><Value>..</Value></Record>
        for rec in root.findall("./Record"):
            ds = rec.attrib.get("Date", "")
            try:
                d = datetime.strptime(ds, "%d.%m.%Y").date()
            except ValueError:
                continue
            nominal = _as_int(rec.findtext("Nominal") or "1")
            value = _parse_decimal_ru(rec.findtext("Value") or "0")
            # Normalize to per 1 unit to simplify consumers
            per_one = (value / Decimal(nominal)).quantize(Decimal("0.0001"))
            series.append((d, per_one))

        series.sort(key=lambda x: x[0])
        return series

    # ----------------------- Conversions ------------------------

    def convert(self, amount: Decimal, from_code: str, to_code: str, on_date: Optional[date] = None) -> Decimal:
        """
        Convert amount between currencies using official CBR rates via RUB cross.

        For daily rates, official base is RUB; we compute:
          amount_in_rub = amount * (value_from / nominal_from)
          result        = amount_in_rub / (value_to / nominal_to)
        """
        if from_code.upper() == to_code.upper():
            return amount

        daily = self.get_daily(on_date)
        rf = daily.get(from_code)
        rt = daily.get(to_code)
        if from_code.upper() != "RUB" and not rf:
            raise CBRClientError(f"Rate for {from_code} not found on {daily.as_of}")
        if to_code.upper() != "RUB" and not rt:
            raise CBRClientError(f"Rate for {to_code} not found on {daily.as_of}")

        # Compute amount in RUB first
        if from_code.upper() == "RUB":
            amount_in_rub = amount
        else:
            amount_in_rub = (amount * (rf.value / Decimal(rf.nominal))).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)

        # Convert from RUB to target
        if to_code.upper() == "RUB":
            return amount_in_rub

        result = (amount_in_rub / (rt.value / Decimal(rt.nominal))).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
        return result

    # ----------------------- Caching API ------------------------

    def clear_cache(self) -> None:
        self._cache.clear()


# --------------------------- Convenience ----------------------------

@functools.lru_cache(maxsize=64)
def default_client() -> CBRClient:
    """Shared default client with sane retries/timeouts."""
    return CBRClient()

# filepath: automation-core/examples/fetch_cbr_rates.py
"""
Fetch official exchange rates from the Bank of Russia (CBR) XML endpoints.

Authoritative reference (CBR official):
- XML daily quotes (XML_daily.asp) with date_req=dd/mm/yyyy; if absent -> last published date.
- Currency codes directory (XML_val.asp?d=0).
- Dynamics over a date range for a currency (XML_dynamic.asp) with VAL_NM_RQ.
Docs: https://www.cbr.ru/development/sxml/
Key examples & parameter semantics are explicitly shown on that page.

This script:
- Uses only Python stdlib (urllib, xml.etree) — no third-party deps.
- Robust HTTP: timeouts, retries with exponential backoff, basic validation.
- Supports: daily snapshot (--date), dynamics (--range-start/--range-end + --code or --char-code),
  currency filtering (--char-codes), normalization to "per 1 unit" price.
- Outputs JSON or CSV, stdout or file.
- Locale-agnostic parsing of numeric values (CBR XML uses comma decimal; we normalize to float).

Usage examples:
  # Daily rates for latest published date, all currencies -> JSON to stdout
  python fetch_cbr_rates.py daily --format json

  # Daily rates for 2025-09-05, filter by USD,EUR -> CSV file
  python fetch_cbr_rates.py daily --date 2025-09-05 --char-codes USD,EUR --format csv --out rates.csv

  # Dynamics for USD (by char code) between two dates -> JSON
  python fetch_cbr_rates.py dynamic --range-start 2025-08-01 --range-end 2025-09-05 --char-code USD --format json

  # Dynamics for specific VAL_NM_RQ (e.g., R01235 for USD) -> CSV
  python fetch_cbr_rates.py dynamic --range-start 2025-08-01 --range-end 2025-09-05 --code R01235 --format csv

Exit codes:
  0 success; 2 usage error; 3 remote/parse error; 4 empty result (not considered a hard error unless --strict-empty).

NOTE: Endpoints & parameter semantics taken from the official CBR page above.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import io
import json
import sys
import time
import typing as t
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

CBR_BASE = "https://www.cbr.ru"
ENDPOINT_DAILY = "/scripts/XML_daily.asp"
ENDPOINT_VALDIR = "/scripts/XML_val.asp"      # with ?d=0 for daily-set currencies (directory)
ENDPOINT_DYNAMIC = "/scripts/XML_dynamic.asp" # with date_req1, date_req2, VAL_NM_RQ

DEFAULT_TIMEOUT = 10.0
MAX_RETRIES = 4
BACKOFF_BASE = 0.6
USER_AGENT = "automation-core-fetch-cbr/1.0 (+https://www.cbr.ru/development/sxml/)"

# --------------------------- utils ---------------------------

def _iso_to_cbr(date_iso: str) -> str:
    """
    Convert 'YYYY-MM-DD' -> 'dd/mm/yyyy' required by CBR endpoints.
    """
    d = dt.date.fromisoformat(date_iso)
    return f"{d.day:02d}/{d.month:02d}/{d.year:04d}"

def _fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """
    Fetch URL with retries and exponential backoff.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                # CBR responds text/xml; read bytes and let XML parser decode
                return resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_err = e
            # backoff
            sleep_s = BACKOFF_BASE * (2 ** (attempt - 1))
            time.sleep(sleep_s)
    raise RuntimeError(f"Failed to fetch {url!r} after {MAX_RETRIES} retries: {last_err}")

def _parse_xml(xml_bytes: bytes) -> ET.Element:
    try:
        return ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise RuntimeError(f"Invalid XML: {e}") from e

def _to_float_cbr(text: str) -> float:
    """
    CBR XML numbers often use comma as decimal separator; normalize.
    """
    txt = (text or "").strip().replace(",", ".")
    return float(txt)

# --------------------------- models ---------------------------

@dataclasses.dataclass(frozen=True)
class DailyRate:
    date: str          # ISO date of the rates (CBR assigns a single date to the set)
    id: str            # VAL_NM_RQ (e.g., R01235)
    num_code: str
    char_code: str
    nominal: int
    name: str
    value: float       # value per 'nominal' units in RUB
    value_per_unit: float  # normalized per 1 unit (value / nominal)

@dataclasses.dataclass(frozen=True)
class DynamicPoint:
    id: str            # VAL_NM_RQ
    char_code: str     # best-effort fill (from directory), if available
    date: str          # ISO yyyy-mm-dd
    value: float       # RUB per 'nominal' units as provided in XML
    nominal: int       # nominal units for the quotation
    value_per_unit: float

# --------------------------- directory (codes) ---------------------------

def fetch_currency_directory(timeout: float = DEFAULT_TIMEOUT) -> dict[str, dict[str, str]]:
    """
    Fetch currency directory (d=0) returning mapping by VAL_NM_RQ and by CharCode.
    Docs: XML_val.asp?d=0 on CBR XML page.
    """
    q = urllib.parse.urlencode({"d": 0})
    url = f"{CBR_BASE}{ENDPOINT_VALDIR}?{q}"
    root = _parse_xml(_fetch(url, timeout=timeout))
    by_id: dict[str, dict[str, str]] = {}
    by_cc: dict[str, dict[str, str]] = {}
    for el in root.findall(".//Item"):
        # Structure typically: <Item ID="R01235"><Name>…</Name><EngName>…</EngName><Nominal>1</Nominal><ParentCode>…</ParentCode><ISO_Num_Code>840</ISO_Num_Code><ISO_Char_Code>USD</ISO_Char_Code></Item>
        vid = el.get("ID") or ""
        name = (el.findtext("Name") or "").strip()
        iso_cc = (el.findtext("ISO_Char_Code") or "").strip()
        nominal = (el.findtext("Nominal") or "1").strip()
        by_id[vid] = {"Name": name, "ISO_Char_Code": iso_cc, "Nominal": nominal}
        if iso_cc:
            by_cc[iso_cc.upper()] = {"ID": vid, "Name": name, "Nominal": nominal}
    return {"by_id": by_id, "by_char": by_cc}

# --------------------------- daily ---------------------------

def fetch_daily(date_iso: str | None, timeout: float = DEFAULT_TIMEOUT, filter_char_codes: set[str] | None = None) -> list[DailyRate]:
    """
    Fetch daily rates for a given ISO date or latest published if None.
    Docs (CBR): XML_daily.asp with optional date_req=dd/mm/yyyy.
    """
    params = {}
    if date_iso:
        params["date_req"] = _iso_to_cbr(date_iso)
    url = f"{CBR_BASE}{ENDPOINT_DAILY}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    root = _parse_xml(_fetch(url, timeout=timeout))

    # Date attribute present on root <ValCurs Date="DD.MM.YYYY" name="Foreign Currency Market">
    date_attr = root.get("Date") or ""
    if date_attr:
        # convert "DD.MM.YYYY" -> ISO
        d = dt.datetime.strptime(date_attr, "%d.%m.%Y").date().isoformat()
    else:
        # fallback to provided date or today (shouldn't happen in practice)
        d = (date_iso or dt.date.today().isoformat())

    out: list[DailyRate] = []
    wanted = {cc.upper() for cc in (filter_char_codes or set())}
    for val in root.findall(".//Valute"):
        char = (val.findtext("CharCode") or "").strip().upper()
        if wanted and char not in wanted:
            continue
        vid = val.get("ID") or ""
        num = (val.findtext("NumCode") or "").strip()
        nominal = int((val.findtext("Nominal") or "1").strip())
        name = (val.findtext("Name") or "").strip()
        value = _to_float_cbr(val.findtext("Value") or "0")
        out.append(DailyRate(
            date=d, id=vid, num_code=num, char_code=char, nominal=nominal,
            name=name, value=value, value_per_unit=(value / nominal if nominal else value),
        ))
    return out

# --------------------------- dynamic ---------------------------

def fetch_dynamic(
    start_iso: str,
    end_iso: str,
    id_or_char: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[DynamicPoint]:
    """
    Fetch dynamics for a currency using VAL_NM_RQ or ISO char code.

    If id_or_char looks like Rdddddd, use as is; otherwise resolve char code -> ID via directory.
    Docs: XML_dynamic.asp requires date_req1, date_req2, VAL_NM_RQ.
    """
    cur_id = id_or_char
    char_code = ""
    if not id_or_char.upper().startswith("R0"):
        # resolve char -> ID
        dir_map = fetch_currency_directory(timeout=timeout)
        cc_map = dir_map["by_char"]
        item = cc_map.get(id_or_char.upper())
        if not item:
            raise ValueError(f"Unknown char code {id_or_char!r} (not found in CBR directory)")
        cur_id = item["ID"]
        char_code = id_or_char.upper()
    else:
        # try to discover char code from directory (best-effort)
        dir_map = fetch_currency_directory(timeout=timeout)
        info = dir_map["by_id"].get(id_or_char)
        if info:
            char_code = (info.get("ISO_Char_Code") or "").upper()  # may be empty if not in daily-set

    params = {
        "date_req1": _iso_to_cbr(start_iso),
        "date_req2": _iso_to_cbr(end_iso),
        "VAL_NM_RQ": cur_id,
    }
    url = f"{CBR_BASE}{ENDPOINT_DYNAMIC}?{urllib.parse.urlencode(params)}"
    root = _parse_xml(_fetch(url, timeout=timeout))

    out: list[DynamicPoint] = []
    # Typical structure: <Record Date="01.09.2025" Id="R01235"><Nominal>1</Nominal><Value>90,1234</Value></Record>
    for rec in root.findall(".//Record"):
        date_attr = rec.get("Date") or ""
        dt_iso = dt.datetime.strptime(date_attr, "%d.%m.%Y").date().isoformat()
        nominal = int((rec.findtext("Nominal") or "1").strip())
        value = _to_float_cbr(rec.findtext("Value") or "0")
        out.append(DynamicPoint(
            id=cur_id,
            char_code=char_code,
            date=dt_iso,
            nominal=nominal,
            value=value,
            value_per_unit=(value / nominal if nominal else value),
        ))
    return out

# --------------------------- output ---------------------------

def _to_json(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=_json_default)

def _json_default(o):
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    raise TypeError(f"Type not serializable: {type(o)}")

def write_json(data: list[dict] | list[DailyRate] | list[DynamicPoint], out_path: str | None) -> None:
    payload = _to_json(data)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(payload)
    else:
        sys.stdout.write(payload + "\n")

def write_csv_daily(rows: list[DailyRate], out_path: str | None) -> None:
    fieldnames = ["date", "id", "num_code", "char_code", "nominal", "name", "value", "value_per_unit"]
    _write_csv([dataclasses.asdict(r) for r in rows], fieldnames, out_path)

def write_csv_dynamic(rows: list[DynamicPoint], out_path: str | None) -> None:
    fieldnames = ["date", "id", "char_code", "nominal", "value", "value_per_unit"]
    _write_csv([dataclasses.asdict(r) for r in rows], fieldnames, out_path)

def _write_csv(rows: list[dict], fieldnames: list[str], out_path: str | None) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    content = buf.getvalue()
    if out_path:
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    else:
        sys.stdout.write(content)

# --------------------------- CLI ---------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fetch_cbr_rates.py",
        description="Fetch official CBR FX rates (daily or dynamics) and export to JSON/CSV.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_daily = sub.add_parser("daily", help="Fetch daily rates for a date (or latest published if omitted).")
    p_daily.add_argument("--date", help="ISO date YYYY-MM-DD; if omitted, use the latest published set.")
    p_daily.add_argument("--char-codes", help="Comma-separated ISO char codes to filter (e.g., USD,EUR).")
    p_daily.add_argument("--format", choices=["json", "csv"], default="json")
    p_daily.add_argument("--out", help="Output file path (stdout if omitted).")
    p_daily.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p_daily.add_argument("--strict-empty", action="store_true", help="Non-zero exit if result is empty.")

    p_dyn = sub.add_parser("dynamic", help="Fetch dynamics for a currency by VAL_NM_RQ or char code.")
    p_dyn.add_argument("--range-start", required=True, help="ISO start date, YYYY-MM-DD")
    p_dyn.add_argument("--range-end", required=True, help="ISO end date, YYYY-MM-DD")
    grp = p_dyn.add_mutually_exclusive_group(required=True)
    grp.add_argument("--code", help="CBR currency ID (VAL_NM_RQ), e.g., R01235 for USD.")
    grp.add_argument("--char-code", help="ISO char code, e.g., USD.")
    p_dyn.add_argument("--format", choices=["json", "csv"], default="json")
    p_dyn.add_argument("--out", help="Output file path (stdout if omitted).")
    p_dyn.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p_dyn.add_argument("--strict-empty", action="store_true", help="Non-zero exit if result is empty.")

    return p

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.cmd == "daily":
            codes: set[str] | None = None
            if args.char_codes:
                codes = {c.strip().upper() for c in args.char_codes.split(",") if c.strip()}
            rows = fetch_daily(args.date, timeout=args.timeout, filter_char_codes=codes)
            if args.strict_empty and not rows:
                sys.stderr.write("No daily rates returned\n")
                return 4
            if args.format == "json":
                write_json(rows, args.out)
            else:
                write_csv_daily(rows, args.out)
            return 0

        if args.cmd == "dynamic":
            target = args.code or args.char_code
            rows = fetch_dynamic(args.range_start, args.range_end, target, timeout=args.timeout)
            if args.strict_empty and not rows:
                sys.stderr.write("No dynamic points returned\n")
                return 4
            if args.format == "json":
                write_json(rows, args.out)
            else:
                write_csv_dynamic(rows, args.out)
            return 0

        sys.stderr.write("Unknown command\n")
        return 2

    except ValueError as e:
        sys.stderr.write(f"Usage/data error: {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Remote/parse error: {e}\n")
        return 3

if __name__ == "__main__":
    sys.exit(main())

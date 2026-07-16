# agent_mash/tests/tools/coverage_enforcer.py
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Mapping


class CoverageEnforcerError(Exception):
    pass


def _read_json(path: str) -> Mapping[str, Any]:
    if not os.path.exists(path):
        raise CoverageEnforcerError(f"coverage report not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise CoverageEnforcerError(f"invalid JSON in coverage report: {path}") from exc


def _extract_total_coverage(data: Mapping[str, Any]) -> float:
    """
    Expected coverage.py JSON structure:
    {
      "totals": {
        "percent_covered": 87.32,
        ...
      }
    }
    """
    totals = data.get("totals")
    if not isinstance(totals, Mapping):
        raise CoverageEnforcerError("missing 'totals' section in coverage report")

    percent = totals.get("percent_covered")
    if not isinstance(percent, (int, float)):
        raise CoverageEnforcerError("missing or invalid 'percent_covered' value")

    return float(percent)


def _parse_threshold(value: str) -> float:
    try:
        threshold = float(value)
    except ValueError as exc:
        raise CoverageEnforcerError(f"invalid coverage threshold: {value}") from exc

    if threshold < 0.0 or threshold > 100.0:
        raise CoverageEnforcerError("coverage threshold must be between 0 and 100")

    return threshold


def enforce_coverage(report_path: str, min_coverage: float) -> None:
    data = _read_json(report_path)
    actual = _extract_total_coverage(data)

    if actual < min_coverage:
        raise CoverageEnforcerError(
            f"coverage check failed: {actual:.2f}% < required {min_coverage:.2f}%"
        )

    print(f"coverage check passed: {actual:.2f}% >= {min_coverage:.2f}%")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail build if coverage.py total coverage is below threshold"
    )
    parser.add_argument(
        "--report",
        default=os.environ.get("COVERAGE_JSON", "coverage.json"),
        help="Path to coverage.py JSON report (default: coverage.json or COVERAGE_JSON env)",
    )
    parser.add_argument(
        "--min",
        dest="min_coverage",
        default=os.environ.get("MIN_COVERAGE", "0"),
        help="Minimum required coverage percentage (default: 0 or MIN_COVERAGE env)",
    )

    args = parser.parse_args(argv)

    try:
        threshold = _parse_threshold(args.min_coverage)
        enforce_coverage(args.report, threshold)
        return 0
    except CoverageEnforcerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

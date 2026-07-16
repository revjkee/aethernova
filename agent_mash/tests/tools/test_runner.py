from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TESTS_PATH = PROJECT_ROOT / "agent_mash" / "tests"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent Mash test runner. Unified entry point for pytest execution.",
    )

    parser.add_argument(
        "--tests-path",
        type=Path,
        default=DEFAULT_TESTS_PATH,
        help="Path to tests directory (default: agent_mash/tests)",
    )

    parser.add_argument(
        "--markers",
        type=str,
        default="",
        help="Pytest markers expression, e.g. 'unit and not slow'",
    )

    parser.add_argument(
        "--keywords",
        type=str,
        default="",
        help="Run tests matching given substring expression (-k in pytest)",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose pytest output (-v)",
    )

    parser.add_argument(
        "--exit-first",
        action="store_true",
        help="Stop on first failure (-x)",
    )

    parser.add_argument(
        "--maxfail",
        type=int,
        default=None,
        help="Maximum number of failures before stopping",
    )

    parser.add_argument(
        "--disable-warnings",
        action="store_true",
        help="Disable pytest warnings summary",
    )

    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Only collect tests, do not execute them",
    )

    return parser


def _build_pytest_args(args: argparse.Namespace) -> List[str]:
    pytest_args: List[str] = []

    tests_path = args.tests_path.resolve()
    if not tests_path.exists():
        raise FileNotFoundError(f"Tests path does not exist: {tests_path}")

    pytest_args.append(str(tests_path))

    if args.verbose:
        pytest_args.append("-v")

    if args.exit_first:
        pytest_args.append("-x")

    if args.maxfail is not None:
        pytest_args.append(f"--maxfail={args.maxfail}")

    if args.disable_warnings:
        pytest_args.append("--disable-warnings")

    if args.collect_only:
        pytest_args.append("--collect-only")

    if args.markers:
        pytest_args.extend(["-m", args.markers])

    if args.keywords:
        pytest_args.extend(["-k", args.keywords])

    return pytest_args


def run() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)

    pytest_args = _build_pytest_args(args)

    exit_code = pytest.main(pytest_args)
    return int(exit_code)


if __name__ == "__main__":
    sys.exit(run())

# -*- coding: utf-8 -*-
"""
Zero-Trust Decision Evaluator CLI

Features:
- Policy + context evaluation with deny-first semantics and risk thresholds.
- Robust imports (works as script or package), stdin support via '-' for files.
- Atomic output to file (--out), JSON or pretty formats.
- Optional HMAC signature (detached) and tamper-evident JSONL audit chain.
- Optional time freeze for reproducible runs (--now, if zero_trust.utils.time is available).
- Clean exit codes: 0=ALLOW, 1=DENY, 2=ERROR, with graceful BrokenPipe handling.

Python 3.10+
"""
from __future__ import annotations
import os
import sys
from typing import Any, Dict, Optional
from dataclasses import asdict

# ----------------------------------------------------------------------
# Import robustness: allow running as a script from cli/ or as a package
# ----------------------------------------------------------------------
def _ensure_local_path():
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)

_ensure_local_path()

try:
    # Preferred local imports (when running as script in cli/)
    from tools.cli_io import (
        make_argparser, read_json_file, parse_overrides, deep_merge,
        load_secret, eprint, CliError
    )
    from tools.policy import load_policy
    from tools.decision_engine import evaluate
    from tools.hmac_sign import sign_decision
    from tools.audit_log import append_jsonl_with_chain
    from tools.output import to_json, pretty_decision
except Exception:
    # Fallback to package-style imports (when installed as zero_trust.cli)
    from zero_trust.cli.tools.cli_io import (  # type: ignore
        make_argparser, read_json_file, parse_overrides, deep_merge,
        load_secret, eprint, CliError
    )
    from zero_trust.cli.tools.policy import load_policy  # type: ignore
    from zero_trust.cli.tools.decision_engine import evaluate  # type: ignore
    from zero_trust.cli.tools.hmac_sign import sign_decision  # type: ignore
    from zero_trust.cli.tools.audit_log import append_jsonl_with_chain  # type: ignore
    from zero_trust.cli.tools.output import to_json, pretty_decision  # type: ignore

# Optional time helpers
try:
    from zero_trust.utils.time import FrozenTime, parse_rfc3339
except Exception:
    FrozenTime = None  # type: ignore
    parse_rfc3339 = None  # type: ignore

# ----------------------------------------------------------------------
# Exit codes
# ----------------------------------------------------------------------
EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_ERROR = 2

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _read_json_maybe_stdin(path: str) -> Dict[str, Any]:
    """
    Read JSON from file or stdin if path == '-'.
    """
    if path == "-":
        import json
        try:
            return json.load(sys.stdin)
        except Exception as e:
            raise CliError(f"Failed to read JSON from stdin: {e}") from e
    return read_json_file(path)

def _apply_overrides(ctx: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    return deep_merge(ctx, overrides)

def _print_or_write(payload: str, out_path: Optional[str]) -> None:
    """
    Print to stdout or write atomically to a file if --out is set.
    """
    if out_path:
        from tools.cli_io import atomic_write_text  # local import to avoid cycle
        atomic_write_text(out_path, payload + ("\n" if not payload.endswith("\n") else ""))
    else:
        try:
            sys.stdout.write(payload)
            if not payload.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        except BrokenPipeError:
            # Allow pipelines like `... | head -n1` without stacktraces
            try:
                sys.stdout.flush()
            except Exception:
                pass
            # Ensure a clean exit for pipeline consumers
            os._exit(EXIT_ALLOW)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = make_argparser()
    # Extend parser with optional output file
    ap.add_argument("--out", help="Write result to file (atomic). Default: stdout")
    args = ap.parse_args(argv)

    try:
        policy_doc = _read_json_maybe_stdin(args.policy)
        ctx = _read_json_maybe_stdin(args.context)

        overrides = parse_overrides(args.sets)
        ctx = _apply_overrides(ctx, overrides)

        def run_eval() -> int:
            policy = load_policy(policy_doc)
            decision_obj = evaluate(policy, ctx)
            dec_dict: Dict[str, Any] = asdict(decision_obj)

            # Optional signature
            secret = load_secret(args.sign_secret_env, args.sign_secret_file)
            sig = sign_decision(dec_dict, secret)
            if sig:
                dec_dict["signature"] = sig

            # Output
            if args.format == "json":
                _print_or_write(to_json(dec_dict), args.out)
            else:
                _print_or_write(pretty_decision(dec_dict), args.out)

            # Audit JSONL chain (if requested)
            if args.audit_log:
                append_jsonl_with_chain(args.audit_log, dec_dict)

            return EXIT_ALLOW if dec_dict["decision"] == "allow" else EXIT_DENY

        # Reproducible time if supported
        if args.now and FrozenTime and parse_rfc3339:
            _ = parse_rfc3339(args.now)  # validate RFC3339
            with FrozenTime(args.now):
                rc = run_eval()
        else:
            rc = run_eval()
        return rc

    except CliError as e:
        eprint(f"ERROR: {e}")
        return EXIT_ERROR
    except SystemExit as e:
        # argparse or nested exit; propagate numeric codes if present
        try:
            return int(e.code)  # type: ignore
        except Exception:
            return EXIT_ERROR
    except BrokenPipeError:
        # Handle rare race of early pipe close outside print stage
        return EXIT_ALLOW
    except Exception as e:
        eprint(f"ERROR: {type(e).__name__}: {e}")
        return EXIT_ERROR

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

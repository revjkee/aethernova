# chronowatch-core/cli/tools/window_set.py
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------- Optional dependencies with graceful fallback ----------
_YAML_IMPL = "pyyaml"
try:
    from ruamel.yaml import YAML  # type: ignore
    _YAML_IMPL = "ruamel"
except Exception:  # pragma: no cover
    YAML = None  # type: ignore

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    from croniter import croniter  # type: ignore
except Exception:  # pragma: no cover
    croniter = None  # type: ignore

try:
    from filelock import FileLock  # type: ignore
except Exception:  # pragma: no cover
    FileLock = None  # type: ignore

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# ------------------------------ Logging --------------------------------
log = logging.getLogger("chronowatch.window_set")
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_handler)
log.setLevel(os.getenv("WINDOW_SET_LOG_LEVEL", "INFO").upper())

# ----------------------------- Defaults --------------------------------
REPO_ROOT = Path(os.getenv("REPO_ROOT", Path(__file__).resolve().parents[3]))
DEFAULT_CONFIG = Path(os.getenv("HEARTBEATS_CONFIG", REPO_ROOT / "configs" / "heartbeats.yaml"))
LOCK_PATH = Path(os.getenv("HEARTBEATS_LOCK", str(DEFAULT_CONFIG) + ".lock"))
DEFAULT_TZ = os.getenv("WINDOWS_TZ", "UTC")

# ---------------------- Duration parsing/formatting ---------------------
_DUR_RE = re.compile(
    r"^(?:(?P<days>\d+)d)?(?:(?P<hours>\d+)h)?(?:(?P<minutes>\d+)m)?(?:(?P<seconds>\d+)s)?$"
)

def parse_duration(s: str) -> dt.timedelta:
    """
    Parse duration like '1h30m15s', '2h', '45m', '1d2h'.
    """
    if not s or not isinstance(s, str):
        raise ValueError("duration must be a non-empty string")
    m = _DUR_RE.match(s.strip())
    if not m:
        raise ValueError(f"invalid duration format: {s!r}")
    parts = {k: int(v) if v else 0 for k, v in m.groupdict().items()}
    td = dt.timedelta(days=parts["days"], hours=parts["hours"], minutes=parts["minutes"], seconds=parts["seconds"])
    if td.total_seconds() <= 0:
        raise ValueError("duration must be > 0")
    return td

def fmt_duration(td: dt.timedelta) -> str:
    total = int(td.total_seconds())
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    out = []
    if days: out.append(f"{days}d")
    if hours: out.append(f"{hours}h")
    if minutes: out.append(f"{minutes}m")
    if seconds: out.append(f"{seconds}s")
    return "".join(out) or "0s"

# ----------------------------- Data model -------------------------------
@dataclass
class Window:
    name: str
    schedule: str                # cron, e.g. "0 2 * * *"
    duration: str                # "1h", "30m"
    suppress_alerts: bool = True
    probes: List[str] = field(default_factory=list)  # match.probes
    match: Optional[Dict[str, Any]] = None          # raw match dict (probes, labels etc.)

    @staticmethod
    def from_yaml(doc: Dict[str, Any]) -> "Window":
        name = str(doc.get("name", "")).strip()
        schedule = str(doc.get("schedule", "")).strip()
        duration = str(doc.get("duration", "")).strip()
        if not name or not schedule or not duration:
            raise ValueError("window requires name, schedule, duration")
        suppress = bool(doc.get("suppress_alerts", True))
        match = doc.get("match") or {}
        probes = list(match.get("probes", [])) if isinstance(match, dict) else []
        return Window(name=name, schedule=schedule, duration=duration, suppress_alerts=suppress, probes=probes, match=match or {"probes": probes})

    def to_yaml(self) -> Dict[str, Any]:
        m = self.match or {"probes": self.probes}
        return {
            "name": self.name,
            "match": m,
            "schedule": self.schedule,
            "duration": self.duration,
            "suppress_alerts": bool(self.suppress_alerts),
        }

@dataclass
class Config:
    path: Path
    raw: Dict[str, Any]

    def windows(self) -> List[Window]:
        maint = self.raw.get("spec", {}).get("maintenance", {})
        arr = maint.get("windows", []) if isinstance(maint, dict) else []
        return [Window.from_yaml(x) for x in arr if isinstance(x, dict)]

    def upsert_window(self, win: Window) -> None:
        spec = self.raw.setdefault("spec", {})
        maint = spec.setdefault("maintenance", {})
        arr = maint.setdefault("windows", [])
        # Replace by name
        replaced = False
        for i, w in enumerate(arr):
            if isinstance(w, dict) and str(w.get("name", "")).strip() == win.name:
                arr[i] = win.to_yaml()
                replaced = True
                break
        if not replaced:
            arr.append(win.to_yaml())

    def remove_window(self, name: str) -> bool:
        spec = self.raw.get("spec", {})
        maint = spec.get("maintenance", {})
        arr = maint.get("windows", [])
        if not isinstance(arr, list):
            return False
        before = len(arr)
        arr[:] = [w for w in arr if not (isinstance(w, dict) and str(w.get("name", "")).strip() == name)]
        return len(arr) != before

# --------------------------- YAML I/O helpers --------------------------
def yaml_load(path: Path) -> Config:
    if not path.exists():
        raise FileNotFoundError(f"config not found: {path}")
    text = path.read_text(encoding="utf-8")
    if _YAML_IMPL == "ruamel" and YAML is not None:
        y = YAML(typ="rt")
        data = y.load(text)
        if not isinstance(data, dict):
            raise ValueError("YAML root must be a mapping")
        return Config(path=path, raw=data)
    if yaml is None:
        raise RuntimeError("No YAML parser available. Install ruamel.yaml or PyYAML.")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a mapping")
    return Config(path=path, raw=data)

def yaml_dump(cfg: Config, dry_run: bool = False) -> None:
    path = cfg.path
    if dry_run:
        # Print to stdout
        if _YAML_IMPL == "ruamel" and YAML is not None:
            y = YAML(typ="rt")
            y.default_flow_style = False
            y.dump(cfg.raw, sys.stdout)
        else:
            print(yaml.safe_dump(cfg.raw, sort_keys=False, allow_unicode=True))
        return
    # File lock if available
    lock_ctx = open(str(LOCK_PATH), "a+") if FileLock is None else FileLock(str(LOCK_PATH))
    try:
        if FileLock is None:
            # best-effort lock via creating companion file
            pass
        else:
            lock_ctx.acquire(timeout=10)  # type: ignore
        # Backup
        backup = path.with_suffix(path.suffix + f".bak.{dt.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}")
        shutil.copy2(path, backup)
        # Write atomically
        tmp = Path(tempfile.mkstemp(prefix=path.name, dir=str(path.parent))[1])
        try:
            if _YAML_IMPL == "ruamel" and YAML is not None:
                y = YAML(typ="rt")
                y.default_flow_style = False
                with tmp.open("w", encoding="utf-8") as fp:
                    y.dump(cfg.raw, fp)
            else:
                with tmp.open("w", encoding="utf-8") as fp:
                    yaml.safe_dump(cfg.raw, fp, sort_keys=False, allow_unicode=True)
            tmp.replace(path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass
        log.info("saved %s (backup: %s)", path, backup.name)
    finally:
        try:
            if FileLock is None:
                lock_ctx.close()
            else:
                lock_ctx.release()  # type: ignore
        except Exception:
            pass

# ------------------------------ Validation ---------------------------
_CRON_NOTE = (
    "cron validation requires 'croniter'. Install with: pip install croniter"
)

def validate_window(win: Window, tz: str = DEFAULT_TZ) -> List[str]:
    errors: List[str] = []
    # duration
    try:
        parse_duration(win.duration)
    except Exception as e:
        errors.append(f"duration: {e}")
    # cron
    if croniter is None:
        log.warning(_CRON_NOTE)
    else:
        try:
            ref = now_tz(tz)
            _ = croniter(win.schedule, ref)
        except Exception as e:
            errors.append(f"schedule: invalid cron: {e}")
    # name
    if not re.match(r"^[A-Za-z0-9_.:-]+$", win.name):
        errors.append("name: allowed [A-Za-z0-9_.:-] only")
    # probes/match
    if not (win.probes or (win.match and isinstance(win.match, dict))):
        errors.append("match: specify probes list or match object")
    return errors

def now_tz(tz: str) -> dt.datetime:
    if ZoneInfo is None:
        return dt.datetime.utcnow()
    try:
        return dt.datetime.now(ZoneInfo(tz))
    except Exception:
        return dt.datetime.utcnow()

def preview_occurrences(win: Window, count: int, tz: str = DEFAULT_TZ) -> List[Tuple[str, str]]:
    """
    Return list of (start_iso, end_iso) for next N occurrences in TZ.
    """
    if croniter is None:
        raise RuntimeError(_CRON_NOTE)
    start = now_tz(tz)
    it = croniter(win.schedule, start)
    dur = parse_duration(win.duration)
    out: List[Tuple[str, str]] = []
    for _ in range(max(1, min(count, 50))):
        s = it.get_next(dt.datetime)
        e = s + dur
        out.append((iso_z(s), iso_z(e)))
    return out

def iso_z(d: dt.datetime) -> str:
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")

# ------------------------------ Git helpers --------------------------
def maybe_git_commit(path: Path, message: str) -> None:
    if os.getenv("WINDOW_SET_GIT_COMMIT", "false").lower() not in ("1", "true", "yes"):
        return
    import subprocess
    try:
        subprocess.run(["git", "add", str(path)], check=True)
        subprocess.run(["git", "commit", "-m", message], check=True)
        log.info("git commit created")
    except Exception as e:  # pragma: no cover
        log.warning("git commit failed: %r", e)

# ------------------------------- Commands ----------------------------
def cmd_list(cfg: Config, args: argparse.Namespace) -> int:
    items = cfg.windows()
    if args.output == "json":
        print(json.dumps([w.to_yaml() for w in items], ensure_ascii=False, indent=2))
        return 0
    # table
    print(f"{'NAME':28} {'CRON':18} {'DUR':6} {'SUPPR':5} PROBES/MATCH")
    for w in items:
        probes = ",".join(w.probes) if w.probes else json.dumps(w.match, ensure_ascii=False)
        print(f"{w.name:28} {w.schedule:18} {w.duration:6} {str(w.suppress_alerts):5} {probes}")
    return 0

def cmd_add(cfg: Config, args: argparse.Namespace) -> int:
    win = Window(
        name=args.name,
        schedule=args.schedule,
        duration=args.duration,
        suppress_alerts=not args.no_suppress,
        probes=args.probe or [],
        match={"probes": args.probe} if args.probe else (json.loads(args.match) if args.match else {"probes": []}),
    )
    errs = validate_window(win, tz=args.tz)
    if errs:
        for e in errs:
            log.error("validation: %s", e)
        return 2
    cfg.upsert_window(win)
    if args.preview:
        try:
            occ = preview_occurrences(win, args.preview, tz=args.tz)
            print(json.dumps({"preview": occ}, ensure_ascii=False, indent=2))
        except Exception as e:
            log.warning("preview failed: %r", e)
    yaml_dump(cfg, dry_run=args.dry_run)
    maybe_git_commit(cfg.path, f"window_set: add/update '{win.name}'")
    return 0

def cmd_remove(cfg: Config, args: argparse.Namespace) -> int:
    ok = cfg.remove_window(args.name)
    if not ok:
        log.error("window not found: %s", args.name)
        return 3
    yaml_dump(cfg, dry_run=args.dry_run)
    maybe_git_commit(cfg.path, f"window_set: remove '{args.name}'")
    return 0

def cmd_update(cfg: Config, args: argparse.Namespace) -> int:
    # Find existing
    existing = {w.name: w for w in cfg.windows()}
    if args.name not in existing:
        log.error("window not found: %s", args.name)
        return 3
    w = existing[args.name]
    if args.schedule: w.schedule = args.schedule
    if args.duration: w.duration = args.duration
    if args.no_suppress is not None: w.suppress_alerts = not args.no_suppress
    if args.probe is not None: 
        w.probes = args.probe
        w.match = {"probes": args.probe}
    if args.match is not None:
        w.match = json.loads(args.match) if args.match else {"probes": w.probes}
    errs = validate_window(w, tz=args.tz)
    if errs:
        for e in errs:
            log.error("validation: %s", e)
        return 2
    cfg.upsert_window(w)
    if args.preview:
        try:
            occ = preview_occurrences(w, args.preview, tz=args.tz)
            print(json.dumps({"preview": occ}, ensure_ascii=False, indent=2))
        except Exception as e:
            log.warning("preview failed: %r", e)
    yaml_dump(cfg, dry_run=args.dry_run)
    maybe_git_commit(cfg.path, f"window_set: update '{w.name}'")
    return 0

def cmd_validate(cfg: Config, args: argparse.Namespace) -> int:
    wins = cfg.windows()
    all_errs: Dict[str, List[str]] = {}
    for w in wins:
        errs = validate_window(w, tz=args.tz)
        if errs:
            all_errs[w.name] = errs
    if all_errs:
        print(json.dumps({"valid": False, "errors": all_errs}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps({"valid": True, "count": len(wins)}, ensure_ascii=False))
    return 0

def cmd_preview(cfg: Config, args: argparse.Namespace) -> int:
    target = next((w for w in cfg.windows() if w.name == args.name), None)
    if not target:
        log.error("window not found: %s", args.name)
        return 3
    try:
        occ = preview_occurrences(target, args.count, tz=args.tz)
    except Exception as e:
        log.error("preview failed: %r", e)
        return 2
    print(json.dumps({"name": target.name, "occurrences": occ}, ensure_ascii=False, indent=2))
    return 0

# ------------------------------ CLI parser ---------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="window-set",
        description="Manage maintenance windows in configs/heartbeats.yaml",
    )
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Path to heartbeats.yaml")
    p.add_argument("--tz", default=DEFAULT_TZ, help="Timezone for cron preview (default: UTC)")
    p.add_argument("--output", choices=["table", "json"], default="table", help="List output format")
    p.add_argument("--dry-run", action="store_true", help="Do not write file, print to stdout")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_list = sub.add_parser("list", help="List maintenance windows")
    s_list.set_defaults(func=cmd_list)

    s_add = sub.add_parser("add", help="Add or update a maintenance window")
    s_add.add_argument("--name", required=True)
    s_add.add_argument("--schedule", required=True, help='Cron spec, e.g. "0 2 * * *"')
    s_add.add_argument("--duration", required=True, help='Duration like "1h30m"')
    s_add.add_argument("--probe", action="append", help="Probe matcher (repeatable). Mutually exclusive with --match")
    s_add.add_argument("--match", help="Raw JSON match object (e.g. '{\"probes\":[\"db-*\"]}')")
    s_add.add_argument("--no-suppress", action="store_true", help="Do not suppress alerts during window")
    s_add.add_argument("--preview", type=int, help="Preview next N occurrences")
    s_add.set_defaults(func=cmd_add)

    s_update = sub.add_parser("update", help="Update existing window by name")
    s_update.add_argument("--name", required=True)
    s_update.add_argument("--schedule", help='Cron spec')
    s_update.add_argument("--duration", help='Duration like "1h30m"')
    s_update.add_argument("--probe", action="append", help="Replace probes list (repeatable)")
    s_update.add_argument("--match", help="Replace raw match JSON object")
    s_update.add_argument("--no-suppress", action="store_true", default=None)
    s_update.add_argument("--preview", type=int, help="Preview next N occurrences")
    s_update.set_defaults(func=cmd_update)

    s_rm = sub.add_parser("remove", help="Remove window by name")
    s_rm.add_argument("--name", required=True)
    s_rm.set_defaults(func=cmd_remove)

    s_val = sub.add_parser("validate", help="Validate windows in config")
    s_val.set_defaults(func=cmd_validate)

    s_prev = sub.add_parser("preview", help="Preview next occurrences for a window")
    s_prev.add_argument("--name", required=True)
    s_prev.add_argument("--count", type=int, default=5)
    s_prev.set_defaults(func=cmd_preview)

    return p

# ------------------------------- Main ---------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = yaml_load(args.config)
    except Exception as e:
        log.error("failed to load config: %r", e)
        return 1
    return args.func(cfg, args)

if __name__ == "__main__":
    sys.exit(main())

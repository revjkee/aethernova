#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Neuroforge Training CLI (industrial-grade)

Features:
- Config loading: YAML/JSON/TOML (optional libs).
- Overrides: --set key.path=value (dot-notation), ENV NEUROFORGE_*=.
- Plugin trainer loader: "pkg.module:Class".
- Run directory: timestamped, atomic artifact writes, metadata capture.
- Structured logging: console + rotating file handler.
- Signals: graceful shutdown with checkpoint save.
- Subcommands: train | resume | eval | export | inspect
- Zero hard deps on ML frameworks; any framework via BaseTrainer interface.

To implement a trainer, provide a class with the BaseTrainer API (see below),
and pass --trainer my_pkg.my_trainer:MyTrainer or put it into config:
trainer.target: "my_pkg.my_trainer:MyTrainer"
trainer.params: {...}
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import logging
import logging.handlers
import os
import re
import signal
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# -------- Optional IO & config parsers (graceful degradation) --------
# Prefer project-level IO if available
try:
    from neuroforge.utils import io as nf_io  # type: ignore
except Exception:
    nf_io = None  # type: ignore

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

try:  # Python 3.11+
    import tomllib  # type: ignore
except Exception:
    tomllib = None  # type: ignore

try:  # TOML write (not strictly needed here)
    import tomli_w  # type: ignore
except Exception:
    tomli_w = None  # type: ignore


# =========================
# Trainer Interface
# =========================
class BaseTrainer:
    """
    Minimal contract for trainer plugins.
    Implement these methods in your trainer class.
    """

    def __init__(self, config: Dict[str, Any], run_ctx: "RunContext") -> None:
        self.config = config
        self.run_ctx = run_ctx

    @classmethod
    def from_config(cls, config: Dict[str, Any], run_ctx: "RunContext") -> "BaseTrainer":
        return cls(config, run_ctx)

    def train(self) -> Dict[str, Any]:
        """
        Run training epochs. Return final metrics dict (JSON-serializable).
        Should periodically call run_ctx.heartbeat() and check run_ctx.should_stop.
        """
        raise NotImplementedError

    def evaluate(self) -> Dict[str, Any]:
        """
        Run evaluation on validation/test set. Return metrics.
        """
        raise NotImplementedError

    def save_checkpoint(self, tag: str = "latest") -> Path:
        """
        Persist checkpoint under run_ctx.paths['checkpoints'].
        Must be idempotent and atomic (write to temp, then move).
        """
        raise NotImplementedError

    def load_checkpoint(self, path: Path) -> None:
        """
        Restore trainer state from checkpoint path.
        """
        raise NotImplementedError

    def export(self) -> Dict[str, Path]:
        """
        Export deployable artifacts (e.g., ONNX). Return map name->path.
        """
        raise NotImplementedError


# =========================
# Run Context & Utilities
# =========================
@dataclass(slots=True)
class RunContext:
    run_id: str
    run_dir: Path
    config: Dict[str, Any]
    logger: logging.Logger
    start_time: float = field(default_factory=time.time)
    should_stop: bool = False
    paths: Dict[str, Path] = field(default_factory=dict)

    def heartbeat(self) -> None:
        """
        Lightweight heartbeat for long loops; can be extended (telemetry, etc.).
        """
        # No-op now; placeholder for future telemetry hooks.
        pass


# -------- Config helpers --------
_KEY_VALUE_RE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+)=(?P<val>.*)$")


def deep_update(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_update(dst[k], v)  # type: ignore[index]
        else:
            dst[k] = v
    return dst


def set_by_path(cfg: Dict[str, Any], key_path: str, value: Any) -> None:
    cur = cfg
    parts = key_path.split(".")
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def parse_literal(val: str) -> Any:
    # Try JSON-like literals first (true/false/null/nums/arrays/objects)
    lowered = val.strip().lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "none"):
        return None
    # numeric?
    try:
        if re.match(r"^-?\d+$", val.strip()):
            return int(val.strip())
        if re.match(r"^-?\d+\.\d+$", val.strip()):
            return float(val.strip())
    except Exception:
        pass
    # JSON object/array?
    if (val.startswith("{") and val.endswith("}")) or (val.startswith("[") and val.endswith("]")):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


def parse_set_overrides(pairs: list[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for item in pairs:
        m = _KEY_VALUE_RE.match(item)
        if not m:
            raise ValueError(f"Invalid --set item: '{item}'. Expected key.path=value")
        key = m.group("key")
        val = parse_literal(m.group("val"))
        cur = out
        parts = key.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = val
    return out


def env_overrides(prefix: str = "NEUROFORGE_") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in os.environ.items():
        if not k.startswith(prefix):
            continue
        key = k[len(prefix) :].lower().replace("__", ".")  # allow double underscore as path separator
        set_by_path(out, key, parse_literal(v))
    return out


def load_config(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    suffix = path.suffix.lower()
    # Prefer project IO for safe reads if available
    if nf_io:
        if suffix in (".yaml", ".yml"):
            return nf_io.IOService(base_dir=None).read_yaml(str(path))  # type: ignore[no-any-return]
        if suffix == ".json":
            return nf_io.IOService(base_dir=None).read_json(str(path))  # type: ignore[no-any-return]
        if suffix == ".toml":
            return nf_io.IOService(base_dir=None).read_toml(str(path))  # type: ignore[no-any-return]

    text = path.read_bytes()
    if suffix in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed but YAML config provided.")
        return yaml.safe_load(text) or {}
    if suffix == ".json":
        return json.loads(text.decode("utf-8"))
    if suffix == ".toml":
        if tomllib is None:
            raise RuntimeError("tomllib (Python 3.11+) not available for TOML config.")
        return tomllib.loads(text.decode("utf-8"))
    raise RuntimeError(f"Unsupported config format: {suffix}")


# -------- Logging --------
def setup_logging(run_dir: Path, level: str = "INFO") -> logging.Logger:
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "logs" / "train.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("neuroforge.train")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch.setFormatter(logging.Formatter(fmt="%(asctime)s | %(levelname)s | %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(ch)

    # Rotating File
    fh = logging.handlers.RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh.setFormatter(
        logging.Formatter(fmt="%(asctime)s | %(levelname)s | %(name)s | %(filename)s:%(lineno)d | %(message)s")
    )
    logger.addHandler(fh)

    logger.debug("Logging initialized. Run dir: %s", run_dir)
    return logger


# -------- Run directory & metadata --------
def make_run_id() -> str:
    return dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")


def prepare_run_dir(base: Path, run_id: str) -> Path:
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def atomic_write_bytes(path: Path, data: bytes) -> None:
    if nf_io:
        nf_io.atomic_write_bytes(path, data)  # type: ignore[attr-defined]
        return
    # Fallback atomic write
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        # fsync dir (best effort, posix only)
        try:
            if os.name != "nt":
                dfd = os.open(str(path.parent), os.O_DIRECTORY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        except Exception:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def dump_json_atomic(path: Path, obj: Dict[str, Any]) -> None:
    data = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    atomic_write_bytes(path, data)


def capture_env_snapshot() -> Dict[str, Any]:
    return {
        "python": sys.version,
        "platform": sys.platform,
        "argv": sys.argv,
        "env_whitelist": {k: v for k, v in os.environ.items() if k.startswith("NEUROFORGE_") or k in ("CUDA_VISIBLE_DEVICES",)},
        "cwd": os.getcwd(),
        "time_utc": dt.datetime.utcnow().isoformat() + "Z",
    }


# -------- Trainer loader --------
def load_trainer_class(target: str):
    """
    target format: "pkg.module:ClassName"
    """
    if ":" not in target:
        raise ValueError("Trainer target must be in form 'pkg.module:ClassName'")
    module_name, cls_name = target.split(":", 1)
    mod = importlib.import_module(module_name)
    cls = getattr(mod, cls_name, None)
    if cls is None:
        raise ImportError(f"Class '{cls_name}' not found in module '{module_name}'")
    return cls


# -------- Signals handling --------
def install_signal_handlers(ctx: RunContext, trainer_ref: Dict[str, Optional[BaseTrainer]]) -> None:
    def _handler(signum, frame):
        ctx.logger.warning("Signal %s received; requesting graceful stop...", signum)
        ctx.should_stop = True
        t = trainer_ref.get("trainer")
        if t is not None:
            try:
                path = t.save_checkpoint(tag="signal")
                ctx.logger.info("Checkpoint saved on signal: %s", path)
            except Exception as e:
                ctx.logger.exception("Failed to save checkpoint on signal: %s", e)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except Exception:
            pass


# =========================
# CLI Commands
# =========================
def cmd_inspect(args: argparse.Namespace) -> int:
    cfg = build_config(args)
    run_id = make_run_id()
    run_dir = prepare_run_dir(Path(args.run_base), run_id)
    logger = setup_logging(run_dir, cfg.get("logging", {}).get("level", "INFO"))
    ctx = RunContext(
        run_id=run_id,
        run_dir=run_dir,
        config=cfg,
        logger=logger,
        paths={
            "artifacts": run_dir / "artifacts",
            "checkpoints": run_dir / "checkpoints",
            "metrics": run_dir / "metrics",
        },
    )
    ctx.logger.info("Inspection summary")
    summary = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "config": cfg,
        "env": capture_env_snapshot(),
    }
    dump_json_atomic(run_dir / "run_inspect.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def _create_run_context(args: argparse.Namespace) -> RunContext:
    cfg = build_config(args)
    run_id = make_run_id()
    base = Path(args.run_base)
    run_dir = prepare_run_dir(base, run_id)
    logger = setup_logging(run_dir, cfg.get("logging", {}).get("level", "INFO"))
    paths = {
        "artifacts": run_dir / "artifacts",
        "checkpoints": run_dir / "checkpoints",
        "metrics": run_dir / "metrics",
        "logs": run_dir / "logs",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)

    # Persist config & env snapshot
    dump_json_atomic(run_dir / "config_merged.json", cfg)
    dump_json_atomic(run_dir / "env_snapshot.json", capture_env_snapshot())

    return RunContext(run_id=run_id, run_dir=run_dir, config=cfg, logger=logger, paths=paths)


def _init_trainer(ctx: RunContext) -> BaseTrainer:
    tcfg = ctx.config.get("trainer", {})
    target = tcfg.get("target")
    params = tcfg.get("params", {})
    if not target:
        raise RuntimeError("trainer.target is required (e.g., 'my_pkg.my_trainer:MyTrainer')")
    trainer_cls = load_trainer_class(target)
    if not issubclass(trainer_cls, BaseTrainer):
        # allow duck-typing; just warn
        ctx.logger.warning("Trainer %s does not subclass BaseTrainer; proceeding (duck-typed).", trainer_cls.__name__)
    trainer = trainer_cls.from_config(params, ctx)  # type: ignore[call-arg]
    return trainer


def cmd_train(args: argparse.Namespace) -> int:
    ctx = _create_run_context(args)
    trainer_ref: Dict[str, Optional[BaseTrainer]] = {"trainer": None}
    install_signal_handlers(ctx, trainer_ref)
    try:
        trainer = _init_trainer(ctx)
        trainer_ref["trainer"] = trainer
        ctx.logger.info("Training started. Run ID: %s", ctx.run_id)
        metrics = trainer.train()
        # Save final checkpoint and metrics
        try:
            ckpt_path = trainer.save_checkpoint(tag="final")
            ctx.logger.info("Final checkpoint: %s", ckpt_path)
        except Exception as e:
            ctx.logger.warning("Final checkpoint save failed: %s", e)
        dump_json_atomic(ctx.paths["metrics"] / "train_final.json", metrics or {})
        ctx.logger.info("Training finished. Metrics: %s", metrics)
        return 0
    except KeyboardInterrupt:
        ctx.logger.warning("Interrupted by user.")
        return 130
    except Exception as e:
        ctx.logger.exception("Training failed: %s", e)
        return 3


def cmd_resume(args: argparse.Namespace) -> int:
    ctx = _create_run_context(args)
    trainer_ref: Dict[str, Optional[BaseTrainer]] = {"trainer": None}
    install_signal_handlers(ctx, trainer_ref)
    try:
        trainer = _init_trainer(ctx)
        trainer_ref["trainer"] = trainer
        ckpt = Path(args.checkpoint).expanduser().resolve()
        if not ckpt.exists():
            raise FileNotFoundError(f"Checkpoint not found: {ckpt}")
        trainer.load_checkpoint(ckpt)
        ctx.logger.info("Resuming from checkpoint: %s", ckpt)
        metrics = trainer.train()
        dump_json_atomic(ctx.paths["metrics"] / "resume_final.json", metrics or {})
        ctx.logger.info("Resume finished. Metrics: %s", metrics)
        return 0
    except KeyboardInterrupt:
        ctx.logger.warning("Interrupted by user.")
        return 130
    except Exception as e:
        ctx.logger.exception("Resume failed: %s", e)
        return 3


def cmd_eval(args: argparse.Namespace) -> int:
    ctx = _create_run_context(args)
    try:
        trainer = _init_trainer(ctx)
        if args.checkpoint:
            ckpt = Path(args.checkpoint).expanduser().resolve()
            trainer.load_checkpoint(ckpt)
            ctx.logger.info("Loaded checkpoint for eval: %s", ckpt)
        metrics = trainer.evaluate()
        dump_json_atomic(ctx.paths["metrics"] / "eval.json", metrics or {})
        ctx.logger.info("Eval finished. Metrics: %s", metrics)
        return 0
    except KeyboardInterrupt:
        ctx.logger.warning("Interrupted by user.")
        return 130
    except Exception as e:
        ctx.logger.exception("Eval failed: %s", e)
        return 3


def cmd_export(args: argparse.Namespace) -> int:
    ctx = _create_run_context(args)
    try:
        trainer = _init_trainer(ctx)
        if args.checkpoint:
            ckpt = Path(args.checkpoint).expanduser().resolve()
            trainer.load_checkpoint(ckpt)
            ctx.logger.info("Loaded checkpoint for export: %s", ckpt)
        artifacts = trainer.export() or {}
        # Symlink/copy exported artifacts into run artifacts dir
        exported = {}
        for name, path in artifacts.items():
            path = Path(path)
            dst = ctx.paths["artifacts"] / path.name
            try:
                if dst.exists():
                    dst.unlink()
                # Prefer hardlink/symlink if same filesystem
                try:
                    os.link(path, dst)
                except Exception:
                    try:
                        os.symlink(path, dst)  # may require privileges
                    except Exception:
                        # fall back to copy
                        data = path.read_bytes()
                        atomic_write_bytes(dst, data)
                exported[name] = str(dst)
            except Exception as e:
                ctx.logger.warning("Failed to stage artifact %s from %s: %s", name, path, e)
        dump_json_atomic(ctx.paths["artifacts"] / "export_index.json", exported)
        ctx.logger.info("Export complete. Artifacts: %s", exported)
        return 0
    except KeyboardInterrupt:
        ctx.logger.warning("Interrupted by user.")
        return 130
    except Exception as e:
        ctx.logger.exception("Export failed: %s", e)
        return 3


# =========================
# Config build pipeline
# =========================
def build_config(args: argparse.Namespace) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}

    # base file
    base_cfg = load_config(Path(args.config)) if args.config else {}
    deep_update(cfg, base_cfg)

    # env overrides
    deep_update(cfg, env_overrides(prefix=args.env_prefix))

    # CLI --set
    if args.set:
        deep_update(cfg, parse_set_overrides(args.set))

    # inject CLI trainer target if provided
    if args.trainer:
        tcfg = cfg.setdefault("trainer", {})
        tcfg["target"] = args.trainer

    # logging level from CLI
    if args.log_level:
        lcfg = cfg.setdefault("logging", {})
        lcfg["level"] = args.log_level

    # seed default
    sdefault = cfg.get("seed")
    if sdefault is None:
        cfg["seed"] = 42

    return cfg


# =========================
# Argparse
# =========================
def common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", type=str, help="Path to config file (.yaml/.yml/.json/.toml)")
    p.add_argument("--set", metavar="KEY=VAL", nargs="*", help="Override config values via dot-notation", default=[])
    p.add_argument("--trainer", type=str, help="Trainer target 'pkg.module:ClassName' (overrides config)")
    p.add_argument("--run-base", type=str, default="./runs", help="Base directory for run artifacts")
    p.add_argument("--env-prefix", type=str, default="NEUROFORGE_", help="ENV prefix for overrides")
    p.add_argument("--log-level", type=str, default=None, help="Logging level (DEBUG/INFO/WARN/ERROR)")


def build_cli(argv: Optional[list[str]] = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neuroforge-train",
        description="Neuroforge Training CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              neuroforge-train train --config cfg.yaml --trainer my_pkg.mod:MyTrainer --set trainer.params.epochs=10
              NEUROFORGE_trainer__params__lr=0.001 neuroforge-train eval --config cfg.yaml --checkpoint ckpt.pt
            Notes:
              - ENV overrides use prefix (default NEUROFORGE_) and '__' as a path separator.
              - --set supports JSON literals: --set a.b='{"x":1}'
            """
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # train
    p_train = sub.add_parser("train", help="Start training")
    common_args(p_train)

    # resume
    p_resume = sub.add_parser("resume", help="Resume training from checkpoint")
    common_args(p_resume)
    p_resume.add_argument("--checkpoint", type=str, required=True, help="Path to checkpoint file")

    # eval
    p_eval = sub.add_parser("eval", help="Evaluate checkpoint")
    common_args(p_eval)
    p_eval.add_argument("--checkpoint", type=str, help="Path to checkpoint file (optional)")

    # export
    p_export = sub.add_parser("export", help="Export artifacts")
    common_args(p_export)
    p_export.add_argument("--checkpoint", type=str, help="Path to checkpoint file (optional)")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Inspect config/env and write summary")
    common_args(p_inspect)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_cli(argv)
    args = parser.parse_args(argv)

    if args.command == "train":
        return cmd_train(args)
    if args.command == "resume":
        return cmd_resume(args)
    if args.command == "eval":
        return cmd_eval(args)
    if args.command == "export":
        return cmd_export(args)
    if args.command == "inspect":
        return cmd_inspect(args)

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

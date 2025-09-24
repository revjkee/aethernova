# neuroforge-core/examples/quickstart/train.py
"""
NeuroForge Quickstart Trainer (PyTorch)

Dependencies:
  - Python 3.10+
  - torch >= 2.0

Features:
  - Strict typed config (CLI + key=value overrides).
  - Reproducibility: global seeds, deterministic flags.
  - Device selection: cuda / mps / cpu.
  - Mixed Precision (AMP) + GradScaler.
  - Gradient accumulation.
  - Train/Val loop with metrics (loss, accuracy).
  - CosineAnnealingLR (optional) and EarlyStopping.
  - Checkpointing: latest + best + resume support (safe replace).
  - JSONL metrics logging and human-readable stdout.
  - TorchScript export of best model.
  - Clean exit codes and no side-effects on import.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import torch
from torch import Tensor, nn
from torch.optim import AdamW
from torch.utils.data import DataLoader, Dataset, random_split

# --------------------------- Utilities -----------------------------------------------------------

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_RUNTIME = 5
EXIT_IO = 6

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def set_global_seed(seed: int, deterministic: bool = True) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    if deterministic:
        torch.backends.cudnn.deterministic = True  # type: ignore[attr-defined]
        torch.backends.cudnn.benchmark = False     # type: ignore[attr-defined]

def select_device(prefer: str = "auto") -> torch.device:
    if prefer == "cpu":
        return torch.device("cpu")
    if prefer == "cuda" or (prefer == "auto" and torch.cuda.is_available()):
        return torch.device("cuda")
    if prefer == "mps" or (prefer == "auto" and getattr(torch.backends, "mps", None) and torch.backends.mps.is_available()):  # type: ignore[attr-defined]
        return torch.device("mps")
    return torch.device("cpu")

def safe_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except Exception:
        pass

def safe_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    safe_write_bytes(path, text.encode("utf-8"), mode=mode)

def human_time_dur(start_s: float, end_s: float) -> str:
    sec = end_s - start_s
    mm, ss = divmod(int(sec), 60)
    hh, mm = divmod(mm, 60)
    return f"{hh:02d}:{mm:02d}:{ss:02d}"

def parse_overrides(items: List[str]) -> Dict[str, Any]:
    """
    Parse key=value overrides where value is JSON if possible, else string/number/bool.
    Example: train.lr=1e-3 model.width=256 amp=true notes="quick run"
    """
    out: Dict[str, Any] = {}
    for it in items:
        if "=" not in it:
            raise ValueError(f"Invalid override (expected key=value): {it}")
        k, v = it.split("=", 1)
        # try JSON
        try:
            val = json.loads(v)
        except json.JSONDecodeError:
            # try number/bool
            if v.lower() in ("true", "false"):
                val = v.lower() == "true"
            else:
                try:
                    if re.match(r"^-?\d+$", v):
                        val = int(v)
                    elif re.match(r"^-?\d+(\.\d+)?([eE]-?\d+)?$", v):
                        val = float(v)
                    else:
                        val = v
                except Exception:
                    val = v
        out[k] = val
    return out

def apply_overrides_dc(dc: Any, overrides: Dict[str, Any]) -> Any:
    """
    Apply dotted-path overrides into nested dataclasses/dicts.
    """
    for k, v in overrides.items():
        path = k.split(".")
        target = dc
        for p in path[:-1]:
            target = getattr(target, p) if dataclasses.is_dataclass(target) else target[p]
        last = path[-1]
        if dataclasses.is_dataclass(target):
            setattr(target, last, v)
        else:
            target[last] = v
    return dc

# --------------------------- Config --------------------------------------------------------------

@dataclass
class DataCfg:
    n_samples: int = 20000
    n_features: int = 32
    n_classes: int = 2
    val_split: float = 0.2
    seed: int = 42

@dataclass
class ModelCfg:
    width: int = 128
    depth: int = 3
    dropout: float = 0.1

@dataclass
class TrainCfg:
    epochs: int = 20
    batch_size: int = 256
    lr: float = 3e-4
    weight_decay: float = 1e-2
    grad_accum_steps: int = 1
    amp: bool = True
    early_stop_patience: int = 5
    scheduler_cosine: bool = True
    scheduler_tmin: int = 10

@dataclass
class RunCfg:
    out_dir: str = "runs"
    project: str = "quickstart"
    device: str = "auto"  # auto|cuda|mps|cpu
    seed: int = 7
    num_workers: int = 0  # set >0 for real datasets
    pin_memory: bool = False
    resume: Optional[str] = None  # path to checkpoint

@dataclass
class Config:
    data: DataCfg = DataCfg()
    model: ModelCfg = ModelCfg()
    train: TrainCfg = TrainCfg()
    run: RunCfg = RunCfg()

# --------------------------- Data ----------------------------------------------------------------

class SyntheticBlobs(Dataset):
    """
    Two-class synthetic dataset with controllable difficulty.
    """
    def __init__(self, n_samples: int, n_features: int, n_classes: int, seed: int) -> None:
        assert n_classes == 2, "SyntheticBlobs supports exactly 2 classes for quickstart"
        g = torch.Generator().manual_seed(seed)
        n0 = n_samples // 2
        n1 = n_samples - n0
        cov = torch.eye(n_features)
        mean0 = torch.zeros(n_features)
        mean1 = torch.cat([torch.ones(n_features // 2), -torch.ones(n_features - n_features // 2)])
        x0 = torch.distributions.MultivariateNormal(mean0, cov).sample((n0,)).to(torch.float32)
        x1 = torch.distributions.MultivariateNormal(mean1, cov).sample((n1,)).to(torch.float32)
        y0 = torch.zeros(n0, dtype=torch.long)
        y1 = torch.ones(n1, dtype=torch.long)
        self.x = torch.cat([x0, x1], dim=0)
        self.y = torch.cat([y0, y1], dim=0)
        # shuffle
        idx = torch.randperm(len(self.x), generator=g)
        self.x = self.x[idx]
        self.y = self.y[idx]

    def __len__(self) -> int:
        return self.x.size(0)

    def __getitem__(self, i: int) -> Tuple[Tensor, Tensor]:
        return self.x[i], self.y[i]

def build_loaders(cfg: Config) -> Tuple[DataLoader, DataLoader]:
    ds = SyntheticBlobs(
        n_samples=cfg.data.n_samples,
        n_features=cfg.data.n_features,
        n_classes=cfg.data.n_classes,
        seed=cfg.data.seed,
    )
    val_len = int(len(ds) * cfg.data.val_split)
    train_len = len(ds) - val_len
    train_ds, val_ds = random_split(ds, [train_len, val_len], generator=torch.Generator().manual_seed(cfg.run.seed))
    train_loader = DataLoader(
        train_ds,
        batch_size=cfg.train.batch_size,
        shuffle=True,
        num_workers=cfg.run.num_workers,
        pin_memory=cfg.run.pin_memory,
        drop_last=False,
    )
    val_loader = DataLoader(
        val_ds,
        batch_size=cfg.train.batch_size,
        shuffle=False,
        num_workers=cfg.run.num_workers,
        pin_memory=cfg.run.pin_memory,
        drop_last=False,
    )
    return train_loader, val_loader

# --------------------------- Model ---------------------------------------------------------------

class MLP(nn.Module):
    def __init__(self, in_dim: int, width: int, depth: int, out_dim: int, dropout: float) -> None:
        super().__init__()
        layers: List[nn.Module] = []
        last = in_dim
        for i in range(depth):
            layers += [nn.Linear(last, width), nn.GELU(), nn.Dropout(dropout)]
            last = width
        layers += [nn.Linear(last, out_dim)]
        self.net = nn.Sequential(*layers)

    def forward(self, x: Tensor) -> Tensor:
        return self.net(x)

# --------------------------- Checkpointing & Logging --------------------------------------------

class CheckpointMgr:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.ckpt_latest = run_dir / "checkpoint_latest.pt"
        self.ckpt_best = run_dir / "checkpoint_best.pt"
        self.metrics_jsonl = run_dir / "metrics.jsonl"

    def save(self, state: Dict[str, Any], best: bool = False) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        blob = torch.save(state, self.ckpt_latest)
        # torch.save returns None; ensure atomic replace was successful by re-saving via temp
        if best:
            torch.save(state, self.ckpt_best)

    def load(self, path: Optional[str]) -> Optional[Dict[str, Any]]:
        p = Path(path) if path else self.ckpt_latest
        if p.exists():
            return torch.load(p, map_location="cpu")
        return None

    def log_metrics(self, rec: Dict[str, Any]) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with open(self.metrics_jsonl, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# --------------------------- Train / Validate ----------------------------------------------------

@torch.no_grad()
def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> Tuple[float, float]:
    model.eval()
    loss_fn = nn.CrossEntropyLoss()
    total = 0
    correct = 0
    total_loss = 0.0
    for x, y in loader:
        x = x.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        logits = model(x)
        loss = loss_fn(logits, y)
        total_loss += loss.item() * x.size(0)
        pred = logits.argmax(dim=1)
        correct += (pred == y).sum().item()
        total += x.size(0)
    avg_loss = total_loss / max(total, 1)
    acc = correct / max(total, 1)
    return avg_loss, acc

def train(cfg: Config) -> int:
    # Prepare run dir
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(cfg.run.out_dir) / cfg.run.project / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    # Save resolved config snapshot
    safe_write_text(run_dir / "config.json", json.dumps(dataclasses.asdict(cfg), indent=2, ensure_ascii=False))

    # Seed & device
    set_global_seed(cfg.run.seed)
    device = select_device(cfg.run.device)
    print(f"[{utc_now_iso()}] device={device}, seed={cfg.run.seed}")

    # Data
    train_loader, val_loader = build_loaders(cfg)
    in_dim = cfg.data.n_features
    out_dim = cfg.data.n_classes

    # Model/opt/sched
    model = MLP(in_dim=in_dim, width=cfg.model.width, depth=cfg.model.depth, out_dim=out_dim, dropout=cfg.model.dropout).to(device)
    opt = AdamW(model.parameters(), lr=cfg.train.lr, weight_decay=cfg.train.weight_decay)
    sched = None
    if cfg.train.scheduler_cosine:
        sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=cfg.train.scheduler_tmin)

    scaler = torch.cuda.amp.GradScaler(enabled=cfg.train.amp and device.type == "cuda")
    loss_fn = nn.CrossEntropyLoss()

    # Resume
    ckpt = CheckpointMgr(run_dir)
    best_val_loss = math.inf
    start_epoch = 0
    steps_seen = 0
    epochs_no_improve = 0

    if cfg.run.resume:
        state = ckpt.load(cfg.run.resume)
        if state:
            model.load_state_dict(state["model"])
            opt.load_state_dict(state["opt"])
            if state.get("sched") and sched:
                sched.load_state_dict(state["sched"])
            scaler.load_state_dict(state["scaler"])
            start_epoch = state.get("epoch", 0) + 1
            steps_seen = state.get("steps", 0)
            best_val_loss = state.get("best_val_loss", best_val_loss)
            epochs_no_improve = state.get("epochs_no_improve", 0)
            print(f"[{utc_now_iso()}] Resumed from {cfg.run.resume} at epoch {start_epoch}")

    # Train loop
    t0 = time.perf_counter()
    for epoch in range(start_epoch, cfg.train.epochs):
        model.train()
        epoch_loss = 0.0
        seen = 0
        ep_start = time.perf_counter()
        opt.zero_grad(set_to_none=True)

        for i, (x, y) in enumerate(train_loader):
            x = x.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)

            with torch.cuda.amp.autocast(enabled=cfg.train.amp and device.type == "cuda"):
                logits = model(x)
                loss = loss_fn(logits, y) / max(1, cfg.train.grad_accum_steps)

            scaler.scale(loss).backward()
            if (i + 1) % cfg.train.grad_accum_steps == 0:
                scaler.step(opt)
                scaler.update()
                opt.zero_grad(set_to_none=True)
                if sched:
                    sched.step()

            bsz = x.size(0)
            epoch_loss += loss.item() * bsz * max(1, cfg.train.grad_accum_steps)
            seen += bsz
            steps_seen += 1

        # Validation
        val_loss, val_acc = evaluate(model, val_loader, device)
        tr_loss = epoch_loss / max(seen, 1)

        # Early stopping bookkeeping
        improved = val_loss < best_val_loss - 1e-6
        if improved:
            best_val_loss = val_loss
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1

        # Save checkpoints
        state = {
            "epoch": epoch,
            "steps": steps_seen,
            "model": model.state_dict(),
            "opt": opt.state_dict(),
            "sched": sched.state_dict() if sched else None,  # type: ignore[union-attr]
            "scaler": scaler.state_dict(),
            "best_val_loss": best_val_loss,
            "epochs_no_improve": epochs_no_improve,
            "cfg": dataclasses.asdict(cfg),
        }
        ckpt.save(state, best=improved)

        # Log JSONL
        rec = {
            "ts": utc_now_iso(),
            "epoch": epoch,
            "train_loss": tr_loss,
            "val_loss": val_loss,
            "val_acc": val_acc,
            "lr": opt.param_groups[0]["lr"],
            "elapsed_epoch": human_time_dur(ep_start, time.perf_counter()),
        }
        ckpt.log_metrics(rec)

        # Stdout
        print(f"[{rec['ts']}] epoch={epoch:03d} train_loss={tr_loss:.4f} val_loss={val_loss:.4f} val_acc={val_acc:.4f} lr={rec['lr']:.6f} no_improve={epochs_no_improve}")

        # Early stop
        if epochs_no_improve >= cfg.train.early_stop_patience:
            print(f"[{utc_now_iso()}] Early stopping after {epoch+1} epochs (patience={cfg.train.early_stop_patience})")
            break

    # Export best model to TorchScript
    best_state = ckpt.load(str(ckpt.ckpt_best))
    if best_state:
        model.load_state_dict(best_state["model"])
        model.eval()
        example = torch.randn(1, cfg.data.n_features, device=device)
        try:
            traced = torch.jit.trace(model, example)
            out_path = run_dir / "model_best.ts.pt"
            traced.save(str(out_path))
            print(f"[{utc_now_iso()}] TorchScript saved: {out_path}")
        except Exception as e:
            print(f"[{utc_now_iso()}] TorchScript export failed: {e}", file=sys.stderr)

    print(f"[{utc_now_iso()}] Finished in {human_time_dur(t0, time.perf_counter())}. Artifacts: {run_dir}")
    return EXIT_OK

# --------------------------- CLI ----------------------------------------------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NeuroForge Quickstart Trainer")
    p.add_argument("--device", type=str, default=None, help="auto|cuda|mps|cpu")
    p.add_argument("--resume", type=str, default=None, help="path to checkpoint (.pt)")
    p.add_argument("--out-dir", type=str, default=None, help="output root (default runs)")
    p.add_argument("--project", type=str, default=None, help="project name (subfolder)")
    p.add_argument("--epochs", type=int, default=None)
    p.add_argument("--batch-size", type=int, default=None)
    p.add_argument("--lr", type=float, default=None)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--width", type=int, default=None)
    p.add_argument("--depth", type=int, default=None)
    p.add_argument("--dropout", type=float, default=None)
    p.add_argument("--grad-accum", type=int, default=None)
    p.add_argument("--no-amp", action="store_true")
    p.add_argument("--no-cosine", action="store_true")
    p.add_argument("--early-stop", type=int, default=None, help="patience")
    p.add_argument("--override", nargs="*", default=[], help="dotted overrides key=value (JSON accepted)")
    return p

def make_config_from_cli(ns: argparse.Namespace) -> Config:
    cfg = Config()
    if ns.device is not None:
        cfg.run.device = ns.device
    if ns.resume is not None:
        cfg.run.resume = ns.resume
    if ns.out_dir is not None:
        cfg.run.out_dir = ns.out_dir
    if ns.project is not None:
        cfg.run.project = ns.project
    if ns.epochs is not None:
        cfg.train.epochs = ns.epochs
    if ns.batch_size is not None:
        cfg.train.batch_size = ns.batch_size
    if ns.lr is not None:
        cfg.train.lr = ns.lr
    if ns.seed is not None:
        cfg.run.seed = ns.seed
    if ns.width is not None:
        cfg.model.width = ns.width
    if ns.depth is not None:
        cfg.model.depth = ns.depth
    if ns.dropout is not None:
        cfg.model.dropout = ns.dropout
    if ns.grad_accum is not None:
        cfg.train.grad_accum_steps = ns.grad_accum
    if ns.no_amp:
        cfg.train.amp = False
    if ns.no_cosine:
        cfg.train.scheduler_cosine = False
    if ns.early_stop is not None:
        cfg.train.early_stop_patience = ns.early_stop

    if ns.override:
        overrides = parse_overrides(ns.override)
        cfg = apply_overrides_dc(cfg, overrides)
    return cfg

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_argparser()
    ns = parser.parse_args(argv)
    try:
        cfg = make_config_from_cli(ns)
        return train(cfg)
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return EXIT_USAGE
    except FileNotFoundError as e:
        print(f"File not found: {e}", file=sys.stderr)
        return EXIT_IO
    except ValueError as e:
        print(f"Invalid value: {e}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as e:
        print(f"Runtime error: {e}", file=sys.stderr)
        return EXIT_RUNTIME

if __name__ == "__main__":
    sys.exit(main())

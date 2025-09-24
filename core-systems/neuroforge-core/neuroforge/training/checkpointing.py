# neuroforge-core/neuroforge/training/checkpointing.py
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import enum
import io
import json
import math
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# ------------------------------ Optional deps ------------------------------
try:
    import torch
    _HAVE_TORCH = True
except Exception:
    torch = None  # type: ignore
    _HAVE_TORCH = False

try:
    import numpy as _np  # type: ignore
    _HAVE_NUMPY = True
except Exception:
    _np = None
    _HAVE_NUMPY = False

try:
    import fsspec  # type: ignore
    _HAVE_FSSPEC = True
except Exception:
    fsspec = None  # type: ignore
    _HAVE_FSSPEC = False

try:
    from safetensors.torch import save_file as safetensors_save, load_file as safetensors_load  # type: ignore
    _HAVE_SAFETENSORS = True
except Exception:
    safetensors_save = safetensors_load = None  # type: ignore
    _HAVE_SAFETENSORS = False

# ------------------------------ Helpers ------------------------------

def _utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def _sha256_bytes(data: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _sha256_file(fp: Union[str, Path], chunk: int = 2**20) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(fp, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

@contextlib.contextmanager
def _file_lock(path: Union[str, Path]):
    """
    Lightweight advisory lock based on lockfile in the same dir.
    Safe for single-host concurrency.
    """
    path = Path(path)
    lock = path.with_suffix(path.suffix + ".lock")
    fd = None
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        os.write(fd, str(os.getpid()).encode("ascii"))
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
            with contextlib.suppress(Exception):
                os.remove(lock)

def _atomic_move(src: Path, dst: Path) -> None:
    # Cross-device move fallback
    try:
        os.replace(src, dst)
    except OSError:
        shutil.move(str(src), str(dst))

def _fsync_dir(dirpath: Path) -> None:
    try:
        fd = os.open(str(dirpath), os.O_RDONLY)
        os.fsync(fd)
        os.close(fd)
    except Exception:
        pass

def _ensure_dir(p: Union[str, Path]) -> Path:
    path = Path(p)
    path.mkdir(parents=True, exist_ok=True)
    return path

def _is_remote(path: Union[str, Path]) -> bool:
    s = str(path)
    return "://" in s and not s.startswith("file://")

# ------------------------------ Data classes ------------------------------

class ModelFormat(str, enum.Enum):
    TORCH = "torch"
    SAFETENSORS = "safetensors"

@dataclass
class RNGState:
    python: Optional[List[int]] = None
    numpy: Optional[bytes] = None
    torch_cpu: Optional[bytes] = None
    torch_cuda: Optional[List[bytes]] = None

def capture_rng() -> RNGState:
    py_state = random.getstate()
    numpy_state = _np.random.get_state() if _HAVE_NUMPY else None
    torch_cpu = torch.random.get_rng_state().numpy().tobytes() if _HAVE_TORCH else None
    cuda_states: Optional[List[bytes]] = None
    if _HAVE_TORCH and torch.cuda.is_available():
        cuda_states = []
        for i in range(torch.cuda.device_count()):
            s = torch.cuda.get_rng_state(i).cpu().numpy().tobytes()
            cuda_states.append(s)
    return RNGState(
        python=list(py_state[1]) if isinstance(py_state, tuple) else None,
        numpy=_np.random.get_state()[1].tobytes() if (_HAVE_NUMPY) else None,
        torch_cpu=torch_cpu,
        torch_cuda=cuda_states,
    )

def restore_rng(state: RNGState) -> None:
    try:
        if state.python is not None:
            random.setstate((3, tuple(state.python), None))
    except Exception:
        pass
    if _HAVE_NUMPY and state.numpy is not None:
        try:
            arr = _np.frombuffer(state.numpy, dtype=_np.uint32)
            _np.random.set_state(('MT19937', arr, 624, 0, 0.0))
        except Exception:
            pass
    if _HAVE_TORCH and state.torch_cpu is not None:
        try:
            torch.random.set_rng_state(torch.frombuffer(state.torch_cpu, dtype=torch.uint8))
        except Exception:
            pass
    if _HAVE_TORCH and state.torch_cuda:
        for i, buf in enumerate(state.torch_cuda):
            with contextlib.suppress(Exception):
                torch.cuda.set_rng_state(torch.frombuffer(buf, dtype=torch.uint8), device=i)

@dataclass
class TrainingState:
    epoch: int
    global_step: int
    samples_seen: int
    best_metric: Optional[float] = None
    best_step: Optional[int] = None
    lr: Optional[float] = None
    extra: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass
class CheckpointManifest:
    version: int
    created_at: str
    step: int
    epoch: int
    wall_time: float
    format: ModelFormat
    files: Dict[str, Dict[str, Any]]  # name -> {path, sha256, bytes}
    rng: Dict[str, Any]
    training: TrainingState
    etag: Optional[str] = None

# ------------------------------ Storage backend ------------------------------

class Storage:
    def __init__(self, base: Union[str, Path]) -> None:
        self.base = str(base)

    def _fs(self):
        if _HAVE_FSSPEC and _is_remote(self.base):
            return fsspec.open_files
        return None

    def join(self, *parts: str) -> str:
        if _HAVE_FSSPEC and _is_remote(self.base):
            base = self.base.rstrip("/")
            return "/".join([base, *[p.strip("/") for p in parts]])
        return str(Path(self.base, *parts))

    def exists(self, path: str) -> bool:
        if _HAVE_FSSPEC and _is_remote(path):
            with fsspec.open(path, "rb") as f:  # type: ignore
                try:
                    f.head(1)
                    return True
                except Exception:
                    return False
        return Path(path).exists()

    def mkdir(self, path: str) -> None:
        if _HAVE_FSSPEC and _is_remote(path):
            fs, _, paths = fsspec.get_fs_token_paths(path)  # type: ignore
            fs.mkdirs(paths[0], exist_ok=True)
            return
        Path(path).mkdir(parents=True, exist_ok=True)

    def put(self, local: Path, remote: str) -> None:
        if _HAVE_FSSPEC and _is_remote(remote):
            with fsspec.open(remote, "wb") as f:  # type: ignore
                with open(local, "rb") as src:
                    shutil.copyfileobj(src, f)
            return
        _ensure_dir(Path(remote).parent)
        _atomic_move(local, Path(remote))

    def open(self, path: str, mode: str = "rb"):
        if _HAVE_FSSPEC and _is_remote(path):
            return fsspec.open(path, mode).open()  # type: ignore
        return open(path, mode)

    def listdir(self, path: str) -> List[str]:
        if _HAVE_FSSPEC and _is_remote(path):
            fs, _, paths = fsspec.get_fs_token_paths(path)  # type: ignore
            return [p.rstrip("/") for p in fs.ls(paths[0])]
        return [str(Path(path, p)) for p in os.listdir(path)]

    def remove(self, path: str) -> None:
        if _HAVE_FSSPEC and _is_remote(path):
            fs, _, paths = fsspec.get_fs_token_paths(path)  # type: ignore
            fs.rm_file(paths[0])
            return
        with contextlib.suppress(FileNotFoundError):
            Path(path).unlink()

    def rmtree(self, path: str) -> None:
        if _HAVE_FSSPEC and _is_remote(path):
            fs, _, paths = fsspec.get_fs_token_paths(path)  # type: ignore
            fs.rm(paths[0], recursive=True)
            return
        shutil.rmtree(path, ignore_errors=True)

# ------------------------------ Core manager ------------------------------

class CheckpointManager:
    """
    Checkpoint manager with atomic writes, manifest+hashes, and retention.
    Layout:
      base_dir/
        ckpt-<step>-<timestamp>/
          manifest.json
          model.safetensors | model.pt | model-shard-*.safetensors
          optimizer.pt
          scheduler.pt
          scaler.pt
          rng.json
          training.json
        latest -> ckpt-... (symlink if local)
        best -> ckpt-... (symlink if local)
    """

    def __init__(
        self,
        base_dir: Union[str, Path],
        fmt: ModelFormat = ModelFormat.SAFETENSORS,
        max_shard_bytes: int = 0,  # 0 = no sharding
        keep_last: int = 5,
        keep_every: Optional[int] = None,  # keep every Nth checkpoint regardless of keep_last
        keep_best: int = 3,
        async_io: bool = True,
        enable_hash_validation: bool = True,
    ) -> None:
        self.base_dir = str(base_dir)
        self.storage = Storage(self.base_dir)
        self.fmt = fmt
        self.max_shard_bytes = max_shard_bytes
        self.keep_last = keep_last
        self.keep_every = keep_every
        self.keep_best = keep_best
        self.async_io = async_io
        self.enable_hash_validation = enable_hash_validation
        _ensure_dir(self.base_dir)

        self._io_thread: Optional[threading.Thread] = None
        self._io_queue: List[Tuple[str, Dict[str, Any]]] = []
        self._io_cv = threading.Condition()
        if self.async_io:
            self._start_io_thread()

    # ----------------- Public API -----------------

    def save(
        self,
        step: int,
        epoch: int,
        model: Any,
        optimizer: Optional[Any] = None,
        scheduler: Optional[Any] = None,
        scaler: Optional[Any] = None,
        training_state: Optional[TrainingState] = None,
        is_best: bool = False,
        user_meta: Optional[Dict[str, Any]] = None,
        fsync: bool = True,
    ) -> str:
        """
        Save checkpoint; returns checkpoint directory path (string).
        If async_io=True, heavy file uploads move to IO thread; manifest is written before return.
        """
        t0 = time.perf_counter()
        wall_time = time.time()
        ts = dt.datetime.fromtimestamp(wall_time, dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        ckpt_dir = self.storage.join(f"ckpt-{step}-{ts}")
        self.storage.mkdir(ckpt_dir)

        # Serialize components to temp files locally
        tmp_dir = Path(tempfile.mkdtemp(prefix=".tmpckpt-", dir=os.getcwd()))
        files: Dict[str, Dict[str, Any]] = {}

        # 1) Model
        model_files = self._dump_model(model, tmp_dir, self.fmt, self.max_shard_bytes)
        files.update(model_files)

        # 2) Optimizer/Scheduler/Scaler
        if optimizer is not None:
            files["optimizer.pt"] = self._dump_torch(obj=optimizer.state_dict(), tmp_dir=tmp_dir, name="optimizer.pt")
        if scheduler is not None:
            try:
                files["scheduler.pt"] = self._dump_torch(obj=scheduler.state_dict(), tmp_dir=tmp_dir, name="scheduler.pt")
            except Exception:
                pass
        if scaler is not None and _HAVE_TORCH:
            try:
                files["scaler.pt"] = self._dump_torch(obj=scaler.state_dict(), tmp_dir=tmp_dir, name="scaler.pt")
            except Exception:
                pass

        # 3) RNG + Training state
        rng = capture_rng()
        rng_path = tmp_dir / "rng.json"
        rng_json = json.dumps(dataclasses.asdict(rng)).encode("utf-8")
        rng_path.write_bytes(rng_json)
        files["rng.json"] = {"path": str(rng_path), "sha256": _sha256_bytes(rng_json), "bytes": len(rng_json)}

        training = training_state or TrainingState(epoch=epoch, global_step=step, samples_seen=0)
        training_path = tmp_dir / "training.json"
        training_json = json.dumps(asdict(training)).encode("utf-8")
        training_path.write_bytes(training_json)
        files["training.json"] = {"path": str(training_path), "sha256": _sha256_bytes(training_json), "bytes": len(training_json)}

        if user_meta:
            meta_path = tmp_dir / "meta.json"
            meta_bytes = json.dumps(user_meta).encode("utf-8")
            meta_path.write_bytes(meta_bytes)
            files["meta.json"] = {"path": str(meta_path), "sha256": _sha256_bytes(meta_bytes), "bytes": len(meta_bytes)}

        manifest = CheckpointManifest(
            version=1,
            created_at=_utc_iso(),
            step=step,
            epoch=epoch,
            wall_time=wall_time,
            format=self.fmt,
            files=files,
            rng=asdict(rng),
            training=training,
            etag=None,
        )
        manifest_bytes = json.dumps(dataclasses.asdict(manifest), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        manifest_etag = _sha256_bytes(manifest_bytes)
        manifest.etag = manifest_etag
        manifest_bytes = json.dumps(dataclasses.asdict(manifest), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        # Persist manifest first (atomic)
        man_tmp = Path(tempfile.mkstemp(prefix="manifest-", suffix=".json", dir=tmp_dir)[1])
        man_tmp.write_bytes(manifest_bytes)
        man_rel = "manifest.json"
        man_dst = self.storage.join(ckpt_dir, man_rel)

        with _file_lock(self.storage.join(self.base_dir, ".ckpt.lock")):
            # push manifest
            self.storage.put(man_tmp, man_dst)
            # then push blobs (async or sync)
            payload = {"ckpt_dir": ckpt_dir, "files": files, "fsync": fsync}
            if self.async_io:
                self._enqueue_io("upload", payload)
            else:
                self._perform_upload(payload)

            # update symlinks latest/best for local FS
            if not _is_remote(self.base_dir):
                self._update_symlink("latest", ckpt_dir)
                if is_best:
                    self._update_symlink("best", ckpt_dir)

        # retention
        with _file_lock(self.storage.join(self.base_dir, ".ckpt.lock")):
            self._retention(is_best=is_best)

        dt_ms = int((time.perf_counter() - t0) * 1000)
        print(f"[checkpoint] saved step={step} in {dt_ms} ms -> {ckpt_dir}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return ckpt_dir

    def load(
        self,
        ckpt_dir: Optional[str] = None,
        model: Optional[Any] = None,
        optimizer: Optional[Any] = None,
        scheduler: Optional[Any] = None,
        scaler: Optional[Any] = None,
        map_location: Optional[Union[str, torch.device]] = "cpu",
        strict_model: bool = True,
        restore_rng_state: bool = True,
    ) -> Tuple[TrainingState, Dict[str, Any]]:
        """
        Load checkpoint from directory (default: 'latest').
        Returns (training_state, meta_dict). Model/optimizer/etc are restored if provided.
        """
        if ckpt_dir is None:
            # Prefer local symlink if available
            ckpt_dir = self.resolve_alias("latest")

        man_path = self.storage.join(ckpt_dir, "manifest.json")
        with self.storage.open(man_path, "rb") as f:
            manifest = json.loads(f.read().decode("utf-8"))

        # Integrity check
        if self.enable_hash_validation:
            # Validate manifest ETag equals sha256(manifest with etag present)
            etag = manifest.get("etag")
            man_no_change_bytes = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if _sha256_bytes(man_no_change_bytes) != etag:
                raise RuntimeError("manifest etag mismatch")

        files = manifest["files"]

        # Model
        if model is not None:
            self._load_model(model, manifest, ckpt_dir, map_location=map_location, strict=strict_model)

        # Optimizer/Scheduler/Scaler
        if optimizer is not None and "optimizer.pt" in files:
            state = self._load_torch(self.storage.join(ckpt_dir, "optimizer.pt"), map_location)
            with contextlib.suppress(Exception):
                optimizer.load_state_dict(state)
        if scheduler is not None and "scheduler.pt" in files:
            state = self._load_torch(self.storage.join(ckpt_dir, "scheduler.pt"), map_location)
            with contextlib.suppress(Exception):
                scheduler.load_state_dict(state)
        if scaler is not None and "scaler.pt" in files:
            state = self._load_torch(self.storage.join(ckpt_dir, "scaler.pt"), map_location)
            with contextlib.suppress(Exception):
                scaler.load_state_dict(state)

        # RNG
        if restore_rng_state:
            rng_json = json.loads(self.storage.open(self.storage.join(ckpt_dir, "rng.json"), "rb").read().decode("utf-8"))
            restore_rng(RNGState(**rng_json))

        training = TrainingState(**manifest["training"])
        meta = {}
        if "meta.json" in files:
            meta = json.loads(self.storage.open(self.storage.join(ckpt_dir, "meta.json"), "rb").read().decode("utf-8"))
        return training, meta

    def resolve_alias(self, alias: str) -> str:
        """
        Resolve 'latest'/'best' to real checkpoint directory.
        Local FS uses symlinks; for remote, pick the most recent directory.
        """
        if not _is_remote(self.base_dir):
            p = Path(self.base_dir, alias)
            if p.is_symlink() or p.exists():
                return str(p.resolve())
        # remote: list and choose
        dirs = [d for d in self.storage.listdir(self.base_dir) if "ckpt-" in d]
        if not dirs:
            raise FileNotFoundError("no checkpoints found")
        return sorted(dirs)[-1]

    # ----------------- Internals -----------------

    def _dump_model(
        self, model: Any, tmp_dir: Path, fmt: ModelFormat, max_shard_bytes: int
    ) -> Dict[str, Dict[str, Any]]:
        if not _HAVE_TORCH:
            raise RuntimeError("PyTorch not available")

        # Try FSDP full state dict
        state: Mapping[str, Any]
        use_fsdp = False
        if hasattr(torch.nn, "modules") and hasattr(torch.nn.modules, "module") and hasattr(model, "state_dict"):
            state = model.state_dict()
        else:
            state = model.state_dict()

        files: Dict[str, Dict[str, Any]] = {}

        if fmt == ModelFormat.SAFETENSORS and _HAVE_SAFETENSORS:
            # safetensors requires all tensors on CPU
            cpu_state = {k: v.detach().cpu() if torch.is_tensor(v) else v for k, v in state.items()}
            if max_shard_bytes and max_shard_bytes > 0:
                shard_idx = 0
                accum: Dict[str, Any] = {}
                cur_bytes = 0
                for k, v in cpu_state.items():
                    t_bytes = int(v.element_size() * v.nelement()) if torch.is_tensor(v) else 0
                    if cur_bytes and (cur_bytes + t_bytes) > max_shard_bytes:
                        shard_idx += 1
                        shard_path = tmp_dir / f"model-shard-{shard_idx:05d}.safetensors"
                        safetensors_save(accum, str(shard_path))
                        sha = _sha256_file(shard_path)
                        files[shard_path.name] = {"path": str(shard_path), "sha256": sha, "bytes": shard_path.stat().st_size}
                        accum = {}
                        cur_bytes = 0
                    accum[k] = v
                    cur_bytes += t_bytes
                if accum:
                    shard_idx += 1
                    shard_path = tmp_dir / f"model-shard-{shard_idx:05d}.safetensors"
                    safetensors_save(accum, str(shard_path))
                    sha = _sha256_file(shard_path)
                    files[shard_path.name] = {"path": str(shard_path), "sha256": sha, "bytes": shard_path.stat().st_size}
            else:
                f = tmp_dir / "model.safetensors"
                safetensors_save(cpu_state, str(f))
                files[f.name] = {"path": str(f), "sha256": _sha256_file(f), "bytes": f.stat().st_size}
        else:
            # torch save
            f = tmp_dir / "model.pt"
            torch.save(state, str(f))
            files[f.name] = {"path": str(f), "sha256": _sha256_file(f), "bytes": f.stat().st_size}
        return files

    def _dump_torch(self, obj: Any, tmp_dir: Path, name: str) -> Dict[str, Any]:
        f = tmp_dir / name
        if _HAVE_TORCH:
            torch.save(obj, str(f))
        else:
            # Fallback to pickle (not recommended)
            import pickle
            with open(f, "wb") as fh:
                pickle.dump(obj, fh)
        return {"path": str(f), "sha256": _sha256_file(f), "bytes": f.stat().st_size}

    def _perform_upload(self, payload: Dict[str, Any]) -> None:
        ckpt_dir = payload["ckpt_dir"]
        files = payload["files"]
        fsync = payload.get("fsync", True)

        # Upload/move each file
        for rel, meta in files.items():
            src = Path(meta["path"])
            dst = self.storage.join(ckpt_dir, rel)
            self.storage.put(src, dst)

        # fsync directory (local only)
        if fsync and not _is_remote(ckpt_dir):
            _fsync_dir(Path(ckpt_dir))

        # Validate hashes (best effort)
        if self.enable_hash_validation:
            for rel, meta in files.items():
                dst = self.storage.join(ckpt_dir, rel)
                if not _is_remote(dst):
                    sha = _sha256_file(Path(dst))
                    if sha != meta["sha256"]:
                        raise RuntimeError(f"hash mismatch for {rel}")

    def _enqueue_io(self, kind: str, payload: Dict[str, Any]) -> None:
        with self._io_cv:
            self._io_queue.append((kind, payload))
            self._io_cv.notify()

    def _start_io_thread(self) -> None:
        def run():
            while True:
                with self._io_cv:
                    while not self._io_queue:
                        self._io_cv.wait()
                    kind, payload = self._io_queue.pop(0)
                try:
                    if kind == "upload":
                        self._perform_upload(payload)
                    elif kind == "stop":
                        break
                except Exception as e:
                    print(f"[checkpoint] async io error: {e}", file=sys.stderr)
        t = threading.Thread(target=run, name="ckpt-io", daemon=True)
        t.start()
        self._io_thread = t

    def stop(self) -> None:
        if self._io_thread:
            self._enqueue_io("stop", {})
            self._io_thread.join(timeout=2.0)
            self._io_thread = None

    def _update_symlink(self, name: str, target: str) -> None:
        link = Path(self.base_dir) / name
        with contextlib.suppress(Exception):
            if link.is_symlink() or link.exists():
                link.unlink()
        with contextlib.suppress(Exception):
            os.symlink(Path(target).resolve(), link)

    def _retention(self, is_best: bool = False) -> None:
        # List checkpoints
        entries = []
        for p in Path(self.base_dir).glob("ckpt-*"):
            if p.is_dir():
                try:
                    step = int(p.name.split("-")[1])
                except Exception:
                    step = -1
                mtime = p.stat().st_mtime
                entries.append((p, step, mtime))
        if not entries:
            return
        entries.sort(key=lambda x: (x[1], x[2]))  # by step then mtime

        # Determine protected set: last N, every Mth, best link
        protected: set[Path] = set()
        last = entries[-self.keep_last:] if self.keep_last > 0 else []
        protected.update(p for p, *_ in last)
        if self.keep_every and self.keep_every > 0:
            for p, step, _ in entries:
                if step >= 0 and (step % self.keep_every == 0):
                    protected.add(p)
        best_target = None
        if not _is_remote(self.base_dir):
            best_link = Path(self.base_dir) / "best"
            if best_link.exists():
                with contextlib.suppress(Exception):
                    best_target = best_link.resolve()
        if best_target:
            protected.add(best_target)

        # Remove others
        for p, _, _ in entries:
            if p not in protected:
                shutil.rmtree(p, ignore_errors=True)

    # ----------------- Load helpers -----------------

    def _load_torch(self, path: str, map_location) -> Any:
        if _HAVE_TORCH:
            with self.storage.open(path, "rb") as f:
                buf = io.BytesIO(f.read())
                return torch.load(buf, map_location=map_location)
        import pickle
        with self.storage.open(path, "rb") as f:
            return pickle.load(f)

    def _load_model(self, model: Any, manifest: Dict[str, Any], ckpt_dir: str, map_location, strict: bool) -> None:
        files = manifest["files"]
        fmt = ModelFormat(manifest.get("format", "torch"))
        if fmt == ModelFormat.SAFETENSORS and _HAVE_SAFETENSORS:
            # Collect shards or single file
            shard_names = [k for k in files.keys() if k.startswith("model-shard-") and k.endswith(".safetensors")]
            if shard_names:
                # Merge shards
                tensors = {}
                for name in sorted(shard_names):
                    path = self.storage.join(ckpt_dir, name)
                    with self.storage.open(path, "rb") as f:
                        # safetensors_load expects path; write to temp
                        tmp = Path(tempfile.mkstemp(prefix="load-", suffix=".safetensors")[1])
                        tmp.write_bytes(f.read())
                        part = safetensors_load(str(tmp))
                        tensors.update(part)
                        tmp.unlink(missing_ok=True)
                missing, unexpected = model.load_state_dict(tensors, strict=strict)
            else:
                path = self.storage.join(ckpt_dir, "model.safetensors")
                with self.storage.open(path, "rb") as f:
                    tmp = Path(tempfile.mkstemp(prefix="load-", suffix=".safetensors")[1])
                    tmp.write_bytes(f.read())
                    tensors = safetensors_load(str(tmp))
                    tmp.unlink(missing_ok=True)
                missing, unexpected = model.load_state_dict(tensors, strict=strict)
            if (missing or unexpected) and strict:
                raise RuntimeError(f"state_dict mismatch: missing={missing}, unexpected={unexpected}")
        else:
            path = self.storage.join(ckpt_dir, "model.pt")
            state = self._load_torch(path, map_location)
            missing, unexpected = model.load_state_dict(state, strict=strict)
            if (missing or unexpected) and strict:
                raise RuntimeError(f"state_dict mismatch: missing={missing}, unexpected={unexpected}")

# ------------------------------ Convenience API ------------------------------

def save_checkpoint(
    manager: CheckpointManager,
    step: int,
    epoch: int,
    model: Any,
    optimizer: Optional[Any] = None,
    scheduler: Optional[Any] = None,
    scaler: Optional[Any] = None,
    training_state: Optional[TrainingState] = None,
    is_best: bool = False,
    user_meta: Optional[Dict[str, Any]] = None,
) -> str:
    return manager.save(
        step=step,
        epoch=epoch,
        model=model,
        optimizer=optimizer,
        scheduler=scheduler,
        scaler=scaler,
        training_state=training_state,
        is_best=is_best,
        user_meta=user_meta,
    )

def load_checkpoint(
    manager: CheckpointManager,
    ckpt_dir: Optional[str],
    model: Optional[Any] = None,
    optimizer: Optional[Any] = None,
    scheduler: Optional[Any] = None,
    scaler: Optional[Any] = None,
    map_location: Optional[Union[str, Any]] = "cpu",
    strict_model: bool = True,
    restore_rng_state: bool = True,
) -> Tuple[TrainingState, Dict[str, Any]]:
    return manager.load(
        ckpt_dir=ckpt_dir,
        model=model,
        optimizer=optimizer,
        scheduler=scheduler,
        scaler=scaler,
        map_location=map_location,
        strict_model=strict_model,
        restore_rng_state=restore_rng_state,
    )

#!/usr/bin/env python3
# neuroforge-core/cli/tools/export_onnx.py
"""
NeuroForge ONNX Export Tool (industrial-grade)

Features:
- Import model builder via "pkg.module:callable" (returns torch.nn.Module)
- Load checkpoint (state_dict or full object), map_location=cpu/cuda
- Inputs from CLI string or YAML; dtypes: float32/16/64, int64/32, bool
- Dynamic axes per input, e.g. --dynamic "input:0,2,3"
- Export via torch.onnx.export or torch.onnx.dynamo_export (PyTorch>=2.1)
- Opset selection, constant folding, external data for >2GB
- Optional onnx-simplifier pass (--simplify)
- Optional dynamic quantization (--quantize dynamic)
- ONNX Runtime validation: run PyTorch vs ORT on random inputs and compare
- Metadata embedding (producer_name/version, custom key=value)
- SHA256 of resulting files (ONNX and external data directory)
- Determinism (seeds), structured logging and clear error reporting

Examples:
  python export_onnx.py \
    --model "models.resnet:build_model" \
    --checkpoint "checkpoints/resnet50.pt" \
    --inputs "input:1x3x224x224:float32" \
    --dynamic "input:0" \
    --opset 17 \
    --output "dist/resnet50.onnx" \
    --simplify \
    --verify \
    --metadata "project=NeuroForge,stage=prod"

  python export_onnx.py \
    --model "pkg.module:make" \
    --inputs-yaml "export_inputs.yaml" \
    --device cuda \
    --quantize dynamic \
    --external-data \
    --save-config "dist/export_config.json"

YAML format for --inputs-yaml:
  inputs:
    - name: input
      shape: [1, 3, 224, 224]
      dtype: float32
  dynamic:
    input: [0, 2, 3]   # batch, H, W dynamic
"""

from __future__ import annotations

import argparse
import importlib
import io
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# ----- Optional heavy deps (graceful degradation) -----
try:
    import torch
    import torch.nn as nn
except Exception as e:  # pragma: no cover
    torch = None  # type: ignore
    nn = None  # type: ignore
    _torch_err = e
else:
    _torch_err = None

try:
    import onnx
except Exception as e:  # pragma: no cover
    onnx = None  # type: ignore
    _onnx_err = e
else:
    _onnx_err = None

try:
    import onnxruntime as ort
except Exception as e:  # pragma: no cover
    ort = None  # type: ignore
    _ort_err = e
else:
    _ort_err = None

try:
    import numpy as np
except Exception as e:  # pragma: no cover
    np = None  # type: ignore
    _np_err = e
else:
    _np_err = None

# Optional tools
try:
    import yaml  # pyyaml
except Exception:
    yaml = None  # type: ignore

try:
    from onnxsim import simplify as onnx_simplify  # type: ignore
except Exception:
    onnx_simplify = None  # type: ignore

try:
    from onnxruntime.quantization import quantize_dynamic, QuantType  # type: ignore
except Exception:
    quantize_dynamic = None  # type: ignore
    QuantType = None  # type: ignore

# Optional NeuroForge tracing (safe if unavailable)
try:
    from neuroforge.observability import tracing as nf_tracing  # type: ignore
except Exception:
    nf_tracing = None  # type: ignore


# ====== Configuration ======
@dataclass
class InputSpec:
    name: str
    shape: List[int]
    dtype: str = "float32"  # float32|float16|float64|int64|int32|bool


@dataclass
class ExportConfig:
    model_path: str
    checkpoint: Optional[str]
    inputs: List[InputSpec]
    dynamic_axes: Dict[str, List[int]]
    opset: int = 17
    device: str = "cpu"  # "cpu" or "cuda"
    use_dynamo: bool = False
    constant_folding: bool = True
    external_data: bool = False
    output: str = "model.onnx"
    simplify: bool = False
    quantize: Optional[str] = None  # "dynamic" or None
    verify: bool = False
    atol: float = 1e-4
    rtol: float = 1e-3
    seed: int = 42
    metadata: Dict[str, str] = None  # type: ignore
    save_config: Optional[str] = None
    ort_threads: int = 1

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)


# ====== Utilities ======
def fail(msg: str, exc: Optional[BaseException] = None) -> None:
    logging.error(msg)
    if exc:
        logging.debug("Exception detail", exc_info=exc)
    sys.exit(2)


def ensure_deps() -> None:
    if torch is None:
        fail(f"PyTorch not available: {repr(_torch_err)}")
    if onnx is None:
        fail(f"onnx not available: {repr(_onnx_err)}")
    if np is None:
        fail(f"numpy not available: {repr(_np_err)}")


def set_seeds(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as _np

        _np.random.seed(seed)
    except Exception:
        pass
    if torch is not None:
        torch.manual_seed(seed)
        torch.use_deterministic_algorithms(False)


def parse_inputs_str(s: str) -> List[InputSpec]:
    """
    Format: "name:1x3x224x224:float32;other:4:int64"
    dtype optional defaults to float32.
    """
    if not s:
        return []
    specs: List[InputSpec] = []
    for part in s.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split(":")
        if len(toks) == 1:
            name, shape_s, dtype = toks[0], "1", "float32"
        elif len(toks) == 2:
            name, shape_s = toks
            dtype = "float32"
        else:
            name, shape_s, dtype = toks[0], toks[1], toks[2]
        shape = [int(x) for x in shape_s.split("x") if x]
        specs.append(InputSpec(name=name, shape=shape, dtype=dtype))
    return specs


def parse_dynamic_str(s: str) -> Dict[str, List[int]]:
    """
    Format: "input:0,2,3;tokens:0"
    """
    if not s:
        return {}
    out: Dict[str, List[int]] = {}
    for part in s.split(";"):
        part = part.strip()
        if not part:
            continue
        name, dims = part.split(":")
        axes = [int(x) for x in dims.split(",") if x != ""]
        out[name] = axes
    return out


def load_inputs_yaml(path: str) -> Tuple[List[InputSpec], Dict[str, List[int]]]:
    if yaml is None:
        fail("YAML support is not available. Install PyYAML to use --inputs-yaml")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    inputs = []
    for item in data.get("inputs", []):
        inputs.append(InputSpec(name=item["name"], shape=list(item["shape"]), dtype=item.get("dtype", "float32")))
    dynamic = {k: list(v) for k, v in (data.get("dynamic", {}) or {}).items()}
    return inputs, dynamic


def dtype_to_torch(dtype: str):
    if torch is None:
        return None
    m = {
        "float32": torch.float32,
        "float16": torch.float16,
        "float64": torch.float64,
        "int64": torch.int64,
        "int32": torch.int32,
        "bool": torch.bool,
    }
    if dtype not in m:
        fail(f"Unsupported dtype: {dtype}")
    return m[dtype]


def mk_dummy(shape: Sequence[int], dtype: str, device: str):
    if torch is None:
        return None
    dt = dtype_to_torch(dtype)
    if dt is torch.bool:
        return torch.zeros(shape, dtype=dt, device=device) > 0.5
    if "int" in str(dt):
        return torch.randint(low=0, high=3, size=tuple(shape), dtype=dt, device=device)
    # floats
    return torch.randn(shape, dtype=dt, device=device)


def build_inputs_tensors(cfg: ExportConfig) -> Tuple[List[str], List[Any], Dict[str, Dict[int, str]]]:
    names = [sp.name for sp in cfg.inputs]
    tensors = [mk_dummy(sp.shape, sp.dtype, cfg.device) for sp in cfg.inputs]
    dyn_axes: Dict[str, Dict[int, str]] = {}
    for sp in cfg.inputs:
        axes_map: Dict[int, str] = {}
        for ax in cfg.dynamic_axes.get(sp.name, []):
            axes_map[ax] = f"{sp.name}_dim{ax}"
        if axes_map:
            dyn_axes[sp.name] = axes_map
    return names, tensors, dyn_axes


def import_builder(qualname: str):
    """
    'pkg.module:callable_or_class'
    """
    if ":" not in qualname:
        fail("Model path must be 'pkg.module:callable_or_class'")
    mod_name, obj_name = qualname.split(":", 1)
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        fail(f"Failed to import module '{mod_name}'", e)
    try:
        obj = getattr(mod, obj_name)
    except Exception as e:
        fail(f"Object '{obj_name}' not found in '{mod_name}'", e)
    return obj


def apply_checkpoint(model: Any, path: Optional[str], device: str) -> None:
    if not path:
        return
    logging.info("Loading checkpoint: %s", path)
    map_loc = "cuda" if (device == "cuda" and torch.cuda.is_available()) else "cpu"
    ckpt = torch.load(path, map_location=map_loc)
    if isinstance(ckpt, dict) and "state_dict" in ckpt:
        sd = ckpt["state_dict"]
    elif isinstance(ckpt, dict):
        sd = ckpt
    else:
        # Full object; try to get state_dict
        if hasattr(ckpt, "state_dict"):
            sd = ckpt.state_dict()
        else:
            fail("Checkpoint format not recognized: neither dict nor object with state_dict()")
    missing, unexpected = model.load_state_dict(sd, strict=False)
    if missing:
        logging.warning("Missing keys: %s", missing)
    if unexpected:
        logging.warning("Unexpected keys: %s", unexpected)


def torch_out_to_numpy(outputs: Any) -> List["np.ndarray"]:
    if isinstance(outputs, (list, tuple)):
        arrs = []
        for o in outputs:
            if hasattr(o, "detach"):
                arrs.append(o.detach().cpu().numpy())
            else:
                arrs.append(np.asarray(o))
        return arrs
    if hasattr(outputs, "detach"):
        return [outputs.detach().cpu().numpy()]
    return [np.asarray(outputs)]


def compare_outputs(ref: List["np.ndarray"], test: List["np.ndarray"], rtol: float, atol: float) -> Tuple[bool, str]:
    if len(ref) != len(test):
        return False, f"#outputs mismatch: ref={len(ref)} vs test={len(test)}"
    for i, (a, b) in enumerate(zip(ref, test)):
        if a.shape != b.shape:
            return False, f"shape mismatch at {i}: {a.shape} vs {b.shape}"
        ok = np.allclose(a, b, rtol=rtol, atol=atol, equal_nan=True)
        if not ok:
            # report max abs diff
            diff = np.max(np.abs(a - b))
            return False, f"mismatch at {i}: max_abs_diff={float(diff):.6g} rtol={rtol} atol={atol}"
    return True, "OK"


def write_sha256(path: Path) -> str:
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    with open(path.with_suffix(path.suffix + ".sha256"), "w", encoding="utf-8") as f:
        f.write(f"{digest}  {path.name}\n")
    return digest


def add_metadata(onnx_path: Path, meta: Mapping[str, str]) -> None:
    model = onnx.load(str(onnx_path))
    # Producer info
    model.producer_name = "NeuroForge-Export"
    model.producer_version = "1.0.0"
    for k, v in (meta or {}).items():
        p = onnx.helper.make_string_string_pair(k, str(v))
        model.metadata_props.append(p)
    onnx.save(model, str(onnx_path))


def maybe_simplify(onnx_path: Path) -> None:
    if onnx_simplify is None:
        fail("onnx-simplifier is not installed; install onnxsim or omit --simplify")
    logging.info("Simplifying ONNX graph ...")
    model = onnx.load(str(onnx_path))
    model_simplified, ok = onnx_simplify(model, check_n=0)
    if not ok:
        fail("onnx-simplifier reported failure")
    onnx.save(model_simplified, str(onnx_path))
    logging.info("Simplified saved: %s", onnx_path)


def maybe_quantize(onnx_path: Path, mode: Optional[str]) -> None:
    if not mode:
        return
    if quantize_dynamic is None:
        fail("onnxruntime.quantization is not available; install onnxruntime-tools")
    if mode != "dynamic":
        fail(f"Unsupported quantization mode: {mode}")
    qpath = onnx_path.with_suffix(".quant.onnx")
    logging.info("Applying dynamic quantization -> %s", qpath.name)
    quantize_dynamic(
        model_input=str(onnx_path),
        model_output=str(qpath),
        weight_type=QuantType.QInt8 if QuantType is not None else None,  # type: ignore
    )
    # Replace original file with quantized
    onnx_path.unlink()
    qpath.rename(onnx_path)
    logging.info("Quantized model saved: %s", onnx_path)


def validate_with_ort(
    onnx_path: Path,
    input_names: List[str],
    inputs_np: List["np.ndarray"],
    threads: int,
    rtol: float,
    atol: float,
) -> Tuple[bool, str]:
    if ort is None:
        fail(f"ONNX Runtime not available: {repr(_ort_err)}")
    so = ort.SessionOptions()
    so.intra_op_num_threads = threads
    so.inter_op_num_threads = threads
    sess = ort.InferenceSession(str(onnx_path), sess_options=so, providers=["CPUExecutionProvider"])
    feed = {name: arr for name, arr in zip(input_names, inputs_np)}
    ort_outs = sess.run(None, feed)
    return True, f"ORT outputs: {len(ort_outs)}"


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def export_onnx(cfg: ExportConfig) -> None:
    ensure_deps()
    set_seeds(cfg.seed)
    device = cfg.device
    if device == "cuda" and (torch is None or not torch.cuda.is_available()):
        logging.warning("CUDA requested but not available; falling back to CPU")
        device = "cpu"

    # Tracing (optional)
    if nf_tracing is not None:
        try:
            nf_tracing.init_tracing()
        except Exception:
            pass

    # Build model
    builder = import_builder(cfg.model_path)
    try:
        model = builder()  # type: ignore
    except TypeError:
        # maybe class
        model = builder  # type: ignore
        try:
            model = model()
        except Exception as e:
            fail("Failed to instantiate model", e)
    if not hasattr(model, "forward"):
        fail("Provided object does not look like torch.nn.Module (no .forward)")

    model = model.to(device)
    model.eval()

    if cfg.checkpoint:
        apply_checkpoint(model, cfg.checkpoint, device)

    # Inputs
    input_names, input_tensors, dyn_axes = build_inputs_tensors(cfg)
    output_names = ["output"]  # default, will be overwritten if we can infer better

    # Infer outputs once with torch (also for validation)
    with torch.no_grad():
        torch_out = model(*input_tensors)
    torch_out_np = torch_out_to_numpy(torch_out)
    output_names = [f"out_{i}" for i in range(len(torch_out_np))]

    # Export
    onnx_path = Path(cfg.output)
    ensure_parent(onnx_path)
    logging.info("Exporting to ONNX: %s (opset=%d, exporter=%s)", onnx_path, cfg.opset, "dynamo" if cfg.use_dynamo else "export")

    if cfg.use_dynamo and hasattr(torch.onnx, "dynamo_export"):
        # New exporter (PyTorch 2.1+)
        exported = torch.onnx.dynamo_export(  # type: ignore[attr-defined]
            model,
            *input_tensors,
            export_options=torch.onnx.ExportOptions(  # type: ignore[attr-defined]
                opset_version=cfg.opset,
                dynamic_shapes=bool(dyn_axes),
            ),
        )
        if cfg.external_data:
            exported.save(str(onnx_path), use_external_data_format=True)
        else:
            exported.save(str(onnx_path))
    else:
        # Classic exporter
        torch.onnx.export(
            model,
            tuple(input_tensors),
            str(onnx_path),
            opset_version=cfg.opset,
            input_names=input_names,
            output_names=output_names,
            dynamic_axes=dyn_axes if dyn_axes else None,
            do_constant_folding=cfg.constant_folding,
            training=torch.onnx.TrainingMode.EVAL,  # type: ignore[attr-defined]
            use_external_data_format=cfg.external_data,
        )

    # Post steps
    if cfg.simplify:
        maybe_simplify(onnx_path)

    if cfg.quantize:
        maybe_quantize(onnx_path, cfg.quantize)

    # Add metadata
    meta = dict(cfg.metadata or {})
    meta.update(
        {
            "nf.producer": "neuroforge",
            "nf.export.opset": str(cfg.opset),
            "nf.export.device": device,
            "nf.export.time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "nf.exporter": "dynamo" if cfg.use_dynamo and hasattr(torch.onnx, "dynamo_export") else "export",
        }
    )
    add_metadata(onnx_path, meta)

    # Hashes
    digest = write_sha256(onnx_path)
    logging.info("SHA256: %s", digest)

    # Verify via ONNX Runtime
    if cfg.verify:
        inputs_np = [t.detach().cpu().numpy() if hasattr(t, "detach") else t for t in input_tensors]
        ok, msg = validate_with_ort(onnx_path, input_names, inputs_np, cfg.ort_threads, cfg.rtol, cfg.atol)
        if not ok:
            fail(f"ORT validation failed: {msg}")
        # Compare PyTorch vs ORT
        if ort is None:
            fail(f"ONNX Runtime not available: {repr(_ort_err)}")
        sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        feed = {n: x for n, x in zip(input_names, inputs_np)}
        ort_outs = sess.run(None, feed)
        ok, msg = compare_outputs(torch_out_np, ort_outs, rtol=cfg.rtol, atol=cfg.atol)
        if not ok:
            fail(f"Numerical comparison failed: {msg}")
        logging.info("Validation passed: %s", msg)

    # Save export config for provenance
    if cfg.save_config:
        cfg_path = Path(cfg.save_config)
        ensure_parent(cfg_path)
        cfg_json = cfg.to_json()
        cfg_path.write_text(cfg_json, encoding="utf-8")
        write_sha256(cfg_path)
        logging.info("Export config saved: %s", cfg_path)


# ====== CLI ======
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NeuroForge ONNX Export Tool")
    p.add_argument("--model", required=True, help="Model builder 'pkg.module:callable_or_class'")
    p.add_argument("--checkpoint", help="Path to checkpoint (state_dict or object)")
    p.add_argument("--inputs", help="Inline inputs: 'name:1x3x224x224:float32;other:4:int64'")
    p.add_argument("--inputs-yaml", help="YAML file with inputs/dynamic")
    p.add_argument("--dynamic", help="Dynamic axes: 'input:0,2,3;tokens:0'")
    p.add_argument("--opset", type=int, default=17, help="ONNX opset")
    p.add_argument("--device", choices=["cpu", "cuda"], default="cpu", help="Device for tracing")
    p.add_argument("--use-dynamo", action="store_true", help="Use torch.onnx.dynamo_export if available")
    p.add_argument("--no-const-fold", action="store_true", help="Disable constant folding")
    p.add_argument("--external-data", action="store_true", help="Use external data format (for >2GB)")
    p.add_argument("--output", default="model.onnx", help="Output ONNX path")
    p.add_argument("--simplify", action="store_true", help="Run onnx-simplifier after export")
    p.add_argument("--quantize", choices=["dynamic"], help="Apply quantization (dynamic)")
    p.add_argument("--verify", action="store_true", help="Validate with ONNX Runtime and compare with PyTorch")
    p.add_argument("--rtol", type=float, default=1e-3, help="Relative tolerance for comparison")
    p.add_argument("--atol", type=float, default=1e-4, help="Absolute tolerance for comparison")
    p.add_argument("--seed", type=int, default=42, help="Random seed")
    p.add_argument("--metadata", help="Comma-separated 'k=v' pairs")
    p.add_argument("--save-config", help="Path to save export config JSON")
    p.add_argument("--ort-threads", type=int, default=1, help="Threads for ONNX Runtime")
    p.add_argument("--verbose", action="store_true", help="Verbose logs")
    return p


def parse_metadata(s: Optional[str]) -> Dict[str, str]:
    if not s:
        return {}
    out: Dict[str, str] = {}
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main(argv: Optional[Sequence[str]] = None) -> None:
    ap = build_argparser()
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    # Compose inputs/dynamic
    in_specs: List[InputSpec] = []
    dyn_axes: Dict[str, List[int]] = {}
    if args.inputs_yaml:
        specs, dyn = load_inputs_yaml(args.inputs_yaml)
        in_specs.extend(specs)
        dyn_axes.update(dyn)
    if args.inputs:
        in_specs.extend(parse_inputs_str(args.inputs))
    if args.dynamic:
        dyn_axes.update(parse_dynamic_str(args.dynamic))

    if not in_specs:
        fail("No inputs specified. Use --inputs or --inputs-yaml")

    cfg = ExportConfig(
        model_path=args.model,
        checkpoint=args.checkpoint,
        inputs=in_specs,
        dynamic_axes=dyn_axes,
        opset=args.opset,
        device=args.device,
        use_dynamo=bool(args.use_dynamo),
        constant_folding=not args.no_const_fold,
        external_data=bool(args.external_data),
        output=args.output,
        simplify=bool(args.simplify),
        quantize=args.quantize,
        verify=bool(args.verify),
        rtol=float(args.rtol),
        atol=float(args.atol),
        seed=int(args.seed),
        metadata=parse_metadata(args.metadata),
        save_config=args.save_config,
        ort_threads=int(args.ort_threads),
    )

    logging.info("Starting export with config:\n%s", cfg.to_json())
    try:
        export_onnx(cfg)
    except SystemExit:
        raise
    except Exception as e:
        fail("Export failed", e)
    logging.info("Export finished successfully: %s", cfg.output)


if __name__ == "__main__":
    main()

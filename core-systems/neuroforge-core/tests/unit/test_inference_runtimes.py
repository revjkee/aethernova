# neuroforge-core/tests/unit/test_inference_runtimes.py
# -*- coding: utf-8 -*-
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List

import pytest


# ---------- Helpers: project import bootstrap ----------
def _add_project_root():
    # tests/unit/test_inference_runtimes.py -> tests/unit/ -> tests/ -> neuroforge-core/
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


_add_project_root()
import cli.tools.run_infer as ri  # noqa: E402


# ---------- Dummy modules for HF (torch + transformers) ----------
class _DummyInfMode:
    def __enter__(self):  # noqa: D401
        return None

    def __exit__(self, exc_type, exc, tb):  # noqa: D401
        return False


class _DummyCuda:
    @staticmethod
    def manual_seed_all(seed: int):
        return None

    @staticmethod
    def is_available() -> bool:
        return False


class _DummyTorch(ModuleType):
    float32 = object()
    float16 = object()
    bfloat16 = object()
    cuda = _DummyCuda()

    @staticmethod
    def manual_seed(seed: int):
        return None

    @staticmethod
    def use_deterministic_algorithms(flag: bool):
        return None

    @staticmethod
    def inference_mode():
        return _DummyInfMode()

    @staticmethod
    def compile(model):
        # emulate torch.compile passthrough
        return model


class _DummyTokenizer:
    eos_token_id = 0

    @classmethod
    def from_pretrained(cls, *a, **k):
        return cls()

    def __call__(self, prompts: List[str], return_tensors="pt", padding=True, truncation=True):
        # emulate tokenization: return any structure compatible with runner
        return {"input_ids": [[1, 2]] * len(prompts)}

    def batch_decode(self, out, skip_special_tokens=True):
        # produce deterministic text per item
        return [f"text-{i}" for i, _ in enumerate(out)]


class _DummyHFModel:
    def __init__(self):
        self._device = "cpu"

    @classmethod
    def from_pretrained(cls, *a, **k):
        return cls()

    def to(self, device: str):
        self._device = device
        return self

    def eval(self):
        return None

    def generate(self, **kwargs):
        # emulate generation: return list with length = batch size
        # use input length from tokenized inputs to determine batch size
        input_ids = kwargs.get("input_ids") or [[]]
        bsz = len(input_ids)
        return [f"tok-{i}" for i in range(bsz)]


class _DummyTransformers(ModuleType):
    AutoModelForCausalLM = _DummyHFModel
    AutoTokenizer = _DummyTokenizer


# ---------- Dummy module for ONNX runtime ----------
class _DummyIo:
    def __init__(self, name: str, shape, type_str: str):
        self.name = name
        self.shape = shape
        self.type = type_str


class _DummyOrtSession:
    def __init__(self, model_path: str, sess_options=None, providers=None):
        self.model_path = model_path
        self._inputs = [_DummyIo("x", [None, 3], "tensor(float)")]
        self._outputs = [_DummyIo("y", [None, 2], "tensor(float)")]
        self._providers = providers or ["CPUExecutionProvider"]

    def get_inputs(self):
        return self._inputs

    def get_outputs(self):
        return self._outputs

    def get_providers(self):
        return self._providers

    def run(self, output_names, feeds: Dict[str, Any]):
        import numpy as np

        x = feeds["x"]  # shape (N, 3)
        # produce (N,2) by echoing first two features
        y = x[:, :2].astype(np.float32)
        return [y]


class _DummyOrt(ModuleType):
    class SessionOptions:
        def __init__(self):
            self.intra_op_num_threads = 0
            self.inter_op_num_threads = 0

    InferenceSession = _DummyOrtSession


# ---------- Fixtures ----------
@pytest.fixture
def patch_hf(monkeypatch):
    dummy_torch = _DummyTorch("torch")
    dummy_tr = _DummyTransformers("transformers")
    monkeypatch.setitem(sys.modules, "torch", dummy_torch)
    monkeypatch.setitem(sys.modules, "transformers", dummy_tr)
    yield


@pytest.fixture
def patch_onnx(monkeypatch):
    dummy_ort = _DummyOrt("onnxruntime")
    monkeypatch.setitem(sys.modules, "onnxruntime", dummy_ort)
    yield


# ---------- Tests: HFTextGenRunner ----------
def test_hf_load_and_infer_basic(patch_hf):
    runner = ri.HFTextGenRunner(
        model_id="dummy/model",
        device="cpu",
        dtype="float32",
        max_new_tokens=8,
        temperature=0.1,
        top_p=0.9,
        do_sample=False,
    )
    runner.load()
    runner.warmup(batch_size=2)
    out = runner.infer_batch(
        [{"id": "a", "prompt": "hello"}, {"id": "b", "prompt": "world"}]
    )
    assert isinstance(out, list)
    assert len(out) == 2
    assert out[0].startswith("text-") and out[1].startswith("text-")


def test_hf_infer_raises_on_missing_prompt(patch_hf):
    runner = ri.HFTextGenRunner(model_id="dummy/model")
    runner.load()
    with pytest.raises(ValueError):
        runner.infer_batch([{"id": "a"}])


# ---------- Tests: OnnxRunner ----------
def test_onnx_load_and_infer_basic(patch_onnx):
    import numpy as np

    runner = ri.OnnxRunner(model_path="model.onnx", providers=["CPUExecutionProvider"])
    runner.load()
    runner.warmup(batch_size=3)

    # two rows, each with single-input API
    row1 = {"id": "r1", "input": np.array([[1.0, 2.0, 3.0]], dtype=np.float32)}
    row2 = {"id": "r2", "input": np.array([[4.0, 5.0, 6.0]], dtype=np.float32)}
    out = runner.infer_batch([row1, row2])

    assert isinstance(out, list) and len(out) == 2
    assert "y" in out[0] and "y" in out[1]
    assert out[0]["y"] == [1.0, 2.0]
    assert out[1]["y"] == [4.0, 5.0]


def test_onnx_infer_with_inputs_dict(patch_onnx):
    import numpy as np

    runner = ri.OnnxRunner(model_path="model.onnx")
    runner.load()
    batch = [
        {"id": "1", "inputs": {"x": np.array([[7.0, 8.0, 9.0]], dtype=np.float32)}},
    ]
    out = runner.infer_batch(batch)
    assert out[0]["y"] == [7.0, 8.0]


# ---------- Tests: Orchestration (run_infer) ----------
class _FakeRunner(ri.BaseRunner):
    name = "fake"

    def __init__(self):
        self.loaded = False

    def load(self) -> None:
        self.loaded = True

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Any]:
        # return id-tagged echo
        return [f"ok-{row.get('id')}" for row in batch]


class _ErrorRunner(ri.BaseRunner):
    name = "fake_err"

    def load(self) -> None:
        return None

    def infer_batch(self, batch: List[Dict[str, Any]]) -> List[Any]:
        raise RuntimeError("boom")


def test_run_infer_writes_jsonl_and_reports(monkeypatch, tmp_path):
    # register fake runner in registry
    runners = dict(ri.RUNNERS)
    runners[_FakeRunner.name] = ri.RunnerSpec(_FakeRunner.name, _FakeRunner)
    monkeypatch.setattr(ri, "RUNNERS", runners, raising=True)

    # create input JSONL
    inp = tmp_path / "in.jsonl"
    outp = tmp_path / "out.jsonl"
    rows = [{"id": str(i), "prompt": f"p{i}"} for i in range(5)]
    inp.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")

    # run
    m = ri.run_infer(
        runner=_FakeRunner(),
        input_path=str(inp),
        output_path=str(outp),
        batch_size=2,
        warmup_batches=0,
        max_batches=None,
    )
    assert m.total_rows == 5
    assert m.total_time_ms >= 0

    # check JSONL output
    out_lines = outp.read_text(encoding="utf-8").strip().splitlines()
    assert len(out_lines) == 5
    parsed = [json.loads(x) for x in out_lines]
    assert parsed[0]["id"] == "0"
    assert parsed[0]["result"] == "ok-0"
    assert "latency_ms" in parsed[0]["meta"]


def test_run_infer_handles_batch_exception(monkeypatch, tmp_path):
    # when runner fails, outputs should contain error for each row in batch
    inp = tmp_path / "in.jsonl"
    outp = tmp_path / "out.jsonl"
    rows = [{"id": "x", "prompt": "q"}, {"id": "y", "prompt": "w"}]
    inp.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")

    m = ri.run_infer(
        runner=_ErrorRunner(),
        input_path=str(inp),
        output_path=str(outp),
        batch_size=2,
        warmup_batches=0,
        max_batches=1,
    )
    assert m.total_rows == 2

    out_lines = outp.read_text(encoding="utf-8").strip().splitlines()
    parsed = [json.loads(x) for x in out_lines]
    assert "error" in parsed[0]["result"] or "error" in parsed[0] or "error" in parsed[0].get("result", {})


def test_seed_function_is_safe():
    # should not raise even without real torch/numpy present
    ri._set_seed(123)

# path: agent_mash/tests/e2e/scenarios/test_multi_agent_interaction.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import random
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest


"""
Industrial E2E scenario for multi-agent interaction.

Design goals:
- Deterministic: fixed seed, stable scheduling points.
- Observable: structured trace, event log, artifacts directory.
- Safe: bounded timeouts, hard deadlines, cancellation cleanup.
- Honest integration: can run with an embedded test harness OR plug into a real orchestrator.

Integration mode:
- Default uses embedded harness (no project dependencies required).
- To plug a real orchestrator, set:
  - AGENT_MASH_E2E_MODE=real
  - AGENT_MASH_E2E_ORCHESTRATOR_IMPORT="some.module:factory_function"
Where factory_function returns an object with async methods:
  - start() -> None
  - stop() -> None
  - submit(task: dict) -> dict  (or async generator - see adapter below)
If this cannot be imported, test is skipped (not failed).

Artifacts:
- AGENT_MASH_E2E_ARTIFACTS_DIR defaults to: agent_mash/tests/.artifacts/e2e
"""


# -----------------------------
# Config
# -----------------------------

DEFAULT_SEED = 13371337

ENV_MODE = "AGENT_MASH_E2E_MODE"
ENV_IMPORT = "AGENT_MASH_E2E_ORCHESTRATOR_IMPORT"
ENV_ARTIFACTS_DIR = "AGENT_MASH_E2E_ARTIFACTS_DIR"
ENV_TIMEOUT_S = "AGENT_MASH_E2E_TIMEOUT_S"
ENV_AGENTS_N = "AGENT_MASH_E2E_AGENTS_N"
ENV_RUNS = "AGENT_MASH_E2E_RUNS"

DEFAULT_TIMEOUT_S = 20.0
DEFAULT_AGENTS_N = 5
DEFAULT_RUNS = 2


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(env_name: str, default: int) -> int:
    v = os.getenv(env_name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except Exception:
        return default


def _safe_float(env_name: str, default: float) -> float:
    v = os.getenv(env_name)
    if v is None or v.strip() == "":
        return default
    try:
        return float(v)
    except Exception:
        return default


def _artifact_dir() -> Path:
    p = os.getenv(ENV_ARTIFACTS_DIR)
    if p and p.strip():
        return Path(p).resolve()
    # Default: agent_mash/tests/.artifacts/e2e (relative to repo root from this file)
    here = Path(__file__).resolve()
    # .../agent_mash/tests/e2e/scenarios/test_multi_agent_interaction.py
    tests_dir = here.parents[3]  # .../agent_mash/tests
    return (tests_dir / ".artifacts" / "e2e").resolve()


# -----------------------------
# Trace and invariants
# -----------------------------

@dataclasses.dataclass(frozen=True)
class Envelope:
    message_id: str
    correlation_id: str
    sender: str
    recipient: str
    type: str
    payload: Dict[str, Any]
    created_ms: int


@dataclasses.dataclass
class Event:
    ts_ms: int
    kind: str
    data: Dict[str, Any]


class TraceRecorder:
    def __init__(self, out_dir: Path, scenario_id: str) -> None:
        self._out_dir = out_dir
        self._scenario_id = scenario_id
        self._events: List[Event] = []
        self._lock = asyncio.Lock()

    @property
    def out_dir(self) -> Path:
        return self._out_dir

    @property
    def scenario_id(self) -> str:
        return self._scenario_id

    async def emit(self, kind: str, **data: Any) -> None:
        e = Event(ts_ms=_now_ms(), kind=kind, data=dict(data))
        async with self._lock:
            self._events.append(e)

    async def flush(self) -> None:
        self._out_dir.mkdir(parents=True, exist_ok=True)
        path = self._out_dir / f"trace_{self._scenario_id}.jsonl"
        async with self._lock:
            lines = []
            for e in self._events:
                lines.append(json.dumps({"ts_ms": e.ts_ms, "kind": e.kind, "data": e.data}, ensure_ascii=False))
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


class InvariantViolation(AssertionError):
    pass


class Invariants:
    def __init__(self) -> None:
        self.seen_message_ids: set[str] = set()
        self.seen_correlation_ids: set[str] = set()
        self.deliveries: Dict[str, int] = {}
        self.last_seen_by_agent: Dict[str, int] = {}

    def observe_created(self, env: Envelope) -> None:
        if not env.message_id:
            raise InvariantViolation("message_id is empty")
        if not env.correlation_id:
            raise InvariantViolation("correlation_id is empty")
        if env.message_id in self.seen_message_ids:
            raise InvariantViolation(f"duplicate message_id observed: {env.message_id}")
        self.seen_message_ids.add(env.message_id)
        self.seen_correlation_ids.add(env.correlation_id)

    def observe_delivery(self, env: Envelope) -> None:
        self.deliveries[env.message_id] = self.deliveries.get(env.message_id, 0) + 1
        if self.deliveries[env.message_id] > 1:
            raise InvariantViolation(f"message delivered more than once: {env.message_id}")

    def observe_agent_progress(self, agent_id: str, step: int) -> None:
        prev = self.last_seen_by_agent.get(agent_id, -1)
        if step < prev:
            raise InvariantViolation(f"agent progress went backwards: {agent_id} step={step} prev={prev}")
        self.last_seen_by_agent[agent_id] = step


# -----------------------------
# Embedded multi-agent harness
# -----------------------------

class MessageBus:
    def __init__(self, trace: TraceRecorder, inv: Invariants) -> None:
        self._trace = trace
        self._inv = inv
        self._queues: Dict[str, asyncio.Queue[Envelope]] = {}
        self._lock = asyncio.Lock()

    async def register(self, agent_id: str) -> asyncio.Queue[Envelope]:
        async with self._lock:
            if agent_id in self._queues:
                return self._queues[agent_id]
            q: asyncio.Queue[Envelope] = asyncio.Queue()
            self._queues[agent_id] = q
            await self._trace.emit("bus.register", agent_id=agent_id)
            return q

    async def send(self, env: Envelope) -> None:
        self._inv.observe_created(env)
        async with self._lock:
            q = self._queues.get(env.recipient)
            if q is None:
                raise InvariantViolation(f"recipient not registered: {env.recipient}")
            await self._trace.emit(
                "bus.send",
                message_id=env.message_id,
                correlation_id=env.correlation_id,
                sender=env.sender,
                recipient=env.recipient,
                type=env.type,
            )
            q.put_nowait(env)

    async def recv(self, agent_id: str, timeout_s: float) -> Envelope:
        async with self._lock:
            q = self._queues.get(agent_id)
            if q is None:
                raise InvariantViolation(f"agent not registered: {agent_id}")
        try:
            env = await asyncio.wait_for(q.get(), timeout=timeout_s)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout waiting for message at {agent_id}") from e
        self._inv.observe_delivery(env)
        await self._trace.emit(
            "bus.recv",
            message_id=env.message_id,
            correlation_id=env.correlation_id,
            sender=env.sender,
            recipient=env.recipient,
            type=env.type,
        )
        return env


class Agent:
    """
    Embedded agent protocol:
    - Receives "task" messages
    - Optionally queries peer agents ("subtask")
    - Returns "result" to coordinator

    This models multi-agent coordination, not AI correctness.
    """

    def __init__(
        self,
        agent_id: str,
        bus: MessageBus,
        trace: TraceRecorder,
        inv: Invariants,
        rng: random.Random,
        peers: List[str],
    ) -> None:
        self.agent_id = agent_id
        self._bus = bus
        self._trace = trace
        self._inv = inv
        self._rng = rng
        self._peers = peers
        self._task: Optional[asyncio.Task[None]] = None
        self._stop = asyncio.Event()
        self._step = 0

    async def start(self) -> None:
        await self._bus.register(self.agent_id)
        self._task = asyncio.create_task(self._run(), name=f"agent:{self.agent_id}")
        await self._trace.emit("agent.start", agent_id=self.agent_id)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(Exception):
                await self._task
        await self._trace.emit("agent.stop", agent_id=self.agent_id)

    async def _run(self) -> None:
        while not self._stop.is_set():
            # Small deterministic yield point
            await asyncio.sleep(0)
            try:
                env = await self._bus.recv(self.agent_id, timeout_s=0.25)
            except TimeoutError:
                continue

            self._step += 1
            self._inv.observe_agent_progress(self.agent_id, self._step)

            if env.type == "task":
                await self._handle_task(env)
            elif env.type == "subtask":
                await self._handle_subtask(env)
            else:
                await self._trace.emit("agent.unknown", agent_id=self.agent_id, type=env.type)

    async def _handle_task(self, env: Envelope) -> None:
        await self._trace.emit("agent.task.received", agent_id=self.agent_id, correlation_id=env.correlation_id)

        # Deterministic branching: sometimes ask a peer
        ask_peer = self._peers and (self._rng.randint(0, 2) == 0)
        peer_answer: Optional[Dict[str, Any]] = None

        if ask_peer:
            peer_id = self._rng.choice(self._peers)
            sub_id = str(uuid.uuid4())
            sub_env = Envelope(
                message_id=sub_id,
                correlation_id=env.correlation_id,
                sender=self.agent_id,
                recipient=peer_id,
                type="subtask",
                payload={"question": "ping", "from": self.agent_id},
                created_ms=_now_ms(),
            )
            await self._bus.send(sub_env)
            await self._trace.emit("agent.task.subtask.sent", agent_id=self.agent_id, peer=peer_id)

            # Wait for a response from that peer via coordinator routing (simplified below),
            # or just proceed if none arrives quickly.
            # In embedded harness, peer replies directly to sender as "subtask_result".
            try:
                reply = await self._bus.recv(self.agent_id, timeout_s=0.75)
                if reply.type == "subtask_result" and reply.correlation_id == env.correlation_id:
                    peer_answer = reply.payload
                    await self._trace.emit("agent.task.subtask.received", agent_id=self.agent_id, peer=reply.sender)
            except TimeoutError:
                await self._trace.emit("agent.task.subtask.timeout", agent_id=self.agent_id)

        # Produce result
        result_payload = {
            "agent": self.agent_id,
            "ok": True,
            "input": env.payload,
            "peer_answer": peer_answer,
        }

        res_env = Envelope(
            message_id=str(uuid.uuid4()),
            correlation_id=env.correlation_id,
            sender=self.agent_id,
            recipient=env.payload["reply_to"],
            type="result",
            payload=result_payload,
            created_ms=_now_ms(),
        )
        await self._bus.send(res_env)
        await self._trace.emit("agent.task.result.sent", agent_id=self.agent_id, correlation_id=env.correlation_id)

    async def _handle_subtask(self, env: Envelope) -> None:
        await self._trace.emit("agent.subtask.received", agent_id=self.agent_id, from_agent=env.sender)
        # Reply directly to sender with subtask_result
        res_env = Envelope(
            message_id=str(uuid.uuid4()),
            correlation_id=env.correlation_id,
            sender=self.agent_id,
            recipient=env.sender,
            type="subtask_result",
            payload={"agent": self.agent_id, "answer": "pong"},
            created_ms=_now_ms(),
        )
        await self._bus.send(res_env)
        await self._trace.emit("agent.subtask.result.sent", agent_id=self.agent_id, to_agent=env.sender)


# contextlib is used inside Agent.stop without polluting top-level imports earlier
import contextlib  # noqa: E402


class EmbeddedOrchestrator:
    """
    Coordinator sends tasks to agents and gathers results.
    """

    def __init__(self, trace: TraceRecorder, agents_n: int, seed: int) -> None:
        self._trace = trace
        self._inv = Invariants()
        self._bus = MessageBus(trace=trace, inv=self._inv)
        self._agents_n = agents_n
        self._seed = seed
        self._rng = random.Random(seed)
        self._agents: List[Agent] = []
        self._coordinator_id = "coordinator"
        self._started = False

    @property
    def inv(self) -> Invariants:
        return self._inv

    async def start(self) -> None:
        if self._started:
            return
        await self._bus.register(self._coordinator_id)
        agent_ids = [f"agent-{i+1}" for i in range(self._agents_n)]
        for aid in agent_ids:
            peers = [x for x in agent_ids if x != aid]
            a = Agent(
                agent_id=aid,
                bus=self._bus,
                trace=self._trace,
                inv=self._inv,
                rng=self._rng,
                peers=peers,
            )
            self._agents.append(a)

        for a in self._agents:
            await a.start()

        self._started = True
        await self._trace.emit("orch.start", agents=self._agents_n, seed=self._seed)

    async def stop(self) -> None:
        if not self._started:
            return
        await self._trace.emit("orch.stop.begin")
        for a in self._agents:
            with contextlib.suppress(Exception):
                await a.stop()
        self._started = False
        await self._trace.emit("orch.stop.end")

    async def submit(self, task: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
        """
        Sends a task to all agents and waits for all results.
        Returns summary with per-agent results and invariant stats.
        """
        if not self._started:
            raise RuntimeError("orchestrator not started")

        correlation_id = str(uuid.uuid4())
        await self._trace.emit("orch.submit", correlation_id=correlation_id, task=task)

        # Send tasks
        for a in self._agents:
            env = Envelope(
                message_id=str(uuid.uuid4()),
                correlation_id=correlation_id,
                sender=self._coordinator_id,
                recipient=a.agent_id,
                type="task",
                payload={"task": task, "reply_to": self._coordinator_id},
                created_ms=_now_ms(),
            )
            await self._bus.send(env)

        # Collect results
        deadline = time.monotonic() + timeout_s
        results: Dict[str, Any] = {}
        while len(results) < len(self._agents):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"deadline exceeded collecting results, got={len(results)}/{len(self._agents)}")
            env = await self._bus.recv(self._coordinator_id, timeout_s=min(0.5, remaining))
            if env.type != "result":
                await self._trace.emit("orch.unexpected", type=env.type, sender=env.sender)
                continue
            if env.correlation_id != correlation_id:
                await self._trace.emit("orch.correlation.mismatch", got=env.correlation_id, expected=correlation_id)
                continue
            results[env.sender] = env.payload

        await self._trace.emit("orch.submit.done", correlation_id=correlation_id, results=len(results))

        summary = {
            "correlation_id": correlation_id,
            "results": results,
            "stats": {
                "messages_total": len(self._inv.seen_message_ids),
                "correlations_total": len(self._inv.seen_correlation_ids),
            },
        }
        return summary


# -----------------------------
# Real orchestrator integration
# -----------------------------

def _import_factory(spec: str):
    """
    spec: "module.submodule:factory"
    """
    if ":" not in spec:
        raise ValueError("import spec must be module:attr")
    mod_name, attr = spec.split(":", 1)
    mod = __import__(mod_name, fromlist=[attr])
    return getattr(mod, attr)


class RealOrchestratorAdapter:
    def __init__(self, impl: Any, trace: TraceRecorder) -> None:
        self._impl = impl
        self._trace = trace

    async def start(self) -> None:
        await self._trace.emit("real.start")
        m = getattr(self._impl, "start", None)
        if asyncio.iscoroutinefunction(m):
            await m()
        elif callable(m):
            m()

    async def stop(self) -> None:
        await self._trace.emit("real.stop")
        m = getattr(self._impl, "stop", None)
        if asyncio.iscoroutinefunction(m):
            await m()
        elif callable(m):
            m()

    async def submit(self, task: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
        await self._trace.emit("real.submit", task=task, timeout_s=timeout_s)
        m = getattr(self._impl, "submit", None)
        if m is None:
            raise AttributeError("real orchestrator has no submit(task, timeout_s)")

        if asyncio.iscoroutinefunction(m):
            return await asyncio.wait_for(m(task), timeout=timeout_s)
        # If sync
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(loop.run_in_executor(None, lambda: m(task)), timeout=timeout_s)


async def _make_orchestrator(trace: TraceRecorder, agents_n: int, seed: int) -> Tuple[Any, Optional[Invariants]]:
    mode = (os.getenv(ENV_MODE) or "embedded").strip().lower()

    if mode == "real":
        spec = (os.getenv(ENV_IMPORT) or "").strip()
        if not spec:
            pytest.skip(f"{ENV_MODE}=real but {ENV_IMPORT} is not set")
        try:
            factory = _import_factory(spec)
        except Exception as e:
            pytest.skip(f"cannot import real orchestrator factory {spec}: {e!r}")
        try:
            impl = factory()
        except Exception as e:
            pytest.skip(f"cannot construct real orchestrator via {spec}: {e!r}")
        return RealOrchestratorAdapter(impl=impl, trace=trace), None

    # embedded
    return EmbeddedOrchestrator(trace=trace, agents_n=agents_n, seed=seed), None


# -----------------------------
# Pytest fixtures
# -----------------------------

@pytest.fixture(scope="session")
def e2e_seed() -> int:
    return DEFAULT_SEED


@pytest.fixture()
def scenario_id() -> str:
    return uuid.uuid4().hex


@pytest.fixture()
def artifacts_dir() -> Path:
    d = _artifact_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture()
def timeout_s() -> float:
    return _safe_float(ENV_TIMEOUT_S, DEFAULT_TIMEOUT_S)


@pytest.fixture()
def agents_n() -> int:
    return max(2, _safe_int(ENV_AGENTS_N, DEFAULT_AGENTS_N))


@pytest.fixture()
def runs() -> int:
    return max(1, _safe_int(ENV_RUNS, DEFAULT_RUNS))


@pytest.fixture()
def trace(artifacts_dir: Path, scenario_id: str) -> TraceRecorder:
    return TraceRecorder(out_dir=artifacts_dir, scenario_id=scenario_id)


# -----------------------------
# The E2E test
# -----------------------------

@pytest.mark.asyncio
async def test_multi_agent_interaction_e2e(trace: TraceRecorder, e2e_seed: int, agents_n: int, runs: int, timeout_s: float) -> None:
    """
    E2E guarantees:
    - Multi-agent fan-out task dispatch.
    - All agents produce results within deadline.
    - No duplicate deliveries (exactly-once in embedded harness).
    - Trace artifacts are persisted for postmortem.
    """
    await trace.emit(
        "scenario.start",
        seed=e2e_seed,
        agents_n=agents_n,
        runs=runs,
        timeout_s=timeout_s,
        mode=(os.getenv(ENV_MODE) or "embedded"),
    )

    orch, _ = await _make_orchestrator(trace=trace, agents_n=agents_n, seed=e2e_seed)

    started = False
    try:
        await asyncio.wait_for(orch.start(), timeout=timeout_s)
        started = True

        # Run multiple rounds to catch race conditions
        for i in range(runs):
            task = {
                "round": i,
                "kind": "coordination_probe",
                "payload": {
                    "ping": "hello",
                    "nonce": uuid.uuid4().hex,
                },
            }
            t0 = time.monotonic()
            summary = await orch.submit(task=task, timeout_s=timeout_s)
            dt = time.monotonic() - t0

            # Validate summary structure (project-agnostic)
            if not isinstance(summary, dict):
                raise AssertionError(f"submit returned non-dict: {type(summary)}")

            results = summary.get("results")
            if not isinstance(results, dict):
                raise AssertionError("summary.results must be a dict")

            # For embedded harness, must receive exactly agents_n results.
            # For real harness, we accept any non-empty results but do not invent invariants we cannot verify.
            mode = (os.getenv(ENV_MODE) or "embedded").strip().lower()
            if mode != "real":
                if len(results) != agents_n:
                    raise AssertionError(f"expected {agents_n} agent results, got {len(results)}")
            else:
                if len(results) < 1:
                    raise AssertionError("expected at least one result in real mode")

            # Basic per-agent payload checks (non-AI correctness)
            for agent_id, payload in results.items():
                if not isinstance(agent_id, str) or not agent_id:
                    raise AssertionError("agent_id must be a non-empty string")
                if not isinstance(payload, dict):
                    raise AssertionError(f"payload for {agent_id} must be dict")
                # If the implementation exposes ok flag, ensure it is True
                if "ok" in payload and payload["ok"] is not True:
                    raise AssertionError(f"agent {agent_id} returned ok={payload['ok']}")

            await trace.emit(
                "scenario.round.ok",
                round=i,
                duration_s=dt,
                results=len(results),
            )

    except Exception as e:
        await trace.emit("scenario.error", error=repr(e))
        raise
    finally:
        with contextlib.suppress(Exception):
            if started:
                await asyncio.wait_for(orch.stop(), timeout=timeout_s)
        with contextlib.suppress(Exception):
            await trace.emit("scenario.end")
            await trace.flush()

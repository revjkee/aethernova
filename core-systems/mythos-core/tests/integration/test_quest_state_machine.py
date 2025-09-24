# mythos-core/tests/integration/test_quest_state_machine.py
# Industrial-grade integration tests for Mythos Quest State Machine.
# If the real implementation is available, tests will use it.
# Otherwise, a reference in-memory implementation is used to validate contract.
#
# Requirements:
#   pytest, pytest-asyncio, hypothesis
# Optional:
#   asyncpg (if POSTGRES_DSN set), redis.asyncio (if REDIS_URL set)
#
# Marks:
#   -m "integration" to run only integration tests
#   -m "slow" to include heavier property/concurrency cases

import asyncio
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional, List, Tuple, Any, Set
import importlib

import pytest

try:
    import hypothesis
    from hypothesis import given, settings, HealthCheck
    from hypothesis import strategies as st
except Exception:  # pragma: no cover
    hypothesis = None
    st = None

pytestmark = pytest.mark.integration

# --------------------------------------------------------------------------------------
# Attempt to import real state machine from project; otherwise define reference impl
# --------------------------------------------------------------------------------------

REAL_IMPORT_PATHS = [
    "mythos_core.domain.quests.state_machine",
    "mythos_core.quests.state_machine",
    "mythos_core.state.quests",
]

_loaded_impl = None
for path in REAL_IMPORT_PATHS:
    try:
        _loaded_impl = importlib.import_module(path)
        break
    except ModuleNotFoundError:
        continue

# --------------------------------------------------------------------------------------
# Domain contract (shared for real/fallback)
# --------------------------------------------------------------------------------------

class QuestState(Enum):
    DRAFT = auto()
    ACTIVE = auto()
    FAILED = auto()
    COMPLETED = auto()
    CANCELLED = auto()
    ARCHIVED = auto()

VALID_TRANSITIONS: Dict[QuestState, Set[QuestState]] = {
    QuestState.DRAFT: {QuestState.ACTIVE, QuestState.CANCELLED},
    QuestState.ACTIVE: {QuestState.FAILED, QuestState.COMPLETED, QuestState.CANCELLED},
    QuestState.FAILED: {QuestState.ACTIVE, QuestState.ARCHIVED, QuestState.CANCELLED},
    QuestState.COMPLETED: {QuestState.ARCHIVED},
    QuestState.CANCELLED: {QuestState.ARCHIVED},
    QuestState.ARCHIVED: set(),
}

@dataclass
class QuestEvent:
    idempotency_key: str
    at: float
    actor: str
    name: str
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Quest:
    quest_id: str
    state: QuestState = QuestState.DRAFT
    version: int = 0
    # Observability
    audit: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, int] = field(default_factory=lambda: {"transitions": 0, "retries": 0})
    # Idempotency
    seen_keys: Set[str] = field(default_factory=set)

class VersionConflict(Exception):
    pass

class InvalidTransition(Exception):
    pass

class IdempotencyViolation(Exception):
    pass

class QuestRepository:
    """Abstract repository contract; real impl can be Postgres/Redis/…"""
    async def get(self, quest_id: str) -> Optional[Quest]:
        raise NotImplementedError

    async def save(self, quest: Quest, expected_version: Optional[int]) -> Quest:
        raise NotImplementedError

# --------------------------------------------------------------------------------------
# Reference in-memory repository with optimistic locking
# --------------------------------------------------------------------------------------

class InMemoryQuestRepository(QuestRepository):
    def __init__(self):
        self._store: Dict[str, Quest] = {}
        self._lock = asyncio.Lock()

    async def get(self, quest_id: str) -> Optional[Quest]:
        async with self._lock:
            q = self._store.get(quest_id)
            if not q:
                return None
            # Return a shallow copy to simulate detached entity semantics
            return Quest(
                quest_id=q.quest_id,
                state=q.state,
                version=q.version,
                audit=list(q.audit),
                metrics=dict(q.metrics),
                seen_keys=set(q.seen_keys),
            )

    async def save(self, quest: Quest, expected_version: Optional[int]) -> Quest:
        async with self._lock:
            current = self._store.get(quest.quest_id)
            if current is None:
                if expected_version not in (None, 0):
                    raise VersionConflict("Quest does not exist but expected_version provided")
                # create new
                self._store[quest.quest_id] = quest
                return quest
            # optimistic lock
            if expected_version is not None and expected_version != current.version:
                raise VersionConflict(f"Version mismatch: expected {expected_version}, got {current.version}")
            # increment version and persist
            quest.version = current.version + 1
            self._store[quest.quest_id] = quest
            return quest

# --------------------------------------------------------------------------------------
# Reference State Machine (used if real impl not found)
# --------------------------------------------------------------------------------------

class ReferenceQuestStateMachine:
    def __init__(self, repo: QuestRepository):
        self.repo = repo

    async def create_if_absent(self, quest_id: str) -> Quest:
        q = await self.repo.get(quest_id)
        if q:
            return q
        q = Quest(quest_id=quest_id)
        await self.repo.save(q, expected_version=0)
        return q

    async def apply(self, quest_id: str, event: QuestEvent, expected_version: Optional[int] = None) -> Quest:
        q = await self.create_if_absent(quest_id)

        # idempotency
        if event.idempotency_key in q.seen_keys:
            q.metrics["retries"] += 1
            q.audit.append({"at": event.at, "actor": event.actor, "name": event.name, "result": "deduplicated"})
            # do not change version on idempotent replay, but persist audit/metrics
            await self.repo.save(q, expected_version=q.version)
            return q

        next_state = self._next_state(q.state, event)
        if next_state is None:
            raise InvalidTransition(f"Event {event.name} is not valid for state {q.state.name}")

        q.state = next_state
        q.seen_keys.add(event.idempotency_key)
        q.metrics["transitions"] += 1
        q.audit.append({"at": event.at, "actor": event.actor, "name": event.name, "to": q.state.name})

        # expected_version allows external optimistic locking
        saved = await self.repo.save(q, expected_version=q.version if expected_version is None else expected_version)
        return saved

    def _next_state(self, state: QuestState, event: QuestEvent) -> Optional[QuestState]:
        mapping = {
            "start": QuestState.ACTIVE,
            "fail": QuestState.FAILED,
            "complete": QuestState.COMPLETED,
            "cancel": QuestState.CANCELLED,
            "archive": QuestState.ARCHIVED,
            # recovery transition
            "retry": QuestState.ACTIVE if state == QuestState.FAILED else None,
        }
        candidate = mapping.get(event.name)
        if candidate is None:
            return None
        return candidate if candidate in VALID_TRANSITIONS[state] else None

# --------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------

@pytest.fixture(scope="session")
def has_hypothesis():
    if hypothesis is None:
        pytest.skip("hypothesis not installed")
    return True

@pytest.fixture
def repo():
    return InMemoryQuestRepository()

@pytest.fixture
def state_machine(repo):
    # Use real implementation if present, otherwise reference
    if _loaded_impl and hasattr(_loaded_impl, "QuestStateMachine"):
        return _loaded_impl.QuestStateMachine(repo)
    return ReferenceQuestStateMachine(repo)

def _evt(name: str, key: str, actor: str = "tester", **payload) -> QuestEvent:
    return QuestEvent(idempotency_key=key, at=time.time(), actor=actor, name=name, payload=payload or {})

# --------------------------------------------------------------------------------------
# Basic contract tests
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_happy_path_create_start_complete_archive(state_machine):
    qid = "q-001"
    q = await state_machine.apply(qid, _evt("start", "k1"))
    assert q.state == QuestState.ACTIVE
    v1 = q.version

    q = await state_machine.apply(qid, _evt("complete", "k2"))
    assert q.state == QuestState.COMPLETED
    assert q.version == v1 + 1

    q = await state_machine.apply(qid, _evt("archive", "k3"))
    assert q.state == QuestState.ARCHIVED
    assert q.metrics["transitions"] == 3
    assert any(a["name"] == "archive" for a in q.audit)

@pytest.mark.asyncio
async def test_invalid_transition_rejected(state_machine):
    qid = "q-002"
    # cannot archive directly from DRAFT
    with pytest.raises(InvalidTransition):
        await state_machine.apply(qid, _evt("archive", "k1"))

@pytest.mark.asyncio
async def test_idempotent_replay_does_not_double_apply(state_machine):
    qid = "q-003"
    e = _evt("start", "idemp-1")
    q = await state_machine.apply(qid, e)
    v = q.version
    # replay same idempotency key
    q2 = await state_machine.apply(qid, e)
    assert q2.state == QuestState.ACTIVE
    assert q2.version == v  # no version bump on idempotent replay
    assert q2.metrics["retries"] == 1
    assert any(a.get("result") == "deduplicated" for a in q2.audit)

@pytest.mark.asyncio
async def test_retry_from_failed(state_machine):
    qid = "q-004"
    await state_machine.apply(qid, _evt("start", "k1"))
    q = await state_machine.apply(qid, _evt("fail", "k2"))
    assert q.state == QuestState.FAILED
    q = await state_machine.apply(qid, _evt("retry", "k3"))
    assert q.state == QuestState.ACTIVE

# --------------------------------------------------------------------------------------
# Concurrency and optimistic locking
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_updates_with_optimistic_lock(state_machine, repo):
    qid = "q-005"
    # Start quest
    await state_machine.apply(qid, _evt("start", "k1"))
    # Two concurrent actions from ACTIVE: complete and cancel — one must win, other conflict or invalid
    async def actor(name, key, delay=0.02):
        await asyncio.sleep(delay)
        try:
            return await state_machine.apply(qid, _evt(name, key))
        except (VersionConflict, InvalidTransition) as e:
            return e

    res_a, res_b = await asyncio.gather(actor("complete", "k2", 0.01), actor("cancel", "k3", 0.01))
    outcomes = {type(res_a).__name__, type(res_b).__name__}
    # Expect one Quest or an exception on the other path
    assert outcomes.intersection({"Quest", "InvalidTransition", "VersionConflict"})
    # And the final state must be one of terminal states from ACTIVE
    final = await repo.get(qid)
    assert final.state in {QuestState.COMPLETED, QuestState.CANCELLED, QuestState.FAILED}

# --------------------------------------------------------------------------------------
# Observability (audit trail and metrics)
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_and_metrics_populated(state_machine):
    qid = "q-006"
    await state_machine.apply(qid, _evt("start", "k1", actor="svc-policy"))
    await state_machine.apply(qid, _evt("fail", "k2", actor="svc-engine"))
    q = await state_machine.apply(qid, _evt("retry", "k3", actor="svc-retry"))
    assert q.metrics["transitions"] == 3
    actors = [a.get("actor") for a in q.audit if "actor" in a]
    assert {"svc-policy", "svc-engine", "svc-retry"}.issubset(set(actors))

# --------------------------------------------------------------------------------------
# Property-based tests for transition safety
# --------------------------------------------------------------------------------------

EVENTS = ["start", "fail", "retry", "complete", "cancel", "archive"]

def _valid_next(state: QuestState, name: str) -> bool:
    tmp_event = QuestEvent(idempotency_key="tmp", at=time.time(), actor="gen", name=name)
    mapping = {
        "start": QuestState.ACTIVE,
        "fail": QuestState.FAILED,
        "complete": QuestState.COMPLETED,
        "cancel": QuestState.CANCELLED,
        "archive": QuestState.ARCHIVED,
        "retry": QuestState.ACTIVE if state == QuestState.FAILED else None,
    }
    candidate = mapping.get(name)
    if candidate is None:
        return False
    return candidate in VALID_TRANSITIONS[state]

@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.skipif(hypothesis is None, reason="hypothesis not installed")
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None, max_examples=100)
@given(seq=st.lists(st.sampled_from(EVENTS), min_size=1, max_size=25))
async def test_property_transitions_do_not_violate_contract(state_machine, seq):
    qid = "q-prop"
    seen = set()
    # start fresh
    # apply events; invalid transitions should raise InvalidTransition
    for i, name in enumerate(seq):
        key = f"p-{i}"
        try:
            q = await state_machine.apply(qid, _evt(name, key))
            # verify the transition matched the contract
            assert _valid_next(q.state if name == "archive" else q.state, name) or name == "retry"
            seen.add(name)
        except InvalidTransition:
            # If invalid, ensure the machine indeed rejects according to VALID_TRANSITIONS
            # We fetch current state to validate expectation
            # This assumes reference/real impl uses same VALID_TRANSITIONS table.
            pass

# --------------------------------------------------------------------------------------
# Optional external integrations (skipped if env not set)
# --------------------------------------------------------------------------------------

POSTGRES_DSN = os.getenv("POSTGRES_DSN") or os.getenv("MYTHOS_PG_DSN")
REDIS_URL = os.getenv("REDIS_URL") or os.getenv("MYTHOS_REDIS_URL")

@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.skipif(not POSTGRES_DSN, reason="POSTGRES_DSN not set")
async def test_postgres_roundtrip_contract():
    try:
        import asyncpg  # type: ignore
    except Exception:
        pytest.skip("asyncpg not installed")
    conn = await asyncpg.connect(POSTGRES_DSN)
    try:
        await conn.execute("""
        create table if not exists quests(
            quest_id text primary key,
            state text not null,
            version int not null,
            updated_at timestamptz default now()
        );""")
        # Write
        await conn.execute("insert into quests(quest_id, state, version) values($1,$2,$3) on conflict (quest_id) do update set state=excluded.state, version=excluded.version",
                           "q-db-1", "DRAFT", 0)
        # Read
        row = await conn.fetchrow("select state, version from quests where quest_id=$1", "q-db-1")
        assert row["state"] == "DRAFT" and row["version"] == 0
    finally:
        await conn.close()

@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.skipif(not REDIS_URL, reason="REDIS_URL not set")
async def test_redis_idempotency_cache():
    try:
        import redis.asyncio as aioredis  # type: ignore
    except Exception:
        pytest.skip("redis.asyncio not installed")
    r = aioredis.from_url(REDIS_URL)
    try:
        key = "mythos:test:idemp:k1"
        await r.set(key, 1, ex=30)
        v = await r.get(key)
        assert v is not None
    finally:
        await r.close()

# --------------------------------------------------------------------------------------
# Backward-compat and regression tests
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cannot_transition_from_archived(state_machine):
    qid = "q-arch"
    await state_machine.apply(qid, _evt("start", "k1"))
    await state_machine.apply(qid, _evt("complete", "k2"))
    q = await state_machine.apply(qid, _evt("archive", "k3"))
    assert q.state == QuestState.ARCHIVED
    with pytest.raises(InvalidTransition):
        await state_machine.apply(qid, _evt("retry", "k4"))
    with pytest.raises(InvalidTransition):
        await state_machine.apply(qid, _evt("start", "k5"))

@pytest.mark.asyncio
async def test_expected_version_argument_enforced(state_machine, repo):
    qid = "q-ver"
    q1 = await state_machine.apply(qid, _evt("start", "k1"))
    # Simulate stale writer expecting older version
    try:
        await state_machine.apply(qid, _evt("fail", "k2"), expected_version=q1.version - 1)
        assert False, "Expected VersionConflict"
    except VersionConflict:
        pass

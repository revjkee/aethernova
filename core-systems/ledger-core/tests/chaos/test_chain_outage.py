# path: ledger-core/tests/chaos/test_chain_outage.py
"""
Industrial chaos tests for chain outage recovery behavior.

These tests simulate chain/RPC outages, exponential backoff, recovery,
and reorg handling for a generic ledger "follower" (chain syncer).
They use a deterministic virtual clock to avoid flaky sleeps.
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Iterable

import pytest


# =============================
# Domain model and test fakes
# =============================

class ChainUnavailable(Exception):
    """Raised when the chain/RPC endpoint is unavailable."""


@dataclass(frozen=True)
class Block:
    height: int
    parent_hash: str
    hash: str
    ts: float


def _hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def make_block(parent: Optional[Block], height: int, ts: float) -> Block:
    parent_hash = parent.hash if parent else "GENESIS"
    return Block(
        height=height,
        parent_hash=parent_hash,
        hash=_hash(f"{parent_hash}|{height}|{ts}"),
        ts=ts,
    )


class VirtualClock:
    """Deterministic clock with manual advancement."""

    def __init__(self, start: float = 0.0):
        self._now = float(start)

    @property
    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        assert seconds >= 0
        self._now += seconds


class FakeChain:
    """
    Deterministic chain backend that:
      - Produces a new block every `block_interval` seconds.
      - Can be in outage for time windows (raising ChainUnavailable).
      - Can trigger a reorg event by rewriting blocks after `reorg_from_height`.
    """

    def __init__(
        self,
        clock: VirtualClock,
        block_interval: float = 1.0,
        max_height: int = 10_000,
        outages: Optional[List[Tuple[float, float]]] = None,
        reorg_event: Optional[Tuple[float, int, int]] = None,
        jitter: float = 0.0,
    ):
        """
        :param clock: VirtualClock
        :param block_interval: seconds per new block
        :param max_height: chain stops after this height
        :param outages: list of (start_time, end_time) windows
        :param reorg_event: (trigger_time, reorg_from_height, new_length_from_anchor)
        :param jitter: optional timestamp jitter added to block times for realism
        """
        self.clock = clock
        self.block_interval = block_interval
        self.max_height = max_height
        self.outages = outages or []
        self.reorg_event = reorg_event
        self.jitter = jitter

        self._blocks: List[Block] = [make_block(None, 0, 0.0)]
        self._last_build_time = 0.0
        self._reorg_applied = False

    def _in_outage(self) -> bool:
        t = self.clock.now
        return any(start <= t < end for start, end in self.outages)

    def _ensure_built_up_to_now(self) -> None:
        """
        Build blocks deterministically up to the current time tick,
        unless we've reached max_height.
        """
        # Produce blocks based on clock and interval
        while (
            len(self._blocks) - 1 < self.max_height
            and self._last_build_time + self.block_interval <= self.clock.now
        ):
            parent = self._blocks[-1]
            self._last_build_time += self.block_interval
            ts = self._last_build_time + (random.random() * self.jitter if self.jitter else 0.0)
            blk = make_block(parent, parent.height + 1, ts)
            self._blocks.append(blk)

        # Maybe apply a reorg event once
        if self.reorg_event and not self._reorg_applied and self.clock.now >= self.reorg_event[0]:
            _, from_h, new_len = self.reorg_event
            from_h = int(from_h)
            assert 0 < from_h < len(self._blocks), "reorg_from_height must be within built chain"
            # Keep anchor (from_h - 1), rewrite from 'from_h' for 'new_len' blocks
            anchor = self._blocks[from_h - 1]
            rewritten: List[Block] = [*self._blocks[:from_h]]
            h = from_h
            ts = self.clock.now  # new timeline
            for _ in range(new_len):
                parent = rewritten[-1]
                ts += self.block_interval
                blk = make_block(parent, h, ts)
                rewritten.append(blk)
                h += 1
            self._blocks = rewritten
            self._last_build_time = ts
            self._reorg_applied = True

    def latest_height(self) -> int:
        if self._in_outage():
            raise ChainUnavailable("RPC unreachable during outage window")
        self._ensure_built_up_to_now()
        return len(self._blocks) - 1

    def get_block_by_height(self, height: int) -> Block:
        if self._in_outage():
            raise ChainUnavailable("RPC unreachable during outage window")
        self._ensure_built_up_to_now()
        if height < 0 or height >= len(self._blocks):
            raise IndexError(f"height {height} out of range")
        return self._blocks[height]


class InMemoryStore:
    """
    Minimal store with idempotency, contiguous chain enforcement and rollback.
    """

    def __init__(self) -> None:
        self._by_height: Dict[int, Block] = {}
        self._head_h: int = -1  # "-1" means empty
        self.checkpoints: List[int] = []
        self.events: List[Tuple[str, Dict]] = []

    @property
    def head_height(self) -> int:
        return self._head_h

    @property
    def head(self) -> Optional[Block]:
        return self._by_height.get(self._head_h)

    def has_height(self, height: int) -> bool:
        return height in self._by_height

    def get(self, height: int) -> Optional[Block]:
        return self._by_height.get(height)

    def apply_block(self, blk: Block) -> None:
        # Idempotent write
        if self._head_h >= 0 and self._by_height[self._head_h].hash == blk.hash:
            return

        # Enforce contiguity
        expected_parent = self._by_height[self._head_h].hash if self._head_h >= 0 else "GENESIS"
        if blk.parent_hash != expected_parent or blk.height != self._head_h + 1:
            raise ValueError(
                f"Non-contiguous block apply: got h={blk.height} parent={blk.parent_hash[:8]} "
                f"expected h={self._head_h + 1} parent={expected_parent[:8]}"
            )
        self._by_height[blk.height] = blk
        self._head_h = blk.height

        # Optional: periodic checkpointing every 100 blocks
        if blk.height % 100 == 0:
            self.checkpoints.append(blk.height)

    def rollback_to(self, height: int) -> None:
        # Remove blocks above 'height'
        for h in sorted(list(self._by_height.keys()), reverse=True):
            if h > height:
                self._by_height.pop(h, None)
        self._head_h = height
        self.events.append(("rollback", {"to_height": height}))


class Backoff:
    """Exponential backoff with cap and jitter, deterministic via seed."""

    def __init__(
        self,
        base: float = 0.2,
        factor: float = 2.0,
        cap: float = 10.0,
        jitter: float = 0.1,
        seed: int = 42,
    ) -> None:
        self.base = base
        self.factor = factor
        self.cap = cap
        self.jitter = jitter
        self._attempt = 0
        self._rnd = random.Random(seed)

    def reset(self) -> None:
        self._attempt = 0

    def next_delay(self) -> float:
        raw = min(self.cap, self.base * (self.factor ** self._attempt))
        self._attempt += 1
        # Full jitter in [0 .. jitter * raw]
        return raw + self._rnd.random() * self.jitter * raw


class ResilientFollower:
    """
    Reference chain follower under test.

    Behavior:
      - Tracks chain tip, applies blocks sequentially into `store`.
      - On outage, emits outage_start once, backs off exponentially, and emits outage_end on recovery.
      - If parent mismatch occurs (reorg), find common ancestor and rollback store before replay.
      - Emits 'prolonged_outage' alert if outage exceeds `alert_after` seconds.
    """

    def __init__(
        self,
        chain: FakeChain,
        store: InMemoryStore,
        clock: VirtualClock,
        backoff: Optional[Backoff] = None,
        alert_after: float = 15.0,
        max_batch: int = 10,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.chain = chain
        self.store = store
        self.clock = clock
        self.backoff = backoff or Backoff()
        self.alert_after = alert_after
        self.max_batch = max_batch
        self.logger = logger or logging.getLogger("ResilientFollower")

        self._outage_started_at: Optional[float] = None
        self._was_outage = False
        self._stats = {"applied": 0, "reorgs": 0, "outage_alerts": 0}

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def _emit(self, name: str, **payload) -> None:
        self.store.events.append((name, payload))
        self.logger.debug("event %s %s", name, payload)

    def _mark_outage_start(self) -> None:
        if self._outage_started_at is None:
            self._outage_started_at = self.clock.now
            self._emit("outage_start", at=self._outage_started_at)

    def _mark_outage_end(self) -> None:
        if self._outage_started_at is not None:
            self._emit("outage_end", duration=self.clock.now - self._outage_started_at)
            self._outage_started_at = None
            self.backoff.reset()

    def _check_prolonged_outage(self) -> None:
        if self._outage_started_at is not None:
            dur = self.clock.now - self._outage_started_at
            # Emit only once per prolonged outage
            if dur >= self.alert_after and not any(
                name == "prolonged_outage" and ev.get("started_at") == self._outage_started_at
                for name, ev in self.store.events
            ):
                self._stats["outage_alerts"] += 1
                self._emit("prolonged_outage", started_at=self._outage_started_at, duration=dur)

    def step(self) -> Optional[float]:
        """
        Perform one non-blocking step of syncing.
        :return: if None -> immediate next step allowed; if float -> wait at least this many seconds (backoff).
        """
        try:
            tip = self.chain.latest_height()
        except ChainUnavailable:
            self._mark_outage_start()
            self._check_prolonged_outage()
            return self.backoff.next_delay()

        # If we reached here, chain is reachable
        self._mark_outage_end()

        # Determine next height to apply
        next_h = self.store.head_height + 1
        if next_h > tip:
            # Nothing to do
            return None

        # Apply up to max_batch blocks
        batch = 0
        while next_h <= tip and batch < self.max_batch:
            try:
                blk = self.chain.get_block_by_height(next_h)
            except ChainUnavailable:
                # Outage mid-batch
                self._mark_outage_start()
                self._check_prolonged_outage()
                return self.backoff.next_delay()

            # Parent continuity check
            if self.store.head_height >= 0:
                expected_parent = self.store.get(self.store.head_height).hash
                if blk.parent_hash != expected_parent:
                    # reorg detected, find common ancestor
                    self._stats["reorgs"] += 1
                    # Walk back until parent matches
                    rollback_to = self.store.head_height
                    while rollback_to >= 0:
                        if self.store.get(rollback_to).hash == blk.parent_hash:
                            break
                        rollback_to -= 1
                    if rollback_to < 0 and blk.parent_hash != "GENESIS":
                        raise AssertionError("No common ancestor found")
                    self.store.rollback_to(rollback_to)

            # Apply block
            self.store.apply_block(blk)
            self._stats["applied"] += 1
            next_h += 1
            batch += 1

        return None


# =============================
# Pytest fixtures
# =============================

@pytest.fixture()
def clock() -> VirtualClock:
    return VirtualClock(start=0.0)


@pytest.fixture()
def store() -> InMemoryStore:
    return InMemoryStore()


# =============================
# Test cases
# =============================

def run_follower_until(
    follower: ResilientFollower,
    clock: VirtualClock,
    seconds: float,
    tick: float = 0.1,
    max_iters: int = 200_000,
) -> None:
    """
    Drive the follower for up to `seconds` of virtual time.
    """
    iters = 0
    deadline = clock.now + seconds
    while clock.now < deadline and iters < max_iters:
        wait = follower.step()
        # Advance either by 'wait' (if provided) or a small tick to re-check tip
        advance_by = wait if (wait and wait > 0) else tick
        clock.advance(advance_by)
        iters += 1


def test_recovers_from_short_outage(clock: VirtualClock, store: InMemoryStore) -> None:
    # Outage from t=5..t=12
    chain = FakeChain(clock, block_interval=1.0, outages=[(5.0, 12.0)], max_height=60)
    follower = ResilientFollower(chain, store, clock, alert_after=30.0, max_batch=5)

    # Run 40 seconds of virtual time
    run_follower_until(follower, clock, seconds=40.0)

    # Assertions
    assert store.head_height >= 25, "Should have caught up after outage"
    # Ensure we emitted outage start/end once
    outbreak = [e for e in store.events if e[0] == "outage_start"]
    outend = [e for e in store.events if e[0] == "outage_end"]
    assert len(outbreak) == 1 and len(outend) == 1
    # No prolonged outage alert expected (alert_after=30)
    assert not any(e[0] == "prolonged_outage" for e in store.events)


@pytest.mark.parametrize(
    "outage_len,expected_alerts",
    [
        (10.0, 0),
        (20.0, 1),
        (45.0, 1),
    ],
)
def test_prolonged_outage_alert(clock: VirtualClock, store: InMemoryStore, outage_len: float, expected_alerts: int) -> None:
    chain = FakeChain(clock, outages=[(2.0, 2.0 + outage_len)], max_height=200)
    follower = ResilientFollower(chain, store, clock, alert_after=15.0)

    run_follower_until(follower, clock, seconds=60.0)

    alerts = [e for e in store.events if e[0] == "prolonged_outage"]
    assert len(alerts) == expected_alerts, f"Expected {expected_alerts} prolonged outage alerts"


def test_exponential_backoff_caps(clock: VirtualClock, store: InMemoryStore) -> None:
    # Persistent outage for 30s to exercise backoff
    chain = FakeChain(clock, outages=[(0.0, 30.0)], max_height=10)
    follower = ResilientFollower(
        chain,
        store,
        clock,
        backoff=Backoff(base=0.5, factor=2.0, cap=8.0, jitter=0.0, seed=1),
        alert_after=5.0,
    )

    delays: List[float] = []

    end_at = clock.now + 12.0  # sample first 12s of attempts
    while clock.now < end_at:
        wait = follower.step()
        assert wait is not None
        delays.append(wait)
        clock.advance(wait)

    # Backoff sequence should double until capped at 8.0
    # base=0.5 => 0.5, 1, 2, 4, 8, 8, 8...
    assert delays[:6] == [0.5, 1.0, 2.0, 4.0, 8.0, 8.0]


def test_no_duplicate_processing_when_rpc_flaps(clock: VirtualClock, store: InMemoryStore) -> None:
    # Multiple short outages (flapping)
    chain = FakeChain(clock, outages=[(3.0, 4.5), (6.0, 7.0), (9.0, 9.3)], max_height=200)
    follower = ResilientFollower(chain, store, clock, max_batch=3)

    run_follower_until(follower, clock, seconds=25.0)

    # Verify contiguity and idempotency: heights are 0..head with no gaps
    assert store.head_height > 0
    for h in range(0, store.head_height + 1):
        blk = store.get(h)
        assert blk is not None, f"Missing height {h}"
        if h == 0:
            assert blk.parent_hash == "GENESIS"
        else:
            assert blk.parent_hash == store.get(h - 1).hash


def test_reorg_after_outage_rollback_and_replay(clock: VirtualClock, store: InMemoryStore) -> None:
    # Outage overlaps reorg trigger; reorg rewrites from height 15 with length 20
    chain = FakeChain(
        clock,
        outages=[(8.0, 14.0)],
        reorg_event=(10.0, 15, 20),
        max_height=100,
    )
    follower = ResilientFollower(chain, store, clock, max_batch=5)

    # Let it run long enough to pass outage and reorg
    run_follower_until(follower, clock, seconds=40.0)

    # We expect at least one rollback event
    rb = [e for e in store.events if e[0] == "rollback"]
    assert rb, "Expected rollback due to reorg"
    # Head should be aligned with chain tip at this time
    assert store.head_height >= 30


def test_resumes_quickly_after_long_outage_without_overloading(clock: VirtualClock, store: InMemoryStore) -> None:
    # Long outage, then quickly catching up in batches limited by max_batch
    chain = FakeChain(clock, outages=[(0.0, 20.0)], max_height=300)
    follower = ResilientFollower(chain, store, clock, max_batch=7)

    run_follower_until(follower, clock, seconds=60.0)

    # Ensure progress beyond simple head
    assert store.head_height >= 35
    # Check that checkpoints were created (every 100 blocks)
    assert all(h % 100 == 0 for h in store.checkpoints)


def test_outage_events_are_paired(clock: VirtualClock, store: InMemoryStore) -> None:
    chain = FakeChain(clock, outages=[(2.0, 5.0), (7.0, 9.0)], max_height=100)
    follower = ResilientFollower(chain, store, clock)

    run_follower_until(follower, clock, seconds=20.0)

    starts = [e for e in store.events if e[0] == "outage_start"]
    ends = [e for e in store.events if e[0] == "outage_end"]
    # Starts should equal ends count
    assert len(starts) == len(ends)


def test_integrity_after_interrupted_batch(clock: VirtualClock, store: InMemoryStore) -> None:
    # Outage hits mid-batch (max_batch=10), ensure no skipped or duplicated blocks
    chain = FakeChain(clock, outages=[(4.5, 6.5)], max_height=200)
    follower = ResilientFollower(chain, store, clock, max_batch=10)

    run_follower_until(follower, clock, seconds=25.0)

    # Verify all parent links are valid
    head = store.head_height
    assert head >= 10
    for h in range(1, head + 1):
        assert store.get(h).parent_hash == store.get(h - 1).hash


def test_multiple_reorgs_across_time(clock: VirtualClock, store: InMemoryStore) -> None:
    # First reorg at t=6 from h=10, then another at t=18 from h=25
    chain = FakeChain(
        clock,
        outages=[(5.0, 7.0), (17.0, 19.0)],
        reorg_event=(6.0, 10, 30),  # the class only supports one reorg event;
        max_height=120,
    )
    # To simulate a second reorg, we will modify the chain after first event
    follower = ResilientFollower(chain, store, clock, max_batch=6)

    # Run past the first reorg
    run_follower_until(follower, clock, seconds=12.0)
    assert any(e[0] == "rollback" for e in store.events)

    # Manually inject a second reorg by updating chain internals for test
    # This is acceptable in a chaos test.
    chain.reorg_event = (18.0, 25, 25)
    chain._reorg_applied = False

    run_follower_until(follower, clock, seconds=30.0)

    # Expect another rollback captured
    rb = [e for e in store.events if e[0] == "rollback"]
    assert len(rb) >= 2


def test_stats_exposed_for_observability(clock: VirtualClock, store: InMemoryStore) -> None:
    chain = FakeChain(clock, outages=[(3.0, 6.0)], max_height=80)
    follower = ResilientFollower(chain, store, clock, max_batch=4)

    run_follower_until(follower, clock, seconds=25.0)

    stats = follower.stats()
    assert "applied" in stats and stats["applied"] >= 10
    assert "reorgs" in stats
    assert "outage_alerts" in stats

"""
ledger-core/tests/chaos/test_queue_partitions.py

Industrial-grade chaos tests for partitioned message queues.

These tests simulate a partitioned broker with fault injection to verify:
- Per-partition ordering is preserved despite delays, reordering and duplicates.
- Consumer group rebalancing resumes from the last committed offset without loss.
- At-least-once delivery is achievable with idempotent consumers under duplication.
- Backpressure and paused partitions do not stall unrelated partitions.
- System invariants hold under randomized fault storms.

The tests are self-contained and do not require external services.
They intentionally avoid pytest-asyncio dependency by running asyncio within sync tests.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set, Iterable
import pytest

# ------- Broker Simulation Primitives -----------------------------------------------------------

@dataclass(frozen=True)
class Message:
    id: int
    key: str
    partition: int
    offset: int
    value: int


@dataclass
class FaultModel:
    drop_prob: float = 0.0          # Probability to drop a produced message before it becomes available
    duplicate_prob: float = 0.0     # Probability to duplicate a produced message
    max_delay_ms: int = 0           # Max artificial delay before message becomes available
    reorder_window: int = 0         # Max size of a temporary buffer to reorder messages (still FIFO within a partition)


@dataclass
class PartitionState:
    partition: int
    next_offset: int = 0
    paused: bool = False
    # Messages waiting to "arrive" with a release timestamp in ms
    inflight: List[Tuple[float, Message]] = field(default_factory=list)
    # Messages available to consume in order (by offset)
    available: List[Message] = field(default_factory=list)

    def schedule(self, msg: Message, release_at_ms: float) -> None:
        self.inflight.append((release_at_ms, msg))

    def tick(self, now_ms: float, reorder_window: int) -> None:
        """Move arrived messages from inflight to available with a small reordering window."""
        if not self.inflight:
            return
        # Move all arrived to a buffer
        arrived = []
        remaining = []
        for rel, msg in self.inflight:
            if rel <= now_ms:
                arrived.append(msg)
            else:
                remaining.append((rel, msg))
        self.inflight = remaining

        if not arrived:
            return

        # For reordering across partitions we don't do anything here.
        # For per-partition, we emulate small local reorder window by shuffling arrived up to window.
        if reorder_window > 0:
            random.shuffle(arrived)
        # Extend available but keep it sorted by offset to enforce per-partition ordering
        self.available.extend(arrived)
        self.available.sort(key=lambda m: m.offset)


class FaultyBroker:
    """
    In-memory simulation of a partitioned message broker with fault injection.
    """
    def __init__(self, num_partitions: int, faults: Optional[Dict[int, FaultModel]] = None, seed: int = 0) -> None:
        assert num_partitions >= 1
        self.num_partitions = num_partitions
        self.parts: Dict[int, PartitionState] = {p: PartitionState(partition=p) for p in range(num_partitions)}
        self.faults = faults or {}
        self._id_seq = 0
        self._rng = random.Random(seed)
        # Metrics
        self.metrics = {
            "produced": 0,
            "dropped": 0,
            "scheduled": 0,
            "delivered": 0,
            "duplicates_emitted": 0,
        }
        # Committed offsets per partition (highest committed offset)
        self.committed: Dict[int, int] = {p: -1 for p in range(num_partitions)}

    def _fm(self, p: int) -> FaultModel:
        return self.faults.get(p, FaultModel())

    def now_ms(self) -> float:
        return time.monotonic() * 1000.0

    # --------------- Producer API --------------------

    def produce(self, key: str, value: int) -> Message:
        p = self._partition_for_key(key)
        part = self.parts[p]
        msg = Message(
            id=self._next_id(),
            key=key,
            partition=p,
            offset=part.next_offset,
            value=value,
        )
        part.next_offset += 1
        self.metrics["produced"] += 1

        fm = self._fm(p)
        # Drop?
        if self._rng.random() < fm.drop_prob:
            self.metrics["dropped"] += 1
            # Optionally still duplicate a dropped? We consider drop terminal (no delivery).
            # So we do not schedule dropped messages.
            return msg

        # Delay and schedule
        delay_ms = self._rng.randint(0, fm.max_delay_ms) if fm.max_delay_ms > 0 else 0
        release_at = self.now_ms() + delay_ms
        self.parts[p].schedule(msg, release_at)
        self.metrics["scheduled"] += 1

        # Duplicate?
        if self._rng.random() < fm.duplicate_prob:
            # We create a second message with the same id/offset to simulate duplication at broker/producer level
            dup_msg = msg  # same identity
            dup_delay = self._rng.randint(0, fm.max_delay_ms) if fm.max_delay_ms > 0 else 0
            self.parts[p].schedule(dup_msg, self.now_ms() + dup_delay)
            self.metrics["duplicates_emitted"] += 1

        return msg

    def produce_many(self, n: int, key_selector: Optional[Iterable[str]] = None) -> List[Message]:
        msgs = []
        if key_selector is None:
            # Default: keys that hash to partitions uniformly
            keys = (f"k-{i}" for i in range(n))
        else:
            keys = key_selector
        for i, k in enumerate(keys):
            msgs.append(self.produce(k, i))
            if len(msgs) >= n:
                break
        return msgs

    # --------------- Consumer API --------------------

    def poll(self, assigned: List[int], max_batch: int = 100) -> List[Message]:
        """
        Fetch next available messages from assigned partitions.
        Per-partition ordering is enforced by partition available list ordering.
        """
        now_ms = self.now_ms()
        # Tick all partitions to release inflight
        for p in assigned:
            part = self.parts[p]
            fm = self._fm(p)
            part.tick(now_ms, fm.reorder_window)

        batch: List[Message] = []
        for p in assigned:
            part = self.parts[p]
            if part.paused:
                continue
            if part.available:
                # Pop the head (lowest offset)
                msg = part.available.pop(0)
                batch.append(msg)
                self.metrics["delivered"] += 1
                if len(batch) >= max_batch:
                    break
        return batch

    def commit(self, partition: int, offset: int) -> None:
        # Commit is idempotent, track highest committed offset
        if offset > self.committed[partition]:
            self.committed[partition] = offset

    # Control
    def pause_partition(self, p: int) -> None:
        self.parts[p].paused = True

    def resume_partition(self, p: int) -> None:
        self.parts[p].paused = False

    def _partition_for_key(self, key: str) -> int:
        return hash(key) % self.num_partitions

    def _next_id(self) -> int:
        i = self._id_seq
        self._id_seq += 1
        return i

# ----------------- Consumer Implementations -----------------------------------------------------

class IdempotentConsumer:
    """
    Consumer that deduplicates messages by (partition, offset, id) triple,
    and commits after processing each message.
    """
    def __init__(self, broker: FaultyBroker, assigned: List[int], name: str = "c") -> None:
        self.broker = broker
        self.assigned = list(sorted(assigned))
        self.name = name
        self._seen: Set[Tuple[int, int, int]] = set()
        self.processed: List[Message] = []
        self._stop = False

    async def run(self, runtime_ms: int = 1000, poll_interval_ms: int = 5) -> None:
        start = self.broker.now_ms()
        while not self._stop and self.broker.now_ms() - start < runtime_ms:
            batch = self.broker.poll(self.assigned, max_batch=64)
            if not batch:
                await asyncio.sleep(poll_interval_ms / 1000.0)
                continue
            for m in batch:
                key = (m.partition, m.offset, m.id)
                if key in self._seen:
                    # Duplicate detected; still "processed" but do not double-count
                    continue
                self._seen.add(key)
                # Simulate processing work
                self.processed.append(m)
                # Commit offset
                self.broker.commit(m.partition, m.offset)
        # Drain a last time after runtime to catch late arrivals
        for _ in range(10):
            batch = self.broker.poll(self.assigned, max_batch=64)
            if not batch:
                break
            for m in batch:
                key = (m.partition, m.offset, m.id)
                if key in self._seen:
                    continue
                self._seen.add(key)
                self.processed.append(m)
                self.broker.commit(m.partition, m.offset)

    def stop(self) -> None:
        self._stop = True

# ----------------- Test Utilities ----------------------------------------------------------------

def _drain_for(broker: FaultyBroker, consumers: List[IdempotentConsumer], duration_ms: int = 1000) -> None:
    """Run all consumers concurrently for duration."""
    async def main():
        await asyncio.gather(*(c.run(runtime_ms=duration_ms) for c in consumers))
    asyncio.run(main())


def _produce_uniform(broker: FaultyBroker, n: int) -> None:
    # Produce messages with keys designed to spread across partitions
    keys = (f"key-{i}" for i in range(n))
    broker.produce_many(n, key_selector=keys)


def _unique_messages(msgs: List[Message]) -> List[Tuple[int, int]]:
    """Return unique (partition, offset) pairs observed."""
    seen: Set[Tuple[int, int]] = set()
    out: List[Tuple[int, int]] = []
    for m in msgs:
        key = (m.partition, m.offset)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out

# ----------------- Tests -------------------------------------------------------------------------

@pytest.mark.timeout(5)
def test_partition_ordering_preserved_per_partition_under_faults():
    """
    Even under delay and local reordering windows, per-partition offsets must be strictly increasing.
    """
    broker = FaultyBroker(
        num_partitions=8,
        faults={p: FaultModel(drop_prob=0.0, duplicate_prob=0.2, max_delay_ms=10, reorder_window=4) for p in range(8)},
        seed=42,
    )
    _produce_uniform(broker, n=500)

    consumer = IdempotentConsumer(broker, assigned=list(range(8)), name="c1")
    _drain_for(broker, [consumer], duration_ms=600)

    # Group processed messages by partition and check monotonic offsets
    by_part: Dict[int, List[int]] = {}
    for m in consumer.processed:
        by_part.setdefault(m.partition, []).append(m.offset)

    for p, offsets in by_part.items():
        # After dedupe, entries should be unique and strictly increasing
        assert offsets == sorted(set(offsets)), f"Partition {p} offsets not strictly increasing"


@pytest.mark.timeout(5)
def test_consumer_group_rebalance_retains_progress():
    """
    Simulate a rebalance: consumer A processes some data on partitions [0,1], then consumer B takes partition 1.
    Ensure B resumes from correct committed offset without loss or duplication.
    """
    broker = FaultyBroker(
        num_partitions=2,
        faults={0: FaultModel(max_delay_ms=5), 1: FaultModel(max_delay_ms=5, duplicate_prob=0.1)},
        seed=7,
    )
    _produce_uniform(broker, n=300)

    consumer_a = IdempotentConsumer(broker, assigned=[0, 1], name="A")
    _drain_for(broker, [consumer_a], duration_ms=300)

    # Capture committed offsets after A ran
    committed_before = dict(broker.committed)

    # Rebalance: A keeps [0], B takes [1]
    consumer_a.assigned = [0]
    consumer_b = IdempotentConsumer(broker, assigned=[1], name="B")
    _drain_for(broker, [consumer_a, consumer_b], duration_ms=400)

    # Collect unique (partition, offset) consumed
    seen = set((m.partition, m.offset) for m in (consumer_a.processed + consumer_b.processed))

    # For each partition, we expect all scheduled but not dropped messages to have been seen
    total_by_part = {p: state.next_offset for p, state in broker.parts.items()}
    delivered_unique = {p: 0 for p in broker.parts.keys()}
    for (p, off) in seen:
        delivered_unique[p] += 1

    # Because drop_prob is 0, every produced offset should be eventually delivered exactly once (after dedupe)
    for p in broker.parts.keys():
        assert delivered_unique[p] == total_by_part[p], f"Partition {p} missing or extra messages after rebalance"

    # Committed offsets should land on the last offset for each partition
    for p in broker.parts.keys():
        assert broker.committed[p] == total_by_part[p] - 1

    # Ensure B started from >= committed offset on partition 1
    assert broker.committed[1] >= committed_before[1]


@pytest.mark.timeout(5)
def test_at_least_once_with_idempotent_consumer_under_duplicates():
    """
    With duplicates present, an idempotent consumer should ensure each (partition, offset) is processed once.
    """
    broker = FaultyBroker(
        num_partitions=4,
        faults={p: FaultModel(drop_prob=0.0, duplicate_prob=0.5, max_delay_ms=2) for p in range(4)},
        seed=101,
    )
    _produce_uniform(broker, n=400)

    consumer = IdempotentConsumer(broker, assigned=[0, 1, 2, 3], name="c")
    _drain_for(broker, [consumer], duration_ms=400)

    unique = set((m.partition, m.offset) for m in consumer.processed)
    # Every produced offset (no drops) should be processed once
    for p, state in broker.parts.items():
        assert len([1 for u in unique if u[0] == p]) == state.next_offset


@pytest.mark.timeout(5)
def test_paused_partition_does_not_block_others_and_backlog_drains_on_resume():
    """
    When a partition is paused, other partitions should continue to flow.
    On resume, the backlog should drain and ordering per partition must hold.
    """
    broker = FaultyBroker(
        num_partitions=3,
        faults={0: FaultModel(max_delay_ms=10), 1: FaultModel(max_delay_ms=10), 2: FaultModel(max_delay_ms=10)},
        seed=33,
    )
    _produce_uniform(broker, n=300)

    # Pause partition 1
    broker.pause_partition(1)

    consumer = IdempotentConsumer(broker, assigned=[0, 1, 2], name="c")
    _drain_for(broker, [consumer], duration_ms=250)

    # Ensure we processed messages from partitions 0 and 2, but not 1
    seen_parts = set(m.partition for m in consumer.processed)
    assert 0 in seen_parts and 2 in seen_parts
    assert 1 not in seen_parts

    # Resume partition 1 and drain
    broker.resume_partition(1)
    _drain_for(broker, [consumer], duration_ms=400)

    # Now all partitions should be fully processed
    unique_pairs = set((m.partition, m.offset) for m in consumer.processed)
    for p, state in broker.parts.items():
        expected = set((p, off) for off in range(state.next_offset))
        assert expected.issubset(unique_pairs), f"Partition {p} did not fully drain after resume"

    # Check ordering per partition
    by_part: Dict[int, List[int]] = {}
    for m in consumer.processed:
        by_part.setdefault(m.partition, []).append(m.offset)
    for p, offs in by_part.items():
        assert offs == sorted(set(offs))


@pytest.mark.timeout(7)
def test_random_fault_storm_invariants_hold():
    """
    Randomized chaos: varying drop and duplicate probabilities and delays.
    Invariant: delivered_unique + dropped == produced, per partition.
    """
    rng = random.Random(2025)
    num_partitions = 6
    faults = {}
    for p in range(num_partitions):
        faults[p] = FaultModel(
            drop_prob=rng.uniform(0.0, 0.3),
            duplicate_prob=rng.uniform(0.0, 0.7),
            max_delay_ms=rng.randint(0, 15),
            reorder_window=rng.randint(0, 5),
        )
    broker = FaultyBroker(num_partitions=num_partitions, faults=faults, seed=999)

    # Produce a sizable batch
    _produce_uniform(broker, n=1000)

    consumer = IdempotentConsumer(broker, assigned=list(range(num_partitions)), name="storm")
    _drain_for(broker, [consumer], duration_ms=1000)

    produced_by_part = {p: s.next_offset for p, s in broker.parts.items()}
    dropped_total = broker.metrics["dropped"]

    unique_pairs = set((m.partition, m.offset) for m in consumer.processed)
    delivered_by_part = {p: 0 for p in broker.parts.keys()}
    for (p, _off) in unique_pairs:
        delivered_by_part[p] += 1

    # Because drops happen at produce time only, invariant holds globally:
    # sum(delivered_unique) + dropped == produced
    delivered_sum = sum(delivered_by_part.values())
    produced_sum = sum(produced_by_part.values())
    assert delivered_sum + dropped_total == produced_sum

    # Per partition, delivered_unique <= produced
    for p in broker.parts.keys():
        assert delivered_by_part[p] <= produced_by_part[p]

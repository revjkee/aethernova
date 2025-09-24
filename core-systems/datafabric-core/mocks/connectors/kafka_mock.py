# mocks/connectors/kafka_mock.py
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Tuple

# =========================
# Messages & Exceptions
# =========================

@dataclass(frozen=True)
class RecordMetadata:
    topic: str
    partition: int
    offset: int
    timestamp_ms: int

@dataclass(frozen=True)
class ConsumerRecord:
    topic: str
    partition: int
    offset: int
    timestamp_ms: int
    key: Optional[bytes]
    value: Optional[bytes]
    headers: Tuple[Tuple[str, bytes], ...] = field(default_factory=tuple)

class KafkaMockError(Exception): ...
class TimeoutError(KafkaMockError): ...
class PartitionEOF(KafkaMockError): ...
class RebalanceInProgress(KafkaMockError): ...
class TransactionAborted(KafkaMockError): ...
class ProducerFenced(KafkaMockError): ...
class MessageDropped(KafkaMockError): ...
class LeaderNotAvailable(KafkaMockError): ...

# =========================
# Chaos / Fault injection
# =========================

@dataclass
class ChaosConfig:
    delay_ms_min: int = 0
    delay_ms_max: int = 0
    drop_probability: float = 0.0
    error_probability: float = 0.0
    leader_flap_probability: float = 0.0

    def random_delay(self) -> float:
        if self.delay_ms_max <= 0:
            return 0.0
        lo = max(0, self.delay_ms_min)
        hi = max(lo, self.delay_ms_max)
        return random.randint(lo, hi) / 1000.0

    def maybe_error(self) -> None:
        if self.error_probability > 0 and random.random() < self.error_probability:
            raise KafkaMockError("Injected random error")

    def maybe_leader_flap(self) -> None:
        if self.leader_flap_probability > 0 and random.random() < self.leader_flap_probability:
            raise LeaderNotAvailable("Injected leader flap")

    def maybe_drop(self) -> None:
        if self.drop_probability > 0 and random.random() < self.drop_probability:
            raise MessageDropped("Injected drop")

# =========================
# Broker core (in‑memory)
# =========================

@dataclass
class _Partition:
    # Log as deque for fast pops and bounded retention
    log: Deque[ConsumerRecord] = field(default_factory=deque)
    next_offset: int = 0
    cond: asyncio.Condition = field(default_factory=asyncio.Condition)  # signals new messages

@dataclass
class TopicConfig:
    partitions: int = 1
    retention_bytes: Optional[int] = None
    retention_messages: Optional[int] = None
    compaction: bool = False  # if True, keep only last record per key (log-compaction-like)

class MockKafkaBroker:
    """
    Singleton in‑memory broker. Not thread-safe; use in one asyncio loop per test.
    """
    _instance: Optional["MockKafkaBroker"] = None

    def __init__(self) -> None:
        self._topics: Dict[str, List[_Partition]] = {}
        self._topic_cfg: Dict[str, TopicConfig] = {}
        self._group_offsets: Dict[str, Dict[Tuple[str, int], int]] = defaultdict(dict)
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.chaos = ChaosConfig()

    # ---------------- Singleton ----------------
    @classmethod
    def get(cls) -> "MockKafkaBroker":
        if cls._instance is None:
            cls._instance = MockKafkaBroker()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = MockKafkaBroker()

    # ---------------- Admin ops ----------------
    async def create_topic(self, name: str, partitions: int = 1,
                           retention_bytes: Optional[int] = None,
                           retention_messages: Optional[int] = None,
                           compaction: bool = False) -> None:
        async with self._locks[name]:
            if name in self._topics:
                return
            if partitions < 1:
                raise ValueError("partitions must be >= 1")
            self._topics[name] = [ _Partition() for _ in range(partitions) ]
            self._topic_cfg[name] = TopicConfig(partitions, retention_bytes, retention_messages, compaction)

    async def delete_topic(self, name: str) -> None:
        async with self._locks[name]:
            self._topics.pop(name, None)
            self._topic_cfg.pop(name, None)

    def list_topics(self) -> List[str]:
        return list(self._topics.keys())

    def partitions_for(self, topic: str) -> int:
        cfg = self._topic_cfg.get(topic)
        return cfg.partitions if cfg else 0

    # ---------------- Produce ----------------
    async def produce(self, topic: str, key: Optional[bytes], value: Optional[bytes],
                      headers: Optional[Iterable[Tuple[str, bytes]]] = None,
                      partition: Optional[int] = None,
                      timestamp_ms: Optional[int] = None) -> RecordMetadata:
        if topic not in self._topics:
            # auto-create topic with 1 partition by default
            await self.create_topic(topic, partitions=1)

        self.chaos.maybe_leader_flap()
        self.chaos.maybe_error()
        delay = self.chaos.random_delay()
        if delay:
            await asyncio.sleep(delay)
        self.chaos.maybe_drop()  # simulate at-most-once delivery

        parts = self._topics[topic]
        if partition is None:
            # sticky partitioner imitation: use hash of key or round-robin timestamp
            if key is not None:
                partition = abs(hash(key)) % len(parts)
            else:
                partition = int(time.time_ns()) % len(parts)
        if partition < 0 or partition >= len(parts):
            raise ValueError("invalid partition")

        ts = int(time.time() * 1000) if timestamp_ms is None else int(timestamp_ms)
        p = parts[partition]

        async with p.cond:
            offset = p.next_offset
            rec = ConsumerRecord(
                topic=topic,
                partition=partition,
                offset=offset,
                timestamp_ms=ts,
                key=key,
                value=value,
                headers=tuple(headers or ()),
            )
            # append
            p.log.append(rec)
            p.next_offset += 1
            # retention (messages)
            cfg = self._topic_cfg[topic]
            if cfg.compaction and rec.key is not None:
                # naive compaction: remove older messages with same key, leaving only latest
                last_seen = None
                # reverse scan to find previous offsets for that key
                for i in range(len(p.log) - 2, -1, -1):
                    if p.log[i].key == rec.key:
                        last_seen = i
                        break
                if last_seen is not None:
                    del p.log[last_seen]
            if cfg.retention_messages:
                while len(p.log) > cfg.retention_messages:
                    p.log.popleft()
            # signal
            p.cond.notify_all()

        return RecordMetadata(topic=topic, partition=partition, offset=offset, timestamp_ms=ts)

    # ---------------- Fetch ----------------
    async def fetch(self, topic: str, partition: int, offset: int, max_records: int, timeout_ms: int) -> List[ConsumerRecord]:
        if topic not in self._topics:
            return []
        parts = self._topics[topic]
        if partition < 0 or partition >= len(parts):
            return []
        p = parts[partition]
        deadline = time.time() + (timeout_ms / 1000.0)

        async with p.cond:
            # wait until we have data or timeout
            while offset >= p.next_offset and time.time() < deadline:
                await asyncio.wait_for(p.cond.wait(), timeout=deadline - time.time())
            if offset >= p.next_offset:
                return []
            # gather up to max_records starting from offset
            res: List[ConsumerRecord] = []
            start_index = 0
            # map offset to index: since we may have dropped left of deque due to retention,
            # approximate by scanning (OK for tests). For large tests, consider index map.
            for idx, rec in enumerate(p.log):
                if rec.offset >= offset:
                    start_index = idx
                    break
            for i in range(start_index, min(len(p.log), start_index + max_records)):
                res.append(p.log[i])
            return res

    # ---------------- Offsets (group state) ----------------
    def committed(self, group_id: str, topic: str, partition: int) -> Optional[int]:
        return self._group_offsets.get(group_id, {}).get((topic, partition))

    def commit(self, group_id: str, offsets: Dict[Tuple[str, int], int]) -> None:
        g = self._group_offsets[group_id]
        for tp, off in offsets.items():
            g[tp] = off

# =========================
# Producer
# =========================

DeliveryCallback = Callable[[Optional[KafkaMockError], Optional[RecordMetadata]], Any]

class MockKafkaProducer:
    """
    Async producer API roughly similar to aiokafka.
    Supports idempotence and transactions (single producer per transactional_id).
    """

    _fences: Dict[str, int] = {}  # transactional_id -> epoch

    def __init__(self,
                 bootstrap_servers: str = "mock://broker",
                 acks: str | int = "all",
                 linger_ms: int = 0,
                 enable_idempotence: bool = True,
                 transactional_id: Optional[str] = None,
                 chaos: Optional[ChaosConfig] = None) -> None:
        self.broker = MockKafkaBroker.get()
        self.acks = acks
        self.linger_ms = max(0, int(linger_ms))
        self.enable_idempotence = enable_idempotence
        self.transactional_id = transactional_id
        self._tx_active = False
        self._tx_buffer: List[Tuple[str, Optional[bytes], Optional[bytes], Optional[Iterable[Tuple[str, bytes]]], Optional[int], Optional[int]]] = []
        self._closed = False
        self.chaos = chaos or self.broker.chaos
        self._epoch = 0

    async def start(self) -> None:
        if self.transactional_id:
            # increment epoch (fencing)
            MockKafkaProducer._fences[self.transactional_id] = MockKafkaProducer._fences.get(self.transactional_id, 0) + 1
            self._epoch = MockKafkaProducer._fences[self.transactional_id]

    async def stop(self) -> None:
        await self.flush()
        self._closed = True

    async def flush(self, timeout: Optional[float] = None) -> None:
        # in memory: nothing to flush; sleep linger to emulate batching
        if self.linger_ms:
            await asyncio.sleep(self.linger_ms / 1000.0)

    # ------------- Transactions -------------
    async def begin_transaction(self) -> None:
        if not self.transactional_id:
            raise KafkaMockError("Transactions require transactional_id")
        if self._tx_active:
            raise KafkaMockError("Transaction already active")
        # fencing check
        if MockKafkaProducer._fences.get(self.transactional_id, 0) != self._epoch:
            raise ProducerFenced("Producer fenced by newer epoch")
        self._tx_active = True
        self._tx_buffer.clear()

    async def commit_transaction(self) -> None:
        if not self._tx_active:
            raise KafkaMockError("No active transaction")
        # publish buffered messages atomically
        for args in self._tx_buffer:
            await self._produce_impl(*args)
        self._tx_buffer.clear()
        self._tx_active = False

    async def abort_transaction(self) -> None:
        if not self._tx_active:
            raise KafkaMockError("No active transaction")
        self._tx_buffer.clear()
        self._tx_active = False
        raise TransactionAborted("Transaction aborted")

    # ------------- Produce -------------
    async def send_and_wait(self, topic: str, value: Optional[bytes], key: Optional[bytes] = None,
                            headers: Optional[Iterable[Tuple[str, bytes]]] = None,
                            partition: Optional[int] = None,
                            timestamp_ms: Optional[int] = None) -> RecordMetadata:
        md = await self.send(topic, value=value, key=key, headers=headers, partition=partition, timestamp_ms=timestamp_ms)
        # emulate ack wait
        await self.flush()
        return md

    async def send(self, topic: str, value: Optional[bytes], key: Optional[bytes] = None,
                   headers: Optional[Iterable[Tuple[str, bytes]]] = None,
                   partition: Optional[int] = None,
                   timestamp_ms: Optional[int] = None,
                   on_delivery: Optional[DeliveryCallback] = None) -> RecordMetadata:
        if self._closed:
            raise KafkaMockError("Producer is closed")

        if self._tx_active:
            self._tx_buffer.append((topic, key, value, headers, partition, timestamp_ms))
            md = RecordMetadata(topic, partition if partition is not None else 0, -1, int(time.time() * 1000))
            if on_delivery:
                on_delivery(None, md)
            return md

        try:
            md = await self._produce_impl(topic, key, value, headers, partition, timestamp_ms)
            if on_delivery:
                on_delivery(None, md)
            return md
        except KafkaMockError as e:
            if on_delivery:
                on_delivery(e, None)
            raise

    async def _produce_impl(self, topic: str, key: Optional[bytes], value: Optional[bytes],
                            headers: Optional[Iterable[Tuple[str, bytes]]],
                            partition: Optional[int], timestamp_ms: Optional[int]) -> RecordMetadata:
        # linger simulation
        if self.linger_ms:
            await asyncio.sleep(self.linger_ms / 1000.0)
        # chaos
        self.chaos.maybe_error()
        self.chaos.maybe_leader_flap()
        # idempotence is a noop here since broker is local and single instance
        return await self.broker.produce(topic, key=key, value=value, headers=headers, partition=partition, timestamp_ms=timestamp_ms)

# =========================
# Consumer
# =========================

class MockKafkaConsumer:
    """
    Async consumer with subscribe/assign, poll, commits and simple rebalance.
    Offsets are per group_id and stored in broker.
    """

    def __init__(self,
                 group_id: str,
                 bootstrap_servers: str = "mock://broker",
                 enable_auto_commit: bool = True,
                 auto_offset_reset: str = "latest",  # "earliest" | "latest"
                 max_poll_records: int = 500,
                 session_timeout_ms: int = 10000,
                 chaos: Optional[ChaosConfig] = None) -> None:
        self.broker = MockKafkaBroker.get()
        self.group_id = group_id
        self.enable_auto_commit = enable_auto_commit
        self.auto_offset_reset = auto_offset_reset
        self.max_poll_records = max_poll_records
        self.session_timeout_ms = session_timeout_ms
        self._topics: List[str] = []
        self._assignment: List[Tuple[str, int]] = []
        self._next_offsets: Dict[Tuple[str, int], int] = {}
        self._closed = False
        self.chaos = chaos or self.broker.chaos
        self._rebalance_generation = 0

    async def start(self) -> None:
        # no-op
        return

    async def stop(self) -> None:
        await self.commit()
        self._closed = True

    # ---------- Subscription / assignment ----------
    async def subscribe(self, topics: Iterable[str]) -> None:
        self._topics = list(topics)
        await self._rebalance()

    async def assign(self, partitions: Iterable[Tuple[str, int]]) -> None:
        self._topics = []
        self._assignment = list(partitions)
        self._initialize_offsets()

    async def unsubscribe(self) -> None:
        self._topics = []
        self._assignment = []
        self._next_offsets.clear()

    def assignment(self) -> List[Tuple[str, int]]:
        return list(self._assignment)

    async def _rebalance(self) -> None:
        """
        Simplified: assign all partitions of subscribed topics to this consumer.
        For tests with multiple consumers, call _rebalance() on each to re‑split externally.
        """
        self._rebalance_generation += 1
        self._assignment.clear()
        for t in self._topics:
            parts = max(self.broker.partitions_for(t), 1)
            for p in range(parts):
                self._assignment.append((t, p))
        self._initialize_offsets()

    def _initialize_offsets(self) -> None:
        self._next_offsets.clear()
        for (t, p) in self._assignment:
            committed = self.broker.committed(self.group_id, t, p)
            if committed is None:
                # earliest or latest
                part = self.broker._topics.get(t, [])[p] if t in self.broker._topics and p < len(self.broker._topics[t]) else None
                if part is None or part.next_offset == 0:
                    base = 0
                else:
                    base = 0 if self.auto_offset_reset == "earliest" else part.next_offset
                self._next_offsets[(t, p)] = base
            else:
                self._next_offsets[(t, p)] = committed

    # ---------- Poll / Commit ----------
    async def poll(self, timeout_ms: int = 1000) -> List[ConsumerRecord]:
        if self._closed:
            return []
        self.chaos.maybe_error()
        self.chaos.maybe_leader_flap()
        records: List[ConsumerRecord] = []

        # Deadline for poll
        deadline = time.time() + timeout_ms / 1000.0
        remaining = lambda: max(0, int((deadline - time.time()) * 1000))

        # one fetch round over assigned tps
        for (t, p) in self._assignment:
            if time.time() > deadline:
                break
            off = self._next_offsets.get((t, p), 0)
            batch = await self.broker.fetch(t, p, off, self.max_poll_records, timeout_ms=remaining())
            if not batch:
                continue
            records.extend(batch)
            # advance offset to last + 1
            self._next_offsets[(t, p)] = batch[-1].offset + 1

        if self.enable_auto_commit and records:
            await self.commit()

        return records

    async def commit(self) -> None:
        # commit the next_offsets (which are offsets to consume next)
        if not self._next_offsets:
            return
        self.broker.commit(self.group_id, dict(self._next_offsets))

    def position(self, topic: str, partition: int) -> Optional[int]:
        return self._next_offsets.get((topic, partition))

    def committed(self, topic: str, partition: int) -> Optional[int]:
        return self.broker.committed(self.group_id, topic, partition)

# =========================
# Utility fixtures/helpers
# =========================

@asynccontextmanager
async def running_producer(**kwargs) -> Any:
    p = MockKafkaProducer(**kwargs)
    await p.start()
    try:
        yield p
    finally:
        await p.stop()

@asynccontextmanager
async def running_consumer(**kwargs) -> Any:
    c = MockKafkaConsumer(**kwargs)
    await c.start()
    try:
        yield c
    finally:
        await c.stop()

# =========================
# Example usage (manual)
# =========================
# if __name__ == "__main__":
#     async def demo():
#         broker = MockKafkaBroker.get()
#         await broker.create_topic("events", partitions=2)
#         async with running_producer(transactional_id="tx-1") as prod, running_consumer(group_id="g1") as cons:
#             await prod.begin_transaction()
#             await prod.send("events", b"v1", key=b"k1")
#             await prod.send("events", b"v2", key=b"k2")
#             await prod.commit_transaction()
#             await cons.subscribe(["events"])
#             records = await cons.poll(1000)
#             print("polled:", [(r.partition, r.offset, r.value) for r in records])
#     asyncio.run(demo())

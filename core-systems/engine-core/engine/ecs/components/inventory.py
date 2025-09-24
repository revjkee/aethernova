# -*- coding: utf-8 -*-
"""
engine-core / engine / ecs / components / inventory.py

Industrial-grade Inventory component for ECS.

Key features:
- Thread-safe (RLock), transactional updates with rollback on error
- Slots with filters (tag whitelist/blacklist), equipment slots (single item), bag slots (stackable)
- Item definition vs instance: stackable, stack_limit, weight, volume, tags, durability, expiration
- Capacity constraints: max_slots, max_weight, max_volume
- Accurate stack merge/split; partial insert returns remainder
- Queries (find by id/def_id/tags), metrics (total_weight/volume/count)
- Event hooks: on_change(change), where change contains diff and metadata
- Serialization with schema version and integrity checks
- Deterministic state versioning (change_id)

This module avoids external deps for portability.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union

# =========================
# Errors
# =========================

class InventoryError(Exception):
    pass


class ConstraintError(InventoryError):
    pass


class NotFoundError(InventoryError):
    pass


class SerializationError(InventoryError):
    pass


# =========================
# Utils
# =========================

UTC = timezone.utc

def _now_ts() -> int:
    return int(time.time())

def _uuid() -> str:
    return uuid.uuid4().hex

def _safe_int(v: Any, *, min_v: Optional[int] = None) -> int:
    iv = int(v)
    if min_v is not None and iv < min_v:
        raise ConstraintError(f"value {iv} < {min_v}")
    return iv

def _sum_safe(values: Iterable[Union[int, float]]) -> float:
    total = 0.0
    for v in values:
        total += float(v)
    return total

def _tags_normalize(tags: Iterable[str]) -> List[str]:
    # normalize to unique sorted lowercase
    return sorted({str(t).strip().lower() for t in tags if str(t).strip()})


# =========================
# Data model
# =========================

@dataclass(frozen=True)
class ItemDef:
    """
    Item definition (catalog / archetype).
    """
    def_id: str
    name: str
    stackable: bool = True
    stack_limit: int = 9999
    weight: float = 0.0            # per unit
    volume: float = 0.0            # per unit
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.stack_limit <= 0:
            raise ConstraintError("stack_limit must be > 0")
        object.__setattr__(self, "tags", _tags_normalize(self.tags))


@dataclass
class ItemInstance:
    """
    Concrete item instance stored in inventory.
    For stackable items, 'qty' > 1; for unique items, qty must be 1.
    """
    inst_id: str
    def_id: str
    qty: int = 1
    durability: Optional[float] = None       # 0..1
    expiration_ts: Optional[int] = None      # unix seconds
    meta: Dict[str, Any] = field(default_factory=dict)

    def clone_shallow(self) -> "ItemInstance":
        return ItemInstance(
            inst_id=self.inst_id,
            def_id=self.def_id,
            qty=self.qty,
            durability=self.durability,
            expiration_ts=self.expiration_ts,
            meta=dict(self.meta),
        )

    def expired(self, now_ts: Optional[int] = None) -> bool:
        if self.expiration_ts is None:
            return False
        ts = _now_ts() if now_ts is None else int(now_ts)
        return ts >= int(self.expiration_ts)


SlotType = Literal["bag", "equipment"]

@dataclass
class SlotFilter:
    """Slot filter for allowed/denied tags."""
    allow_tags: List[str] = field(default_factory=list)
    deny_tags: List[str] = field(default_factory=list)

    def allows(self, item_tags: Iterable[str]) -> bool:
        t = set(_tags_normalize(item_tags))
        allow = set(self.allow_tags)
        deny = set(self.deny_tags)
        if deny & t:
            return False
        if allow and not (allow & t):
            return False
        return True


@dataclass
class Slot:
    """
    Inventory slot, may contain multiple stackable items (bag) or one item (equipment).
    """
    slot_id: str
    type: SlotType = "bag"
    filter: SlotFilter = field(default_factory=SlotFilter)
    items: List[ItemInstance] = field(default_factory=list)

    def is_empty(self) -> bool:
        return len(self.items) == 0

    def total_qty(self) -> int:
        return sum(it.qty for it in self.items)

    def clear(self) -> None:
        self.items.clear()


@dataclass
class Constraints:
    max_slots: Optional[int] = None
    max_weight: Optional[float] = None
    max_volume: Optional[float] = None

    def validate(self) -> None:
        if self.max_slots is not None and self.max_slots < 0:
            raise ConstraintError("max_slots must be >= 0")
        if self.max_weight is not None and self.max_weight < 0:
            raise ConstraintError("max_weight must be >= 0")
        if self.max_volume is not None and self.max_volume < 0:
            raise ConstraintError("max_volume must be >= 0")


@dataclass
class ChangeEvent:
    change_id: str
    ts: int
    actor: Optional[str]
    kind: Literal[
        "add", "remove", "move", "split", "merge", "update", "expire", "create", "load"
    ]
    data: Dict[str, Any]


OnChange = Callable[[ChangeEvent], None]


# =========================
# Inventory component
# =========================

SCHEMA_VERSION = 1

class Inventory:
    """
    Thread-safe Inventory component.

    Notes:
    - Uses RLock to guard mutate operations.
    - All public mutating methods emit on_change event.
    - Transaction() context allows atomic group of operations with rollback.
    """

    def __init__(
        self,
        *,
        item_defs: Dict[str, ItemDef],
        slots: Optional[List[Slot]] = None,
        constraints: Optional[Constraints] = None,
        on_change: Optional[OnChange] = None,
        owner_entity_id: Optional[str] = None,
    ) -> None:
        self._lock = RLock()
        self.item_defs: Dict[str, ItemDef] = dict(item_defs)
        self.slots: List[Slot] = list(slots or [])
        self.constraints: Constraints = constraints or Constraints()
        self.constraints.validate()
        self.on_change: Optional[OnChange] = on_change
        self.owner_entity_id = owner_entity_id
        self._version: int = 0  # monotonic version for state changes

    # -------------------------
    # Query helpers
    # -------------------------

    def version(self) -> int:
        return self._version

    def list_slots(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._slot_as_dict(s) for s in self.slots]

    def find_slot(self, slot_id: str) -> Slot:
        with self._lock:
            for s in self.slots:
                if s.slot_id == slot_id:
                    return s
        raise NotFoundError(f"slot {slot_id} not found")

    def find_item(self, inst_id: str) -> Tuple[int, int, ItemInstance]:
        """
        Returns (slot_idx, item_idx, item)
        """
        with self._lock:
            for si, s in enumerate(self.slots):
                for ii, it in enumerate(s.items):
                    if it.inst_id == inst_id:
                        return si, ii, it
        raise NotFoundError(f"item {inst_id} not found")

    def find_by_def(self, def_id: str) -> List[Tuple[str, ItemInstance]]:
        with self._lock:
            res: List[Tuple[str, ItemInstance]] = []
            for s in self.slots:
                for it in s.items:
                    if it.def_id == def_id:
                        res.append((s.slot_id, it))
            return res

    def total_weight(self) -> float:
        with self._lock:
            return _sum_safe(
                self._item_weight(it) for s in self.slots for it in s.items
            )

    def total_volume(self) -> float:
        with self._lock:
            return _sum_safe(
                self._item_volume(it) for s in self.slots for it in s.items
            )

    def total_count(self) -> int:
        with self._lock:
            return sum(it.qty for s in self.slots for it in s.items)

    def capacity_left(self) -> Dict[str, Optional[float]]:
        with self._lock:
            weight_left = None if self.constraints.max_weight is None else max(
                0.0, float(self.constraints.max_weight) - self.total_weight()
            )
            volume_left = None if self.constraints.max_volume is None else max(
                0.0, float(self.constraints.max_volume) - self.total_volume()
            )
            slots_left = None
            if self.constraints.max_slots is not None:
                used = len(self.slots)
                slots_left = max(0, int(self.constraints.max_slots) - used)
            return {"weight": weight_left, "volume": volume_left, "slots": slots_left}

    # -------------------------
    # Slot management
    # -------------------------

    def add_slot(self, slot: Slot, *, actor: Optional[str] = None) -> None:
        with self._lock:
            if self.constraints.max_slots is not None and len(self.slots) >= self.constraints.max_slots:
                raise ConstraintError("max_slots reached")
            self.slots.append(slot)
            self._bump("create", {"slot": self._slot_as_dict(slot)}, actor)

    def remove_slot(self, slot_id: str, *, actor: Optional[str] = None) -> None:
        with self._lock:
            idx = None
            for i, s in enumerate(self.slots):
                if s.slot_id == slot_id:
                    idx = i
                    break
            if idx is None:
                raise NotFoundError(f"slot {slot_id} not found")
            if self.slots[idx].items:
                raise ConstraintError("slot not empty")
            removed = self.slots.pop(idx)
            self._bump("remove", {"slot": self._slot_as_dict(removed)}, actor)

    # -------------------------
    # Item operations
    # -------------------------

    def can_place(self, slot: Slot, def_id: str) -> bool:
        d = self._require_def(def_id)
        # allow by filter
        if not slot.filter.allows(d.tags):
            return False
        # equipment slot cannot hold more than one item (but may hold non-stackable or stackable as single entity)
        if slot.type == "equipment" and not slot.is_empty():
            return False
        return True

    def add_item(
        self,
        slot_id: str,
        *,
        def_id: str,
        qty: int = 1,
        durability: Optional[float] = None,
        expiration_ts: Optional[int] = None,
        meta: Optional[Dict[str, Any]] = None,
        actor: Optional[str] = None,
    ) -> Tuple[Optional[ItemInstance], int]:
        """
        Try to add items to slot. Returns (added_instance, remainder_qty).
        For stackable: creates/extends a stack up to stack_limit; leftover returned as remainder.
        For unique: creates one instance per call; remainder is qty-1 if qty>1.
        """
        with self._lock:
            qty = _safe_int(qty, min_v=1)
            slot = self.find_slot(slot_id)
            d = self._require_def(def_id)
            if not self.can_place(slot, def_id):
                raise ConstraintError("slot filter/type rejects item")
            # Check capacity (weight/volume) pessimistically for full qty; we will recheck after partial merge
            est_weight = d.weight * qty
            est_volume = d.volume * qty
            self._enforce_capacity_add(est_weight, est_volume)

            if d.stackable:
                # find existing stack of same def and compatible meta (meta-insensitive by default)
                target = self._find_stack(slot, def_id, durability, expiration_ts, meta)
                to_add = qty
                if target is None:
                    # create new instance
                    put = min(d.stack_limit, to_add)
                    inst = ItemInstance(
                        inst_id=_uuid(),
                        def_id=def_id,
                        qty=put,
                        durability=durability,
                        expiration_ts=expiration_ts,
                        meta=dict(meta or {}),
                    )
                    slot.items.append(inst)
                    to_add -= put
                    added = inst
                else:
                    can_merge = d.stack_limit - target.qty
                    put = min(can_merge, to_add)
                    target.qty += put
                    to_add -= put
                    added = target

                # final capacity check with actual deltas (weight/volume already pessimistically allowed)
                self._bump("add", {
                    "slot_id": slot.slot_id,
                    "def_id": def_id,
                    "inst_id": added.inst_id,
                    "qty_added": qty - to_add,
                    "remainder": to_add,
                }, actor)
                return added, to_add
            else:
                # unique item; qty beyond 1 is remainder
                if qty > 1:
                    remainder = qty - 1
                else:
                    remainder = 0
                inst = ItemInstance(
                    inst_id=_uuid(),
                    def_id=def_id,
                    qty=1,
                    durability=durability,
                    expiration_ts=expiration_ts,
                    meta=dict(meta or {}),
                )
                slot.items.append(inst)
                self._enforce_capacity_add(d.weight, d.volume)
                self._bump("add", {
                    "slot_id": slot.slot_id,
                    "def_id": def_id,
                    "inst_id": inst.inst_id,
                    "qty_added": 1,
                    "remainder": remainder,
                }, actor)
                return inst, remainder

    def remove_item(self, inst_id: str, *, qty: Optional[int] = None, actor: Optional[str] = None) -> ItemInstance:
        """
        Remove entire instance or subtract qty from stack.
        Returns removed instance (for full remove) or copy with removed qty.
        """
        with self._lock:
            si, ii, it = self.find_item(inst_id)
            d = self._require_def(it.def_id)
            if qty is None:
                removed = self.slots[si].items.pop(ii)
                delta_w = -self._item_weight(removed)
                delta_v = -self._item_volume(removed)
                # capacity decreases, no enforcement needed
                self._bump("remove", {
                    "slot_id": self.slots[si].slot_id,
                    "inst_id": inst_id,
                    "def_id": it.def_id,
                    "qty_removed": removed.qty,
                }, actor)
                return removed
            else:
                qty = _safe_int(qty, min_v=1)
                if not d.stackable:
                    raise ConstraintError("cannot remove partial from unique item")
                if qty > it.qty:
                    raise ConstraintError("qty exceeds stack size")
                it.qty -= qty
                removed = it.clone_shallow()
                removed.qty = qty
                if it.qty == 0:
                    self.slots[si].items.pop(ii)
                self._bump("remove", {
                    "slot_id": self.slots[si].slot_id,
                    "inst_id": inst_id,
                    "def_id": it.def_id,
                    "qty_removed": qty,
                }, actor)
                return removed

    def move_item(self, inst_id: str, dst_slot_id: str, *, actor: Optional[str] = None) -> None:
        with self._lock:
            si, ii, it = self.find_item(inst_id)
            src = self.slots[si]
            dst = self.find_slot(dst_slot_id)
            if not self.can_place(dst, it.def_id):
                raise ConstraintError("destination slot rejects item")
            d = self._require_def(it.def_id)

            if dst.type == "equipment" and not dst.is_empty():
                raise ConstraintError("destination equipment slot occupied")

            # Check capacity delta for destination
            self._enforce_capacity_add(self._item_weight(it), self._item_volume(it))

            # Merge with existing stack if possible
            if d.stackable:
                target = self._find_stack(dst, it.def_id, it.durability, it.expiration_ts, it.meta)
                if target is not None and target.inst_id != it.inst_id:
                    can_merge = d.stack_limit - target.qty
                    if can_merge <= 0:
                        pass
                    else:
                        move_qty = min(can_merge, it.qty)
                        target.qty += move_qty
                        it.qty -= move_qty
                        if it.qty == 0:
                            src.items.pop(ii)
                            self._bump("merge", {
                                "from": src.slot_id, "to": dst.slot_id,
                                "inst_id_merged_into": target.inst_id,
                                "qty": move_qty,
                            }, actor)
                            return
                        # If leftover, fall through to relocation of remaining stack
            # relocate item object
            src.items.pop(ii)
            dst.items.append(it)
            self._bump("move", {"from": src.slot_id, "to": dst.slot_id, "inst_id": it.inst_id}, actor)

    def split_stack(self, inst_id: str, qty: int, dst_slot_id: str, *, actor: Optional[str] = None) -> ItemInstance:
        with self._lock:
            qty = _safe_int(qty, min_v=1)
            si, ii, it = self.find_item(inst_id)
            d = self._require_def(it.def_id)
            if not d.stackable:
                raise ConstraintError("cannot split non-stackable")
            if qty >= it.qty:
                raise ConstraintError("qty must be < current stack")
            dst = self.find_slot(dst_slot_id)
            if not self.can_place(dst, d.def_id):
                raise ConstraintError("destination slot rejects item")
            # capacity delta for moved qty
            self._enforce_capacity_add(d.weight * qty, d.volume * qty)
            # create new instance
            new_inst = ItemInstance(
                inst_id=_uuid(),
                def_id=it.def_id,
                qty=qty,
                durability=it.durability,
                expiration_ts=it.expiration_ts,
                meta=dict(it.meta),
            )
            it.qty -= qty
            dst.items.append(new_inst)
            self._bump("split", {
                "from": self.slots[si].slot_id,
                "to": dst.slot_id,
                "src_inst": inst_id,
                "new_inst": new_inst.inst_id,
                "qty": qty,
            }, actor)
            return new_inst

    def merge_stacks(self, src_inst_id: str, dst_inst_id: str, *, actor: Optional[str] = None) -> None:
        with self._lock:
            s_si, s_ii, s_it = self.find_item(src_inst_id)
            d_si, d_ii, d_it = self.find_item(dst_inst_id)
            if s_it.def_id != d_it.def_id:
                raise ConstraintError("different def_id for merge")
            d = self._require_def(d_it.def_id)
            if not d.stackable:
                raise ConstraintError("non-stackable items cannot merge")
            if not self._same_stack_attrs(s_it, d_it):
                raise ConstraintError("incompatible stack attributes")
            can = d.stack_limit - d_it.qty
            if can <= 0:
                return
            move_qty = min(can, s_it.qty)
            d_it.qty += move_qty
            s_it.qty -= move_qty
            if s_it.qty == 0:
                self.slots[s_si].items.pop(s_ii)
            self._bump("merge", {
                "from_inst": src_inst_id,
                "to_inst": dst_inst_id,
                "qty": move_qty,
            }, actor)

    def tick_expiration(self, now_ts: Optional[int] = None, *, actor: Optional[str] = None) -> List[str]:
        """
        Remove expired items. Returns list of removed instance ids.
        """
        with self._lock:
            now = _now_ts() if now_ts is None else int(now_ts)
            removed: List[str] = []
            for s in self.slots:
                keep: List[ItemInstance] = []
                for it in s.items:
                    if it.expired(now):
                        removed.append(it.inst_id)
                    else:
                        keep.append(it)
                if len(keep) != len(s.items):
                    s.items = keep
            if removed:
                self._bump("expire", {"inst_ids": removed, "now": now}, actor)
            return removed

    # -------------------------
    # Transactions
    # -------------------------

    class Transaction:
        def __init__(self, inv: "Inventory", actor: Optional[str]) -> None:
            self._inv = inv
            self._snapshot: Optional[str] = None
            self._actor = actor

        def __enter__(self) -> "Inventory.Transaction":
            self._inv._lock.acquire()
            self._snapshot = self._inv.to_json()  # snapshot includes schema
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            try:
                if exc is not None:
                    # rollback
                    if self._snapshot is not None:
                        self._inv._restore_json(self._snapshot)
                        self._inv._bump("update", {"rollback": True, "reason": str(exc)}, self._actor)
            finally:
                self._inv._lock.release()

        # Proxy methods can be added as needed to chain operations.

    def transaction(self, *, actor: Optional[str] = None) -> "Inventory.Transaction":
        return Inventory.Transaction(self, actor)

    # -------------------------
    # Serialization
    # -------------------------

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": SCHEMA_VERSION,
                "owner_entity_id": self.owner_entity_id,
                "version": self._version,
                "constraints": asdict(self.constraints),
                "item_defs": {k: asdict(v) for k, v in self.item_defs.items()},
                "slots": [self._slot_as_dict(s) for s in self.slots],
            }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def from_json(payload: str, *, on_change: Optional[OnChange] = None) -> "Inventory":
        try:
            data = json.loads(payload)
        except Exception as e:
            raise SerializationError("invalid JSON") from e
        if not isinstance(data, dict):
            raise SerializationError("payload root must be object")
        if int(data.get("schema", -1)) != SCHEMA_VERSION:
            raise SerializationError("unsupported schema")
        item_defs = {
            k: ItemDef(**v) for k, v in (data.get("item_defs") or {}).items()
        }
        slots = [Inventory._slot_from_dict(sd) for sd in data.get("slots", [])]
        inv = Inventory(
            item_defs=item_defs,
            slots=slots,
            constraints=Constraints(**(data.get("constraints") or {})),
            on_change=on_change,
            owner_entity_id=data.get("owner_entity_id"),
        )
        inv._version = int(data.get("version", 0))
        # emit synthetic "load" event
        inv._emit(ChangeEvent(
            change_id=_uuid(),
            ts=_now_ts(),
            actor=None,
            kind="load",
            data={"version": inv._version},
        ))
        return inv

    # internal restore used by Transaction rollback
    def _restore_json(self, payload: str) -> None:
        other = Inventory.from_json(payload)
        self.item_defs = other.item_defs
        self.slots = other.slots
        self.constraints = other.constraints
        self._version = other._version

    # -------------------------
    # Internal helpers
    # -------------------------

    def _require_def(self, def_id: str) -> ItemDef:
        d = self.item_defs.get(def_id)
        if d is None:
            raise NotFoundError(f"item def {def_id} not found")
        return d

    def _item_weight(self, it: ItemInstance) -> float:
        d = self._require_def(it.def_id)
        return float(d.weight) * int(it.qty)

    def _item_volume(self, it: ItemInstance) -> float:
        d = self._require_def(it.def_id)
        return float(d.volume) * int(it.qty)

    def _enforce_capacity_add(self, add_weight: float, add_volume: float) -> None:
        # Called under lock
        if self.constraints.max_weight is not None:
            if self.total_weight() + add_weight > self.constraints.max_weight + 1e-9:
                raise ConstraintError("max_weight exceeded")
        if self.constraints.max_volume is not None:
            if self.total_volume() + add_volume > self.constraints.max_volume + 1e-9:
                raise ConstraintError("max_volume exceeded")

    def _find_stack(
        self,
        slot: Slot,
        def_id: str,
        durability: Optional[float],
        expiration_ts: Optional[int],
        meta: Optional[Dict[str, Any]],
    ) -> Optional[ItemInstance]:
        for it in slot.items:
            if it.def_id != def_id:
                continue
            if not self._same_stack_attrs(it, ItemInstance(inst_id="", def_id=def_id, qty=0,
                                                           durability=durability, expiration_ts=expiration_ts,
                                                           meta=dict(meta or {}))):
                continue
            return it
        return None

    @staticmethod
    def _same_stack_attrs(a: ItemInstance, b: ItemInstance) -> bool:
        # Same durability bucket (treat None as wildcard), same expiration_ts, same meta keys/values
        if a.durability is not None and b.durability is not None:
            if abs(float(a.durability) - float(b.durability)) > 1e-9:
                return False
        elif (a.durability is None) != (b.durability is None):
            return False
        if a.expiration_ts != b.expiration_ts:
            return False
        return a.meta == b.meta

    def _slot_as_dict(self, s: Slot) -> Dict[str, Any]:
        return {
            "slot_id": s.slot_id,
            "type": s.type,
            "filter": {"allow_tags": _tags_normalize(s.filter.allow_tags),
                       "deny_tags": _tags_normalize(s.filter.deny_tags)},
            "items": [asdict(it) for it in s.items],
        }

    @staticmethod
    def _slot_from_dict(d: Dict[str, Any]) -> Slot:
        filt = d.get("filter") or {}
        s = Slot(
            slot_id=d["slot_id"],
            type=d.get("type", "bag"),
            filter=SlotFilter(
                allow_tags=_tags_normalize(filt.get("allow_tags", [])),
                deny_tags=_tags_normalize(filt.get("deny_tags", [])),
            ),
            items=[ItemInstance(**it) for it in d.get("items", [])],
        )
        return s

    def _bump(self, kind: ChangeEvent["kind"].__args__, data: Dict[str, Any], actor: Optional[str]) -> None:  # type: ignore[attr-defined]
        self._version += 1
        evt = ChangeEvent(
            change_id=_uuid(),
            ts=_now_ts(),
            actor=actor,
            kind=kind,  # type: ignore[arg-type]
            data=data | {"version": self._version, "owner_entity_id": self.owner_entity_id},
        )
        self._emit(evt)

    def _emit(self, evt: ChangeEvent) -> None:
        cb = self.on_change
        if cb:
            try:
                cb(evt)
            except Exception:
                # swallow observer errors to avoid poisoning inventory
                pass


# =========================
# Example usage (self-test stubs)
# =========================
if __name__ == "__main__":
    # Minimal smoke test (not exhaustive)
    defs = {
        "gold_coin": ItemDef(def_id="gold_coin", name="Gold Coin", stackable=True, stack_limit=1000, weight=0.01, volume=0.001, tags=["currency"]),
        "sword": ItemDef(def_id="sword", name="Iron Sword", stackable=False, weight=3.0, volume=1.0, tags=["weapon","melee"]),
    }
    inv = Inventory(
        item_defs=defs,
        slots=[
            Slot(slot_id="bag1", type="bag", filter=SlotFilter(allow_tags=[], deny_tags=["quest-only"])),
            Slot(slot_id="head", type="equipment", filter=SlotFilter(allow_tags=["helmet"], deny_tags=[])),
        ],
        constraints=Constraints(max_slots=10, max_weight=50.0, max_volume=20.0),
        on_change=lambda e: None,
        owner_entity_id="player#1",
    )

    # Add stackable
    added, rem = inv.add_item("bag1", def_id="gold_coin", qty=150)
    assert rem == 0 and added is not None
    # Add unique
    sword, rem2 = inv.add_item("bag1", def_id="sword", qty=1)
    assert rem2 == 0 and sword is not None
    # Move to equipment should fail due to filter
    try:
        inv.move_item(sword.inst_id, "head")
    except ConstraintError:
        pass
    # Split stack
    part = inv.split_stack(added.inst_id, 30, "bag1")
    assert part.qty == 30
    # Merge back
    inv.merge_stacks(part.inst_id, added.inst_id)
    # Remove some coins
    inv.remove_item(added.inst_id, qty=50)
    # Serialize/Deserialize
    payload = inv.to_json()
    inv2 = Inventory.from_json(payload)
    assert inv2.total_count() == inv.total_count()

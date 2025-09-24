//! Transaction Pool (txpool) for Aethernova chain node.
//!
//! Features:
//! - Thread-safe TxPool with priority scheduling by effective_tip
//! - Per-account nonce tracking and replacement-by-fee policy
//! - Batch selection for block building with gas/size limits
//! - Eviction policies (capacity, per-sender caps)
//! - Pluggable validation and metrics via traits
//! - Event stream for pool mutations
//! - Snapshots for observability/debugging
//!
//! Notes:
//! - This is an industrial-grade baseline with careful error handling.
//! - Integrate chain-specific validation/price rules via `TxValidator`.
//! - Integrate metrics via `TxPoolMetrics`.
//!
//! (c) Aethernova

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet},
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use parking_lot::RwLock;
use tokio::sync::broadcast;

/// Unique transaction identifier.
/// Replace with actual hash type from your crypto module.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct TxId(pub [u8; 32]);

/// Minimal address type (20 bytes typical for EVM-like chains).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Address(pub [u8; 20]);

/// Basic 256-bit quantity using u128 pair to avoid external deps.
/// Replace with U256 from your primitives if available.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    pub const ZERO: U256 = U256 { hi: 0, lo: 0 };
    pub fn from_u128(v: u128) -> Self {
        Self { hi: 0, lo: v }
    }
    pub fn saturating_add(self, rhs: Self) -> Self {
        let (lo, carry) = self.lo.overflowing_add(rhs.lo);
        let hi = self.hi.saturating_add(rhs.hi).saturating_add(if carry { 1 } else { 0 });
        Self { hi, lo }
    }
    pub fn saturating_sub(self, rhs: Self) -> Self {
        let (lo, borrow) = self.lo.overflowing_sub(rhs.lo);
        let hi = self.hi.saturating_sub(rhs.hi).saturating_sub(if borrow { 1 } else { 0 });
        Self { hi, lo }
    }
    pub fn is_zero(&self) -> bool {
        self.hi == 0 && self.lo == 0
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hi.cmp(&other.hi) {
            Ordering::Equal => self.lo.cmp(&other.lo),
            x => x,
        }
    }
}
impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hi == 0 {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "U256({}:{})", self.hi, self.lo)
        }
    }
}

/// Transaction representation required by the pool.
/// Extend with chain-specific fields as needed.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub id: TxId,
    pub sender: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    /// Base max fee per gas (ceiling).
    pub max_fee_per_gas: U256,
    /// Priority tip per gas paid to block producer.
    pub max_priority_fee_per_gas: U256,
    /// Optional: size in bytes used for block packing limits.
    pub size_bytes: u32,
    /// Arbitrary payload cost estimator hook.
    pub created_at: SystemTime,
}

impl Transaction {
    /// Effective tip used for prioritization (simplified).
    /// In chain integration, clamp by current base fee if applicable.
    pub fn effective_tip(&self, base_fee: Option<U256>) -> U256 {
        // tip = min(max_priority_fee, max_fee - base_fee). Here we don’t know base_fee => use max_priority_fee if base_fee absent
        match base_fee {
            Some(bf) => {
                let cap = if self.max_fee_per_gas > bf {
                    self.max_fee_per_gas.saturating_sub(bf)
                } else {
                    U256::ZERO
                };
                if self.max_priority_fee_per_gas < cap {
                    self.max_priority_fee_per_gas
                } else {
                    cap
                }
            }
            None => self.max_priority_fee_per_gas,
        }
    }
}

/// Errors emitted by TxPool.
#[derive(thiserror::Error, Debug)]
pub enum TxPoolError {
    #[error("transaction already exists: {0:?}")]
    AlreadyExists(TxId),
    #[error("nonce gap for sender {sender:?}: expected {expected}, got {got}")]
    NonceGap { sender: Address, expected: u64, got: u64 },
    #[error("replacement not allowed (id={existing:?}) - tip increase too low")]
    ReplacementTooLow { existing: TxId },
    #[error("pool capacity exceeded")]
    CapacityExceeded,
    #[error("per-sender capacity exceeded for {0:?}")]
    PerSenderLimit(Address),
    #[error("invalid transaction: {0}")]
    Invalid(String),
    #[error("not found: {0:?}")]
    NotFound(TxId),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Pool configuration.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Max total transactions in pool.
    pub soft_capacity: usize,
    /// Hard cap (beyond this, insertion fails immediately).
    pub hard_capacity: usize,
    /// Max transactions per sender kept in pool.
    pub per_sender_limit: usize,
    /// Minimal required bump factor for replacement (e.g., 10% => 1.1x).
    pub replace_bump_numerator: u32,  // e.g., 110
    pub replace_bump_denominator: u32, // e.g., 100
    /// Default base fee for effective_tip calc if chain base fee is unknown here.
    pub default_base_fee: Option<U256>,
    /// Block selection constraints.
    pub max_block_gas: u64,
    pub max_block_bytes: u64,
    /// Broadcast channel capacity for events.
    pub event_channel_capacity: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            soft_capacity: 100_000,
            hard_capacity: 120_000,
            per_sender_limit: 1024,
            replace_bump_numerator: 110,
            replace_bump_denominator: 100,
            default_base_fee: None,
            max_block_gas: 30_000_000,
            max_block_bytes: 5_000_000,
            event_channel_capacity: 512,
        }
    }
}

/// Pool events.
#[derive(Clone, Debug)]
pub enum PoolEvent {
    Inserted(TxId),
    Replaced { old: TxId, new: TxId },
    Evicted(TxId),
    RemovedIncluded(TxId),
    RemovedInvalid(TxId),
}

/// Pluggable validator to enforce chain-specific rules.
pub trait TxValidator: Send + Sync + 'static {
    fn validate(&self, tx: &Transaction) -> Result<(), TxPoolError>;
    /// For nonce expectations (e.g., from state), return the next expected nonce for sender.
    fn expected_nonce(&self, sender: Address) -> Result<u64, TxPoolError>;
    /// Optional check before block packing; default is ok.
    fn can_pack(&self, _tx: &Transaction) -> Result<(), TxPoolError> {
        Ok(())
    }
}

/// Pluggable metrics recorder.
pub trait TxPoolMetrics: Send + Sync + 'static {
    fn inc_inserted(&self);
    fn inc_replaced(&self);
    fn inc_evicted(&self);
    fn inc_removed_included(&self);
    fn inc_removed_invalid(&self);
    fn gauge_size(&self, size: usize);
}

/// No-op metrics for defaults.
#[derive(Default)]
pub struct NoopMetrics;
impl TxPoolMetrics for NoopMetrics {
    fn inc_inserted(&self) {}
    fn inc_replaced(&self) {}
    fn inc_evicted(&self) {}
    fn inc_removed_included(&self) {}
    fn inc_removed_invalid(&self) {}
    fn gauge_size(&self, _size: usize) {}
}

/// Internal pool entry maintained in priority queues.
#[derive(Clone, Debug)]
struct PoolEntry {
    tx: Arc<Transaction>,
    /// Cached priority (effective tip) for fast ordering.
    prio: U256,
}

impl PoolEntry {
    fn new(tx: Arc<Transaction>, base_fee: Option<U256>) -> Self {
        let prio = tx.effective_tip(base_fee);
        Self { tx, prio }
    }
}

/// Max-heap by `prio`, then FIFO by created_at (older first to avoid starvation).
#[derive(Clone, Debug)]
struct PrioEntry {
    prio: U256,
    created_at: SystemTime,
    id: TxId,
}

impl PartialEq for PrioEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for PrioEntry {}

impl PartialOrd for PrioEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PrioEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prio.cmp(&other.prio) {
            Ordering::Equal => other.created_at.cmp(&self.created_at), // older first => reverse
            x => x,
        }
    }
}

/// Core pool state protected by RwLock.
struct PoolState {
    // Storage:
    by_id: HashMap<TxId, PoolEntry>,
    // Priority queue for global selection:
    heap: BinaryHeap<PrioEntry>,
    // Per-sender nonce map (nonce -> txid), and a set of nonces:
    by_sender_nonce: HashMap<Address, BTreeMap<u64, TxId>>,
    // Per-sender counts for eviction policy:
    per_sender_counts: HashMap<Address, usize>,
    // Index: tx size and gas for packing limits:
    gas_of: HashMap<TxId, u64>,
    size_of: HashMap<TxId, u32>,
    // For quick removal from heap, keep a tombstone set:
    tombstones: HashSet<TxId>,
}

impl PoolState {
    fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            heap: BinaryHeap::new(),
            by_sender_nonce: HashMap::new(),
            per_sender_counts: HashMap::new(),
            gas_of: HashMap::new(),
            size_of: HashMap::new(),
            tombstones: HashSet::new(),
        }
    }

    fn size(&self) -> usize {
        self.by_id.len()
    }
}

/// Public TxPool handle.
pub struct TxPool {
    cfg: PoolConfig,
    validator: Arc<dyn TxValidator>,
    metrics: Arc<dyn TxPoolMetrics>,
    state: RwLock<PoolState>,
    events_tx: broadcast::Sender<PoolEvent>,
}

impl fmt::Debug for TxPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxPool")
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl TxPool {
    pub fn new(cfg: PoolConfig, validator: Arc<dyn TxValidator>, metrics: Arc<dyn TxPoolMetrics>) -> Arc<Self> {
        let (tx, _) = broadcast::channel(cfg.event_channel_capacity);
        Arc::new(Self {
            cfg,
            validator,
            metrics,
            state: RwLock::new(PoolState::new()),
            events_tx: tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PoolEvent> {
        self.events_tx.subscribe()
    }

    /// Insert or replace a transaction.
    pub fn insert(&self, tx: Transaction) -> Result<(), TxPoolError> {
        self.validator.validate(&tx)?;

        let mut st = self.state.write();
        if st.by_id.contains_key(&tx.id) {
            return Err(TxPoolError::AlreadyExists(tx.id));
        }

        // Per-sender policy and nonce continuity.
        let expected_nonce = self.validator.expected_nonce(tx.sender)?;
        if tx.nonce < expected_nonce {
            return Err(TxPoolError::Invalid(format!(
                "stale nonce: got {}, expected >= {}",
                tx.nonce, expected_nonce
            )));
        }

        // Handle replacement if same (sender, nonce) exists.
        if let Some(existing_id) = st.by_sender_nonce
            .entry(tx.sender)
            .or_default()
            .get(&tx.nonce)
            .cloned()
        {
            // Compare tips for replacement policy.
            let base_fee = self.cfg.default_base_fee;
            let new_tip = tx.effective_tip(base_fee);
            let existing_tip = st.by_id.get(&existing_id).map(|e| e.prio).ok_or_else(|| {
                TxPoolError::Internal("index desync on replacement".into())
            })?;

            // require new_tip >= existing_tip * bump_factor
            let num = self.cfg.replace_bump_numerator as u128;
            let den = self.cfg.replace_bump_denominator as u128;

            // Compare via multiplication to avoid division on U256.
            let lhs_hi = existing_tip.hi.saturating_mul(num);
            let lhs_lo = existing_tip.lo.saturating_mul(num);
            let lhs = U256 { hi: lhs_hi, lo: lhs_lo };

            let rhs_hi = new_tip.hi.saturating_mul(den);
            let rhs_lo = new_tip.lo.saturating_mul(den);
            let rhs = U256 { hi: rhs_hi, lo: rhs_lo };

            if rhs < lhs {
                return Err(TxPoolError::ReplacementTooLow { existing: existing_id });
            }

            // Remove existing, then insert new.
            self.remove_locked(&mut st, existing_id, PoolEvent::Replaced { old: existing_id, new: tx.id });
        } else {
            // If nonce gap, prevent insertion (enforce continuity starting from expected_nonce).
            if tx.nonce > expected_nonce {
                return Err(TxPoolError::NonceGap { sender: tx.sender, expected: expected_nonce, got: tx.nonce });
            }
        }

        // Capacity checks.
        if st.size() >= self.cfg.hard_capacity {
            return Err(TxPoolError::CapacityExceeded);
        }
        // Per-sender cap:
        let cnt = st.per_sender_counts.get(&tx.sender).cloned().unwrap_or(0);
        if cnt >= self.cfg.per_sender_limit {
            return Err(TxPoolError::PerSenderLimit(tx.sender));
        }

        // Insert.
        let tx_arc = Arc::new(tx);
        let entry = PoolEntry::new(tx_arc.clone(), self.cfg.default_base_fee);
        st.gas_of.insert(tx_arc.id, tx_arc.gas_limit);
        st.size_of.insert(tx_arc.id, tx_arc.size_bytes);
        st.by_id.insert(tx_arc.id, entry.clone());
        st.by_sender_nonce.entry(tx_arc.sender).or_default().insert(tx_arc.nonce, tx_arc.id);
        st.per_sender_counts.insert(tx_arc.sender, cnt + 1);
        st.heap.push(PrioEntry { prio: entry.prio, created_at: tx_arc.created_at, id: tx_arc.id });

        self.metrics.inc_inserted();
        self.metrics.gauge_size(st.size());
        let _ = self.events_tx.send(PoolEvent::Inserted(tx_arc.id));

        // Soft capacity eviction (LIFO lowest prio).
        self.enforce_soft_capacity_locked(&mut st);

        Ok(())
    }

    /// Remove transaction by id (invalidated or included).
    pub fn remove(&self, id: TxId, reason: PoolEvent) -> Result<(), TxPoolError> {
        let mut st = self.state.write();
        self.remove_locked(&mut st, id, reason);
        Ok(())
    }

    /// Select a batch for block building under gas/bytes constraints.
    /// Enforces per-account nonce order and validator.can_pack().
    pub fn select_block_batch(&self) -> Vec<Arc<Transaction>> {
        let mut st = self.state.write();

        let mut selected = Vec::new();
        let mut used_gas: u64 = 0;
        let mut used_bytes: u64 = 0;

        // Track which (sender, next_nonce) we expect as we select
        let mut next_nonce: HashMap<Address, u64> = HashMap::new();

        // We pop from heap but must respect tombstones and nonce order.
        let mut popped: Vec<PrioEntry> = Vec::new();

        while let Some(pe) = st.heap.pop() {
            if st.tombstones.contains(&pe.id) {
                continue;
            }
            let Some(entry) = st.by_id.get(&pe.id) else {
                // stale heap entry
                continue;
            };
            let tx = entry.tx.clone();

            // Per-account nonce gating:
            let expected = *next_nonce.entry(tx.sender).or_insert_with(|| {
                // initial expected is the smallest nonce present for this sender not yet selected,
                // but we also must align with validator.expected_nonce if lower.
                // For packing, start from minimal present in pool or validator state, whichever is larger.
                // Here we choose validator expected, and rely on pool's continuity.
                self.validator.expected_nonce(tx.sender).unwrap_or(tx.nonce)
            });

            if tx.nonce != expected {
                // Cannot pack this yet; keep aside and continue.
                popped.push(pe);
                continue;
            }

            // Check chain-specific packing predicate:
            if let Err(_) = self.validator.can_pack(&tx) {
                // Skip un-packable tx for now; do not remove from pool, just defer.
                popped.push(pe);
                continue;
            }

            // Check limits:
            let gas = st.gas_of.get(&tx.id).cloned().unwrap_or(tx.gas_limit);
            let sz = st.size_of.get(&tx.id).cloned().unwrap_or(tx.size_bytes) as u64;

            if used_gas.saturating_add(gas) > self.cfg.max_block_gas ||
               used_bytes.saturating_add(sz) > self.cfg.max_block_bytes {
                // Can't fit; defer this tx, try next.
                popped.push(pe);
                continue;
            }

            // Accept:
            used_gas = used_gas.saturating_add(gas);
            used_bytes = used_bytes.saturating_add(sz);
            selected.push(tx.clone());

            // Advance expected nonce for this sender
            *next_nonce.get_mut(&tx.sender).unwrap() = expected + 1;

            // Mark as tombstone; will be removed when included/committed by caller.
            st.tombstones.insert(tx.id);
        }

        // Return deferred entries to heap to preserve priority order.
        for e in popped {
            st.heap.push(e);
        }

        selected
    }

    /// Mark list of included transactions to be removed from pool.
    /// Use `PoolEvent::RemovedIncluded` to signal downstream.
    pub fn mark_included(&self, ids: &[TxId]) {
        let mut st = self.state.write();
        for id in ids {
            if st.by_id.contains_key(id) {
                self.remove_locked(&mut st, *id, PoolEvent::RemovedIncluded(*id));
            }
        }
    }

    /// Snapshot of current pool for diagnostics.
    pub fn snapshot(&self, limit: usize) -> TxPoolSnapshot {
        let st = self.state.read();
        let mut txs: Vec<_> = st
            .by_id
            .values()
            .map(|e| TxSnapshotEntry {
                id: e.tx.id,
                sender: e.tx.sender,
                nonce: e.tx.nonce,
                gas_limit: e.tx.gas_limit,
                size_bytes: e.tx.size_bytes,
                prio: e.prio,
                created_at: e.tx.created_at,
            })
            .collect();

        // Sort by priority desc, created_at asc
        txs.sort_by(|a, b| match b.prio.cmp(&a.prio) {
            Ordering::Equal => a.created_at.cmp(&b.created_at),
            x => x,
        });

        if txs.len() > limit {
            txs.truncate(limit);
        }

        TxPoolSnapshot {
            total: st.size(),
            senders: st.per_sender_counts.clone(),
            txs,
        }
    }

    /// Internal removal: updates all indices and notifies.
    fn remove_locked(&self, st: &mut PoolState, id: TxId, reason: PoolEvent) {
        if let Some(entry) = st.by_id.remove(&id) {
            // indices
            st.gas_of.remove(&id);
            st.size_of.remove(&id);
            st.tombstones.insert(id);

            if let Some(nmap) = st.by_sender_nonce.get_mut(&entry.tx.sender) {
                nmap.retain(|_, v| v != &id);
                if nmap.is_empty() {
                    st.by_sender_nonce.remove(&entry.tx.sender);
                }
            }
            if let Some(cnt) = st.per_sender_counts.get_mut(&entry.tx.sender) {
                if *cnt > 0 {
                    *cnt -= 1;
                }
                if *cnt == 0 {
                    st.per_sender_counts.remove(&entry.tx.sender);
                }
            }

            // metrics and events
            match &reason {
                PoolEvent::Replaced { .. } => self.metrics.inc_replaced(),
                PoolEvent::RemovedIncluded(_) => self.metrics.inc_removed_included(),
                PoolEvent::RemovedInvalid(_) => self.metrics.inc_removed_invalid(),
                PoolEvent::Evicted(_) => self.metrics.inc_evicted(),
                PoolEvent::Inserted(_) => { /* not possible here */ }
            }
            self.metrics.gauge_size(st.size());
            let _ = self.events_tx.send(reason);
        }
    }

    /// Enforce soft capacity by evicting lowest-priority tail.
    fn enforce_soft_capacity_locked(&self, st: &mut PoolState) {
        if st.size() <= self.cfg.soft_capacity {
            return;
        }

        // Build a temporary vector to sort by ascending priority for eviction.
        // For efficiency in large pools, a more advanced structure can be used.
        let mut all: Vec<(TxId, U256, SystemTime)> = st
            .by_id
            .values()
            .map(|e| (e.tx.id, e.prio, e.tx.created_at))
            .collect();

        all.sort_by(|a, b| match a.1.cmp(&b.1) {
            Ordering::Equal => b.2.cmp(&a.2), // newer first to keep older; evict newer first
            x => x,
        });

        let to_evict = st.size().saturating_sub(self.cfg.soft_capacity);
        for i in 0..to_evict {
            let id = all[i].0;
            self.remove_locked(st, id, PoolEvent::Evicted(id));
        }
    }
}

/// Compact snapshot types for observability.
#[derive(Clone, Debug)]
pub struct TxSnapshotEntry {
    pub id: TxId,
    pub sender: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub size_bytes: u32,
    pub prio: U256,
    pub created_at: SystemTime,
}

#[derive(Clone, Debug)]
pub struct TxPoolSnapshot {
    pub total: usize,
    pub senders: HashMap<Address, usize>,
    pub txs: Vec<TxSnapshotEntry>,
}

//
// -------------------------- Tests (unit) --------------------------
//

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    struct TestValidator {
        nonces: parking_lot::Mutex<HashMap<Address, u64>>,
    }
    impl TestValidator {
        fn new() -> Self {
            Self { nonces: parking_lot::Mutex::new(HashMap::new()) }
        }
        fn set_nonce(&self, a: Address, n: u64) { self.nonces.lock().insert(a, n); }
    }
    impl TxValidator for TestValidator {
        fn validate(&self, tx: &Transaction) -> Result<(), TxPoolError> {
            if tx.gas_limit == 0 { return Err(TxPoolError::Invalid("zero gas".into())); }
            Ok(())
        }
        fn expected_nonce(&self, sender: Address) -> Result<u64, TxPoolError> {
            Ok(*self.nonces.lock().get(&sender).unwrap_or(&0))
        }
    }

    static COUNTER: AtomicU64 = AtomicU64::new(1);
    fn id() -> TxId {
        let n = COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&n.to_be_bytes());
        TxId(b)
    }
    fn addr(x: u8) -> Address { let mut a = [0u8; 20]; a[0]=x; Address(a) }
    fn tx(sender: Address, nonce: u64, tip: u128, maxfee: u128) -> Transaction {
        Transaction {
            id: id(),
            sender,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: U256::from_u128(maxfee),
            max_priority_fee_per_gas: U256::from_u128(tip),
            size_bytes: 120,
            created_at: SystemTime::now(),
        }
    }

    #[test]
    fn insert_and_replace() {
        let v = Arc::new(TestValidator::new());
        let pool = TxPool::new(PoolConfig::default(), v.clone(), Arc::new(NoopMetrics));

        let a = addr(1);
        v.set_nonce(a, 0);

        // insert nonce 0
        let t0 = tx(a, 0, 2, 100);
        pool.insert(t0.clone()).unwrap();

        // too low bump => fail
        let t0r_low = Transaction { max_priority_fee_per_gas: U256::from_u128(2), ..tx(a, 0, 2, 100) };
        assert!(matches!(pool.insert(t0r_low), Err(TxPoolError::ReplacementTooLow{..})));

        // higher bump passes (default 10% => >=2.2)
        let t0r_hi = Transaction { max_priority_fee_per_gas: U256::from_u128(3), ..tx(a, 0, 3, 100) };
        pool.insert(t0r_hi.clone()).unwrap();

        // select batch => returns replaced tx only
        let batch = pool.select_block_batch();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].nonce, 0);
    }

    #[test]
    fn nonce_gap_prevented() {
        let v = Arc::new(TestValidator::new());
        let pool = TxPool::new(PoolConfig::default(), v.clone(), Arc::new(NoopMetrics));
        let a = addr(2);
        v.set_nonce(a, 0);

        // gap: nonce 1 before 0
        let t1 = tx(a, 1, 2, 100);
        assert!(matches!(pool.insert(t1), Err(TxPoolError::NonceGap{..})));

        // insert 0 then 1 ok
        let t0 = tx(a, 0, 2, 100);
        pool.insert(t0).unwrap();
        let t1b = tx(a, 1, 2, 100);
        // will fail because expected_nonce is still 0 until t0 included, but we allow pool continuity only for next == expected
        // Here our policy requires exact expected nonce, so inserting 1 before 0 included is not allowed.
        assert!(matches!(pool.insert(t1b), Err(TxPoolError::NonceGap{..})));
    }

    #[test]
    fn capacity_eviction() {
        let mut cfg = PoolConfig::default();
        cfg.soft_capacity = 3;
        cfg.hard_capacity = 4;

        let v = Arc::new(TestValidator::new());
        let pool = TxPool::new(cfg, v.clone(), Arc::new(NoopMetrics));
        let a = addr(3);
        v.set_nonce(a, 0);

        let mut ids = Vec::new();
        for n in 0..3 {
            let t = tx(a, 0, (n+1) as u128, 100); // forces replacement path; last has highest tip
            let _ = pool.insert(t.clone());
            ids.push(t.id);
        }
        // only latest replacement remains due to (sender,nonce) uniqueness:
        let snap = pool.snapshot(10);
        assert_eq!(snap.total, 1);
    }
}

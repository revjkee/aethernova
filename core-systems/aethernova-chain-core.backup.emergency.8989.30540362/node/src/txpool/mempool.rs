// aethernova-chain-core/node/src/txpool/mempool.rs
//! Industrial-grade mempool for Aethernova Chain Core.
//!
//! Design goals:
//! - Deterministic, stable ordering by effective fee-per-gas with sender/nonce constraints
//! - RBF: replace-by-fee for same (sender, nonce) if strictly better
//! - Size/bytes caps, per-sender caps, TTL eviction, low-fee eviction
//! - Batch selection under block gas limit with sender nonce continuity
//! - Mark-included + reorg handling (return pending)
//! - Snapshots for observability & debugging
//!
//! Concurrency model:
//! - Single RwLock protects state; read ops avoid write contention
//! - O(log N) hot paths via BTreeMap-based fee indexes
//!
//! No external crates; suitable as a baseline. Hook a real validator/chain state
//! via the TxValidator trait.

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 32-byte transaction hash.
#[derive(Clone, Copy, Eq)]
pub struct TxHash([u8; 32]);

impl PartialEq for TxHash {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Hash for TxHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}
impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

pub type Address = [u8; 20];

/// Canonical transaction view used by mempool.
/// If у вас есть собственная Tx-структура — адаптируйте From/Into.
#[derive(Clone, Debug)]
pub struct Tx {
    pub hash: TxHash,
    pub from: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,     // wei per gas equivalent
    pub max_priority_fee_per_gas: u128,
    pub size_bytes: usize,
    pub created_unix_ms: u64,
}

impl Tx {
    pub fn new(
        hash: TxHash,
        from: Address,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        size_bytes: usize,
    ) -> Self {
        let created_unix_ms = now_millis();
        Self {
            hash,
            from,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            size_bytes,
            created_unix_ms,
        }
    }

    #[inline]
    pub fn effective_fee_per_gas(&self, base_fee: u128) -> u128 {
        // EIP-1559 style: min(max_fee, base_fee + tip)
        let cap = self.max_fee_per_gas;
        let tip = self.max_priority_fee_per_gas;
        let with_base = base_fee.saturating_add(tip);
        if cap < with_base { cap } else { with_base }
    }
}

#[inline]
fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis() as u64
}

/// Validation errors surfaced by TxValidator.
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidSignature,
    NonceTooLow { expected: u64, got: u64 },
    NonceTooHigh { current: u64, got: u64 },
    InsufficientBalance,
    GasLimitExceeded,
    FeeTooLow { min_effective_fee: u128, got: u128 },
    Custom(String),
}

/// Pluggable validator to integrate chain state/rules.
pub trait TxValidator: Send + Sync + 'static {
    /// Validate tx for admission. `base_fee` provided for EIP-1559 style chains.
    fn validate(&self, tx: &Tx, base_fee: u128) -> Result<(), ValidationError>;
    /// Return current sender nonce to maintain continuity.
    fn account_nonce(&self, sender: &Address) -> u64;
    /// Return minimal acceptable effective fee/priority under current policy.
    fn min_effective_fee(&self) -> u128;
}

/// Public configuration for mempool behavior.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub capacity_txs: usize,          // hard cap number of txs
    pub capacity_bytes: usize,        // hard cap total bytes
    pub per_sender_limit: usize,      // cap per sender
    pub ttl_ms: u64,                  // drop txs older than TTL
    pub min_replacement_bump_bps: u32,// minimal RBF improvement in basis points (1/100 of %), e.g. 1000 = +10%
    pub select_oldest_first: bool,    // tie-breaker: false => prefer higher tip, true => older
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            capacity_txs: 100_000,
            capacity_bytes: 256 * 1024 * 1024,
            per_sender_limit: 1024,
            ttl_ms: 3_600_000, // 1h
            min_replacement_bump_bps: 1000, // 10%
            select_oldest_first: false,
        }
    }
}

/// Metrics snapshot (for observability).
#[derive(Clone, Debug)]
pub struct MempoolStats {
    pub total_txs: usize,
    pub total_bytes: usize,
    pub unique_senders: usize,
    pub dropped_ttl: u64,
    pub dropped_low_fee: u64,
    pub replaced_rbf: u64,
}

/// Internal entry with cached ordering keys.
#[derive(Clone)]
struct Entry {
    tx: Tx,
    // Cached order keys for selection. base_fee-dependent key is passed during selection, not stored.
    // For low-fee eviction index we use max_fee_per_gas as a proxy.
}

impl Entry {
    fn fee_key(&self) -> u128 {
        // proxy for eviction ordering when base_fee unknown: max_fee_per_gas
        self.tx.max_fee_per_gas
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("hash", &self.tx.hash)
            .field("from", &hex20(&self.tx.from))
            .field("nonce", &self.tx.nonce)
            .field("max_fee_per_gas", &self.tx.max_fee_per_gas)
            .field("tip", &self.tx.max_priority_fee_per_gas)
            .finish()
    }
}

/// For each sender maintain contiguous nonces via BTreeMap.
#[derive(Default)]
struct SenderQueue {
    // nonce -> hash
    by_nonce: BTreeMap<u64, TxHash>,
    total_bytes: usize,
}
impl SenderQueue {
    fn len(&self) -> usize { self.by_nonce.len() }
    fn is_empty(&self) -> bool { self.by_nonce.is_empty() }
    fn first_nonce(&self) -> Option<u64> { self.by_nonce.keys().next().copied() }
    fn insert(&mut self, nonce: u64, h: TxHash, bytes: usize) -> Option<TxHash> {
        let prev = self.by_nonce.insert(nonce, h);
        if prev.is_none() { self.total_bytes += bytes; }
        prev
    }
    fn remove(&mut self, nonce: &u64, bytes: usize) -> Option<TxHash> {
        let prev = self.by_nonce.remove(nonce);
        if prev.is_some() { self.total_bytes = self.total_bytes.saturating_sub(bytes); }
        prev
    }
}

/// Core state under RwLock.
struct State {
    cfg: MempoolConfig,
    // Main storage
    entries: HashMap<TxHash, Entry>,
    total_bytes: usize,
    // Per-sender queues
    by_sender: HashMap<Address, SenderQueue>,
    // Eviction index: (fee_key -> set of hashes). Low fee at beginning.
    by_fee_asc: BTreeMap<u128, BTreeSet<TxHash>>,
    // Age index for TTL and tie-breaker: queue of hashes by arrival
    arrival: VecDeque<TxHash>,
    // Metrics
    dropped_ttl: u64,
    dropped_low_fee: u64,
    replaced_rbf: u64,
}

impl State {
    fn new(cfg: MempoolConfig) -> Self {
        Self {
            cfg,
            entries: HashMap::new(),
            total_bytes: 0,
            by_sender: HashMap::new(),
            by_fee_asc: BTreeMap::new(),
            arrival: VecDeque::new(),
            dropped_ttl: 0,
            dropped_low_fee: 0,
            replaced_rbf: 0,
        }
    }
}

/// Public handle.
#[derive(Clone)]
pub struct Mempool {
    inner: Arc<RwLock<State>>,
    validator: Arc<dyn TxValidator>,
}

impl Mempool {
    pub fn new(cfg: MempoolConfig, validator: Arc<dyn TxValidator>) -> Self {
        Self { inner: Arc::new(RwLock::new(State::new(cfg))), validator }
    }

    pub fn stats(&self) -> MempoolStats {
        let st = self.inner.read().unwrap();
        MempoolStats {
            total_txs: st.entries.len(),
            total_bytes: st.total_bytes,
            unique_senders: st.by_sender.len(),
            dropped_ttl: st.dropped_ttl,
            dropped_low_fee: st.dropped_low_fee,
            replaced_rbf: st.replaced_rbf,
        }
    }

    pub fn config(&self) -> MempoolConfig {
        self.inner.read().unwrap().cfg.clone()
    }

    /// Admission API: validate + insert with eviction if needed.
    pub fn add(&self, tx: Tx, base_fee: u128) -> Result<(), ValidationError> {
        // Stateless/chain validation first
        self.validator.validate(&tx, base_fee)?;

        let mut st = self.inner.write().unwrap();

        // TTL purge (lazy)
        st.evict_ttl();

        // Per-sender continuity window check:
        let current_nonce = self.validator.account_nonce(&tx.from);
        if tx.nonce < current_nonce {
            return Err(ValidationError::NonceTooLow { expected: current_nonce, got: tx.nonce });
        }

        // RBF: same (sender, nonce) replacement policy.
        if let Some(existing_hash) = st.by_sender.get(&tx.from).and_then(|sq| sq.by_nonce.get(&tx.nonce).copied()) {
            let existing_eff = st.entries.get(&existing_hash).map(|e| e.tx.effective_fee_per_gas(base_fee)).unwrap_or(0);
            let new_eff = tx.effective_fee_per_gas(base_fee);
            if !is_rbf_better(existing_eff, new_eff, st.cfg.min_replacement_bump_bps) {
                return Err(ValidationError::FeeTooLow { min_effective_fee: bump_target(existing_eff, st.cfg.min_replacement_bump_bps), got: new_eff });
            }
            // Perform replacement
            st.remove_entry(existing_hash);
            st.replaced_rbf = st.replaced_rbf.saturating_add(1);
        } else {
            // Per-sender cap
            let count = st.by_sender.get(&tx.from).map(|s| s.len()).unwrap_or(0);
            if count >= st.cfg.per_sender_limit {
                // Evict sender's lowest-fee tx to make room if new one is better; otherwise reject.
                let sender_low = st.lowest_fee_of_sender(&tx.from);
                if let Some((low_hash, low_fee)) = sender_low {
                    let new_eff = tx.effective_fee_per_gas(base_fee);
                    if new_eff > low_fee {
                        st.remove_entry(low_hash);
                        st.dropped_low_fee = st.dropped_low_fee.saturating_add(1);
                    } else {
                        return Err(ValidationError::FeeTooLow { min_effective_fee: low_fee + 1, got: new_eff });
                    }
                } else {
                    return Err(ValidationError::Custom("per-sender capacity reached".into()));
                }
            }
        }

        // Global capacity enforcement (count/bytes): evict low-fee until fits.
        st.ensure_capacity_for(tx.size_bytes);

        // Insert
        st.insert_entry(tx);

        Ok(())
    }

    /// Remove by hash (e.g., user cancellation).
    pub fn remove(&self, h: TxHash) -> bool {
        let mut st = self.inner.write().unwrap();
        st.remove_entry(h)
    }

    /// Called when a block is produced: mark included; drop from pool.
    pub fn mark_included(&self, included: &[TxHash]) {
        let mut st = self.inner.write().unwrap();
        for h in included {
            st.remove_entry(*h);
        }
    }

    /// On reorg, return transactions to pool if still valid.
    /// Invalid ones (nonce below current or fee too low) will be dropped by re-admission.
    pub fn on_reorg(&self, reverted: Vec<Tx>, base_fee: u128) {
        for tx in reverted {
            let _ = self.add(tx, base_fee);
        }
    }

    /// Select best transactions up to `block_gas_limit`, respecting sender nonce continuity.
    /// `base_fee` influences effective ordering (EIP-1559).
    pub fn select_for_block(&self, block_gas_limit: u64, base_fee: u128) -> Vec<Tx> {
        let st_read = self.inner.read().unwrap();
        if st_read.entries.is_empty() { return Vec::new(); }

        // Build candidate set ordered by (effective_fee desc, tie: created or max_fee desc)
        // We cannot precompute continuity across all senders without scanning. Use a two-phase approach:
        // 1) compute best head tx per sender (next nonce), rank all heads globally
        // 2) pop best head, push that sender's next nonce as head, repeat
        let mut result = Vec::with_capacity(1024);
        let mut gas_used: u64 = 0;

        // Prepare per-sender head nonce (>= current account nonce)
        let mut heads: Vec<(OrderingKey, TxHash, Address)> = Vec::new();
        for (sender, queue) in &st_read.by_sender {
            let expected = st_read.expected_nonce_for(sender, &*self.validator);
            // find smallest nonce >= expected
            let next = queue.by_nonce.range(expected..).next().map(|(_, h)| *h);
            if let Some(h) = next {
                let e = st_read.entries.get(&h).unwrap(); // safe
                let key = OrderingKey::new(e, base_fee, st_read.cfg.select_oldest_first);
                heads.push((key, h, *sender));
            }
        }
        // Build max-heap via sort (no heap in std for custom key). We will keep heads sorted descending.
        heads.sort_by(|a, b| b.0.cmp(&a.0));

        let mut heads_idx: HashMap<Address, usize> = HashMap::new();
        for (i, (_, _, s)) in heads.iter().enumerate() {
            heads_idx.insert(*s, i);
        }

        // Mutable projection for advancing sender queues
        let mut cursor_nonce: HashMap<Address, u64> = HashMap::new();
        for (sender, queue) in &st_read.by_sender {
            let expected = st_read.expected_nonce_for(sender, &*self.validator);
            cursor_nonce.insert(*sender, expected);
        }

        // Iterate while gas budget allows and heads exist
        while gas_used < block_gas_limit && !heads.is_empty() {
            // take best head
            let (best_key, best_hash, best_sender) = heads.remove(0);
            // Update index for shifted elements
            heads_idx.clear();
            for (i, (_, _, s)) in heads.iter().enumerate() {
                heads_idx.insert(*s, i);
            }

            let entry = match st_read.entries.get(&best_hash) {
                Some(e) => e,
                None => continue, // was concurrently removed
            };
            if gas_used.saturating_add(entry.tx.gas_limit) > block_gas_limit {
                // Cannot include — skip this head; try next
                continue;
            }

            // Continuity: ensure this is exactly the cursor nonce
            let c = cursor_nonce.get(&best_sender).copied().unwrap_or_else(|| st_read.expected_nonce_for(&best_sender, &*self.validator));
            if entry.tx.nonce != c {
                // Not next in sequence; this head is invalid right now -> advance cursor if possible or skip
                // Try to find a tx with current cursor nonce
                let q = st_read.by_sender.get(&best_sender).unwrap();
                if let Some((n, h)) = q.by_nonce.get_key_value(&c) {
                    // replace head with the correct nonce tx
                    let e2 = st_read.entries.get(h).unwrap();
                    let key2 = OrderingKey::new(e2, base_fee, st_read.cfg.select_oldest_first);
                    // put back current head
                    heads.push((best_key, best_hash, best_sender));
                    // add/replace with correct head
                    heads.push((key2, *h, best_sender));
                    heads.sort_by(|a, b| b.0.cmp(&a.0));
                    continue;
                } else {
                    // No tx for current cursor nonce: we cannot include from this sender until gap filled.
                    // Drop this head and proceed with others.
                    continue;
                }
            }

            // Include entry
            result.push(entry.tx.clone());
            gas_used = gas_used.saturating_add(entry.tx.gas_limit);
            // Advance sender cursor
            let next_nonce = c.saturating_add(1);
            cursor_nonce.insert(best_sender, next_nonce);

            // Push next head for this sender, if exists
            if let Some(q) = st_read.by_sender.get(&best_sender) {
                if let Some((n2, h2)) = q.by_nonce.range(next_nonce..).next() {
                    let e2 = st_read.entries.get(h2).unwrap();
                    let key2 = OrderingKey::new(e2, base_fee, st_read.cfg.select_oldest_first);
                    heads.push((key2, *h2, best_sender));
                    heads.sort_by(|a, b| b.0.cmp(&a.0));
                }
            }
        }

        result
    }

    /// Return a lightweight snapshot for debugging/metrics endpoints.
    pub fn snapshot(&self, limit: usize) -> Vec<SnapshotTx> {
        let st = self.inner.read().unwrap();
        let mut out = Vec::with_capacity(limit.min(st.entries.len()));
        for (h, e) in st.entries.iter().take(limit) {
            out.push(SnapshotTx {
                hash: *h,
                from: e.tx.from,
                nonce: e.tx.nonce,
                max_fee_per_gas: e.tx.max_fee_per_gas,
                tip: e.tx.max_priority_fee_per_gas,
                gas_limit: e.tx.gas_limit,
                size_bytes: e.tx.size_bytes,
                age_ms: now_millis().saturating_sub(e.tx.created_unix_ms),
            });
        }
        out
    }
}

/// Compact snapshot entry for observability endpoints.
#[derive(Clone, Debug)]
pub struct SnapshotTx {
    pub hash: TxHash,
    pub from: Address,
    pub nonce: u64,
    pub max_fee_per_gas: u128,
    pub tip: u128,
    pub gas_limit: u64,
    pub size_bytes: usize,
    pub age_ms: u64,
}

/* ----------------------- Internal helpers & impls ------------------------ */

impl State {
    fn expected_nonce_for(&self, sender: &Address, val: &dyn TxValidator) -> u64 {
        val.account_nonce(sender)
    }

    fn insert_entry(&mut self, tx: Tx) {
        let h = tx.hash;
        let bytes = tx.size_bytes;

        let ent = Entry { tx };
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.arrival.push_back(h);

        // entries
        self.entries.insert(h, ent.clone());

        // fee index
        self.by_fee_asc.entry(ent.fee_key()).or_default().insert(h);

        // sender queue
        let sq = self.by_sender.entry(ent.tx.from).or_default();
        let _prev = sq.insert(ent.tx.nonce, h, bytes);
        // _prev shouldn't happen here; duplicates handled earlier
    }

    fn remove_entry(&mut self, h: TxHash) -> bool {
        if let Some(ent) = self.entries.remove(&h) {
            // fee index
            if let Some(set) = self.by_fee_asc.get_mut(&ent.fee_key()) {
                set.remove(&h);
                if set.is_empty() { self.by_fee_asc.remove(&ent.fee_key()); }
            }
            // sender queue
            if let Some(q) = self.by_sender.get_mut(&ent.tx.from) {
                let _ = q.remove(&ent.tx.nonce, ent.tx.size_bytes);
                if q.is_empty() {
                    self.by_sender.remove(&ent.tx.from);
                }
            }
            // arrival: lazy cleanup — compact occasionally
            // For simplicity: mark removal via skip on read; full compaction when grows large.
            if self.arrival.len() > self.entries.len() * 2 {
                self.compact_arrival();
            }
            self.total_bytes = self.total_bytes.saturating_sub(ent.tx.size_bytes);
            return true;
        }
        false
    }

    fn compact_arrival(&mut self) {
        let set: HashSet<TxHash> = self.entries.keys().copied().collect();
        let mut newq = VecDeque::with_capacity(self.entries.len());
        for h in self.arrival.drain(..) {
            if set.contains(&h) { newq.push_back(h); }
        }
        self.arrival = newq;
    }

    fn evict_ttl(&mut self) {
        if self.cfg.ttl_ms == 0 || self.arrival.is_empty() { return; }
        let now = now_millis();
        // Pop from front while expired
        let mut to_remove = Vec::new();
        // Note: arrival may contain stale hashes already removed; skip them.
        for _ in 0..self.arrival.len() {
            if let Some(h) = self.arrival.front().copied() {
                if let Some(ent) = self.entries.get(&h) {
                    if now.saturating_sub(ent.tx.created_unix_ms) >= self.cfg.ttl_ms {
                        to_remove.push(h);
                        self.arrival.pop_front();
                    } else {
                        break; // queue is time-ordered
                    }
                } else {
                    // stale entry; drop
                    self.arrival.pop_front();
                }
            } else {
                break;
            }
        }
        for h in to_remove {
            if self.remove_entry(h) {
                self.dropped_ttl = self.dropped_ttl.saturating_add(1);
            }
        }
    }

    fn ensure_capacity_for(&mut self, incoming_bytes: usize) {
        // Evict by lowest fee (and oldest tie-break) until fits capacity_txs and capacity_bytes
        while (self.entries.len() + 1) > self.cfg.capacity_txs || (self.total_bytes + incoming_bytes) > self.cfg.capacity_bytes {
            if let Some((&fee_key, set)) = self.by_fee_asc.iter_mut().next() {
                if let Some(&victim) = set.iter().next() {
                    // tie-break: try to pick oldest among equal-fee victims using arrival queue
                    let vh = self.pick_oldest_among(&set);
                    let chosen = vh.unwrap_or(victim);
                    // remove chosen
                    // need to get entry for size accounting; remove_entry handles indices
                    if self.remove_entry(chosen) {
                        self.dropped_low_fee = self.dropped_low_fee.saturating_add(1);
                    }
                } else {
                    // empty set — cleanup
                    self.by_fee_asc.remove(&fee_key);
                }
            } else {
                // No items to evict, break to avoid infinite loop
                break;
            }
        }
    }

    fn pick_oldest_among(&self, candidates: &BTreeSet<TxHash>) -> Option<TxHash> {
        if candidates.is_empty() { return None; }
        // Walk arrival from front to find first candidate
        for h in self.arrival.iter() {
            if candidates.contains(h) {
                return Some(*h);
            }
        }
        candidates.iter().next().copied()
    }

    fn lowest_fee_of_sender(&self, sender: &Address) -> Option<(TxHash, u128)> {
        let sq = self.by_sender.get(sender)?;
        // Find minimal fee among sender's txs
        let mut best: Option<(TxHash, u128)> = None;
        for (_n, h) in sq.by_nonce.iter() {
            if let Some(e) = self.entries.get(h) {
                let fk = e.fee_key();
                match &mut best {
                    None => best = Some((*h, fk)),
                    Some((_bh, bf)) if fk < *bf => { *bf = fk; *best.as_mut().unwrap() = (*h, fk); }
                    _ => {}
                }
            }
        }
        best
    }
}

/// Ordering key for block selection.
#[derive(Clone, Copy)]
struct OrderingKey {
    // Higher is better
    effective_fee: u128,
    // Tie-breaker
    secondary: u128, // max_fee_per_gas or inverse age
    // Final tie: older first if select_oldest_first=true else any stable
    created_unix_ms: u64,
}

impl OrderingKey {
    fn new(e: &Entry, base_fee: u128, prefer_oldest: bool) -> Self {
        let eff = e.tx.effective_fee_per_gas(base_fee);
        let secondary = if prefer_oldest {
            // smaller created => older; to make higher better, invert
            u128::MAX - (e.tx.created_unix_ms as u128)
        } else {
            e.tx.max_fee_per_gas
        };
        Self {
            effective_fee: eff,
            secondary,
            created_unix_ms: e.tx.created_unix_ms,
        }
    }
}

impl PartialEq for OrderingKey {
    fn eq(&self, other: &Self) -> bool {
        self.effective_fee == other.effective_fee &&
        self.secondary == other.secondary &&
        self.created_unix_ms == other.created_unix_ms
    }
}
impl Eq for OrderingKey {}

impl PartialOrd for OrderingKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrderingKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Desc by effective_fee, then desc by secondary, then asc by age (older first)
        self.effective_fee.cmp(&other.effective_fee)
            .then(self.secondary.cmp(&other.secondary))
            .then(other.created_unix_ms.cmp(&self.created_unix_ms))
    }
}

/* ----------------------------- Utilities --------------------------------- */

fn is_rbf_better(old_eff: u128, new_eff: u128, bump_bps: u32) -> bool {
    if new_eff <= old_eff { return false; }
    let target = bump_target(old_eff, bump_bps);
    new_eff >= target
}

fn bump_target(old_eff: u128, bump_bps: u32) -> u128 {
    // target = old * (1 + bps/10000)
    old_eff + (old_eff.saturating_mul(bump_bps as u128) / 10_000u128)
}

fn hex20(a: &Address) -> String {
    let mut s = String::with_capacity(2 + 40);
    s.push_str("0x");
    for b in a {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/* -------------------------------- Tests ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyValidator;
    impl TxValidator for DummyValidator {
        fn validate(&self, _tx: &Tx, _base_fee: u128) -> Result<(), ValidationError> {
            Ok(())
        }
        fn account_nonce(&self, _sender: &Address) -> u64 { 0 }
        fn min_effective_fee(&self) -> u128 { 0 }
    }

    fn addr(x: u8) -> Address { [x; 20] }
    fn hash(x: u8) -> TxHash { TxHash([x; 32]) }

    #[test]
    fn rbf_policy() {
        let v = Arc::new(DummyValidator);
        let mp = Mempool::new(MempoolConfig::default(), v);

        let t1 = Tx::new(hash(1), addr(1), 0, 21_000, 100, 2, 100);
        mp.add(t1.clone(), 0).unwrap();

        // insufficient bump
        let t2 = Tx::new(hash(2), addr(1), 0, 21_000, 105, 2, 100);
        assert!(mp.add(t2.clone(), 0).is_err());

        // sufficient bump (>=10%)
        let t3 = Tx::new(hash(3), addr(1), 0, 21_000, 111, 2, 100);
        mp.add(t3.clone(), 0).unwrap();

        // head should be t3
        let sel = mp.select_for_block(1_000_000, 0);
        assert_eq!(sel[0].hash.0, t3.hash.0);
    }

    #[test]
    fn per_sender_continuity() {
        let v = Arc::new(DummyValidator);
        let mp = Mempool::new(MempoolConfig::default(), v);

        // Nonce 1 without 0 should not be selectable
        let t1 = Tx::new(hash(1), addr(1), 1, 50_000, 100, 2, 100);
        mp.add(t1, 0).unwrap();
        let sel = mp.select_for_block(10_000_000, 0);
        assert!(sel.is_empty());

        // Add nonce 0
        let t0 = Tx::new(hash(2), addr(1), 0, 50_000, 100, 2, 100);
        mp.add(t0.clone(), 0).unwrap();
        let sel2 = mp.select_for_block(10_000_000, 0);
        assert_eq!(sel2.len(), 2);
        assert_eq!(sel2[0].nonce, 0);
        assert_eq!(sel2[1].nonce, 1);
    }

    #[test]
    fn capacity_eviction_low_fee() {
        let mut cfg = MempoolConfig::default();
        cfg.capacity_txs = 2;
        cfg.capacity_bytes = usize::MAX;
        let v = Arc::new(DummyValidator);
        let mp = Mempool::new(cfg, v);

        let a = addr(1);
        mp.add(Tx::new(hash(1), a, 0, 21_000, 10, 1, 100), 0).unwrap();
        mp.add(Tx::new(hash(2), a, 1, 21_000, 20, 1, 100), 0).unwrap();
        // new high-fee should evict lowest-fee
        mp.add(Tx::new(hash(3), a, 2, 21_000, 30, 1, 100), 0).unwrap();

        let snap = mp.snapshot(10);
        assert_eq!(snap.len(), 2);
        let hashes: HashSet<_> = snap.iter().map(|s| s.hash.0[0]).collect();
        assert!(hashes.contains(&2) && hashes.contains(&3));
    }
}

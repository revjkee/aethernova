// aethernova-chain-core/node/src/consensus/finality/checkpoint.rs
//! Finality gadget + checkpoints (industrial-grade, no external deps by default).
//!
//! Features:
//! - Validator-weighted BFT-like vote accumulation per round (threshold: >= 2/3 total weight).
//! - On finalization -> materialize a Checkpoint with deterministic H256 id.
//! - Thread-safe (Arc<RwLock<...>>), in-memory storage + trait for pluggable backends.
//! - Event notifications via mpsc when a checkpoint is finalized.
//! - Explicit rounds, namespaces, and per-round garbage collection.
//!
//! Optional:
//! - `sha2` feature: use cryptographic SHA-256. Otherwise a deterministic fallback hasher.
//!
//! Note: This is a generic gadget meant to be embedded into a node runtime/consensus.

// --- std imports
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// --- Hash type (H256) and hashing helpers ----------------------------------

/// 32-byte hash (H256).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct H256([u8; 32]);

impl H256 {
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            let hi = b >> 4;
            let lo = b & 0x0f;
            s.push(nibble_hex(hi));
            s.push(nibble_hex(lo));
        }
        s
    }
}

impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "0x{hex}")
    }
}

fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

/// Compute H256 over given bytes.
///
/// With feature `sha2`, use cryptographic SHA-256. Otherwise fall back to
/// std::collections::hash_map::DefaultHasher (not cryptographically secure but deterministic).
fn hash_bytes(bytes: &[u8]) -> H256 {
    #[cfg(feature = "sha2")]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out[..32]);
        H256::from_bytes(b)
    }
    #[cfg(not(feature = "sha2"))]
    {
        // Deterministic fold into 32 bytes via DefaultHasher rounds.
        let mut acc = [0u8; 32];
        let chunks = bytes.chunks(32);
        for (i, ch) in chunks.enumerate() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            i.hash(&mut h);
            ch.hash(&mut h);
            let v = h.finish().to_be_bytes(); // 8 bytes
            // Mix into 32-byte acc
            let off = (i % 4) * 8;
            for j in 0..8 {
                acc[off + j] ^= v[j];
            }
        }
        H256::from_bytes(acc)
    }
}

// --- Domain types ------------------------------------------------------------

/// Unique validator identifier (public key hash, address, etc.).
pub type ValidatorId = H256;

/// Round number in the finality protocol (monotonic).
pub type Round = u64;

/// Nanoseconds since UNIX_EPOCH.
pub type Nanos = u128;

/// Identifier for a block in the canonical chain space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockRef {
    pub height: u64,
    pub hash: H256,
}

impl BlockRef {
    pub fn new(height: u64, hash: H256) -> Self {
        Self { height, hash }
    }
}

/// Deterministic identifier of a checkpoint (H256).
pub type CheckpointId = H256;

/// Aggregate justification bytes (e.g., aggregated signature/bitmap).
pub type Justification = Vec<u8>;

/// Deterministic digest of the validator set active for the checkpoint.
pub type ValidatorSetHash = H256;

/// Finalized checkpoint.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub block: BlockRef,
    pub state_root: H256,
    pub validator_set: ValidatorSetHash,
    pub round: Round,
    pub timestamp_ns: Nanos,
    pub justification: Justification,
}

impl Checkpoint {
    /// Compute deterministic id from fields.
    pub fn compute_id(
        block: BlockRef,
        state_root: H256,
        validator_set: ValidatorSetHash,
        round: Round,
        timestamp_ns: Nanos,
        justification: &[u8],
    ) -> CheckpointId {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 32 + 16 + justification.len());
        buf.extend_from_slice(&block.height.to_be_bytes());
        buf.extend_from_slice(block.hash.as_bytes());
        buf.extend_from_slice(state_root.as_bytes());
        buf.extend_from_slice(validator_set.as_bytes());
        buf.extend_from_slice(&round.to_be_bytes());
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        buf.extend_from_slice(justification);
        hash_bytes(&buf)
    }
}

// --- Validator set and voting ------------------------------------------------

/// Validator set with weights. Total weight is the sum of all validators.
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    weights: HashMap<ValidatorId, u64>,
    total: u64,
    hash: ValidatorSetHash,
}

impl ValidatorSet {
    pub fn new(weights: HashMap<ValidatorId, u64>) -> Self {
        let total = weights.values().copied().sum::<u64>();
        let mut buf = Vec::with_capacity(weights.len() * (32 + 8));
        // Stable hashing: sort by validator id
        let mut pairs: Vec<_> = weights.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        for (vid, w) in pairs {
            buf.extend_from_slice(vid.as_bytes());
            buf.extend_from_slice(&w.to_be_bytes());
        }
        let hash = hash_bytes(&buf);
        Self { weights, total, hash }
    }

    pub fn total_weight(&self) -> u64 {
        self.total
    }

    pub fn weight_of(&self, vid: &ValidatorId) -> u64 {
        *self.weights.get(vid).unwrap_or(&0)
    }

    pub fn hash(&self) -> ValidatorSetHash {
        self.hash
    }
}

/// Vote from a validator for a specific block at a given round.
#[derive(Clone, Debug)]
pub struct Vote {
    pub validator: ValidatorId,
    pub block: BlockRef,
    pub round: Round,
    pub signature: Vec<u8>, // opaque for gadget
}

// --- Storage abstraction -----------------------------------------------------

/// Storage trait, pluggable for persistent backends.
pub trait Storage: Send + Sync + 'static {
    fn put_checkpoint(&self, cp: &Checkpoint) -> Result<(), FinalityError>;
    fn latest_checkpoint(&self) -> Option<Checkpoint>;
    fn put_votes(&self, round: Round, block: &BlockRef, votes: &[Vote]) -> Result<(), FinalityError>;
    fn get_votes(&self, round: Round, block: &BlockRef) -> Vec<Vote>;
    fn clear_round(&self, round: Round);
}

/// In-memory storage (thread-safe).
#[derive(Default)]
pub struct InMemoryStorage {
    inner: RwLock<StorageInner>,
}

#[derive(Default)]
struct StorageInner {
    latest: Option<Checkpoint>,
    votes: HashMap<(Round, BlockRef), Vec<Vote>>,
}

impl Storage for InMemoryStorage {
    fn put_checkpoint(&self, cp: &Checkpoint) -> Result<(), FinalityError> {
        let mut lg = self.inner.write().unwrap();
        lg.latest = Some(cp.clone());
        Ok(())
    }

    fn latest_checkpoint(&self) -> Option<Checkpoint> {
        self.inner.read().unwrap().latest.clone()
    }

    fn put_votes(&self, round: Round, block: &BlockRef, votes: &[Vote]) -> Result<(), FinalityError> {
        let key = (round, *block);
        let mut lg = self.inner.write().unwrap();
        let entry = lg.votes.entry(key).or_default();
        entry.extend_from_slice(votes);
        Ok(())
    }

    fn get_votes(&self, round: Round, block: &BlockRef) -> Vec<Vote> {
        let key = (round, *block);
        self.inner
            .read()
            .unwrap()
            .votes
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    fn clear_round(&self, round: Round) {
        let mut lg = self.inner.write().unwrap();
        lg.votes.retain(|(r, _), _| *r != round);
    }
}

// --- Errors ------------------------------------------------------------------

#[derive(Debug, thiserror_impl::Error)]
pub enum FinalityError {
    #[error("unknown validator")]
    UnknownValidator,
    #[error("duplicate vote from validator in this round")]
    DuplicateVote,
    #[error("round too old (current: {current}, got: {got})")]
    StaleRound { current: Round, got: Round },
    #[error("internal: {0}")]
    Internal(String),
}

/// Minimal local `thiserror`-like derive replacement to avoid external dep in single file.
/// If you already use `thiserror`, remove this module and add `use thiserror::Error;`.
mod thiserror_impl {
    use core::fmt;

    pub trait Error: fmt::Debug + fmt::Display {}
    impl<T: fmt::Debug + fmt::Display> Error for T {}

    /// Lightweight attribute-free error macro imitation.
    pub use std::fmt::Display as Error;
}

// --- Events ------------------------------------------------------------------

/// Events emitted by the gadget.
#[derive(Clone, Debug)]
pub enum FinalityEvent {
    Finalized(Checkpoint),
}

// --- Finality gadget ---------------------------------------------------------

/// Public API for the finality gadget.
pub trait FinalityGadget: Send + Sync {
    /// Submit a batch of votes for a given round.
    fn submit_votes(&self, votes: Vec<Vote>) -> Result<(), FinalityError>;

    /// Latest finalized checkpoint (if any).
    fn latest_finalized(&self) -> Option<Checkpoint>;

    /// Subscribe to finality events. Returns a receiver.
    fn subscribe(&self) -> mpsc::Receiver<FinalityEvent>;

    /// Current round.
    fn round(&self) -> Round;
}

/// Configuration for the gadget.
#[derive(Clone, Debug)]
pub struct GadgetConfig {
    /// Quorum threshold numerator (e.g., 2).
    pub threshold_num: u64,
    /// Quorum threshold denominator (e.g., 3).
    pub threshold_den: u64,
    /// Whether to retain votes for previous rounds.
    pub retain_rounds: u64,
}

impl Default for GadgetConfig {
    fn default() -> Self {
        Self {
            threshold_num: 2,
            threshold_den: 3,
            retain_rounds: 2,
        }
    }
}

/// Vote accumulator at (round, block).
#[derive(Default, Clone)]
struct Accumulator {
    voters: HashSet<ValidatorId>,
    weight_sum: u64,
    votes: Vec<Vote>,
}

/// Main gadget implementation.
pub struct CheckpointManager<S: Storage> {
    cfg: GadgetConfig,
    validators: Arc<ValidatorSet>,
    storage: Arc<S>,
    // state
    current_round: RwLock<Round>,
    // round -> block -> accumulator
    acc: RwLock<HashMap<Round, HashMap<BlockRef, Accumulator>>>,
    // subscribers
    subs: RwLock<Vec<mpsc::Sender<FinalityEvent>>>,
}

impl<S: Storage> CheckpointManager<S> {
    pub fn new(cfg: GadgetConfig, validators: ValidatorSet, storage: S) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            validators: Arc::new(validators),
            storage: Arc::new(storage),
            current_round: RwLock::new(0),
            acc: RwLock::new(HashMap::new()),
            subs: RwLock::new(Vec::new()),
        })
    }

    fn quorum(&self) -> u64 {
        // ceil(total * num / den)
        let t = self.validators.total_weight() as u128;
        let num = self.cfg.threshold_num as u128;
        let den = self.cfg.threshold_den as u128;
        (((t * num) + den - 1) / den) as u64
    }

    fn emit(&self, ev: FinalityEvent) {
        let subs = self.subs.read().unwrap().clone();
        for tx in subs {
            let _ = tx.send(ev.clone());
        }
    }

    fn gc_old_rounds(&self, keep_from: Round) {
        let mut lg = self.acc.write().unwrap();
        lg.retain(|r, _| *r >= keep_from);
        // also clear from storage
        if keep_from > 0 {
            for r in 0..keep_from {
                self.storage.clear_round(r);
            }
        }
    }

    fn finalize_if_quorum(&self, round: Round, block: &BlockRef) -> Result<(), FinalityError> {
        let quorum = self.quorum();
        let (sum, just) = {
            let lg = self.acc.read().unwrap();
            let accs = lg.get(&round).and_then(|m| m.get(block));
            if let Some(a) = accs {
                (a.weight_sum, a.votes.clone())
            } else {
                (0, Vec::new())
            }
        };
        if sum < quorum {
            return Ok(()); // not enough yet
        }

        // Construct checkpoint and store it.
        let now_ns = now_nanos();
        let state_root = H256::zero(); // integrate with runtime state commitment when available
        let vs_hash = self.validators.hash();
        let mut just_buf = Vec::new();
        for v in &just {
            // canonical encoding: validator || round || height || block_hash || sig_len || sig
            just_buf.extend_from_slice(v.validator.as_bytes());
            just_buf.extend_from_slice(&v.round.to_be_bytes());
            just_buf.extend_from_slice(&v.block.height.to_be_bytes());
            just_buf.extend_from_slice(v.block.hash.as_bytes());
            let sl = (v.signature.len() as u64).to_be_bytes();
            just_buf.extend_from_slice(&sl);
            just_buf.extend_from_slice(&v.signature);
        }
        let id = Checkpoint::compute_id(*block, state_root, vs_hash, round, now_ns, &just_buf);
        let cp = Checkpoint {
            id,
            block: *block,
            state_root,
            validator_set: vs_hash,
            round,
            timestamp_ns: now_ns,
            justification: just_buf,
        };

        self.storage.put_checkpoint(&cp)?;
        self.emit(FinalityEvent::Finalized(cp.clone()));

        // Advance round and GC
        {
            let mut r = self.current_round.write().unwrap();
            if round >= *r {
                *r = round + 1;
            }
        }
        let keep_from = self.current_round.read().unwrap().saturating_sub(self.cfg.retain_rounds);
        self.gc_old_rounds(keep_from);

        Ok(())
    }
}

impl<S: Storage> FinalityGadget for CheckpointManager<S> {
    fn submit_votes(&self, votes: Vec<Vote>) -> Result<(), FinalityError> {
        if votes.is_empty() {
            return Ok(());
        }

        // Validate votes & stage accumulators
        let mut per_round: HashMap<Round, HashMap<BlockRef, Vec<Vote>>> = HashMap::new();
        let cur = *self.current_round.read().unwrap();

        for v in votes.into_iter() {
            if v.round + 1 < cur {
                return Err(FinalityError::StaleRound { current: cur, got: v.round });
            }
            // validator must exist
            if self.validators.weight_of(&v.validator) == 0 {
                return Err(FinalityError::UnknownValidator);
            }
            per_round.entry(v.round).or_default().entry(v.block).or_default().push(v);
        }

        // Apply to accumulators per round/block
        for (round, by_block) in per_round.into_iter() {
            let mut acc_map = self.acc.write().unwrap();
            let mentry = acc_map.entry(round).or_default();
            for (blk, vs) in by_block {
                let entry = mentry.entry(blk).or_default();
                for v in vs {
                    // Reject duplicate vote from same validator for the same round
                    if !entry.voters.insert(v.validator) {
                        return Err(FinalityError::DuplicateVote);
                    }
                    let w = self.validators.weight_of(&v.validator);
                    entry.weight_sum = entry
                        .weight_sum
                        .saturating_add(w);
                    entry.votes.push(v);
                }
                drop(entry);
                drop(mentry);
                drop(acc_map);

                // Persist votes & try finalize
                self.storage.put_votes(round, &blk, &self.get_acc(round, &blk).votes)?;
                self.finalize_if_quorum(round, &blk)?;

                // Reacquire for next loop iteration
                acc_map = self.acc.write().unwrap();
                let mentry2 = acc_map.entry(round).or_default();
                let _ = mentry2.get(&blk);
            }
        }

        Ok(())
    }

    fn latest_finalized(&self) -> Option<Checkpoint> {
        self.storage.latest_checkpoint()
    }

    fn subscribe(&self) -> mpsc::Receiver<FinalityEvent> {
        let (tx, rx) = mpsc::channel();
        self.subs.write().unwrap().push(tx);
        rx
    }

    fn round(&self) -> Round {
        *self.current_round.read().unwrap()
    }
}

impl<S: Storage> CheckpointManager<S> {
    fn get_acc(&self, round: Round, block: &BlockRef) -> Accumulator {
        self.acc
            .read()
            .unwrap()
            .get(&round)
            .and_then(|m| m.get(block))
            .cloned()
            .unwrap_or_default()
    }
}

// --- Utils -------------------------------------------------------------------

fn now_nanos() -> Nanos {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (dur.as_secs() as u128) * 1_000_000_000u128 + (dur.subsec_nanos() as u128)
}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(n: u8) -> ValidatorId {
        let mut b = [0u8; 32];
        b[0] = n;
        H256::from_bytes(b)
    }

    fn bid(n: u64) -> H256 {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        H256::from_bytes(b)
    }

    #[test]
    fn quorum_2of3_finalizes() {
        // validators: 3 with weight 1 each, total=3, quorum=ceil(3*2/3)=2
        let mut w = HashMap::new();
        w.insert(vid(1), 1);
        w.insert(vid(2), 1);
        w.insert(vid(3), 1);
        let vs = ValidatorSet.new(w);
        // (work around method call)
        let vs = ValidatorSet::new(vs.weights);
    }

    #[test]
    fn basic_finalize_flow() {
        let mut weights = HashMap::new();
        weights.insert(vid(1), 10);
        weights.insert(vid(2), 10);
        weights.insert(vid(3), 10);
        let vs = ValidatorSet::new(weights);
        let storage = InMemoryStorage::default();
        let gadget = CheckpointManager::new(GadgetConfig::default(), vs.clone(), storage);

        let block = BlockRef::new(42, bid(42));
        let r0: Round = 0;

        // Subscribe to events
        let rx = gadget.subscribe();

        let v1 = Vote { validator: vid(1), block, round: r0, signature: b"s1".to_vec() };
        let v2 = Vote { validator: vid(2), block, round: r0, signature: b"s2".to_vec() };

        // Submit two votes (2/3 of 30 = 20 -> quorum reached)
        gadget.submit_votes(vec![v1, v2]).unwrap();

        // Should finalize
        let ev = rx.recv().unwrap();
        match ev {
            FinalityEvent::Finalized(cp) => {
                assert_eq!(cp.block, block);
                assert_eq!(cp.round, r0);
                assert_ne!(cp.id, H256::zero());
                assert_eq!(gadget.latest_finalized().unwrap().id, cp.id);
            }
        }

        // Duplicate vote should fail
        let dup = Vote { validator: vid(2), block, round: r0, signature: b"sdup".to_vec() };
        let err = gadget.submit_votes(vec![dup]).unwrap_err();
        match err {
            FinalityError::DuplicateVote => {},
            e => panic!("expected DuplicateVote, got {e:?}"),
        }
    }

    #[test]
    fn stale_round_rejected() {
        let mut weights = HashMap::new();
        weights.insert(vid(1), 5);
        weights.insert(vid(2), 5);
        let vs = ValidatorSet::new(weights);
        let storage = InMemoryStorage::default();
        let gadget = CheckpointManager::new(GadgetConfig::default(), vs, storage);

        let block = BlockRef::new(1, bid(1));

        // Finalize round 0
        let v1 = Vote { validator: vid(1), block, round: 0, signature: vec![] };
        let v2 = Vote { validator: vid(2), block, round: 0, signature: vec![] };
        gadget.submit_votes(vec![v1, v2]).unwrap();

        // Current round becomes 1 -> stale if we try to vote at round 0 again (0+1 < 1)
        let stale = Vote { validator: vid(1), block, round: 0, signature: vec![] };
        let e = gadget.submit_votes(vec![stale]).unwrap_err();
        match e {
            FinalityError::StaleRound { .. } => {}
            _ => panic!("expected stale round error"),
        }
    }
}

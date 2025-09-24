//! Finality epochs & checkpoints module.
//!
//! Design goals:
//! - Epoch/slot accounting
//! - Checkpoints (root, epoch, parent) with justify/finalize state
//! - Supermajority (e.g., 2/3) justification and FFG-style finalization
//! - Safety checks: double vote & surround vote detection (Casper FFG)
//! - Pluggable storage trait + in-memory store
//! - Deterministic arithmetic (no floats) and explicit errors
//!
//! References (concepts, thresholds, slashing conditions):
//! - Casper the Friendly Finality Gadget (FFG) — 2/3-supermajority links, slashing (double & surround votes). :contentReference[oaicite:1]{index=1}
//! - GRANDPA finality gadget (Polkadot) — независимый сервис финализации, раунды голосования. :contentReference[oaicite:2]{index=2}
//! - Tendermint/PBFT-порог 2/3 для коммита блока (классическая BFT-семья). :contentReference[oaicite:3]{index=3}

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

/// Newtype for slot number.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(pub u64);

impl Slot {
    pub const ZERO: Slot = Slot(0);

    pub fn checked_add(self, rhs: u64) -> Option<Slot> {
        self.0.checked_add(rhs).map(Slot)
    }

    pub fn epoch(self, epoch_len: u64) -> EpochNumber {
        EpochNumber(self.0 / epoch_len)
    }
}

/// Newtype for epoch number.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochNumber(pub u64);

impl EpochNumber {
    pub const ZERO: EpochNumber = EpochNumber(0);
    pub fn next(self) -> EpochNumber {
        EpochNumber(self.0.saturating_add(1))
    }
}

/// 32-byte checkpoint root identifier (e.g., block root).
pub type Root = [u8; 32];

/// Validator identifier (opaque).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatorId(pub u64);

/// Stake weight (supports large validator sets).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Weight(pub u128);

impl Weight {
    pub const ZERO: Weight = Weight(0);
    pub fn checked_add(self, rhs: Weight) -> Option<Weight> {
        self.0.checked_add(rhs.0).map(Weight)
    }
    pub fn saturating_add(self, rhs: Weight) -> Weight {
        Weight(self.0.saturating_add(rhs.0))
    }
    pub fn ge_fraction_of(self, num: u128, den: u128, total: Weight) -> bool {
        // Compare self >= (num/den)*total  ->  self*den >= num*total
        self.0.saturating_mul(den) >= num.saturating_mul(total.0)
    }
}

/// Finality configuration.
#[derive(Clone, Debug)]
pub struct FinalityConfig {
    /// Number of slots per epoch.
    pub epoch_length_slots: u64,
    /// Supermajority numerator (e.g., 2).
    pub supermajority_num: u128,
    /// Supermajority denominator (e.g., 3).
    pub supermajority_den: u128,
    /// Total active stake for the voting set of the epoch-range.
    pub total_active_stake: Weight,
}

impl FinalityConfig {
    pub fn with_two_thirds(epoch_length_slots: u64, total_active_stake: Weight) -> Self {
        Self {
            epoch_length_slots,
            supermajority_num: 2,
            supermajority_den: 3,
            total_active_stake,
        }
    }
}

/// Checkpoint describes an epoch boundary candidate for justification/finality.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub epoch: EpochNumber,
    pub root: Root,
    pub parent: Option<Root>,
    pub justified: bool,
    pub finalized: bool,
    /// Total voting weight observed towards this checkpoint (for current justification round).
    pub accumulated_weight: Weight,
    /// Wall-clock when the checkpoint was seen/created (diagnostic).
    pub created_at_unix_ms: u128,
}

impl Checkpoint {
    pub fn new(epoch: EpochNumber, root: Root, parent: Option<Root>) -> Self {
        Self {
            epoch,
            root,
            parent,
            justified: false,
            finalized: false,
            accumulated_weight: Weight::ZERO,
            created_at_unix_ms: now_ms(),
        }
    }
}

/// Vote record following FFG semantics: source -> target (both are epoch checkpoints).
#[derive(Clone, Debug)]
pub struct Vote {
    pub validator: ValidatorId,
    pub weight: Weight,
    pub source_epoch: EpochNumber,
    pub source_root: Root,
    pub target_epoch: EpochNumber,
    pub target_root: Root,
    pub slot: Slot,
}

/// Events emitted by the finality gadget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalityEvent {
    /// A checkpoint reached supermajority and is justified.
    Justified { target_epoch: EpochNumber, root: Root },
    /// Previous justified checkpoint finalized due to a justified link to a later epoch.
    Finalized { epoch: EpochNumber, root: Root },
}

/// Storage abstraction for checkpoints and votes.
pub trait Storage: Send + Sync {
    fn put_checkpoint(&mut self, cp: Checkpoint);
    fn get_checkpoint(&self, root: &Root) -> Option<Checkpoint>;
    fn update_checkpoint(&mut self, cp: &Checkpoint);
    fn put_vote(&mut self, v: &Vote);
    fn last_vote_of(&self, v: ValidatorId) -> Option<Vote>;
    fn iter_votes_for_target(&self, target_root: &Root) -> Vec<Vote>;
    fn mark_justified(&mut self, root: &Root);
    fn mark_finalized(&mut self, root: &Root);
}

/// In-memory storage (for testing and single-process usage).
#[derive(Default)]
pub struct MemoryStorage {
    cps: HashMap<Root, Checkpoint>,
    votes: Vec<Vote>,
    last_vote_by: HashMap<ValidatorId, Vote>,
    votes_by_target: HashMap<Root, Vec<Vote>>,
}

impl Storage for MemoryStorage {
    fn put_checkpoint(&mut self, cp: Checkpoint) {
        self.cps.insert(cp.root, cp);
    }
    fn get_checkpoint(&self, root: &Root) -> Option<Checkpoint> {
        self.cps.get(root).cloned()
    }
    fn update_checkpoint(&mut self, cp: &Checkpoint) {
        self.cps.insert(cp.root, cp.clone());
    }
    fn put_vote(&mut self, v: &Vote) {
        self.votes.push(v.clone());
        self.last_vote_by.insert(v.validator, v.clone());
        self.votes_by_target.entry(v.target_root).or_default().push(v.clone());
    }
    fn last_vote_of(&self, v: ValidatorId) -> Option<Vote> {
        self.last_vote_by.get(&v).cloned()
    }
    fn iter_votes_for_target(&self, target_root: &Root) -> Vec<Vote> {
        self.votes_by_target.get(target_root).cloned().unwrap_or_default()
    }
    fn mark_justified(&mut self, root: &Root) {
        if let Some(cp) = self.cps.get_mut(root) {
            cp.justified = true;
        }
    }
    fn mark_finalized(&mut self, root: &Root) {
        if let Some(cp) = self.cps.get_mut(root) {
            cp.finalized = true;
        }
    }
}

/// Finality gadget.
pub struct FinalityGadget<S: Storage> {
    cfg: FinalityConfig,
    store: S,
    /// Root of the latest justified checkpoint.
    current_justified: Option<Root>,
    /// Root of the latest finalized checkpoint.
    current_finalized: Option<Root>,
    /// Track known parents to validate simple ancestry checks (optional).
    parents: HashMap<Root, Option<Root>>,
}

#[derive(Debug)]
pub enum FinalityError {
    UnknownSourceCheckpoint,
    UnknownTargetCheckpoint,
    /// Vote by the same validator for different targets at the same target epoch.
    DoubleVote { validator: ValidatorId },
    /// One vote surrounds another (Casper FFG surround rule).
    SurroundVote { validator: ValidatorId },
    ArithmeticOverflow,
    ThresholdZero,
}

impl fmt::Display for FinalityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FinalityError::*;
        match self {
            UnknownSourceCheckpoint => write!(f, "unknown source checkpoint"),
            UnknownTargetCheckpoint => write!(f, "unknown target checkpoint"),
            DoubleVote { validator } => write!(f, "double vote detected for validator {:?}", validator),
            SurroundVote { validator } => write!(f, "surround vote detected for validator {:?}", validator),
            ArithmeticOverflow => write!(f, "arithmetic overflow"),
            ThresholdZero => write!(f, "threshold denominator or total stake is zero"),
        }
    }
}

impl<S: Storage> FinalityGadget<S> {
    pub fn new(cfg: FinalityConfig, store: S) -> Self {
        Self {
            cfg,
            store,
            current_justified: None,
            current_finalized: None,
            parents: HashMap::new(),
        }
    }

    /// Register a checkpoint (epoch boundary). Idempotent by root.
    pub fn register_checkpoint(&mut self, cp: Checkpoint) {
        self.parents.insert(cp.root, cp.parent);
        self.store.put_checkpoint(cp);
    }

    /// Submit a validator vote (FFG-like: source -> target).
    ///
    /// Safety checks:
    /// - Double vote: same validator, same target epoch, different target root. :contentReference[oaicite:4]{index=4}
    /// - Surround vote: existing vote (s1,t1) and new (s2,t2) with s1 < s2 < t2 < t1. :contentReference[oaicite:5]{index=5}
    pub fn submit_vote(&mut self, vote: Vote) -> Result<Vec<FinalityEvent>, FinalityError> {
        // Ensure checkpoints known
        let src = self.store.get_checkpoint(&vote.source_root).ok_or(FinalityError::UnknownSourceCheckpoint)?;
        let tgt = self.store.get_checkpoint(&vote.target_root).ok_or(FinalityError::UnknownTargetCheckpoint)?;

        // Basic epoch monotonicity: source epoch < target epoch
        if !(src.epoch < tgt.epoch) {
            // We allow equal-epoch votes only if explicitly needed; by default reject
            return Err(FinalityError::SurroundVote { validator: vote.validator });
        }

        // Double vote & surround checks against the validator's last vote
        if let Some(prev) = self.store.last_vote_of(vote.validator) {
            // Double vote: same target epoch, different target root
            if prev.target_epoch == vote.target_epoch && prev.target_root != vote.target_root {
                return Err(FinalityError::DoubleVote { validator: vote.validator });
            }
            // Surround vote: s1 < s2 < t2 < t1
            let s1 = prev.source_epoch.0;
            let t1 = prev.target_epoch.0;
            let s2 = vote.source_epoch.0;
            let t2 = vote.target_epoch.0;
            if s1 < s2 && s2 < t2 && t2 < t1 {
                return Err(FinalityError::SurroundVote { validator: vote.validator });
            }
        }

        // Persist the vote
        self.store.put_vote(&vote);

        // Accumulate weight and possibly justify/finalize
        let mut events = Vec::new();
        let weight = self.accumulate_target_weight(&vote.target_root)?;
        if self.reached_supermajority(weight)? {
            // Mark justified
            self.store.mark_justified(&vote.target_root);
            events.push(FinalityEvent::Justified {
                target_epoch: tgt.epoch,
                root: vote.target_root,
            });

            // Finalization rule (FFG style):
            // if (source justified) and (link source->target justified) then source finalized. :contentReference[oaicite:6]{index=6}
            if let Some(src_cp) = self.store.get_checkpoint(&vote.source_root) {
                if src_cp.justified {
                    self.store.mark_finalized(&vote.source_root);
                    events.push(FinalityEvent::Finalized {
                        epoch: src_cp.epoch,
                        root: vote.source_root,
                    });
                    self.current_finalized = Some(vote.source_root);
                }
            }

            self.current_justified = Some(vote.target_root);
        }

        Ok(events)
    }

    /// Total weight accumulated for a target checkpoint (recomputed from storage).
    fn accumulate_target_weight(&mut self, target_root: &Root) -> Result<Weight, FinalityError> {
        let votes = self.store.iter_votes_for_target(target_root);
        let mut acc = Weight::ZERO;
        for v in votes {
            acc = acc.checked_add(v.weight).ok_or(FinalityError::ArithmeticOverflow)?;
        }
        // Update checkpoint view
        if let Some(mut cp) = self.store.get_checkpoint(target_root) {
            cp.accumulated_weight = acc;
            self.store.update_checkpoint(&cp);
        }
        Ok(acc)
    }

    fn reached_supermajority(&self, w: Weight) -> Result<bool, FinalityError> {
        let den = self.cfg.supermajority_den;
        if den == 0 || self.cfg.total_active_stake.0 == 0 {
            return Err(FinalityError::ThresholdZero);
        }
        Ok(w.ge_fraction_of(self.cfg.supermajority_num, den, self.cfg.total_active_stake))
    }

    /// Return currently justified and finalized roots (if any).
    pub fn heads(&self) -> (Option<Root>, Option<Root>) {
        (self.current_justified, self.current_finalized)
    }
}

/// Utility to get monotonic timestamp in milliseconds (diagnostic).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

// ------------------------------ Tests ---------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn r(b: u8) -> Root {
        let mut x = [0u8; 32];
        x[0] = b;
        x
    }

    #[test]
    fn justify_and_finalize_ffg_like() {
        // 4 validators, weights: 30, 30, 30, 10 (total 100) -> 2/3 = 66.666..
        let cfg = FinalityConfig::with_two_thirds(32, Weight(100));
        let mut store = MemoryStorage::default();
        let mut fg = FinalityGadget::new(cfg, store);

        // Register source (epoch 1) and target (epoch 2) checkpoints
        let cp1 = Checkpoint::new(EpochNumber(1), r(1), Some(r(0)));
        let cp2 = Checkpoint::new(EpochNumber(2), r(2), Some(r(1)));

        fg.register_checkpoint(cp1.clone());
        // Mark cp1 justified to allow cp1 finalization when cp2 justified.
        // (In полноценных системах cp1 justify получается из предыдущего раунда.)
        let mut cp1j = cp1.clone();
        cp1j.justified = true;
        fg.register_checkpoint(cp1j);

        fg.register_checkpoint(cp2);

        // Votes towards cp2:
        let v1 = Vote { validator: ValidatorId(1), weight: Weight(30), source_epoch: EpochNumber(1), source_root: r(1), target_epoch: EpochNumber(2), target_root: r(2), slot: Slot(64) };
        let v2 = Vote { validator: ValidatorId(2), weight: Weight(30), source_epoch: EpochNumber(1), source_root: r(1), target_epoch: EpochNumber(2), target_root: r(2), slot: Slot(64) };
        let v3 = Vote { validator: ValidatorId(3), weight: Weight(10), source_epoch: EpochNumber(1), source_root: r(1), target_epoch: EpochNumber(2), target_root: r(2), slot: Slot(64) };

        // 30 + 30 + 10 = 70 >= 2/3*100 -> justify cp2 and finalize cp1
        let mut ev = Vec::new();
        ev.extend(fg.submit_vote(v1).unwrap());
        ev.extend(fg.submit_vote(v2).unwrap());
        ev.extend(fg.submit_vote(v3).unwrap());

        // Expect both events
        assert!(ev.iter().any(|e| matches!(e, FinalityEvent::Justified { target_epoch, .. } if *target_epoch == EpochNumber(2))));
        assert!(ev.iter().any(|e| matches!(e, FinalityEvent::Finalized { epoch, .. } if *epoch == EpochNumber(1))));
    }

    #[test]
    fn double_vote_detected() {
        let cfg = FinalityConfig::with_two_thirds(32, Weight(100));
        let mut fg = FinalityGadget::new(cfg, MemoryStorage::default());

        let cp1 = Checkpoint::new(EpochNumber(1), r(1), Some(r(0)));
        let cp2a = Checkpoint::new(EpochNumber(2), r(2), Some(r(1)));
        let cp2b = Checkpoint::new(EpochNumber(2), r(3), Some(r(1)));

        fg.register_checkpoint(cp1.clone());
        let mut cp1j = cp1.clone();
        cp1j.justified = true;
        fg.register_checkpoint(cp1j);
        fg.register_checkpoint(cp2a);
        fg.register_checkpoint(cp2b);

        let v_ok = Vote { validator: ValidatorId(11), weight: Weight(40), source_epoch: EpochNumber(1), source_root: r(1), target_epoch: EpochNumber(2), target_root: r(2), slot: Slot(65) };
        fg.submit_vote(v_ok).unwrap();

        // Double vote: same target epoch 2, different target root
        let v_bad = Vote { validator: ValidatorId(11), weight: Weight(10), source_epoch: EpochNumber(1), source_root: r(1), target_epoch: EpochNumber(2), target_root: r(3), slot: Slot(66) };
        let err = fg.submit_vote(v_bad).unwrap_err();
        matches!(err, FinalityError::DoubleVote { .. });
    }

    #[test]
    fn surround_vote_detected() {
        let cfg = FinalityConfig::with_two_thirds(32, Weight(100));
        let mut fg = FinalityGadget::new(cfg, MemoryStorage::default());

        let cp1 = Checkpoint::new(EpochNumber(1), r(1), Some(r(0)));
        let cp4 = Checkpoint::new(EpochNumber(4), r(4), Some(r(1)));
        let cp2 = Checkpoint::new(EpochNumber(2), r(2), Some(r(1)));
        let cp3 = Checkpoint::new(EpochNumber(3), r(3), Some(r(2)));

        fg.register_checkpoint(cp1.clone());
        fg.register_checkpoint(cp2);
        fg.register_checkpoint(cp3);
        fg.register_checkpoint(cp4);

        let v1 = Vote { validator: ValidatorId(9), weight: Weight(25), source_epoch: EpochNumber(1), source_root: r(1), target_epoch: EpochNumber(4), target_root: r(4), slot: Slot(70) };
        fg.submit_vote(v1).unwrap();

        // Surround: previous (s1=1,t1=4); new (s2=2,t2=3) satisfies 1 < 2 < 3 < 4
        let v2 = Vote { validator: ValidatorId(9), weight: Weight(25), source_epoch: EpochNumber(2), source_root: r(2), target_epoch: EpochNumber(3), target_root: r(3), slot: Slot(71) };
        let err = fg.submit_vote(v2).unwrap_err();
        matches!(err, FinalityError::SurroundVote { .. });
    }
}

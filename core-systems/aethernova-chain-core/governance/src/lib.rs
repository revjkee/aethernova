// aethernova-chain-core/governance/src/lib.rs
//! Industrial-grade, self-contained governance core in Rust.
//!
//! Key points:
//! - Deterministic H256 IDs for proposals (no external deps; optional crypto behind trait boundaries).
//! - Full proposal lifecycle: propose -> vote -> queue -> execute/cancel.
//! - Snapshot-based voting: voting power provider trait, quorum provider trait.
//! - Off-chain signature voting via pluggable verifier trait (no crypto by default).
//! - Thread-safe in-memory store with receipts and weighted tallies (u128).
//! - Event broadcasting over mpsc.
//!
//! This file is dependency-free (std only). Plug actual crypto/time/VP providers in your runtime.
//! All numeric policy is expressed in blocks (votingDelay, votingPeriod) and seconds (timelock).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 32-byte hash (H256), hex-debuggable.
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
            s.push(nibble_hex(b >> 4));
            s.push(nibble_hex(b & 0x0f));
        }
        s
    }
}
impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}
fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

/// Deterministic non-crypto hasher that folds into 32 bytes (no external deps).
fn hash_bytes(bytes: &[u8]) -> H256 {
    let mut acc = [0u8; 32];
    for (i, ch) in bytes.chunks(32).enumerate() {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        i.hash(&mut h);
        ch.hash(&mut h);
        let v = h.finish().to_be_bytes();
        let off = (i % 4) * 8;
        for j in 0..8 {
            acc[off + j] ^= v[j];
        }
    }
    H256::from_bytes(acc)
}

/// Minimal H160-like address type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address([u8; 20]);
impl Address {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 0x + 40 hex chars
        let mut s = String::with_capacity(42);
        s.push_str("0x");
        for b in self.0 {
            s.push(nibble_hex(b >> 4));
            s.push(nibble_hex(b & 0x0f));
        }
        write!(f, "{s}")
    }
}

/// Voting options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteType {
    Against = 0,
    For = 1,
    Abstain = 2,
}

/// Canonical proposal states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalState {
    Pending,
    Active,
    Canceled,
    Defeated,
    Succeeded,
    Queued,
    Expired,
    Executed,
}

/// Immutable action set (targets/values/calldatas lengths must match).
#[derive(Clone, Debug)]
pub struct ProposalAction {
    pub targets: Vec<Address>,
    pub values: Vec<u128>,
    pub calldatas: Vec<Vec<u8>>,
}
impl ProposalAction {
    pub fn len(&self) -> usize {
        self.targets.len()
    }
    pub fn is_well_formed(&self) -> bool {
        self.targets.len() == self.values.len() && self.values.len() == self.calldatas.len()
    }
}

/// Snapshot-based vote receipt.
#[derive(Clone, Debug)]
pub struct Receipt {
    pub has_voted: bool,
    pub support: VoteType,
    pub weight: u128,
    pub reason: String,
}

/// ECDSA signature tuple for off-chain ballots (opaque for this core).
#[derive(Clone, Debug)]
pub struct Signature {
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

/// Events emitted by the governor.
#[derive(Clone, Debug)]
pub enum GovEvent {
    ProposalCreated {
        id: H256,
        proposer: Address,
        start_block: u64,
        end_block: u64,
        description: String,
        actions: ProposalAction,
    },
    ProposalCanceled { id: H256 },
    ProposalQueued { id: H256, eta: u64 },
    ProposalExecuted { id: H256 },
    VoteCast {
        voter: Address,
        proposal_id: H256,
        support: VoteType,
        weight: u128,
        reason: String,
    },
    ParamVotingDelaySet { old: u64, newv: u64 },
    ParamVotingPeriodSet { old: u64, newv: u64 },
    ParamProposalThresholdSet { old: u128, newv: u128 },
}

/// Errors surfaced by API.
#[derive(Debug)]
pub enum GovError {
    InvalidArrayLengths,
    UnknownProposal,
    UnexpectedState { expected: ProposalState, actual: ProposalState },
    AlreadyQueued,
    NotQueued,
    AlreadyVoted,
    InsufficientProposerVotes { proposer: Address, votes: u128, threshold: u128 },
    SignatureExpired,
    InvalidSignature,
    NonceMismatch,
    Unauthorized,
    Internal(String),
}
impl fmt::Display for GovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use GovError::*;
        match self {
            InvalidArrayLengths => write!(f, "invalid array lengths"),
            UnknownProposal => write!(f, "unknown proposal"),
            UnexpectedState { expected, actual } => write!(f, "unexpected state: expected {expected:?}, got {actual:?}"),
            AlreadyQueued => write!(f, "proposal already queued"),
            NotQueued => write!(f, "proposal not queued"),
            AlreadyVoted => write!(f, "already voted"),
            InsufficientProposerVotes { proposer, votes, threshold } =>
                write!(f, "proposer {:?} has {} < threshold {}", proposer, votes, threshold),
            SignatureExpired => write!(f, "signature expired"),
            InvalidSignature => write!(f, "invalid signature"),
            NonceMismatch => write!(f, "nonce mismatch"),
            Unauthorized => write!(f, "unauthorized"),
            Internal(s) => write!(f, "internal: {s}"),
        }
    }
}
impl std::error::Error for GovError {}

/// Governance configuration (blocks for voting; seconds for timelock).
#[derive(Clone, Debug)]
pub struct GovConfig {
    pub name: String,
    pub counting_mode: String,
    pub voting_delay: u64,         // blocks
    pub voting_period: u64,        // blocks
    pub proposal_threshold: u128,  // absolute votes
    pub timelock_delay: u64,       // seconds
}
impl Default for GovConfig {
    fn default() -> Self {
        Self {
            name: "Aethernova Governance".into(),
            counting_mode: "support=bravo,quorum=for,params=threshold".into(),
            voting_delay: 1,
            voting_period: 45818, // ~1 week on 13s blocks (example only)
            proposal_threshold: 0,
            timelock_delay: 2 * 24 * 60 * 60, // 2 days
        }
    }
}

/// Provider of voting power snapshots.
pub trait VotingPowerProvider: Send + Sync + 'static {
    fn votes_at(&self, who: Address, block: u64) -> u128;
}

/// Provider of quorum requirement per block.
pub trait QuorumProvider: Send + Sync + 'static {
    fn quorum_at(&self, block: u64) -> u128;
}

/// Provider for time source (UNIX seconds).
pub trait TimeSource: Send + Sync + 'static {
    fn now(&self) -> u64;
}

/// Provider to verify off-chain vote signatures.
pub trait SignatureVerifier: Send + Sync + 'static {
    fn verify_vote_sig(
        &self,
        proposal_id: H256,
        support: VoteType,
        voter: Address,
        nonce: u64,
        expiry: u64,
        sig: &Signature,
    ) -> bool;
}

/// Default time source: system clock.
pub struct SystemTimeSource;
impl TimeSource for SystemTimeSource {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Fixed quorum provider (absolute value).
pub struct FixedQuorum(pub u128);
impl QuorumProvider for FixedQuorum {
    fn quorum_at(&self, _block: u64) -> u128 {
        self.0
    }
}

/// No-op signature verifier that always fails.
pub struct NoVerify;
impl SignatureVerifier for NoVerify {
    fn verify_vote_sig(&self, _p: H256, _s: VoteType, _v: Address, _n: u64, _e: u64, _sig: &Signature) -> bool {
        false
    }
}

/// Proposal storage model.
#[derive(Clone)]
struct Proposal {
    id: H256,
    proposer: Address,
    actions: ProposalAction,
    description: String,
    description_hash: H256,
    snapshot: u64,
    deadline: u64,
    eta: Option<u64>,
    canceled: bool,
    executed: bool,
    for_votes: u128,
    against_votes: u128,
    abstain_votes: u128,
    receipts: HashMap<Address, Receipt>,
}

/// In-memory, thread-safe governor implementation.
pub struct InMemoryGovernor {
    cfg: RwLock<GovConfig>,
    vp: Arc<dyn VotingPowerProvider>,
    qp: Arc<dyn QuorumProvider>,
    ts: Arc<dyn TimeSource>,
    sv: Arc<dyn SignatureVerifier>,

    proposals: RwLock<HashMap<H256, Proposal>>,
    nonces: RwLock<HashMap<Address, u64>>,
    subscribers: RwLock<Vec<mpsc::Sender<GovEvent>>>,
}

impl InMemoryGovernor {
    pub fn new(
        cfg: GovConfig,
        vp: Arc<dyn VotingPowerProvider>,
        qp: Arc<dyn QuorumProvider>,
        ts: Arc<dyn TimeSource>,
        sv: Arc<dyn SignatureVerifier>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg: RwLock::new(cfg),
            vp,
            qp,
            ts,
            sv,
            proposals: RwLock::new(HashMap::new()),
            nonces: RwLock::new(HashMap::new()),
            subscribers: RwLock::new(Vec::new()),
        })
    }

    /// Subscribe to governance events.
    pub fn subscribe(&self) -> mpsc::Receiver<GovEvent> {
        let (tx, rx) = mpsc::channel();
        self.subscribers.write().unwrap().push(tx);
        rx
    }

    fn emit(&self, ev: GovEvent) {
        let subs = self.subscribers.read().unwrap().clone();
        for tx in subs {
            let _ = tx.send(ev.clone());
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> String {
        self.cfg.read().unwrap().name.clone()
    }

    /// Counting mode description for UIs/analytics.
    pub fn counting_mode(&self) -> String {
        self.cfg.read().unwrap().counting_mode.clone()
    }

    /// Returns current nonce for a voter (next expected nonce).
    pub fn nonce(&self, voter: Address) -> u64 {
        *self.nonces.read().unwrap().get(&voter).unwrap_or(&0)
    }

    /// Propose new actions. Returns proposal id.
    pub fn propose(
        &self,
        actions: ProposalAction,
        description: String,
        proposer: Address,
        current_block: u64,
    ) -> Result<H256, GovError> {
        if !actions.is_well_formed() {
            return Err(GovError::InvalidArrayLengths);
        }
        // Threshold check at current block
        let cfg = self.cfg.read().unwrap().clone();
        let proposer_votes = self.vp.votes_at(proposer, current_block);
        if proposer_votes < cfg.proposal_threshold {
            return Err(GovError::InsufficientProposerVotes {
                proposer,
                votes: proposer_votes,
                threshold: cfg.proposal_threshold,
            });
        }

        // Deterministic proposal id: hash(targets|values|calldatas|description_hash)
        let mut buf = Vec::new();
        for t in &actions.targets {
            buf.extend_from_slice(t.as_bytes());
        }
        for v in &actions.values {
            buf.extend_from_slice(&v.to_be_bytes());
        }
        for c in &actions.calldatas {
            buf.extend_from_slice(&(c.len() as u64).to_be_bytes());
            buf.extend_from_slice(c);
        }
        let desc_hash = hash_bytes(description.as_bytes());
        buf.extend_from_slice(desc_hash.as_bytes());
        let id = hash_bytes(&buf);

        let snapshot = current_block.saturating_add(cfg.voting_delay);
        let deadline = snapshot.saturating_add(cfg.voting_period);

        let p = Proposal {
            id,
            proposer,
            actions: actions.clone(),
            description: description.clone(),
            description_hash: desc_hash,
            snapshot,
            deadline,
            eta: None,
            canceled: false,
            executed: false,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            receipts: HashMap::new(),
        };

        self.proposals.write().unwrap().insert(id, p.clone());
        self.emit(GovEvent::ProposalCreated {
            id,
            proposer,
            start_block: snapshot,
            end_block: deadline,
            description,
            actions,
        });
        Ok(id)
    }

    /// Returns derived state for a proposal.
    pub fn state(&self, id: H256, current_block: u64, now: u64) -> Result<ProposalState, GovError> {
        let p = self.proposals.read().unwrap().get(&id).cloned().ok_or(GovError::UnknownProposal)?;
        if p.canceled {
            return Ok(ProposalState::Canceled);
        }
        if p.executed {
            return Ok(ProposalState::Executed);
        }
        if p.eta.is_some() {
            // queued or expired
            let eta = p.eta.unwrap();
            if now > eta && self.is_defeated(&p) {
                return Ok(ProposalState::Expired); // safety: shouldn't happen if already succeeded
            }
            // If queued and time not reached -> Queued; after execute it becomes Executed.
            if now < eta {
                return Ok(ProposalState::Queued);
            }
            // If now >= eta and not executed -> still Queued (awaiting execute)
            return Ok(ProposalState::Queued);
        }
        if current_block <= p.snapshot.saturating_sub(1) {
            return Ok(ProposalState::Pending);
        }
        if current_block <= p.deadline.saturating_sub(1) {
            return Ok(ProposalState::Active);
        }
        // After deadline: either Defeated or Succeeded
        if self.is_defeated(&p) {
            Ok(ProposalState::Defeated)
        } else {
            Ok(ProposalState::Succeeded)
        }
    }

    fn is_defeated(&self, p: &Proposal) -> bool {
        // Quorum on For+Abstain; outcome by For > Against (strict).
        let q = self.qp.quorum_at(p.snapshot);
        let participating = p.for_votes.saturating_add(p.abstain_votes);
        !(participating >= q && p.for_votes > p.against_votes)
    }

    /// Cast a vote.
    pub fn cast_vote(
        &self,
        id: H256,
        voter: Address,
        support: VoteType,
        reason: Option<String>,
        current_block: u64,
    ) -> Result<u128, GovError> {
        let mut store = self.proposals.write().unwrap();
        let p = store.get_mut(&id).ok_or(GovError::UnknownProposal)?;

        // State must be Active
        let state = self.state(id, current_block, self.ts.now())?;
        if state != ProposalState::Active {
            return Err(GovError::UnexpectedState { expected: ProposalState::Active, actual: state });
        }
        if p.receipts.get(&voter).map(|r| r.has_voted).unwrap_or(false) {
            return Err(GovError::AlreadyVoted);
        }

        // Weight is snapshotted at proposal.snapshot
        let weight = self.vp.votes_at(voter, p.snapshot);
        let reason_str = reason.unwrap_or_default();
        let rec = Receipt {
            has_voted: true,
            support,
            weight,
            reason: reason_str.clone(),
        };
        p.receipts.insert(voter, rec);

        match support {
            VoteType::Against => p.against_votes = p.against_votes.saturating_add(weight),
            VoteType::For => p.for_votes = p.for_votes.saturating_add(weight),
            VoteType::Abstain => p.abstain_votes = p.abstain_votes.saturating_add(weight),
        }

        self.emit(GovEvent::VoteCast {
            voter,
            proposal_id: id,
            support,
            weight,
            reason: reason_str,
        });

        Ok(weight)
    }

    /// Cast a vote by signature (nonce/expiry enforced; verification via trait).
    pub fn cast_vote_by_sig(
        &self,
        id: H256,
        support: VoteType,
        voter: Address,
        sig: Signature,
        nonce: u64,
        expiry: u64,
        current_block: u64,
    ) -> Result<u128, GovError> {
        if self.ts.now() > expiry {
            return Err(GovError::SignatureExpired);
        }
        let current_nonce = self.nonce(voter);
        if nonce != current_nonce {
            return Err(GovError::NonceMismatch);
        }
        if !self.sv.verify_vote_sig(id, support, voter, nonce, expiry, &sig) {
            return Err(GovError::InvalidSignature);
        }

        // advance nonce
        self.nonces.write().unwrap().insert(voter, current_nonce + 1);

        self.cast_vote(id, voter, support, None, current_block)
    }

    /// Get receipt.
    pub fn receipt(&self, id: H256, voter: Address) -> Result<Option<Receipt>, GovError> {
        let p = self.proposals.read().unwrap().get(&id).ok_or(GovError::UnknownProposal)?;
        Ok(p.receipts.get(&voter).cloned())
    }

    /// Queue a succeeded proposal for timelock.
    pub fn queue(&self, id: H256, current_block: u64) -> Result<u64, GovError> {
        let now = self.ts.now();
        let mut store = self.proposals.write().unwrap();
        let p = store.get_mut(&id).ok_or(GovError::UnknownProposal)?;
        if p.eta.is_some() {
            return Err(GovError::AlreadyQueued);
        }
        let state = self.state(id, current_block, now)?;
        if state != ProposalState::Succeeded {
            return Err(GovError::UnexpectedState { expected: ProposalState::Succeeded, actual: state });
        }
        let eta = now.saturating_add(self.cfg.read().unwrap().timelock_delay);
        p.eta = Some(eta);
        self.emit(GovEvent::ProposalQueued { id, eta });
        Ok(eta)
    }

    /// Execute a queued proposal.
    pub fn execute(&self, id: H256) -> Result<(), GovError> {
        let now = self.ts.now();
        let mut store = self.proposals.write().unwrap();
        let p = store.get_mut(&id).ok_or(GovError::UnknownProposal)?;
        let eta = p.eta.ok_or(GovError::NotQueued)?;
        if now < eta {
            return Err(GovError::UnexpectedState { expected: ProposalState::Queued, actual: ProposalState::Pending });
        }
        if p.executed {
            return Err(GovError::UnexpectedState { expected: ProposalState::Queued, actual: ProposalState::Executed });
        }
        p.executed = true;
        self.emit(GovEvent::ProposalExecuted { id });
        Ok(())
    }

    /// Cancel a proposal (e.g., proposer dropped below threshold).
    pub fn cancel(&self, id: H256, current_block: u64) -> Result<(), GovError> {
        let mut store = self.proposals.write().unwrap();
        let p = store.get_mut(&id).ok_or(GovError::UnknownProposal)?;
        if p.executed {
            return Err(GovError::UnexpectedState { expected: ProposalState::Active, actual: ProposalState::Executed });
        }
        if p.canceled {
            return Ok(());
        }
        let threshold = self.cfg.read().unwrap().proposal_threshold;
        let proposer_votes = self.vp.votes_at(p.proposer, current_block);
        if proposer_votes >= threshold {
            return Err(GovError::Unauthorized);
        }
        p.canceled = true;
        self.emit(GovEvent::ProposalCanceled { id });
        Ok(())
    }

    /// Governance parameter setters (emit events).
    pub fn set_voting_delay(&self, new_delay: u64) {
        let mut cfg = self.cfg.write().unwrap();
        let old = cfg.voting_delay;
        cfg.voting_delay = new_delay;
        drop(cfg);
        self.emit(GovEvent::ParamVotingDelaySet { old, newv: new_delay });
    }
    pub fn set_voting_period(&self, new_period: u64) {
        let mut cfg = self.cfg.write().unwrap();
        let old = cfg.voting_period;
        cfg.voting_period = new_period;
        drop(cfg);
        self.emit(GovEvent::ParamVotingPeriodSet { old, newv: new_period });
    }
    pub fn set_proposal_threshold(&self, new_threshold: u128) {
        let mut cfg = self.cfg.write().unwrap();
        let old = cfg.proposal_threshold;
        cfg.proposal_threshold = new_threshold;
        drop(cfg);
        self.emit(GovEvent::ParamProposalThresholdSet { old, newv: new_threshold });
    }

    /// Introspection helpers
    pub fn proposal_actions(&self, id: H256) -> Result<ProposalAction, GovError> {
        let p = self.proposals.read().unwrap().get(&id).ok_or(GovError::UnknownProposal)?;
        Ok(p.actions.clone())
    }
    pub fn proposal_proposer(&self, id: H256) -> Result<Address, GovError> {
        let p = self.proposals.read().unwrap().get(&id).ok_or(GovError::UnknownProposal)?;
        Ok(p.proposer)
    }
    pub fn proposal_snapshot(&self, id: H256) -> Result<u64, GovError> {
        let p = self.proposals.read().unwrap().get(&id).ok_or(GovError::UnknownProposal)?;
        Ok(p.snapshot)
    }
    pub fn proposal_deadline(&self, id: H256) -> Result<u64, GovError> {
        let p = self.proposals.read().unwrap().get(&id).ok_or(GovError::UnknownProposal)?;
        Ok(p.deadline)
    }
    pub fn proposal_eta(&self, id: H256) -> Result<u64, GovError> {
        let p = self.proposals.read().unwrap().get(&id).ok_or(GovError::UnknownProposal)?;
        Ok(p.eta.unwrap_or(0))
    }

    /// Derive description hash (for parity with Solidity UIs).
    pub fn hash_description(desc: &str) -> H256 {
        hash_bytes(desc.as_bytes())
    }
}

// ------------------------------- Tests ---------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockVP {
        // block -> address -> votes
        map: HashMap<u64, HashMap<Address, u128>>,
    }
    impl VotingPowerProvider for MockVP {
        fn votes_at(&self, who: Address, block: u64) -> u128 {
            self.map.get(&block).and_then(|m| m.get(&who).cloned()).unwrap_or(0)
        }
    }

    #[derive(Clone)]
    struct MockTime {
        now: Arc<RwLock<u64>>,
    }
    impl MockTime {
        fn new(ts: u64) -> Self {
            Self { now: Arc::new(RwLock::new(ts)) }
        }
        fn set(&self, ts: u64) { *self.now.write().unwrap() = ts; }
    }
    impl TimeSource for MockTime {
        fn now(&self) -> u64 { *self.now.read().unwrap() }
    }

    struct TrueSig;
    impl SignatureVerifier for TrueSig {
        fn verify_vote_sig(&self, _p: H256, _s: VoteType, _v: Address, _n: u64, _e: u64, _sig: &Signature) -> bool {
            true
        }
    }

    fn addr(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address::new(b)
    }

    #[test]
    fn end_to_end_lifecycle() {
        // Setup providers
        let mut vp = MockVP::default();
        let a1 = addr(1);
        let a2 = addr(2);
        // Voting power: block 10 -> proposer and voters
        vp.map.entry(10).or_default().insert(a1, 1_000);
        vp.map.entry(11).or_default().insert(a1, 1_000);
        vp.map.entry(11).or_default().insert(a2, 800);

        let ts = MockTime::new(1_700_000_000);
        let cfg = GovConfig {
            name: "TestGov".into(),
            counting_mode: "support=bravo,quorum=for".into(),
            voting_delay: 1,
            voting_period: 5,
            proposal_threshold: 100,
            timelock_delay: 3600,
        };
        let gov = InMemoryGovernor::new(cfg, Arc::new(vp), Arc::new(FixedQuorum(500)), Arc::new(ts.clone()), Arc::new(TrueSig));

        let rx = gov.subscribe();

        // Propose at block 10
        let actions = ProposalAction {
            targets: vec![addr(9)],
            values: vec![0u128],
            calldatas: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        };
        let pid = gov.propose(actions.clone(), "desc".into(), a1, 10).unwrap();

        // Check created event
        let ev = rx.recv().unwrap();
        match ev {
            GovEvent::ProposalCreated { id, proposer, start_block, end_block, .. } => {
                assert_eq!(id, pid);
                assert_eq!(proposer, a1);
                assert_eq!(start_block, 11);
                assert_eq!(end_block, 16);
            }
            _ => panic!("unexpected event"),
        }

        // Pending at block 10, Active at 11..15
        assert_eq!(gov.state(pid, 10, 0).unwrap(), ProposalState::Pending);
        assert_eq!(gov.state(pid, 11, 0).unwrap(), ProposalState::Active);

        // Vote by signature for a2 at block 11
        let sig = Signature { v: 27, r: H256::zero(), s: H256::zero() };
        let weight = gov.cast_vote_by_sig(pid, VoteType::For, a2, sig, 0, ts.now() + 1000, 11).unwrap();
        assert_eq!(weight, 800);

        // Close voting: jump to block 16
        assert_eq!(gov.state(pid, 16, 0).unwrap(), ProposalState::Succeeded);

        // Queue
        let eta = gov.queue(pid, 16).unwrap();
        let ev2 = rx.recv().unwrap();
        match ev2 {
            GovEvent::ProposalQueued { id, eta: e } => {
                assert_eq!(id, pid);
                assert_eq!(e, eta);
            }
            _ => panic!("unexpected event"),
        }

        // Execute after timelock
        ts.set(eta + 1);
        gov.execute(pid).unwrap();
        let ev3 = rx.recv().unwrap();
        match ev3 {
            GovEvent::ProposalExecuted { id } => assert_eq!(id, pid),
            _ => panic!("unexpected event"),
        }
        assert_eq!(gov.state(pid, 16, ts.now()).unwrap(), ProposalState::Executed);
    }

    #[test]
    fn cancel_requires_proposer_below_threshold() {
        let mut vp = MockVP::default();
        let proposer = addr(1);
        // at block 5 proposer has 10 votes (< threshold 100)
        vp.map.entry(5).or_default().insert(proposer, 10);

        let ts = MockTime::new(0);
        let cfg = GovConfig { voting_delay: 1, voting_period: 3, proposal_threshold: 1, timelock_delay: 1, name: "x".into(), counting_mode: "x".into() };
        let gov = InMemoryGovernor::new(cfg, Arc::new(vp), Arc::new(FixedQuorum(1)), Arc::new(ts), Arc::new(NoVerify));

        let pid = gov.propose(
            ProposalAction { targets: vec![addr(2)], values: vec![0], calldatas: vec![vec![]] },
            "d".into(),
            proposer,
            5,
        ).unwrap();

        // At block 5 proposer still has >= threshold -> cancel should fail
        assert!(matches!(gov.cancel(pid, 5), Err(GovError::Unauthorized)));

        // When at block 6 VP provider returns 0 -> cancel succeeds
        assert!(gov.cancel(pid, 6).is_ok());
        assert_eq!(gov.state(pid, 6, 0).unwrap(), ProposalState::Canceled);
    }

    #[test]
    fn quorum_and_tallies() {
        let mut vp = MockVP::default();
        let a = addr(1);
        vp.map.entry(100).or_default().insert(a, 1000);

        let ts = MockTime::new(0);
        let cfg = GovConfig { voting_delay: 1, voting_period: 1, proposal_threshold: 1, timelock_delay: 1, name: "x".into(), counting_mode: "x".into() };
        let gov = InMemoryGovernor::new(cfg, Arc::new(vp), Arc::new(FixedQuorum(1001)), Arc::new(ts), Arc::new(NoVerify));

        let pid = gov.propose(
            ProposalAction { targets: vec![addr(2)], values: vec![0], calldatas: vec![vec![]] },
            "d".into(),
            a,
            100,
        ).unwrap();

        // Active at 101; cast FOR with weight 1000
        let _ = gov.cast_vote(pid, a, VoteType::For, None, 101).unwrap();

        // After deadline (102): quorum is 1001, for+abstain=1000 -> Defeated
        assert_eq!(gov.state(pid, 102, 0).unwrap(), ProposalState::Defeated);
    }
}

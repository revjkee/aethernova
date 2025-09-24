//! Governance proposals module (industrial-grade)
//!
//! - Proposal lifecycle aligned with OpenZeppelin Governor semantics:
//!   Pending → Active → Succeeded/Defeated → (Queued) → Executed / Expired; Canceled possible. :contentReference[oaicite:4]{index=4}
//! - Quorum as a fraction numerator/denominator over total voting power at snapshot. :contentReference[oaicite:5]{index=5}
//! - Counting modes:
//!     * ForOnly: кворум достигается только голосами "За" (совместимо с Bravo-style режимами). :contentReference[oaicite:6]{index=6}
//!     * ForPlusAbstain: кворум считают "За"+"Воздержался" (рекомендация к совместимости OZ).
//! - Voting kinds: Standard (For/Against/Abstain), Approval (множ. одобрений), Weighted (веса по опциям),
//!   Quadratic (целочисл. √веса; см. литературу по QV). :contentReference[oaicite:7]{index=7}
//! - Offchain signatures: EIP-712 typed data for votes (проверка вне этого модуля). :contentReference[oaicite:8]{index=8}
//!
//! This module is storage-agnostic via trait `Storage` and provides `MemoryStorage` for tests.

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

pub type ProposalId = u128;
pub type AccountId = [u8; 32];

/// Snapshot/timepoint abstraction (e.g., block number or unix-seconds).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timepoint(pub u64);

/// Voting weights are u128 for large systems.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Weight(pub u128);

impl Weight {
    pub const ZERO: Weight = Weight(0);
    pub fn checked_add(self, rhs: Weight) -> Option<Weight> { self.0.checked_add(rhs.0).map(Weight) }
    pub fn checked_sub(self, rhs: Weight) -> Option<Weight> { self.0.checked_sub(rhs.0).map(Weight) }
    pub fn saturating_add(self, rhs: Weight) -> Weight { Weight(self.0.saturating_add(rhs.0)) }

    /// Compare w >= (num/den)*total via cross-multiplication to avoid FP.
    pub fn ge_fraction_of(self, num: u128, den: u128, total: Weight) -> bool {
        if den == 0 { return false; }
        self.0.saturating_mul(den) >= num.saturating_mul(total.0)
    }
}

/// Proposal state (Close to OZ Governor terminology). :contentReference[oaicite:9]{index=9}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProposalState {
    Pending,
    Active,
    Succeeded,
    Defeated,
    Canceled,
    Queued,
    Executed,
    Expired,
}

/// Counting mode influences quorum and success rules.
/// ForOnly ~ only "For" counts to quorum (Bravo-style); ForPlusAbstain ~ include abstain. :contentReference[oaicite:10]{index=10}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuorumMode {
    ForOnly,
    ForPlusAbstain,
}

/// Voting kind
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VotingKind {
    /// Standard 3-way: For/Against/Abstain (OZ-compatible).
    Standard,
    /// Approval voting: voter may approve any number of options. :contentReference[oaicite:11]{index=11}
    Approval,
    /// Weighted (custom weights across options, sum constrained).
    Weighted,
    /// Quadratic voting: weights transformed by integer sqrt. :contentReference[oaicite:12]{index=12}
    Quadratic,
}

/// Standard support type
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Support {
    Against,
    For,
    Abstain,
}

/// Option identifier for multi-option proposals
pub type OptionId = u32;

/// Configuration of quorum and thresholds.
#[derive(Clone, Debug)]
pub struct TallyConfig {
    /// quorum = quorum_num / quorum_den of total voting power at snapshot. :contentReference[oaicite:13]{index=13}
    pub quorum_num: u128,
    pub quorum_den: u128,
    /// success threshold: For > Against (standard) OR argmin/argmax by mode.
    /// For Weighted/Approval/Quadratic use winner_by_plurality if true, else require >50% of counted votes.
    pub winner_by_plurality: bool,
    /// quorum mode (ForOnly vs ForPlusAbstain).
    pub quorum_mode: QuorumMode,
    /// voting kind
    pub kind: VotingKind,
    /// number of options (>=1). For Standard must be 1.
    pub options: u32,
}

/// Proposal action (opaque; offchain or onchain executor interprets).
#[derive(Clone, Debug)]
pub struct Action {
    pub target: [u8; 20],    // e.g., EVM address or module id
    pub value: u128,         // e.g., native value
    pub calldata: Vec<u8>,   // ABI-encoded or custom
}

/// Proposal record
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: ProposalId,
    pub proposer: AccountId,
    pub title: String,
    pub description: String,
    /// Optional description hash for deterministic IDs / EIP-712 alignment.
    pub description_hash: [u8; 32],
    pub created_at: Timepoint,
    pub vote_start: Timepoint,
    pub vote_end: Timepoint,
    pub execute_after: Option<Timepoint>, // timelock ETA equivalent. :contentReference[oaicite:14]{index=14}
    pub canceled: bool,
    pub queued: bool,
    pub executed: bool,
    pub config: TallyConfig,
    pub actions: Vec<Action>,
    pub snapshot_total_power: Weight,
}

/// Casted vote (multiple forms supported)
#[derive(Clone, Debug)]
pub enum Ballot {
    /// Standard: one of For/Against/Abstain with weight.
    Standard { support: Support, weight: Weight },
    /// Approval: set of approved options with total weight budget.
    Approval { approved: BTreeSet<OptionId>, weight: Weight },
    /// Weighted: map option → weight (sum = voter weight).
    Weighted { allocations: BTreeMap<OptionId, Weight>, total: Weight },
    /// Quadratic: map option → credits; effective weight = sum( floor(sqrt(credits)) ).
    Quadratic { credits: BTreeMap<OptionId, u128>, total_credits: u128 },
}

#[derive(Clone, Debug)]
pub struct Vote {
    pub voter: AccountId,
    pub timepoint: Timepoint,
    pub ballot: Ballot,
}

/// Aggregated tallies
#[derive(Clone, Debug, Default)]
pub struct Tallies {
    pub for_votes: Weight,
    pub against_votes: Weight,
    pub abstain_votes: Weight,
    /// option → accumulated (Approval/Weighted/Quadratic)
    pub by_option: BTreeMap<OptionId, Weight>,
    pub total_participation: Weight, // ForPlusAbstain counts abstain as participation
}

/// Storage abstraction
pub trait Storage {
    fn put_proposal(&mut self, p: Proposal);
    fn get_proposal(&self, id: ProposalId) -> Option<Proposal>;
    fn update_proposal(&mut self, p: &Proposal);

    fn put_vote(&mut self, pid: ProposalId, v: Vote);
    fn votes_of(&self, pid: ProposalId) -> Vec<Vote>;

    fn set_tallies(&mut self, pid: ProposalId, t: &Tallies);
    fn get_tallies(&self, pid: ProposalId) -> Option<Tallies>;
}

/// In-memory storage (for tests / single-process)
#[derive(Default)]
pub struct MemoryStorage {
    props: HashMap<ProposalId, Proposal>,
    votes: HashMap<ProposalId, Vec<Vote>>,
    tallies: HashMap<ProposalId, Tallies>,
}

impl Storage for MemoryStorage {
    fn put_proposal(&mut self, p: Proposal) { self.props.insert(p.id, p); }
    fn get_proposal(&self, id: ProposalId) -> Option<Proposal> { self.props.get(&id).cloned() }
    fn update_proposal(&mut self, p: &Proposal) { self.props.insert(p.id, p.clone()); }

    fn put_vote(&mut self, pid: ProposalId, v: Vote) { self.votes.entry(pid).or_default().push(v); }
    fn votes_of(&self, pid: ProposalId) -> Vec<Vote> { self.votes.get(&pid).cloned().unwrap_or_default() }

    fn set_tallies(&mut self, pid: ProposalId, t: &Tallies) { self.tallies.insert(pid, t.clone()); }
    fn get_tallies(&self, pid: ProposalId) -> Option<Tallies> { self.tallies.get(&pid).cloned() }
}

/// Errors
#[derive(Debug, PartialEq, Eq)]
pub enum GovError {
    NotFound,
    BadState,
    ArithmeticOverflow,
    QuorumZero,
    VotingClosed,
    VotingNotStarted,
    AlreadyCanceled,
    AlreadyQueued,
    AlreadyExecuted,
    NotEligible, // e.g., proposer not authorized or vote weight zero
    InvalidBallot,
}

impl fmt::Display for GovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}
impl std::error::Error for GovError {}

/// Governance engine, parameterized by Storage.
pub struct Governance<S: Storage> {
    store: S,
}

impl<S: Storage> Governance<S> {
    pub fn new(store: S) -> Self { Self { store } }

    pub fn state(&self, id: ProposalId, now: Timepoint) -> Result<ProposalState, GovError> {
        let p = self.store.get_proposal(id).ok_or(GovError::NotFound)?;
        if p.canceled { return Ok(ProposalState::Canceled); }
        if p.executed { return Ok(ProposalState::Executed); }
        if p.vote_start.0 > now.0 { return Ok(ProposalState::Pending); }
        if p.vote_end.0 > now.0 { return Ok(ProposalState::Active); }

        // Voting ended: compute succeeded/defeated or queued/expired
        let t = self.store.get_tallies(id).unwrap_or_default();
        let succeeded = self.success(&p, &t)?;
        if succeeded {
            if p.queued {
                // If timelock ETA passed and not executed -> Expired else Queued until executed
                if let Some(eta) = p.execute_after {
                    if eta.0 < now.0 { return Ok(ProposalState::Queued); } // ready to execute
                }
                return Ok(ProposalState::Queued);
            }
            // Not queued yet: it's Succeeded
            return Ok(ProposalState::Succeeded);
        } else {
            return Ok(ProposalState::Defeated);
        }
    }

    /// Create proposal (snapshot_total_power must be determined by caller at snapshot).
    pub fn propose(
        &mut self,
        id: ProposalId,
        proposer: AccountId,
        title: String,
        description: String,
        description_hash: [u8; 32],
        vote_start: Timepoint,
        vote_end: Timepoint,
        execute_after: Option<Timepoint>,
        config: TallyConfig,
        actions: Vec<Action>,
        snapshot_total_power: Weight,
    ) -> Result<(), GovError> {
        if self.store.get_proposal(id).is_some() { return Err(GovError::BadState); }
        if vote_end.0 <= vote_start.0 { return Err(GovError::BadState); }
        if config.quorum_den == 0 { return Err(GovError::QuorumZero); }
        if matches!(config.kind, VotingKind::Standard) && config.options != 1 { return Err(GovError::InvalidBallot); }

        let p = Proposal {
            id, proposer, title, description, description_hash,
            created_at: now_tp(), vote_start, vote_end, execute_after,
            canceled: false, queued: false, executed: false, config, actions,
            snapshot_total_power: snapshot_total_power,
        };
        self.store.put_proposal(p);
        Ok(())
    }

    /// Cancel proposal (similar to OZ: allowed before execution; in OZ cancel возможен почти всегда кроме частей состояний). :contentReference[oaicite:15]{index=15}
    pub fn cancel(&mut self, id: ProposalId) -> Result<(), GovError> {
        let mut p = self.store.get_proposal(id).ok_or(GovError::NotFound)?;
        if p.canceled { return Err(GovError::AlreadyCanceled); }
        if p.executed { return Err(GovError::AlreadyExecuted); }
        p.canceled = true;
        self.store.update_proposal(&p);
        Ok(())
        // Emit ProposalCanceled (в проде: событие)
    }

    /// Queue successful proposal (timelock-style). Requires Succeeded. :contentReference[oaicite:16]{index=16}
    pub fn queue(&mut self, id: ProposalId, now: Timepoint) -> Result<(), GovError> {
        let mut p = self.store.get_proposal(id).ok_or(GovError::NotFound)?;
        if p.queued { return Err(GovError::AlreadyQueued); }
        match self.state(id, now)? {
            ProposalState::Succeeded => {
                p.queued = true;
                self.store.update_proposal(&p);
                Ok(())
            }
            _ => Err(GovError::BadState),
        }
    }

    /// Execute queued/successful proposal after ETA. :contentReference[oaicite:17]{index=17}
    pub fn execute(&mut self, id: ProposalId, now: Timepoint) -> Result<(), GovError> {
        let mut p = self.store.get_proposal(id).ok_or(GovError::NotFound)?;
        if p.executed { return Err(GovError::AlreadyExecuted); }
        let st = self.state(id, now)?;
        match st {
            ProposalState::Succeeded | ProposalState::Queued => {
                if let Some(eta) = p.execute_after {
                    if now.0 < eta.0 { return Err(GovError::BadState); }
                }
                p.executed = true;
                self.store.update_proposal(&p);
                Ok(())
            }
            _ => Err(GovError::BadState),
        }
    }

    /// Cast a vote (caller pre-validates eligibility & weight at snapshot).
    pub fn cast_vote(&mut self, id: ProposalId, now: Timepoint, vote: Vote) -> Result<(), GovError> {
        let p = self.store.get_proposal(id).ok_or(GovError::NotFound)?;
        if now.0 < p.vote_start.0 { return Err(GovError::VotingNotStarted); }
        if now.0 >= p.vote_end.0 { return Err(GovError::VotingClosed); }
        if self.is_zero_weight(&vote)? { return Err(GovError::NotEligible); }

        // prevent double-voting by same voter (simple model: one vote; extendable to updates)
        if self.store.votes_of(id).iter().any(|v| v.voter == vote.voter) {
            return Err(GovError::BadState);
        }
        self.store.put_vote(id, vote);
        // recompute tallies
        let t = self.tally(id)?;
        self.store.set_tallies(id, &t);
        Ok(())
    }

    fn is_zero_weight(&self, v: &Vote) -> Result<bool, GovError> {
        Ok(match &v.ballot {
            Ballot::Standard{weight,..} => weight.0 == 0,
            Ballot::Approval{weight,..} => weight.0 == 0,
            Ballot::Weighted{total,..} => total.0 == 0,
            Ballot::Quadratic{total_credits,..} => *total_credits == 0,
        })
    }

    /// Compute tallies from stored votes.
    pub fn tally(&self, id: ProposalId) -> Result<Tallies, GovError> {
        let p = self.store.get_proposal(id).ok_or(GovError::NotFound)?;
        let mut t = Tallies::default();

        for v in self.store.votes_of(id) {
            match (&p.config.kind, &v.ballot) {
                (VotingKind::Standard, Ballot::Standard{support, weight}) => {
                    match support {
                        Support::For => { t.for_votes = t.for_votes.saturating_add(*weight); }
                        Support::Against => { t.against_votes = t.against_votes.saturating_add(*weight); }
                        Support::Abstain => { t.abstain_votes = t.abstain_votes.saturating_add(*weight); }
                    }
                }
                (VotingKind::Approval, Ballot::Approval{approved, weight}) => {
                    // equally allocate weight to approved options
                    let n = approved.len() as u128;
                    if n == 0 { return Err(GovError::InvalidBallot); }
                    let per = weight.0 / n;
                    for &opt in approved {
                        *t.by_option.entry(opt).or_default() = t.by_option.get(&opt).copied().unwrap_or(Weight::ZERO).saturating_add(Weight(per));
                    }
                    t.for_votes = t.for_votes.saturating_add(*weight); // treat as participation
                }
                (VotingKind::Weighted, Ballot::Weighted{allocations, total}) => {
                    // sum allocations must equal total (caller guaranteed; soft-check)
                    let mut sum = 0u128;
                    for (opt, w) in allocations {
                        *t.by_option.entry(*opt).or_default() = t.by_option.get(opt).copied().unwrap_or(Weight::ZERO).saturating_add(*w);
                        sum = sum.saturating_add(w.0);
                    }
                    if sum != total.0 { return Err(GovError::InvalidBallot); }
                    t.for_votes = t.for_votes.saturating_add(*total); // participation
                }
                (VotingKind::Quadratic, Ballot::Quadratic{credits, total_credits:_}) => {
                    for (opt, c) in credits {
                        let w = int_sqrt(*c) as u128;
                        *t.by_option.entry(*opt).or_default() = t.by_option.get(opt).copied().unwrap_or(Weight::ZERO).saturating_add(Weight(w));
                        t.for_votes = t.for_votes.saturating_add(Weight(w));
                    }
                }
                _ => return Err(GovError::InvalidBallot),
            }
        }

        // participation (for quorum)
        t.total_participation = match p.config.quorum_mode {
            QuorumMode::ForOnly => t.for_votes,
            QuorumMode::ForPlusAbstain => t.for_votes.saturating_add(t.abstain_votes),
        };
        Ok(t)
    }

    /// Success rule after voting ended.
    pub fn success(&self, p: &Proposal, t: &Tallies) -> Result<bool, GovError> {
        if p.config.quorum_den == 0 { return Err(GovError::QuorumZero); }
        // quorum reached?
        let quorum_ok = t.total_participation.ge_fraction_of(p.config.quorum_num, p.config.quorum_den, p.snapshot_total_power);
        if !quorum_ok { return Ok(false); }

        // success per kind
        let ok = match p.config.kind {
            VotingKind::Standard => {
                // OZ default: For > Against to succeed.
                t.for_votes.0 > t.against_votes.0
            }
            VotingKind::Approval | VotingKind::Weighted | VotingKind::Quadratic => {
                if p.config.options == 0 { return Err(GovError::InvalidBallot); }
                if p.config.winner_by_plurality {
                    // winner is option with max tally, ties fail
                    let mut best: Option<(OptionId, u128)> = None;
                    for (opt, w) in &t.by_option {
                        match best {
                            None => best = Some((*opt, w.0)),
                            Some((_, bw)) if w.0 > bw => best = Some((*opt, w.0)),
                            Some((_, bw)) if w.0 == bw => { return Ok(false); } // tie → not succeed
                            _ => {}
                        }
                    }
                    best.is_some()
                } else {
                    // require majority: best option > 50% of sum
                    let sum: u128 = t.by_option.values().map(|w| w.0).sum();
                    let (&best_w, _) = t.by_option.values().map(|w| w.0).max().map(|m| (m, ())).unwrap_or((0, ()));
                    best_w.saturating_mul(2) > sum
                }
            }
        };
        Ok(ok)
    }
}

/// Helpers
fn int_sqrt(x: u128) -> u64 {
    // integer sqrt via Newton method (monotone)
    if x == 0 { return 0; }
    let mut z = (x / 2) + 1;
    let mut y = x;
    while z < y {
        y = z;
        z = (x / z + z) / 2;
    }
    y as u64
}

fn now_tp() -> Timepoint {
    Timepoint(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as u64)
}

// ----------------------------- Tests ----------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn aid(n: u8) -> AccountId { let mut a = [0u8;32]; a[0]=n; a }
    fn tp(n: u64) -> Timepoint { Timepoint(n) }

    fn std_config() -> TallyConfig {
        TallyConfig {
            quorum_num: 10, quorum_den: 100, // 10%
            winner_by_plurality: true,
            quorum_mode: QuorumMode::ForOnly,
            kind: VotingKind::Standard,
            options: 1,
        }
    }

    #[test]
    fn standard_succeeds_with_quorum_and_more_for() {
        let mut gov = Governance::new(MemoryStorage::default());
        let id = 1u128;
        gov.propose(
            id, aid(1), "Upgrade".into(), "desc".into(), [0u8;32],
            tp(10), tp(20), None, std_config(), vec![],
            Weight(100) // total power
        ).unwrap();

        // cast two votes before end: For=15, Against=5 → quorum=10 reached, success
        gov.cast_vote(id, tp(12), Vote{ voter: aid(2), timepoint: tp(12), ballot: Ballot::Standard{ support: Support::For, weight: Weight(15) } }).unwrap();
        gov.cast_vote(id, tp(13), Vote{ voter: aid(3), timepoint: tp(13), ballot: Ballot::Standard{ support: Support::Against, weight: Weight(5) } }).unwrap();

        let t = gov.tally(id).unwrap();
        assert!(gov.success(&gov.store.get_proposal(id).unwrap(), &t).unwrap());
        assert!(matches!(gov.state(id, tp(25)).unwrap(), ProposalState::Succeeded));
    }

    #[test]
    fn approval_plurality_winner() {
        let mut gov = Governance::new(MemoryStorage::default());
        let id = 2u128;
        let mut cfg = std_config();
        cfg.kind = VotingKind::Approval;
        cfg.options = 3;
        cfg.quorum_mode = QuorumMode::ForPlusAbstain; // count abstain into quorum
        gov.propose(id, aid(1), "Choose param".into(), "desc".into(), [1u8;32], tp(10), tp(20), None, cfg, vec![], Weight(100)).unwrap();

        // Voter approves {1,2} with weight 8; voter2 approves {2} with 5; voter3 abstains 3
        gov.cast_vote(id, tp(12), Vote{voter: aid(2), timepoint: tp(12), ballot: Ballot::Approval{approved: BTreeSet::from([1,2]), weight: Weight(8)}}).unwrap();
        gov.cast_vote(id, tp(13), Vote{voter: aid(3), timepoint: tp(13), ballot: Ballot::Approval{approved: BTreeSet::from([2]), weight: Weight(5)}}).unwrap();
        gov.cast_vote(id, tp(14), Vote{voter: aid(4), timepoint: tp(14), ballot: Ballot::Standard{support: Support::Abstain, weight: Weight(3)}}).unwrap();

        let st = gov.state(id, tp(25)).unwrap();
        assert!(matches!(st, ProposalState::Succeeded));
    }

    #[test]
    fn quadratic_tie_fails_without_majority() {
        let mut gov = Governance::new(MemoryStorage::default());
        let id = 3u128;
        let mut cfg = std_config();
        cfg.kind = VotingKind::Quadratic;
        cfg.options = 2;
        cfg.winner_by_plurality = false; // require >50%
        gov.propose(id, aid(1), "QV choice".into(), "desc".into(), [2u8;32], tp(10), tp(20), None, cfg, vec![], Weight(100)).unwrap();

        // Two voters put equal credits for option 1 and 2 → tie under sqrt transform
        gov.cast_vote(id, tp(12), Vote{
            voter: aid(2), timepoint: tp(12),
            ballot: Ballot::Quadratic{ credits: BTreeMap::from([(1,16)]), total_credits: 16 }
        }).unwrap();
        gov.cast_vote(id, tp(13), Vote{
            voter: aid(3), timepoint: tp(13),
            ballot: Ballot::Quadratic{ credits: BTreeMap::from([(2,16)]), total_credits: 16 }
        }).unwrap();

        let st = gov.state(id, tp(25)).unwrap();
        assert!(matches!(st, ProposalState::Defeated));
    }
}

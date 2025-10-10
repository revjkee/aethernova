//! File: aethernova-chain-core/governance/src/voting.rs
//! Production-grade on-chain/off-chain governance voting core.
//!
//! Key features:
//! - Snapshot-based voting power via `VotingPowerOracle`.
//! - Configurable quorum & support thresholds (basis points).
//! - Abstain handling (include/exclude from quorum).
//! - Linear / Quadratic weighting strategies.
//! - Safe receipts with optional vote updates.
//! - Deterministic tally and outcome classification.
//!
//! This module is transport-agnostic: integrate with runtime/DB as needed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

pub type SnapshotId = u64;
pub type ProposalId = u64;
pub type Power = u128;

/// Voter identifier: raw bytes of account/public key hash or address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VoterId(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Debug for VoterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "VoterId(0x{})", hex::encode(&self.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Against,
    For,
    Abstain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WeightStrategy {
    /// weight = raw_power
    Linear,
    /// weight = floor(sqrt(raw_power))
    Quadratic,
}

impl WeightStrategy {
    pub fn weight(&self, raw: Power) -> Power {
        match self {
            WeightStrategy::Linear => raw,
            WeightStrategy::Quadratic => integer_sqrt(raw),
        }
    }
}

/// Integer sqrt for u128 by Newton iteration.
fn integer_sqrt(x: u128) -> u128 {
    if x <= 1 {
        return x;
    }
    let mut z = x;
    let mut y = (x >> 1) + 1;
    while y < z {
        z = y;
        y = (x / y + y) >> 1;
    }
    z
}

/// Interface that provides total supply and per-voter power at a snapshot.
pub trait VotingPowerOracle: Clone + Send + Sync + 'static {
    fn total_supply_at(&self, snapshot: SnapshotId) -> Power;
    fn power_of_at(&self, who: &VoterId, snapshot: SnapshotId) -> Power;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VotingParams {
    /// Quorum in basis points of total supply (0..=10000).
    pub quorum_bps: u16,
    /// Support threshold among For vs Against in basis points (0..=10000).
    pub support_bps: u16,
    /// Whether Abstain counts toward quorum.
    pub abstain_counts_for_quorum: bool,
    /// Allow replacing an existing vote (idempotent update).
    pub allow_update: bool,
    /// Weighting strategy (linear/quadratic).
    pub strategy: WeightStrategy,
}

impl Default for VotingParams {
    fn default() -> Self {
        Self {
            quorum_bps: 2000,          // 20%
            support_bps: 5000,         // 50%+
            abstain_counts_for_quorum: true,
            allow_update: true,
            strategy: WeightStrategy::Linear,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalMeta {
    pub id: ProposalId,
    pub title: String,
    pub snapshot_id: SnapshotId,
    /// Voting window in unix seconds (inclusive start, exclusive end).
    pub voting_start: u64,
    pub voting_end: u64,
    pub params: VotingParams,
}

impl ProposalMeta {
    pub fn is_open(&self, now_unix: u64) -> bool {
        now_unix >= self.voting_start && now_unix < self.voting_end
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteReceipt {
    pub voter: VoterId,
    pub choice: VoteChoice,
    pub raw_power: Power,
    pub weight: Power,
    pub cast_at: u64, // unix seconds
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Tally {
    pub for_votes: Power,
    pub against_votes: Power,
    pub abstain_votes: Power,
}

impl Tally {
    pub fn total_cast(&self, include_abstain: bool) -> Power {
        if include_abstain {
            self.for_votes
                .saturating_add(self.against_votes)
                .saturating_add(self.abstain_votes)
        } else {
            self.for_votes.saturating_add(self.against_votes)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub meta: ProposalMeta,
    pub receipts: BTreeMap<VoterId, VoteReceipt>,
    pub tally: Tally,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Quorum not met.
    QuorumNotMet,
    /// Defeated (quorum met, but support below threshold).
    Defeated,
    /// Tie (support exactly equals threshold boundary with no strict majority rule).
    Tie,
    /// Succeeded (quorum met and support above threshold).
    Succeeded,
    /// Voting is still open.
    Ongoing,
    /// Voting window not started.
    NotStarted,
}

/// Governance book: stores proposals and votes.
#[derive(Default)]
pub struct VotingBook {
    by_id: BTreeMap<ProposalId, Proposal>,
    next_id: ProposalId,
}

impl VotingBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_proposal(
        &mut self,
        title: impl Into<String>,
        snapshot_id: SnapshotId,
        voting_start: u64,
        voting_end: u64,
        params: VotingParams,
    ) -> ProposalId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let proposal = Proposal {
            meta: ProposalMeta {
                id,
                title: title.into(),
                snapshot_id,
                voting_start,
                voting_end,
                params,
            },
            receipts: BTreeMap::new(),
            tally: Tally::default(),
        };
        self.by_id.insert(id, proposal);
        id
    }

    pub fn get(&self, id: ProposalId) -> Option<&Proposal> {
        self.by_id.get(&id)
    }

    pub fn get_mut(&mut self, id: ProposalId) -> Option<&mut Proposal> {
        self.by_id.get_mut(&id)
    }

    /// Cast or update a vote. Returns receipt.
    pub fn cast_vote<O: VotingPowerOracle>(
        &mut self,
        oracle: &O,
        id: ProposalId,
        voter: VoterId,
        choice: VoteChoice,
        now_unix: u64,
    ) -> Result<VoteReceipt, String> {
        let p = self
            .by_id
            .get_mut(&id)
            .ok_or_else(|| "proposal not found".to_string())?;

        if now_unix < p.meta.voting_start {
            return Err("voting has not started".into());
        }
        if now_unix >= p.meta.voting_end {
            return Err("voting has ended".into());
        }

        let raw = oracle.power_of_at(&voter, p.meta.snapshot_id);
        if raw == 0 {
            return Err("no voting power at snapshot".into());
        }
        let weight = p.meta.params.strategy.weight(raw);

        // If updating, subtract previous weights from tally first.
        if let Some(prev) = p.receipts.get(&voter) {
            if !p.meta.params.allow_update {
                return Err("vote already cast; updates disabled".into());
            }
            match prev.choice {
                VoteChoice::For => p.tally.for_votes = p.tally.for_votes.saturating_sub(prev.weight),
                VoteChoice::Against => {
                    p.tally.against_votes = p.tally.against_votes.saturating_sub(prev.weight)
                }
                VoteChoice::Abstain => {
                    p.tally.abstain_votes = p.tally.abstain_votes.saturating_sub(prev.weight)
                }
            }
        }

        // Apply new vote to tally.
        match choice {
            VoteChoice::For => p.tally.for_votes = p.tally.for_votes.saturating_add(weight),
            VoteChoice::Against => {
                p.tally.against_votes = p.tally.against_votes.saturating_add(weight)
            }
            VoteChoice::Abstain => {
                p.tally.abstain_votes = p.tally.abstain_votes.saturating_add(weight)
            }
        }

        let receipt = VoteReceipt {
            voter: voter.clone(),
            choice,
            raw_power: raw,
            weight,
            cast_at: now_unix,
        };
        p.receipts.insert(voter, receipt.clone());
        Ok(receipt)
    }

    /// Compute the outcome at `now_unix`. Does not mutate state.
    pub fn outcome<O: VotingPowerOracle>(
        &self,
        oracle: &O,
        id: ProposalId,
        now_unix: u64,
    ) -> Result<Outcome, String> {
        let p = self.by_id.get(&id).ok_or_else(|| "proposal not found".to_string())?;
        if now_unix < p.meta.voting_start {
            return Ok(Outcome::NotStarted);
        }
        if now_unix < p.meta.voting_end {
            return Ok(Outcome::Ongoing);
        }

        let total_supply = oracle.total_supply_at(p.meta.snapshot_id);
        let include_abstain = p.meta.params.abstain_counts_for_quorum;
        let total_cast = p.tally.total_cast(include_abstain);

        // Check quorum: total_cast / total_supply >= quorum_bps / 10_000
        let quorum_ok = meets_bps(total_cast, total_supply, p.meta.params.quorum_bps);

        if !quorum_ok {
            return Ok(Outcome::QuorumNotMet);
        }

        // Support = for / (for + against) against threshold support_bps
        let denom = p.tally.for_votes.saturating_add(p.tally.against_votes);
        if denom == 0 {
            // all abstained; quorum already met -> treat as defeated
            return Ok(Outcome::Defeated);
        }
        // Compare in integer domain: for_votes * 10000 ? support_bps * denom
        let lhs = p.tally.for_votes.saturating_mul(10_000);
        let rhs = Power::from(p.meta.params.support_bps).saturating_mul(denom);

        if lhs > rhs {
            Ok(Outcome::Succeeded)
        } else if lhs == rhs {
            Ok(Outcome::Tie)
        } else {
            Ok(Outcome::Defeated)
        }
    }
}

/// Return true if a/b >= bps/10_000; handles a=0 or b=0 safely.
fn meets_bps(a: Power, b: Power, bps: u16) -> bool {
    if b == 0 {
        return false;
    }
    // a/b >= bps/10000  <=>  a*10000 >= bps*b
    a.saturating_mul(10_000) >= Power::from(bps).saturating_mul(b)
}

/// Helpers
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone)]
    struct StaticOracle {
        total: Power,
        by: Arc<BTreeMap<VoterId, Power>>,
    }
    impl VotingPowerOracle for StaticOracle {
        fn total_supply_at(&self, _snapshot: SnapshotId) -> Power {
            self.total
        }
        fn power_of_at(&self, who: &VoterId, _snapshot: SnapshotId) -> Power {
            *self.by.get(who).unwrap_or(&0)
        }
    }

    fn vid(s: &str) -> VoterId {
        VoterId(s.as_bytes().to_vec())
    }

    #[test]
    fn linear_quorum_and_support() {
        let mut book = VotingBook::new();
        let params = VotingParams {
            quorum_bps: 2000,  // 20%
            support_bps: 6000, // 60%
            abstain_counts_for_quorum: true,
            allow_update: false,
            strategy: WeightStrategy::Linear,
        };
        let now = 1_700_000_000;
        let pid = book.create_proposal(
            "P1",
            1,
            now - 10,
            now + 100, // open
            params.clone(),
        );

        let by = Arc::new(BTreeMap::from([
            (vid("A"), 40u128),
            (vid("B"), 30u128),
            (vid("C"), 30u128),
        ]));
        let oracle = StaticOracle { total: 100, by };

        // Cast votes: A For (40), B Against (30), C Abstain (30)
        book.cast_vote(&oracle, pid, vid("A"), VoteChoice::For, now).unwrap();
        book.cast_vote(&oracle, pid, vid("B"), VoteChoice::Against, now).unwrap();
        book.cast_vote(&oracle, pid, vid("C"), VoteChoice::Abstain, now).unwrap();

        // Ongoing while open
        assert_eq!(book.outcome(&oracle, pid, now).unwrap(), Outcome::Ongoing);

        // Close and evaluate
        let closed = now + 200;
        let outcome = book.outcome(&oracle, pid, closed).unwrap();
        // quorum: (40+30+30)/100 = 100% >= 20% ok
        // support: 40/(40+30) = 57.14% < 60% => Defeated
        assert_eq!(outcome, Outcome::Defeated);
    }

    #[test]
    fn quadratic_can_change_outcome() {
        let mut book = VotingBook::new();
        let params = VotingParams {
            quorum_bps: 1000,  // 10%
            support_bps: 5000, // 50%
            abstain_counts_for_quorum: false,
            allow_update: true,
            strategy: WeightStrategy::Quadratic,
        };
        let now = 1_700_000_000;
        let pid = book.create_proposal("P2", 2, now - 5, now + 5, params);

        let by = Arc::new(BTreeMap::from([
            (vid("Big"), 81u128), // sqrt=9
            (vid("Small1"), 16u128), // 4
            (vid("Small2"), 16u128), // 4
        ]));
        let oracle = StaticOracle { total: 113, by };

        // Big voter Against (weight 9), small voters For (4+4=8)
        book.cast_vote(&oracle, pid, vid("Big"), VoteChoice::Against, now).unwrap();
        book.cast_vote(&oracle, pid, vid("Small1"), VoteChoice::For, now).unwrap();
        book.cast_vote(&oracle, pid, vid("Small2"), VoteChoice::For, now).unwrap();

        // Close
        let outcome = book.outcome(&oracle, pid, now + 10).unwrap();
        // for=8, against=9 => support ~47% -> Defeated
        assert_eq!(outcome, Outcome::Defeated);
    }

    #[test]
    fn updates_replace_weights() {
        let mut book = VotingBook::new();
        let params = VotingParams {
            allow_update: true,
            ..Default::default()
        };
        let now = 1_700_000_000;
        let pid = book.create_proposal("Upd", 3, now - 1, now + 1, params);

        let by = Arc::new(BTreeMap::from([(vid("X"), 25u128)]));
        let oracle = StaticOracle { total: 25, by };

        book.cast_vote(&oracle, pid, vid("X"), VoteChoice::Against, now).unwrap();
        {
            let p = book.get(pid).unwrap();
            assert_eq!(p.tally.against_votes, 25);
            assert_eq!(p.tally.for_votes, 0);
        }
        // Update to For
        book.cast_vote(&oracle, pid, vid("X"), VoteChoice::For, now).unwrap();
        {
            let p = book.get(pid).unwrap();
            assert_eq!(p.tally.against_votes, 0);
            assert_eq!(p.tally.for_votes, 25);
        }
    }
}

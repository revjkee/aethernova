// core-systems\aethernova-chain-core\launchpad\src\allocations.rs
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]

/*!
Allocation engine for Aethernova Launchpad.

This module is intentionally self-contained and deterministic:
- No floating-point arithmetic.
- Stable sorting for tie-breaking.
- Checked arithmetic for all u128 operations.
- Explicit error model.

Important:
I cannot verify this module matches your repository interfaces, because the existing file and adjacent types
were not provided. Treat this as an industrial-grade drop-in that may require minimal wiring.
*/

use core::cmp::Ordering;
use core::fmt;

use serde::{Deserialize, Serialize};

/// Public identifier for a participant.
/// Keep as bytes-friendly string to remain chain-agnostic (EVM addr, TON addr, DID, etc).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub String);

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Basis points (1/100 of a percent). 10_000 = 100.00%.
pub type Bps = u16;

/// Allocation amount unit (e.g. token smallest units).
pub type Amount = u128;

/// Round identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoundId(pub String);

/// A single participant request.
/// `requested` is in allocation units (e.g. token smallest units).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationRequest {
    /// Participant id.
    pub participant: ParticipantId,
    /// Requested amount.
    pub requested: Amount,
    /// Optional participant max cap override for this request (if your business logic supports it).
    pub max_override: Option<Amount>,
    /// Optional metadata (client-side idempotency, signature hash, etc).
    pub memo: Option<String>,
}

/// Per-participant computed allocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationResult {
    /// Participant id.
    pub participant: ParticipantId,
    /// Final allocated amount.
    pub allocated: Amount,
    /// Effective requested after clamping.
    pub effective_requested: Amount,
    /// Whether the request was included.
    pub included: bool,
    /// Optional reason for exclusion.
    pub exclusion_reason: Option<String>,
}

/// Full snapshot of a computed round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationSnapshot {
    /// Round id.
    pub round_id: RoundId,
    /// Total supply available for allocation in this round.
    pub total_supply: Amount,
    /// Sum of all effective requests included.
    pub total_effective_demand: Amount,
    /// Sum allocated (must be <= total_supply).
    pub total_allocated: Amount,
    /// Per participant results (deterministic order).
    pub results: Vec<AllocationResult>,
    /// Deterministic digest input to allow external hashing (hashing itself left to caller).
    pub digest_canonical: String,
}

/// Allowlist configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllowlistMode {
    /// No allowlist checks.
    Disabled,
    /// Only listed participants can participate.
    Enforced {
        /// Exact participant ids.
        participants: Vec<ParticipantId>,
    },
}

impl AllowlistMode {
    fn contains(&self, pid: &ParticipantId) -> bool {
        match self {
            AllowlistMode::Disabled => true,
            AllowlistMode::Enforced { participants } => participants.iter().any(|x| x == pid),
        }
    }
}

/// Round allocation algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocationAlgorithm {
    /// If demand <= supply: allocate effective_requested, else pro-rata with deterministic remainder distribution.
    ProRataDeterministic,
    /// If demand > supply: first-come (stable order), clamped by caps, until supply runs out.
    ///
    /// Note: "first-come" requires trusted ordering input (e.g. block height, server timestamp).
    FirstComeFirstServed,
}

/// Round configuration for allocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundConfig {
    /// Round id.
    pub round_id: RoundId,
    /// Total supply available for the round.
    pub total_supply: Amount,
    /// Minimum per participant.
    pub min_per_participant: Amount,
    /// Maximum per participant (global).
    pub max_per_participant: Amount,
    /// If true, any request below min is excluded; if false, it is clamped up to min (not recommended).
    pub strict_min: bool,
    /// Allowlist enforcement.
    pub allowlist: AllowlistMode,
    /// Algorithm.
    pub algorithm: AllocationAlgorithm,
    /// Optional fee in bps applied to allocated amount (e.g. protocol fee). Fee is subtracted from user allocation.
    pub fee_bps: Option<Bps>,
}

impl RoundConfig {
    fn validate(&self) -> Result<(), AllocationError> {
        if self.total_supply == 0 {
            return Err(AllocationError::InvalidConfig("total_supply must be > 0"));
        }
        if self.max_per_participant == 0 {
            return Err(AllocationError::InvalidConfig("max_per_participant must be > 0"));
        }
        if self.min_per_participant > self.max_per_participant {
            return Err(AllocationError::InvalidConfig(
                "min_per_participant must be <= max_per_participant",
            ));
        }
        if let Some(fee_bps) = self.fee_bps {
            if fee_bps > 10_000 {
                return Err(AllocationError::InvalidConfig("fee_bps must be <= 10000"));
            }
        }
        Ok(())
    }
}

/// Allocation errors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocationError {
    /// Invalid round config.
    InvalidConfig(&'static str),
    /// Duplicate participant requests are not allowed (industrial safety).
    DuplicateParticipant(ParticipantId),
    /// Arithmetic overflow or underflow.
    Arithmetic(&'static str),
}

impl fmt::Display for AllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllocationError::InvalidConfig(s) => write!(f, "invalid config: {}", s),
            AllocationError::DuplicateParticipant(p) => write!(f, "duplicate participant: {}", p),
            AllocationError::Arithmetic(s) => write!(f, "arithmetic error: {}", s),
        }
    }
}

impl std::error::Error for AllocationError {}

/// Compute allocation snapshot.
/// Input order matters only for `FirstComeFirstServed`. For pro-rata it is normalized and then made deterministic.
pub fn compute_allocations(
    cfg: &RoundConfig,
    requests: &[AllocationRequest],
) -> Result<AllocationSnapshot, AllocationError> {
    cfg.validate()?;

    // 1) Reject duplicates to avoid ambiguous business logic.
    {
        use std::collections::HashSet;
        let mut set: HashSet<&ParticipantId> = HashSet::with_capacity(requests.len());
        for r in requests {
            if !set.insert(&r.participant) {
                return Err(AllocationError::DuplicateParticipant(r.participant.clone()));
            }
        }
    }

    // 2) Build working set with inclusion decisions and effective requests (pre-allocation clamp).
    let mut work: Vec<WorkItem> = Vec::with_capacity(requests.len());
    for r in requests {
        let mut item = WorkItem::from_request(cfg, r);
        item.apply_allowlist(cfg);
        item.apply_min_max(cfg);
        work.push(item);
    }

    // For deterministic output: we keep a stable sort key (participant id).
    // For FirstComeFirstServed, we preserve input order (work already in order).
    if matches!(cfg.algorithm, AllocationAlgorithm::ProRataDeterministic) {
        work.sort_by(|a, b| a.participant.0.cmp(&b.participant.0));
    }

    // 3) Sum effective demand.
    let total_effective_demand = sum_effective_demand(&work)?;

    // 4) Allocate based on algorithm.
    let mut total_allocated: Amount = 0;
    match cfg.algorithm {
        AllocationAlgorithm::ProRataDeterministic => {
            if total_effective_demand <= cfg.total_supply {
                // Everyone gets what they effectively requested.
                for w in work.iter_mut() {
                    if w.included {
                        w.allocated = w.effective_requested;
                        total_allocated = checked_add(total_allocated, w.allocated)?;
                    }
                }
            } else {
                // Pro-rata: floor division then distribute remainder by deterministic order.
                pro_rata_allocate(cfg.total_supply, &mut work, total_effective_demand, &mut total_allocated)?;
            }
        }
        AllocationAlgorithm::FirstComeFirstServed => {
            let mut remaining = cfg.total_supply;
            for w in work.iter_mut() {
                if !w.included {
                    continue;
                }
                if remaining == 0 {
                    w.allocated = 0;
                    continue;
                }
                let give = core::cmp::min(w.effective_requested, remaining);
                w.allocated = give;
                total_allocated = checked_add(total_allocated, give)?;
                remaining = checked_sub(remaining, give)?;
            }
        }
    }

    // 5) Apply fee if configured. Fee is subtracted from participant allocation, and fee is NOT re-distributed.
    // This keeps accounting straightforward and avoids second-order rounding games.
    if let Some(fee_bps) = cfg.fee_bps {
        for w in work.iter_mut() {
            if w.allocated == 0 {
                continue;
            }
            let fee = mul_div_floor(w.allocated, fee_bps as u128, 10_000)?;
            w.allocated = checked_sub(w.allocated, fee)?;
        }
        // Recompute total_allocated after fees.
        total_allocated = 0;
        for w in work.iter() {
            total_allocated = checked_add(total_allocated, w.allocated)?;
        }
    }

    // 6) Prepare results in deterministic order:
    // - For pro-rata: already sorted by participant
    // - For FCFS: preserve input order for auditability (work kept in input order).
    let results: Vec<AllocationResult> = work
        .into_iter()
        .map(|w| AllocationResult {
            participant: w.participant,
            allocated: w.allocated,
            effective_requested: w.effective_requested,
            included: w.included,
            exclusion_reason: w.exclusion_reason,
        })
        .collect();

    let digest_canonical = build_canonical_digest(cfg, &results, total_effective_demand, total_allocated);

    Ok(AllocationSnapshot {
        round_id: cfg.round_id.clone(),
        total_supply: cfg.total_supply,
        total_effective_demand,
        total_allocated,
        results,
        digest_canonical,
    })
}

#[derive(Clone, Debug)]
struct WorkItem {
    participant: ParticipantId,
    requested: Amount,
    max_override: Option<Amount>,
    included: bool,
    exclusion_reason: Option<String>,
    effective_requested: Amount,
    allocated: Amount,
}

impl WorkItem {
    fn from_request(_cfg: &RoundConfig, r: &AllocationRequest) -> Self {
        Self {
            participant: r.participant.clone(),
            requested: r.requested,
            max_override: r.max_override,
            included: true,
            exclusion_reason: None,
            effective_requested: r.requested,
            allocated: 0,
        }
    }

    fn exclude(&mut self, reason: &str) {
        self.included = false;
        self.exclusion_reason = Some(reason.to_string());
        self.effective_requested = 0;
        self.allocated = 0;
    }

    fn apply_allowlist(&mut self, cfg: &RoundConfig) {
        if !cfg.allowlist.contains(&self.participant) {
            self.exclude("not in allowlist");
        }
    }

    fn apply_min_max(&mut self, cfg: &RoundConfig) {
        if !self.included {
            return;
        }

        // clamp by max first
        let mut max_cap = cfg.max_per_participant;
        if let Some(ovr) = self.max_override {
            // safest: use the smaller cap
            max_cap = core::cmp::min(max_cap, ovr);
        }
        if max_cap == 0 {
            self.exclude("max cap is zero");
            return;
        }
        self.effective_requested = core::cmp::min(self.effective_requested, max_cap);

        if self.effective_requested == 0 {
            self.exclude("requested is zero after cap");
            return;
        }

        if self.effective_requested < cfg.min_per_participant {
            if cfg.strict_min {
                self.exclude("below min_per_participant");
            } else {
                // Not recommended but supported: clamp up to min if supply allows later.
                self.effective_requested = cfg.min_per_participant;
            }
        }
    }
}

fn sum_effective_demand(work: &[WorkItem]) -> Result<Amount, AllocationError> {
    let mut sum: Amount = 0;
    for w in work {
        if !w.included {
            continue;
        }
        sum = checked_add(sum, w.effective_requested)?;
    }
    Ok(sum)
}

fn pro_rata_allocate(
    supply: Amount,
    work: &mut [WorkItem],
    total_demand: Amount,
    total_allocated_out: &mut Amount,
) -> Result<(), AllocationError> {
    // Base allocation: floor(supply * req / total_demand)
    // Remainder: supply - sum(base)
    // Distribute remainder by descending fractional part; we avoid fractions by ranking by (supplyc:
    // remainder_rank = (supply * req) % total_demand, then tie-break by participant lexicographic.
    let mut base_sum: Amount = 0;

    // Precompute numerator and remainder rank for each included entry.
    let mut ranks: Vec<(usize, u128)> = Vec::new(); // (index, remainder_rank)
    for (idx, w) in work.iter_mut().enumerate() {
        if !w.included {
            w.allocated = 0;
            continue;
        }

        let num = checked_mul(supply, w.effective_requested)?;
        let base = num / total_demand;
        let rem = num % total_demand;

        w.allocated = base;
        base_sum = checked_add(base_sum, base)?;

        ranks.push((idx, rem));
    }

    if base_sum > supply {
        return Err(AllocationError::Arithmetic("base_sum > supply"));
    }

    let mut remainder = supply - base_sum;

    // Sort ranks by:
    // - higher remainder rank first
    // - then by participant id ascending (already stable order in `work`, but we enforce for safety)
    ranks.sort_by(|(ia, ra), (ib, rb)| {
        match rb.cmp(ra) {
            Ordering::Equal => work[*ia].participant.0.cmp(&work[*ib].participant.0),
            other => other,
        }
    });

    // Distribute 1 unit at a time to the top ranks until remainder is exhausted.
    // Industrial note: O(n + remainder) could be heavy if remainder is huge.
    // Optimization: distribute in batches by counts of equal ranks. Here we do a safe batched approach.
    if remainder > 0 && !ranks.is_empty() {
        // Group by equal remainder rank.
        let mut i = 0usize;
        while remainder > 0 && i < ranks.len() {
            let current_rank = ranks[i].1;
            let mut j = i + 1;
            while j < ranks.len() && ranks[j].1 == current_rank {
                j += 1;
            }
            let group_len = (j - i) as u128;
            if group_len == 0 {
                break;
            }

            // Give each member at most 1 per pass. If remainder >= group_len, we can give 1 to all.
            if remainder >= group_len {
                for k in i..j {
                    let idx = ranks[k].0;
                    work[idx].allocated = checked_add(work[idx].allocated, 1)?;
                }
                remainder -= group_len;
            } else {
                // Give to first `remainder` members in this deterministic order.
                let mut take = remainder;
                let mut k = i;
                while take > 0 && k < j {
                    let idx = ranks[k].0;
                    work[idx].allocated = checked_add(work[idx].allocated, 1)?;
                    take -= 1;
                    k += 1;
                }
                remainder = 0;
            }

            i = j;
        }
    }

    // Update total allocated
    let mut total: Amount = 0;
    for w in work.iter() {
        total = checked_add(total, w.allocated)?;
    }
    if total > supply {
        return Err(AllocationError::Arithmetic("total allocated > supply"));
    }
    *total_allocated_out = total;

    Ok(())
}

fn build_canonical_digest(
    cfg: &RoundConfig,
    results: &[AllocationResult],
    total_demand: Amount,
    total_allocated: Amount,
) -> String {
    // Canonical string for external hashing.
    // Format is stable and explicit.
    let mut s = String::new();
    s.push_str("round_id=");
    s.push_str(&cfg.round_id.0);
    s.push_str("|total_supply=");
    s.push_str(&cfg.total_supply.to_string());
    s.push_str("|min=");
    s.push_str(&cfg.min_per_participant.to_string());
    s.push_str("|max=");
    s.push_str(&cfg.max_per_participant.to_string());
    s.push_str("|strict_min=");
    s.push_str(if cfg.strict_min { "1" } else { "0" });
    s.push_str("|algo=");
    s.push_str(match cfg.algorithm {
        AllocationAlgorithm::ProRataDeterministic => "pro_rata",
        AllocationAlgorithm::FirstComeFirstServed => "fcfs",
    });
    s.push_str("|fee_bps=");
    s.push_str(&cfg.fee_bps.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()));
    s.push_str("|total_demand=");
    s.push_str(&total_demand.to_string());
    s.push_str("|total_allocated=");
    s.push_str(&total_allocated.to_string());
    s.push_str("|results=[");
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            s.push(';');
        }
        s.push_str(&r.participant.0);
        s.push(':');
        s.push_str(&r.allocated.to_string());
        s.push(':');
        s.push_str(&r.effective_requested.to_string());
        s.push(':');
        s.push_str(if r.included { "1" } else { "0" });
    }
    s.push(']');
    s
}

#[inline]
fn checked_add(a: Amount, b: Amount) -> Result<Amount, AllocationError> {
    a.checked_add(b).ok_or(AllocationError::Arithmetic("add overflow"))
}

#[inline]
fn checked_sub(a: Amount, b: Amount) -> Result<Amount, AllocationError> {
    a.checked_sub(b).ok_or(AllocationError::Arithmetic("sub underflow"))
}

#[inline]
fn checked_mul(a: Amount, b: Amount) -> Result<Amount, AllocationError> {
    a.checked_mul(b).ok_or(AllocationError::Arithmetic("mul overflow"))
}

/// floor(a * b / denom) with checked arithmetic.
#[inline]
fn mul_div_floor(a: Amount, b: Amount, denom: Amount) -> Result<Amount, AllocationError> {
    if denom == 0 {
        return Err(AllocationError::Arithmetic("division by zero"));
    }
    let num = checked_mul(a, b)?;
    Ok(num / denom)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_basic(supply: u128) -> RoundConfig {
        RoundConfig {
            round_id: RoundId("r1".to_string()),
            total_supply: supply,
            min_per_participant: 1,
            max_per_participant: 1_000_000,
            strict_min: true,
            allowlist: AllowlistMode::Disabled,
            algorithm: AllocationAlgorithm::ProRataDeterministic,
            fee_bps: None,
        }
    }

    #[test]
    fn pro_rata_exact_when_demand_leq_supply() {
        let cfg = cfg_basic(1000);
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 100, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("b".into()), requested: 200, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        assert_eq!(snap.total_effective_demand, 300);
        assert_eq!(snap.total_allocated, 300);
        assert_eq!(snap.results[0].participant.0, "a");
        assert_eq!(snap.results[0].allocated, 100);
        assert_eq!(snap.results[1].allocated, 200);
    }

    #[test]
    fn pro_rata_scales_down_when_demand_gt_supply() {
        let cfg = cfg_basic(100);
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 100, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("b".into()), requested: 100, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("c".into()), requested: 100, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        assert_eq!(snap.total_effective_demand, 300);
        assert_eq!(snap.total_allocated, 100);
        let sum: u128 = snap.results.iter().map(|r| r.allocated).sum();
        assert_eq!(sum, 100);
    }

    #[test]
    fn deterministic_remainder_distribution() {
        // supply=10, demand=3+3+3=9 -> leq supply: exact
        // Let's force remainder case by supply smaller.
        let cfg = cfg_basic(10);
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 5, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("b".into()), requested: 5, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("c".into()), requested: 5, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        assert_eq!(snap.total_effective_demand, 15);
        assert_eq!(snap.total_allocated, 10);
        // Deterministic ordering by participant for pro-rata output:
        assert_eq!(snap.results[0].participant.0, "a");
        assert_eq!(snap.results[1].participant.0, "b");
        assert_eq!(snap.results[2].participant.0, "c");
        let sum: u128 = snap.results.iter().map(|r| r.allocated).sum();
        assert_eq!(sum, 10);
    }

    #[test]
    fn allowlist_excludes() {
        let mut cfg = cfg_basic(100);
        cfg.allowlist = AllowlistMode::Enforced {
            participants: vec![ParticipantId("a".into())],
        };
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 10, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("b".into()), requested: 10, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        let a = snap.results.iter().find(|r| r.participant.0 == "a").unwrap();
        let b = snap.results.iter().find(|r| r.participant.0 == "b").unwrap();
        assert!(a.included);
        assert_eq!(a.allocated, 10);
        assert!(!b.included);
        assert_eq!(b.allocated, 0);
        assert_eq!(b.exclusion_reason.as_deref(), Some("not in allowlist"));
    }

    #[test]
    fn fee_bps_reduces_allocation() {
        let mut cfg = cfg_basic(1000);
        cfg.fee_bps = Some(1000); // 10%
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 100, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        assert_eq!(snap.results[0].allocated, 90);
    }

    #[test]
    fn duplicate_participant_rejected() {
        let cfg = cfg_basic(1000);
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 100, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("a".into()), requested: 200, max_override: None, memo: None },
        ];
        let err = compute_allocations(&cfg, &reqs).unwrap_err();
        match err {
            AllocationError::DuplicateParticipant(_) => {}
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn strict_min_excludes_below_min() {
        let mut cfg = cfg_basic(1000);
        cfg.min_per_participant = 50;
        cfg.strict_min = true;
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("a".into()), requested: 10, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("b".into()), requested: 60, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        let a = snap.results.iter().find(|r| r.participant.0 == "a").unwrap();
        let b = snap.results.iter().find(|r| r.participant.0 == "b").unwrap();
        assert!(!a.included);
        assert_eq!(a.allocated, 0);
        assert!(b.included);
        assert_eq!(b.allocated, 60);
    }

    #[test]
    fn fcfs_respects_input_order() {
        let mut cfg = cfg_basic(100);
        cfg.algorithm = AllocationAlgorithm::FirstComeFirstServed;
        let reqs = vec![
            AllocationRequest { participant: ParticipantId("z".into()), requested: 80, max_override: None, memo: None },
            AllocationRequest { participant: ParticipantId("a".into()), requested: 80, max_override: None, memo: None },
        ];
        let snap = compute_allocations(&cfg, &reqs).unwrap();
        assert_eq!(snap.results[0].participant.0, "z");
        assert_eq!(snap.results[0].allocated, 80);
        assert_eq!(snap.results[1].participant.0, "a");
        assert_eq!(snap.results[1].allocated, 20);
        assert_eq!(snap.total_allocated, 100);
    }
}

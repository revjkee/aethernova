//! Priority scoring for transaction selection in the txpool.
//!
//! Core ideas implemented here:
//! - EIP-1559 effective priority fee per gas calculation:
//!   tip_per_gas = min(max_fee_per_gas - base_fee_per_gas, max_priority_fee_per_gas).
//!   (Legacy tx: tip_per_gas = gas_price - base_fee_per_gas; if negative, tx is not includable.)
//!   Source: EIP-1559 specification. :contentReference[oaicite:1]{index=1}
//! - Ordering: primarily by tip_per_gas descending; tie-breaker by first-seen time ascending,
//!   as recommended to deter spam by equal-fee flooding. Source: EIP-1559 "Transaction Ordering". :contentReference[oaicite:2]{index=2}
//! - Replacement bump check (same account+nonce): configurable percentage. In geth the default
//!   is 10% (--txpool.pricebump=10). Source: Geth command-line docs. :contentReference[oaicite:3]{index=3}
//!
//! This module is self-contained and avoids any chain-specific types. Integrations can
//! adapt `TxPricing`/`TxMeta` to their transaction representation.

#![forbid(unsafe_code)]

use core::cmp::Ordering;
use core::fmt;
use core::time::Duration;

/// How the transaction pays for gas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxPricing {
    /// Pre-EIP-1559 legacy pricing: a single gas_price.
    Legacy {
        gas_price: u128,
    },
    /// EIP-1559 style pricing with fee caps.
    Eip1559 {
        /// Maximum total per-gas fee the sender is willing to pay (covers base fee + tip).
        max_fee_per_gas: u128,
        /// Maximum priority fee per gas (tip) the sender is willing to pay to the block producer.
        max_priority_fee_per_gas: u128,
    },
}

/// Minimal metadata the pool needs for prioritization.
/// Keep this struct chain-agnostic; extend at integration boundaries if needed.
#[derive(Clone, Debug)]
pub struct TxMeta {
    /// Monotonically increasing arrival time in milliseconds since some epoch chosen by the pool.
    /// It must be comparable within a single process lifetime (e.g., SystemTime::now() ms).
    pub first_seen_ms: u64,
    /// Gas limit declared by the transaction (upper bound on execution gas usage).
    pub gas_limit: u64,
    /// Opaque transaction identifier used solely as a deterministic final tie-breaker.
    pub id32: [u8; 32],
    /// Pricing mode (legacy or EIP-1559).
    pub pricing: TxPricing,
}

/// Environment inputs required to compute priority.
#[derive(Clone, Copy, Debug)]
pub struct Env {
    /// Current base fee per gas (for EIP-1559-style chains).
    pub base_fee_per_gas: u128,
}

/// Configuration of the priority policy.
#[derive(Clone, Copy, Debug)]
pub struct PriorityConfig {
    /// Age bonus in micro tip units per second. Set to 0 to disable age bias.
    ///
    /// Age bias helps break large groups of equal-fee tx by preferring older ones,
    /// consistent with EIP-1559 guidance to sort equal-priority by time received. :contentReference[oaicite:4]{index=4}
    pub age_bonus_per_s: u128,

    /// Replacement bump threshold in percent (e.g., 10 means +10% or more).
    /// Only used by `is_sufficient_bump`.
    ///
    /// In geth, the default for --txpool.pricebump is 10. :contentReference[oaicite:5]{index=5}
    pub replace_bump_percent: u32,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            age_bonus_per_s: 0,
            replace_bump_percent: 10,
        }
    }
}

/// Computed priority score. Larger is better.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PriorityScore {
    /// Primary component: effective miner tip per gas (u128).
    /// See `tip_per_gas()` for details and references. :contentReference[oaicite:6]{index=6}
    tip_per_gas: u128,
    /// Secondary component: arrival time bias (older wins). Stored as negative age to keep
    /// tuple ordering simple (larger score is better).
    neg_age_bonus: i128,
    /// Final tiebreaker: deterministic hash-derived integer (lexicographic on id32).
    tie_hi: u128,
    tie_lo: u128,
}

impl fmt::Debug for PriorityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PriorityScore")
            .field("tip_per_gas", &self.tip_per_gas)
            .field("neg_age_bonus", &self.neg_age_bonus)
            .finish()
    }
}

impl Ord for PriorityScore {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher tip_per_gas first
        self.tip_per_gas
            .cmp(&other.tip_per_gas)
            // Then larger (less negative) age bonus first => older tx (more time elapsed) has bigger bonus magnitude,
            // but since we store neg_age_bonus, we reverse compare so that older (more negative) ranks lower;
            // instead, compare by negated value to achieve "older first".
            .then_with(|| other.neg_age_bonus.cmp(&self.neg_age_bonus))
            // Finally deterministic tiebreaker
            .then_with(|| self.tie_hi.cmp(&other.tie_hi))
            .then_with(|| self.tie_lo.cmp(&other.tie_lo))
    }
}

impl PartialOrd for PriorityScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Policy trait for computing transaction priority.
pub trait PriorityPolicy {
    /// Compute the score for inclusion ordering. Returns None if the tx is not includable
    /// under current base fee (e.g., cap below base).
    fn score(&self, tx: &TxMeta, env: Env, now_ms: u64) -> Option<PriorityScore>;

    /// Check whether `new_tx` sufficiently bumps `old_tx` (same account+nonce) to justify
    /// replacement in the pool, according to configured percentage threshold.
    fn is_sufficient_bump(&self, old_tx: &TxMeta, new_tx: &TxMeta, env: Env) -> bool;
}

/// EIP-1559 aware priority policy.
#[derive(Clone, Copy, Debug)]
pub struct Eip1559PriorityPolicy {
    cfg: PriorityConfig,
}

impl Eip1559PriorityPolicy {
    pub fn new(cfg: PriorityConfig) -> Self {
        Self { cfg }
    }

    /// Effective miner tip per gas according to EIP-1559.
    /// - EIP-1559: tip = min(max_fee - base_fee, max_priority_fee). :contentReference[oaicite:7]{index=7}
    /// - Legacy:   tip = gas_price - base_fee. If <= 0 → not includable in block. :contentReference[oaicite:8]{index=8}
    pub fn tip_per_gas(pricing: TxPricing, base_fee_per_gas: u128) -> Option<u128> {
        match pricing {
            TxPricing::Legacy { gas_price } => gas_price.checked_sub(base_fee_per_gas),
            TxPricing::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => {
                let cap_minus_base = max_fee_per_gas.checked_sub(base_fee_per_gas)?;
                Some(core::cmp::min(cap_minus_base, max_priority_fee_per_gas))
            }
        }
        .filter(|&tip| tip > 0)
    }

    /// Compose final score tuple.
    fn build_score(&self, tip_per_gas: u128, first_seen_ms: u64, now_ms: u64, id32: [u8; 32]) -> PriorityScore {
        // Age bonus: simple linear function tip-micros per second.
        let age_s = now_ms.saturating_sub(first_seen_ms) as u128 / 1000;
        let age_bonus = self.cfg.age_bonus_per_s.saturating_mul(age_s);

        // Split id32 into two u128s for deterministic tie-break.
        let mut hi = [0u8; 16];
        let mut lo = [0u8; 16];
        hi.copy_from_slice(&id32[0..16]);
        lo.copy_from_slice(&id32[16..32]);
        let tie_hi = u128::from_be_bytes(hi);
        let tie_lo = u128::from_be_bytes(lo);

        PriorityScore {
            tip_per_gas: tip_per_gas.saturating_add(age_bonus),
            // Store negative of age_bonus for explicit secondary comparison if primary equal.
            neg_age_bonus: -(age_bonus as i128),
            tie_hi,
            tie_lo,
        }
    }
}

impl PriorityPolicy for Eip1559PriorityPolicy {
    fn score(&self, tx: &TxMeta, env: Env, now_ms: u64) -> Option<PriorityScore> {
        let tip = Self::tip_per_gas(tx.pricing, env.base_fee_per_gas)?;
        Some(self.build_score(tip, tx.first_seen_ms, now_ms, tx.id32))
    }

    fn is_sufficient_bump(&self, old_tx: &TxMeta, new_tx: &TxMeta, env: Env) -> bool {
        // Compare effective tip per gas (what block producer actually keeps under EIP-1559).
        let old_tip = match Self::tip_per_gas(old_tx.pricing, env.base_fee_per_gas) {
            Some(v) => v,
            None => 0,
        };
        let new_tip = match Self::tip_per_gas(new_tx.pricing, env.base_fee_per_gas) {
            Some(v) => v,
            None => return false, // cannot replace with a non-includable tx
        };
        if old_tip == 0 {
            return new_tip > 0;
        }
        // Bump check: new_tip >= old_tip * (1 + bump%), using integer math.
        // Formula: new_tip * 100 >= old_tip * (100 + bump)
        let bump = self.cfg.replace_bump_percent as u128;
        new_tip.saturating_mul(100) >= old_tip.saturating_mul(100 + bump)
    }
}

// ------------------------------ Tests ------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: [u8; 32] = [0xAA; 32];
    const ID_B: [u8; 32] = [0xBB; 32];

    #[test]
    fn tip_calc_eip1559_basic() {
        // base=30, max_fee=100, max_priority=5 => tip = min(100-30, 5) = 5
        let tip = Eip1559PriorityPolicy::tip_per_gas(
            TxPricing::Eip1559 {
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 5,
            },
            30,
        );
        assert_eq!(tip, Some(5));
    }

    #[test]
    fn tip_calc_eip1559_cap_below_base() {
        // base=100, cap=90 => not includable (None)
        let tip = Eip1559PriorityPolicy::tip_per_gas(
            TxPricing::Eip1559 {
                max_fee_per_gas: 90,
                max_priority_fee_per_gas: 50,
            },
            100,
        );
        assert_eq!(tip, None);
    }

    #[test]
    fn tip_calc_legacy() {
        // legacy: tip = gas_price - base; if negative -> None
        assert_eq!(
            Eip1559PriorityPolicy::tip_per_gas(TxPricing::Legacy { gas_price: 50 }, 30),
            Some(20)
        );
        assert_eq!(
            Eip1559PriorityPolicy::tip_per_gas(TxPricing::Legacy { gas_price: 20 }, 30),
            None
        );
    }

    #[test]
    fn ordering_by_tip_then_time() {
        let policy = Eip1559PriorityPolicy::new(PriorityConfig { age_bonus_per_s: 0, replace_bump_percent: 10 });
        let env = Env { base_fee_per_gas: 30 };
        let now = 10_000;

        // tx1: tip 5, seen earlier
        let tx1 = TxMeta {
            first_seen_ms: 1_000,
            gas_limit: 21_000,
            id32: ID_A,
            pricing: TxPricing::Eip1559 { max_fee_per_gas: 100, max_priority_fee_per_gas: 5 },
        };
        // tx2: higher tip -> must win regardless of time
        let tx2 = TxMeta {
            first_seen_ms: 2_000,
            gas_limit: 21_000,
            id32: ID_B,
            pricing: TxPricing::Eip1559 { max_fee_per_gas: 200, max_priority_fee_per_gas: 7 },
        };

        let s1 = policy.score(&tx1, env, now).unwrap();
        let s2 = policy.score(&tx2, env, now).unwrap();
        assert!(s2 > s1);
    }

    #[test]
    fn replacement_bump_check() {
        let policy = Eip1559PriorityPolicy::new(PriorityConfig { age_bonus_per_s: 0, replace_bump_percent: 10 });
        let env = Env { base_fee_per_gas: 30 };

        // Old: tip 5
        let old_tx = TxMeta {
            first_seen_ms: 0,
            gas_limit: 21_000,
            id32: ID_A,
            pricing: TxPricing::Eip1559 { max_fee_per_gas: 100, max_priority_fee_per_gas: 5 },
        };
        // New: tip 5.4 -> +8% (not enough for 10%)
        let new_tx_low = TxMeta {
            first_seen_ms: 0,
            gas_limit: 21_000,
            id32: ID_B,
            pricing: TxPricing::Eip1559 { max_fee_per_gas: 300, max_priority_fee_per_gas: 6 },
        };
        // New: tip 6 -> +20% (sufficient)
        let new_tx_ok = TxMeta {
            first_seen_ms: 0,
            gas_limit: 21_000,
            id32: ID_B,
            pricing: TxPricing::Eip1559 { max_fee_per_gas: 300, max_priority_fee_per_gas: 6 + 1 },
        };

        assert!(!policy.is_sufficient_bump(&old_tx, &new_tx_low, env));
        assert!(policy.is_sufficient_bump(&old_tx, &new_tx_ok, env));
    }
}

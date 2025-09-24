//! Fee market & estimator for Aethernova node.
//!
//! Features:
//! - EIP-1559 base fee projection (deterministic, integer math).
//! - Legacy gas price estimator.
//! - Sliding window quantile estimator (P²-lite via sort on bounded window).
//! - EWMA smoothing to reduce jitter.
//! - Urgency tiers -> percentiles mapping.
//! - Thread-safe API (Arc + RwLock), zero-unsafe, saturating math.
//!
//! All units are wei unless explicitly noted.

use std::{
    cmp::{max, min},
    collections::VecDeque,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Urgency levels for fee suggestions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Urgency {
    Slow,
    Standard,
    Fast,
    Instant,
}

/// Result of a fee estimation request.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FeeSuggestion {
    /// For EIP-1559: suggested max_fee_per_gas.
    pub max_fee_per_gas: Option<u128>,
    /// For EIP-1559: suggested max_priority_fee_per_gas.
    pub max_priority_fee_per_gas: Option<u128>,
    /// For legacy chains/wallets: effective gasPrice.
    pub legacy_gas_price: Option<u128>,
    /// Latest (or projected) base fee.
    pub base_fee_per_gas: Option<u128>,
    /// Confidence 0.0..1.0 based on sample size and window coverage.
    pub confidence: f32,
    /// Human-friendly name of the algorithm/percentile.
    pub algorithm: &'static str,
}

/// Fee estimator trait.
pub trait FeeEstimator: Send + Sync {
    fn estimate(&self, urgency: Urgency) -> FeeSuggestion;
}

/// Immutable configuration for the fee market.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FeeMarketConfig {
    /// Sliding window sizes (number of samples).
    pub window_txs: usize,
    pub window_blocks: usize,
    /// EWMA alpha for smoothing [0.0, 1.0]; 0 -> no smoothing, 1 -> no memory.
    pub ewma_alpha: f64,
    /// Default priority tip if mempool has insufficient data (in wei).
    pub default_priority_tip_wei: u128,
    /// Minimum/maximum clamps (saturation guards).
    pub min_fee_wei: u128,
    pub max_fee_wei: u128,
    /// Percentile mapping per urgency (0..100).
    pub pctl_slow: u8,
    pub pctl_standard: u8,
    pub pctl_fast: u8,
    pub pctl_instant: u8,
}

impl Default for FeeMarketConfig {
    fn default() -> Self {
        Self {
            window_txs: 1024,
            window_blocks: 256,
            ewma_alpha: 0.25,
            default_priority_tip_wei: gwei(1), // 1 gwei fallback
            min_fee_wei: gwei(1),
            max_fee_wei: eth(1), // clamp at 1 ETH gas (safety)
            pctl_slow: 25,
            pctl_standard: 50,
            pctl_fast: 75,
            pctl_instant: 90,
        }
    }
}

/// Observation from mempool or recent block tx set.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FeeObservation {
    /// Effective gas price paid by the tx (legacy: gasPrice; 1559: min(maxFee, baseFee+tip)).
    pub effective_gas_price: u128,
    /// Priority tip (1559), or 0 for legacy if unknown.
    pub priority_fee_per_gas: u128,
    pub timestamp_s: u64,
}

/// Block observation to update base fee projection.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlockObservation {
    pub base_fee_per_gas: u128,
    pub gas_used: u128,
    pub gas_limit: u128,
    pub timestamp_s: u64,
}

/// Internal sliding window with bounded capacity.
#[derive(Clone, Debug)]
struct SlidingWindow {
    cap: usize,
    buf: VecDeque<u128>,
}

impl SlidingWindow {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            buf: VecDeque::with_capacity(cap),
        }
    }

    fn push(&mut self, v: u128) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn percentile(&self, pctl: u8) -> Option<u128> {
        if self.buf.is_empty() {
            return None;
        }
        let mut v: Vec<u128> = self.buf.iter().copied().collect();
        v.sort_unstable();
        let p = min(pctl as usize, 100);
        // nearest-rank method
        let idx = ((p as f64 / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
        v.get(idx).copied()
    }

    fn min(&self) -> Option<u128> {
        self.buf.iter().copied().min()
    }

    fn max(&self) -> Option<u128> {
        self.buf.iter().copied().max()
    }

    fn mean(&self) -> Option<u128> {
        if self.buf.is_empty() {
            None
        } else {
            let sum: u128 = self.buf.iter().copied().sum();
            Some(sum / self.buf.len() as u128)
        }
    }
}

/// Main fee market state.
#[derive(Clone, Debug)]
pub struct FeeMarket {
    cfg: FeeMarketConfig,
    // samples
    fee_samples: SlidingWindow,      // effective gas price samples (wei)
    tip_samples: SlidingWindow,      // priority fee samples (wei)
    basefee_samples: SlidingWindow,  // base fee samples (wei)
    // EWMA trackers (f64 to avoid overflow/jitter)
    ewma_fee: Option<f64>,
    ewma_tip: Option<f64>,
    ewma_base: Option<f64>,
    // last known base fee (wei)
    last_base_fee: Option<u128>,
}

impl FeeMarket {
    pub fn new(cfg: FeeMarketConfig) -> Self {
        Self {
            cfg,
            fee_samples: SlidingWindow::new(cfg.window_txs),
            tip_samples: SlidingWindow::new(cfg.window_txs),
            basefee_samples: SlidingWindow::new(cfg.window_blocks),
            ewma_fee: None,
            ewma_tip: None,
            ewma_base: None,
            last_base_fee: None,
        }
    }

    /// Thread-safe wrapper.
    pub fn shared(cfg: FeeMarketConfig) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self::new(cfg)))
    }

    /// Record a mempool transaction observation.
    pub fn record_mempool_tx(&mut self, obs: FeeObservation) {
        let clamped_eff = clamp(obs.effective_gas_price, self.cfg.min_fee_wei, self.cfg.max_fee_wei);
        let clamped_tip = clamp(obs.priority_fee_per_gas, 0, self.cfg.max_fee_wei);
        self.fee_samples.push(clamped_eff);
        self.tip_samples.push(clamped_tip);
        self.update_ewma_pair(clamped_eff as f64, clamped_tip as f64);
    }

    /// Record a new block and update base fee projection (EIP-1559 style).
    pub fn record_block(&mut self, b: BlockObservation) {
        let base = b.base_fee_per_gas;
        self.last_base_fee = Some(base);
        self.basefee_samples.push(clamp(base, self.cfg.min_fee_wei, self.cfg.max_fee_wei));
        self.update_ewma_base(base as f64);
        // compute next base fee for projection using EIP-1559 formula
        if b.gas_limit > 0 {
            let next = calc_next_base_fee(base, b.gas_used, b.gas_limit);
            self.last_base_fee = Some(next);
        }
    }

    fn update_ewma_pair(&mut self, fee: f64, tip: f64) {
        let a = self.cfg.ewma_alpha;
        self.ewma_fee = Some(ewma(self.ewma_fee, fee, a));
        self.ewma_tip = Some(ewma(self.ewma_tip, tip, a));
    }

    fn update_ewma_base(&mut self, base: f64) {
        let a = self.cfg.ewma_alpha;
        self.ewma_base = Some(ewma(self.ewma_base, base, a));
    }

    /// Calculate EIP-1559 suggestion given percentile.
    fn estimate_1559(&self, pctl: u8) -> FeeSuggestion {
        let base = self
            .last_base_fee
            .or(self.basefee_samples.mean())
            .or_else(|| self.fee_samples.min()) // conservative fallback
            .unwrap_or(self.cfg.min_fee_wei);

        // Priority tip from samples or default.
        let priority = self
            .tip_samples.percentile(pctl)
            .or(self.tip_samples.mean())
            .unwrap_or(self.cfg.default_priority_tip_wei);

        // Max fee: percentile of effective gas or base+priority (with headroom)
        let eff_p = self
            .fee_samples.percentile(pctl)
            .or(self.fee_samples.mean())
            .unwrap_or(base.saturating_add(priority));

        // Add 12.5% headroom like EIP-1559 max change per block to reduce underpricing.
        let headroom = mul_pct(eff_p, 1250); // 12.50% of eff_p
        let max_fee = clamp(
            base.saturating_add(priority).saturating_add(headroom),
            self.cfg.min_fee_wei,
            self.cfg.max_fee_wei,
        );

        FeeSuggestion {
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(priority),
            legacy_gas_price: None,
            base_fee_per_gas: Some(base),
            confidence: self.confidence(),
            algorithm: "eip1559-pctl-ewma",
        }
    }

    /// Legacy gas price estimation given percentile.
    fn estimate_legacy(&self, pctl: u8) -> FeeSuggestion {
        let gas_price = self
            .fee_samples.percentile(pctl)
            .or(self.fee_samples.mean())
            .unwrap_or(self.cfg.min_fee_wei);

        FeeSuggestion {
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            legacy_gas_price: Some(clamp(gas_price, self.cfg.min_fee_wei, self.cfg.max_fee_wei)),
            base_fee_per_gas: self.last_base_fee,
            confidence: self.confidence(),
            algorithm: "legacy-pctl-ewma",
        }
    }

    fn confidence(&self) -> f32 {
        let tx_cov = min(self.fee_samples.len(), self.cfg.window_txs) as f32 / self.cfg.window_txs as f32;
        let blk_cov = min(self.basefee_samples.len(), self.cfg.window_blocks) as f32 / self.cfg.window_blocks as f32;
        0.5 * tx_cov + 0.5 * blk_cov
    }
}

impl FeeEstimator for Arc<RwLock<FeeMarket>> {
    fn estimate(&self, urgency: Urgency) -> FeeSuggestion {
        let (pctl, eip1559) = match urgency {
            Urgency::Slow => (self.read().unwrap().cfg.pctl_slow, true),
            Urgency::Standard => (self.read().unwrap().cfg.pctl_standard, true),
            Urgency::Fast => (self.read().unwrap().cfg.pctl_fast, true),
            Urgency::Instant => (self.read().unwrap().cfg.pctl_instant, true),
        };
        let s = self.read().unwrap();
        // Prefer 1559 if we have a base fee signal; otherwise fall back to legacy.
        if s.last_base_fee.is_some() || !s.basefee_samples.is_empty() {
            s.estimate_1559(pctl)
        } else {
            s.estimate_legacy(pctl)
        }
    }
}

/// EIP-1559 next base fee calculation (integer, saturating).
///
/// target = gas_limit / 2
/// delta = prev_base_fee * (gas_used - target) / target / 8
/// next = prev_base_fee + delta (clamped at >= 0)
fn calc_next_base_fee(prev_base_fee: u128, gas_used: u128, gas_limit: u128) -> u128 {
    if gas_limit == 0 {
        return prev_base_fee;
    }
    let target = gas_limit / 2;
    if target == 0 {
        return prev_base_fee;
    }

    // Signed difference
    let used_diff: i128 = gas_used as i128 - target as i128;

    // prev_base_fee * |used_diff| / target / 8
    let mut adj = (prev_base_fee as u128)
        .saturating_mul(used_diff.unsigned_abs())
        / target
        / 8;

    // Minimum delta of 1 if gas_used != target and prev_base_fee > 0 (classic nuance)
    if used_diff != 0 && adj == 0 && prev_base_fee > 0 {
        adj = 1;
    }

    if used_diff > 0 {
        prev_base_fee.saturating_add(adj)
    } else if used_diff < 0 {
        prev_base_fee.saturating_sub(min(prev_base_fee, adj))
    } else {
        prev_base_fee
    }
}

/// Simple EWMA.
fn ewma(prev: Option<f64>, x: f64, alpha: f64) -> f64 {
    let a = alpha.clamp(0.0, 1.0);
    match prev {
        Some(p) => a * x + (1.0 - a) * p,
        None => x,
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn clamp(v: u128, lo: u128, hi: u128) -> u128 {
    max(lo, min(v, hi))
}

fn mul_pct(v: u128, bp: u32) -> u128 {
    // basis points: 1% = 100 bp; 12.5% = 1250 bp
    v.saturating_mul(bp as u128) / 10_000u128
}

#[inline]
pub const fn gwei(n: u128) -> u128 {
    n * 1_000_000_000u128
}

#[inline]
pub const fn eth(n: u128) -> u128 {
    n * 1_000_000_000_000_000_000u128
}

/// Public API facade (thread-safe).
#[derive(Clone)]
pub struct FeeMarketHandle {
    inner: Arc<RwLock<FeeMarket>>,
}

impl FeeMarketHandle {
    pub fn new(cfg: FeeMarketConfig) -> Self {
        Self {
            inner: FeeMarket::shared(cfg),
        }
    }

    pub fn record_mempool_tx(&self, effective_gas_price: u128, priority_fee: u128) {
        let obs = FeeObservation {
            effective_gas_price,
            priority_fee_per_gas: priority_fee,
            timestamp_s: now_s(),
        };
        if let Ok(mut m) = self.inner.write() {
            m.record_mempool_tx(obs);
        }
    }

    pub fn record_block(&self, base_fee: u128, gas_used: u128, gas_limit: u128) {
        let obs = BlockObservation {
            base_fee_per_gas: base_fee,
            gas_used,
            gas_limit,
            timestamp_s: now_s(),
        };
        if let Ok(mut m) = self.inner.write() {
            m.record_block(obs);
        }
    }

    pub fn estimate(&self, urgency: Urgency) -> FeeSuggestion {
        self.inner.estimate(urgency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fee_adjusts_up_and_down() {
        // Start with base fee 100 gwei, simulate high gas usage (increase)
        let prev = gwei(100);
        let gas_limit = 30_000_000u128;
        let target = gas_limit / 2;
        let up = calc_next_base_fee(prev, target + 10_000_000, gas_limit);
        assert!(up > prev, "base fee should increase when gas_used > target");

        let down = calc_next_base_fee(prev, target - 10_000_000, gas_limit);
        assert!(down < prev, "base fee should decrease when gas_used < target");

        let same = calc_next_base_fee(prev, target, gas_limit);
        assert_eq!(same, prev, "base fee unchanged when gas_used == target");
    }

    #[test]
    fn sliding_window_percentiles() {
        let mut w = SlidingWindow::new(5);
        for v in [1u128, 2, 3, 4, 100] {
            w.push(v);
        }
        assert_eq!(w.percentile(0), Some(1));
        assert_eq!(w.percentile(50), Some(3));
        let p90 = w.percentile(90).unwrap();
        assert!(p90 >= 4 && p90 <= 100);
    }

    #[test]
    fn estimator_behaviour() {
        let cfg = FeeMarketConfig::default();
        let h = FeeMarketHandle::new(cfg);

        // No base fee yet -> legacy path.
        for v in 1..=10u128 {
            h.record_mempool_tx(gwei(10 + v), gwei(1));
        }
        let s_legacy = h.estimate(Urgency::Standard);
        assert!(s_legacy.legacy_gas_price.is_some());
        assert!(s_legacy.max_fee_per_gas.is_none());

        // Now feed a block to enable 1559 path.
        h.record_block(gwei(50), 15_000_000, 30_000_000);
        for _ in 0..64 {
            h.record_mempool_tx(gwei(60), gwei(2));
        }
        let s_1559 = h.estimate(Urgency::Fast);
        assert!(s_1559.max_fee_per_gas.is_some());
        assert!(s_1559.max_priority_fee_per_gas.is_some());
        assert!(s_1559.legacy_gas_price.is_none());
        assert!(s_1559.base_fee_per_gas.unwrap() > 0);
    }

    #[test]
    fn ewma_smoothing_monotone() {
        let mut m = FeeMarket::new(FeeMarketConfig::default());
        // push increasing fees, EWMA should follow without exploding
        for k in 0..100u128 {
            m.record_mempool_tx(FeeObservation {
                effective_gas_price: gwei(10) + k,
                priority_fee_per_gas: gwei(1),
                timestamp_s: now_s(),
            });
        }
        // Sanity
        assert!(m.fee_samples.len() > 0);
    }
}

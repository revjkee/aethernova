//! Token vesting primitives for Launchpad.
//!
//! Features:
//! - TGE (initial unlock) specified in basis points (0..=10_000).
//! - Cliff, linear vesting with slice-based discretization.
//! - Revocable schedules; cancel() freezes further accrual at cancel time,
//!   already-vested but unreleased remains claimable.
//! - Registry managing multiple schedules with incremental IDs.
//! - Saturating/checked math on u128 amounts, explicit invariants.
//! - Serde support for persistence and deterministic state snapshots.
//!
//! Time model: seconds since Unix epoch (i64). All computations are deterministic
//! and monotonic with respect to time inputs provided by the integration layer.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_docs)]

use core::fmt;
use std::collections::HashMap;

/// Amount type (atomic token units).
pub type Amount = u128;

/// Seconds since Unix epoch.
pub type Timestamp = i64;

/// Identifier of a vesting schedule inside a registry.
pub type ScheduleId = u64;

/// Basis points denominator (100% == 10_000 bps).
pub const BPS_DENOM: u32 = 10_000;

/// Errors returned by vesting operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum VestingError {
    /// Generic invalid argument with context.
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
    /// Overflow detected in arithmetic.
    #[error("arithmetic overflow")]
    Overflow,
    /// Operation is not permitted (e.g., cancel on non-revocable).
    #[error("not allowed: {0}")]
    NotAllowed(&'static str),
    /// Schedule not found in registry.
    #[error("schedule not found")]
    NotFound,
}

/// One vesting schedule with TGE + Cliff + Linear remainder.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct VestingSchedule {
    /// Beneficiary identity (opaque string, e.g. address).
    pub beneficiary: String,
    /// Total allocated amount for this schedule.
    pub total_amount: Amount,
    /// Start timestamp of the schedule (also TGE moment).
    pub start_ts: Timestamp,
    /// Cliff timestamp. Before this moment (exclusive), only TGE is vested.
    pub cliff_ts: Timestamp,
    /// Full vesting duration in seconds (from start_ts to end_ts == start_ts + duration_s).
    pub duration_s: u64,
    /// Discretization period in seconds for linear vesting (>= 1).
    pub slice_period_s: u64,
    /// Initial unlock at TGE in basis points (0..=10_000).
    pub tge_bps: u16,
    /// Is schedule revocable by the issuer?
    pub revocable: bool,

    /// Amount already released to beneficiary.
    pub released: Amount,
    /// If present, accrual is stopped at this timestamp.
    pub canceled_at: Option<Timestamp>,

    /// Optional human-readable tag.
    pub tag: Option<String>,
}

impl fmt::Debug for VestingSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VestingSchedule")
            .field("beneficiary", &self.beneficiary)
            .field("total_amount", &self.total_amount)
            .field("start_ts", &self.start_ts)
            .field("cliff_ts", &self.cliff_ts)
            .field("duration_s", &self.duration_s)
            .field("slice_period_s", &self.slice_period_s)
            .field("tge_bps", &self.tge_bps)
            .field("revocable", &self.revocable)
            .field("released", &self.released)
            .field("canceled_at", &self.canceled_at)
            .field("tag", &self.tag)
            .finish()
    }
}

/// Builder ensuring invariants at construction time.
#[derive(Debug, Default)]
pub struct VestingBuilder {
    beneficiary: Option<String>,
    total_amount: Option<Amount>,
    start_ts: Option<Timestamp>,
    cliff_ts: Option<Timestamp>,
    duration_s: Option<u64>,
    slice_period_s: Option<u64>,
    tge_bps: Option<u16>,
    revocable: bool,
    tag: Option<String>,
}

impl VestingBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn beneficiary(mut self, b: impl Into<String>) -> Self {
        self.beneficiary = Some(b.into());
        self
    }
    pub fn total_amount(mut self, a: Amount) -> Self {
        self.total_amount = Some(a);
        self
    }
    pub fn start_ts(mut self, t: Timestamp) -> Self {
        self.start_ts = Some(t);
        self
    }
    pub fn cliff_ts(mut self, t: Timestamp) -> Self {
        self.cliff_ts = Some(t);
        self
    }
    pub fn duration_s(mut self, d: u64) -> Self {
        self.duration_s = Some(d);
        self
    }
    pub fn slice_period_s(mut self, s: u64) -> Self {
        self.slice_period_s = Some(s);
        self
    }
    pub fn tge_bps(mut self, bps: u16) -> Self {
        self.tge_bps = Some(bps);
        self
    }
    pub fn revocable(mut self, yes: bool) -> Self {
        self.revocable = yes;
        self
    }
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tag = Some(t.into());
        self
    }

    /// Build a schedule validating invariants.
    pub fn build(self) -> Result<VestingSchedule, VestingError> {
        let beneficiary = self.beneficiary.ok_or(VestingError::Invalid("beneficiary"))?;
        let total_amount = self.total_amount.ok_or(VestingError::Invalid("total_amount"))?;
        if total_amount == 0 {
            return Err(VestingError::Invalid("total_amount must be > 0"));
        }

        let start_ts = self.start_ts.ok_or(VestingError::Invalid("start_ts"))?;
        let cliff_ts = self.cliff_ts.ok_or(VestingError::Invalid("cliff_ts"))?;
        let duration_s = self.duration_s.ok_or(VestingError::Invalid("duration_s"))?;
        if duration_s == 0 {
            return Err(VestingError::Invalid("duration_s must be > 0"));
        }
        let slice_period_s = self.slice_period_s.unwrap_or(1);
        if slice_period_s == 0 {
            return Err(VestingError::Invalid("slice_period_s must be >= 1"));
        }
        let tge_bps = self.tge_bps.unwrap_or(0);
        if tge_bps as u32 > BPS_DENOM as u32 {
            return Err(VestingError::Invalid("tge_bps out of range"));
        }

        // start <= cliff <= start + duration
        let end_ts = start_ts
            .checked_add(duration_s as i64)
            .ok_or(VestingError::Overflow)?;
        if cliff_ts < start_ts {
            return Err(VestingError::Invalid("cliff before start"));
        }
        if cliff_ts > end_ts {
            return Err(VestingError::Invalid("cliff after end"));
        }

        Ok(VestingSchedule {
            beneficiary,
            total_amount,
            start_ts,
            cliff_ts,
            duration_s,
            slice_period_s,
            tge_bps,
            revocable: self.revocable,
            released: 0,
            canceled_at: None,
            tag: self.tag,
        })
    }
}

impl VestingSchedule {
    /// End timestamp (inclusive boundary for accrual).
    #[inline]
    pub fn end_ts(&self) -> Timestamp {
        self.start_ts + self.duration_s as i64
    }

    /// Amount unlocked at TGE.
    #[inline]
    pub fn tge_amount(&self) -> Result<Amount, VestingError> {
        mul_bps(self.total_amount, self.tge_bps)
    }

    /// Amount that is subject to linear vesting after TGE.
    #[inline]
    pub fn linear_pool(&self) -> Result<Amount, VestingError> {
        self.total_amount
            .checked_sub(self.tge_amount()?)
            .ok_or(VestingError::Overflow)
    }

    /// Compute vested amount at `now`, respecting cliff, slice discretization and cancel freeze.
    ///
    /// Rules:
    /// - If now < start: 0
    /// - If now >= start: at least TGE amount is vested.
    /// - If now < cliff: vested == TGE
    /// - Linear part accrues from cliff to end (inclusive) in `slice_period_s` chunks.
    /// - If canceled, accrual time is truncated by `canceled_at`.
    pub fn vested_at(&self, now: Timestamp) -> Result<Amount, VestingError> {
        if now < self.start_ts {
            return Ok(0);
        }

        let tge = self.tge_amount()?;

        if self.duration_s == 0 {
            return Ok(self.total_amount); // shouldn't happen due to builder guard
        }

        let stop = match self.canceled_at {
            Some(c) => now.min(c),
            None => now,
        };

        if stop < self.cliff_ts {
            return Ok(tge);
        }

        let end = self.end_ts();
        if stop >= end {
            return Ok(self.total_amount);
        }

        // Linear accrual window (from cliff to end).
        let linear_total = self.linear_pool()?;
        if linear_total == 0 {
            return Ok(tge);
        }

        let elapsed_s = (stop - self.cliff_ts) as i64;
        let total_linear_s = (end - self.cliff_ts) as i64;

        // Discretize elapsed to full slices.
        let slice = self.slice_period_s as i64;
        let full_slices = if slice <= 0 { 0 } else { elapsed_s / slice };
        let elapsed_discrete = (full_slices * slice).clamp(0, total_linear_s);

        // Pro rata: linear_total * elapsed_discrete / total_linear_s
        let lin = mul_div_u128(linear_total, elapsed_discrete as u128, total_linear_s as u128)?;

        tge.checked_add(lin).ok_or(VestingError::Overflow)
    }

    /// Releasable amount at `now`.
    #[inline]
    pub fn releasable_at(&self, now: Timestamp) -> Result<Amount, VestingError> {
        let v = self.vested_at(now)?;
        v.checked_sub(self.released).ok_or(VestingError::Overflow)
    }

    /// Apply release at `now`: increases `released` and returns delta.
    pub fn release(&mut self, now: Timestamp) -> Result<Amount, VestingError> {
        let delta = self.releasable_at(now)?;
        self.released = self
            .released
            .checked_add(delta)
            .ok_or(VestingError::Overflow)?;
        Ok(delta)
    }

    /// Cancel a revocable schedule at `now`. After this, no further vesting accrues.
    pub fn cancel(&mut self, now: Timestamp) -> Result<(), VestingError> {
        if !self.revocable {
            return Err(VestingError::NotAllowed("not revocable"));
        }
        if self.canceled_at.is_none() {
            self.canceled_at = Some(now.max(self.start_ts));
        }
        Ok(())
    }

    /// Unvested remainder at time t (for bookkeeping/refund).
    pub fn unvested_at(&self, now: Timestamp) -> Result<Amount, VestingError> {
        let vested = self.vested_at(now)?;
        self.total_amount
            .checked_sub(vested)
            .ok_or(VestingError::Overflow)
    }
}

/// Multiply amount by basis points (bps / 10_000).
#[inline]
fn mul_bps(amount: Amount, bps: u16) -> Result<Amount, VestingError> {
    mul_div_u128(amount, bps as u128, BPS_DENOM as u128)
}

/// Compute a * b / d with overflow check: returns floor((a*b)/d).
#[inline]
fn mul_div_u128(a: u128, b: u128, d: u128) -> Result<u128, VestingError> {
    if d == 0 {
        return Err(VestingError::Invalid("division by zero"));
    }
    // 256-bit intermediate via double-width strategy on u128:
    // split a and b into hi/lo 64-bit limbs to avoid overflow in multiplication.
    let a_hi = (a >> 64) as u128;
    let a_lo = (a & ((1u128 << 64) - 1)) as u128;
    let b_hi = (b >> 64) as u128;
    let b_lo = (b & ((1u128 << 64) - 1)) as u128;

    let mid = a_hi * b_lo + a_lo * b_hi;
    let mid_hi = mid >> 64;
    let mid_lo = mid << 64;

    let lo = a_lo
        .checked_mul(b_lo)
        .ok_or(VestingError::Overflow)?;
    let hi = a_hi
        .checked_mul(b_hi)
        .ok_or(VestingError::Overflow)?
        .checked_add(mid_hi)
        .ok_or(VestingError::Overflow)?;

    // Now we have 256-bit product as (hi, mid_lo + lo). Combine safely:
    let (sum_lo, carry) = sum_with_carry(lo, mid_lo);
    let hi = hi
        .checked_add(carry as u128)
        .ok_or(VestingError::Overflow)?;

    // We need floor((hi<<128 + sum_lo)/d). We cannot represent hi<<128 directly.
    // Use long division: divide the 256-bit by d using two limbs.
    div_256_by_u128(hi, sum_lo, d)
}

/// Add two u128 with carry-out (as bool).
#[inline]
fn sum_with_carry(a: u128, b: u128) -> (u128, bool) {
    let (res, carry1) = a.overflowing_add(b);
    (res, carry1)
}

/// Divide 256-bit value (hi:lo) by 128-bit divisor d. Return floor((hi<<128 + lo)/d).
fn div_256_by_u128(hi: u128, lo: u128, d: u128) -> Result<u128, VestingError> {
    if d == 0 {
        return Err(VestingError::Invalid("division by zero"));
    }
    // Simple normalization-based division since d fits 128 bits and hi <= u128::MAX.
    // When hi == 0, regular division is enough.
    if hi == 0 {
        return Ok(lo / d);
    }
    // Use leading zeros to normalize d into 127..128 bits and shift (hi:lo) accordingly.
    let lz = d.leading_zeros();
    let d_norm = d << lz;
    let hi_norm = (hi << lz) | (lo >> (128 - lz));
    let lo_norm = lo << lz;

    // 256/128 division: quotient fits into 128 bits. We can approximate with two 128/128 steps.
    let q1 = hi_norm / d_norm;
    let r1 = hi_norm % d_norm;

    // Build remainder limb with next 128 bits.
    let num2_hi = r1;
    let num2_lo = lo_norm;
    // Merge into 256 then divide: since denominator is 128-bit, q2 fits 128.
    // But we only need lower limb quotient.
    let q2 = div_256_small(num2_hi, num2_lo, d_norm);

    // Full quotient is (q1<<128) + q2, but it must fit in u128; if q1 != 0, overflow.
    if q1 != 0 {
        return Err(VestingError::Overflow);
    }
    Ok(q2)
}

/// Divide (hi:lo) by d where d is 128-bit and hi < d (guaranteed). Return floor((hi<<128 + lo)/d).
fn div_256_small(hi: u128, lo: u128, d: u128) -> u128 {
    // Since hi < d, the quotient fits into 128 bits.
    // Use binary search / Newton could be overkill; standard long division:
    // We iteratively subtract shifted divisor. For performance, this path is hot only in setup math.
    let mut rem_hi = hi;
    let mut rem_lo = lo;
    let mut q = 0u128;

    for bit in (0..128).rev() {
        // Compare remainder with d<<bit
        let (b_hi, b_lo) = shl_128(d, bit);
        if ge_256(rem_hi, rem_lo, b_hi, b_lo) {
            let (n_hi, n_lo) = sub_256(rem_hi, rem_lo, b_hi, b_lo);
            rem_hi = n_hi;
            rem_lo = n_lo;
            q |= 1u128 << bit;
        }
    }
    q
}

#[inline]
fn shl_128(x: u128, shift: u32) -> (u128, u128) {
    if shift == 0 {
        (0, x)
    } else if shift < 128 {
        let hi = x >> (128 - shift);
        let lo = x << shift;
        (hi, lo)
    } else {
        (x << (shift - 128), 0)
    }
}

#[inline]
fn ge_256(a_hi: u128, a_lo: u128, b_hi: u128, b_lo: u128) -> bool {
    (a_hi > b_hi) || (a_hi == b_hi && a_lo >= b_lo)
}

#[inline]
fn sub_256(a_hi: u128, a_lo: u128, b_hi: u128, b_lo: u128) -> (u128, u128) {
    let (lo, borrow) = a_lo.overflowing_sub(b_lo);
    let hi = a_hi - b_hi - (borrow as u128);
    (hi, lo)
}

/// In-memory registry of vesting schedules.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct VestingRegistry {
    next_id: ScheduleId,
    schedules: HashMap<ScheduleId, VestingSchedule>,
}

impl VestingRegistry {
    /// Create empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert schedule and return its id.
    pub fn insert(&mut self, schedule: VestingSchedule) -> ScheduleId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.schedules.insert(id, schedule);
        id
    }

    /// Get immutable reference.
    pub fn get(&self, id: ScheduleId) -> Option<&VestingSchedule> {
        self.schedules.get(&id)
    }

    /// Get mutable reference.
    pub fn get_mut(&mut self, id: ScheduleId) -> Option<&mut VestingSchedule> {
        self.schedules.get_mut(&id)
    }

    /// Release releasable amount at `now`, returning amount released.
    pub fn release(&mut self, id: ScheduleId, now: Timestamp) -> Result<Amount, VestingError> {
        let sch = self.get_mut(id).ok_or(VestingError::NotFound)?;
        sch.release(now)
    }

    /// Cancel a revocable schedule at `now`.
    pub fn cancel(&mut self, id: ScheduleId, now: Timestamp) -> Result<(), VestingError> {
        let sch = self.get_mut(id).ok_or(VestingError::NotFound)?;
        sch.cancel(now)
    }

    /// Compute vested at `now`.
    pub fn vested_at(&self, id: ScheduleId, now: Timestamp) -> Result<Amount, VestingError> {
        self.get(id).ok_or(VestingError::NotFound)?.vested_at(now)
    }

    /// Compute releasable at `now`.
    pub fn releasable_at(&self, id: ScheduleId, now: Timestamp) -> Result<Amount, VestingError> {
        self.get(id).ok_or(VestingError::NotFound)?.releasable_at(now)
    }
}

/* ---------------------------------- TESTS ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    const A: Amount = 1_000_000_000_000u128; // 1e12

    fn sch(
        tge_bps: u16,
        start: Timestamp,
        cliff: Timestamp,
        dur: u64,
        slice: u64,
    ) -> VestingSchedule {
        VestingBuilder::new()
            .beneficiary("alice")
            .total_amount(A)
            .start_ts(start)
            .cliff_ts(cliff)
            .duration_s(dur)
            .slice_period_s(slice)
            .tge_bps(tge_bps)
            .revocable(true)
            .tag("unit")
            .build()
            .unwrap()
    }

    #[test]
    fn tge_and_cliff_behavior() {
        let start = 1_000;
        let dur = 1_000;
        let cliff = start + 300;
        let s = sch(1_000, start, cliff, dur, 10); // 10% TGE

        // Before start -> 0
        assert_eq!(s.vested_at(start - 1).unwrap(), 0);

        // At start -> TGE
        assert_eq!(s.vested_at(start).unwrap(), mul_bps(A, 1_000).unwrap());

        // Before cliff -> TGE
        assert_eq!(s.vested_at(cliff - 1).unwrap(), mul_bps(A, 1_000).unwrap());
    }

    #[test]
    fn linear_after_cliff() {
        let start = 0;
        let dur = 1_000;
        let cliff = 200;
        let s = sch(0, start, cliff, dur, 100);

        // Half-way between cliff and end; slices at 100s.
        let end = start + dur as i64;
        let mid = cliff + (end - cliff) / 2;
        let v = s.vested_at(mid).unwrap();
        // Approximately 50% (due to slicing it may be slightly less).
        assert!(v > A / 2 - A / 100 && v <= A / 2);
    }

    #[test]
    fn full_after_end() {
        let s = sch(2_000, 0, 0, 10, 1);
        assert_eq!(s.vested_at(100).unwrap(), A);
    }

    #[test]
    fn release_and_cancel() {
        let start = 0;
        let dur = 1_000;
        let cliff = 200;
        let mut s = sch(1_000, start, cliff, dur, 50);

        // Some time after cliff
        let t = 600;
        let vested = s.vested_at(t).unwrap();
        let rel = s.release(t).unwrap();
        assert_eq!(rel, vested);

        // Cancel later: accrual frozen
        s.cancel(800).unwrap();
        let vested_after = s.vested_at(999_999).unwrap();
        assert_eq!(vested_after, s.vested_at(800).unwrap());
    }

    #[test]
    fn registry_flow() {
        let mut reg = VestingRegistry::new();
        let id = reg.insert(sch(0, 0, 0, 1_000, 10));
        let r1 = reg.releasable_at(id, 100).unwrap();
        assert!(r1 > 0);
        let rel = reg.release(id, 100).unwrap();
        assert_eq!(rel, r1);
        let r2 = reg.releasable_at(id, 100).unwrap();
        assert_eq!(r2, 0);
    }
}

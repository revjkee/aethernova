//! Multidimensional gas accounting for a VM: CPU / IO / Storage.
//!
//! Design goals:
//! - Vector gas model (`Gas`) with three independent dimensions.
//! - Budgeted metering (`GasMeter`) with predictable errors.
//! - Safe arithmetic: u128; checked math for fees, saturating for internal tallies.
//! - Deterministic refund semantics.
//! - serde for persistence; tracing for observability.
//!
//! References (concepts & safety):
//! - Rust std saturating_* / checked_* for u128 (overflow behavior). See std docs.
//! - Ethereum: gas as computation limit & pricing.
//! - Solana: Compute Units & prioritization fee (per-unit pricing).
//! - WASM gas metering instrumentation and "fuel" counters.
//!
//! NOTE: fee arithmetic uses *checked* math and returns Overflow on exceeding u128.

use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, instrument};

/// Core resource vector: CPU / IO / Storage.
/// Units are abstract; define a consistent convention at the VM boundary:
/// - cpu: abstract compute units (e.g., wasm ops or ns normalized)
/// - io: bytes transferred (r/w), or weighted IO-ops
/// - storage: persisted bytes delta or weighted writes
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gas {
    pub cpu: u128,
    pub io: u128,
    pub storage: u128,
}

impl fmt::Debug for Gas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gas{{cpu:{}, io:{}, storage:{}}}", self.cpu, self.io, self.storage)
    }
}

impl Gas {
    pub const ZERO: Gas = Gas { cpu: 0, io: 0, storage: 0 };

    #[inline]
    pub const fn new(cpu: u128, io: u128, storage: u128) -> Self {
        Gas { cpu, io, storage }
    }

    /// Saturating add for internal tallies (never wraps).
    #[inline]
    pub fn saturating_add(self, rhs: Gas) -> Gas {
        Gas {
            cpu: self.cpu.saturating_add(rhs.cpu),
            io: self.io.saturating_add(rhs.io),
            storage: self.storage.saturating_add(rhs.storage),
        }
    }

    /// Checked add returning None on overflow.
    #[inline]
    pub fn checked_add(self, rhs: Gas) -> Option<Gas> {
        Some(Gas {
            cpu: self.cpu.checked_add(rhs.cpu)?,
            io: self.io.checked_add(rhs.io)?,
            storage: self.storage.checked_add(rhs.storage)?,
        })
    }

    /// Returns true iff `rhs` fits into `self` component-wise (self >= rhs).
    #[inline]
    pub fn covers(&self, rhs: &Gas) -> bool {
        self.cpu >= rhs.cpu && self.io >= rhs.io && self.storage >= rhs.storage
    }

    /// Component-wise subtraction with saturation at zero.
    #[inline]
    pub fn saturating_sub(self, rhs: Gas) -> Gas {
        Gas {
            cpu: self.cpu.saturating_sub(rhs.cpu),
            io: self.io.saturating_sub(rhs.io),
            storage: self.storage.saturating_sub(rhs.storage),
        }
    }

    /// Scale by scalar with checked multiplication.
    #[inline]
    pub fn checked_scale(self, k: u128) -> Option<Gas> {
        Some(Gas {
            cpu: self.cpu.checked_mul(k)?,
            io: self.io.checked_mul(k)?,
            storage: self.storage.checked_mul(k)?,
        })
    }

    /// True if all components are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.cpu == 0 && self.io == 0 && self.storage == 0
    }
}

/// Per-dimension price (tokens-per-unit) for fee calculation.
/// All amounts are u128 to reduce overflow risk.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GasPrice {
    pub cpu: u128,
    pub io: u128,
    pub storage: u128,
}

impl GasPrice {
    pub const ZERO: GasPrice = GasPrice { cpu: 0, io: 0, storage: 0 };

    #[inline]
    pub const fn new(cpu: u128, io: u128, storage: u128) -> Self {
        GasPrice { cpu, io, storage }
    }

    /// Compute total fee = dot(Gas, GasPrice) with checked math.
    #[inline]
    pub fn fee_checked(&self, g: Gas) -> Result<u128, GasError> {
        let cpu = g.cpu.checked_mul(self.cpu).ok_or(GasError::Overflow)?;
        let io = g.io.checked_mul(self.io).ok_or(GasError::Overflow)?;
        let st = g.storage.checked_mul(self.storage).ok_or(GasError::Overflow)?;
        cpu.checked_add(io)
            .and_then(|x| x.checked_add(st))
            .ok_or(GasError::Overflow)
    }
}

/// Errors produced by the gas system.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum GasError {
    #[error("out of gas: need {need:?}, have {have:?}")]
    OutOfGas { need: Gas, have: Gas },

    #[error("arithmetic overflow")]
    Overflow,

    #[error("refund exceeds used gas")]
    InvalidRefund,
}

/// Meter with a fixed budget. Not thread-safe; wrap externally if needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasMeter {
    remaining: Gas,
    used: Gas,
}

impl GasMeter {
    pub fn new(budget: Gas) -> Self {
        Self { remaining: budget, used: Gas::ZERO }
    }

    #[inline]
    pub fn remaining(&self) -> Gas {
        self.remaining
    }

    #[inline]
    pub fn used(&self) -> Gas {
        self.used
    }

    /// Try to charge `cost`. Fails if any dimension exceeds remaining.
    #[instrument(level = "trace", skip(self))]
    pub fn try_charge(&mut self, cost: Gas) -> Result<(), GasError> {
        if !self.remaining.covers(&cost) {
            return Err(GasError::OutOfGas { need: cost, have: self.remaining });
        }
        self.remaining = self.remaining.saturating_sub(cost);
        self.used = self.used.saturating_add(cost);
        Ok(())
    }

    /// Refund previously used gas (e.g., on overestimation). Cannot exceed `used`.
    #[instrument(level = "trace", skip(self))]
    pub fn refund(&mut self, g: Gas) -> Result<(), GasError> {
        // Ensure refund does not exceed 'used'
        if !self.used.covers(&g) {
            return Err(GasError::InvalidRefund);
        }
        self.used = self.used.saturating_sub(g);
        self.remaining = self.remaining.saturating_add(g);
        Ok(())
    }

    /// Consume nothing but return a *preview* of whether `cost` would fit.
    pub fn fits(&self, cost: &Gas) -> bool {
        self.remaining.covers(cost)
    }
}

/// Helper constructors for common costs.
impl Gas {
    #[inline] pub fn cpu(units: u128) -> Self { Gas { cpu: units, io: 0, storage: 0 } }
    #[inline] pub fn io(bytes: u128) -> Self { Gas { cpu: 0, io: bytes, storage: 0 } }
    #[inline] pub fn storage(bytes: u128) -> Self { Gas { cpu: 0, io: 0, storage: bytes } }

    /// Combine heterogeneous components in one call.
    #[inline] pub fn tuple(cpu: u128, io: u128, storage: u128) -> Self { Gas::new(cpu, io, storage) }
}

/* ------------------------------ Tests ------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturating_add_sub() {
        let a = Gas::new(u128::MAX - 1, 10, 0);
        let b = Gas::new(10, 5, u128::MAX);
        let s = a.saturating_add(b);
        assert_eq!(s.cpu, u128::MAX);
        assert_eq!(s.io, 15);
        assert_eq!(s.storage, u128::MAX);
        let d = s.saturating_sub(b);
        assert_eq!(d.cpu, u128::MAX - 10);
        assert_eq!(d.io, 10);
        assert_eq!(d.storage, 0);
    }

    #[test]
    fn meter_charge_refund() {
        let mut m = GasMeter::new(Gas::new(100, 1000, 500));
        assert!(m.try_charge(Gas::cpu(10)).is_ok());
        assert!(m.try_charge(Gas::io(200)).is_ok());
        assert!(m.try_charge(Gas::storage(100)).is_ok());
        assert_eq!(m.remaining(), Gas::new(90, 800, 400));
        assert_eq!(m.used(), Gas::new(10, 200, 100));
        // refund part
        m.refund(Gas::io(50)).unwrap();
        assert_eq!(m.remaining().io, 850);
        assert_eq!(m.used().io, 150);
    }

    #[test]
    fn out_of_gas() {
        let mut m = GasMeter::new(Gas::new(1, 2, 3));
        assert!(matches!(
            m.try_charge(Gas::tuple(2, 0, 0)).unwrap_err(),
            GasError::OutOfGas { .. }
        ));
        // nothing consumed on failure
        assert_eq!(m.used(), Gas::ZERO);
    }

    #[test]
    fn fee_checked() {
        let g = Gas::new(10, 20, 30);
        let p = GasPrice::new(2, 3, 4);
        let fee = p.fee_checked(g).unwrap();
        assert_eq!(fee, 10*2 + 20*3 + 30*4);
        let big = Gas::new(u128::MAX, 0, 0);
        let p2 = GasPrice::new(u128::MAX, 0, 0);
        assert!(matches!(p2.fee_checked(big), Err(GasError::Overflow)));
    }

    #[test]
    fn invalid_refund() {
        let mut m = GasMeter::new(Gas::new(10, 10, 10));
        m.try_charge(Gas::cpu(3)).unwrap();
        assert!(matches!(m.refund(Gas::cpu(4)), Err(GasError::InvalidRefund)));
    }
}

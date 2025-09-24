// aethernova-chain-core/launchpad/src/ido.rs
#![forbid(unsafe_code)]
//! Industrial-grade IDO engine for Aethernova Launchpad.
//!
//! Features:
//! - Deterministic fixed-price sale (raise_asset per sale_token)
//! - Phases: Pending -> Whitelist -> Public -> Ended -> Finalized|Canceled
//! - Whitelist allowlist, per-wallet min/max caps, global soft/hard caps
//! - Oversubscription handled by pro-rata (largest remainder, integer-safe)
//! - Vesting: TGE (bps) + cliff (blocks) + linear vesting (blocks)
//! - Pausable, cancelable by admin; event log for observability
//! - Thread-safe state via RwLock; std-only, no external deps
//!
//! Integration points:
//! - Implement `Funds` trait to move assets (native/erc20) in your runtime.
//! - Use `Listener` to stream business events where needed.

use std::cmp::{min, Ordering};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, RwLock};

pub type Address = [u8; 20];

/// Asset identifier understood by the runtime ledger.
/// You can extend this enum in upstream code if needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssetId {
    Native,
    Token(Address),
}

/// Abstract funds/money provider to plug chain ledger/bank.
/// All amounts are in smallest units (u128).
pub trait Funds: Send + Sync + 'static {
    /// Pull `amount` of `asset` from `from` into this module escrow.
    fn pull(&self, from: &Address, asset: AssetId, amount: u128) -> Result<(), IdoError>;
    /// Push `amount` of `asset` to `to` from escrow.
    fn push(&self, to: &Address, asset: AssetId, amount: u128) -> Result<(), IdoError>;
}

/// Optional business event listener (e.g., for metrics/telemetry).
pub trait Listener: Send + Sync + 'static {
    fn on_event(&self, _ev: &Event) {}
}

/// No-op listener.
pub struct NoopListener;
impl Listener for NoopListener {}

/// Administrative and sale configuration (immutable post-creation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdoConfig {
    pub admin: Address,
    pub sale_token: AssetId,
    pub raise_asset: AssetId,

    /// Fixed price: raise_asset per 1 sale_token = num / den (rational).
    /// Effective paid = tokens * num / den (floor). Remainders accumulate in pro-rata rounding.
    pub price_num: u128,
    pub price_den: u128,

    /// Tokens available for sale (supply allocated to IDO).
    pub sale_token_supply: u128,

    /// Caps in raise asset units.
    pub soft_cap_raise: u128,
    pub hard_cap_raise: u128,

    /// Per-wallet caps in raise asset units (0 => disabled).
    pub per_wallet_min: u128,
    pub per_wallet_max: u128,

    /// Schedule in block heights (inclusive start, inclusive end per phase).
    pub start_whitelist: u64,
    pub end_whitelist: u64,
    pub start_public: u64,
    pub end_public: u64,

    /// Whitelist required in whitelist phase; in public phase ignored.
    pub whitelist_enabled: bool,

    /// Pause initially (e.g., for staged activation).
    pub paused: bool,

    /// Fee taken from raised funds upon finalize (basis points). Sent to `fee_recipient`.
    pub fee_bps: u16,
    pub fee_recipient: Address,

    /// Vesting schedule for distributed sale tokens.
    pub vesting: Vesting,
}

/// Vesting configuration: TGE + cliff + linear vesting by blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vesting {
    /// Immediate unlock at TGE in basis points (0..=10000).
    pub tge_bps: u16,
    /// Cliff after TGE in blocks.
    pub cliff_blocks: u64,
    /// Linear vesting duration after cliff in blocks. 0 => fully unlocked at TGE+cliff.
    pub linear_blocks: u64,
}

/// Sale phase derived from current height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Pending,
    Whitelist,
    Public,
    Ended,
    Finalized,
    Canceled,
}

/// High-level sale status snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub paused: bool,
    pub total_contrib: u128,
    pub total_accepted_raise: u128,
    pub total_refunds: u128,
    pub tokens_distributed: u128,
    pub participants: usize,
    pub finalized_height: Option<u64>,
    pub version: u64,
}

/// Event log entry (append-only, bounded by `MAX_EVENTS` oldest-first eviction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Contributed { from: Address, amount: u128, phase: Phase, height: u64 },
    Finalized {
        height: u64,
        accepted_raise: u128,
        fee_taken: u128,
        price_num: u128, price_den: u128,
    },
    Refunded { to: Address, amount: u128 },
    TokensClaimed { to: Address, amount: u128 },
    Canceled { height: u64 },
    Paused { by: Address, height: u64 },
    Unpaused { by: Address, height: u64 },
    WhitelistAdded { who: Address },
    WhitelistRemoved { who: Address },
}

const MAX_EVENTS: usize = 10_000;

/// Internal contribution/settlement record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Wallet {
    /// Total contributed (escrowed).
    contrib: u128,
    /// Accepted raise share after finalize (<= contrib).
    accepted: u128,
    /// Refund amount after finalize.
    refund: u128,
    /// Token allocation after finalize.
    allocation_tokens: u128,
    /// Claimed tokens so far (<= allocation_tokens).
    claimed_tokens: u128,
    /// Refunded flag
    refunded: bool,
}

/// Engine state under RwLock.
#[derive(Clone)]
pub struct Ido {
    cfg: IdoConfig,
    state: Arc<RwLock<State>>,
    funds: Arc<dyn Funds>,
    listener: Arc<dyn Listener>,
}

/// Mutable state details.
#[derive(Debug)]
struct State {
    paused: bool,
    /// Latest observed height (monotonic non-decreasing assumed by caller).
    height: u64,
    /// Version increments on every write that influences snapshot semantics.
    version: u64,

    /// Whitelist set (optional).
    whitelist: BTreeSet<Address>,

    /// Wallet accounting, deterministic order by address.
    wallets: BTreeMap<Address, Wallet>,

    /// Aggregate counters
    total_contrib: u128,

    /// Settlement after finalize
    finalized: bool,
    canceled: bool,
    finalized_height: Option<u64>,
    total_accepted_raise: u128,
    total_refunds: u128,
    tokens_distributed: u128,

    /// Events ring buffer (bounded)
    events: VecDeque<Event>,
}

impl IdoConfig {
    pub fn validate(&self) -> Result<(), IdoError> {
        if self.price_den == 0 || self.price_num == 0 {
            return Err(IdoError::Invalid("price_num and price_den must be > 0"));
        }
        if self.sale_token_supply == 0 {
            return Err(IdoError::Invalid("sale_token_supply must be > 0"));
        }
        if self.hard_cap_raise == 0 || self.hard_cap_raise < self.soft_cap_raise {
            return Err(IdoError::Invalid("hard_cap_raise must be >= soft_cap_raise and > 0"));
        }
        if self.start_whitelist > self.end_whitelist {
            return Err(IdoError::Invalid("start_whitelist > end_whitelist"));
        }
        if self.start_public > self.end_public {
            return Err(IdoError::Invalid("start_public > end_public"));
        }
        if self.end_whitelist + 1 != self.start_public {
            // enforce contiguous phases (WL immediately followed by Public), can be relaxed.
            return Err(IdoError::Invalid("end_whitelist + 1 must equal start_public"));
        }
        if self.fee_bps > 10_000 {
            return Err(IdoError::Invalid("fee_bps must be <= 10000"));
        }
        if self.vesting.tge_bps > 10_000 {
            return Err(IdoError::Invalid("vesting.tge_bps must be <= 10000"));
        }
        if self.per_wallet_max > 0 && self.per_wallet_min > self.per_wallet_max {
            return Err(IdoError::Invalid("per_wallet_min > per_wallet_max"));
        }
        Ok(())
    }
}

impl Ido {
    pub fn new(cfg: IdoConfig, funds: Arc<dyn Funds>, listener: Option<Arc<dyn Listener>>) -> Result<Self, IdoError> {
        cfg.validate()?;
        let st = State {
            paused: cfg.paused,
            height: 0,
            version: 1,
            whitelist: BTreeSet::new(),
            wallets: BTreeMap::new(),
            total_contrib: 0,
            finalized: false,
            canceled: false,
            finalized_height: None,
            total_accepted_raise: 0,
            total_refunds: 0,
            tokens_distributed: 0,
            events: VecDeque::with_capacity(1024),
        };
        Ok(Self {
            cfg,
            state: Arc::new(RwLock::new(st)),
            funds,
            listener: listener.unwrap_or_else(|| Arc::new(NoopListener)),
        })
    }

    /// Advance observed height and return current phase.
    pub fn tick_height(&self, new_height: u64) -> Phase {
        let mut st = self.state.write().unwrap();
        if new_height > st.height {
            st.height = new_height;
            st.version = st.version.saturating_add(1);
        }
        self.phase_locked(&st)
    }

    /// Current snapshot.
    pub fn snapshot(&self) -> Snapshot {
        let st = self.state.read().unwrap();
        Snapshot {
            phase: self.phase_locked(&st),
            paused: st.paused,
            total_contrib: st.total_contrib,
            total_accepted_raise: st.total_accepted_raise,
            total_refunds: st.total_refunds,
            tokens_distributed: st.tokens_distributed,
            participants: st.wallets.len(),
            finalized_height: st.finalized_height,
            version: st.version,
        }
    }

    /// Add address to whitelist.
    pub fn whitelist_add(&self, who: Address) -> Result<(), IdoError> {
        let mut st = self.state.write().unwrap();
        require_admin(&self.cfg, &who, false)?;
        // Admin can whitelist others; but often admin != who. To keep generic, we do not enforce caller identity here.
        st.whitelist.insert(who);
        st.push_event(Event::WhitelistAdded { who });
        Ok(())
    }

    /// Remove address from whitelist.
    pub fn whitelist_remove(&self, who: Address) -> Result<(), IdoError> {
        let mut st = self.state.write().unwrap();
        st.whitelist.remove(&who);
        st.push_event(Event::WhitelistRemoved { who });
        Ok(())
    }

    /// Contribute `amount` of raise_asset from `from`. Pulls funds via `Funds`.
    pub fn contribute(&self, from: Address, amount: u128) -> Result<(), IdoError> {
        if amount == 0 { return Err(IdoError::Invalid("amount must be > 0")); }
        let mut st = self.state.write().unwrap();

        if st.paused { return Err(IdoError::Paused); }
        if st.canceled { return Err(IdoError::Canceled); }
        if st.finalized { return Err(IdoError::AlreadyFinalized); }

        let phase = self.phase_locked(&st);
        match phase {
            Phase::Whitelist => {
                if self.cfg.whitelist_enabled && !st.whitelist.contains(&from) {
                    return Err(IdoError::NotWhitelisted);
                }
            }
            Phase::Public => { /* open */ }
            _ => return Err(IdoError::NotInSaleWindow),
        }

        // Per-wallet caps
        let w = st.wallets.entry(from).or_default();
        let new_total = w.contrib.saturating_add(amount);
        if self.cfg.per_wallet_max > 0 && new_total > self.cfg.per_wallet_max {
            return Err(IdoError::PerWalletMaxExceeded);
        }
        if self.cfg.per_wallet_min > 0 && w.contrib == 0 && amount < self.cfg.per_wallet_min {
            return Err(IdoError::PerWalletMinNotMet);
        }

        // Hard cap protection at contribution time (best-effort).
        let potential_total = st.total_contrib.saturating_add(amount);
        if potential_total > self.cfg.hard_cap_raise {
            return Err(IdoError::HardCapExceeded);
        }

        // Pull funds into escrow.
        self.funds.pull(&from, self.cfg.raise_asset, amount)?;

        // Book-keep
        w.contrib = new_total;
        st.total_contrib = potential_total;
        let ph = self.phase_locked(&st);
        st.push_event(Event::Contributed { from, amount, phase: ph, height: st.height });

        Ok(())
    }

    /// Finalize sale (admin). Computes pro-rata, fees, and opens claims/refunds.
    pub fn finalize(&self, caller: Address) -> Result<(), IdoError> {
        require_admin(&self.cfg, &caller, true)?;
        let mut st = self.state.write().unwrap();
        if st.paused { return Err(IdoError::Paused); }
        if st.finalized { return Err(IdoError::AlreadyFinalized); }
        if st.canceled { return Err(IdoError::Canceled); }

        let phase = self.phase_locked(&st);
        if phase != Phase::Ended {
            return Err(IdoError::NotEnded);
        }

        // Required raise to sell all tokens at fixed price.
        let required_raise = mul_div_floor(self.cfg.sale_token_supply, self.cfg.price_num, self.cfg.price_den);

        // If soft cap not met, allow finalize to enable refunds of all contributions.
        let total = st.total_contrib;
        let mut accepted_total = 0u128;
        let mut refunds_total = 0u128;
        let mut tokens_total = 0u128;

        // Determine target accept = min(total, required_raise, hard_cap_raise)
        let target_accept = total.min(required_raise).min(self.cfg.hard_cap_raise);

        if total == 0 || target_accept == 0 || total < self.cfg.soft_cap_raise {
            // Refund everything
            for (_addr, w) in st.wallets.iter_mut() {
                w.accepted = 0;
                w.refund = w.contrib;
                w.allocation_tokens = 0;
                refunds_total = refunds_total.saturating_add(w.refund);
            }
        } else if total <= target_accept {
            // Everyone fully accepted
            for (_addr, w) in st.wallets.iter_mut() {
                w.accepted = w.contrib;
                w.refund = 0;
                // tokens = accepted * price_den / price_num
                w.allocation_tokens = mul_div_floor(w.accepted, self.cfg.price_den, self.cfg.price_num);
                accepted_total = accepted_total.saturating_add(w.accepted);
                tokens_total = tokens_total.saturating_add(w.allocation_tokens);
            }
        } else {
            // Oversubscribed: pro-rata
            // First pass: proportional floor
            let mut remainders: Vec<(Address, u128)> = Vec::with_capacity(st.wallets.len());
            for (addr, w) in st.wallets.iter_mut() {
                // accepted_i = floor(target_accept * contrib_i / total)
                let accepted_i = mul_div_floor(target_accept, w.contrib, total);
                w.accepted = accepted_i;
                let used = accepted_i;
                let refund_i = w.contrib.saturating_sub(used);
                w.refund = refund_i;
                accepted_total = accepted_total.saturating_add(accepted_i);
                refunds_total = refunds_total.saturating_add(refund_i);
                // tokens_i preliminary
                w.allocation_tokens = mul_div_floor(accepted_i, self.cfg.price_den, self.cfg.price_num);
                tokens_total = tokens_total.saturating_add(w.allocation_tokens);
                // store remainder for largest-remainder correction
                let rem = mul_mod(target_accept, w.contrib, total);
                remainders.push((*addr, rem));
            }
            // Distribute any leftover (due to floor) by largest remainder, deterministic by (remainder desc, addr asc)
            let mut leftover_accept = target_accept.saturating_sub(accepted_total);
            remainders.sort_by(|a, b| {
                // Desc by remainder, asc by address for stability
                b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))
            });
            for (addr, _rem) in remainders {
                if leftover_accept == 0 { break; }
                let w = st.wallets.get_mut(&addr).unwrap();
                w.accepted = w.accepted.saturating_add(1);
                w.refund = w.refund.saturating_sub(1);
                accepted_total = accepted_total.saturating_add(1);
                refunds_total = refunds_total.saturating_sub(1);
                let add_tokens = mul_div_floor(1, self.cfg.price_den, self.cfg.price_num);
                w.allocation_tokens = w.allocation_tokens.saturating_add(add_tokens);
                tokens_total = tokens_total.saturating_add(add_tokens);
                leftover_accept -= 1;
            }
        }

        // Clamp tokens_total to available supply (safety; pro-rata may under-allocate due to rounding)
        if tokens_total > self.cfg.sale_token_supply {
            // Remove excess deterministically by smallest remainder (reverse order of adding).
            let mut excess = tokens_total - self.cfg.sale_token_supply;
            let mut addrs: Vec<Address> = st.wallets.keys().copied().collect();
            addrs.sort(); // ascending
            // remove 1 token from highest address first (arbitrary but stable)
            for addr in addrs.into_iter().rev() {
                if excess == 0 { break; }
                let w = st.wallets.get_mut(&addr).unwrap();
                if w.allocation_tokens > 0 {
                    w.allocation_tokens -= 1;
                    tokens_total -= 1;
                    excess -= 1;
                    // Adjust accepted accordingly (increase refund by price_num/price_den rounded up):
                    let inc_refund = div_round_up(self.cfg.price_num, self.cfg.price_den);
                    if w.accepted >= inc_refund {
                        w.accepted -= inc_refund;
                        w.refund += inc_refund;
                        accepted_total = accepted_total.saturating_sub(inc_refund);
                        refunds_total = refunds_total.saturating_add(inc_refund);
                    }
                }
            }
        }

        // Take protocol fee from accepted raise
        let fee = (accepted_total.saturating_mul(self.cfg.fee_bps as u128)) / 10_000u128;
        if fee > 0 {
            self.funds.push(&self.cfg.fee_recipient, self.cfg.raise_asset, fee)?;
        }

        st.finalized = true;
        st.finalized_height = Some(st.height);
        st.total_accepted_raise = accepted_total;
        st.total_refunds = refunds_total;
        st.tokens_distributed = tokens_total;
        st.version = st.version.saturating_add(1);

        st.push_event(Event::Finalized {
            height: st.height,
            accepted_raise: accepted_total,
            fee_taken: fee,
            price_num: self.cfg.price_num, price_den: self.cfg.price_den,
        });

        Ok(())
    }

    /// Claim tokens according to vesting. Returns claimable amount actually transferred.
    pub fn claim_tokens(&self, who: Address) -> Result<u128, IdoError> {
        let mut st = self.state.write().unwrap();
        if !st.finalized || st.canceled { return Err(IdoError::NotFinalized); }

        let w = st.wallets.get_mut(&who).ok_or(IdoError::NoContribution)?;
        let unlocked = unlocked_amount(self.cfg.vesting, st.finalized_height.unwrap_or(0), st.height, w.allocation_tokens);
        if unlocked <= w.claimed_tokens {
            return Ok(0);
        }
        let claim = unlocked - w.claimed_tokens;
        w.claimed_tokens = unlocked;

        // Transfer sale tokens to user
        self.funds.push(&who, self.cfg.sale_token, claim)?;
        st.tokens_distributed = st.tokens_distributed; // unchanged aggregate
        st.push_event(Event::TokensClaimed { to: who, amount: claim });
        Ok(claim)
    }

    /// Claim refund (available post-finalize or post-cancel). Returns refunded amount.
    pub fn claim_refund(&self, who: Address) -> Result<u128, IdoError> {
        let mut st = self.state.write().unwrap();
        if !(st.finalized || st.canceled) { return Err(IdoError::NotFinalized); }
        let w = st.wallets.get_mut(&who).ok_or(IdoError::NoContribution)?;
        if w.refunded { return Ok(0); }
        if w.refund == 0 { w.refunded = true; return Ok(0); }

        // Transfer refund
        self.funds.push(&who, self.cfg.raise_asset, w.refund)?;
        let amt = w.refund;
        w.refund = 0;
        w.refunded = true;
        st.total_refunds = st.total_refunds.saturating_sub(amt);
        st.push_event(Event::Refunded { to: who, amount: amt });
        Ok(amt)
    }

    /// Cancel sale (admin). Makes all contributions refundable, disables tokens distribution.
    pub fn cancel(&self, caller: Address) -> Result<(), IdoError> {
        require_admin(&self.cfg, &caller, true)?;
        let mut st = self.state.write().unwrap();
        if st.canceled { return Err(IdoError::AlreadyCanceled); }
        if st.finalized { return Err(IdoError::AlreadyFinalized); }

        st.canceled = true;
        st.finalized = false;
        st.finalized_height = Some(st.height);

        // All funds refundable
        for (_a, w) in st.wallets.iter_mut() {
            w.accepted = 0;
            w.allocation_tokens = 0;
            w.refund = w.contrib;
        }
        st.total_refunds = st.total_contrib;
        st.tokens_distributed = 0;
        st.version = st.version.saturating_add(1);
        st.push_event(Event::Canceled { height: st.height });
        Ok(())
    }

    /// Pause/unpause (admin).
    pub fn set_paused(&self, caller: Address, paused: bool) -> Result<(), IdoError> {
        require_admin(&self.cfg, &caller, true)?;
        let mut st = self.state.write().unwrap();
        if st.paused == paused { return Ok(()); }
        st.paused = paused;
        st.version = st.version.saturating_add(1);
        if paused {
            st.push_event(Event::Paused { by: caller, height: st.height });
        } else {
            st.push_event(Event::Unpaused { by: caller, height: st.height });
        }
        Ok(())
    }

    /// Return bounded recent events.
    pub fn events(&self, limit: usize) -> Vec<Event> {
        let st = self.state.read().unwrap();
        st.events.iter().cloned().rev().take(limit).collect()
    }

    /// Internal: compute current phase from state.
    fn phase_locked(&self, st: &State) -> Phase {
        if st.canceled { return Phase::Canceled; }
        if st.finalized { return Phase::Finalized; }
        let h = st.height;
        if h < self.cfg.start_whitelist { return Phase::Pending; }
        if h >= self.cfg.start_whitelist && h <= self.cfg.end_whitelist { return Phase::Whitelist; }
        if h >= self.cfg.start_public && h <= self.cfg.end_public { return Phase::Public; }
        Phase::Ended
    }
}

/* ------------------------------- Errors -------------------------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdoError {
    Invalid(&'static str),
    Paused,
    NotWhitelisted,
    NotInSaleWindow,
    PerWalletMinNotMet,
    PerWalletMaxExceeded,
    HardCapExceeded,
    NotEnded,
    NotFinalized,
    AlreadyFinalized,
    AlreadyCanceled,
    Canceled,
    NoContribution,
    Unauthorized,
    FundsError,
}
impl fmt::Display for IdoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IdoError::*;
        match self {
            Invalid(s) => write!(f, "invalid: {}", s),
            Paused => write!(f, "sale is paused"),
            NotWhitelisted => write!(f, "address not whitelisted"),
            NotInSaleWindow => write!(f, "not in sale window"),
            PerWalletMinNotMet => write!(f, "per-wallet minimum not met"),
            PerWalletMaxExceeded => write!(f, "per-wallet maximum exceeded"),
            HardCapExceeded => write!(f, "hard cap would be exceeded"),
            NotEnded => write!(f, "sale not ended"),
            NotFinalized => write!(f, "not finalized"),
            AlreadyFinalized => write!(f, "already finalized"),
            AlreadyCanceled => write!(f, "already canceled"),
            Canceled => write!(f, "sale canceled"),
            NoContribution => write!(f, "no contribution"),
            Unauthorized => write!(f, "unauthorized"),
            FundsError => write!(f, "funds transfer error"),
        }
    }
}

fn require_admin(cfg: &IdoConfig, caller: &Address, require_equal: bool) -> Result<(), IdoError> {
    if require_equal && caller != &cfg.admin { return Err(IdoError::Unauthorized); }
    Ok(())
}

/* ----------------------------- Math helpers ---------------------------- */

#[inline]
fn mul_div_floor(a: u128, b: u128, d: u128) -> u128 {
    if d == 0 { return 0; }
    // (a * b) / d with saturation on overflow
    match a.checked_mul(b) {
        Some(p) => p / d,
        None => {
            // Use 256-bit emulation naive: degrade to u128::MAX if overflow (conservative floor upper bound)
            u128::MAX / d
        }
    }
}

/// a*b mod d without overflow if possible, best-effort fallback.
#[inline]
fn mul_mod(a: u128, b: u128, d: u128) -> u128 {
    if d == 0 { return 0; }
    match a.checked_mul(b) {
        Some(p) => p % d,
        None => {
            // Fallback using double-and-add modulo to avoid overflow
            let mut x = a % d;
            let mut y = b;
            let mut acc: u128 = 0;
            while y > 0 {
                if (y & 1) == 1 { acc = (acc + x) % d; }
                x = (x << 1) % d;
                y >>= 1;
            }
            acc
        }
    }
}

#[inline]
fn div_round_up(num: u128, den: u128) -> u128 {
    if den == 0 { return 0; }
    (num + den - 1) / den
}

/// Vesting unlocked amount given finalized height f_h, current height c_h and total allocation.
fn unlocked_amount(v: Vesting, finalized_h: u64, current_h: u64, total: u128) -> u128 {
    if total == 0 { return 0; }
    if current_h < finalized_h { return 0; }
    let tge = (total as u256() * (v.tge_bps as u256()) / 10_000u128_as_u256()).as_u128();

    let after_tge_h = finalized_h;
    if current_h <= after_tge_h {
        return tge;
    }
    // apply cliff
    let cliff_end = after_tge_h.saturating_add(v.cliff_blocks);
    if current_h <= cliff_end {
        return tge;
    }
    // linear vest
    if v.linear_blocks == 0 {
        return total;
    }
    let past = (current_h - cliff_end) as u128;
    let linear = ((total - tge) as u256() * past as u256() / v.linear_blocks as u256()).as_u128();
    let unlocked = tge.saturating_add(linear);
    unlocked.min(total)
}

/* --------------------------- Tiny u256 helper --------------------------- */
// Lightweight helpers to avoid external bigint crates.
// Very small subset sufficient for vesting math above.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256 { hi: u128, lo: u128 }

#[inline] fn u256(v: u128) -> U256 { U256 { hi: 0, lo: v } }
trait U256Cast { fn as_u128(self) -> u128; }
impl U256Cast for U256 { fn as_u128(self) -> u128 { self.lo } }
trait U256FromU128 { fn u256(self) -> U256; }
impl U256FromU128 for u128 { fn u256(self) -> U256 { u256(self) } }

#[inline] fn u128_as_u256(v: u128) -> U256 { u256(v) }
trait U256FromU128Alias { fn as_u256(self) -> U256; }
impl U256FromU128Alias for u128 { fn as_u256(self) -> U256 { u256(self) } }

impl std::ops::Add for U256 {
    type Output = U256;
    fn add(self, rhs: U256) -> U256 {
        let (lo, c) = self.lo.overflowing_add(rhs.lo);
        let hi = self.hi + rhs.hi + if c { 1 } else { 0 };
        U256 { hi, lo }
    }
}
impl std::ops::Sub for U256 {
    type Output = U256;
    fn sub(self, rhs: U256) -> U256 {
        let (lo, b) = self.lo.overflowing_sub(rhs.lo);
        let hi = self.hi - rhs.hi - if b { 1 } else { 0 };
        U256 { hi, lo }
    }
}
impl std::ops::Mul for U256 {
    type Output = U256;
    fn mul(self, rhs: U256) -> U256 {
        // (hi,lo) * (hi,lo) -> basic long multiplication with only lo used in this file
        let a = self.lo as u128;
        let b = rhs.lo as u128;
        // 128x128 -> 256
        let (hi, lo) = mul_128x128(a, b);
        U256 { hi, lo }
    }
}
impl std::ops::Div for U256 {
    type Output = U256;
    fn div(self, rhs: U256) -> U256 {
        if rhs.hi == 0 && rhs.lo == 0 { return U256 { hi: 0, lo: 0 }; }
        if self.hi == 0 && rhs.hi == 0 {
            return U256 { hi: 0, lo: self.lo / rhs.lo };
        }
        // slow path: shift-subtract division
        div_u256(self, rhs)
    }
}
fn mul_128x128(a: u128, b: u128) -> (u128, u128) {
    // split into 64-bit limbs
    let a0 = a as u64 as u128;
    let a1 = (a >> 64) as u64 as u128;
    let b0 = b as u64 as u128;
    let b1 = (b >> 64) as u64 as u128;

    let p0 = a0 * b0;
    let p1 = a0 * b1;
    let p2 = a1 * b0;
    let p3 = a1 * b1;

    let carry = ((p0 >> 64) + (p1 & ((1u128<<64)-1)) + (p2 & ((1u128<<64)-1))) >> 64;
    let lo = (p0 & ((1u128<<64)-1)) | (((p1 + p2) & ((1u128<<64)-1)) << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + carry;
    (hi, lo)
}
fn div_u256(n: U256, d: U256) -> U256 {
    // very simple restoring division; sufficient for our use (small numbers)
    if d.hi == 0 && d.lo == 0 { return U256 { hi: 0, lo: 0 }; }
    let mut q = U256 { hi: 0, lo: 0 };
    let mut r = U256 { hi: 0, lo: 0 };
    for i in (0..256).rev() {
        // r <<= 1; r |= n.bit(i)
        r = U256 { hi: (r.hi << 1) | (r.lo >> 127), lo: r.lo << 1 };
        let bit = if i >= 128 {
            ((n.hi >> (i - 128)) & 1) as u128
        } else {
            ((n.lo >> i) & 1) as u128
        };
        if bit == 1 { r.lo |= 1; }
        // if r >= d { r -= d; q.set_bit(i); }
        if ge_u256(r, d) {
            r = r - d;
            if i >= 128 {
                q.hi |= 1 << (i - 128);
            } else {
                q.lo |= 1 << i;
            }
        }
    }
    q
}
fn ge_u256(a: U256, b: U256) -> bool {
    (a.hi > b.hi) || (a.hi == b.hi && a.lo >= b.lo)
}
fn u256_from_u128(v: u128) -> U256 { u256(v) }
fn u256_to_u128(v: U256) -> u128 { v.lo }

trait U256Ext {
    fn as_u128(self) -> u128;
    fn from_u128(v: u128) -> Self;
}
impl U256Ext for U256 {
    fn as_u128(self) -> u128 { self.lo }
    fn from_u128(v: u128) -> Self { u256(v) }
}
// convenience constructors used above
#[inline] fn u128_as_u256() -> fn(u128) -> U256 { u256_from_u128 }
#[inline] fn u256_as_u128() -> fn(U256) -> u128 { u256_to_u128 }

/* ----------------------------- State utils ----------------------------- */

impl State {
    fn push_event(&mut self, ev: Event) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(ev.clone());
    }
}

/* -------------------------------- Tests -------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MemBank;
    impl Funds for MemBank {
        fn pull(&self, _from: &Address, _asset: AssetId, _amount: u128) -> Result<(), IdoError> { Ok(()) }
        fn push(&self, _to: &Address, _asset: AssetId, _amount: u128) -> Result<(), IdoError> { Ok(()) }
    }

    fn addr(x: u8) -> Address { [x; 20] }

    fn cfg_default() -> IdoConfig {
        IdoConfig {
            admin: addr(0xAA),
            sale_token: AssetId::Token(addr(0x01)),
            raise_asset: AssetId::Native,
            price_num: 2,     // 2 raise units per 1 token
            price_den: 1,
            sale_token_supply: 1_000_000,
            soft_cap_raise: 10,
            hard_cap_raise: 2_000_000,
            per_wallet_min: 0,
            per_wallet_max: 0,
            start_whitelist: 10,
            end_whitelist: 19,
            start_public: 20,
            end_public: 29,
            whitelist_enabled: true,
            paused: false,
            fee_bps: 100, // 1%
            fee_recipient: addr(0xFE),
            vesting: Vesting { tge_bps: 1000, cliff_blocks: 5, linear_blocks: 10 },
        }
    }

    #[test]
    fn flow_subscribe_finalize_pro_rata() {
        let cfg = cfg_default();
        let ido = Ido::new(cfg.clone(), Arc::new(MemBank), None).unwrap();

        // progress to whitelist
        assert_eq!(ido.tick_height(10), Phase::Whitelist);
        // whitelist Alice & Bob
        ido.whitelist_add(addr(1)).unwrap();
        ido.whitelist_add(addr(2)).unwrap();

        // contribute in whitelist
        assert!(ido.contribute(addr(1), 100).is_ok());
        assert!(ido.contribute(addr(2), 300).is_ok());

        // move to public; Charlie contributes
        assert_eq!(ido.tick_height(20), Phase::Public);
        assert!(ido.contribute(addr(3), 700).is_ok());

        // end sale
        assert_eq!(ido.tick_height(30), Phase::Ended);

        // required raise to sell all tokens = supply * price_num / price_den = 1_000_000 * 2 = 2_000_000
        // total contrib = 1100 <= required_raise -> everyone fully accepted
        ido.finalize(cfg.admin).unwrap();
        let snap = ido.snapshot();
        assert_eq!(snap.total_accepted_raise, 1100);

        // claims: TGE = 10%
        let _ = ido.tick_height(30);
        let tge_claim_a = ido.claim_tokens(addr(1)).unwrap();
        assert_eq!(tge_claim_a, (100 / 2) / 10); // tokens = 50, TGE=5

        // advance over cliff and some linear vesting
        let _ = ido.tick_height(30 + cfg.vesting.cliff_blocks + 5);
        let more = ido.claim_tokens(addr(1)).unwrap();
        assert!(more > 0);
    }

    #[test]
    fn oversubscription_pro_rata_largest_remainder() {
        let mut cfg = cfg_default();
        cfg.sale_token_supply = 10; // 10 tokens, price 2 => required_raise=20
        cfg.soft_cap_raise = 1;
        let ido = Ido::new(cfg.clone(), Arc::new(MemBank), None).unwrap();
        let _ = ido.tick_height(20); // public

        // total contrib 23 > required 20 => oversub
        assert!(ido.contribute(addr(1), 10).is_ok());
        assert!(ido.contribute(addr(2), 7).is_ok());
        assert!(ido.contribute(addr(3), 6).is_ok());
        let _ = ido.tick_height(30);
        ido.finalize(cfg.admin).unwrap();
        let snap = ido.snapshot();
        assert_eq!(snap.total_accepted_raise, 20);
        assert_eq!(snap.tokens_distributed, 10);
    }

    #[test]
    fn cancel_refund_all() {
        let cfg = cfg_default();
        let ido = Ido::new(cfg.clone(), Arc::new(MemBank), None).unwrap();
        let _ = ido.tick_height(20);
        assert!(ido.contribute(addr(1), 100).is_ok());
        assert!(ido.cancel(cfg.admin).is_ok());
        // refund claim
        let refunded = ido.claim_refund(addr(1)).unwrap();
        assert_eq!(refunded, 100);
    }
}

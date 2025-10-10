//! Aethernova Launchpad — industrial-grade core
//! Features:
//! - Project lifecycle: create -> contribute -> finalize(success/failed) -> claim or refund
//! - Caps and limits: soft_cap/hard_cap, per-address min/max, whitelist-only mode
//! - Single payment asset per project with rational price (payment_per_token = num/den)
//! - Vesting: TGE (bps) + cliff + linear vesting; claimable = unlocked - claimed
//! - Safety: checked arithmetic, saturating guards, pause switch, blacklist
//! - Concurrency: parking_lot RwLock + per-project execute mutex
//! - Events: tokio::broadcast
//! - Tests: mock backend with time and balances
//!
//! Notes:
//! - Address/Asset/Balance are placeholders; integrate with chain primitives in your node.
//! - Backend trait abstracts asset transfers and token delivery.
//!
//! (c) Aethernova

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]

use parking_lot::{Mutex, RwLock};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    sync::Arc,
    time::SystemTime,
};
use thiserror::Error;
use tokio::sync::broadcast;

// ---------- Primitives ----------

/// 20-byte address placeholder; replace with chain primitive.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub [u8; 20]);

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Asset identifier (payment or token to distribute).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AssetId(pub u32);

/// Smallest unit balance.
pub type Balance = u128;

/// Project identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ProjectId(pub u64);

// ---------- Backend abstraction ----------

/// Backend for value transfer and time.
/// All monetary side-effects go through this trait.
pub trait LaunchpadBackend: Send + Sync + 'static {
    /// Current UNIX time (seconds).
    fn now_unix(&self) -> u64;

    /// Treasury where payments accumulate.
    fn treasury_address(&self) -> Address;

    /// Pull payment from buyer to treasury (escrow on finalize).
    fn transfer_payment_from(
        &self,
        payer: Address,
        asset: AssetId,
        to_treasury: Address,
        amount: Balance,
    ) -> Result<(), BackendError>;

    /// Refund payment from treasury back to buyer.
    fn refund_payment(
        &self,
        to_buyer: Address,
        asset: AssetId,
        amount: Balance,
    ) -> Result<(), BackendError>;

    /// Deliver purchased tokens to beneficiary (on claim).
    fn deliver_tokens(
        &self,
        token_asset: AssetId,
        to: Address,
        amount: Balance,
    ) -> Result<(), BackendError>;

    /// Optional hooks.
    fn on_project_finalized(&self, _project: ProjectId, _success: bool) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("insufficient balance")]
    Insufficient,
    #[error("asset not supported")]
    UnsupportedAsset,
    #[error("backend failure: {0}")]
    Other(String),
}

// ---------- Config and state ----------

/// Price defined as payment_per_token = num/den (both in smallest units).
/// payment = tokens * num / den; tokens = payment * den / num (floored).
#[derive(Clone, Copy, Debug)]
pub struct Price {
    pub num: Balance,
    pub den: Balance,
}

impl Price {
    pub fn new(num: Balance, den: Balance) -> Result<Self, LaunchpadError> {
        if num == 0 || den == 0 {
            return Err(LaunchpadError::InvalidConfig("price num/den must be > 0".into()));
        }
        Ok(Self { num, den })
    }
}

/// Vesting schedule in basis points (1% = 100 bps, 100% = 10000 bps).
#[derive(Clone, Copy, Debug)]
pub struct Vesting {
    pub tge_bps: u16,        // unlocked at TGE time (project end_ts)
    pub cliff_seconds: u64,  // delay after TGE before linear vest starts
    pub vest_seconds: u64,   // linear vest duration after cliff
}

impl Vesting {
    pub fn validate(&self) -> Result<(), LaunchpadError> {
        if self.tge_bps > 10_000 {
            return Err(LaunchpadError::InvalidConfig("tge_bps > 10000".into()));
        }
        Ok(())
    }
}

/// Core sale parameters.
#[derive(Clone, Debug)]
pub struct SaleConfig {
    pub payment_asset: AssetId,
    pub sold_token: AssetId,
    pub price: Price, // payment_per_token = num/den
    pub start_ts: u64,
    pub end_ts: u64,
    pub whitelist_only: bool,
    pub soft_cap_payment: Balance,
    pub hard_cap_payment: Balance,
    pub min_contribution: Balance,
    pub max_contribution: Balance,
    pub vesting: Vesting,
}

impl SaleConfig {
    pub fn validate(&self) -> Result<(), LaunchpadError> {
        if self.end_ts <= self.start_ts {
            return Err(LaunchpadError::InvalidConfig("end_ts <= start_ts".into()));
        }
        if self.soft_cap_payment == 0 || self.hard_cap_payment == 0 {
            return Err(LaunchpadError::InvalidConfig("caps must be > 0".into()));
        }
        if self.soft_cap_payment > self.hard_cap_payment {
            return Err(LaunchpadError::InvalidConfig("soft cap > hard cap".into()));
        }
        if self.min_contribution > self.max_contribution && self.max_contribution != 0 {
            return Err(LaunchpadError::InvalidConfig("min > max".into()));
        }
        self.vesting.validate()?;
        Ok(())
    }
}

/// Project status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectStatus {
    Pending,
    Active,
    FinalizedSuccess,
    FinalizedFailed,
    Canceled,
}

/// Contribution record and purchased tokens per user.
#[derive(Clone, Copy, Debug, Default)]
pub struct LedgerEntry {
    pub paid: Balance,
    pub purchased: Balance, // in sold_token units
    pub claimed: Balance,   // in sold_token units
}

/// Project state.
#[derive(Clone, Debug)]
pub struct Project {
    pub id: ProjectId,
    pub owner: Address,
    pub config: SaleConfig,
    pub status: ProjectStatus,
    pub created_at: u64,
    pub paused: bool,
    pub collected_payment: Balance,
    pub whitelisted: BTreeSet<Address>,
    pub blacklist: BTreeSet<Address>,
    pub ledger: HashMap<Address, LedgerEntry>,
}

impl Project {
    fn new(id: ProjectId, owner: Address, cfg: SaleConfig, now: u64) -> Self {
        Self {
            id,
            owner,
            config: cfg,
            status: ProjectStatus::Pending,
            created_at: now,
            paused: false,
            collected_payment: 0,
            whitelisted: BTreeSet::new(),
            blacklist: BTreeSet::new(),
            ledger: HashMap::new(),
        }
    }
}

// ---------- Events ----------

#[derive(Clone, Debug)]
pub enum LaunchpadEvent {
    ProjectCreated(ProjectId),
    ProjectActivated(ProjectId),
    ProjectFinalized { id: ProjectId, success: bool },
    ProjectCanceled(ProjectId),
    Contributed { id: ProjectId, buyer: Address, paid: Balance, accepted: Balance, purchased: Balance },
    Refunded { id: ProjectId, buyer: Address, amount: Balance },
    Claimed { id: ProjectId, beneficiary: Address, amount: Balance },
    Paused { id: ProjectId, paused: bool },
    WhitelistUpdated { id: ProjectId, addr: Address, added: bool },
    BlacklistUpdated { id: ProjectId, addr: Address, banned: bool },
}

// ---------- Errors ----------

#[derive(Error, Debug)]
pub enum LaunchpadError {
    #[error("not authorized")]
    NotAuthorized,
    #[error("project not found")]
    NotFound,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("sale is paused")]
    Paused,
    #[error("sale not started")]
    NotStarted,
    #[error("sale ended")]
    Ended,
    #[error("whitelist only")]
    WhitelistOnly,
    #[error("blacklisted")]
    Blacklisted,
    #[error("amount must be > 0")]
    ZeroAmount,
    #[error("per-address limit violation")]
    AddressLimit,
    #[error("hard cap exceeded")]
    HardCapExceeded,
    #[error("soft cap not met")]
    SoftCapNotMet,
    #[error("nothing to claim")]
    NothingToClaim,
    #[error("nothing to refund")]
    NothingToRefund,
    #[error("arithmetic overflow")]
    MathOverflow,
    #[error("backend: {0}")]
    Backend(#[from] BackendError),
}

// ---------- Launchpad core ----------

pub struct Launchpad<B: LaunchpadBackend> {
    backend: Arc<B>,
    next_id: RwLock<u64>,
    projects: RwLock<BTreeMap<ProjectId, Arc<ProjectLock>>>,
    events_tx: broadcast::Sender<LaunchpadEvent>,
}

/// Per-project lock + state container.
struct ProjectLock {
    exec: Mutex<()>,
    state: RwLock<Project>,
}

impl<B: LaunchpadBackend> fmt::Debug for Launchpad<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Launchpad")
            .field("projects", &self.projects.read().len())
            .finish()
    }
}

impl<B: LaunchpadBackend> Launchpad<B> {
    pub fn new(backend: Arc<B>, event_capacity: usize) -> Arc<Self> {
        let (tx, _) = broadcast::channel(event_capacity);
        Arc::new(Self {
            backend,
            next_id: RwLock::new(1),
            projects: RwLock::new(BTreeMap::new()),
            events_tx: tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LaunchpadEvent> {
        self.events_tx.subscribe()
    }

    fn now(&self) -> u64 {
        self.backend.now_unix()
    }

    fn is_owner(&self, p: &Project, who: Address) -> bool {
        p.owner == who
    }

    pub fn create_project(&self, owner: Address, cfg: SaleConfig) -> Result<ProjectId, LaunchpadError> {
        cfg.validate()?;
        let mut g = self.next_id.write();
        let id = ProjectId(*g);
        *g = g.saturating_add(1);

        let now = self.now();
        let p = Project::new(id, owner, cfg, now);
        let lock = Arc::new(ProjectLock { exec: Mutex::new(()), state: RwLock::new(p) });
        self.projects.write().insert(id, lock);
        let _ = self.events_tx.send(LaunchpadEvent::ProjectCreated(id));
        Ok(id)
    }

    pub fn set_pause(&self, caller: Address, id: ProjectId, paused: bool) -> Result<(), LaunchpadError> {
        let pl = self.project_lock(id)?;
        let mut p = pl.state.write();
        if !self.is_owner(&p, caller) {
            return Err(LaunchpadError::NotAuthorized);
        }
        p.paused = paused;
        let _ = self.events_tx.send(LaunchpadEvent::Paused { id, paused });
        Ok(())
    }

    pub fn activate(&self, caller: Address, id: ProjectId) -> Result<(), LaunchpadError> {
        let pl = self.project_lock(id)?;
        let mut p = pl.state.write();
        if !self.is_owner(&p, caller) {
            return Err(LaunchpadError::NotAuthorized);
        }
        if p.status != ProjectStatus::Pending {
            return Err(LaunchpadError::InvalidState("not pending".into()));
        }
        p.status = ProjectStatus::Active;
        let _ = self.events_tx.send(LaunchpadEvent::ProjectActivated(id));
        Ok(())
    }

    pub fn cancel(&self, caller: Address, id: ProjectId) -> Result<(), LaunchpadError> {
        let pl = self.project_lock(id)?;
        let mut p = pl.state.write();
        if !self.is_owner(&p, caller) {
            return Err(LaunchpadError::NotAuthorized);
        }
        if matches!(p.status, ProjectStatus::FinalizedSuccess | ProjectStatus::FinalizedFailed) {
            return Err(LaunchpadError::InvalidState("already finalized".into()));
        }
        p.status = ProjectStatus::Canceled;
        let _ = self.events_tx.send(LaunchpadEvent::ProjectCanceled(id));
        Ok(())
    }

    pub fn set_whitelist(&self, caller: Address, id: ProjectId, addr: Address, added: bool) -> Result<(), LaunchpadError> {
        let pl = self.project_lock(id)?;
        let mut p = pl.state.write();
        if !self.is_owner(&p, caller) {
            return Err(LaunchpadError::NotAuthorized);
        }
        if added { p.whitelisted.insert(addr); } else { p.whitelisted.remove(&addr); }
        let _ = self.events_tx.send(LaunchpadEvent::WhitelistUpdated { id, addr, added });
        Ok(())
    }

    pub fn set_blacklist(&self, caller: Address, id: ProjectId, addr: Address, banned: bool) -> Result<(), LaunchpadError> {
        let pl = self.project_lock(id)?;
        let mut p = pl.state.write();
        if !self.is_owner(&p, caller) {
            return Err(LaunchpadError::NotAuthorized);
        }
        if banned { p.blacklist.insert(addr); } else { p.blacklist.remove(&addr); }
        let _ = self.events_tx.send(LaunchpadEvent::BlacklistUpdated { id, addr, banned });
        Ok(())
    }

    /// Contribute payment to a sale. Accepts partial if amount exceeds remaining hard cap.
    /// Returns (accepted_payment, purchased_tokens).
    pub fn contribute(
        &self,
        buyer: Address,
        id: ProjectId,
        amount_payment: Balance,
    ) -> Result<(Balance, Balance), LaunchpadError> {
        if amount_payment == 0 {
            return Err(LaunchpadError::ZeroAmount);
        }
        let pl = self.project_lock(id)?;
        let _ex = pl.exec.lock(); // serialize accepts
        let mut p = pl.state.write();

        if p.paused {
            return Err(LaunchpadError::Paused);
        }
        if p.blacklist.contains(&buyer) {
            return Err(LaunchpadError::Blacklisted);
        }
        if p.status != ProjectStatus::Active {
            return Err(LaunchpadError::InvalidState("project not active".into()));
        }
        let now = self.now();
        if now < p.config.start_ts {
            return Err(LaunchpadError::NotStarted);
        }
        if now >= p.config.end_ts {
            return Err(LaunchpadError::Ended);
        }
        if p.config.whitelist_only && !p.whitelisted.contains(&buyer) {
            return Err(LaunchpadError::WhitelistOnly);
        }

        let remaining = p.config.hard_cap_payment.saturating_sub(p.collected_payment);
        if remaining == 0 {
            return Err(LaunchpadError::HardCapExceeded);
        }
        let accepted = amount_payment.min(remaining);

        // Per-address min/max check on total contributed by this address.
        let entry = p.ledger.entry(buyer).or_default();
        let new_total = entry.paid.saturating_add(accepted);

        if p.config.max_contribution != 0 && new_total > p.config.max_contribution {
            return Err(LaunchpadError::AddressLimit);
        }
        // Enforce min contribution per-address at first contribution only.
        if entry.paid == 0 && p.config.min_contribution != 0 && accepted < p.config.min_contribution {
            return Err(LaunchpadError::AddressLimit);
        }

        // Pull funds into treasury.
        let treasury = self.backend.treasury_address();
        self.backend
            .transfer_payment_from(buyer, p.config.payment_asset, treasury, accepted)?;

        // Compute purchased tokens at fixed price.
        // tokens = payment * den / num (floored)
        let purchased = mul_div_u128(accepted, p.config.price.den, p.config.price.num)
            .ok_or(LaunchpadError::MathOverflow)?;

        entry.paid = new_total;
        entry.purchased = entry.purchased.saturating_add(purchased);
        p.collected_payment = p.collected_payment.saturating_add(accepted);

        let _ = self.events_tx.send(LaunchpadEvent::Contributed {
            id,
            buyer,
            paid: amount_payment,
            accepted,
            purchased,
        });

        Ok((accepted, purchased))
    }

    /// Finalize a project after sale end. Success if soft cap met.
    pub fn finalize(&self, caller: Address, id: ProjectId) -> Result<bool, LaunchpadError> {
        let pl = self.project_lock(id)?;
        let _ex = pl.exec.lock();
        let mut p = pl.state.write();

        if !self.is_owner(&p, caller) {
            return Err(LaunchpadError::NotAuthorized);
        }
        if p.status != ProjectStatus::Active {
            return Err(LaunchpadError::InvalidState("not active".into()));
        }
        let now = self.now();
        if now < p.config.end_ts {
            return Err(LaunchpadError::InvalidState("sale not ended".into()));
        }

        let success = p.collected_payment >= p.config.soft_cap_payment;
        p.status = if success {
            ProjectStatus::FinalizedSuccess
        } else {
            ProjectStatus::FinalizedFailed
        };
        let _ = self.events_tx.send(LaunchpadEvent::ProjectFinalized { id, success });
        self.backend.on_project_finalized(id, success)?;
        Ok(success)
    }

    /// Claim vested tokens. Available only after success finalization.
    pub fn claim(&self, beneficiary: Address, id: ProjectId) -> Result<Balance, LaunchpadError> {
        let pl = self.project_lock(id)?;
        let _ex = pl.exec.lock();
        let mut p = pl.state.write();

        if p.status != ProjectStatus::FinalizedSuccess {
            return Err(LaunchpadError::InvalidState("not finalized success".into()));
        }
        let entry = p.ledger.get_mut(&beneficiary).ok_or(LaunchpadError::NothingToClaim)?;

        let unlocked_bps = self.unlocked_bps(&p);
        let unlocked_total = mul_div_u128(entry.purchased, unlocked_bps as u128, 10_000)
            .ok_or(LaunchpadError::MathOverflow)?;
        let claimable = unlocked_total.saturating_sub(entry.claimed);
        if claimable == 0 {
            return Err(LaunchpadError::NothingToClaim);
        }

        self.backend
            .deliver_tokens(p.config.sold_token, beneficiary, claimable)?;

        entry.claimed = entry.claimed.saturating_add(claimable);
        let _ = self.events_tx.send(LaunchpadEvent::Claimed { id, beneficiary, amount: claimable });
        Ok(claimable)
    }

    /// Refund full payment if sale failed or was canceled.
    pub fn refund(&self, buyer: Address, id: ProjectId) -> Result<Balance, LaunchpadError> {
        let pl = self.project_lock(id)?;
        let _ex = pl.exec.lock();
        let mut p = pl.state.write();

        match p.status {
            ProjectStatus::FinalizedFailed | ProjectStatus::Canceled => {}
            _ => return Err(LaunchpadError::InvalidState("refund not allowed".into())),
        }
        let entry = p.ledger.get_mut(&buyer).ok_or(LaunchpadError::NothingToRefund)?;
        if entry.paid == 0 {
            return Err(LaunchpadError::NothingToRefund);
        }

        let amt = entry.paid;
        entry.paid = 0;
        entry.purchased = 0;
        entry.claimed = 0;

        self.backend
            .refund_payment(buyer, p.config.payment_asset, amt)?;

        let _ = self.events_tx.send(LaunchpadEvent::Refunded { id, buyer, amount: amt });
        Ok(amt)
    }

    /// Read-only snapshot of project state.
    pub fn snapshot(&self, id: ProjectId) -> Result<Project, LaunchpadError> {
        let pl = self.project_lock(id)?;
        Ok(pl.state.read().clone())
    }

    fn unlocked_bps(&self, p: &Project) -> u16 {
        // Timeline:
        // tge = end_ts
        // If now < end_ts: 0
        // [end, end+cliff): tge_bps
        // [end+cliff, end+cliff+vest): tge_bps + linear remainder
        // >= end+cliff+vest: 10000
        let now = self.now();
        let end = p.config.end_ts;
        let v = p.config.vesting;

        if now < end {
            return 0;
        }
        if v.vest_seconds == 0 {
            return 10_000; // immediate if vest duration is zero
        }

        let tge = v.tge_bps.min(10_000);
        if now < end.saturating_add(v.cliff_seconds) {
            return tge;
        }
        let vest_end = end.saturating_add(v.cliff_seconds).saturating_add(v.vest_seconds);
        if now >= vest_end {
            return 10_000;
        }
        let elapsed = now.saturating_sub(end.saturating_add(v.cliff_seconds));
        // linear fraction of remainder
        let remainder = 10_000u64.saturating_sub(tge as u64);
        let linear = remainder.saturating_mul(elapsed).saturating_div(v.vest_seconds);
        (tge as u64 + linear).min(10_000) as u16
    }

    fn project_lock(&self, id: ProjectId) -> Result<Arc<ProjectLock>, LaunchpadError> {
        self.projects
            .read()
            .get(&id)
            .cloned()
            .ok_or(LaunchpadError::NotFound)
    }
}

// ---------- Math helpers ----------

/// Compute (a * b) / d with checked u128 arithmetic; returns None on overflow or d == 0.
fn mul_div_u128(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    // Try simple path; if multiply overflows, fail gracefully.
    a.checked_mul(b)?.checked_div(d)
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn addr(x: u8) -> Address {
        let mut a = [0u8; 20];
        a[0] = x;
        Address(a)
    }

    #[derive(Default)]
    struct MockBackend {
        now: AtomicU64,
        treasury: Address,
        // balances[(asset, address)]
        balances: RwLock<HashMap<(AssetId, Address), Balance>>,
        delivered: RwLock<HashMap<(AssetId, Address), Balance>>,
    }

    impl MockBackend {
        fn new() -> Self {
            let mut b = Self::default();
            b.treasury = addr(0xFE);
            b.set_now(1_700_000_000);
            b
        }
        fn set_now(&self, t: u64) {
            self.now.store(t, Ordering::SeqCst);
        }
        fn mint(&self, asset: AssetId, to: Address, amount: Balance) {
            let mut m = self.balances.write();
            *m.entry((asset, to)).or_default() += amount;
        }
        fn bal(&self, asset: AssetId, who: Address) -> Balance {
            *self.balances.read().get(&(asset, who)).unwrap_or(&0)
        }
        fn delivered(&self, asset: AssetId, who: Address) -> Balance {
            *self.delivered.read().get(&(asset, who)).unwrap_or(&0)
        }
    }

    impl LaunchpadBackend for MockBackend {
        fn now_unix(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
        fn treasury_address(&self) -> Address {
            self.treasury
        }
        fn transfer_payment_from(
            &self,
            payer: Address,
            asset: AssetId,
            to_treasury: Address,
            amount: Balance,
        ) -> Result<(), BackendError> {
            let mut m = self.balances.write();
            let pb = m.entry((asset, payer)).or_default();
            if *pb < amount {
                return Err(BackendError::Insufficient);
            }
            *pb -= amount;
            *m.entry((asset, to_treasury)).or_default() += amount;
            Ok(())
        }
        fn refund_payment(&self, to_buyer: Address, asset: AssetId, amount: Balance) -> Result<(), BackendError> {
            let mut m = self.balances.write();
            let tb = m.entry((asset, self.treasury)).or_default();
            if *tb < amount {
                return Err(BackendError::Insufficient);
            }
            *tb -= amount;
            *m.entry((asset, to_buyer)).or_default() += amount;
            Ok(())
        }
        fn deliver_tokens(&self, token_asset: AssetId, to: Address, amount: Balance) -> Result<(), BackendError> {
            // For test just record delivery; assume token mint/transfer ok.
            let mut d = self.delivered.write();
            *d.entry((token_asset, to)).or_default() += amount;
            Ok(())
        }
    }

    fn default_cfg() -> SaleConfig {
        SaleConfig {
            payment_asset: AssetId(1),
            sold_token: AssetId(100),
            price: Price::new(2, 1).unwrap(), // 2 payment units per 1 token
            start_ts: 1_700_000_100,
            end_ts: 1_700_000_200,
            whitelist_only: false,
            soft_cap_payment: 1_000,
            hard_cap_payment: 2_000,
            min_contribution: 100,
            max_contribution: 2_000,
            vesting: Vesting { tge_bps: 1000, cliff_seconds: 3600, vest_seconds: 86_400 },
        }
    }

    #[test]
    fn flow_success_claim() {
        let be = Arc::new(MockBackend::new());
        let lp = Launchpad::new(be.clone(), 128);
        let owner = addr(0x01);
        let u1 = addr(0x10);
        let u2 = addr(0x11);

        // fund buyers
        be.mint(AssetId(1), u1, 1_000);
        be.mint(AssetId(1), u2, 1_000);

        // create + activate
        let mut cfg = default_cfg();
        cfg.start_ts = be.now_unix() + 10;
        cfg.end_ts = cfg.start_ts + 100;
        let pid = lp.create_project(owner, cfg.clone()).unwrap();
        lp.activate(owner, pid).unwrap();

        // before start
        assert!(matches!(lp.contribute(u1, pid, 200), Err(LaunchpadError::NotStarted)));

        // move into window
        be.set_now(cfg.start_ts + 1);
        let (acc1, bought1) = lp.contribute(u1, pid, 600).unwrap();
        assert_eq!(acc1, 600);
        assert_eq!(bought1, 300); // price 2:1 => tokens = payment/2

        let (acc2, bought2) = lp.contribute(u2, pid, 500).unwrap();
        assert_eq!(acc2, 500);
        assert_eq!(bought2, 250);

        // end sale
        be.set_now(cfg.end_ts);
        // cannot claim before finalize
        assert!(matches!(lp.claim(u1, pid), Err(LaunchpadError::InvalidState(_))));
        // finalize success (collected 1100 >= softcap 1000)
        let ok = lp.finalize(owner, pid).unwrap();
        assert!(ok);

        // TGE = 10% => claimable = 10% of purchased
        let claimed_tge = lp.claim(u1, pid).unwrap();
        assert_eq!(claimed_tge, 30);

        // before cliff, second claim should be zero
        assert!(matches!(lp.claim(u1, pid), Err(LaunchpadError::NothingToClaim)));

        // after full vest all should be claimable
        be.set_now(cfg.end_ts + cfg.vesting.cliff_seconds + cfg.vesting.vest_seconds + 1);
        let remaining1 = lp.claim(u1, pid).unwrap();
        assert_eq!(remaining1, 270); // total 300
        let remaining2 = lp.claim(u2, pid).unwrap();
        assert_eq!(remaining2, 250);
        // double claiming should yield zero
        assert!(matches!(lp.claim(u2, pid), Err(LaunchpadError::NothingToClaim)));
    }

    #[test]
    fn flow_failed_refund() {
        let be = Arc::new(MockBackend::new());
        let lp = Launchpad::new(be.clone(), 128);
        let owner = addr(0x02);
        let u1 = addr(0x20);
        be.mint(AssetId(1), u1, 400);

        let mut cfg = default_cfg();
        cfg.soft_cap_payment = 1_000;
        cfg.hard_cap_payment = 2_000;
        cfg.start_ts = be.now_unix() + 1;
        cfg.end_ts = cfg.start_ts + 100;

        let pid = lp.create_project(owner, cfg.clone()).unwrap();
        lp.activate(owner, pid).unwrap();

        be.set_now(cfg.start_ts + 1);
        lp.contribute(u1, pid, 400).unwrap(); // collected < softcap

        be.set_now(cfg.end_ts);
        let ok = lp.finalize(owner, pid).unwrap();
        assert!(!ok);

        // refund full 400
        let rf = lp.refund(u1, pid).unwrap();
        assert_eq!(rf, 400);
        // second refund should be zero
        assert!(matches!(lp.refund(u1, pid), Err(LaunchpadError::NothingToRefund)));
    }

    #[test]
    fn caps_and_limits() {
        let be = Arc::new(MockBackend::new());
        let lp = Launchpad::new(be.clone(), 128);
        let owner = addr(0x03);
        let u1 = addr(0x30);
        let u2 = addr(0x31);
        be.mint(AssetId(1), u1, 2_000);
        be.mint(AssetId(1), u2, 2_000);

        let mut cfg = default_cfg();
        cfg.start_ts = be.now_unix();
        cfg.end_ts = cfg.start_ts + 100;
        cfg.hard_cap_payment = 1000; // small cap
        cfg.min_contribution = 200;
        cfg.max_contribution = 600;

        let pid = lp.create_project(owner, cfg.clone()).unwrap();
        lp.activate(owner, pid).unwrap();

        // below min on first try
        assert!(matches!(lp.contribute(u1, pid, 100), Err(LaunchpadError::AddressLimit)));

        // accept 600 (max)
        be.set_now(cfg.start_ts + 1);
        lp.contribute(u1, pid, 600).unwrap();

        // user cannot exceed personal max
        assert!(matches!(lp.contribute(u1, pid, 1), Err(LaunchpadError::AddressLimit)));

        // hard cap remaining = 400, so accept partial from u2
        let (acc, bought) = lp.contribute(u2, pid, 500).unwrap();
        assert_eq!(acc, 400);
        assert_eq!(bought, 200);
        // further attempts exceed cap
        assert!(matches!(lp.contribute(u2, pid, 1), Err(LaunchpadError::HardCapExceeded)));
    }
}

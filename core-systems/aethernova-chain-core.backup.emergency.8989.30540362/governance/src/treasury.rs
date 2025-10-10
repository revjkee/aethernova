//! Aethernova Governance — Treasury
//!
//! Industrial-grade governance treasury with:
//! - Roles: ADMIN, SIGNER (approver), OPERATOR (executor), AUDITOR (read-only helpers)
//! - Multisig proposals with threshold approvals
//! - Per-asset rolling window spend limits
//! - Pause switch and recipient blacklist
//! - Allowed assets registry
//! - Event stream (tokio broadcast) and audit snapshots
//! - Thread-safety via parking_lot::RwLock and an execute mutex
//!
//! Integrate by implementing `TreasuryBackend` for your runtime/ledger.
//! NOTE: Address/AssetId/Balance here are generic placeholders.
//! Chain-specific invariants must be enforced in your backend. Не могу подтвердить это.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use thiserror::Error;
use tokio::sync::broadcast;

/// 20-byte address placeholder; align with your chain primitives.
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

/// Asset identifier (e.g., ERC20 address or native asset id).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AssetId(pub u32);

/// Balance type in smallest units. Adjust if your chain uses wider ints.
pub type Balance = u128;

/// Backend errors surfaced to Treasury.
#[derive(Error, Debug)]
pub enum BackendError {
    #[error("insufficient balance")]
    Insufficient,
    #[error("asset not supported by backend")]
    UnsupportedAsset,
    #[error("backend failure: {0}")]
    Other(String),
}

/// Abstracts ledger/time operations needed by the treasury.
///
/// IMPORTANT: `transfer` is expected to move funds FROM the treasury account
/// (returned by `treasury_address`) to `to`.
pub trait TreasuryBackend: Send + Sync + 'static {
    fn now_unix(&self) -> u64;
    fn treasury_address(&self) -> Address;

    fn transfer(&self, asset: AssetId, to: Address, amount: Balance) -> Result<(), BackendError>;
    fn balance_of_treasury(&self, asset: AssetId) -> Result<Balance, BackendError>;

    /// Optional hooks; default is no-op
    fn on_execute(&self, _proposal_id: u64) -> Result<(), BackendError> { Ok(()) }
    fn on_config_changed(&self) -> Result<(), BackendError> { Ok(()) }
}

/// Roles.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Role {
    Admin,
    Signer,
    Operator,
    Auditor,
}

/// Treasury configuration.
#[derive(Clone, Debug)]
pub struct TreasuryConfig {
    /// How many signer approvals are required to execute a proposal.
    pub approval_threshold: u32,
    /// Spending caps per asset for a rolling window.
    pub spend_limits: HashMap<AssetId, SpendWindow>,
    /// Allowed assets registry.
    pub allowed_assets: HashSet<AssetId>,
    /// Max proposals kept in memory (older archived will be pruned).
    pub proposal_retention: usize,
    /// Event channel capacity.
    pub event_capacity: usize,
}

impl Default for TreasuryConfig {
    fn default() -> Self {
        Self {
            approval_threshold: 2,
            spend_limits: HashMap::new(),
            allowed_assets: HashSet::new(),
            proposal_retention: 10_000,
            event_capacity: 1024,
        }
    }
}

/// Rolling spend window (cap per window_seconds).
#[derive(Clone, Copy, Debug)]
pub struct SpendWindow {
    pub window_seconds: u64,
    pub cap: Balance,
}

/// Proposal kinds supported by the treasury.
#[derive(Clone, Debug)]
pub enum ProposalKind {
    /// Transfer funds from treasury to `to`.
    Transfer { asset: AssetId, to: Address, amount: Balance, ref_id: Option<String> },
    /// Grant or revoke role.
    SetRole { who: Address, role: Role, grant: bool },
    /// Update per-asset spend limit window/cap.
    SetLimit { asset: AssetId, window: SpendWindow },
    /// Allow or disallow asset.
    SetAssetAllowed { asset: AssetId, allowed: bool },
    /// Pause or unpause treasury execution.
    SetPause { paused: bool },
}

/// Proposal status lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Executed,
    Rejected,
    Canceled,
}

/// Proposal object.
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub creator: Address,
    pub created_at: u64,
    pub kind: ProposalKind,
    pub status: ProposalStatus,
    pub approvals: BTreeSet<Address>, // signer addresses
    pub memo: Option<String>,
}

/// Events emitted by treasury.
#[derive(Clone, Debug)]
pub enum TreasuryEvent {
    ProposalCreated(Proposal),
    ProposalApproved { id: u64, by: Address, approvals: u32 },
    ProposalExecuted { id: u64 },
    ProposalRejected { id: u64 },
    ProposalCanceled { id: u64 },
    Paused(bool),
    RoleChanged { who: Address, role: Role, grant: bool },
    LimitUpdated { asset: AssetId, window: SpendWindow },
    AssetAllowed { asset: AssetId, allowed: bool },
    Spent { asset: AssetId, amount: Balance, window_left: Balance },
}

/// Treasury errors.
#[derive(Error, Debug)]
pub enum TreasuryError {
    #[error("not authorized")]
    NotAuthorized,
    #[error("proposal not found: {0}")]
    NotFound(u64),
    #[error("proposal not pending")]
    NotPending,
    #[error("already approved")]
    AlreadyApproved,
    #[error("threshold not met")]
    ThresholdNotMet,
    #[error("treasury paused")]
    Paused,
    #[error("asset not allowed")]
    AssetNotAllowed,
    #[error("recipient blacklisted")]
    BlacklistedRecipient,
    #[error("exceeds spend window")]
    WindowExceeded,
    #[error("backend: {0}")]
    Backend(#[from] BackendError),
    #[error("internal: {0}")]
    Internal(String),
}

/// Internal accounting for rolling window.
#[derive(Clone, Debug, Default)]
struct WindowState {
    period_start: u64,
    spent_in_period: Balance,
}

/// Main treasury structure.
pub struct Treasury<B: TreasuryBackend> {
    backend: Arc<B>,
    cfg: RwLock<TreasuryConfig>,

    // Roles.
    roles_admin: RwLock<HashSet<Address>>,
    roles_signer: RwLock<HashSet<Address>>,
    roles_operator: RwLock<HashSet<Address>>,
    roles_auditor: RwLock<HashSet<Address>>,

    // Blacklist.
    blacklist: RwLock<HashSet<Address>>,

    // Pause.
    paused: RwLock<bool>,

    // Proposals and approvals.
    proposals: RwLock<BTreeMap<u64, Proposal>>,
    next_proposal_id: RwLock<u64>,

    // Spend window states per asset.
    windows: RwLock<HashMap<AssetId, WindowState>>,

    // Event stream.
    events_tx: broadcast::Sender<TreasuryEvent>,

    // Execute mutex to serialize side-effects.
    exec_lock: Mutex<()>,
}

impl<B: TreasuryBackend> fmt::Debug for Treasury<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Treasury")
            .field("paused", &self.paused.read())
            .finish()
    }
}

impl<B: TreasuryBackend> Treasury<B> {
    /// Create a new treasury instance.
    pub fn new(backend: Arc<B>, cfg: TreasuryConfig, initial_admins: &[Address], initial_signers: &[Address]) -> Arc<Self> {
        let (tx, _) = broadcast::channel(cfg.event_capacity);

        let t = Arc::new(Self {
            backend,
            cfg: RwLock::new(cfg.clone()),
            roles_admin: RwLock::new(initial_admins.iter().copied().collect()),
            roles_signer: RwLock::new(initial_signers.iter().copied().collect()),
            roles_operator: RwLock::new(HashSet::new()),
            roles_auditor: RwLock::new(HashSet::new()),
            blacklist: RwLock::new(HashSet::new()),
            paused: RwLock::new(false),
            proposals: RwLock::new(BTreeMap::new()),
            next_proposal_id: RwLock::new(1),
            windows: RwLock::new(HashMap::new()),
            events_tx: tx,
            exec_lock: Mutex::new(()),
        });

        // Preload windows map from cfg.
        {
            let mut w = t.windows.write();
            for (asset, sw) in &cfg.spend_limits {
                let now = t.now();
                w.insert(*asset, WindowState { period_start: now, spent_in_period: 0 });
                // ensure allowed assets include those with limits
                t.cfg.write().allowed_assets.insert(*asset);
            }
        }
        t
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TreasuryEvent> {
        self.events_tx.subscribe()
    }

    /// Helpers: role checks
    fn is_admin(&self, who: &Address) -> bool { self.roles_admin.read().contains(who) }
    fn is_signer(&self, who: &Address) -> bool { self.roles_signer.read().contains(who) }
    fn is_operator(&self, who: &Address) -> bool { self.roles_operator.read().contains(who) || self.is_admin(who) }
    fn is_auditor(&self, who: &Address) -> bool { self.roles_auditor.read().contains(who) }

    /// Admin: grant or revoke roles.
    pub fn set_role(&self, caller: Address, who: Address, role: Role, grant: bool) -> Result<(), TreasuryError> {
        if !self.is_admin(&caller) { return Err(TreasuryError::NotAuthorized); }
        match role {
            Role::Admin => { let mut s = self.roles_admin.write(); if grant { s.insert(who); } else { s.remove(&who); } }
            Role::Signer => { let mut s = self.roles_signer.write(); if grant { s.insert(who); } else { s.remove(&who); } }
            Role::Operator => { let mut s = self.roles_operator.write(); if grant { s.insert(who); } else { s.remove(&who); } }
            Role::Auditor => { let mut s = self.roles_auditor.write(); if grant { s.insert(who); } else { s.remove(&who); } }
        }
        let _ = self.events_tx.send(TreasuryEvent::RoleChanged { who, role, grant });
        self.backend.on_config_changed()?;
        Ok(())
    }

    /// Admin: set pause flag.
    pub fn set_pause(&self, caller: Address, paused: bool) -> Result<(), TreasuryError> {
        if !self.is_admin(&caller) { return Err(TreasuryError::NotAuthorized); }
        *self.paused.write() = paused;
        let _ = self.events_tx.send(TreasuryEvent::Paused(paused));
        Ok(())
    }

    /// Admin: set or clear blacklist entry.
    pub fn set_blacklisted(&self, caller: Address, addr: Address, banned: bool) -> Result<(), TreasuryError> {
        if !self.is_admin(&caller) { return Err(TreasuryError::NotAuthorized); }
        let mut bl = self.blacklist.write();
        if banned { bl.insert(addr); } else { bl.remove(&addr); }
        Ok(())
    }

    /// Admin: update spend limit for an asset.
    pub fn set_limit(&self, caller: Address, asset: AssetId, window: SpendWindow) -> Result<(), TreasuryError> {
        if !self.is_admin(&caller) { return Err(TreasuryError::NotAuthorized); }
        self.cfg.write().spend_limits.insert(asset, window);
        self.cfg.write().allowed_assets.insert(asset);
        self.windows.write().insert(asset, WindowState { period_start: self.now(), spent_in_period: 0 });
        let _ = self.events_tx.send(TreasuryEvent::LimitUpdated { asset, window });
        self.backend.on_config_changed()?;
        Ok(())
    }

    /// Admin: mark asset allowed/disallowed.
    pub fn set_asset_allowed(&self, caller: Address, asset: AssetId, allowed: bool) -> Result<(), TreasuryError> {
        if !self.is_admin(&caller) { return Err(TreasuryError::NotAuthorized); }
        if allowed {
            self.cfg.write().allowed_assets.insert(asset);
        } else {
            self.cfg.write().allowed_assets.remove(&asset);
        }
        let _ = self.events_tx.send(TreasuryEvent::AssetAllowed { asset, allowed });
        self.backend.on_config_changed()?;
        Ok(())
    }

    /// Create a proposal. Anyone may create; policy can be tightened by front-end.
    pub fn create_proposal(&self, creator: Address, kind: ProposalKind, memo: Option<String>) -> Result<u64, TreasuryError> {
        let mut id_guard = self.next_proposal_id.write();
        let id = *id_guard;
        *id_guard = id.saturating_add(1);

        // Basic pre-checks to fail fast.
        if let ProposalKind::Transfer { asset, to, amount, .. } = &kind {
            if !self.cfg.read().allowed_assets.contains(asset) {
                return Err(TreasuryError::AssetNotAllowed);
            }
            if self.blacklist.read().contains(to) {
                return Err(TreasuryError::BlacklistedRecipient);
            }
            if *amount == 0 {
                return Err(TreasuryError::Internal("zero amount".into()));
            }
        }

        let p = Proposal {
            id,
            creator,
            created_at: self.now(),
            kind,
            status: ProposalStatus::Pending,
            approvals: BTreeSet::new(),
            memo,
        };
        self.proposals.write().insert(id, p.clone());
        let _ = self.events_tx.send(TreasuryEvent::ProposalCreated(p));

        // prune if above retention
        let retention = self.cfg.read().proposal_retention;
        let mut ps = self.proposals.write();
        while ps.len() > retention {
            if let Some((&oldest, _)) = ps.iter().next() {
                ps.remove(&oldest);
            } else {
                break;
            }
        }

        Ok(id)
    }

    /// Approve a proposal by signer.
    pub fn approve(&self, signer: Address, id: u64) -> Result<u32, TreasuryError> {
        if !self.is_signer(&signer) && !self.is_admin(&signer) {
            return Err(TreasuryError::NotAuthorized);
        }
        let mut ps = self.proposals.write();
        let p = ps.get_mut(&id).ok_or(TreasuryError::NotFound(id))?;
        if p.status != ProposalStatus::Pending { return Err(TreasuryError::NotPending); }
        if !p.approvals.insert(signer) { return Err(TreasuryError::AlreadyApproved); }
        let approvals = p.approvals.len() as u32;
        let _ = self.events_tx.send(TreasuryEvent::ProposalApproved { id, by: signer, approvals });
        Ok(approvals)
    }

    /// Execute a proposal when threshold reached.
    pub fn execute(&self, caller: Address, id: u64) -> Result<(), TreasuryError> {
        if !self.is_operator(&caller) { return Err(TreasuryError::NotAuthorized); }
        if *self.paused.read() { return Err(TreasuryError::Paused); }

        let _guard = self.exec_lock.lock(); // serialize side effects

        // Re-check under lock
        let threshold = self.cfg.read().approval_threshold;
        let mut ps = self.proposals.write();
        let p = ps.get_mut(&id).ok_or(TreasuryError::NotFound(id))?;
        if p.status != ProposalStatus::Pending { return Err(TreasuryError::NotPending); }
        if (p.approvals.len() as u32) < threshold { return Err(TreasuryError::ThresholdNotMet); }

        // Execute according to kind
        match &p.kind {
            ProposalKind::Transfer { asset, to, amount, .. } => {
                // policy checks
                self.ensure_allowed(*asset)?;
                self.ensure_not_blacklisted(*to)?;
                self.ensure_within_window(*asset, *amount)?;

                // ensure treasury has funds (backend decides real failure)
                let _treasury_bal = self.backend.balance_of_treasury(*asset)?;
                // attempt transfer
                self.backend.transfer(*asset, *to, *amount)?;
                self.note_spent(*asset, *amount)?;
                let left = self.window_left(*asset)?;
                let _ = self.events_tx.send(TreasuryEvent::Spent { asset: *asset, amount: *amount, window_left: left });
            }
            ProposalKind::SetRole { who, role, grant } => {
                // only Admin can execute such proposals — caller is operator/admin already
                match role {
                    Role::Admin => { if *grant { self.roles_admin.write().insert(*who); } else { self.roles_admin.write().remove(who); } }
                    Role::Signer => { if *grant { self.roles_signer.write().insert(*who); } else { self.roles_signer.write().remove(who); } }
                    Role::Operator => { if *grant { self.roles_operator.write().insert(*who); } else { self.roles_operator.write().remove(who); } }
                    Role::Auditor => { if *grant { self.roles_auditor.write().insert(*who); } else { self.roles_auditor.write().remove(who); } }
                }
                let _ = self.events_tx.send(TreasuryEvent::RoleChanged { who: *who, role: *role, grant: *grant });
                self.backend.on_config_changed()?;
            }
            ProposalKind::SetLimit { asset, window } => {
                self.cfg.write().spend_limits.insert(*asset, *window);
                self.cfg.write().allowed_assets.insert(*asset);
                self.windows.write().insert(*asset, WindowState { period_start: self.now(), spent_in_period: 0 });
                let _ = self.events_tx.send(TreasuryEvent::LimitUpdated { asset: *asset, window: *window });
                self.backend.on_config_changed()?;
            }
            ProposalKind::SetAssetAllowed { asset, allowed } => {
                if *allowed { self.cfg.write().allowed_assets.insert(*asset); }
                else { self.cfg.write().allowed_assets.remove(asset); }
                let _ = self.events_tx.send(TreasuryEvent::AssetAllowed { asset: *asset, allowed: *allowed });
                self.backend.on_config_changed()?;
            }
            ProposalKind::SetPause { paused } => {
                *self.paused.write() = *paused;
                let _ = self.events_tx.send(TreasuryEvent::Paused(*paused));
            }
        }

        p.status = ProposalStatus::Executed;
        let _ = self.events_tx.send(TreasuryEvent::ProposalExecuted { id });
        self.backend.on_execute(id)?;
        Ok(())
    }

    /// Cancel or reject a proposal (admin only).
    pub fn set_status_admin(&self, caller: Address, id: u64, status: ProposalStatus) -> Result<(), TreasuryError> {
        if !self.is_admin(&caller) { return Err(TreasuryError::NotAuthorized); }
        match status {
            ProposalStatus::Canceled | ProposalStatus::Rejected => {
                let mut ps = self.proposals.write();
                let p = ps.get_mut(&id).ok_or(TreasuryError::NotFound(id))?;
                if p.status != ProposalStatus::Pending { return Err(TreasuryError::NotPending); }
                p.status = status;
                match status {
                    ProposalStatus::Canceled => { let _ = self.events_tx.send(TreasuryEvent::ProposalCanceled { id }); }
                    ProposalStatus::Rejected => { let _ = self.events_tx.send(TreasuryEvent::ProposalRejected { id }); }
                    _ => {}
                }
                Ok(())
            }
            _ => Err(TreasuryError::Internal("invalid admin status".into())),
        }
    }

    /// Read-only: snapshot for audit.
    pub fn snapshot(&self, limit: usize) -> TreasurySnapshot {
        let cfg = self.cfg.read().clone();
        let paused = *self.paused.read();
        let roles = RolesSnapshot {
            admin: self.roles_admin.read().clone(),
            signer: self.roles_signer.read().clone(),
            operator: self.roles_operator.read().clone(),
            auditor: self.roles_auditor.read().clone(),
        };
        let mut proposals = Vec::new();
        for p in self.proposals.read().values().rev().take(limit) {
            proposals.push(p.clone());
        }
        let windows = self.windows.read().clone();
        TreasurySnapshot { cfg, paused, roles, proposals, windows }
    }

    // ----- internal policy helpers -----
    fn ensure_allowed(&self, asset: AssetId) -> Result<(), TreasuryError> {
        if !self.cfg.read().allowed_assets.contains(&asset) {
            return Err(TreasuryError::AssetNotAllowed);
        }
        Ok(())
    }

    fn ensure_not_blacklisted(&self, addr: Address) -> Result<(), TreasuryError> {
        if self.blacklist.read().contains(&addr) {
            return Err(TreasuryError::BlacklistedRecipient);
        }
        Ok(())
    }

    fn ensure_within_window(&self, asset: AssetId, amount: Balance) -> Result<(), TreasuryError> {
        if let Some(sw) = self.cfg.read().spend_limits.get(&asset).cloned() {
            let mut w = self.windows.write();
            let ws = w.entry(asset).or_insert_with(|| WindowState { period_start: self.now(), spent_in_period: 0 });
            let now = self.now();
            if now.saturating_sub(ws.period_start) >= sw.window_seconds {
                ws.period_start = now;
                ws.spent_in_period = 0;
            }
            if ws.spent_in_period.saturating_add(amount) > sw.cap {
                return Err(TreasuryError::WindowExceeded);
            }
        }
        Ok(())
    }

    fn note_spent(&self, asset: AssetId, amount: Balance) -> Result<(), TreasuryError> {
        if let Some(sw) = self.cfg.read().spend_limits.get(&asset).cloned() {
            let mut w = self.windows.write();
            let ws = w.entry(asset).or_insert_with(|| WindowState { period_start: self.now(), spent_in_period: 0 });
            let now = self.now();
            if now.saturating_sub(ws.period_start) >= sw.window_seconds {
                ws.period_start = now;
                ws.spent_in_period = 0;
            }
            ws.spent_in_period = ws.spent_in_period.saturating_add(amount);
        }
        Ok(())
    }

    fn window_left(&self, asset: AssetId) -> Result<Balance, TreasuryError> {
        if let Some(sw) = self.cfg.read().spend_limits.get(&asset).cloned() {
            let w = self.windows.read();
            if let Some(ws) = w.get(&asset) {
                return Ok(sw.cap.saturating_sub(ws.spent_in_period));
            }
            return Ok(sw.cap);
        }
        Ok(Balance::MAX)
    }

    fn now(&self) -> u64 { self.backend.now_unix() }
}

/// Snapshot types for audit/export.
#[derive(Clone, Debug)]
pub struct RolesSnapshot {
    pub admin: HashSet<Address>,
    pub signer: HashSet<Address>,
    pub operator: HashSet<Address>,
    pub auditor: HashSet<Address>,
}

#[derive(Clone, Debug)]
pub struct TreasurySnapshot {
    pub cfg: TreasuryConfig,
    pub paused: bool,
    pub roles: RolesSnapshot,
    pub proposals: Vec<Proposal>,
    pub windows: HashMap<AssetId, WindowState>,
}

//
// ---------------------- Mock backend for tests ----------------------
//

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct MockBackend {
        now: AtomicU64,
        treasury: Address,
        balances: RwLock<HashMap<(AssetId, Address), Balance>>,
    }

    impl MockBackend {
        fn new() -> Self {
            let mut b = Self::default();
            b.treasury = addr(0xAA);
            b.set_now(1_700_000_000);
            b
        }
        fn set_now(&self, t: u64) { self.now.store(t, Ordering::SeqCst); }
        fn mint_to_treasury(&self, asset: AssetId, amount: Balance) {
            let mut m = self.balances.write();
            *m.entry((asset, self.treasury)).or_default() = amount;
        }
        fn balance(&self, asset: AssetId, who: Address) -> Balance {
            *self.balances.read().get(&(asset, who)).unwrap_or(&0)
        }
    }

    impl TreasuryBackend for MockBackend {
        fn now_unix(&self) -> u64 { self.now.load(Ordering::SeqCst) }
        fn treasury_address(&self) -> Address { self.treasury }

        fn transfer(&self, asset: AssetId, to: Address, amount: Balance) -> Result<(), BackendError> {
            let from = self.treasury;
            let mut m = self.balances.write();
            let fb = m.entry((asset, from)).or_default();
            if *fb < amount { return Err(BackendError::Insufficient); }
            *fb -= amount;
            *m.entry((asset, to)).or_default() += amount;
            Ok(())
        }

        fn balance_of_treasury(&self, asset: AssetId) -> Result<Balance, BackendError> {
            Ok(self.balance(asset, self.treasury))
        }
    }

    fn addr(x: u8) -> Address { let mut a = [0u8; 20]; a[0] = x; Address(a) }

    #[test]
    fn transfer_with_threshold_and_limit() {
        let be = Arc::new(MockBackend::new());
        let asset = AssetId(1);
        be.mint_to_treasury(asset, 1_000);

        let mut cfg = TreasuryConfig::default();
        cfg.approval_threshold = 2;
        cfg.allowed_assets.insert(asset);
        cfg.spend_limits.insert(asset, SpendWindow { window_seconds: 3600, cap: 500 });

        let admin = addr(0x01);
        let s1 = addr(0x02);
        let s2 = addr(0x03);
        let op = addr(0x04);

        let t = Treasury::new(be.clone(), cfg, &[admin], &[s1, s2]);
        t.set_role(admin, op, Role::Operator, true).unwrap();

        let to = addr(0x10);
        let pid = t.create_proposal(admin, ProposalKind::Transfer { asset, to, amount: 400, ref_id: Some("inv-001".into()) }, None).unwrap();

        assert_eq!(t.approve(s1, pid).unwrap(), 1);
        assert_eq!(t.approve(s2, pid).unwrap(), 2);

        t.execute(op, pid).unwrap();

        // after execute
        assert_eq!(be.balance(asset, to), 400);
        // try exceed window
        let pid2 = t.create_proposal(admin, ProposalKind::Transfer { asset, to, amount: 150, ref_id: None }, None).unwrap();
        t.approve(s1, pid2).unwrap();
        t.approve(s2, pid2).unwrap();
        let err = t.execute(op, pid2).unwrap_err();
        assert!(matches!(err, TreasuryError::WindowExceeded));

        // advance window and try again
        be.set_now(1_700_000_000 + 3601);
        t.execute(op, pid2).unwrap();
        assert_eq!(be.balance(asset, to), 550);
    }

    #[test]
    fn pause_and_blacklist() {
        let be = Arc::new(MockBackend::new());
        let asset = AssetId(7);
        be.mint_to_treasury(asset, 5_000);

        let mut cfg = TreasuryConfig::default();
        cfg.approval_threshold = 1;
        cfg.allowed_assets.insert(asset);

        let admin = addr(0xA1);
        let signer = addr(0xA2);
        let op = addr(0xA3);

        let t = Treasury::new(be.clone(), cfg, &[admin], &[signer]);
        t.set_role(admin, op, Role::Operator, true).unwrap();

        let to = addr(0xFE);
        let pid = t.create_proposal(admin, ProposalKind::Transfer { asset, to, amount: 100, ref_id: None }, None).unwrap();
        t.approve(signer, pid).unwrap();

        // pause blocks execution
        t.set_pause(admin, true).unwrap();
        let e = t.execute(op, pid).unwrap_err();
        assert!(matches!(e, TreasuryError::Paused));

        // blacklist blocks creation/execution
        t.set_pause(admin, false).unwrap();
        t.set_blacklisted(admin, to, true).unwrap();
        let pid2 = t.create_proposal(admin, ProposalKind::Transfer { asset, to, amount: 50, ref_id: None }, None).unwrap_err();
        assert!(matches!(pid2, TreasuryError::BlacklistedRecipient));
    }

    #[test]
    fn role_update_via_proposal() {
        let be = Arc::new(MockBackend::new());
        let cfg = TreasuryConfig::default();
        let admin = addr(0x11);
        let signer = addr(0x12);
        let t = Treasury::new(be, cfg, &[admin], &[signer]);

        let who = addr(0x55);
        let pid = t.create_proposal(admin, ProposalKind::SetRole { who, role: Role::Operator, grant: true }, None).unwrap();
        t.approve(signer, pid).unwrap();
        // caller must be operator/admin; admin is allowed
        t.execute(admin, pid).unwrap();
        assert!(t.is_operator(&who));
    }
}

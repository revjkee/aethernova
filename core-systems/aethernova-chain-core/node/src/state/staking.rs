// node/src/state/staking.rs
//! Industrial staking state: validators, delegations, rewards, unbonding, slashing.
//!
//! Основано на проверяемых практиках:
//! - Lazy accounting и обязательное снятие наград при изменении делегации (Cosmos SDK Distribution).
//! - Slashing также применим к незавершённым unbonding-депозитам после времени проступка (Cosmos SDK Staking).
//! - Коллективный слэшинг валидатора и его делегаторов/номинаторов (Substrate pallet_staking).
//! - Причины слэшинга (double vote, surround vote, downtime) — PoS (Ethereum/Cosmos).
//!
//! В модуле намеренно нет криптографии и журналирования транзакций — только чистая логика состояния.
//! Внешние компоненты должны проверять подписи, происхождение событий и производить перевод средств.
//!
//! Нотация:
//! - Все суммы — в минимальных единицах токена (u128).
//! - RPS (rewards-per-share): фикс-точность через умножение на RPS_SCALE.
//! - Epoch/Slot/Time — абстракции консенсуса. Периоды конфигурируются снаружи.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub type Amount = u128;
pub type Shares = u128;
pub type Epoch = u64;
pub type Address = [u8; 32]; // абстрактный идентификатор аккаунта/валидатора

const RPS_SCALE: u128 = 1_000_000_000_000u128; // 1e12 для точности начисления

// ---------- Ошибки ----------

#[derive(Debug)]
pub enum StakingError {
    Storage(String),
    MathOverflow,
    NotFound,
    AlreadyExists,
    InvalidAmount,
    InvalidCommission,
    InvalidState,
    NotEnoughBalance,
    NotEnoughShares,
    UnbondingNotMature,
    SlashingFractionInvalid,
    ValidatorJailed,
    ValidatorInactive,
    Unauthorized,
}

impl fmt::Display for StakingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use StakingError::*;
        match self {
            Storage(s) => write!(f, "storage error: {s}"),
            MathOverflow => write!(f, "math overflow"),
            NotFound => write!(f, "not found"),
            AlreadyExists => write!(f, "already exists"),
            InvalidAmount => write!(f, "invalid amount"),
            InvalidCommission => write!(f, "invalid commission"),
            InvalidState => write!(f, "invalid state"),
            NotEnoughBalance => write!(f, "not enough balance"),
            NotEnoughShares => write!(f, "not enough shares"),
            UnbondingNotMature => write!(f, "unbonding not mature"),
            SlashingFractionInvalid => write!(f, "slashing fraction invalid"),
            ValidatorJailed => write!(f, "validator jailed"),
            ValidatorInactive => write!(f, "validator inactive"),
            Unauthorized => write!(f, "unauthorized"),
        }
    }
}
impl std::error::Error for StakingError {}

// ---------- Параметры/константы ----------

#[derive(Clone, Debug)]
pub struct StakingParams {
    /// Макс. количество активных валидаторов (управляет отбором/ротацией).
    pub max_active_validators: u32,
    /// Длина периода unbonding в эпохах. Без «дефолта по индустрии» — задаётся сетью.
    pub unbonding_epochs: Epoch,
    /// Минимальная комиссия валидатора в базисных пунктах [0, 10_000].
    pub min_commission_bps: u16,
    /// Максимальный единовременный шаг изменения комиссии (bps).
    pub max_commission_step_bps: u16,
    /// Доля слэшинга за double-sign (числитель/знаменатель в 1e18-доле).
    pub slash_double_sign_ppm: u64, // parts-per-million *одна миллионная доля* для простоты
    /// Доля слэшинга за длительный downtime.
    pub slash_downtime_ppm: u64,
}

/// Состояние валидатора.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed, // для наказаний/даунтайма
}

/// Причины слэшинга (неисчерпывающий список).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashReason {
    DoubleSign,
    SurroundVote,
    Downtime,
    Other(u8),
}

/// Информация по валидатору.
#[derive(Clone, Debug)]
pub struct Validator {
    pub address: Address,
    pub status: ValidatorStatus,
    pub commission_bps: u16, // [0..=10000]
    pub min_self_bond: Amount,

    pub self_bonded: Amount,
    pub total_stake: Amount, // self + делегирования
    pub total_shares: Shares, // для RPS-учёта и долей делегаторов

    // учёт вознаграждений валидатора (до распределения делегаторам)
    pub acc_rps: u128, // накопленные награды на 1 долю (scaled by RPS_SCALE)
    pub outstanding_rewards: Amount, // накопленные неразобранные (для комиссий и т.п.)

    pub last_heartbeat_epoch: Epoch,
}

/// Делегирование делегатора к конкретному валидатору.
#[derive(Clone, Debug)]
pub struct Delegation {
    pub delegator: Address,
    pub validator: Address,
    pub shares: Shares,
    /// reward_debt = shares * validator.acc_rps / RPS_SCALE
    pub reward_debt: u128,
}

/// Элемент очереди unbonding.
#[derive(Clone, Debug)]
pub struct UnbondingEntry {
    pub amount: Amount,
    pub created_epoch: Epoch,
    pub release_epoch: Epoch,
}

/// Незавершённые unbonding по (delegator, validator).
#[derive(Clone, Debug)]
pub struct UnbondingDelegation {
    pub delegator: Address,
    pub validator: Address,
    pub entries: Vec<UnbondingEntry>,
}

/// События для верхнего уровня (опционально).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum StakingEvent {
    ValidatorCreated { addr: Address },
    ValidatorUpdated { addr: Address },
    ValidatorStatusChanged { addr: Address, status: ValidatorStatus },
    Delegated { delegator: Address, validator: Address, amount: Amount, shares: Shares },
    Undelegated { delegator: Address, validator: Address, amount: Amount },
    UnbondingAdded { delegator: Address, validator: Address, amount: Amount, release_epoch: Epoch },
    UnbondingWithdrawn { delegator: Address, validator: Address, amount: Amount },
    RewardsDistributed { validator: Address, reward: Amount, commission: Amount },
    Slashed { validator: Address, reason: SlashReason, fraction_ppm: u64, at_epoch: Epoch, total_slashed: Amount },
    Jailed { validator: Address },
    Unjailed { validator: Address },
}

// ---------- Абстракция стораджа ----------

pub trait StakingStorage: Send + Sync + 'static {
    // Validators
    fn get_validator(&self, addr: &Address) -> Result<Option<Validator>, StakingError>;
    fn put_validator(&self, v: &Validator) -> Result<(), StakingError>;
    fn remove_validator(&self, addr: &Address) -> Result<(), StakingError>;
    fn active_validator_set(&self) -> Result<Vec<Validator>, StakingError>;

    // Delegations
    fn get_delegation(&self, delegator: &Address, validator: &Address) -> Result<Option<Delegation>, StakingError>;
    fn put_delegation(&self, d: &Delegation) -> Result<(), StakingError>;
    fn remove_delegation(&self, delegator: &Address, validator: &Address) -> Result<(), StakingError>;
    fn delegators_of(&self, validator: &Address) -> Result<Vec<Delegation>, StakingError>;

    // Unbonding queues
    fn get_unbonding(&self, delegator: &Address, validator: &Address) -> Result<Option<UnbondingDelegation>, StakingError>;
    fn put_unbonding(&self, u: &UnbondingDelegation) -> Result<(), StakingError>;
    fn remove_unbonding(&self, delegator: &Address, validator: &Address) -> Result<(), StakingError>;

    // Balances (абстракция токенов, сюда делегируется реальный перевод)
    fn credit_balance(&self, who: &Address, amount: Amount) -> Result<(), StakingError>;
    fn debit_balance(&self, who: &Address, amount: Amount) -> Result<(), StakingError>;
    fn balance_of(&self, who: &Address) -> Result<Amount, StakingError>;

    // Bookkeeping
    fn emit(&self, _ev: StakingEvent) -> Result<(), StakingError> { Ok(()) }
}

/// Простая in-memory реализация для тестов/разработки.
pub struct MemStorage {
    inner: Mutex<MemInner>,
}
#[derive(Default)]
struct MemInner {
    vals: HashMap<Address, Validator>,
    dels: HashMap<(Address, Address), Delegation>,
    unb: HashMap<(Address, Address), UnbondingDelegation>,
    bals: HashMap<Address, Amount>,
}
impl MemStorage {
    pub fn new() -> Self { Self { inner: Mutex::new(MemInner::default()) } }
}
impl StakingStorage for MemStorage {
    fn get_validator(&self, addr: &Address) -> Result<Option<Validator>, StakingError> {
        Ok(self.inner.lock().unwrap().vals.get(addr).cloned())
    }
    fn put_validator(&self, v: &Validator) -> Result<(), StakingError> {
        self.inner.lock().unwrap().vals.insert(v.address, v.clone());
        Ok(())
    }
    fn remove_validator(&self, addr: &Address) -> Result<(), StakingError> {
        self.inner.lock().unwrap().vals.remove(addr);
        Ok(())
    }
    fn active_validator_set(&self) -> Result<Vec<Validator>, StakingError> {
        Ok(self.inner.lock().unwrap().vals.values().cloned().filter(|v| v.status==ValidatorStatus::Active).collect())
    }

    fn get_delegation(&self, d: &Address, v: &Address) -> Result<Option<Delegation>, StakingError> {
        Ok(self.inner.lock().unwrap().dels.get(&(*d, *v)).cloned())
    }
    fn put_delegation(&self, del: &Delegation) -> Result<(), StakingError> {
        self.inner.lock().unwrap().dels.insert((del.delegator, del.validator), del.clone());
        Ok(())
    }
    fn remove_delegation(&self, d: &Address, v: &Address) -> Result<(), StakingError> {
        self.inner.lock().unwrap().dels.remove(&(*d, *v));
        Ok(())
    }
    fn delegators_of(&self, v: &Address) -> Result<Vec<Delegation>, StakingError> {
        Ok(self.inner.lock().unwrap().dels.values().cloned().filter(|x| &x.validator==v).collect())
    }

    fn get_unbonding(&self, d: &Address, v: &Address) -> Result<Option<UnbondingDelegation>, StakingError> {
        Ok(self.inner.lock().unwrap().unb.get(&(*d, *v)).cloned())
    }
    fn put_unbonding(&self, u: &UnbondingDelegation) -> Result<(), StakingError> {
        self.inner.lock().unwrap().unb.insert((u.delegator, u.validator), u.clone());
        Ok(())
    }
    fn remove_unbonding(&self, d: &Address, v: &Address) -> Result<(), StakingError> {
        self.inner.lock().unwrap().unb.remove(&(*d, *v));
        Ok(())
    }

    fn credit_balance(&self, who: &Address, amount: Amount) -> Result<(), StakingError> {
        let mut g = self.inner.lock().unwrap();
        *g.bals.entry(*who).or_insert(0) = g.bals.get(who).copied().unwrap_or(0).saturating_add(amount);
        Ok(())
    }
    fn debit_balance(&self, who: &Address, amount: Amount) -> Result<(), StakingError> {
        let mut g = self.inner.lock().unwrap();
        let cur = g.bals.get(who).copied().unwrap_or(0);
        if cur < amount { return Err(StakingError::NotEnoughBalance); }
        g.bals.insert(*who, cur - amount);
        Ok(())
    }
    fn balance_of(&self, who: &Address) -> Result<Amount, StakingError> {
        Ok(self.inner.lock().unwrap().bals.get(who).copied().unwrap_or(0))
    }
}

// ---------- Хелперы математики ----------

fn mul_div(a: u128, b: u128, div: u128) -> Result<u128, StakingError> {
    a.checked_mul(b).ok_or(StakingError::MathOverflow)?.checked_div(div).ok_or(StakingError::MathOverflow)
}

// ---------- Движок стейкинга ----------

pub struct StakingEngine<S: StakingStorage> {
    pub store: Arc<S>,
    pub params: StakingParams,
}

impl<S: StakingStorage> StakingEngine<S> {
    pub fn new(store: Arc<S>, params: StakingParams) -> Self { Self { store, params } }

    // ---------------- Validators ----------------

    pub fn create_validator(
        &self,
        addr: Address,
        commission_bps: u16,
        min_self_bond: Amount,
        self_bond: Amount,
        now_epoch: Epoch,
        creator: &Address,
    ) -> Result<(), StakingError> {
        if commission_bps > 10_000 { return Err(StakingError::InvalidCommission); }
        if commission_bps < self.params.min_commission_bps { return Err(StakingError::InvalidCommission); }
        if self.store.get_validator(&addr)?.is_some() { return Err(StakingError::AlreadyExists); }
        // перевести self_bond c аккаунта создателя на стейкинг
        if self_bond == 0 { return Err(StakingError::InvalidAmount); }
        self.store.debit_balance(creator, self_bond)?;

        let mut v = Validator {
            address: addr,
            status: ValidatorStatus::Active,
            commission_bps,
            min_self_bond,
            self_bonded: self_bond,
            total_stake: self_bond,
            total_shares: self_bond, // 1:1 начальная цена shares
            acc_rps: 0,
            outstanding_rewards: 0,
            last_heartbeat_epoch: now_epoch,
        };
        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::ValidatorCreated { addr })?;

        // делегирование self-bond как отдельной записи (для унификации учёта)
        let d = Delegation {
            delegator: addr,
            validator: addr,
            shares: self_bond,
            reward_debt: 0,
        };
        self.store.put_delegation(&d)?;
        self.store.emit(StakingEvent::Delegated { delegator: addr, validator: addr, amount: self_bond, shares: self_bond })?;

        // инварианты
        debug_assert_eq!(v.total_shares, v.total_stake);
        Ok(())
    }

    pub fn set_commission(&self, validator: &Address, new_bps: u16) -> Result<(), StakingError> {
        if new_bps > 10_000 { return Err(StakingError::InvalidCommission); }
        let mut v = self.store.get_validator(validator)?.ok_or(StakingError::NotFound)?;
        let delta = if new_bps > v.commission_bps { new_bps - v.commission_bps } else { v.commission_bps - new_bps };
        if delta as u16 > self.params.max_commission_step_bps { return Err(StakingError::InvalidCommission); }
        v.commission_bps = new_bps;
        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::ValidatorUpdated { addr: *validator })?;
        Ok(())
    }

    pub fn heartbeat(&self, validator: &Address, epoch: Epoch) -> Result<(), StakingError> {
        let mut v = self.store.get_validator(validator)?.ok_or(StakingError::NotFound)?;
        v.last_heartbeat_epoch = epoch;
        self.store.put_validator(&v)
    }

    pub fn jail(&self, validator: &Address) -> Result<(), StakingError> {
        let mut v = self.store.get_validator(validator)?.ok_or(StakingError::NotFound)?;
        v.status = ValidatorStatus::Jailed;
        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::Jailed { validator: *validator })?;
        Ok(())
    }

    pub fn unjail(&self, validator: &Address) -> Result<(), StakingError> {
        let mut v = self.store.get_validator(validator)?.ok_or(StakingError::NotFound)?;
        v.status = ValidatorStatus::Active;
        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::Unjailed { validator: *validator })?;
        Ok(())
    }

    // ---------------- Delegations ----------------

    /// Выдать текущие «накопленные» награды делегатора по валидатору (без перевода средств).
    fn pending_rewards(&self, v: &Validator, d: &Delegation) -> Result<Amount, StakingError> {
        // pending = shares * acc_rps / SCALE - reward_debt
        let gross = mul_div(d.shares, v.acc_rps, RPS_SCALE)?;
        let diff = gross.saturating_sub(d.reward_debt);
        Ok(diff as Amount)
    }

    /// Обязательное снятие pending-награды (lazy accounting) — до изменения делегации.
    fn withdraw_rewards_internal(&self, delegator: &Address, v: &mut Validator, d: &mut Delegation) -> Result<Amount, StakingError> {
        let reward = self.pending_rewards(v, d)?;
        if reward > 0 {
            // Комиссия уже учтена при распределении в distribute_rewards (см. ниже).
            self.store.credit_balance(delegator, reward)?;
            v.outstanding_rewards = v.outstanding_rewards.saturating_sub(reward);
            // обновить reward_debt
            d.reward_debt = mul_div(d.shares, v.acc_rps, RPS_SCALE)?;
            self.store.put_delegation(d)?;
            self.store.put_validator(v)?;
            self.store.emit(StakingEvent::RewardsDistributed { validator: v.address, reward, commission: 0 })?;
        }
        Ok(reward)
    }

    /// Делегирование amount к валидатору (mint shares по текущей цене).
    pub fn delegate(&self, delegator: Address, validator: Address, amount: Amount) -> Result<Shares, StakingError> {
        if amount == 0 { return Err(StakingError::InvalidAmount); }
        let mut v = self.store.get_validator(&validator)?.ok_or(StakingError::NotFound)?;
        if v.status != ValidatorStatus::Active { return Err(StakingError::ValidatorInactive); }

        // списать токены
        self.store.debit_balance(&delegator, amount)?;

        // цена 1 share = total_stake / total_shares (или 1 при пустом пуле)
        let new_shares = if v.total_shares == 0 || v.total_stake == 0 {
            amount
        } else {
            mul_div(amount, v.total_shares, v.total_stake)?
        };

        // существующая делегация?
        let mut d = self.store.get_delegation(&delegator, &validator)?
            .unwrap_or(Delegation{delegator, validator, shares: 0, reward_debt: 0});

        // lazy accounting: перед изменением — снять pending
        if d.shares > 0 {
            let _ = self.withdraw_rewards_internal(&delegator, &mut v, &mut d)?;
        }

        d.shares = d.shares.saturating_add(new_shares);
        d.reward_debt = mul_div(d.shares, v.acc_rps, RPS_SCALE)?;
        self.store.put_delegation(&d)?;

        v.total_shares = v.total_shares.saturating_add(new_shares);
        v.total_stake = v.total_stake.saturating_add(amount);
        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::Delegated { delegator, validator, amount, shares: new_shares })?;
        Ok(new_shares)
    }

    /// Начать unbonding: списать shares и записать в очередь возврата токены по текущей цене.
    pub fn undelegate(&self, delegator: Address, validator: Address, shares_to_unbond: Shares, now_epoch: Epoch) -> Result<Amount, StakingError> {
        if shares_to_unbond == 0 { return Err(StakingError::InvalidAmount); }
        let mut v = self.store.get_validator(&validator)?.ok_or(StakingError::NotFound)?;
        let mut d = self.store.get_delegation(&delegator, &validator)?.ok_or(StakingError::NotFound)?;

        if shares_to_unbond > d.shares { return Err(StakingError::NotEnoughShares); }

        // снять pending награды
        let _ = self.withdraw_rewards_internal(&delegator, &mut v, &mut d)?;

        // вычислить эквивалент токенов
        let amount = mul_div(shares_to_unbond, v.total_stake, v.total_shares)?;
        // обновить доли
        d.shares -= shares_to_unbond;
        d.reward_debt = mul_div(d.shares, v.acc_rps, RPS_SCALE)?;
        self.store.put_delegation(&d)?;

        v.total_shares -= shares_to_unbond;
        v.total_stake = v.total_stake.saturating_sub(amount);
        self.store.put_validator(&v)?;

        // записать в unbonding очередь
        let mut u = self.store.get_unbonding(&delegator, &validator)?
            .unwrap_or(UnbondingDelegation{delegator, validator, entries: vec![]});
        let entry = UnbondingEntry {
            amount,
            created_epoch: now_epoch,
            release_epoch: now_epoch.saturating_add(self.params.unbonding_epochs),
        };
        u.entries.push(entry.clone());
        self.store.put_unbonding(&u)?;
        self.store.emit(StakingEvent::UnbondingAdded { delegator, validator, amount, release_epoch: entry.release_epoch })?;

        // если все shares обнулены — можно удалить делегацию
        if d.shares == 0 {
            self.store.remove_delegation(&delegator, &validator)?;
        }

        Ok(amount)
    }

    /// Вывод средств по созревшим unbonding-записям.
    pub fn withdraw_unbonded(&self, delegator: Address, validator: Address, now_epoch: Epoch) -> Result<Amount, StakingError> {
        let mut u = self.store.get_unbonding(&delegator, &validator)?.ok_or(StakingError::NotFound)?;
        let (mature, pending): (Vec<_>, Vec<_>) = u.entries.into_iter().partition(|e| e.release_epoch <= now_epoch);
        if mature.is_empty() { return Err(StakingError::UnbondingNotMature); }
        let total: Amount = mature.iter().fold(0u128, |acc, e| acc.saturating_add(e.amount));
        self.store.credit_balance(&delegator, total)?;
        self.store.emit(StakingEvent::UnbondingWithdrawn { delegator, validator, amount: total })?;
        u.entries = pending;
        if u.entries.is_empty() { self.store.remove_unbonding(&delegator, &validator)?; } else { self.store.put_unbonding(&u)?; }
        Ok(total)
    }

    // ---------------- Rewards ----------------

    /// Начислить `reward` валидатору за эпоху: удержать комиссию, увеличить acc_rps.
    ///
    /// Космос-подобная модель: вознаграждения валидатора хранятся и «лениво» распределяются
    /// делегаторам через acc_rps; при изменении делегации делегатор должен полностью
    /// снять награды (см. Cosmos Distribution).
    pub fn distribute_rewards(&self, validator: Address, gross_reward: Amount) -> Result<(), StakingError> {
        if gross_reward == 0 { return Ok(()); }
        let mut v = self.store.get_validator(&validator)?.ok_or(StakingError::NotFound)?;

        // комиссия валидатора
        let commission = (gross_reward as u128)
            .checked_mul(v.commission_bps as u128).ok_or(StakingError::MathOverflow)?
            .checked_div(10_000).ok_or(StakingError::MathOverflow)? as Amount;

        let net = gross_reward.saturating_sub(commission);
        v.outstanding_rewards = v.outstanding_rewards.saturating_add(net);

        // увеличить acc_rps (если есть доли)
        if v.total_shares > 0 && net > 0 {
            let add_rps = (net as u128)
                .checked_mul(RPS_SCALE).ok_or(StakingError::MathOverflow)?
                .checked_div(v.total_shares as u128).ok_or(StakingError::MathOverflow)?;
            v.acc_rps = v.acc_rps.saturating_add(add_rps);
        }

        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::RewardsDistributed { validator, reward: net, commission })?;
        Ok(())
    }

    // ---------------- Slashing ----------------

    /// Слэшинг валидатора с долями делегаторов и незрелыми unbonding-записями.
    ///
    /// fraction_ppm — доля в миллионных (например, 50_000 = 5%).
    /// at_epoch — момент правонарушения (для обработки unbonding-очереди по правилам Cosmos).
    pub fn slash(
        &self,
        validator: Address,
        reason: SlashReason,
        fraction_ppm: u64,
        at_epoch: Epoch,
    ) -> Result<Amount, StakingError> {
        if fraction_ppm == 0 || fraction_ppm > 1_000_000 { return Err(StakingError::SlashingFractionInvalid); }
        let mut v = self.store.get_validator(&validator)?.ok_or(StakingError::NotFound)?;

        // Слэш долей делегаторов пропорционально stake (как в Substrate/Cosmos).
        let mut total_slashed: Amount = 0;

        // Сначала — активные делегирования
        let mut dels = self.store.delegators_of(&validator)?;
        for mut d in dels.drain(..) {
            // перевод pending наград не требуется: слэш режет stake/shares
            let stake_eq = mul_div(d.shares, v.total_stake, v.total_shares)?;
            let cut = (stake_eq as u128)
                .checked_mul(fraction_ppm as u128).ok_or(StakingError::MathOverflow)?
                .checked_div(1_000_000).ok_or(StakingError::MathOverflow)? as Amount;

            // уменьшить stake/доли валидатора и делегатора
            let new_stake_eq = stake_eq.saturating_sub(cut);
            let new_shares = if v.total_stake > 0 {
                mul_div(new_stake_eq, v.total_shares, v.total_stake)?
            } else { 0 };

            // аккуратно пересчитать total_* валидатора через разницу
            let shares_cut = d.shares.saturating_sub(new_shares);
            v.total_shares = v.total_shares.saturating_sub(shares_cut);
            v.total_stake  = v.total_stake.saturating_sub(cut);

            d.shares = new_shares;
            d.reward_debt = mul_div(d.shares, v.acc_rps, RPS_SCALE)?;
            if d.shares == 0 {
                self.store.remove_delegation(&d.delegator, &d.validator)?;
            } else {
                self.store.put_delegation(&d)?;
            }

            total_slashed = total_slashed.saturating_add(cut);
        }

        // Затем — незавершённые unbonding-записи, начатые ПОСЛЕ времени нарушения (Cosmos rule)
        let mut touched: Vec<UnbondingDelegation> = vec![];
        for d in self.store.delegators_of(&validator)? {
            if let Some(mut u) = self.store.get_unbonding(&d.delegator, &validator)? {
                let mut changed = false;
                for e in u.entries.iter_mut() {
                    if e.created_epoch > at_epoch {
                        let cut = (e.amount as u128)
                            .checked_mul(fraction_ppm as u128).ok_or(StakingError::MathOverflow)?
                            .checked_div(1_000_000).ok_or(StakingError::MathOverflow)? as Amount;
                        e.amount = e.amount.saturating_sub(cut);
                        total_slashed = total_slashed.saturating_add(cut);
                        changed = true;
                    }
                }
                if changed { touched.push(u); }
            }
        }
        for u in touched.into_iter() { self.store.put_unbonding(&u)?; }

        // Сам валидатор (self-bond) режется так же
        let self_cut = (v.self_bonded as u128)
            .checked_mul(fraction_ppm as u128).ok_or(StakingError::MathOverflow)?
            .checked_div(1_000_000).ok_or(StakingError::MathOverflow)? as Amount;
        v.self_bonded = v.self_bonded.saturating_sub(self_cut);
        v.total_stake = v.total_stake.saturating_sub(self_cut);
        total_slashed = total_slashed.saturating_add(self_cut);

        // Джейлим по факту критичных нарушений
        if matches!(reason, SlashReason::DoubleSign | SlashReason::SurroundVote | SlashReason::Downtime) {
            v.status = ValidatorStatus::Jailed;
        }

        self.store.put_validator(&v)?;
        self.store.emit(StakingEvent::Slashed { validator, reason, fraction_ppm, at_epoch, total_slashed })?;
        if v.self_bonded < v.min_self_bond {
            // при падении ниже минимального self-bond валидатор должен быть выведен из активного сета
            v.status = ValidatorStatus::Inactive;
            self.store.put_validator(&v)?;
            self.store.emit(StakingEvent::ValidatorStatusChanged { addr: validator, status: v.status })?;
        }

        Ok(total_slashed)
    }
}

// ---------- Тесты (минимальные инварианты) ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(x: u8) -> Address { let mut a=[0u8;32]; a[0]=x; a }

    #[test]
    fn delegate_and_unbond_flow() {
        let store = Arc::new(MemStorage::new());
        let eng = StakingEngine::new(store.clone(), StakingParams{
            max_active_validators: 100,
            unbonding_epochs: 3,
            min_commission_bps: 0,
            max_commission_step_bps: 10_000,
            slash_double_sign_ppm: 50_000,
            slash_downtime_ppm: 10_000,
        });

        // начальные балансы
        store.credit_balance(&addr(9), 1_000_000).unwrap();
        store.credit_balance(&addr(1), 1_000_000).unwrap();

        // создать валидатора (self-bond 100k)
        eng.create_validator(addr(1), 500, 50_000, 100_000, 0, &addr(1)).unwrap();

        // делегатор делегирует 200k
        eng.delegate(addr(9), addr(1), 200_000).unwrap();

        // начислим 30k наград -> комиссия 5% = 1500, нетто 28_500
        eng.distribute_rewards(addr(1), 30_000).unwrap();

        // делегатор начинает unbonding половины своих shares
        let v_before = store.get_validator(&addr(1)).unwrap().unwrap();
        let d_before = store.get_delegation(&addr(9), &addr(1)).unwrap().unwrap();
        let unstake = eng.undelegate(addr(9), addr(1), d_before.shares/2, 1).unwrap();
        assert!(unstake > 0);

        // через 3 эпохи вывод возможен
        assert!(eng.withdraw_unbonded(addr(9), addr(1), 3).is_ok());

        // слэшинг 5% по даунтайму
        let _slashed = eng.slash(addr(1), SlashReason::Downtime, 50_000, 2).unwrap(); // 5%
        let v_after = store.get_validator(&addr(1)).unwrap().unwrap();
        assert!(matches!(v_after.status, ValidatorStatus::Jailed));
    }
}

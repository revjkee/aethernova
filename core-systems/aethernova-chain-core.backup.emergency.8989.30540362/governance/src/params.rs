// aethernova-chain-core/governance/src/params.rs
#![forbid(unsafe_code)]
//! Governance parameters for Aethernova Chain Core.
//!
//! - Immutable parameters: фиксируются при запуске сети (chain_id, genesis, halving).
//! - Governed parameters: изменяются через on-chain governance с отложенным вступлением.
//! - Halving: безопасный расчёт субсидии по высоте блока с нижней границей.
//! - Scheduler: обновления параметров по высоте блока, защита гонок (RwLock).
//! - Validation: диапазоны значений, типобезопасные ключи/значения.
//! - Versioning & snapshots: монотонный `version`, снимки для телеметрии.
//!
//! Зависимостей нет (std-only). Для сериализации можно добавить serde при необходимости.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

/// 32-байтный хэш (например, genesis hash).
pub type Hash32 = [u8; 32];

/// Неизменяемые параметры сети (фиксируются при генезисе).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImmutableParams {
    pub chain_id: u64,
    pub genesis_time_unix: u64,
    pub genesis_block_hash: Hash32,
    /// Целевое время блока (сек).
    pub target_block_time_sec: u64,
    /// Максимальный размер блока (байт).
    pub max_block_size_bytes: u64,
    /// Halving-настройки эмиссии.
    pub halving: HalvingParams,
}

/// Настройки halving (половиния эмиссии).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalvingParams {
    /// Начальная субсидия на блок (в минимальных единицах, например, в атто-токенах).
    pub initial_subsidy: u128,
    /// Интервал половиния в блоках (>0).
    pub interval_blocks: u64,
    /// Минимальная субсидия (нижняя граница; может быть 0).
    pub min_subsidy: u128,
}

impl HalvingParams {
    /// Расчёт субсидии на заданной высоте `height` (0-индексация).
    /// Формула: subsidy = max(initial >> epochs, min_subsidy), где epochs = height / interval.
    pub fn block_subsidy(&self, height: u64) -> u128 {
        if self.interval_blocks == 0 {
            return self.min_subsidy; // защита от деления на 0
        }
        let epochs = height / self.interval_blocks;
        // Сдвиг вправо на количество эпох равносилен делению на 2^epochs; безопасно ограничиваемся 127 шагами.
        // Если epochs >= 128, результат гарантированно 0 и затем clamp к min_subsidy.
        let sub = if epochs >= 128 {
            0u128
        } else {
            self.initial_subsidy.saturating_shr(epochs as u32)
        };
        sub.max(self.min_subsidy)
    }

    /// Проверка корректности параметров halving.
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.interval_blocks == 0 {
            return Err(ParamError::Invalid("halving.interval_blocks must be > 0"));
        }
        if self.min_subsidy > self.initial_subsidy {
            return Err(ParamError::Invalid("halving.min_subsidy > halving.initial_subsidy"));
        }
        Ok(())
    }
}

/// Управляемые параметры (меняются через governance).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedParams {
    /// Лимит газа блока.
    pub max_block_gas: u64,
    /// Целевая загрузка газа для EIP-1559-подобной модели, если используется.
    pub target_block_gas: u64,
    /// Максимальная относительная смена baseFee за блок (деноминатор: 8 => ±12.5%).
    pub base_fee_max_change_den: u32,
    /// Минимальный tip per gas (в минимальных единицах).
    pub min_tip_per_gas: u128,
    /// Лимит мемпула по транзакциям (soft cap для выбора, может отличаться от внутренних лимитов пула).
    pub mempool_soft_cap: u64,
}

impl GovernedParams {
    /// Базовые безопасные границы.
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.max_block_gas < 100_000 || self.max_block_gas > 50_000_000_000 {
            return Err(ParamError::OutOfRange("max_block_gas out of range [1e5, 5e10]"));
        }
        if self.target_block_gas == 0 || self.target_block_gas > self.max_block_gas {
            return Err(ParamError::Invalid("target_block_gas must be in (0, max_block_gas]"));
        }
        if !(1..=1024).contains(&self.base_fee_max_change_den) {
            return Err(ParamError::OutOfRange("base_fee_max_change_den must be in [1,1024]"));
        }
        // min_tip_per_gas свободен, но ограничим верх разумно (нефундаментально, защита от переполнений).
        if self.min_tip_per_gas > u128::MAX / 2 {
            return Err(ParamError::OutOfRange("min_tip_per_gas too large"));
        }
        if self.mempool_soft_cap == 0 || self.mempool_soft_cap > 10_000_000 {
            return Err(ParamError::OutOfRange("mempool_soft_cap out of range (0, 10_000_000]"));
        }
        Ok(())
    }
}

/// Тип ключей управляемых параметров.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamKey {
    MaxBlockGas,
    TargetBlockGas,
    BaseFeeMaxChangeDen,
    MinTipPerGas,
    MempoolSoftCap,
}

/// Универсальное значение параметра.
#[derive(Clone, Debug, PartialEq)]
pub enum ParamValue {
    U64(u64),
    U128(u128),
    U32(u32),
}

impl fmt::Display for ParamValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamValue::U64(v) => write!(f, "{}", v),
            ParamValue::U128(v) => write!(f, "{}", v),
            ParamValue::U32(v) => write!(f, "{}", v),
        }
    }
}

/// Ошибки параметров/управления.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ParamError {
    #[error("invalid parameter: {0}")]
    Invalid(&'static str),
    #[error("out of range: {0}")]
    OutOfRange(&'static str),
    #[error("unknown key")]
    UnknownKey,
    #[error("guard rejected update")]
    GuardRejected,
    #[error("pending update exists for this key at same height")]
    DuplicatePending,
}

/// Описание запланированного обновления параметра.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamUpdate {
    pub height_effective: u64,
    pub key: ParamKey,
    pub value: ParamValue,
    /// Произвольные метаданные (например, хеш предложения governance).
    pub meta: Option<Hash32>,
}

/// Интерфейс авторизации governance-изменений.
pub trait GovernanceGuard: Send + Sync + 'static {
    /// Возвратить true для разрешения применения/планирования обновления.
    fn allow(&self, current_height: u64, update: &ParamUpdate) -> bool;
}

/// Guard по умолчанию: пропускает всё (для тестовых конфигураций/стенда).
pub struct AllowAllGuard;
impl GovernanceGuard for AllowAllGuard {
    fn allow(&self, _current_height: u64, _update: &ParamUpdate) -> bool {
        true
    }
}

/// Потокобезопасный реестр параметров и планировщик обновлений.
pub struct ParamRegistry {
    inner: RwLock<ParamState>,
    guard: Arc<dyn GovernanceGuard>,
}

/// Внутреннее состояние под RwLock.
#[derive(Clone, Debug)]
struct ParamState {
    version: u64,
    height_applied: u64,
    imm: ImmutableParams,
    gov: GovernedParams,
    /// Запланированные обновления: height -> список.
    pending: BTreeMap<u64, Vec<ParamUpdate>>,
    /// Для быстрого обнаружения дубликатов: (height,key).
    pending_index: BTreeSet<(u64, ParamKey)>,
}

impl ParamRegistry {
    /// Создать реестр с guard (или `AllowAllGuard`).
    pub fn new(imm: ImmutableParams, gov: GovernedParams, guard: Option<Arc<dyn GovernanceGuard>>) -> Result<Self, ParamError> {
        imm.halving.validate()?;
        gov.validate()?;
        Ok(Self {
            inner: RwLock::new(ParamState {
                version: 1,
                height_applied: 0,
                imm,
                gov,
                pending: BTreeMap::new(),
                pending_index: BTreeSet::new(),
            }),
            guard: guard.unwrap_or_else(|| Arc::new(AllowAllGuard)),
        })
    }

    /// Текущая версия конфигурации (монотонно увеличивается при каждом применении обновлений).
    pub fn version(&self) -> u64 {
        self.inner.read().unwrap().version
    }

    /// Снимок неизменяемых параметров.
    pub fn immutables(&self) -> ImmutableParams {
        self.inner.read().unwrap().imm.clone()
    }

    /// Снимок управляемых параметров.
    pub fn governed(&self) -> GovernedParams {
        self.inner.read().unwrap().gov.clone()
    }

    /// Расчёт субсидии на высоте `height` согласно immutable halving-параметрам.
    pub fn block_subsidy(&self, height: u64) -> u128 {
        let st = self.inner.read().unwrap();
        st.imm.halving.block_subsidy(height)
    }

    /// Запланировать обновление параметра (вступает в силу на `height_effective`).
    pub fn schedule_update(&self, current_height: u64, update: ParamUpdate) -> Result<(), ParamError> {
        if !self.guard.allow(current_height, &update) {
            return Err(ParamError::GuardRejected);
        }
        let mut st = self.inner.write().unwrap();

        // запрещаем дубликат того же ключа на ту же высоту (неоднозначность порядка).
        let idx_key = (update.height_effective, update.key);
        if st.pending_index.contains(&idx_key) {
            return Err(ParamError::DuplicatePending);
        }

        // валидация значения без его применения
        Self::validate_candidate_value(update.key, &update.value, &st.gov)?;

        st.pending.entry(update.height_effective).or_default().push(update.clone());
        st.pending_index.insert(idx_key);
        Ok(())
    }

    /// Вызывается консенсусным слоем при достижении новой высоты — применяет все готовые обновления.
    pub fn on_new_height_apply(&self, new_height: u64) -> Result<AppliedBatch, ParamError> {
        let mut st = self.inner.write().unwrap();
        if new_height <= st.height_applied {
            return Ok(AppliedBatch { version: st.version, applied: vec![] });
        }

        let ready_heights: Vec<u64> = st.pending
            .range(..=new_height)
            .map(|(h, _)| *h)
            .collect();

        let mut applied = Vec::new();
        for h in ready_heights {
            if let Some(mut updates) = st.pending.remove(&h) {
                for u in updates.drain(..) {
                    Self::apply_one(&mut st, &u)?;
                    st.pending_index.remove(&(h, u.key));
                    applied.push(u);
                }
            }
        }

        if !applied.is_empty() {
            st.version = st.version.saturating_add(1);
        }
        st.height_applied = new_height;

        Ok(AppliedBatch { version: st.version, applied })
    }

    /// Проверка значения в контексте текущих gov-параметров (для cross-constraints).
    fn validate_candidate_value(key: ParamKey, val: &ParamValue, current: &GovernedParams) -> Result<(), ParamError> {
        match (key, val) {
            (ParamKey::MaxBlockGas, ParamValue::U64(v)) => {
                let next = GovernedParams { max_block_gas: *v, ..current.clone() };
                next.validate()
            }
            (ParamKey::TargetBlockGas, ParamValue::U64(v)) => {
                let next = GovernedParams { target_block_gas: *v, ..current.clone() };
                next.validate()
            }
            (ParamKey::BaseFeeMaxChangeDen, ParamValue::U32(v)) => {
                let next = GovernedParams { base_fee_max_change_den: *v, ..current.clone() };
                next.validate()
            }
            (ParamKey::MinTipPerGas, ParamValue::U128(v)) => {
                let next = GovernedParams { min_tip_per_gas: *v, ..current.clone() };
                next.validate()
            }
            (ParamKey::MempoolSoftCap, ParamValue::U64(v)) => {
                let next = GovernedParams { mempool_soft_cap: *v, ..current.clone() };
                next.validate()
            }
            _ => Err(ParamError::UnknownKey),
        }
    }

    fn apply_one(st: &mut ParamState, u: &ParamUpdate) -> Result<(), ParamError> {
        match (u.key, &u.value) {
            (ParamKey::MaxBlockGas, ParamValue::U64(v)) => {
                st.gov.max_block_gas = *v;
                st.gov.validate()?
            }
            (ParamKey::TargetBlockGas, ParamValue::U64(v)) => {
                st.gov.target_block_gas = *v;
                st.gov.validate()?
            }
            (ParamKey::BaseFeeMaxChangeDen, ParamValue::U32(v)) => {
                st.gov.base_fee_max_change_den = *v;
                st.gov.validate()?
            }
            (ParamKey::MinTipPerGas, ParamValue::U128(v)) => {
                st.gov.min_tip_per_gas = *v;
                st.gov.validate()?
            }
            (ParamKey::MempoolSoftCap, ParamValue::U64(v)) => {
                st.gov.mempool_soft_cap = *v;
                st.gov.validate()?
            }
            _ => return Err(ParamError::UnknownKey),
        }
        Ok(())
    }
}

/// Результат применения пакета обновлений на высоте.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedBatch {
    pub version: u64,
    pub applied: Vec<ParamUpdate>,
}

/* ----------------------- Builders & Defaults ------------------------ */

/// Упрощённый билдер для неизменяемых параметров.
pub struct ImmutableBuilder {
    chain_id: u64,
    genesis_time_unix: u64,
    genesis_block_hash: Hash32,
    target_block_time_sec: u64,
    max_block_size_bytes: u64,
    halving: HalvingParams,
}

impl ImmutableBuilder {
    pub fn new(chain_id: u64, genesis_time_unix: u64, genesis_block_hash: Hash32) -> Self {
        Self {
            chain_id,
            genesis_time_unix,
            genesis_block_hash,
            target_block_time_sec: 2,
            max_block_size_bytes: 2 * 1024 * 1024,
            halving: HalvingParams { initial_subsidy: 0, interval_blocks: 1, min_subsidy: 0 },
        }
    }
    pub fn target_block_time_sec(mut self, v: u64) -> Self { self.target_block_time_sec = v; self }
    pub fn max_block_size_bytes(mut self, v: u64) -> Self { self.max_block_size_bytes = v; self }
    pub fn halving(mut self, h: HalvingParams) -> Self { self.halving = h; self }
    pub fn build(self) -> Result<ImmutableParams, ParamError> {
        let imm = ImmutableParams {
            chain_id: self.chain_id,
            genesis_time_unix: self.genesis_time_unix,
            genesis_block_hash: self.genesis_block_hash,
            target_block_time_sec: self.target_block_time_sec,
            max_block_size_bytes: self.max_block_size_bytes,
            halving: self.halving,
        };
        imm.halving.validate()?;
        Ok(imm)
    }
}

/// Билдер управляемых параметров.
pub struct GovernedBuilder(GovernedParams);
impl GovernedBuilder {
    pub fn new() -> Self {
        Self(GovernedParams {
            max_block_gas: 30_000_000,
            target_block_gas: 15_000_000,
            base_fee_max_change_den: 8,
            min_tip_per_gas: 0,
            mempool_soft_cap: 300_000,
        })
    }
    pub fn max_block_gas(mut self, v: u64) -> Self { self.0.max_block_gas = v; self }
    pub fn target_block_gas(mut self, v: u64) -> Self { self.0.target_block_gas = v; self }
    pub fn base_fee_max_change_den(mut self, v: u32) -> Self { self.0.base_fee_max_change_den = v; self }
    pub fn min_tip_per_gas(mut self, v: u128) -> Self { self.0.min_tip_per_gas = v; self }
    pub fn mempool_soft_cap(mut self, v: u64) -> Self { self.0.mempool_soft_cap = v; self }
    pub fn build(self) -> Result<GovernedParams, ParamError> { self.0.validate()?; Ok(self.0) }
}

/* ------------------------------ Tests ------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash32 { [b; 32] }

    #[test]
    fn halving_basic() {
        let hp = HalvingParams { initial_subsidy: 1_000_000_000u128, interval_blocks: 100, min_subsidy: 1 };
        assert_eq!(hp.block_subsidy(0), 1_000_000_000);
        assert_eq!(hp.block_subsidy(99), 1_000_000_000);
        assert_eq!(hp.block_subsidy(100), 500_000_000);
        assert_eq!(hp.block_subsidy(199), 500_000_000);
        assert_eq!(hp.block_subsidy(200), 250_000_000);
        // далеко в будущем — не опускаемся ниже минимума
        assert_eq!(hp.block_subsidy(100 * 200), 1);
    }

    #[test]
    fn halving_edge_cases() {
        // interval == 0 => защитное поведение (возврат минимума)
        let hp = HalvingParams { initial_subsidy: 10, interval_blocks: 0, min_subsidy: 3 };
        assert_eq!(hp.block_subsidy(10), 3);

        // min > initial => некорректно
        let bad = HalvingParams { initial_subsidy: 10, interval_blocks: 10, min_subsidy: 11 };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn gov_validation() {
        let ok = GovernedParams {
            max_block_gas: 30_000_000,
            target_block_gas: 15_000_000,
            base_fee_max_change_den: 8,
            min_tip_per_gas: 0,
            mempool_soft_cap: 300_000,
        };
        assert!(ok.validate().is_ok());

        let bad = GovernedParams { target_block_gas: 0, ..ok.clone() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn registry_schedule_and_apply() {
        let imm = ImmutableBuilder::new(123, 1_700_000_000, h(1))
            .target_block_time_sec(2)
            .max_block_size_bytes(2 * 1024 * 1024)
            .halving(HalvingParams { initial_subsidy: 100, interval_blocks: 10, min_subsidy: 1 })
            .build()
            .unwrap();
        let gov = GovernedBuilder::new().build().unwrap();
        let reg = ParamRegistry::new(imm, gov, None).unwrap();

        // schedule update at height 50
        reg.schedule_update(0, ParamUpdate {
            height_effective: 50,
            key: ParamKey::MaxBlockGas,
            value: ParamValue::U64(40_000_000),
            meta: None,
        }).unwrap();

        // nothing applied before height 50
        let batch = reg.on_new_height_apply(49).unwrap();
        assert!(batch.applied.is_empty());

        // apply at height 50
        let batch = reg.on_new_height_apply(50).unwrap();
        assert_eq!(batch.applied.len(), 1);
        let g = reg.governed();
        assert_eq!(g.max_block_gas, 40_000_000);

        // duplicate pending for same (height,key) should be rejected
        let dup = reg.schedule_update(51, ParamUpdate {
            height_effective: 60,
            key: ParamKey::MaxBlockGas,
            value: ParamValue::U64(41_000_000),
            meta: None,
        });
        assert!(dup.is_ok());
        let dup2 = reg.schedule_update(52, ParamUpdate {
            height_effective: 60,
            key: ParamKey::MaxBlockGas,
            value: ParamValue::U64(42_000_000),
            meta: None,
        });
        assert_eq!(dup2.err(), Some(ParamError::DuplicatePending));
    }

    struct DenyAll;
    impl GovernanceGuard for DenyAll { fn allow(&self, _h: u64, _u: &ParamUpdate) -> bool { false } }

    #[test]
    fn guard_blocks_updates() {
        let imm = ImmutableBuilder::new(1, 0, h(7))
            .halving(HalvingParams { initial_subsidy: 1, interval_blocks: 1, min_subsidy: 0 })
            .build().unwrap();
        let gov = GovernedBuilder::new().build().unwrap();
        let reg = ParamRegistry {
            inner: RwLock::new(ParamState {
                version: 1,
                height_applied: 0,
                imm,
                gov,
                pending: BTreeMap::new(),
                pending_index: BTreeSet::new(),
            }),
            guard: Arc::new(DenyAll),
        };
        let res = reg.schedule_update(0, ParamUpdate {
            height_effective: 10,
            key: ParamKey::MempoolSoftCap,
            value: ParamValue::U64(1000),
            meta: None,
        });
        assert_eq!(res.err(), Some(ParamError::GuardRejected));
    }
}

/* ----------------------- Minimal thiserror shim ---------------------- */
// Чтобы не тянуть внешние зависимости, включаем компактный shim для Error/Display.
// В реальном проекте можно заменить на crate `thiserror`.
mod thiserror {
    pub use std::fmt::{Display, Formatter, Result as FmtResult};
    pub trait Error: Display {}
    #[macro_export]
    macro_rules! __derive_error {
        ($name:ident) => {};
    }
    pub use std as __std;
    pub mod ErrorImpl {
        use super::*;
        pub trait Err: Display {}
    }
    // Небольшой макрос-имитация `thiserror::Error` для локального использования.
    #[allow(non_snake_case)]
    pub mod __shim {
        pub use std::fmt::{Display, Formatter, Result as FmtResult};
        pub trait Error: Display {}
    }
    // Мини-атрибут для совместимости: #[derive(thiserror::Error)]
    pub use crate::governance::params::__derive_error as Error;
}

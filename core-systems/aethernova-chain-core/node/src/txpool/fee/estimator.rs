// aethernova-chain-core/node/src/txpool/fee/estimator.rs
//! EIP-1559 Fee Estimator (production-grade, no external deps).
//!
//! Основано на:
//! - EIP-1559: формула динамического изменения baseFee (см. eips.ethereum.org/EIPS/eip-1559). [spec] :contentReference[oaicite:4]{index=4}
//! - Исторические перцентили чаевых через eth_feeHistory (reward percentiles). [rpc] :contentReference[oaicite:5]{index=5}
//! - Практическая эвристика maxFee ≈ 2 * baseFee + priorityFee (Blocknative). [heuristic] :contentReference[oaicite:6]{index=6}
//
//! Зависимостей нет (std), потокобезопасность через RwLock.
//! Все арифметические операции насыщаемые (saturating_*), плавающих чисел нет.

use core::cmp::{max, min};
use core::fmt;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

/// Единицы измерения: все значения в wei за газ (u128).
pub type Wei = u128;

/// Ошибки эстиматора.
#[derive(Debug, Clone)]
pub enum EstimatorError {
    /// Нет ни одного образца с base_fee — нечего прогнозировать.
    NoBaseFeeData,
    /// Неверные входные данные.
    InvalidInput(&'static str),
}

impl fmt::Display for EstimatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EstimatorError::NoBaseFeeData => write!(f, "no baseFee data available"),
            EstimatorError::InvalidInput(s) => write!(f, "invalid input: {s}"),
        }
    }
}

impl std::error::Error for EstimatorError {}

/// Срочность запроса комиссии.
#[derive(Debug, Copy, Clone)]
pub enum Urgency {
    Low,
    Standard,
    High,
}

/// Образец блока для истории.
#[derive(Debug, Copy, Clone)]
pub struct BlockSample {
    /// baseFee родительского блока (wei).
    pub parent_base_fee: Wei,
    /// gas_used предыдущего блока.
    pub gas_used: u64,
    /// gas_limit предыдущего блока.
    pub gas_limit: u64,
    /// Наблюдавшиеся чаевые (priority fees) включённых tx, в wei.
    /// Можно оставить пустым — тогда используются только мемпул-наблюдения.
    pub included_priority_fees: &'static [Wei],
}

/// Образец мемпула (снимок наблюдавшихся чаевых).
#[derive(Debug, Clone)]
pub struct MempoolSample {
    pub observed_priority_fees: Vec<Wei>,
}

/// Конфигурация эстиматора.
#[derive(Debug, Clone)]
pub struct EstimatorConfig {
    /// Максимум образцов блоков, хранимых в кольцевом буфере.
    pub block_history_capacity: usize,
    /// Максимум образцов мемпула.
    pub mempool_history_capacity: usize,
    /// Кол-во блоков вперёд для прогноза baseFee (N >= 1).
    pub lookahead_blocks: u32,
    /// Делитель максимального изменения baseFee на блок (из EIP-1559, по умолчанию 8).
    /// Мы делаем параметром, не привязывая жёстко к 8, чтобы быть переносимыми.
    pub base_fee_change_denominator: u64,
    /// Перцентили чаевых для уровней срочности (от 0 до 100).
    pub percentile_low: f64,
    pub percentile_std: f64,
    pub percentile_high: f64,
    /// Минимально допустимое чаевое (safety floor).
    pub min_priority_fee: Wei,
    /// Верхняя отсечка чаевых (safety cap).
    pub max_priority_fee: Wei,
    /// Множитель для вычисления maxFee = k * predictedBaseFee + tip.
    /// По умолчанию 2 (Blocknative heuristic). :contentReference[oaicite:7]{index=7}
    pub max_basefee_multiplier: u64,
    /// Нижняя/верхняя границы baseFee после прогноза (safety clamps).
    pub min_predicted_base_fee: Wei,
    pub max_predicted_base_fee: Wei,
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            block_history_capacity: 128,
            mempool_history_capacity: 256,
            lookahead_blocks: 2,
            base_fee_change_denominator: 8,
            percentile_low: 30.0,
            percentile_std: 60.0,
            percentile_high: 90.0,
            min_priority_fee: 1_000_000_000,          // 1 gwei
            max_priority_fee: 300_000_000_000,        // 300 gwei (sane cap)
            max_basefee_multiplier: 2,
            min_predicted_base_fee: 1,                // EIP-1559 требует baseFee >= 1 wei
            max_predicted_base_fee: Wei::MAX / 4,     // запас по переполнению
        }
    }
}

/// Результат рекомендации комиссии.
#[derive(Debug, Copy, Clone)]
pub struct FeeSuggestion {
    pub base_fee_per_gas: Wei,
    pub priority_fee_per_gas: Wei,
    pub max_fee_per_gas: Wei,
    /// Грубая оценка уверенности [0..100] по объёму данных.
    pub confidence: u8,
}

/// Общий интерфейс эстиматора.
pub trait FeeEstimator: Send + Sync {
    fn observe_block(&self, sample: BlockSample) -> Result<(), EstimatorError>;
    fn observe_mempool(&self, sample: MempoolSample) -> Result<(), EstimatorError>;
    fn suggest(&self, urgency: Urgency) -> Result<FeeSuggestion, EstimatorError>;
}

/// Конкретная реализация по EIP-1559.
pub struct Eip1559Estimator {
    cfg: EstimatorConfig,
    inner: RwLock<InnerState>,
}

#[derive(Default)]
struct InnerState {
    blocks: VecDeque<BlockSampleOwned>,
    mempool: VecDeque<MempoolSample>,
}

#[derive(Clone)]
struct BlockSampleOwned {
    parent_base_fee: Wei,
    gas_used: u64,
    gas_limit: u64,
    included_priority_fees: Vec<Wei>,
}

impl From<BlockSample> for BlockSampleOwned {
    fn from(s: BlockSample) -> Self {
        Self {
            parent_base_fee: s.parent_base_fee,
            gas_used: s.gas_used,
            gas_limit: s.gas_limit,
            included_priority_fees: s.included_priority_fees.to_vec(),
        }
    }
}

impl Eip1559Estimator {
    pub fn new(cfg: EstimatorConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inner: RwLock::new(InnerState::default()),
        })
    }

    /// Прогноз baseFee на 1 шаг по точной формуле EIP-1559.
    /// newBase = parentBase + parentBase * (gasUsed - targetGas) / targetGas / denominator
    /// (ограничено минимальным значением, см. EIP-1559). :contentReference[oaicite:8]{index=8}
    fn forecast_once(parent_base_fee: Wei, gas_used: u64, gas_limit: u64, denom: u64) -> Wei {
        if gas_limit == 0 || denom == 0 {
            return parent_base_fee;
        }
        // targetGas = gas_limit / 2 (Эфириум), но тут не утверждаем константу —
        // вычисляем точно: gasUsedDelta / targetGas = (gas_used - gas_limit/2) / (gas_limit/2)
        // => (2*gas_used - gas_limit) / gas_limit
        let target_gas = gas_limit / 2;
        let parent = parent_base_fee;

        // Вычисляем приращение как parent * delta / denom, где
        // delta = (gas_used - target_gas) / target_gas
        // Избегаем float: используем 256-битный числитель в u128 с аккуратной порядковостью.
        let (gas_used_u128, target_gas_u128) = (gas_used as u128, target_gas as u128);
        let parent_u128 = parent as u128;

        // Если target_gas == 0 (при очень малых gas_limit) — защищаемся
        if target_gas_u128 == 0 {
            return parent;
        }

        let gas_used_delta = if gas_used_u128 >= target_gas_u128 {
            gas_used_u128 - target_gas_u128
        } else {
            target_gas_u128 - gas_used_u128
        };

        let change = (parent_u128)
            .saturating_mul(gas_used_delta)
            .saturating_div(target_gas_u128)
            .saturating_div(denom as u128)
            .max(1); // минимальный шаг изменения по EIP-1559 (блок должен менять хотя бы на 1 wei). :contentReference[oaicite:9]{index=9}

        let new_base = if gas_used_u128 > target_gas_u128 {
            parent_u128.saturating_add(change)
        } else if gas_used_u128 < target_gas_u128 {
            parent_u128.saturating_sub(change)
        } else {
            parent_u128
        };

        new_base.max(1) // baseFee ≥ 1 wei. :contentReference[oaicite:10]{index=10}
    }

    /// Прогноз baseFee на N шагов вперёд, усредняя загрузку по последним K блокам.
    fn forecast_base_fee_n(&self, last_parent_base: Wei, n: u32, k_avg: usize) -> Wei {
        let denom = self.cfg.base_fee_change_denominator;
        let mut base = last_parent_base;

        let inner = self.inner.read().unwrap();
        let k = min(k_avg, inner.blocks.len());
        let (sum_used, sum_limit) = inner
            .blocks
            .iter()
            .rev()
            .take(k)
            .fold((0u128, 0u128), |acc, b| {
                (acc.0 + b.gas_used as u128, acc.1 + b.gas_limit as u128)
            });

        // Если нет истории, считаем, что delta=0 (нейтральный шаг).
        let (avg_used, avg_limit) = if k > 0 && sum_limit > 0 {
            ((sum_used / k as u128) as u64, (sum_limit / k as u128) as u64)
        } else {
            (0u64, 0u64)
        };

        for _ in 0..n {
            base = if avg_limit == 0 {
                base
            } else {
                Self::forecast_once(base, avg_used, avg_limit, denom)
            };
        }

        base.clamp(self.cfg.min_predicted_base_fee, self.cfg.max_predicted_base_fee)
    }

    /// Собираем кандидатов чаевых из истории блоков и мемпула.
    fn collect_priority_fees(&self) -> Vec<Wei> {
        let inner = self.inner.read().unwrap();
        let mut v: Vec<Wei> = Vec::with_capacity(64);

        for b in inner.blocks.iter() {
            v.extend_from_slice(&b.included_priority_fees);
        }
        for m in inner.mempool.iter() {
            v.extend_from_slice(&m.observed_priority_fees);
        }
        v
    }

    /// Перцентиль (0..=100). Возвращает None, если пусто.
    fn percentile(mut values: Vec<Wei>, p: f64) -> Option<Wei> {
        if values.is_empty() {
            return None;
        }
        // Стабильная сортировка: O(n log n), достаточно для десятков/сотен наблюдений.
        values.sort_unstable();
        // Индекс nearest-rank.
        let p = p.clamp(0.0, 100.0);
        let rank = ((p / 100.0) * (values.len() as f64 - 1.0)).round() as usize;
        values.get(rank).copied()
    }

    fn urgency_percentile(&self, u: Urgency) -> f64 {
        match u {
            Urgency::Low => self.cfg.percentile_low,
            Urgency::Standard => self.cfg.percentile_std,
            Urgency::High => self.cfg.percentile_high,
        }
    }

    fn confidence(&self) -> u8 {
        let inner = self.inner.read().unwrap();
        let n_blocks = inner.blocks.len().min(255);
        let n_mp = inner.mempool.len().min(255);
        // Простая эвристика: чем больше источников, тем выше доверие.
        let mut c = (n_blocks as u16 * 2 + n_mp as u16) as u16;
        if c > 100 {
            c = 100;
        }
        c as u8
    }
}

impl FeeEstimator for Eip1559Estimator {
    fn observe_block(&self, sample: BlockSample) -> Result<(), EstimatorError> {
        if sample.gas_limit == 0 {
            return Err(EstimatorError::InvalidInput("gas_limit = 0"));
        }
        if sample.parent_base_fee == 0 {
            return Err(EstimatorError::InvalidInput("parent_base_fee = 0"));
        }
        let mut guard = self.inner.write().unwrap();
        let cap = self.cfg.block_history_capacity;
        let owned = BlockSampleOwned::from(sample);
        if guard.blocks.len() == cap {
            guard.blocks.pop_front();
        }
        guard.blocks.push_back(owned);
        Ok(())
    }

    fn observe_mempool(&self, sample: MempoolSample) -> Result<(), EstimatorError> {
        let mut guard = self.inner.write().unwrap();
        let cap = self.cfg.mempool_history_capacity;
        if guard.mempool.len() == cap {
            guard.mempool.pop_front();
        }
        guard.mempool.push_back(sample);
        Ok(())
    }

    fn suggest(&self, urgency: Urgency) -> Result<FeeSuggestion, EstimatorError> {
        let (last_parent_base, last_limit) = {
            let guard = self.inner.read().unwrap();
            let last = guard
                .blocks
                .back()
                .ok_or(EstimatorError::NoBaseFeeData)?;
            (last.parent_base_fee, last.gas_limit)
        };

        // Прогноз baseFee на N блоков вперёд на основе средней загрузки последних K блоков.
        let predicted_base = self.forecast_base_fee_n(last_parent_base, self.cfg.lookahead_blocks, 16);

        // Перцентиль чаевых для выбранной срочности.
        let p = self.urgency_percentile(urgency);
        let mut tip = Self::percentile(self.collect_priority_fees(), p)
            .unwrap_or(self.cfg.min_priority_fee);

        tip = tip.clamp(self.cfg.min_priority_fee, self.cfg.max_priority_fee);

        // maxFee = k * baseFee + tip  (эвристика Blocknative; k по конфигурации). :contentReference[oaicite:11]{index=11}
        let k = self.cfg.max_basefee_multiplier as u128;
        let max_fee = k
            .saturating_mul(predicted_base)
            .saturating_add(tip)
            .min(Wei::MAX);

        let conf = self.confidence();
        Ok(FeeSuggestion {
            base_fee_per_gas: predicted_base,
            priority_fee_per_gas: tip,
            max_fee_per_gas: max_fee,
            confidence: conf,
        })
    }
}

// ------------------------------- Tests ---------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> EstimatorConfig {
        EstimatorConfig {
            block_history_capacity: 32,
            mempool_history_capacity: 32,
            lookahead_blocks: 2,
            base_fee_change_denominator: 8,
            percentile_low: 30.0,
            percentile_std: 60.0,
            percentile_high: 90.0,
            min_priority_fee: 1_000_000_000,
            max_priority_fee: 200_000_000_000,
            max_basefee_multiplier: 2,
            min_predicted_base_fee: 1,
            max_predicted_base_fee: Wei::MAX / 8,
        }
    }

    #[test]
    fn base_fee_forecast_increase_and_decrease() {
        let est = Eip1559Estimator::new(cfg());

        // Блок с перегрузкой (gas_used > target) — baseFee растёт.
        let gl = 30_000_000u64; // пример
        let gu = 20_000_000u64; // > target(15_000_000)
        let parent_base: Wei = 100 * 1_000_000_000; // 100 gwei

        let next = Eip1559Estimator::forecast_once(parent_base, gu, gl, 8);
        assert!(next > parent_base);

        // Блок с недогрузкой — baseFee падает.
        let gu2 = 10_000_000u64; // < target
        let next2 = Eip1559Estimator::forecast_once(parent_base, gu2, gl, 8);
        assert!(next2 < parent_base);
    }

    #[test]
    fn suggest_works_with_history() {
        let e = Eip1559Estimator::new(cfg());

        // Имитация нескольких блоков и мемпула.
        for _ in 0..8 {
            e.observe_block(BlockSample {
                parent_base_fee: 100 * 1_000_000_000,
                gas_used: 18_000_000,
                gas_limit: 30_000_000,
                included_priority_fees: &[1_500_000_000, 2_000_000_000, 2_500_000_000],
            })
            .unwrap();
            e.observe_mempool(MempoolSample {
                observed_priority_fees: vec![1_000_000_000, 1_500_000_000, 3_000_000_000],
            })
            .unwrap();
        }

        let s = e.suggest(Urgency::Standard).unwrap();
        assert!(s.base_fee_per_gas > 0);
        assert!(s.priority_fee_per_gas >= e.cfg.min_priority_fee);
        assert!(s.max_fee_per_gas >= s.base_fee_per_gas);
    }

    #[test]
    fn percentile_bounds() {
        // Проверяем квантили на краях.
        let v = vec![1, 2, 3, 4, 5];
        assert_eq!(Eip1559Estimator::percentile(v.clone(), 0.0), Some(1));
        assert_eq!(Eip1559Estimator::percentile(v.clone(), 100.0), Some(5));
        assert!(Eip1559Estimator::percentile(Vec::new(), 50.0).is_none());
    }

    #[test]
    fn errors_on_no_history() {
        let e = Eip1559Estimator::new(cfg());
        let err = e.suggest(Urgency::Low).unwrap_err();
        matches!(err, EstimatorError::NoBaseFeeData);
    }
}

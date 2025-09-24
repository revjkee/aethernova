// node/src/consensus/finality/mod.rs
//! Finality gadget + checkpoints (industrial-grade skeleton).
//!
//! Дизайн:
//! - Абстракции FinalityStorage и ValidatorSet (позволяет подменять БД/руntime).
//! - Модель Casper FFG: голоса вида (source_cp -> target_cp, round).
//! - Порог финализации по супермажорити (по умолчанию >= 2/3 голосовой силы).
//! - Состояния чекпойнтов: Created -> Justified -> Finalized.
//! - Анти-слэшинг проверки: double vote (двойное голосование в одном раунде),
//!   surround vote (окружение исторического голоса более поздним голосом с
//!   интервалом раундов/чекпойнтов).
//! - Потокобезопасная реализация на Mutex, пример in-memory стораджа.
//!
//! Теоретическая основа: Casper FFG (Buterin & Griffith), GRANDPA (Polkadot),
//! HotStuff/Tendermint (общие свойства финальности в BFT). См. источники:
//! Casper FFG: https://arxiv.org/pdf/1710.09437 ,
//! Polkadot GRANDPA spec: https://spec.polkadot.network/sect-finality ,
//! GRANDPA paper: https://arxiv.org/pdf/2007.01560 ,
//! HotStuff: https://arxiv.org/abs/1803.05069 ,
//! Tendermint consensus docs: https://docs.tendermint.com/master/tendermint-core/consensus/
//!
//! Данный модуль не содержит криптографии подписей и сетевого слоя — они
//! подключаются сверху (передаются проверенные подписи и роли валидаторов).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

// -------- Типы и доменная модель --------

pub type BlockNumber = u64;
pub type Round = u64;
pub type UnixMillis = u64;

/// Идентификатор валидатора (абстрактный 32-байтный ID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ValidatorId(pub [u8; 32]);

/// Идентификатор блока (hash + number).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BlockId {
    pub hash: [u8; 32],
    pub number: BlockNumber,
}

/// Идентификатор чекпойнта.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CheckpointId(pub [u8; 32]);

/// Состояние чекпойнта.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckpointState {
    Created,
    Justified,
    Finalized,
}

/// Чекпойнт.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub block: BlockId,
    pub round: Round,
    pub timestamp_ms: UnixMillis,
    pub parent: Option<CheckpointId>, // родительский чекпойнт (для FFG-связки)
    pub state: CheckpointState,
}

/// Голос валидатора в раунде `round` с FFG-связкой (source -> target).
#[derive(Clone, Debug)]
pub struct Vote {
    pub validator: ValidatorId,
    pub round: Round,
    pub source: CheckpointId,
    pub target: CheckpointId,
    /// Подпись валидатора над сообщением (проверяется вне модуля).
    pub signature: Vec<u8>,
}

/// Результат обработки голоса.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteOutcome {
    Accepted,
    RejectedAlreadyVoted,   // double vote (тот же раунд)
    RejectedSurroundVote,   // surround vote (нарушение правил Casper FFG)
    RejectedUnknownSource,  // неизвестный source cp
    RejectedUnknownTarget,  // неизвестный target cp
    RejectedOlderRound,
}

/// Ошибки работы движка финализации.
#[derive(thiserror::Error, Debug)]
pub enum FinalityError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("validator set error: {0}")]
    ValidatorSet(String),
    #[error("unknown checkpoint")]
    UnknownCheckpoint,
    #[error("invalid threshold config")]
    InvalidThreshold,
    #[error("logic error: {0}")]
    Logic(String),
}

/// Порог супермажорити (например, 2/3).
#[derive(Clone, Copy, Debug)]
pub struct Threshold {
    pub numer: u32,
    pub denom: u32,
}
impl Threshold {
    pub const fn two_thirds() -> Self { Self { numer: 2, denom: 3 } }
    pub fn is_reached(self, accumulated: u128, total: u128) -> bool {
        // accumulated / total >= numer/denom  <=>  accumulated*denom >= total*numer
        accumulated.saturating_mul(self.denom as u128) >= total.saturating_mul(self.numer as u128)
    }
}

// -------- Абстракции стораджа и валидатор-сета --------

/// Набор валидаторов с весами голосов.
pub trait ValidatorSet: Send + Sync + 'static {
    /// Общая голосовая сила.
    fn total_power(&self) -> u128;
    /// Вес конкретного валидатора (0 если не член сета).
    fn power_of(&self, id: &ValidatorId) -> u128;
}

/// Хранилище финалити-состояния.
pub trait FinalityStorage: Send + Sync + 'static {
    // Чекпойнты
    fn insert_checkpoint(&self, cp: Checkpoint) -> Result<(), FinalityError>;
    fn get_checkpoint(&self, id: &CheckpointId) -> Result<Option<Checkpoint>, FinalityError>;
    fn update_checkpoint_state(&self, id: &CheckpointId, st: CheckpointState) -> Result<(), FinalityError>;
    fn finalized_head(&self) -> Result<Option<Checkpoint>, FinalityError>;

    // Голоса
    fn record_vote(&self, vote: &Vote) -> Result<(), FinalityError>;
    fn has_voted_in_round(&self, v: &ValidatorId, round: Round) -> Result<bool, FinalityError>;
    fn last_vote_of(&self, v: &ValidatorId) -> Result<Option<Vote>, FinalityError>;

    // Агрегация для (round, source, target)
    fn add_vote_weight(&self, round: Round, source: CheckpointId, target: CheckpointId, weight: u128) -> Result<u128, FinalityError>;
    fn accumulated_weight(&self, round: Round, source: CheckpointId, target: CheckpointId) -> Result<u128, FinalityError>;
}

/// In-memory реализация FinalityStorage (потокобезопасная, для dev/тестов).
pub struct MemStorage {
    inner: Mutex<MemStorageInner>,
}
#[derive(Default)]
struct MemStorageInner {
    checkpoints: HashMap<CheckpointId, Checkpoint>,
    // финализованная вершина
    finalized: Option<CheckpointId>,
    // голоса валидатора по раундам (для анти-слэшинга)
    voted_rounds: HashMap<ValidatorId, BTreeSet<Round>>,
    last_vote: HashMap<ValidatorId, Vote>,
    // накопленные веса: (round, source, target) -> weight
    tallies: HashMap<(Round, CheckpointId, CheckpointId), u128>,
}
impl MemStorage {
    pub fn new() -> Self { Self { inner: Mutex::new(MemStorageInner::default()) } }
}
impl FinalityStorage for MemStorage {
    fn insert_checkpoint(&self, cp: Checkpoint) -> Result<(), FinalityError> {
        let mut g = self.inner.lock().unwrap();
        g.checkpoints.insert(cp.id, cp);
        Ok(())
    }
    fn get_checkpoint(&self, id: &CheckpointId) -> Result<Option<Checkpoint>, FinalityError> {
        let g = self.inner.lock().unwrap();
        Ok(g.checkpoints.get(id).cloned())
    }
    fn update_checkpoint_state(&self, id: &CheckpointId, st: CheckpointState) -> Result<(), FinalityError> {
        let mut g = self.inner.lock().unwrap();
        let c = g.checkpoints.get_mut(id).ok_or(FinalityError::UnknownCheckpoint)?;
        c.state = st;
        if st == CheckpointState::Finalized {
            g.finalized = Some(*id);
        }
        Ok(())
    }
    fn finalized_head(&self) -> Result<Option<Checkpoint>, FinalityError> {
        let g = self.inner.lock().unwrap();
        Ok(g.finalized.and_then(|id| g.checkpoints.get(&id).cloned()))
    }

    fn record_vote(&self, vote: &Vote) -> Result<(), FinalityError> {
        let mut g = self.inner.lock().unwrap();
        g.voted_rounds.entry(vote.validator).or_default().insert(vote.round);
        g.last_vote.insert(vote.validator, vote.clone());
        Ok(())
    }
    fn has_voted_in_round(&self, v: &ValidatorId, round: Round) -> Result<bool, FinalityError> {
        let g = self.inner.lock().unwrap();
        Ok(g.voted_rounds.get(v).map(|s| s.contains(&round)).unwrap_or(false))
    }
    fn last_vote_of(&self, v: &ValidatorId) -> Result<Option<Vote>, FinalityError> {
        let g = self.inner.lock().unwrap();
        Ok(g.last_vote.get(v).cloned())
    }

    fn add_vote_weight(&self, round: Round, source: CheckpointId, target: CheckpointId, weight: u128) -> Result<u128, FinalityError> {
        let mut g = self.inner.lock().unwrap();
        let key = (round, source, target);
        let entry = g.tallies.entry(key).or_insert(0);
        *entry = entry.saturating_add(weight);
        Ok(*entry)
    }
    fn accumulated_weight(&self, round: Round, source: CheckpointId, target: CheckpointId) -> Result<u128, FinalityError> {
        let g = self.inner.lock().unwrap();
        Ok(*g.tallies.get(&(round, source, target)).unwrap_or(&0))
    }
}

/// Простая реализация ValidatorSet с равными весами.
pub struct SimpleValidatorSet {
    weights: HashMap<ValidatorId, u128>,
    total: u128,
}
impl SimpleValidatorSet {
    pub fn new(ids: impl IntoIterator<Item = ValidatorId>) -> Self {
        let mut weights = HashMap::new();
        for id in ids {
            weights.insert(id, 1);
        }
        let total = weights.values().sum();
        Self { weights, total }
    }
    pub fn from_weights(map: HashMap<ValidatorId, u128>) -> Self {
        let total = map.values().sum();
        Self { weights: map, total }
    }
}
impl ValidatorSet for SimpleValidatorSet {
    fn total_power(&self) -> u128 { self.total }
    fn power_of(&self, id: &ValidatorId) -> u128 { *self.weights.get(id).unwrap_or(&0) }
}

// -------- Хеширование (плагин через трейты) --------

/// Абстракция хеширования для построения CheckpointId (можно подменить на BLAKE2/3 и т.п.).
pub trait Hasher32: Send + Sync + 'static {
    fn hash32(bytes: &[u8]) -> [u8; 32];
}

/// Дефолт: детерминированно растягиваем std::hash::Hasher (u64) до 32 байт.
/// В проде рекомендуется заменить на криптостойкий хеш через внедрение зависимостей.
pub struct DefaultHasher32;
impl Hasher32 for DefaultHasher32 {
    fn hash32(bytes: &[u8]) -> [u8; 32] {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut h);
        let x = h.finish().to_be_bytes();
        // повторим 4 раза, чтобы получить 32 байта
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&x);
        out[8..16].copy_from_slice(&x);
        out[16..24].copy_from_slice(&x);
        out[24..32].copy_from_slice(&x);
        out
    }
}

// -------- Движок финализации --------

/// Конфигурация движка финализации.
#[derive(Clone)]
pub struct FinalityConfig {
    pub threshold: Threshold, // по умолчанию 2/3
}
impl Default for FinalityConfig {
    fn default() -> Self { Self { threshold: Threshold::two_thirds() } }
}

/// Основной движок финализации (FFG-подобный).
pub struct FinalityEngine<S: FinalityStorage, V: ValidatorSet, H: Hasher32 = DefaultHasher32> {
    storage: Arc<S>,
    vset: Arc<V>,
    cfg: FinalityConfig,
    _h: std::marker::PhantomData<H>,
}

impl<S: FinalityStorage, V: ValidatorSet, H: Hasher32> FinalityEngine<S, V, H> {
    pub fn new(storage: Arc<S>, vset: Arc<V>, cfg: FinalityConfig) -> Result<Self, FinalityError> {
        if cfg.threshold.denom == 0 || cfg.threshold.numer == 0 || cfg.threshold.numer >= cfg.threshold.denom {
            return Err(FinalityError::InvalidThreshold);
        }
        Ok(Self { storage, vset, cfg, _h: Default::default() })
    }

    /// Создать чекпойнт для блока (обычно на границе эпох/интервала).
    pub fn create_checkpoint(
        &self,
        block: BlockId,
        parent: Option<CheckpointId>,
        round: Round,
        now_ms: UnixMillis,
    ) -> Result<Checkpoint, FinalityError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&block.hash);
        bytes.extend_from_slice(&block.number.to_be_bytes());
        if let Some(p) = parent { bytes.extend_from_slice(&p.0); }
        bytes.extend_from_slice(&round.to_be_bytes());
        let id = CheckpointId(H::hash32(&bytes));
        let cp = Checkpoint {
            id,
            block,
            round,
            timestamp_ms: now_ms,
            parent,
            state: CheckpointState::Created,
        };
        self.storage.insert_checkpoint(cp.clone())?;
        Ok(cp)
    }

    /// Обработать голос валидатора (проверка анти-слэшинга, агрегирование, попытка финализации).
    pub fn submit_vote(&self, vote: Vote) -> Result<VoteOutcome, FinalityError> {
        // Проверим известность чекпойнтов
        if self.storage.get_checkpoint(&vote.source)?.is_none() {
            return Ok(VoteOutcome::RejectedUnknownSource);
        }
        if self.storage.get_checkpoint(&vote.target)?.is_none() {
            return Ok(VoteOutcome::RejectedUnknownTarget);
        }

        // Double vote: голосовал ли валидатор в этом раунде ранее?
        if self.storage.has_voted_in_round(&vote.validator, vote.round)? {
            // Если голосовали — это потенциальный double vote. Проверим, не совпадает ли (source,target)
            if let Some(prev) = self.storage.last_vote_of(&vote.validator)? {
                if prev.round == vote.round && (prev.source != vote.source || prev.target != vote.target) {
                    return Ok(VoteOutcome::RejectedAlreadyVoted);
                }
                if prev.round > vote.round {
                    return Ok(VoteOutcome::RejectedOlderRound);
                }
            }
        } else {
            // Surround vote: запрещаем голос, который "окружает" или "окружён" (Casper FFG).
            if let Some(prev) = self.storage.last_vote_of(&vote.validator)? {
                // Простая проверка: запрещаем (prev.round < vote.round) с конфликтной парой source/target,
                // где новый голос "обнимает" предыдущий по цепочке чекпойнтов.
                if self.surrounds(&prev, &vote)? || self.surrounds(&vote, &prev)? {
                    return Ok(VoteOutcome::RejectedSurroundVote);
                }
            }
        }

        // Запишем голос и накопим вес
        self.storage.record_vote(&vote)?;
        let w = self.vset.power_of(&vote.validator);
        let acc = self.storage.add_vote_weight(vote.round, vote.source, vote.target, w)?;

        // Проверка порога для (round, source -> target)
        let total = self.vset.total_power();
        let reached = self.cfg.threshold.is_reached(acc, total);

        if reached {
            // target становится justified
            self.storage.update_checkpoint_state(&vote.target, CheckpointState::Justified)?;

            // Если target — прямой потомок source -> финализируем source
            let target_cp = self.storage.get_checkpoint(&vote.target)?.ok_or(FinalityError::UnknownCheckpoint)?;
            if let Some(parent) = target_cp.parent {
                if parent == vote.source {
                    self.storage.update_checkpoint_state(&vote.source, CheckpointState::Finalized)?;
                }
            }
        }

        Ok(VoteOutcome::Accepted)
    }

    /// Проверка "surround vote" (приближённая): новый голос окружает предыдущий или наоборот.
    /// В полной версии требуется индексирование высот/эпох чекпойнтов; здесь — упрощённая проверка по раундам и родству.
    fn surrounds(&self, outer: &Vote, inner: &Vote) -> Result<bool, FinalityError> {
        if !(outer.round > inner.round) {
            return Ok(false);
        }
        // Требуем, чтобы source/target outer "строго шире" inner и были предками/потомками.
        let is_ancestor = |a: CheckpointId, b: CheckpointId| -> Result<bool, FinalityError> {
            // Проверяем, что a — предок b по parent-ссылкам
            let mut cur = Some(b);
            while let Some(x) = cur {
                if x == a { return Ok(true); }
                let cp = self.storage.get_checkpoint(&x)?.ok_or(FinalityError::UnknownCheckpoint)?;
                cur = cp.parent;
            }
            Ok(false)
        };
        // outer.source <= inner.source И inner.target <= outer.target по родству, хотя бы одно строгое
        let s_ok = is_ancestor(outer.source, inner.source)?;
        let t_ok = is_ancestor(inner.target, outer.target)?;
        Ok(s_ok && t_ok && (outer.source != inner.source || outer.target != inner.target))
    }

    /// Текущая финализованная вершина.
    pub fn finalized_head(&self) -> Result<Option<Checkpoint>, FinalityError> {
        self.storage.finalized_head()
    }
}

// -------- Вспомогательное: генерация фиктивных hash/ID --------

pub fn derive_block_id(seed: u64, number: BlockNumber) -> BlockId {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&seed.to_be_bytes());
    BlockId { hash: bytes, number }
}

pub fn derive_validator(id: u8) -> ValidatorId {
    let mut b = [0u8; 32];
    b[0] = id;
    ValidatorId(b)
}

// -------- Тесты --------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffg_two_step_finalize_parent() {
        // Валидаторы: 4 шт., равные веса -> total = 4; порог >= 2/3 => нужно 3
        let vset = SimpleValidatorSet::new([derive_validator(1), derive_validator(2), derive_validator(3), derive_validator(4)]);
        let storage = Arc::new(MemStorage::new());
        let engine = FinalityEngine::<_, _, DefaultHasher32>::new(Arc::clone(&storage), Arc::new(vset), FinalityConfig::default()).unwrap();

        // genesis checkpoint (round 0)
        let genesis_block = derive_block_id(42, 0);
        let genesis = engine.create_checkpoint(genesis_block, None, 0, 0).unwrap();

        // target checkpoint (round 1), дочерний от genesis
        let b1 = derive_block_id(43, 10);
        let c1 = engine.create_checkpoint(b1, Some(genesis.id), 1, 100).unwrap();

        // Три валидатора голосуют за (genesis -> c1) в round=1
        for vid in [1u8, 2, 3] {
            let vote = Vote {
                validator: derive_validator(vid),
                round: 1,
                source: genesis.id,
                target: c1.id,
                signature: vec![],
            };
            let _ = engine.submit_vote(vote).unwrap();
        }

        // Проверяем статусы
        let g = storage.get_checkpoint(&genesis.id).unwrap().unwrap();
        let t = storage.get_checkpoint(&c1.id).unwrap().unwrap();
        assert_eq!(t.state, CheckpointState::Justified, "target justified");
        assert_eq!(g.state, CheckpointState::Finalized, "parent finalized");
        let head = engine.finalized_head().unwrap().unwrap();
        assert_eq!(head.id, genesis.id);
    }

    #[test]
    fn double_vote_rejected() {
        let vset = SimpleValidatorSet::new([derive_validator(1), derive_validator(2), derive_validator(3)]);
        let storage = Arc::new(MemStorage::new());
        let engine = FinalityEngine::<_, _, DefaultHasher32>::new(Arc::clone(&storage), Arc::new(vset), FinalityConfig::default()).unwrap();

        let g = engine.create_checkpoint(derive_block_id(1, 0), None, 0, 0).unwrap();
        let c = engine.create_checkpoint(derive_block_id(2, 1), Some(g.id), 1, 1).unwrap();
        let c_alt = engine.create_checkpoint(derive_block_id(3, 2), Some(g.id), 1, 1).unwrap();

        let v = derive_validator(1);
        let vote1 = Vote { validator: v, round: 1, source: g.id, target: c.id, signature: vec![] };
        assert_eq!(engine.submit_vote(vote1).unwrap(), VoteOutcome::Accepted);

        // Второй голос того же валидатора в том же раунде — по другому target
        let vote2 = Vote { validator: v, round: 1, source: g.id, target: c_alt.id, signature: vec![] };
        assert_eq!(engine.submit_vote(vote2).unwrap(), VoteOutcome::RejectedAlreadyVoted);
    }
}

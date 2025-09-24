//! Aethernova Consensus Core
//! ---------------------------------------
//! Производственный каркас консенсуса для узла блокчейна.
//! Цели:
//!   - Прозрачные интерфейсы (Storage/Network/EventBus).
//!   - Детерминированная FSM раунда: Propose → Prevote → Precommit → Commit.
//!   - Отсечение побочных эффектов (плагины, WAL, метрики) через trait-хуки.
//!   - Тестируемость: in-memory реализация, прогнозируемые таймауты.
//!
//! Терминология и шаги BFT опираются на открытые спецификации:
//!   • Tendermint BFT (propose/prevote/precommit/commit).
//!     См. спецификацию Tendermint (раздел "Consensus" / "The Consensus Algorithm").
//!     https://github.com/tendermint/spec/tree/master/spec/consensus
//!   • Обоснование терминов "term/leader/commit" см. в Raft paper:
//!     Diego Ongaro, John Ousterhout, "In Search of an Understandable Consensus Algorithm (Raft)",
//!     https://raft.github.io/raft.pdf
//! Эти ссылки даны как справочные источники терминологии. Логика в данном модуле автономна и не зависит от внешних lib.
//!
//! Замечание по криптографии: для компактности в примере применяется u64-хеш на базе `DefaultHasher`.
//! В продакшн-сборках замените на криптографический хеш (например, SHA-256 из rust-crypto).

use std::cmp::Ordering;
use std::collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet};
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

/// Высота блокчейна.
pub type Height = u64;
/// Номер раунда в рамках одной высоты.
pub type Round = u32;

/// Идентификатор валидатора.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatorId(pub u64);

/// Вес (власть голосов) валидатора.
pub type VotingPower = u64;

/// Тип голоса: Prevote или Precommit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// Шаг раунда BFT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundStep {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

/// Заголовок блока (минимально необходимый для консенсуса).
#[derive(Clone, Debug)]
pub struct Header {
    pub height: Height,
    pub round: Round,
    pub prev_hash: u64,
    pub proposer: ValidatorId,
    pub tx_count: u32,
    pub timestamp_ms: u128,
}

/// Блок (упрощённо).
#[derive(Clone, Debug)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Vec<u8>>,
    pub hash: u64,
}

impl Block {
    pub fn new(height: Height, round: Round, proposer: ValidatorId, prev_hash: u64, txs: Vec<Vec<u8>>) -> Self {
        let header = Header {
            height,
            round,
            prev_hash,
            proposer,
            tx_count: txs.len() as u32,
            timestamp_ms: now_ms(),
        };
        let mut hasher = DefaultHasher::new();
        header.height.hash(&mut hasher);
        header.round.hash(&mut hasher);
        header.prev_hash.hash(&mut hasher);
        header.proposer.hash(&mut hasher);
        header.tx_count.hash(&mut hasher);
        for t in &txs {
            t.hash(&mut hasher);
        }
        let hash = hasher.finish();
        Self { header, txs, hash }
    }
}

/// Голос валидатора по блоку.
#[derive(Clone, Debug)]
pub struct Vote {
    pub validator: ValidatorId,
    pub height: Height,
    pub round: Round,
    pub vote_type: VoteType,
    pub block_hash: Option<u64>,
    pub timestamp_ms: u128,
}

/// Коммит (супермножество precommit'ов за блок).
#[derive(Clone, Debug)]
pub struct Commit {
    pub height: Height,
    pub block_hash: u64,
    pub voters: BTreeSet<ValidatorId>,
    pub total_power: VotingPower,
    pub commit_power: VotingPower,
}

/// Набор валидаторов и round-robin выбор proposer'а.
#[derive(Clone, Debug)]
pub struct Validator {
    pub id: ValidatorId,
    pub power: VotingPower,
}

#[derive(Clone, Debug)]
pub struct ValidatorSet {
    pub vals: Vec<Validator>,
}

impl ValidatorSet {
    pub fn total_power(&self) -> VotingPower {
        self.vals.iter().map(|v| v.power).sum()
    }
    pub fn proposer_for(&self, height: Height, round: Round) -> ValidatorId {
        // Простая детерминированная RR-схема: индекс = (height + round) % N.
        let n = self.vals.len().max(1) as u64;
        let idx = ((height as u128 + round as u128) % n as u128) as usize;
        self.vals[idx].id
    }
    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.vals.iter().any(|v| &v.id == id)
    }
    pub fn power_of(&self, id: &ValidatorId) -> VotingPower {
        self.vals.iter().find(|v| &v.id == id).map(|v| v.power).unwrap_or(0)
    }
}

/// Конфигурация таймаутов/ограничений.
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub timeout_propose: Duration,
    pub timeout_prevote: Duration,
    pub timeout_precommit: Duration,
    pub max_rounds_per_height: u32,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            timeout_propose: Duration::from_millis(1500),
            timeout_prevote: Duration::from_millis(1000),
            timeout_precommit: Duration::from_millis(1000),
            max_rounds_per_height: 64,
        }
    }
}

/// События движка консенсуса.
#[derive(Clone, Debug)]
pub enum Event {
    StartHeight { height: Height, prev_hash: u64 },
    Proposal { block: Block },
    VoteReceived { vote: Vote },
    Timeout { height: Height, round: Round, step: RoundStep },
    ExternalCommit { commit: Commit },
    RequestPropose, // триггер локального предложения
    Shutdown,
}

/// Ошибки консенсуса.
#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
    #[error("unknown")]
    Unknown,
}

/// Абстракция хранилища.
pub trait Storage: Send + Sync + 'static {
    fn load_last_commit(&self) -> Option<Commit>;
    fn persist_block(&self, block: &Block) -> Result<(), ConsensusError>;
    fn persist_commit(&self, commit: &Commit) -> Result<(), ConsensusError>;
    fn set_state(&self, height: Height, round: Round, step: RoundStep);
    fn get_state(&self) -> (Height, Round, RoundStep);
}

/// In-memory хранилище для тестов/дева.
#[derive(Default)]
pub struct MemoryStorage {
    inner: Mutex<MemStoreInner>,
}

#[derive(Default)]
struct MemStoreInner {
    last_commit: Option<Commit>,
    blocks: BTreeMap<Height, Block>,
    state: (Height, Round, RoundStep),
}

impl Storage for MemoryStorage {
    fn load_last_commit(&self) -> Option<Commit> {
        self.inner.lock().unwrap().last_commit.clone()
    }
    fn persist_block(&self, block: &Block) -> Result<(), ConsensusError> {
        self.inner.lock().unwrap().blocks.insert(block.header.height, block.clone());
        Ok(())
    }
    fn persist_commit(&self, commit: &Commit) -> Result<(), ConsensusError> {
        self.inner.lock().unwrap().last_commit = Some(commit.clone());
        Ok(())
    }
    fn set_state(&self, height: Height, round: Round, step: RoundStep) {
        self.inner.lock().unwrap().state = (height, round, step);
    }
    fn get_state(&self) -> (Height, Round, RoundStep) {
        self.inner.lock().unwrap().state
    }
}

/// Абстракция сети (минималистичная): трансляция proposal/vote и подписка на входящие события.
pub trait Network: Send + Sync + 'static {
    fn broadcast_proposal(&self, block: &Block) -> Result<(), ConsensusError>;
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), ConsensusError>;
    fn inbound_events(&self) -> Receiver<Event>;
    fn outbound_sender(&self) -> Sender<Event>;
}

/// Канальный адаптер сети: Single-process симуляция.
pub struct ChannelsNetwork {
    rx_in: Receiver<Event>,
    tx_in: Sender<Event>,
    tx_out: Sender<Event>,
}

impl ChannelsNetwork {
    pub fn new() -> Self {
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, _rx_out_stub) = mpsc::channel::<Event>(); // внешний мир может подменить
        Self { rx_in, tx_in, tx_out }
    }
    pub fn with_outbound(tx_out: Sender<Event>) -> Self {
        let (tx_in, rx_in) = mpsc::channel();
        Self { rx_in, tx_in, tx_out }
    }
    pub fn inbound_tx(&self) -> Sender<Event> { self.tx_in.clone() }
}

impl Network for ChannelsNetwork {
    fn broadcast_proposal(&self, block: &Block) -> Result<(), ConsensusError> {
        self.tx_out.send(Event::Proposal { block: block.clone() })
            .map_err(|e| ConsensusError::Network(e.to_string()))
    }
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), ConsensusError> {
        self.tx_out.send(Event::VoteReceived { vote: vote.clone() })
            .map_err(|e| ConsensusError::Network(e.to_string()))
    }
    fn inbound_events(&self) -> Receiver<Event> { self.rx_in.clone() }
    fn outbound_sender(&self) -> Sender<Event> { self.tx_out.clone() }
}

/// Kratкое описание состояния текущего раунда.
#[derive(Clone, Debug)]
pub struct RoundState {
    pub height: Height,
    pub round: Round,
    pub step: RoundStep,
    pub locked_block: Option<Block>,
    pub valid_block: Option<Block>,
    pub prev_hash: u64,
    pub proposal: Option<Block>,
    pub prevotes: BTreeMap<ValidatorId, Vote>,
    pub precommits: BTreeMap<ValidatorId, Vote>,
}

impl RoundState {
    pub fn new(height: Height, round: Round, prev_hash: u64) -> Self {
        Self {
            height,
            round,
            step: RoundStep::Propose,
            locked_block: None,
            valid_block: None,
            prev_hash,
            proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
        }
    }
}

/// Исполнитель консенсуса.
pub struct ConsensusEngine<S: Storage, N: Network> {
    cfg: ConsensusConfig,
    vals: ValidatorSet,
    me: ValidatorId,
    storage: Arc<S>,
    network: Arc<N>,
    events_in: Receiver<Event>,
    events_out: Sender<Event>,
    timers_tx: Sender<()>, // "пинги" для таймеров
}

impl<S: Storage, N: Network> ConsensusEngine<S, N> {
    pub fn new(cfg: ConsensusConfig, vals: ValidatorSet, me: ValidatorId, storage: Arc<S>, network: Arc<N>) -> Self {
        let events_in = network.inbound_events();
        let events_out = network.outbound_sender();
        let (timers_tx, _timers_rx) = mpsc::channel();
        Self { cfg, vals, me, storage, network, events_in, events_out, timers_tx }
    }

    /// Запуск основного цикла в отдельном потоке.
    pub fn start(self) -> thread::JoinHandle<Result<(), ConsensusError>> {
        thread::spawn(move || self.run())
    }

    fn run(mut self) -> Result<(), ConsensusError> {
        // Инициализация высоты и prev_hash
        let (mut height, mut prev_hash) = match self.storage.load_last_commit() {
            Some(c) => (c.height + 1, c.block_hash),
            None => (1u64, 0u64),
        };
        let mut round: Round = 0;
        let mut rs = RoundState::new(height, round, prev_hash);
        self.storage.set_state(height, round, rs.step);

        self.events_out.send(Event::StartHeight { height, prev_hash }).ok();

        // Главный цикл: обрабатываем события/таймауты до Shutdown
        'main: loop {
            // Запускаем таймер под текущий шаг
            let step_timeout = match rs.step {
                RoundStep::Propose => self.cfg.timeout_propose,
                RoundStep::Prevote => self.cfg.timeout_prevote,
                RoundStep::Precommit => self.cfg.timeout_precommit,
                RoundStep::Commit => Duration::from_millis(1), // быстрый переход
            };
            let deadline = Instant::now() + step_timeout;

            // Если мы proposer — инициируем локальный RequestPropose
            if self.is_proposer(rs.height, rs.round) && rs.step == RoundStep::Propose {
                self.events_out.send(Event::RequestPropose).ok();
            }

            // Цикл ожидания события/таймаута
            loop {
                let now = Instant::now();
                if now >= deadline {
                    // генерируем таймаут для текущего шага
                    self.handle_event(&mut rs, Event::Timeout { height: rs.height, round: rs.round, step: rs.step })?;
                    break;
                }
                let remaining = deadline - now;
                if let Ok(ev) = self.events_in.recv_timeout(remaining) {
                    match ev {
                        Event::Shutdown => break 'main,
                        _ => self.handle_event(&mut rs, ev)?,
                    }
                    if rs.step == RoundStep::Commit {
                        // Выполнить коммит и перейти на новую высоту
                        self.try_commit(&mut rs)?;
                        // Переход на следующую высоту
                        prev_hash = rs.valid_block.as_ref().map(|b| b.hash).unwrap_or(prev_hash);
                        height += 1;
                        round = 0;
                        rs = RoundState::new(height, round, prev_hash);
                        self.storage.set_state(height, round, rs.step);
                        self.events_out.send(Event::StartHeight { height, prev_hash }).ok();
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn is_proposer(&self, height: Height, round: Round) -> bool {
        self.vals.proposer_for(height, round) == self.me
    }

    fn make_proposal(&self, rs: &RoundState) -> Block {
        // В реальности: собрать mempool txs, проверить prev_hash, т. д.
        let txs = vec![];
        Block::new(rs.height, rs.round, self.me, rs.prev_hash, txs)
    }

    fn broadcast_vote(&self, rs: &RoundState, vote_type: VoteType, block_hash: Option<u64>) -> Result<(), ConsensusError> {
        let vote = Vote {
            validator: self.me,
            height: rs.height,
            round: rs.round,
            vote_type,
            block_hash,
            timestamp_ms: now_ms(),
        };
        self.network.broadcast_vote(&vote)
    }

    fn handle_event(&self, rs: &mut RoundState, ev: Event) -> Result<(), ConsensusError> {
        match ev {
            Event::RequestPropose if rs.step == RoundStep::Propose && self.is_proposer(rs.height, rs.round) => {
                let block = self.make_proposal(rs);
                rs.proposal = Some(block.clone());
                self.network.broadcast_proposal(&block)?;
                Ok(())
            }
            Event::Proposal { block } => {
                if block.header.height == rs.height && block.header.round == rs.round && block.header.prev_hash == rs.prev_hash {
                    rs.proposal = Some(block.clone());
                    // Здесь можно вставить доп. валидации блока.
                    // Prevote за предложенный блок:
                    self.broadcast_vote(rs, VoteType::Prevote, Some(block.hash))?;
                    rs.step = RoundStep::Prevote;
                    self.storage.set_state(rs.height, rs.round, rs.step);
                }
                Ok(())
            }
            Event::VoteReceived { vote } => {
                if vote.height != rs.height || vote.round != rs.round { return Ok(()); }
                if !self.vals.contains(&vote.validator) { return Ok(()); }
                match vote.vote_type {
                    VoteType::Prevote => {
                        rs.prevotes.insert(vote.validator, vote.clone());
                        if self.has_2f1_prevotes(rs) && rs.step == RoundStep::Prevote {
                            // Блок "валиден" для round: выбираем хеш по большинству
                            if let Some((hash, _power)) = self.prevote_majority(rs) {
                                // локально precommit за этот хеш
                                self.broadcast_vote(rs, VoteType::Precommit, Some(hash))?;
                                rs.valid_block = rs.proposal.clone().filter(|b| b.hash == hash);
                                rs.step = RoundStep::Precommit;
                                self.storage.set_state(rs.height, rs.round, rs.step);
                            }
                        }
                    }
                    VoteType::Precommit => {
                        rs.precommits.insert(vote.validator, vote.clone());
                        if self.has_2f1_precommits(rs) && rs.step == RoundStep::Precommit {
                            rs.step = RoundStep::Commit;
                            self.storage.set_state(rs.height, rs.round, rs.step);
                        }
                    }
                }
                Ok(())
            }
            Event::Timeout { height, round, step } if height == rs.height && round == rs.round => {
                match step {
                    RoundStep::Propose => {
                        // Не получили proposal вовремя: голосуем Prevote(None)
                        self.broadcast_vote(rs, VoteType::Prevote, None)?;
                        rs.step = RoundStep::Prevote;
                        self.storage.set_state(rs.height, rs.round, rs.step);
                        Ok(())
                    }
                    RoundStep::Prevote => {
                        // Нет 2f+1 prevotes за конкретный блок → переход в Precommit(None)
                        self.broadcast_vote(rs, VoteType::Precommit, None)?;
                        rs.step = RoundStep::Precommit;
                        self.storage.set_state(rs.height, rs.round, rs.step);
                        Ok(())
                    }
                    RoundStep::Precommit => {
                        // Нет коммита → новый раунд (liveness)
                        if rs.round + 1 >= self.cfg.max_rounds_per_height {
                            return Err(ConsensusError::InvalidTransition("max rounds per height exceeded".into()));
                        }
                        let next_round = rs.round + 1;
                        *rs = RoundState::new(rs.height, next_round, rs.prev_hash);
                        self.storage.set_state(rs.height, rs.round, rs.step);
                        Ok(())
                    }
                    RoundStep::Commit => Ok(()), // commit исполняется в основном цикле
                }
            }
            Event::ExternalCommit { commit } => {
                // Возможность принять внешний коммит (fast-sync / catch-up).
                if commit.height == rs.height {
                    rs.valid_block = rs.proposal.clone().filter(|b| b.hash == commit.block_hash);
                    rs.step = RoundStep::Commit;
                    self.storage.set_state(rs.height, rs.round, rs.step);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn try_commit(&self, rs: &mut RoundState) -> Result<(), ConsensusError> {
        let block = match rs.valid_block.clone() {
            Some(b) => b,
            None => {
                // На случай ExternalCommit без proposal — соберём пустой блок "по месту".
                let b = self.make_proposal(rs);
                b
            }
        };
        let (commit_power, voters) = self.collect_precommit_power(rs, block.hash);
        let total = self.vals.total_power();
        if commit_power * 3 <= total * 2 {
            // Не набрали 2/3 — это невалидный Commit, откладываем.
            return Ok(());
        }
        let commit = Commit {
            height: block.header.height,
            block_hash: block.hash,
            voters,
            total_power: total,
            commit_power,
        };
        self.storage.persist_block(&block)?;
        self.storage.persist_commit(&commit)?;
        Ok(())
    }

    fn prevote_majority(&self, rs: &RoundState) -> Option<(u64, VotingPower)> {
        // Суммируем power по hash в prevotes
        let mut power_map: BTreeMap<u64, VotingPower> = BTreeMap::new();
        for v in rs.prevotes.values() {
            if let Some(h) = v.block_hash {
                *power_map.entry(h).or_insert(0) += self.vals.power_of(&v.validator);
            }
        }
        power_map.into_iter().max_by(|a, b| a.1.cmp(&b.1)).map(|kv| kv)
    }

    fn has_2f1_prevotes(&self, rs: &RoundState) -> bool {
        let total = self.vals.total_power();
        if let Some((_, pow)) = self.prevote_majority(rs) {
            return pow * 3 > total * 2;
        }
        false
    }

    fn has_2f1_precommits(&self, rs: &RoundState) -> bool {
        let (pow, _) = self.collect_precommit_any(rs);
        let total = self.vals.total_power();
        pow * 3 > total * 2
    }

    fn collect_precommit_any(&self, rs: &RoundState) -> (VotingPower, Option<u64>) {
        // Находим хеш с максимальной суммой power в precommit'ах
        let mut pm: BTreeMap<Option<u64>, VotingPower> = BTreeMap::new();
        for v in rs.precommits.values() {
            *pm.entry(v.block_hash).or_insert(0) += self.vals.power_of(&v.validator);
        }
        pm.into_iter().max_by(|a, b| a.1.cmp(&b.1)).map(|(h, p)| (p, h)).unwrap_or((0, None))
    }

    fn collect_precommit_power(&self, rs: &RoundState, target_hash: u64) -> (VotingPower, BTreeSet<ValidatorId>) {
        let mut voters = BTreeSet::new();
        let mut sum = 0;
        for v in rs.precommits.values() {
            if v.block_hash == Some(target_hash) {
                voters.insert(v.validator);
                sum += self.vals.power_of(&v.validator);
            }
        }
        (sum, voters)
    }
}

fn now_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

/* ============================ TESTS ============================ */

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_vals(n: usize) -> ValidatorSet {
        let vals = (0..n).map(|i| Validator { id: ValidatorId(i as u64 + 1), power: 1 }).collect();
        ValidatorSet { vals }
    }

    struct LocalNet {
        inbound_rx: Receiver<Event>,
        inbound_tx: Sender<Event>,
        outbound_tx: Sender<Event>,
        // внешний слушатель "сети"
        public_rx: Receiver<Event>,
    }

    impl LocalNet {
        fn new_pair() -> (Arc<Self>, Sender<Event>, Receiver<Event>) {
            let (in_tx, in_rx) = mpsc::channel();
            let (out_tx, out_rx) = mpsc::channel();
            let net = Arc::new(Self {
                inbound_rx: in_rx,
                inbound_tx: in_tx.clone(),
                outbound_tx: out_tx.clone(),
                public_rx: out_rx,
            });
            (net, in_tx, out_tx)
        }
    }

    impl Network for LocalNet {
        fn broadcast_proposal(&self, block: &Block) -> Result<(), ConsensusError> {
            self.outbound_tx.send(Event::Proposal { block: block.clone() }).unwrap();
            Ok(())
        }
        fn broadcast_vote(&self, vote: &Vote) -> Result<(), ConsensusError> {
            self.outbound_tx.send(Event::VoteReceived { vote: vote.clone() }).unwrap();
            Ok(())
        }
        fn inbound_events(&self) -> Receiver<Event> {
            self.inbound_rx.clone()
        }
        fn outbound_sender(&self) -> Sender<Event> {
            self.outbound_tx.clone()
        }
    }

    #[test]
    fn single_height_commits_on_2f1() {
        // 4 валидатора, требуется 3 (>2/3) для коммита
        let vals = mk_vals(4);
        let me = vals.vals[0].id;
        let storage = Arc::new(MemoryStorage::default());
        let (net, in_tx, out_tx) = LocalNet::new_pair();

        let cfg = ConsensusConfig {
            timeout_propose: Duration::from_millis(10),
            timeout_prevote: Duration::from_millis(10),
            timeout_precommit: Duration::from_millis(10),
            max_rounds_per_height: 8,
        };

        let engine = ConsensusEngine::new(cfg, vals.clone(), me, storage.clone(), net.clone());
        let handle = engine.start();

        // Запускаем высоту
        in_tx.send(Event::StartHeight { height: 1, prev_hash: 0 }).ok();
        // Дадим себе чуть времени
        thread::sleep(Duration::from_millis(5));
        // Подадим RequestPropose (как будто движок сам это сделал)
        in_tx.send(Event::RequestPropose).ok();

        // Получаем Proposal из "сети"
        let proposed = loop {
            if let Ok(Event::Proposal { block }) = net.public_rx.recv_timeout(Duration::from_millis(100)) {
                break block;
            }
        };

        // Рассылаем 3 prevote/precommit от 3 валидаторов (вкл. меня)
        for vid in [ValidatorId(1), ValidatorId(2), ValidatorId(3)] {
            in_tx.send(Event::VoteReceived { vote: Vote {
                validator: vid, height: 1, round: 0, vote_type: VoteType::Prevote, block_hash: Some(proposed.hash), timestamp_ms: now_ms()
            }}).ok();
        }

        // Перевод в Precommit
        for vid in [ValidatorId(1), ValidatorId(2), ValidatorId(3)] {
            in_tx.send(Event::VoteReceived { vote: Vote {
                validator: vid, height: 1, round: 0, vote_type: VoteType::Precommit, block_hash: Some(proposed.hash), timestamp_ms: now_ms()
            }}).ok();
        }

        // Дождаться, пока движок закроет высоту (commit внутри run-цикла)
        thread::sleep(Duration::from_millis(50));
        // Проверяем, что коммит записан
        let last = storage.load_last_commit().expect("commit should exist");
        assert_eq!(last.height, 1);
        assert_eq!(last.block_hash, proposed.hash);

        // Завершаем
        in_tx.send(Event::Shutdown).ok();
        handle.join().unwrap().unwrap();
    }
}

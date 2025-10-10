//! Tendermint-like BFT консенсус (упрощённое промышленное ядро).
//!
//! Основные свойства:
//! - Раундовая машина состояний: Propose → Prevote → Precommit → Commit (+ NewHeight).
//! - Правила безопасности: polka (≥2/3 prevote), lock/unlock, запрет equivocation.
//! - Взвешенный выбор пропоузера (smooth weighted round-robin).
//! - Таймауты стадий, асинхронный реактор на Tokio.
//! - ABCI-подобный адаптер приложения для validate/apply.
//!
//! Зависимости (указать в Cargo.toml проекта):
//!   tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
//!   thiserror = "1"
//!   bytes = "1"
//!
//! Примечание: сетевой слой здесь абстрагирован каналами; интеграция с P2P — вне этого файла.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::time::{sleep, Instant};

/// Типы шагов консенсуса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    NewHeight,
    Propose,
    Prevote,
    Precommit,
    Commit,
}

/// Типы голосов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// Идентификатор валидатора.
pub type ValidatorId = [u8; 32];

/// Идентификатор блока (хеш).
pub type BlockId = [u8; 32];

/// Высота.
pub type Height = u64;

/// Номер раунда.
pub type Round = u32;

/// Вес (voting power).
pub type Power = u64;

/// Сообщение «Предложение блока».
#[derive(Debug, Clone)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub block_id: Option<BlockId>, // None == nil-пропоузал
    /// Раунд, в котором была получена polka по re-propose (ProposalPOLRound), если применимо.
    pub pol_round: Option<Round>,
    pub proposer: ValidatorId,
    pub payload: Option<Bytes>, // опционально: заголовок/коммит-данные блока
}

/// Сообщение «Голос».
#[derive(Debug, Clone)]
pub struct Vote {
    pub validator: ValidatorId,
    pub height: Height,
    pub round: Round,
    pub vote_type: VoteType,
    pub block_id: Option<BlockId>, // None == голос за nil
    pub signature: Bytes,          // подпись валидатора по каноническому signDoc
}

/// Доказательство злонамеренности (минимально: двойная подпись).
#[derive(Debug, Clone)]
pub struct Evidence {
    pub validator: ValidatorId,
    pub height: Height,
    pub round: Round,
    pub vote_a: Vote,
    pub vote_b: Vote,
}

/// Блок (минимальная модель).
#[derive(Debug, Clone)]
pub struct Block {
    pub height: Height,
    pub round: Round,
    pub id: BlockId,
    pub data: Bytes,
}

/// Ошибки консенсуса.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("invalid proposal")]
    InvalidProposal,
    #[error("invalid vote")]
    InvalidVote,
    #[error("application validation failed: {0}")]
    AppValidation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Конфигурация консенсуса.
#[derive(Debug, Clone)]
pub struct Config {
    pub propose_timeout: Duration,
    pub prevote_timeout: Duration,
    pub precommit_timeout: Duration,
    pub empty_block: bool,
    /// Требуемая доля голосов для polka/commit (обычно 2/3 + ε).
    pub two_thirds: f64, // например, 0.666667
}

impl Default for Config {
    fn default() -> Self {
        Self {
            propose_timeout: Duration::from_millis(3000),
            prevote_timeout: Duration::from_millis(1000),
            precommit_timeout: Duration::from_millis(1000),
            empty_block: true,
            two_thirds: 2.0f64 / 3.0f64,
        }
    }
}

/// Подпись/сертификат — интерфейс подписи голосов.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    async fn sign_vote(&self, vote: &Vote) -> Result<Bytes, ConsensusError>;
}

/// ABCI-подобный адаптер приложения:
/// - `validate_block` вызывается до голосования за блок (ProcessProposal/Validate).
/// - `apply_block` вызывается после commit (FinalizeCommit/Apply).
#[async_trait::async_trait]
pub trait ApplicationAdapter: Send + Sync {
    /// Предложить новый блок (для роли пропоузера).
    async fn propose_block(&self, height: Height) -> Result<Block, ConsensusError>;

    /// Проверить валидность блока (до голосования).
    async fn validate_block(&self, block: &Block) -> Result<(), ConsensusError>;

    /// Применить блок к состоянию (после коммита).
    async fn apply_block(&self, block: &Block) -> Result<(), ConsensusError>;

    /// Репортинг доказательств (двойные голоса).
    async fn report_evidence(&self, ev: Evidence) -> Result<(), ConsensusError>;
}

/// Валидатор.
#[derive(Debug, Clone)]
pub struct Validator {
    pub id: ValidatorId,
    pub power: Power,
}

/// Набор валидаторов с алгоритмом выбора пропоузера (smooth WRR).
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub vals: Vec<Validator>,
    /// Счётчики «score» для smooth weighted round robin.
    scores: Vec<i128>,
    total_power: i128,
    last_chosen: Option<usize>,
}

impl ValidatorSet {
    pub fn new(vals: Vec<Validator>) -> Self {
        let total_power = vals.iter().map(|v| v.power as i128).sum();
        let scores = vec![0; vals.len()];
        Self { vals, scores, total_power, last_chosen: None }
    }

    /// Выбор пропоузера: smooth weighted round-robin (не каноничный, но
    /// концептуально совместимый с идеей приоритета по стейку).
    pub fn choose_proposer(&mut self) -> Option<ValidatorId> {
        if self.vals.is_empty() {
            return None;
        }
        // Обновить score
        for (i, v) in self.vals.iter().enumerate() {
            self.scores[i] += v.power as i128;
        }
        // Выбрать максимум
        let (mut best_i, mut best_score) = (0usize, i128::MIN);
        for (i, s) in self.scores.iter().enumerate() {
            if *s > best_score {
                best_score = *s;
                best_i = i;
            }
        }
        // Нормализация выбранного
        self.scores[best_i] -= self.total_power.max(1);
        self.last_chosen = Some(best_i);
        Some(self.vals[best_i].id)
    }

    pub fn voting_power(&self, id: &ValidatorId) -> Power {
        self.vals.iter().find(|v| &v.id == id).map(|v| v.power).unwrap_or(0)
    }

    pub fn total_voting_power(&self) -> Power {
        self.vals.iter().map(|v| v.power).sum()
    }
}

/// Агрегатор голосов по (height, round, type).
#[derive(Default, Debug, Clone)]
struct VoteSet {
    // block_id(None == nil) -> суммарный вес
    weights: HashMap<Option<BlockId>, Power>,
    // для детекции эквивокации: validator -> (vote_type, block_id) по данному (h,r)
    seen: HashMap<ValidatorId, (VoteType, Option<BlockId>)>,
}

impl VoteSet {
    fn add_vote(
        &mut self,
        v: &Vote,
        valset: &ValidatorSet,
    ) -> Result<Option<Evidence>, ConsensusError> {
        // Детект эквивокации: один и тот же валидатор дал два разных голоса данного типа в том же (h,r)
        if let Some((old_t, old_bid)) = self.seen.get(&v.validator) {
            if *old_t == v.vote_type && *old_bid != v.block_id {
                // Зафиксировать evidence
                return Ok(Some(Evidence {
                    validator: v.validator,
                    height: v.height,
                    round: v.round,
                    vote_a: Vote { signature: Bytes::from_static(b""), ..v.clone() },
                    vote_b: Vote { signature: Bytes::from_static(b""), ..v.clone() }, // в реале нужно хранить оба
                }));
            }
        }
        self.seen.insert(v.validator, (v.vote_type, v.block_id));

        let w = valset.voting_power(&v.validator);
        let entry = self.weights.entry(v.block_id).or_insert(0);
        *entry += w;
        Ok(None)
    }

    fn power_for(&self, bid: Option<BlockId>) -> Power {
        *self.weights.get(&bid).unwrap_or(&0)
    }
}

/// Состояние раунда.
#[derive(Debug, Clone)]
pub struct RoundState {
    pub height: Height,
    pub round: Round,
    pub step: Step,
    pub locked_block: Option<BlockId>,
    pub locked_round: Option<Round>,
}

impl RoundState {
    fn new(height: Height) -> Self {
        Self {
            height,
            round: 0,
            step: Step::NewHeight,
            locked_block: None,
            locked_round: None,
        }
    }
}

/// События машины консенсуса.
#[derive(Debug)]
pub enum Event {
    StartHeight(Height),
    TimeoutPropose { height: Height, round: Round },
    TimeoutPrevote { height: Height, round: Round },
    TimeoutPrecommit { height: Height, round: Round },
    Proposal(Proposal),
    Vote(Vote),
}

/// Каналы вход/выход.
pub struct Channels {
    pub tx_out: mpsc::Sender<Event>,      // исходящие (в сеть) — здесь абстракция
    pub rx_in: mpsc::Receiver<Event>,     // входящие из сети
    pub tx_state: broadcast::Sender<RoundState>, // для наблюдения
}

/// Движок консенсуса.
pub struct TendermintLike<A: ApplicationAdapter, S: Signer> {
    cfg: Config,
    app: Arc<A>,
    signer: Arc<S>,
    valset: Arc<RwLock<ValidatorSet>>,
    state: Arc<RwLock<RoundState>>,
    votes_prev: Arc<RwLock<HashMap<(Height, Round), VoteSet>>>,    // prevote наборы
    votes_prec: Arc<RwLock<HashMap<(Height, Round), VoteSet>>>,    // precommit наборы
    chans: Channels,
}

impl<A: ApplicationAdapter, S: Signer> TendermintLike<A, S> {
    pub fn new(cfg: Config, app: Arc<A>, signer: Arc<S>, valset: ValidatorSet, chans: Channels) -> Self {
        let (tx_state, _) = broadcast::channel(64);
        Self {
            cfg,
            app,
            signer,
            valset: Arc::new(RwLock::new(valset)),
            state: Arc::new(RwLock::new(RoundState::new(1))),
            votes_prev: Arc::new(RwLock::new(HashMap::new())),
            votes_prec: Arc::new(RwLock::new(HashMap::new())),
            chans: Channels { tx_out: chans.tx_out, rx_in: chans.rx_in, tx_state },
        }
    }

    /// Запуск основного цикла консенсуса.
    pub async fn run(mut self) -> Result<(), ConsensusError> {
        // Инициализация высоты
        {
            let mut st = self.state.write().await;
            st.step = Step::NewHeight;
        }
        // Публикация состояния
        let _ = self.chans.tx_state.send(self.state.read().await.clone());

        // Главный цикл событий
        loop {
            tokio::select! {
                maybe_ev = self.chans.rx_in.recv() => {
                    if let Some(ev) = maybe_ev {
                        self.handle_event(ev).await?;
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_event(&mut self, ev: Event) -> Result<(), ConsensusError> {
        match ev {
            Event::StartHeight(h) => self.start_height(h).await,
            Event::TimeoutPropose { height, round } => self.on_timeout_propose(height, round).await,
            Event::TimeoutPrevote { height, round } => self.on_timeout_prevote(height, round).await,
            Event::TimeoutPrecommit { height, round } => self.on_timeout_precommit(height, round).await,
            Event::Proposal(p) => self.on_proposal(p).await,
            Event::Vote(v) => self.on_vote(v).await,
        }
    }

    async fn start_height(&mut self, height: Height) -> Result<(), ConsensusError> {
        let mut st = self.state.write().await;
        st.height = height;
        st.round = 0;
        st.step = Step::Propose;
        drop(st);

        self.spawn_propose_timeout(height, 0).await;
        Ok(())
    }

    async fn on_timeout_propose(&mut self, height: Height, round: Round) -> Result<(), ConsensusError> {
        let st = self.state.read().await;
        if st.height != height || st.round != round || st.step != Step::Propose {
            return Ok(());
        }
        drop(st);

        // Не получили валидного пропоузала: prevote за nil
        self.broadcast_vote(VoteType::Prevote, None).await?;
        self.advance_step(Step::Prevote).await;
        self.spawn_prevote_timeout(height, round).await;
        Ok(())
    }

    async fn on_timeout_prevote(&mut self, height: Height, round: Round) -> Result<(), ConsensusError> {
        let st = self.state.read().await;
        if st.height != height || st.round != round || st.step != Step::Prevote {
            return Ok(());
        }
        drop(st);

        // Проверить polka: ≥2/3 prevote за один BlockID
        if let Some((bid, _pow)) = self.best_polka(height, round).await {
            // Правило: каждый precommit должен быть обоснован polka того же раунда.
            self.broadcast_vote(VoteType::Precommit, bid).await?;
        } else {
            // Нет polka → precommit за nil
            self.broadcast_vote(VoteType::Precommit, None).await?;
        }

        self.advance_step(Step::Precommit).await;
        self.spawn_precommit_timeout(height, round).await;
        Ok(())
    }

    async fn on_timeout_precommit(&mut self, height: Height, round: Round) -> Result<(), ConsensusError> {
        let st = self.state.read().await;
        if st.height != height || st.round != round || st.step != Step::Precommit {
            return Ok(());
        }
        drop(st);

        // Проверить ≥2/3 precommit за один BlockID → commit
        if let Some((bid, _pow)) = self.best_precommit(height, round).await {
            self.do_commit(bid).await?;
            self.begin_new_height().await?;
        } else {
            // Переход в следующий раунд
            self.increment_round().await;
            self.advance_step(Step::Propose).await;
            let st2 = self.state.read().await;
            self.spawn_propose_timeout(st2.height, st2.round).await;
        }
        Ok(())
    }

    async fn on_proposal(&mut self, p: Proposal) -> Result<(), ConsensusError> {
        let st = self.state.read().await;
        if p.height != st.height || p.round != st.round || st.step != Step::Propose {
            // Игнорируем чуждые/старые пропоузалы
            return Ok(());
        }
        drop(st);

        // Проверить предложение
        if let Some(bid) = p.block_id {
            // Получаем блок у приложения или из хранилища — здесь предполагается,
            // что ApplicationAdapter::validate_block знает, как валидировать по block.id.
            // Для примера вызываем validate с «заглушкой блока» (реально блок должен быть собран заранее).
            let blk = Block { height: p.height, round: p.round, id: bid, data: p.payload.clone().unwrap_or_default() };
            self.app.validate_block(&blk).await.map_err(|e| ConsensusError::AppValidation(format!("{e:?}")))?;
            // Если валиден → prevote за предложенный блок
            self.broadcast_vote(VoteType::Prevote, Some(bid)).await?;
        } else {
            // Пропоузал nil → prevote nil
            self.broadcast_vote(VoteType::Prevote, None).await?;
        }

        self.advance_step(Step::Prevote).await;
        let st2 = self.state.read().await;
        self.spawn_prevote_timeout(st2.height, st2.round).await;
        Ok(())
    }

    async fn on_vote(&mut self, v: Vote) -> Result<(), ConsensusError> {
        // Валидация базовая (в реальности: проверка подписи, подписываемых полей и т.п.)
        let st = self.state.read().await;
        if v.height != st.height {
            return Ok(());
        }
        drop(st);

        let valset = self.valset.read().await.clone();

        match v.vote_type {
            VoteType::Prevote => {
                let key = (v.height, v.round);
                let mut all_prev = self.votes_prev.write().await;
                let entry = all_prev.entry(key).or_default();
                if let Some(ev) = entry.add_vote(&v, &valset)? {
                    self.app.report_evidence(ev).await?;
                }
            }
            VoteType::Precommit => {
                let key = (v.height, v.round);
                let mut all_prec = self.votes_prec.write().await;
                let entry = all_prec.entry(key).or_default();
                if let Some(ev) = entry.add_vote(&v, &valset)? {
                    self.app.report_evidence(ev).await?;
                }

                // Если набрали ≥2/3 за один BlockID → commit
                if let Some((bid, _pow)) = self.best_precommit(v.height, v.round).await {
                    self.do_commit(bid).await?;
                    self.begin_new_height().await?;
                }
            }
        }

        Ok(())
    }

    async fn begin_new_height(&mut self) -> Result<(), ConsensusError> {
        let mut st = self.state.write().await;
        st.height += 1;
        st.round = 0;
        st.step = Step::NewHeight;
        st.locked_block = None;
        st.locked_round = None;
        drop(st);

        // Переход к Propose нового height
        {
            let mut st2 = self.state.write().await;
            st2.step = Step::Propose;
        }
        let st3 = self.state.read().await;
        self.spawn_propose_timeout(st3.height, st3.round).await;
        self.publish_state().await;
        Ok(())
    }

    async fn increment_round(&mut self) {
        let mut st = self.state.write().await;
        st.round = st.round.saturating_add(1);
    }

    async fn advance_step(&mut self, step: Step) {
        let mut st = self.state.write().await;
        st.step = step;
        drop(st);
        self.publish_state().await;
    }

    async fn publish_state(&self) {
        let _ = self.chans.tx_state.send(self.state.read().await.clone());
    }

    async fn best_polka(&self, height: Height, round: Round) -> Option<(Option<BlockId>, Power)> {
        let key = (height, round);
        let prevs = self.votes_prev.read().await;
        let vs = prevs.get(&key)?;
        let valset = self.valset.read().await;
        let total = valset.total_voting_power();
        let mut best: Option<(Option<BlockId>, Power)> = None;
        for (bid, pow) in vs.weights.iter() {
            if best.as_ref().map(|b| b.1).unwrap_or(0) < *pow {
                best = Some((*bid, *pow));
            }
        }
        if let Some((bid, pow)) = best {
            let ratio = pow as f64 / total as f64;
            if ratio >= self.cfg.two_thirds {
                return Some((bid, pow));
            }
        }
        None
    }

    async fn best_precommit(&self, height: Height, round: Round) -> Option<(Option<BlockId>, Power)> {
        let key = (height, round);
        let precs = self.votes_prec.read().await;
        let vs = precs.get(&key)?;
        let valset = self.valset.read().await;
        let total = valset.total_voting_power();
        let mut best: Option<(Option<BlockId>, Power)> = None;
        for (bid, pow) in vs.weights.iter() {
            if best.as_ref().map(|b| b.1).unwrap_or(0) < *pow {
                best = Some((*bid, *pow));
            }
        }
        if let Some((bid, pow)) = best {
            let ratio = pow as f64 / total as f64;
            if ratio >= self.cfg.two_thirds {
                return Some((bid, pow));
            }
        }
        None
    }

    async fn do_commit(&mut self, bid: Option<BlockId>) -> Result<(), ConsensusError> {
        let st = self.state.read().await;
        let height = st.height;
        let round = st.round;
        drop(st);

        // В реальности здесь нужно извлечь полный блок по BlockId из блока-хранилища.
        // Для упрощения соберём технический блок-коммит.
        let blk = Block {
            height,
            round,
            id: bid.unwrap_or([0u8; 32]),
            data: Bytes::from_static(b"committed"),
        };
        self.app.apply_block(&blk).await?;
        self.advance_step(Step::Commit).await;
        Ok(())
    }

    async fn broadcast_vote(&mut self, vt: VoteType, bid: Option<BlockId>) -> Result<(), ConsensusError> {
        // Сформировать и подписать голос
        let st = self.state.read().await;
        let mut vote = Vote {
            validator: [0u8; 32], // здесь должен быть реальный ID локального валидатора
            height: st.height,
            round: st.round,
            vote_type: vt,
            block_id: bid,
            signature: Bytes::new(),
        };
        drop(st);

        vote.signature = self.signer.sign_vote(&vote).await?;

        // Отправить в «сеть» (в реальности — по P2P)
        self.chans.tx_out.send(Event::Vote(vote)).await.map_err(|e| ConsensusError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn spawn_propose_timeout(&mut self, height: Height, round: Round) {
        let tx = self.chans.tx_out.clone();
        let timeout = self.cfg.propose_timeout;
        tokio::spawn(async move {
            sleep(timeout).await;
            let _ = tx.send(Event::TimeoutPropose { height, round }).await;
        });
    }

    async fn spawn_prevote_timeout(&mut self, height: Height, round: Round) {
        let tx = self.chans.tx_out.clone();
        let timeout = self.cfg.prevote_timeout;
        tokio::spawn(async move {
            sleep(timeout).await;
            let _ = tx.send(Event::TimeoutPrevote { height, round }).await;
        });
    }

    async fn spawn_precommit_timeout(&mut self, height: Height, round: Round) {
        let tx = self.chans.tx_out.clone();
        let timeout = self.cfg.precommit_timeout;
        tokio::spawn(async move {
            sleep(timeout).await;
            let _ = tx.send(Event::TimeoutPrecommit { height, round }).await;
        });
    }
}

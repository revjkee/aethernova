//! Light Client verification for CometBFT/Tendermint-like chains.
//!
//! Основано на публичных спецификациях CometBFT light client (core verification,
//! skipping/bisection) и IBC ICS-07 (Tendermint light client). Верификация
//! заголовков выполняется по коммиту с порогом голосующей мощности и контролем
//! времени и доверительного периода. См. ссылки в комментариях к типам/функциям.
//!
//! Замечания по криптографии:
//! - Подписи проверяются абстрактным `SignatureVerifier` (ed25519 и др. — вне этого файла).
//! - Хеши/идентификаторы блоков и адреса валидаторов — байтовые срезы; привязка к конкретному
//!   формату выполняется в адаптерах сети.
//!
//! Безопасность/производство:
//! - Проверяются только необходимые инварианты заголовка и коммита для LC (без полной валидации блока).
//! - Предусмотрены два режима: `verify_sequential` (последовательный переход) и
//!   `verify_skipping` (пропуск блоков при достаточном пересечении наборов валидаторов).
//!
//! Термины/источники:
//! - CometBFT Light Client: алгоритмы, skipping, bisection.  (docs.cometbft.com)   [spec] 
//! - ICS-07 Tendermint Light Client: client/consensus state, trust level, время.   [ibc]
//! - Требование +2/3 для коммита: Tendermint Core / whitepaper.                    [2/3]
//!
//! [spec] https://docs.cometbft.com/main/spec/light-client/
//! [ibc]  https://ibc.cosmos.network/main/ibc/light-clients/tendermint/overview/
//! [2/3]  https://tendermint.com/static/docs/tendermint.pdf

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use thiserror::Error;

/// Высота и метка времени заголовка.
pub type Height = u64;

/// Монотонное время заголовка (Unix nanos/millis). Здесь используем сек для простоты.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampSeconds(pub u64);

impl TimestampSeconds {
    pub fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self(now.as_secs())
    }
}

/// Доля порога доверия (например, 1/3 или 2/3), как несократимая дробь.
#[derive(Clone, Copy, Debug)]
pub struct TrustThreshold {
    pub num: u64,
    pub den: u64,
}

impl TrustThreshold {
    /// По умолчанию используем 1/3 — как в ICS-07 Tendermint light client.
    /// См. ibc-go: DefaultTrustLevel. 
    pub const ONE_THIRD: Self = Self { num: 1, den: 3 };
    pub const TWO_THIRDS: Self = Self { num: 2, den: 3 };

    pub fn check(&self) {
        assert!(self.den > 0 && self.num > 0 && self.num < self.den, "invalid trust threshold");
    }
}

/// Публичный ключ валидатора — абстракция.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey(pub Vec<u8>);

/// Идентификатор/адрес валидатора. В Tendermint — адрес = hash(pubkey).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatorAddress(pub Vec<u8>);

/// Валидатор и его голосующая мощность.
#[derive(Clone, Debug)]
pub struct Validator {
    pub address: ValidatorAddress,
    pub pubkey: PublicKey,
    pub power: u64,
}

/// Набор валидаторов.
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_power: u64,
}

impl ValidatorSet {
    pub fn index_by_address(&self) -> BTreeMap<ValidatorAddress, &Validator> {
        self.validators.iter().map(|v| (v.address.clone(), v)).collect()
    }
}

/// Заголовок блока, минимально необходимый light-клиенту.
#[derive(Clone, Debug)]
pub struct Header {
    pub height: Height,
    pub time: TimestampSeconds,
    /// Хеш текущего набора валидаторов (для сверки с переданным ValidatorSet).
    pub validators_hash: Vec<u8>,
    /// Хеш следующего набора валидаторов (для последовательного перехода).
    pub next_validators_hash: Vec<u8>,
    /// Хеш ID блока (BlockID.hash). Для верификации коммита.
    pub block_hash: Vec<u8>,
}

/// Подпись валидатора под коммитом (упрощённая форма).
#[derive(Clone, Debug)]
pub struct CommitSig {
    pub validator_address: ValidatorAddress,
    pub signature: Vec<u8>,
    pub timestamp: TimestampSeconds,
    /// Подписанный хеш блока (BlockID.hash).
    pub block_hash: Vec<u8>,
}

/// Коммит для заголовка.
#[derive(Clone, Debug)]
pub struct Commit {
    pub height: Height,
    pub round: u32,
    pub block_hash: Vec<u8>,
    pub signatures: Vec<CommitSig>,
}

/// Подписанный заголовок.
#[derive(Clone, Debug)]
pub struct SignedHeader {
    pub header: Header,
    pub commit: Commit,
}

/// Единица верификации (как в CometBFT LightBlock: signedHeader + validatorSet).
#[derive(Clone, Debug)]
pub struct LightBlock {
    pub signed_header: SignedHeader,
    pub validator_set: ValidatorSet,
}

/// Состояние доверия клиента (trusted).
#[derive(Clone, Debug)]
pub struct TrustedState {
    pub light_block: LightBlock,
    pub trusted_time: TimestampSeconds,
}

/// Абстракция криптопроверки.
pub trait SignatureVerifier: Send + Sync {
    /// Проверка подписи валидатора по сообщению (здесь — `block_hash`).
    fn verify(&self, pubkey: &PublicKey, msg: &[u8], sig: &[u8]) -> bool;
}

/// Ошибки верификации light-клиента.
#[derive(Error, Debug)]
pub enum LightClientError {
    #[error("header height not increasing: trusted={trusted}, target={target}")]
    NonIncreasingHeight { trusted: Height, target: Height },

    #[error("time monotonicity violated")]
    NonMonotonicTime,

    #[error("trusting period expired")]
    TrustingPeriodExpired,

    #[error("header time outside clock drift bounds")]
    ClockDriftViolation,

    #[error("validator set hash mismatch")]
    ValidatorSetHashMismatch,

    #[error("commit height/block mismatch")]
    CommitMismatch,

    #[error("insufficient voting power: got={got}, need>{need}")]
    InsufficientVotingPower { got: u64, need: u64 },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unknown validator in commit")]
    UnknownValidator,
}

/// Утилита: сравнить байтовые хеши.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Проверка базовой согласованности LightBlock.
fn basic_light_block_checks(lb: &LightBlock) -> Result<(), LightClientError> {
    let h = &lb.signed_header.header;
    let c = &lb.signed_header.commit;
    if c.height != h.height || !bytes_eq(&c.block_hash, &h.block_hash) {
        return Err(LightClientError::CommitMismatch);
    }
    Ok(())
}

/// Расчёт подписанной мощности по набору `vs_power_basis` (мощность берём из этого набора),
/// подсчитывая тех, кто подписал `commit` (по адресам).
fn voting_power_in_commit(
    vs_power_basis: &ValidatorSet,
    commit: &Commit,
    verifier: &dyn SignatureVerifier,
    addr_index: &BTreeMap<ValidatorAddress, &Validator>,
) -> Result<u64, LightClientError> {
    let mut power: u64 = 0;
    let mut seen: BTreeSet<&ValidatorAddress> = BTreeSet::new();
    for sig in &commit.signatures {
        let v = match addr_index.get(&sig.validator_address) {
            Some(v) => *v,
            None => return Err(LightClientError::UnknownValidator),
        };
        // Проверяем подпись блока этим валидатором.
        if !verifier.verify(&v.pubkey, &commit.block_hash, &sig.signature) {
            return Err(LightClientError::InvalidSignature);
        }
        // Учитываем мощность уникального валидатора.
        if !seen.contains(&sig.validator_address) {
            power = power.saturating_add(v.power);
            seen.insert(&sig.validator_address);
        }
    }
    Ok(power)
}

/// Проверка требования +2/3 мощности данного валидсетa.
/// Требование коммита со стороны CometBFT: >2/3 валидсилы подписали. [2/3]
fn require_two_thirds(
    vs: &ValidatorSet,
    signed_power: u64,
) -> Result<(), LightClientError> {
    // Требуем strict > 2/3 (а не >=).
    // need = floor(2/3 * total) + 1  → реализуем через сравнение 3*signed > 2*total.
    if (signed_power as u128) * 3u128 > (vs.total_power as u128) * 2u128 {
        Ok(())
    } else {
        let need = (vs.total_power * 2) / 3 + 1;
        Err(LightClientError::InsufficientVotingPower {
            got: signed_power,
            need,
        })
    }
}

/// Проверка порога доверия trust_level (например, 1/3) относительно `vs_power_basis`.
fn require_trust_level(
    vs_power_basis: &ValidatorSet,
    signed_power: u64,
    tl: TrustThreshold,
) -> Result<(), LightClientError> {
    tl.check();
    // Проверяем signed_power/total > tl.num/tl.den  →  den*signed > num*total
    if (signed_power as u128) * (tl.den as u128) > (vs_power_basis.total_power as u128) * (tl.num as u128) {
        Ok(())
    } else {
        let need = ((vs_power_basis.total_power as u128) * (tl.num as u128)) / (tl.den as u128) + 1;
        Err(LightClientError::InsufficientVotingPower {
            got: signed_power,
            need: need as u64,
        })
    }
}

/// Проверка ограничений по времени (trusting period и clock drift) для целевого заголовка.
fn check_time_constraints(
    trusted_time: TimestampSeconds,
    target_time: TimestampSeconds,
    now: TimestampSeconds,
    trusting_period: Duration,
    max_clock_drift: Duration,
) -> Result<(), LightClientError> {
    // 1) Не истёк ли доверительный период (trusted_time + trusting_period > now)
    let tp_end = trusted_time.0.saturating_add(trusting_period.as_secs());
    if now.0 >= tp_end {
        return Err(LightClientError::TrustingPeriodExpired);
    }

    // 2) Контроль дрейфа часов: target_time ≤ now + drift  и target_time ≥ trusted_time - drift.
    if target_time.0 > now.0.saturating_add(max_clock_drift.as_secs()) {
        return Err(LightClientError::ClockDriftViolation);
    }
    if trusted_time.0 > target_time.0.saturating_add(max_clock_drift.as_secs()) {
        return Err(LightClientError::ClockDriftViolation);
    }
    Ok(())
}

/// Sequential verification: требуем полную проверку коммита целевым валид-сетом (2/3) и
/// согласованность `next_validators_hash` предыдущего доверенного заголовка.
/// Соответствует базовому пути без пропуска блоков. [spec][2/3]
pub fn verify_sequential(
    trusted: &TrustedState,
    target: &LightBlock,
    now: TimestampSeconds,
    trusting_period: Duration,
    max_clock_drift: Duration,
    verifier: &dyn SignatureVerifier,
) -> Result<(), LightClientError> {
    basic_light_block_checks(target)?;

    // Высота и время должны расти.
    let h_old = trusted.light_block.signed_header.header.height;
    let t_old = trusted.light_block.signed_header.header.time;
    let h_new = target.signed_header.header.height;
    let t_new = target.signed_header.header.time;

    if h_new <= h_old {
        return Err(LightClientError::NonIncreasingHeight { trusted: h_old, target: h_new });
    }
    if t_new <= t_old {
        return Err(LightClientError::NonMonotonicTime);
    }

    // Временные ограничения.
    check_time_constraints(trusted.trusted_time, t_new, now, trusting_period, max_clock_drift)?;

    // Согласовать переданный ValidatorSet с header.validators_hash
    if !bytes_eq(
        &hash_of_validators(&target.validator_set),
        &target.signed_header.header.validators_hash,
    ) {
        return Err(LightClientError::ValidatorSetHashMismatch);
    }

    // Для последовательного шага также проверим, что trusted.next_validators_hash == target.validators_hash
    if !bytes_eq(
        &trusted.light_block.signed_header.header.next_validators_hash,
        &target.signed_header.header.validators_hash,
    ) {
        return Err(LightClientError::ValidatorSetHashMismatch);
    }

    // Проверка подписи коммита 2/3 мощности текущего валид-сета:
    let vs_map = target.validator_set.index_by_address();
    let signed_power = voting_power_in_commit(
        &target.validator_set,
        &target.signed_header.commit,
        verifier,
        &vs_map,
    )?;
    require_two_thirds(&target.validator_set, signed_power)?;

    Ok(())
}

/// Skipping verification: разрешаем «перепрыгивать» множество блоков, если
/// доверительный порог (обычно ≥1/3) старого набора подписал новый коммит.
/// Требует достаточного пересечения наборов. [spec]
pub fn verify_skipping(
    trusted: &TrustedState,
    target: &LightBlock,
    trust_level: TrustThreshold,
    now: TimestampSeconds,
    trusting_period: Duration,
    max_clock_drift: Duration,
    verifier: &dyn SignatureVerifier,
) -> Result<(), LightClientError> {
    basic_light_block_checks(target)?;

    let h_old = trusted.light_block.signed_header.header.height;
    let t_old = trusted.light_block.signed_header.header.time;
    let h_new = target.signed_header.header.height;
    let t_new = target.signed_header.header.time;

    if h_new <= h_old {
        return Err(LightClientError::NonIncreasingHeight { trusted: h_old, target: h_new });
    }
    if t_new <= t_old {
        return Err(LightClientError::NonMonotonicTime);
    }
    check_time_constraints(trusted.trusted_time, t_new, now, trusting_period, max_clock_drift)?;

    // Хеш текущего набора валидаторов должен соответствовать target.header.validators_hash:
    if !bytes_eq(
        &hash_of_validators(&target.validator_set),
        &target.signed_header.header.validators_hash,
    ) {
        return Err(LightClientError::ValidatorSetHashMismatch);
    }

    // Считаем мощность ПОДПИСЕЙ target.commit по БАЗИСУ МОЩНОСТЕЙ доверенного набора:
    // (пересечение по адресам; подпись проверяется ключом из target.set — адреса совпадают).
    let trusted_vs = &trusted.light_block.validator_set;
    let trusted_index = trusted_vs.index_by_address();

    // Для криптопроверки используем pubkey из target валид-сета (реальные клиенты сверяют адрес=hash(pubkey)).
    let target_index = target.validator_set.index_by_address();

    // Верифицируем подписи и суммируем мощность ТЕХ, кто есть в trusted_set (пересечение).
    let mut power: u64 = 0;
    let mut seen: BTreeSet<ValidatorAddress> = BTreeSet::new();
    for sig in &target.signed_header.commit.signatures {
        let tv = match target_index.get(&sig.validator_address) {
            Some(v) => *v,
            None => return Err(LightClientError::UnknownValidator),
        };
        if !verifier.verify(&tv.pubkey, &target.signed_header.commit.block_hash, &sig.signature) {
            return Err(LightClientError::InvalidSignature);
        }
        if let Some(v_old) = trusted_index.get(&sig.validator_address) {
            if seen.insert(sig.validator_address.clone()) {
                power = power.saturating_add(v_old.power);
            }
        }
    }
    // Проверяем порог доверия относительно trusted.total_power (напр., 1/3).
    require_trust_level(trusted_vs, power, trust_level)?;

    Ok(())
}

/// Хеш набора валидаторов — абстракция (в проде совпадает с вычислением в целевой сети).
/// Здесь — детерминированный порядок по адресу + power + pubkey; НЕ криптографический гарант.
fn hash_of_validators(vs: &ValidatorSet) -> Vec<u8> {
    use blake3::Hasher;
    let mut h = Hasher::new();
    let mut vals = vs.validators.clone();
    vals.sort_by(|a, b| a.address.0.cmp(&b.address.0));
    for v in vals {
        h.update(&(v.power.to_le_bytes()));
        h.update(&v.address.0);
        h.update(&v.pubkey.0);
    }
    h.finalize().as_bytes().to_vec()
}

/* =============================== TESTS =============================== */

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyVerifier;
    impl SignatureVerifier for DummyVerifier {
        fn verify(&self, _pubkey: &PublicKey, _msg: &[u8], _sig: &[u8]) -> bool { true }
    }

    fn mk_addr(i: u8) -> ValidatorAddress { ValidatorAddress(vec![i]) }
    fn mk_pk(i: u8) -> PublicKey { PublicKey(vec![i + 100]) }

    fn mk_validators(n: usize, power: u64) -> ValidatorSet {
        let mut validators = Vec::new();
        for i in 0..n {
            validators.push(Validator {
                address: mk_addr(i as u8),
                pubkey: mk_pk(i as u8),
                power,
            });
        }
        let total_power = power * (n as u64);
        ValidatorSet { validators, total_power }
    }

    fn sign_commit(vs: &ValidatorSet, block_hash: Vec<u8>, sign_count: usize) -> Vec<CommitSig> {
        vs.validators.iter().take(sign_count).map(|v| CommitSig {
            validator_address: v.address.clone(),
            signature: vec![1,2,3], // заглушка
            timestamp: TimestampSeconds(100),
            block_hash: block_hash.clone(),
        }).collect()
    }

    #[test]
    fn sequential_2f3_passes() {
        let verifier = DummyVerifier;
        let vs1 = mk_validators(10, 10); // total=100
        let vs2 = mk_validators(10, 10); // тот же состав для простоты

        let h1 = Header {
            height: 10,
            time: TimestampSeconds(1000),
            validators_hash: hash_of_validators(&vs1),
            next_validators_hash: hash_of_validators(&vs2),
            block_hash: vec![0xaa],
        };
        let c1 = Commit { height: 10, round: 0, block_hash: h1.block_hash.clone(), signatures: sign_commit(&vs1, h1.block_hash.clone(), 8) };
        let lb1 = LightBlock { signed_header: SignedHeader { header: h1, commit: c1 }, validator_set: vs1.clone() };
        let trusted = TrustedState { light_block: lb1, trusted_time: TimestampSeconds(1000) };

        let h2 = Header {
            height: 11,
            time: TimestampSeconds(1100),
            validators_hash: hash_of_validators(&vs2),
            next_validators_hash: hash_of_validators(&vs2), // не важно для теста
            block_hash: vec![0xbb],
        };
        // подписи >2/3 (70 из 100) → достаточно
        let c2 = Commit { height: 11, round: 0, block_hash: h2.block_hash.clone(), signatures: sign_commit(&vs2, h2.block_hash.clone(), 8) };
        let lb2 = LightBlock { signed_header: SignedHeader { header: h2, commit: c2 }, validator_set: vs2 };

        let now = TimestampSeconds(1200);
        let res = verify_sequential(&trusted, &lb2, now, Duration::from_secs(3600), Duration::from_secs(10), &verifier);
        assert!(res.is_ok());
    }

    #[test]
    fn skipping_1_3_overlap_passes() {
        let verifier = DummyVerifier;
        // Старый набор: 10 валидаторов по 10 power (total=100)
        let vs_old = mk_validators(10, 10);
        // Новый набор: переупорядоченный (адреса совпадают), но мы «подписываем» только 4 валидатора (40 power)
        let vs_new = mk_validators(10, 10);

        let h_old = Header {
            height: 10,
            time: TimestampSeconds(1000),
            validators_hash: hash_of_validators(&vs_old),
            next_validators_hash: hash_of_validators(&vs_new),
            block_hash: vec![0xaa],
        };
        let c_old = Commit { height: 10, round: 0, block_hash: h_old.block_hash.clone(), signatures: sign_commit(&vs_old, h_old.block_hash.clone(), 8) };
        let lb_old = LightBlock { signed_header: SignedHeader { header: h_old, commit: c_old }, validator_set: vs_old.clone() };
        let trusted = TrustedState { light_block: lb_old, trusted_time: TimestampSeconds(1000) };

        let h_new = Header {
            height: 20,
            time: TimestampSeconds(1500),
            validators_hash: hash_of_validators(&vs_new),
            next_validators_hash: hash_of_validators(&vs_new),
            block_hash: vec![0xbb],
        };
        // Подписали ровно 4 (40%) — порог 1/3 выполнен.
        let c_new = Commit { height: 20, round: 0, block_hash: h_new.block_hash.clone(), signatures: sign_commit(&vs_new, h_new.block_hash.clone(), 4) };
        let lb_new = LightBlock { signed_header: SignedHeader { header: h_new, commit: c_new }, validator_set: vs_new };

        let now = TimestampSeconds(1600);
        let res = verify_skipping(&trusted, &lb_new, TrustThreshold::ONE_THIRD, now, Duration::from_secs(3600), Duration::from_secs(10), &verifier);
        assert!(res.is_ok());
    }
}

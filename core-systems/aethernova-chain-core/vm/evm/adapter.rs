// aethernova-chain-core/vm/evm/adapter.rs
//! EVM adapter на базе REVM для интеграции с внутренним состоянием узла.
//! Предоставляет исполнение транзакций/вызовов и коммит диффа в бэкенд состояния.

#![allow(clippy::needless_return)]

use std::collections::HashMap;
use std::sync::Arc;

use revm::{
    primitives::{
        keccak256,
        AccountInfo, Address, BlockEnv, Bytecode, CfgEnv, SpecId, TxEnv, B256, U256,
        Bytes, TxKind, KECCAK256_EMPTY,
    },
    Database, DatabaseCommit, EvmBuilder, ExecuteCommitEvm,
};
use revm::context::{Context, ContextSetters};
use revm::context::result::ExecutionResult;
use revm::state::{Account as RevmAccount, EvmStorageSlot};

/// Ошибки адаптера.
#[derive(thiserror::Error, Debug)]
pub enum AdapterError {
    #[error("backend error: {0}")]
    Backend(String),
    #[error("revm error: {0}")]
    Revm(String),
}

/// Минимальный интерфейс к вашему состоянию узла.
/// Реализуйте этот трейт для вашей State/Storage подсистемы.
pub trait Backend: Send + Sync + 'static {
    /// Существует ли аккаунт.
    fn account_exists(&self, addr: Address) -> Result<bool, String>;
    /// Прочитать базовую информацию аккаунта.
    fn account_basic(&self, addr: Address) -> Result<Option<BackendAccount>, String>;
    /// Прочитать код по хэшу.
    fn code_by_hash(&self, code_hash: B256) -> Result<Option<Bytes>, String>;
    /// Получить значение слота хранилища (32 байта в U256).
    fn storage_get(&self, addr: Address, key: B256) -> Result<U256, String>;
    /// Получить блокхэш (для опкода BLOCKHASH).
    fn block_hash(&self, number: u64) -> Result<B256, String>;

    /// Коммит изменений по аккаунтам/стораджу/кодам (после успешного выполнения tx).
    fn commit(&self, changes: BackendChanges) -> Result<(), String>;
}

/// Представление аккаунта в бэкенде.
#[derive(Clone, Debug)]
pub struct BackendAccount {
    pub nonce: u64,
    pub balance: U256,
    /// Хэш кода, если код не пуст.
    pub code_hash: Option<B256>,
    /// Необязательная инлайн-оптимизация: сразу код (если доступен).
    pub code: Option<Bytes>,
}

/// Изменения для коммита.
#[derive(Default, Debug)]
pub struct BackendChanges {
    pub accounts: HashMap<Address, BackendAccountChange>,
    pub storage: HashMap<(Address, B256), U256>,
    pub selfdestruct: Vec<Address>,
    pub codes: HashMap<B256, Bytes>,
}

#[derive(Debug)]
pub enum BackendAccountChange {
    Update { nonce: u64, balance: U256, code_hash: Option<B256> },
    Delete,
}

/// Обертка БД для REVM поверх нашего Backend.
pub struct EvmDb<B: Backend> {
    backend: Arc<B>,
}

impl<B: Backend> EvmDb<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }
}

/// Реализация интерфейса чтения состояния для REVM.
impl<B: Backend> Database for EvmDb<B> {
    type Error = AdapterError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let acc = self.backend.account_basic(address)
            .map_err(AdapterError::Backend)?;
        if let Some(a) = acc {
            // Код: либо инлайн, либо позднее через code_by_hash.
            let bytecode = if let Some(code) = a.code {
                Some(Bytecode::new_raw(code.into()).expect("valid bytecode bounds"))
            } else {
                None
            };
            let code_hash = a.code_hash.unwrap_or(KECCAK256_EMPTY);
            Ok(Some(AccountInfo {
                balance: a.balance,
                nonce: a.nonce,
                code_hash,
                code: bytecode.map(Arc::new),
            }))
        } else {
            Ok(None)
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let bytes = self.backend.code_by_hash(code_hash)
            .map_err(AdapterError::Backend)?
            .unwrap_or_default();
        Ok(Bytecode::new_raw(bytes.into()).expect("valid bytecode bounds"))
    }

    fn storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        // Ключ слота — 32 байта, REVM передает U256.
        let key_b256 = B256::from(key.to_be_bytes());
        let val = self.backend.storage_get(address, key_b256)
            .map_err(AdapterError::Backend)?;
        Ok(val)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.backend.block_hash(number).map_err(AdapterError::Backend)
    }
}

/// Коммит изменений из REVM в наш Backend.
impl<B: Backend> DatabaseCommit for EvmDb<B> {
    fn commit(&mut self, changes: HashMap<Address, RevmAccount>) {
        let mut patch = BackendChanges::default();

        for (addr, acc) in changes {
            match acc.info {
                Some(info) => {
                    // Обновление аккаунта.
                    let code_hash = if let Some(code) = &info.code {
                        // Если REVM предоставляет код, хешируем (keccak256) и добавляем в change set.
                        let bytes: Bytes = code.bytes().clone().into();
                        let chash = keccak256(&bytes);
                        patch.codes.insert(chash, bytes);
                        Some(chash)
                    } else {
                        // Используем имеющийся hash (может быть KECCAK256_EMPTY).
                        Some(info.code_hash)
                    };

                    patch.accounts.insert(
                        addr,
                        BackendAccountChange::Update {
                            nonce: info.nonce,
                            balance: info.balance,
                            code_hash,
                        },
                    );
                }
                None => {
                    // Удаление аккаунта (selfdestruct или "опустел").
                    patch.accounts.insert(addr, BackendAccountChange::Delete);
                    patch.selfdestruct.push(addr);
                }
            }

            // Фиксируем измененные storage-слоты.
            for (slot_key, slot) in acc.storage {
                if slot.is_changed() {
                    let v = slot.present_value();
                    patch.storage.insert((addr, B256::from(slot_key.to_be_bytes())), v);
                }
            }
        }

        // Пробрасываем в бэкенд.
        let _ = self.backend.commit(patch);
    }
}

/// Конфигурация адаптера.
#[derive(Clone, Debug)]
pub struct EvmConfig {
    pub chain_id: u64,
    pub spec_id: SpecId, // например, SpecId::CANCUN или PRAGUE
    /// Разрешить/запретить баланс-чек до списания газа (см. ревизионирование сети).
    pub disable_balance_check: bool,
    /// Лимит размера кода контракта (байт). None = дефолт сети.
    pub max_code_size: Option<usize>,
}

impl Default for EvmConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            spec_id: SpecId::CANCUN,
            disable_balance_check: false,
            max_code_size: None,
        }
    }
}

/// Параметры блока для окружения EVM.
#[derive(Clone, Debug)]
pub struct EvmBlockParams {
    pub number: U256,
    pub timestamp: U256,
    pub gas_limit: U256,
    pub basefee: U256,            // EIP-1559
    pub coinbase: Address,
    pub prevrandao: Option<B256>, // EIP-4399
}

/// Результат исполнения.
#[derive(Clone, Debug)]
pub struct ExecResult {
    pub status: ExecStatus,
    pub gas_used: u64,
    pub logs: Vec<revm::primitives::Log>,
    pub output: Bytes,
    pub created: Option<Address>,
}

#[derive(Clone, Debug)]
pub enum ExecStatus {
    Success,
    Revert,
    Halt,
}

/// Основной адаптер.
pub struct EvmAdapter<B: Backend> {
    db: EvmDb<B>,
    cfg: EvmConfig,
}

impl<B: Backend> EvmAdapter<B> {
    pub fn new(backend: Arc<B>, cfg: EvmConfig) -> Self {
        Self { db: EvmDb::new(backend), cfg }
    }

    /// Сформировать CfgEnv с учетом сети/спека и ограничений.
    fn build_cfg(&self) -> CfgEnv {
        let mut cfg = CfgEnv::default();
        cfg.chain_id = self.cfg.chain_id;
        cfg.spec_id = self.cfg.spec_id;
        cfg.disable_balance_check = self.cfg.disable_balance_check;
        if let Some(limit) = self.cfg.max_code_size {
            cfg.limit_code_size = Some(limit as u64);
        }
        cfg
    }

    /// Сформировать BlockEnv.
    fn build_block_env(&self, p: &EvmBlockParams) -> BlockEnv {
        BlockEnv {
            number: p.number,
            timestamp: p.timestamp,
            gas_limit: p.gas_limit,
            basefee: p.basefee,
            coinbase: p.coinbase,
            difficulty: U256::ZERO, // после Paris не используется
            prevrandao: p.prevrandao,
            ..Default::default()
        }
    }

    /// Исполнение произвольного TxEnv с коммитом в бэкенд.
    pub fn execute_tx(&mut self, block: &EvmBlockParams, mut tx: TxEnv) -> Result<ExecResult, AdapterError> {
        // Обеспечим корректность поля to: None => CREATE
        if matches!(tx.kind, TxKind::Call(_)) == false && matches!(tx.kind, TxKind::Create) == false {
            // Защитный барьер для будущих расширений типов.
            tx.kind = match tx.to {
                Some(to) => TxKind::Call(to),
                None => TxKind::Create,
            };
        }

        // Строим контекст и исполняем с коммитом.
        let cfg = self.build_cfg();
        let block_env = self.build_block_env(block);

        let ctx = Context::mainnet()
            .with_db(self.db_by_value())
            .modify_cfg_chained(|c| *c = cfg.clone())
            .modify_block_chained(|b| *b = block_env.clone());

        let mut evm = EvmBuilder::new_with_ctx(ctx).build();

        // Вариант 1: передаем TxEnv прямо в транзакцию и коммитим состояние.
        let result = evm.transact_commit(tx)
            .map_err(|e| AdapterError::Revm(format!("{e:?}")))?;

        // Преобразуем ExecutionResult.
        let (status, gas_used, logs, output, created) = match result {
            ExecutionResult::Success { gas_used, logs, output, .. } => {
                (ExecStatus::Success, gas_used, logs, output.into_data(), output.created_address())
            }
            ExecutionResult::Revert { gas_used, output } => {
                (ExecStatus::Revert, gas_used, vec![], Bytes::from(output), None)
            }
            ExecutionResult::Halt { gas_used, .. } => {
                (ExecStatus::Halt, gas_used, vec![], Bytes::new(), None)
            }
        };

        Ok(ExecResult { status, gas_used, logs, output, created })
    }

    /// Удобный helper для обычного CALL без создания контракта.
    pub fn eth_call(
        &mut self,
        block: &EvmBlockParams,
        caller: Address,
        to: Address,
        value: U256,
        data: Bytes,
        gas_limit: u64,
        max_fee_per_gas: Option<U256>,
        max_priority_fee_per_gas: Option<U256>,
    ) -> Result<ExecResult, AdapterError> {
        let mut tx = TxEnv::default();
        tx.caller = caller;
        tx.gas_limit = gas_limit;
        tx.kind = TxKind::Call(to);
        tx.value = value;
        tx.data = data;
        // EIP-1559 поля:
        tx.gas_price = U256::ZERO; // не используется при 1559
        tx.max_fee_per_gas = max_fee_per_gas.unwrap_or_default();
        tx.max_priority_fee_per_gas = max_priority_fee_per_gas.unwrap_or_default();
        tx.chain_id = Some(self.cfg.chain_id);
        self.execute_tx(block, tx)
    }

    /// Передать владение DB (для Context::with_db, который берет по значению).
    fn db_by_value(&mut self) -> EvmDb<B> {
        // Простое перемещение self.db по значению с заменой.
        let db = EvmDb { backend: Arc::clone(&self.db.backend) };
        db
    }
}

/// Вспомогательные утилиты.

/// Вычислить хэш кода контракта (keccak256). Возвращает KECCAK256_EMPTY для пустого.
pub fn code_hash_of(code: &[u8]) -> B256 {
    if code.is_empty() {
        KECCAK256_EMPTY
    } else {
        keccak256(code)
    }
}

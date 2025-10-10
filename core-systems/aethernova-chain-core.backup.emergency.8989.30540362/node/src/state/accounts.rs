//! Aethernova node: state/accounts
//!
//! Промышленный модуль состояния аккаунтов:
//! - Address/Account модель (balance u128, nonce u64, code_hash)
//! - KV storage на аккаунт (Vec<u8> -> Vec<u8>)
//! - Безопасная бухгалтерия: credit/debit с проверками переполнений
//! - Журналирование изменений (checkpoint/commit/rollback)
//! - Абстракция бэкенда StateBackend + InMemoryBackend
//! - Хеширование и корень состояния (Blake3), меркло-свёртка по листам
//! - Дет. бинарная сериализация через Borsh
//!
//! Источники:
//!  - Ethereum Yellow Paper (account model): https://ethereum.github.io/yellowpaper/paper.pdf
//!  - Blake3 crate: https://docs.rs/blake3/latest/blake3/
//!  - Borsh crate: https://docs.rs/borsh/latest/borsh/
//!  - Rust std HashMap/RwLock: https://doc.rust-lang.org/std/collections/struct.HashMap.html
//!                                   https://doc.rust-lang.org/std/sync/struct.RwLock.html

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Arc, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use blake3::Hasher as Blake3Hasher;

/// Размер адреса в байтах.
pub const ADDRESS_LEN: usize = 32;

/// Удобный тип для баланса.
pub type Balance = u128;

/// Однородный тип ключей storage.
pub type StorageKey = Vec<u8>;

/// Однородный тип значений storage.
pub type StorageValue = Vec<u8>;

/// Адрес аккаунта (32 байта).
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    pub fn new(bytes: [u8; ADDRESS_LEN]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }
}

impl From<[u8; ADDRESS_LEN]> for Address {
    fn from(v: [u8; ADDRESS_LEN]) -> Self {
        Address::new(v)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}
impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Структура аккаунта в стиле account-based моделей.
/// Отсылка: Ethereum Yellow Paper (balance/nonce/codeHash).
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: Balance,
    /// Хеш кода (если есть), для совместимости с account-based логикой.
    pub code_hash: Option<[u8; 32]>,
}

impl Debug for Account {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("nonce", &self.nonce)
            .field("balance", &self.balance)
            .field("code_hash", &self.code_hash.as_ref().map(hex::encode))
            .finish()
    }
}

impl Account {
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            code_hash: None,
        }
    }

    /// Пополнение баланса с проверкой переполнения.
    pub fn credit(&mut self, amount: Balance) -> Result<(), StateError> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or(StateError::BalanceOverflow)?;
        Ok(())
    }

    /// Списание с проверкой недостаточности средств.
    pub fn debit(&mut self, amount: Balance) -> Result<(), StateError> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or(StateError::InsufficientFunds)?;
        Ok(())
    }

    /// Инкремент nonce (например, после успешной транзакции).
    pub fn bump_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }
}

/// Ошибки состояния.
#[derive(thiserror::Error, Debug)]
pub enum StateError {
    #[error("account not found")]
    AccountNotFound,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("balance overflow")]
    BalanceOverflow,
    #[error("storage key too large")]
    StorageKeyTooLarge,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Хешер состояния (адаптер).
pub trait StateHasher: Send + Sync {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// Реализация Blake3 (см. docs.rs/blake3).
#[derive(Default, Clone)]
pub struct Blake3;
impl StateHasher for Blake3 {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut h = Blake3Hasher::new();
        h.update(data);
        *h.finalize().as_bytes()
    }
}

/// Абстракция бэкенда состояния.
/// Для корня состояния нужны итераторы по аккаунтам/стораджу.
pub trait StateBackend: Send + Sync {
    /// Получить аккаунт (или None).
    fn get_account(&self, addr: &Address) -> Option<Account>;
    /// Создать/обновить аккаунт.
    fn put_account(&mut self, addr: Address, acc: Account);
    /// Удалить аккаунт.
    fn del_account(&mut self, addr: &Address);

    /// Прочитать storage по ключу.
    fn get_storage(&self, addr: &Address, key: &StorageKey) -> Option<StorageValue>;
    /// Записать storage.
    fn put_storage(&mut self, addr: Address, key: StorageKey, val: StorageValue);
    /// Удалить storage.
    fn del_storage(&mut self, addr: &Address, key: &StorageKey);

    /// Итератор по аккаунтам (для расчёта корня состояния).
    fn iter_accounts<'a>(&'a self) -> Box<dyn Iterator<Item = (Address, Account)> + 'a>;

    /// Итератор по сториджу конкретного аккаунта.
    fn iter_storage<'a>(
        &'a self,
        addr: &Address,
    ) -> Box<dyn Iterator<Item = (StorageKey, StorageValue)> + 'a>;
}

/// In-memory реализация бэкенда: HashMap<Address, Account> + HashMap<Address, HashMap<K,V>>.
/// Документация std::collections::HashMap: см. официальные ссылки stdlib.
#[derive(Default, Clone)]
pub struct InMemoryBackend {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<StorageKey, StorageValue>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
        }
    }
}

impl StateBackend for InMemoryBackend {
    fn get_account(&self, addr: &Address) -> Option<Account> {
        self.accounts.get(addr).cloned()
    }

    fn put_account(&mut self, addr: Address, acc: Account) {
        self.accounts.insert(addr, acc);
    }

    fn del_account(&mut self, addr: &Address) {
        self.accounts.remove(addr);
        self.storage.remove(addr);
    }

    fn get_storage(&self, addr: &Address, key: &StorageKey) -> Option<StorageValue> {
        self.storage.get(addr).and_then(|m| m.get(key).cloned())
    }

    fn put_storage(&mut self, addr: Address, key: StorageKey, val: StorageValue) {
        self.storage.entry(addr).or_default().insert(key, val);
    }

    fn del_storage(&mut self, addr: &Address, key: &StorageKey) {
        if let Some(m) = self.storage.get_mut(addr) {
            m.remove(key);
        }
    }

    fn iter_accounts<'a>(&'a self) -> Box<dyn Iterator<Item = (Address, Account)> + 'a> {
        Box::new(self.accounts.iter().map(|(a, ac)| (*a, ac.clone())))
    }

    fn iter_storage<'a>(
        &'a self,
        addr: &Address,
    ) -> Box<dyn Iterator<Item = (StorageKey, StorageValue)> + 'a> {
        Box::new(
            self.storage
                .get(addr)
                .into_iter()
                .flat_map(|m| m.iter())
                .map(|(k, v)| (k.clone(), v.clone())),
        )
    }
}

/// Запись журнала изменений, позволяющая откат к checkpoint.
#[derive(Clone)]
enum JournalRecord {
    /// Предыдущее состояние аккаунта (None — удалён или отсутствовал).
    AccountUpdate { addr: Address, prev: Option<Account> },
    /// Предыдущее состояние storage-ключа (None — отсутствовал).
    StorageUpdate {
        addr: Address,
        key: StorageKey,
        prev: Option<StorageValue>,
    },
}

/// Состояние с журналированием поверх абстрактного бэкенда.
pub struct State<B: StateBackend, H: StateHasher = Blake3> {
    backend: Arc<RwLock<B>>,
    hasher: H,
    journal: Vec<JournalRecord>,
    checkpoints: Vec<usize>, // индексы начала батча изменений
}

impl<B: StateBackend, H: StateHasher> State<B, H> {
    pub fn new(backend: B, hasher: H) -> Self {
        Self {
            backend: Arc::new(RwLock::new(backend)),
            hasher,
            journal: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    /// Снимок (начало транзакции): пишем маркер в стек.
    pub fn checkpoint(&mut self) {
        self.checkpoints.push(self.journal.len());
    }

    /// Откат к последнему checkpoint.
    pub fn rollback(&mut self) {
        if let Some(start) = self.checkpoints.pop() {
            // Отменяем записи в обратном порядке
            for rec in self.journal.drain(start..).rev() {
                match rec {
                    JournalRecord::AccountUpdate { addr, prev } => {
                        let mut b = self.backend.write().unwrap();
                        match prev {
                            Some(acc_prev) => b.put_account(addr, acc_prev),
                            None => b.del_account(&addr),
                        }
                    }
                    JournalRecord::StorageUpdate { addr, key, prev } => {
                        let mut b = self.backend.write().unwrap();
                        match prev {
                            Some(v_prev) => b.put_storage(addr, key, v_prev),
                            None => b.del_storage(&addr, &key),
                        }
                    }
                }
            }
        }
    }

    /// Фиксация изменений: просто забываем журнал данного checkpoint.
    pub fn commit(&mut self) {
        let _ = self.checkpoints.pop();
        // Ничего не откатываем: изменения уже в бэкенде, журнал для checkpoint стирается срезом.
        // Остатки журнала (если были вложенные checkpoint'ы) остаются.
    }

    /// Получить аккаунт (копию).
    pub fn account(&self, addr: &Address) -> Option<Account> {
        self.backend.read().unwrap().get_account(addr)
    }

    /// Создать или заменить аккаунт. Журналируем «предыдущее значение».
    pub fn put_account(&mut self, addr: Address, acc: Account) {
        let prev = self.backend.read().unwrap().get_account(&addr);
        self.journal.push(JournalRecord::AccountUpdate {
            addr,
            prev: prev.clone(),
        });
        self.backend.write().unwrap().put_account(addr, acc);
    }

    /// Удалить аккаунт с журналированием.
    pub fn del_account(&mut self, addr: &Address) {
        let prev = self.backend.read().unwrap().get_account(addr);
        self.journal.push(JournalRecord::AccountUpdate {
            addr: *addr,
            prev,
        });
        self.backend.write().unwrap().del_account(addr);
    }

    /// Пополнить баланс с проверками и журналированием.
    pub fn credit(&mut self, addr: &Address, amount: Balance) -> Result<(), StateError> {
        let mut b = self.backend.write().unwrap();
        let prev = b.get_account(addr).ok_or(StateError::AccountNotFound)?;
        let mut next = prev.clone();
        drop(b);

        next.credit(amount)?;
        // Журналируем предыдущее значение и записываем новое
        self.journal.push(JournalRecord::AccountUpdate {
            addr: *addr,
            prev: Some(prev.clone()),
        });
        self.backend.write().unwrap().put_account(*addr, next);
        Ok(())
    }

    /// Списать баланс с проверками и журналированием.
    pub fn debit(&mut self, addr: &Address, amount: Balance) -> Result<(), StateError> {
        let mut b = self.backend.write().unwrap();
        let prev = b.get_account(addr).ok_or(StateError::AccountNotFound)?;
        let mut next = prev.clone();
        drop(b);

        next.debit(amount)?;
        self.journal.push(JournalRecord::AccountUpdate {
            addr: *addr,
            prev: Some(prev.clone()),
        });
        self.backend.write().unwrap().put_account(*addr, next);
        Ok(())
    }

    /// Инкремент nonce аккаунта.
    pub fn bump_nonce(&mut self, addr: &Address) -> Result<(), StateError> {
        let mut b = self.backend.write().unwrap();
        let prev = b.get_account(addr).ok_or(StateError::AccountNotFound)?;
        let mut next = prev.clone();
        drop(b);

        next.bump_nonce();
        self.journal.push(JournalRecord::AccountUpdate {
            addr: *addr,
            prev: Some(prev.clone()),
        });
        self.backend.write().unwrap().put_account(*addr, next);
        Ok(())
    }

    /// Читать storage ключа.
    pub fn storage_get(&self, addr: &Address, key: &StorageKey) -> Option<StorageValue> {
        self.backend.read().unwrap().get_storage(addr, key)
    }

    /// Писать storage ключ с журналированием.
    pub fn storage_put(
        &mut self,
        addr: Address,
        key: StorageKey,
        val: StorageValue,
    ) -> Result<(), StateError> {
        let prev = self.backend.read().unwrap().get_storage(&addr, &key);
        self.journal.push(JournalRecord::StorageUpdate {
            addr,
            key: key.clone(),
            prev,
        });
        self.backend.write().unwrap().put_storage(addr, key, val);
        Ok(())
    }

    /// Удалить storage ключ с журналированием.
    pub fn storage_del(&mut self, addr: &Address, key: &StorageKey) {
        let prev = self.backend.read().unwrap().get_storage(addr, key);
        self.journal.push(JournalRecord::StorageUpdate {
            addr: *addr,
            key: key.clone(),
            prev,
        });
        self.backend.write().unwrap().del_storage(addr, key);
    }

    /// Рассчитать хеш аккаунта (детерминированная сериализация через Borsh).
    pub fn account_hash(&self, acc: &Account) -> [u8; 32] {
        let bytes = acc.try_to_vec().expect("borsh serialize");
        self.hasher.hash(&bytes)
    }

    /// Рассчитать хеш хранилища аккаунта (по отсортированным ключам).
    pub fn storage_root(&self, addr: &Address) -> [u8; 32] {
        let mut kv: Vec<(StorageKey, StorageValue)> =
            self.backend.read().unwrap().iter_storage(addr).collect();
        // Стабильный порядок
        kv.sort_by(|a, b| a.0.cmp(&b.0));

        let leaves: Vec<[u8; 32]> = kv
            .into_iter()
            .map(|(k, v)| {
                let mut buf = Vec::with_capacity(k.len() + v.len());
                buf.extend_from_slice(&k);
                buf.extend_from_slice(&v);
                self.hasher.hash(&buf)
            })
            .collect();

        merkle_fold(&self.hasher, &leaves)
    }

    /// Рассчитать корень состояния по всем аккаунтам: hash(addr || account_hash || storage_root).
    pub fn state_root(&self) -> [u8; 32] {
        // Собираем пары (addr, acc), сортируем по адресу
        let mut items: Vec<(Address, Account)> = self.backend.read().unwrap().iter_accounts().collect();
        items.sort_by(|(a1, _), (a2, _)| a1.as_bytes().cmp(a2.as_bytes()));

        let leaves: Vec<[u8; 32]> = items
            .into_iter()
            .map(|(addr, acc)| {
                let ah = self.account_hash(&acc);
                let sr = self.storage_root(&addr);
                let mut buf = Vec::with_capacity(ADDRESS_LEN + 32 + 32);
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&ah);
                buf.extend_from_slice(&sr);
                self.hasher.hash(&buf)
            })
            .collect();

        merkle_fold(&self.hasher, &leaves)
    }

    /// Доступ к бэкенду (read-only).
    pub fn backend(&self) -> Arc<RwLock<B>> {
        Arc::clone(&self.backend)
    }
}

/// Меркло-свёртка по списку листов (pairwise hash left||right; при нечётном — дублируем последний).
fn merkle_fold<H: StateHasher>(hasher: &H, leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return hasher.hash(&[]);
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&left);
            buf.extend_from_slice(&right);
            next.push(hasher.hash(&buf));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; ADDRESS_LEN];
        a[0] = n;
        Address::from(a)
    }

    #[test]
    fn test_account_credit_debit() {
        let mut st = State::new(InMemoryBackend::new(), Blake3::default());
        let a = addr(1);
        st.put_account(a, Account::empty());

        st.credit(&a, 100).unwrap();
        assert_eq!(st.account(&a).unwrap().balance, 100);

        st.debit(&a, 40).unwrap();
        assert_eq!(st.account(&a).unwrap().balance, 60);

        let err = st.debit(&a, 100).unwrap_err();
        matches!(err, StateError::InsufficientFunds);
    }

    #[test]
    fn test_checkpoint_rollback_commit() {
        let mut st = State::new(InMemoryBackend::new(), Blake3::default());
        let a = addr(2);
        st.put_account(a, Account::empty());

        st.checkpoint();
        st.credit(&a, 50).unwrap();
        st.storage_put(a, b"k".to_vec(), b"v".to_vec()).unwrap();

        // Откат
        st.rollback();
        assert_eq!(st.account(&a).unwrap().balance, 0);
        assert!(st.storage_get(&a, &b"k".to_vec()).is_none());

        // Повторно — commit
        st.checkpoint();
        st.credit(&a, 70).unwrap();
        st.commit();
        assert_eq!(st.account(&a).unwrap().balance, 70);
    }

    #[test]
    fn test_state_root_determinism() {
        let mut st1 = State::new(InMemoryBackend::new(), Blake3::default());
        let mut st2 = State::new(InMemoryBackend::new(), Blake3::default());

        for i in 0u8..10 {
            let a = addr(i);
            let mut acc = Account::empty();
            acc.balance = (i as u128) * 100;
            st1.put_account(a, acc.clone());
            st2.put_account(a, acc);
            if i % 2 == 0 {
                st1.storage_put(a, vec![1, i], vec![2, i]).unwrap();
                st2.storage_put(a, vec![1, i], vec![2, i]).unwrap();
            }
        }

        let r1 = st1.state_root();
        let r2 = st2.state_root();
        assert_eq!(r1, r2, "roots must be equal for equal state");
    }
}

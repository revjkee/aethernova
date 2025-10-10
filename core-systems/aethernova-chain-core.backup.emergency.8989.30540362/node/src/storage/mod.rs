//! Aethernova Chain Core - Storage layer
//!
//! Features:
//! - Async storage trait (`Storage`) using `async-trait` (stable).
//! - In-memory backend (`MemStorage`) on top of `tokio::sync::RwLock`.
//! - Filesystem backend (`FsStorage`) with atomic writes via temp file + rename,
//!   per-key sharding by SHA-256, TTL, background GC on read.
//! - Batches (`Batch`) with best-effort atomicity within backend lock.
//! - Typed facade (`TypedStorage<T>`) using `serde` + `bincode`.
//!
//! References:
//! - async-trait macro enabling `async fn` in traits: docs.rs/async-trait. :contentReference[oaicite:1]{index=1}
//! - Tokio fs utilities & atomic-ish `rename` within same mount: docs.rs/tokio::fs. :contentReference[oaicite:2]{index=2}
//! - Atomic write pattern (temp file in same dir then replace): `tempfile`, `atomic-write-file`. :contentReference[oaicite:3]{index=3}
/*! - Serialization: `serde` + `bincode`. */ //! :contentReference[oaicite:4]{index=4}
//! - Hashing: `sha2` (SHA-256). :contentReference[oaicite:5]{index=5}
//! - Errors: `thiserror` derive. :contentReference[oaicite:6]{index=6}
//! - Async RwLock: `tokio::sync::RwLock`. :contentReference[oaicite:7]{index=7}
//!
//! Suggested dependencies (Cargo.toml):
//! tokio = { version = "1", features = ["fs", "rt-multi-thread", "macros", "sync"] }
//! async-trait = "0.1"
//! serde = { version = "1", features = ["derive"] }
//! bincode = "2"                 # compact, fast binary serialization
//! bytes = "1"
//! thiserror = "1"
//! sha2 = "0.10"
//! hex = "0.4"
//! tempfile = "3"

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

const INDEX_FILE: &str = "_index.bin";

/// Milliseconds since UNIX epoch
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Entry metadata, including TTL.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Creation time (ms since epoch).
    pub created_ms: u64,
    /// Optional expiration absolute timestamp in ms since epoch.
    pub expires_ms: Option<u64>,
}

impl Meta {
    pub fn new(ttl: Option<Duration>) -> Self {
        let created_ms = now_ms();
        let expires_ms = ttl.map(|d| created_ms + d.as_millis() as u64);
        Self { created_ms, expires_ms }
    }
    #[inline]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_ms.map(|e| now >= e).unwrap_or(false)
    }
}

/// A single key-value pair for batch operations.
#[derive(Clone, Debug)]
pub enum BatchItem {
    Put { key: Vec<u8>, value: Bytes, meta: Meta },
    Delete { key: Vec<u8> },
}

/// A write batch.
#[derive(Default)]
pub struct Batch {
    items: Vec<BatchItem>,
}
impl Batch {
    pub fn put(mut self, key: impl Into<Vec<u8>>, value: impl Into<Bytes>, ttl: Option<Duration>) -> Self {
        self.items.push(BatchItem::Put {
            key: key.into(),
            value: value.into(),
            meta: Meta::new(ttl),
        });
        self
    }
    pub fn delete(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.items.push(BatchItem::Delete { key: key.into() });
        self
    }
}

/// Storage errors.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("not found")]
    NotFound,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] Box<bincode::ErrorKind>),
    #[error("other: {0}")]
    Other(String),
}

/// Unified async storage trait.
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    /// Store a value with optional TTL.
    async fn put(&self, key: &[u8], value: Bytes, ttl: Option<Duration>) -> Result<(), StorageError>;
    /// Get a value (returns None if missing or expired).
    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, StorageError>;
    /// Delete a key (no error if not exists).
    async fn delete(&self, key: &[u8]) -> Result<(), StorageError>;
    /// Check if key exists and not expired.
    async fn exists(&self, key: &[u8]) -> Result<bool, StorageError>;
    /// List keys by binary prefix (may be O(n) depending on backend).
    async fn list_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StorageError>;
    /// Apply a write batch atomically w.r.t. backend lock.
    async fn write_batch(&self, batch: Batch) -> Result<(), StorageError>;
    /// Force flush/persist if applicable.
    async fn flush(&self) -> Result<(), StorageError>;
}

/// Typed facade over any `Storage`: serializes values via bincode.
pub struct TypedStorage<S: Storage> {
    inner: S,
}
impl<S: Storage> TypedStorage<S> {
    pub fn new(inner: S) -> Self { Self { inner } }

    pub async fn put<T: Serialize + Send + Sync>(
        &self,
        key: &[u8],
        value: &T,
        ttl: Option<Duration>,
    ) -> Result<(), StorageError> {
        let bytes = bincode::serialize(value)?;
        self.inner.put(key, Bytes::from(bytes), ttl).await
    }

    pub async fn get<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>, StorageError> {
        match self.inner.get(key).await? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None),
        }
    }

    pub async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(key).await
    }

    pub async fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        self.inner.exists(key).await
    }
}

// ============================ In-memory backend ===============================

#[derive(Clone)]
pub struct MemStorage {
    inner: std::sync::Arc<RwLock<HashMap<Vec<u8>, (Meta, Bytes)>>>,
}

impl Debug for MemStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemStorage").finish()
    }
}

impl MemStorage {
    pub fn new() -> Self {
        Self { inner: std::sync::Arc::new(RwLock::new(HashMap::new())) }
    }
    fn gc_expired(map: &mut HashMap<Vec<u8>, (Meta, Bytes)>) {
        let now = now_ms();
        map.retain(|_, (m, _)| !m.is_expired(now));
    }
}

#[async_trait]
impl Storage for MemStorage {
    async fn put(&self, key: &[u8], value: Bytes, ttl: Option<Duration>) -> Result<(), StorageError> {
        let mut m = self.inner.write().await;
        m.insert(key.to_vec(), (Meta::new(ttl), value));
        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, StorageError> {
        let mut m = self.inner.write().await;
        Self::gc_expired(&mut m);
        Ok(m.get(key).map(|(_, v)| v.clone()))
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut m = self.inner.write().await;
        m.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        let mut m = self.inner.write().await;
        Self::gc_expired(&mut m);
        Ok(m.contains_key(key))
    }

    async fn list_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut m = self.inner.write().await;
        Self::gc_expired(&mut m);
        let mut out = Vec::new();
        for k in m.keys() {
            if k.starts_with(prefix) {
                out.push(k.clone());
            }
        }
        Ok(out)
    }

    async fn write_batch(&self, batch: Batch) -> Result<(), StorageError> {
        let mut m = self.inner.write().await;
        for item in batch.items {
            match item {
                BatchItem::Put { key, value, meta } => { m.insert(key, (meta, value)); }
                BatchItem::Delete { key } => { m.remove(&key); }
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

// ============================ Filesystem backend ==============================

#[derive(Clone)]
pub struct FsStorage {
    root: PathBuf,
    index: std::sync::Arc<RwLock<HashMap<Vec<u8>, Meta>>>,
}

impl Debug for FsStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsStorage")
            .field("root", &self.root)
            .finish()
    }
}

impl FsStorage {
    /// Create or open storage at `root`. Loads index if present.
    pub async fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&root).await?;
        let index_path = root.join(INDEX_FILE);
        let index = if tokio::fs::try_exists(&index_path).await? {
            let data = tokio::fs::read(&index_path).await?;
            bincode::deserialize::<HashMap<Vec<u8>, Meta>>(&data)?
        } else {
            HashMap::new()
        };
        Ok(Self { root, index: std::sync::Arc::new(RwLock::new(index)) })
    }

    /// Map binary key to sharded path by SHA-256: root/aa/bb/cc/....dat
    fn path_for(root: &Path, key: &[u8]) -> (PathBuf, String) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        let hex = hex::encode(hash);
        let (a, b, c) = (&hex[0..2], &hex[2..4], &hex[4..6]);
        let dir = root.join(a).join(b).join(c);
        let file = format!("{hex}.dat");
        (dir.join(&file), file)
    }

    async fn persist_index(&self) -> Result<(), StorageError> {
        let idx = self.index.read().await;
        let bytes = bincode::serialize(&*idx)?;
        let tmp = self.root.join(format!("{INDEX_FILE}.tmp"));
        tokio::fs::write(&tmp, &bytes).await?;
        // Atomic replace within same mount: rename temp -> index. :contentReference[oaicite:8]{index=8}
        tokio::fs::rename(&tmp, self.root.join(INDEX_FILE)).await?;
        Ok(())
    }

    async fn write_file_atomic(path: &Path, data: &[u8]) -> Result<(), StorageError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Use tempfile in same directory, then rename for atomic replace. :contentReference[oaicite:9]{index=9}
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        use std::io::Write;
        tmp.write_all(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tmp.flush().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        // Persist and rename
        let tmp_path = tmp.into_temp_path();
        tokio::fs::rename(&*tmp_path, path).await?;
        Ok(())
    }

    async fn read_file_if_fresh(
        &self,
        key: &[u8],
        meta: &Meta,
    ) -> Result<Option<Bytes>, StorageError> {
        let now = now_ms();
        if meta.is_expired(now) {
            // GC: delete on read
            let (path, _) = Self::path_for(&self.root, key);
            let _ = tokio::fs::remove_file(&path).await;
            {
                let mut idx = self.index.write().await;
                idx.remove(key);
            }
            let _ = self.persist_index().await;
            return Ok(None);
        }
        let (path, _) = Self::path_for(&self.root, key);
        match tokio::fs::read(path).await {
            Ok(bytes) => Ok(Some(Bytes::from(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl Storage for FsStorage {
    async fn put(&self, key: &[u8], value: Bytes, ttl: Option<Duration>) -> Result<(), StorageError> {
        let (path, _) = Self::path_for(&self.root, key);
        Self::write_file_atomic(&path, &value).await?;
        {
            let mut idx = self.index.write().await;
            idx.insert(key.to_vec(), Meta::new(ttl));
        }
        self.persist_index().await
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, StorageError> {
        let meta = {
            let idx = self.index.read().await;
            idx.get(key).cloned()
        };
        match meta {
            None => Ok(None),
            Some(m) => self.read_file_if_fresh(key, &m).await,
        }
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let (path, _) = Self::path_for(&self.root, key);
        let _ = tokio::fs::remove_file(path).await;
        {
            let mut idx = self.index.write().await;
            idx.remove(key);
        }
        self.persist_index().await
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        let meta = {
            let idx = self.index.read().await;
            idx.get(key).cloned()
        };
        match meta {
            None => Ok(false),
            Some(m) => Ok(!m.is_expired(now_ms())),
        }
    }

    async fn list_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, StorageError> {
        let now = now_ms();
        let mut idx = self.index.write().await;
        // GC expired and collect matching
        let mut out = Vec::new();
        idx.retain(|k, m| {
            let keep = !m.is_expired(now);
            if keep && k.starts_with(prefix) { out.push(k.clone()); }
            keep
        });
        drop(idx);
        self.persist_index().await?;
        Ok(out)
    }

    async fn write_batch(&self, batch: Batch) -> Result<(), StorageError> {
        // Take a single write lock around index; data files are written individually.
        let mut idx = self.index.write().await;
        for item in &batch.items {
            match item {
                BatchItem::Put { key, value, .. } => {
                    let (path, _) = Self::path_for(&self.root, key);
                    Self::write_file_atomic(&path, value).await?;
                }
                BatchItem::Delete { key } => {
                    let (path, _) = Self::path_for(&self.root, key);
                    let _ = tokio::fs::remove_file(path).await;
                }
            }
        }
        // Update index after data is persisted.
        for item in batch.items {
            match item {
                BatchItem::Put { key, meta, .. } => { idx.insert(key, meta); }
                BatchItem::Delete { key } => { idx.remove(&key); }
            }
        }
        drop(idx);
        self.persist_index().await
    }

    async fn flush(&self) -> Result<(), StorageError> {
        self.persist_index().await
    }
}

// ================================ Tests ======================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mem_storage_basic() {
        let s = MemStorage::new();
        let key = b"alpha";
        assert!(!s.exists(key).await.unwrap());
        s.put(key, Bytes::from_static(b"v1"), Some(Duration::from_millis(50))).await.unwrap();
        assert!(s.exists(key).await.unwrap());
        let v = s.get(key).await.unwrap().unwrap();
        assert_eq!(&*v, b"v1");
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!s.exists(key).await.unwrap(), "expired key should not exist");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fs_storage_basic() {
        let dir = TempDir::new().unwrap();
        let s = FsStorage::open(dir.path()).await.unwrap();
        let key = b"beta";
        s.put(key, Bytes::from_static(b"v2"), None).await.unwrap();
        assert!(s.exists(key).await.unwrap());
        let v = s.get(key).await.unwrap().unwrap();
        assert_eq!(&*v, b"v2");
        s.delete(key).await.unwrap();
        assert!(!s.exists(key).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn typed_storage_roundtrip() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Payload { a: u32, b: String }

        let s = TypedStorage::new(MemStorage::new());
        let key = b"k1";
        s.put(key, &Payload { a: 7, b: "x".into() }, None).await.unwrap();
        let got: Option<Payload> = s.get(key).await.unwrap();
        assert_eq!(got.unwrap(), Payload { a: 7, b: "x".into() });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fs_storage_batch() {
        let dir = TempDir::new().unwrap();
        let s = FsStorage::open(dir.path()).await.unwrap();

        let batch = Batch::default()
            .put(b"k1", Bytes::from_static(b"v1"), None)
            .put(b"k2", Bytes::from_static(b"v2"), None)
            .delete(b"nope");

        s.write_batch(batch).await.unwrap();

        assert!(s.exists(b"k1").await.unwrap());
        assert!(s.exists(b"k2").await.unwrap());
        assert!(!s.exists(b"nope").await.unwrap());
    }
}

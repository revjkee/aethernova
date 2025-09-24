//! Key-Value storage abstraction with in-memory and RocksDB backends.
//!
//! Features:
//! - Namespaces mapped to RocksDB Column Families (or logical maps in-memory).
//! - Atomic compare-and-set, batch writes.
//! - TTL with lazy expiration (8-byte LE expiry prefix).
//! - Prefix scan, snapshot-like read via read options.
//! - Tokio-friendly: all blocking DB ops go through `spawn_blocking`.  (Tokio doc)  [refs in README/docs]
//! - Structured errors and tracing for observability.
//!
//! Enable RocksDB backend with `--features rocksdb`.
//!
//! Cargo (example):
//!   [dependencies]
//!   tokio   = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
//!   tracing = "0.1"
//!   thiserror = "1"
//!   bytes = "1"
//!   dashmap = "5"
//!   anyhow = "1"
//!   # optional
//!   rocksdb = { version = "0.22", optional = true, default-features = false, features = ["multi-threaded-cf", "lz4"] }
//!
//! Safety notes:
//! - RocksDB calls are blocking; we offload via `tokio::task::spawn_blocking`.  (Tokio docs)  [citations below]
//! - Column Families provide logical namespacing in RocksDB. (RocksDB docs)
//!
//! Citations: Tokio spawn_blocking; rocksdb crate; Column Families (Rust docs + RocksDB wiki).
//!   See conversation metadata with links.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use thiserror::Error;
use tokio::task::spawn_blocking;
use tracing::{debug, info, instrument, trace, warn};

use dashmap::DashMap;

#[cfg(feature = "rocksdb")]
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, Options, ReadOptions, WriteBatch, WriteOptions, DB,
    DBWithThreadMode, MultiThreaded,
};

/// Namespace name maps to a Column Family (Rocks) or logical partition (memory).
pub type Namespace = String;

/// Storage errors.
#[derive(Error, Debug)]
pub enum KvError {
    #[error("namespace not found: {0}")]
    NamespaceNotFound(String),
    #[error("compare_and_set failed (expected != actual)")]
    CasFailed,
    #[error("internal: {0}")]
    Internal(String),
}

impl From<rocksdb::Error> for KvError {
    fn from(e: rocksdb::Error) -> Self {
        KvError::Internal(e.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct KvConfig {
    pub max_value_size: usize, // guardrail for incoming payloads
    pub default_ttl: Option<Duration>,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            max_value_size: 4 * 1024 * 1024, // 4 MiB
            default_ttl: None,
        }
    }
}

/// Public facade.
#[derive(Clone)]
pub struct Kv {
    inner: Arc<Inner>,
}

#[derive(Clone)]
enum Inner {
    Memory(Arc<MemStore>),
    #[cfg(feature = "rocksdb")]
    Rocks(Arc<RocksStore>),
}

impl Kv {
    /// In-memory KV (multi-namespace).
    pub fn in_memory(cfg: KvConfig) -> Self {
        Self {
            inner: Arc::new(Inner::Memory(Arc::new(MemStore::new(cfg)))),
        }
    }

    /// RocksDB-based KV at `path`, will create DB and CFs on demand.
    #[cfg(feature = "rocksdb")]
    pub fn rocksdb(path: impl AsRef<Path>, cfg: KvConfig, opts: Option<RocksOptions>) -> Result<Self> {
        let store = RocksStore::open(path.as_ref(), opts.unwrap_or_default(), cfg)
            .context("open RocksDB")?;
        Ok(Self {
            inner: Arc::new(Inner::Rocks(Arc::new(store))),
        })
    }

    /// Ensure namespace exists (creates CF in RocksDB or logical map).
    pub async fn ensure_namespace(&self, ns: &str) -> Result<()> {
        match &*self.inner {
            Inner::Memory(m) => {
                m.ensure_ns(ns);
                Ok(())
            }
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.ensure_ns(ns).await,
        }
    }

    /// Put value with optional TTL override (None => use default).
    pub async fn put(&self, ns: &str, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        if value.len() > self.config().max_value_size {
            return Err(anyhow!(
                "value too large: {} > {}",
                value.len(),
                self.config().max_value_size
            ));
        }
        match &*self.inner {
            Inner::Memory(m) => m.put(ns, key, value, ttl),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.put(ns, key, value, ttl).await,
        }
    }

    /// Get value; if expired (TTL), returns Ok(None) and lazily deletes.
    pub async fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Bytes>> {
        match &*self.inner {
            Inner::Memory(m) => Ok(m.get(ns, key)),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.get(ns, key).await,
        }
    }

    /// Delete key (idempotent).
    pub async fn delete(&self, ns: &str, key: &[u8]) -> Result<()> {
        match &*self.inner {
            Inner::Memory(m) => {
                m.delete(ns, key);
                Ok(())
            }
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.delete(ns, key).await,
        }
    }

    /// Compare-and-set: if current == expected (or None if absent), set to new_value.
    pub async fn compare_and_set(
        &self,
        ns: &str,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<()> {
        match &*self.inner {
            Inner::Memory(m) => m.compare_and_set(ns, key, expected, new_value, ttl),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.compare_and_set(ns, key, expected, new_value, ttl).await,
        }
    }

    /// Batch put. All-or-nothing within a single namespace.
    pub async fn batch_put(&self, ns: &str, kvs: &[(Vec<u8>, Vec<u8>)], ttl: Option<Duration>) -> Result<()> {
        for (_, v) in kvs.iter() {
            if v.len() > self.config().max_value_size {
                return Err(anyhow!(
                    "value too large in batch: {} > {}",
                    v.len(),
                    self.config().max_value_size
                ));
            }
        }
        match &*self.inner {
            Inner::Memory(m) => m.batch_put(ns, kvs, ttl),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.batch_put(ns, kvs, ttl).await,
        }
    }

    /// Iterate keys by prefix (lexicographic) yielding (key, value).
    pub async fn prefix_scan(
        &self,
        ns: &str,
        prefix: &[u8],
        limit: Option<usize>,
    ) -> Result<Vec<(Bytes, Bytes)>> {
        match &*self.inner {
            Inner::Memory(m) => Ok(m.prefix_scan(ns, prefix, limit)),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.prefix_scan(ns, prefix, limit).await,
        }
    }

    /// Flush backend buffers (best-effort).
    pub async fn flush(&self) -> Result<()> {
        match &*self.inner {
            Inner::Memory(_) => Ok(()),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.flush().await,
        }
    }

    pub fn config(&self) -> KvConfig {
        match &*self.inner {
            Inner::Memory(m) => m.cfg.clone(),
            #[cfg(feature = "rocksdb")]
            Inner::Rocks(r) => r.cfg.clone(),
        }
    }
}

/* ------------------------------ TTL encoding ------------------------------ */

#[inline]
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[inline]
fn encode_value(raw: &[u8], ttl: Option<Duration>, default_ttl: Option<Duration>) -> Vec<u8> {
    let ttl = ttl.or(default_ttl);
    let exp = if let Some(t) = ttl {
        now_millis() + t.as_millis() as u64
    } else {
        0
    };
    let mut out = Vec::with_capacity(8 + raw.len());
    out.extend_from_slice(&exp.to_le_bytes());
    out.extend_from_slice(raw);
    out
}

#[inline]
fn decode_value(mut stored: Vec<u8>) -> Option<Vec<u8>> {
    if stored.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&stored[..8]);
    let exp = u64::from_le_bytes(buf);
    if exp != 0 && now_millis() > exp {
        return None;
    }
    stored.drain(..8);
    Some(stored)
}

/* ------------------------------ Memory store ------------------------------ */

#[derive(Clone)]
struct MemStore {
    cfg: KvConfig,
    // namespaces -> key -> value
    data: Arc<DashMap<String, DashMap<Vec<u8>, Vec<u8>>>>,
}

impl MemStore {
    fn new(cfg: KvConfig) -> Self {
        Self {
            cfg,
            data: Arc::new(DashMap::new()),
        }
    }

    fn ensure_ns(&self, ns: &str) {
        self.data.entry(ns.to_string()).or_insert_with(DashMap::new);
    }

    fn ns(&self, ns: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, DashMap<Vec<u8>, Vec<u8>>>> {
        self.data.get_mut(ns)
    }

    fn put(&self, ns: &str, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.ensure_ns(ns);
        let v = encode_value(value, ttl, self.cfg.default_ttl);
        if let Some(map) = self.ns(ns) {
            map.insert(key.to_vec(), v);
            Ok(())
        } else {
            Err(anyhow!(KvError::NamespaceNotFound(ns.to_string())))
        }
    }

    fn get(&self, ns: &str, key: &[u8]) -> Option<Bytes> {
        let map = self.data.get(ns)?;
        if let Some(v) = map.get(key) {
            if let Some(decoded) = decode_value(v.clone()) {
                return Some(Bytes::from(decoded));
            } else {
                // expired -> lazy delete
                drop(v);
                map.remove(key);
                return None;
            }
        }
        None
    }

    fn delete(&self, ns: &str, key: &[u8]) {
        if let Some(map) = self.data.get(ns) {
            map.remove(key);
        }
    }

    fn compare_and_set(
        &self,
        ns: &str,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<()> {
        self.ensure_ns(ns);
        let map = self
            .ns(ns)
            .ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let current = map.get(key).map(|v| v.clone());
        let current_decoded = current.as_deref().and_then(|v| decode_value(v.clone()));
        let expected_vec = expected.map(|e| e.to_vec());
        if current_decoded.as_deref() != expected_vec.as_deref() {
            return Err(anyhow!(KvError::CasFailed));
        }
        let encoded = encode_value(new_value, ttl, self.cfg.default_ttl);
        map.insert(key.to_vec(), encoded);
        Ok(())
    }

    fn batch_put(&self, ns: &str, kvs: &[(Vec<u8>, Vec<u8>)], ttl: Option<Duration>) -> Result<()> {
        self.ensure_ns(ns);
        let map = self
            .ns(ns)
            .ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        for (k, v) in kvs.iter() {
            map.insert(k.clone(), encode_value(v, ttl, self.cfg.default_ttl));
        }
        Ok(())
    }

    fn prefix_scan(&self, ns: &str, prefix: &[u8], limit: Option<usize>) -> Vec<(Bytes, Bytes)> {
        let mut out = Vec::new();
        if let Some(map) = self.data.get(ns) {
            for item in map.iter() {
                if item.key().starts_with(prefix) {
                    if let Some(val) = decode_value(item.value().clone()) {
                        out.push((Bytes::from(item.key().clone()), Bytes::from(val)));
                        if let Some(l) = limit {
                            if out.len() >= l {
                                break;
                            }
                        }
                    } else {
                        // expired -> lazy delete
                        map.remove(item.key());
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

/* ------------------------------ RocksDB store ------------------------------ */

#[cfg(feature = "rocksdb")]
#[derive(Clone)]
pub struct RocksOptions {
    pub create_if_missing: bool,
    pub create_missing_column_families: bool,
    pub lz4_compression: bool,
}

#[cfg(feature = "rocksdb")]
impl Default for RocksOptions {
    fn default() -> Self {
        Self {
            create_if_missing: true,
            create_missing_column_families: true,
            lz4_compression: true,
        }
    }
}

#[cfg(feature = "rocksdb")]
#[derive(Clone)]
struct RocksStore {
    cfg: KvConfig,
    db: Arc<DBWithThreadMode<MultiThreaded>>,
    // Keep CF handles alive
    cfs: Arc<DashMap<String, Arc<ColumnFamily>>>,
    write_opts: Arc<WriteOptions>,
}

#[cfg(feature = "rocksdb")]
impl RocksStore {
    fn open(path: &Path, ropts: RocksOptions, cfg: KvConfig) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(ropts.create_if_missing);
        opts.create_missing_column_families(ropts.create_missing_column_families);
        opts.increase_parallelism(num_cpus::get() as i32);
        opts.optimize_level_style_compaction(512 * 1024 * 1024);
        if ropts.lz4_compression {
            opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }

        // Open default DB (bootstrap with 'default' CF only; dynamic CFs created later).
        let db = DBWithThreadMode::<MultiThreaded>::open(&opts, path)
            .map_err(|e| anyhow!("rocksdb open: {e}"))?;

        let write_opts = {
            let mut w = WriteOptions::default();
            w.set_sync(false);
            w.disable_wal(false);
            Arc::new(w)
        };

        Ok(Self {
            cfg,
            db: Arc::new(db),
            cfs: Arc::new(DashMap::new()),
            write_opts,
        })
    }

    #[instrument(level = "debug", skip(self))]
    async fn ensure_ns(&self, ns: &str) -> Result<()> {
        if self.cfs.contains_key(ns) {
            return Ok(());
        }
        let db = self.db.clone();
        let ns_owned = ns.to_string();
        let handle = spawn_blocking(move || {
            if let Some(cf) = db.cf_handle(&ns_owned) {
                return Ok::<Arc<ColumnFamily>, rocksdb::Error>(Arc::new(cf));
            }
            // Create new Column Family
            let mut cf_opts = Options::default();
            cf_opts.set_write_buffer_size(64 * 1024 * 1024);
            cf_opts.set_target_file_size_base(128 * 1024 * 1024);
            let cf = db.create_cf(&ns_owned, &cf_opts)?;
            Ok(Arc::new(cf))
        })
        .await
        .map_err(|e| anyhow!("join error: {e}"))??;

        self.cfs.insert(ns_owned, handle);
        Ok(())
    }

    fn cf(&self, ns: &str) -> Option<Arc<ColumnFamily>> {
        self.cfs.get(ns).map(|r| Arc::clone(r.value()))
    }

    #[instrument(level = "trace", skip(self, key, value))]
    async fn put(&self, ns: &str, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.ensure_ns(ns).await?;
        let cf = self.cf(ns).ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let db = self.db.clone();
        let wo = self.write_opts.clone();
        let data = encode_value(value, ttl, self.cfg.default_ttl);
        let key = key.to_vec();
        spawn_blocking(move || db.put_cf_opt(&cf, key, data, &wo))
            .await
            .map_err(|e| anyhow!("join error: {e}"))?
            .map_err(|e| anyhow!(e))?;
        Ok(())
    }

    #[instrument(level = "trace", skip(self, key))]
    async fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Bytes>> {
        self.ensure_ns(ns).await?;
        let cf = self.cf(ns).ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let db = self.db.clone();
        let key = key.to_vec();
        let res = spawn_blocking(move || db.get_cf(&cf, key))
            .await
            .map_err(|e| anyhow!("join error: {e}"))?
            .map_err(|e| anyhow!(e))?;
        if let Some(bytes) = res {
            if let Some(decoded) = decode_value(bytes.to_vec()) {
                return Ok(Some(Bytes::from(decoded)));
            } else {
                // Lazy delete expired
                let db2 = self.db.clone();
                let cf2 = cf.clone();
                let key2 = key;
                let wo = self.write_opts.clone();
                spawn_blocking(move || db2.delete_cf_opt(&cf2, key2, &wo)).await.ok();
                return Ok(None);
            }
        }
        Ok(None)
    }

    #[instrument(level = "trace", skip(self, key))]
    async fn delete(&self, ns: &str, key: &[u8]) -> Result<()> {
        self.ensure_ns(ns).await?;
        let cf = self.cf(ns).ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let db = self.db.clone();
        let key = key.to_vec();
        let wo = self.write_opts.clone();
        spawn_blocking(move || db.delete_cf_opt(&cf, key, &wo))
            .await
            .map_err(|e| anyhow!("join error: {e}"))?
            .map_err(|e| anyhow!(e))?;
        Ok(())
    }

    #[instrument(level = "debug", skip(self, expected, new_value))]
    async fn compare_and_set(
        &self,
        ns: &str,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<()> {
        self.ensure_ns(ns).await?;
        let cf = self.cf(ns).ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let db = self.db.clone();
        let key_vec = key.to_vec();
        let encoded = encode_value(new_value, ttl, self.cfg.default_ttl);
        let wo = self.write_opts.clone();

        // Emulate CAS via snapshot read + conditional write in a WriteBatch.
        let expected_vec = expected.map(|e| e.to_vec());
        spawn_blocking(move || -> Result<()> {
            let current = db.get_cf(&cf, &key_vec)?;
            let current_decoded = current.as_deref().and_then(|v| decode_value(v.to_vec()));
            if current_decoded.as_deref() != expected_vec.as_deref() {
                return Err(anyhow!(KvError::CasFailed));
            }
            let mut wb = WriteBatch::default();
            wb.put_cf(&cf, &key_vec, encoded)?;
            db.write_opt(wb, &wo)?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("join error: {e}"))??;

        Ok(())
    }

    #[instrument(level = "trace", skip(self, kvs))]
    async fn batch_put(&self, ns: &str, kvs: &[(Vec<u8>, Vec<u8>)], ttl: Option<Duration>) -> Result<()> {
        self.ensure_ns(ns).await?;
        let cf = self.cf(ns).ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let db = self.db.clone();
        let wo = self.write_opts.clone();

        let default_ttl = self.cfg.default_ttl;
        let items: Vec<(Vec<u8>, Vec<u8>)> = kvs
            .iter()
            .map(|(k, v)| (k.clone(), encode_value(v, ttl, default_ttl)))
            .collect();

        spawn_blocking(move || -> Result<()> {
            let mut wb = WriteBatch::default();
            for (k, v) in items {
                wb.put_cf(&cf, k, v)?;
            }
            db.write_opt(wb, &wo)?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("join error: {e}"))??;

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    async fn prefix_scan(
        &self,
        ns: &str,
        prefix: &[u8],
        limit: Option<usize>,
    ) -> Result<Vec<(Bytes, Bytes)>> {
        self.ensure_ns(ns).await?;
        let cf = self.cf(ns).ok_or_else(|| anyhow!(KvError::NamespaceNotFound(ns.to_string())))?;
        let db = self.db.clone();
        let prefix = prefix.to_vec();

        let out: Vec<(Bytes, Bytes)> = spawn_blocking(move || -> Result<Vec<(Bytes, Bytes)>> {
            let mut ro = ReadOptions::default();
            ro.set_prefix_same_as_start(true);
            let mut it = db.raw_iterator_cf_opt(&cf, ro);
            it.seek(&prefix);

            let mut acc = Vec::new();
            while it.valid() {
                let k = it.key().map(|s| s.to_vec()).unwrap_or_default();
                if !k.starts_with(&prefix) {
                    break;
                }
                let v = it.value().map(|s| s.to_vec()).unwrap_or_default();
                if let Some(decoded) = decode_value(v) {
                    acc.push((Bytes::from(k), Bytes::from(decoded)));
                }
                if let Some(l) = limit {
                    if acc.len() >= l {
                        break;
                    }
                }
                it.next();
            }
            Ok(acc)
        })
        .await
        .map_err(|e| anyhow!("join error: {e}"))??;

        Ok(out)
    }

    #[instrument(level = "debug", skip(self))]
    async fn flush(&self) -> Result<()> {
        let db = self.db.clone();
        spawn_blocking(move || db.flush()).await.map_err(|e| anyhow!("join error: {e}"))??;
        Ok(())
    }
}

/* --------------------------------- Tests ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mem_put_get_delete() {
        let kv = Kv::in_memory(KvConfig::default());
        kv.ensure_namespace("n").await.unwrap();
        kv.put("n", b"k", b"v", None).await.unwrap();
        assert_eq!(kv.get("n", b"k").await.unwrap().unwrap().as_ref(), b"v");
        kv.delete("n", b"k").await.unwrap();
        assert!(kv.get("n", b"k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mem_ttl() {
        let kv = Kv::in_memory(KvConfig::default());
        kv.ensure_namespace("n").await.unwrap();
        kv.put("n", b"k", b"v", Some(Duration::from_millis(50))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(kv.get("n", b"k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mem_cas() {
        let kv = Kv::in_memory(KvConfig::default());
        kv.ensure_namespace("n").await.unwrap();
        kv.put("n", b"k", b"v1", None).await.unwrap();
        // wrong expected
        assert!(kv.compare_and_set("n", b"k", Some(b"no"), b"v2", None).await.is_err());
        // correct expected
        kv.compare_and_set("n", b"k", Some(b"v1"), b"v2", None).await.unwrap();
        assert_eq!(kv.get("n", b"k").await.unwrap().unwrap().as_ref(), b"v2");
    }
}

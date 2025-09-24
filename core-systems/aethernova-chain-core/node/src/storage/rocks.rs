// node/src/storage/rocks.rs
//
// Industrial-grade RocksDB wrapper for Aethernova Node.
//
// Requires crate `rocksdb` >= 0.24.*
// Suggested features (optional): zstd,lz4,snappy,multi-threaded-cf
//
// This module provides:
// - Multi-threaded DB instance with Column Families (CF)
// - Block-based table with LRU block cache, Bloom filters, partitioned filters
// - Optional fixed-prefix extractor for efficient prefix scans
// - Atomic WriteBatch across CFs
// - Snapshots for consistent reads
// - Range scan / prefix scan helpers
// - Compact/Flush controls
// - Properties & stats access (`rocksdb.*`)
// - Backup/Restore helpers
//
// All APIs used below exist in `rust-rocksdb` crate and RocksDB:
//   - Options::{create_if_missing,create_missing_column_families,increase_parallelism,...}
//   - BlockBasedOptions, Cache, DBCompressionType
//   - ColumnFamilyDescriptor, BoundColumnFamily, DBWithThreadMode<MultiThreaded>
//   - WriteBatch, ReadOptions (iterate range, prefix_same_as_start)
//   - SnapshotWithThreadMode
//   - backup::{BackupEngine, BackupEngineOptions, RestoreOptions}
//
// See citations in the answer body.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rocksdb::{
    backup::{BackupEngine, BackupEngineOptions, RestoreOptions},
    properties, BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompressionType,
    DBWithThreadMode, Error as RocksError, MultiThreaded, Options, ReadOptions, SnapshotWithThreadMode,
    WriteBatch, WriteOptions, DBCommon,
};

/// Public error alias to avoid leaking crate types elsewhere if desired.
pub type Error = RocksError;
pub type Result<T> = std::result::Result<T, Error>;

/// Column family configuration.
#[derive(Clone, Debug)]
pub struct CfConfig {
    pub name: String,
    /// If set, configure a fixed-prefix extractor of this length for this CF.
    pub fixed_prefix_len: Option<usize>,
}

/// Database configuration.
#[derive(Clone, Debug)]
pub struct RocksConfig {
    pub path: PathBuf,
    /// List of CFs to ensure exist (the "default" CF is always present).
    pub cfs: Vec<CfConfig>,

    /// Create DB if missing.
    pub create_if_missing: bool,
    /// Create any CFs that are missing.
    pub create_missing_cfs: bool,

    /// Block cache size (bytes) for block-based table (shared by CFs).
    pub block_cache_bytes: usize,
    /// Bloom filter bits per key for SST indexes.
    pub bloom_bits_per_key: i32,
    /// Whether to use partitioned filters (recommended for large tables).
    pub use_partitioned_filters: bool,

    /// Compression for SST files (e.g., Zstd).
    pub compression: Option<DBCompressionType>,

    /// Parallelism for background flush/compaction (0 = use num_cpus).
    pub parallelism: i32,

    /// Dump RocksDB stats periodically (seconds). 0 disables.
    pub stats_dump_period_sec: u32,
}

/// Atomic batch operation descriptor.
pub enum BatchOp<'a> {
    Put { cf: &'a str, key: &'a [u8], value: &'a [u8] },
    Delete { cf: &'a str, key: &'a [u8] },
    DeleteRange { cf: &'a str, from: &'a [u8], to: &'a [u8] }, // ["from", "to")
}

/// Main storage handle.
pub struct Rocks {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
    /// Bound CF handles by name.
    cfs: HashMap<String, BoundColumnFamily<'static>>,
    /// Shared block cache to introspect usage via properties.
    _cache: Cache,
}

impl Rocks {
    /// Open or create RocksDB with CFs and options; auto-discovers existing CFs and merges with desired set.
    pub fn open(cfg: &RocksConfig) -> Result<Self> {
        // Base DB options
        let mut db_opts = Options::default();
        db_opts.create_if_missing(cfg.create_if_missing);
        db_opts.create_missing_column_families(cfg.create_missing_cfs);

        // Increase background parallelism for flush/compaction.
        let threads = if cfg.parallelism <= 0 {
            std::thread::available_parallelism().map(|n| n.get() as i32).unwrap_or(4)
        } else {
            cfg.parallelism
        };
        db_opts.increase_parallelism(threads);

        if cfg.stats_dump_period_sec > 0 {
            db_opts.enable_statistics();
            db_opts.set_stats_dump_period_sec(cfg.stats_dump_period_sec);
        }

        // Shared block cache for all CFs
        let cache = Cache::new_lru(cfg.block_cache_bytes);

        // Build CF descriptors: merge existing CFs with requested CFs.
        let existing = DBWithThreadMode::<MultiThreaded>::list_cf(&db_opts, &cfg.path)
            .unwrap_or_else(|_| vec!["default".to_string()]);
        let mut want: HashMap<String, CfConfig> = HashMap::new();
        for cf in &cfg.cfs {
            want.insert(cf.name.clone(), cf.clone());
        }
        // Ensure "default" always present
        want.entry("default".into())
            .or_insert(CfConfig { name: "default".into(), fixed_prefix_len: None });
        // Also include any pre-existing CFs not explicitly configured
        for name in existing {
            want.entry(name.clone())
                .or_insert(CfConfig { name, fixed_prefix_len: None });
        }

        let mut cf_descriptors = Vec::with_capacity(want.len());
        for cf in want.values() {
            let mut opts = Options::default();
            // Attach block-based table + bloom + cache
            let mut table = BlockBasedOptions::default();
            // Bloom filter on filter index
            table.set_bloom_filter(cfg.bloom_bits_per_key, false);
            table.set_cache_index_and_filter_blocks(true);
            table.set_pin_l0_filter_and_index_blocks_in_cache(true);
            table.set_block_cache(&cache);

            if cfg.use_partitioned_filters {
                table.set_partition_filters(true);
                // pinning tier available in recent versions; safe to omit if not compiled
                // table.set_pin_top_level_index_and_filter(true);
            }
            opts.set_block_based_table_factory(&table);

            if let Some(comp) = cfg.compression {
                opts.set_compression_type(comp);
            }

            // CF-scoped prefix extractor (optional)
            if let Some(len) = cf.fixed_prefix_len {
                // Fixed prefix extractor enables efficient prefix bloom and seeks.
                let transform = rocksdb::SliceTransform::create_fixed_prefix(len);
                opts.set_prefix_extractor(transform);
                // Also create memtable prefix bloom (0.05..0.25 typical)
                opts.set_memtable_prefix_bloom_ratio(0.20);
            }

            // Reasonable defaults; callers should still benchmark/tune.
            // Larger base L1 file size & write buffers can be set here if needed.

            cf_descriptors.push(ColumnFamilyDescriptor::new(cf.name.clone(), opts));
        }

        // Open DB with descriptors (must include all CFs).
        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&db_opts, &cfg.path, cf_descriptors)?;
        let db = Arc::new(db);

        // Bind CF handles into a static map for fast lookup.
        let mut map: HashMap<String, BoundColumnFamily<'static>> = HashMap::new();
        for name in want.keys() {
            // SAFETY: BoundColumnFamily lifetime is tied to DB; we extend via transmute
            // because we hold Arc<DB> for the life of self.
            if let Some(handle) = db.cf_handle(name) {
                let handle: BoundColumnFamily<'_> = handle;
                let static_handle: BoundColumnFamily<'static> = unsafe { std::mem::transmute(handle) };
                map.insert(name.clone(), static_handle);
            }
        }

        Ok(Self { db, cfs: map, _cache: cache })
    }

    #[inline]
    fn cf(&self, name: &str) -> &BoundColumnFamily<'_> {
        self.cfs.get(name).expect("unknown CF")
    }

    /// Put key/value into CF with durable write options selectable.
    pub fn put_cf(&self, cf: &str, key: &[u8], value: &[u8], sync: bool) -> Result<()> {
        let mut wopts = WriteOptions::default();
        wopts.set_sync(sync);
        self.db.put_cf_opt(self.cf(cf), key, value, &wopts)
    }

    /// Get value by key from CF.
    pub fn get_cf(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get_cf(self.cf(cf), key)
    }

    /// Delete key from CF.
    pub fn delete_cf(&self, cf: &str, key: &[u8], sync: bool) -> Result<()> {
        let mut wopts = WriteOptions::default();
        wopts.set_sync(sync);
        self.db.delete_cf_opt(self.cf(cf), key, &wopts)
    }

    /// Atomic batch across CFs.
    pub fn write_batch(&self, ops: &[BatchOp<'_>], disable_wal: bool, sync: bool) -> Result<()> {
        let mut wb = WriteBatch::default();
        for op in ops {
            match *op {
                BatchOp::Put { cf, key, value } => wb.put_cf(self.cf(cf), key, value)?,
                BatchOp::Delete { cf, key } => wb.delete_cf(self.cf(cf), key)?,
                BatchOp::DeleteRange { cf, from, to } => {
                    // ["from", "to")
                    wb.delete_range_cf(self.cf(cf), from, to)?
                }
            }
        }
        let mut wopts = WriteOptions::default();
        wopts.disable_wal(disable_wal);
        wopts.set_sync(sync);
        self.db.write_opt(wb, &wopts)
    }

    /// Inclusive prefix scan: collects all (key,value) where key starts with `prefix`.
    /// Uses iterate upper bound to terminate efficiently; compatible with or without prefix extractor.
    pub fn scan_prefix(&self, cf: &str, prefix: &[u8], limit: Option<usize>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let upper = upper_bound_prefix(prefix);
        let mut ro = ReadOptions::default();
        // If you configured a prefix extractor on this CF, this narrows iteration within a prefix.
        ro.set_prefix_same_as_start(true);
        if let Some(ub) = &upper {
            ro.set_iterate_range(prefix..ub.as_slice());
        } else {
            // No upper bound possible (prefix = all 0xFF); fall back to start-bound only.
            ro.set_iterate_lower_bound(prefix.to_vec());
        }

        let mut it = self.db.iterator_cf_opt(self.cf(cf), ro, rocksdb::IteratorMode::From(prefix, rocksdb::Direction::Forward));
        let mut out = Vec::new();
        while let Some(item) = it.next() {
            let (k, v) = item?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
            if let Some(n) = limit {
                if out.len() >= n {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Range scan: half-open ["from", "to") using RocksDB's iterate_range.
    pub fn scan_range(&self, cf: &str, from: &[u8], to: &[u8], limit: Option<usize>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut ro = ReadOptions::default();
        ro.set_iterate_range(from..to);
        let mut it = self.db.iterator_cf_opt(self.cf(cf), ro, rocksdb::IteratorMode::From(from, rocksdb::Direction::Forward));
        let mut out = Vec::new();
        while let Some(item) = it.next() {
            let (k, v) = item?;
            if k.as_ref() >= to {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
            if let Some(n) = limit {
                if out.len() >= n {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Create a consistent snapshot view.
    pub fn snapshot(&self) -> SnapshotWithThreadMode<'_, DBWithThreadMode<MultiThreaded>> {
        self.db.snapshot()
    }

    /// Flush memtables to SST; if `sync_wal` is true, also fsync WAL.
    pub fn flush(&self, sync_wal: bool) -> Result<()> {
        if sync_wal {
            self.db.flush_wal(true)?;
        }
        self.db.flush()
    }

    /// Compact a range within CF. Pass None to compact whole keyspace.
    pub fn compact_cf_range(&self, cf: &str, from: Option<&[u8]>, to: Option<&[u8]>) {
        self.db.compact_range_cf(self.cf(cf), from, to);
    }

    /// Query RocksDB properties (db-wide or CF).
    pub fn db_property(&self, name: &str) -> Option<String> {
        self.db.property_value(name).ok().flatten()
    }
    pub fn cf_property(&self, cf: &str, name: &str) -> Option<String> {
        self.db.property_value_cf(self.cf(cf), name).ok().flatten()
    }

    /// Create a backup into `backup_dir`. If `flush_before_backup` is true, unflushed memtables are persisted.
    pub fn backup_create(&self, backup_dir: impl AsRef<Path>, flush_before_backup: bool) -> Result<()> {
        let mut be = BackupEngine::open(&BackupEngineOptions::default(), backup_dir)?;
        be.create_new_backup_flush(&*self.db, flush_before_backup)
    }

    /// Restore the latest backup into `db_dir` and WAL into `wal_dir`.
    pub fn backup_restore_latest(db_dir: impl AsRef<Path>, wal_dir: impl AsRef<Path>, backup_dir: impl AsRef<Path>) -> Result<()> {
        let mut be = BackupEngine::open(&BackupEngineOptions::default(), backup_dir)?;
        let mut ropts = RestoreOptions::default();
        ropts.set_keep_log_files(true);
        be.restore_from_latest_backup(db_dir, wal_dir, &ropts)
    }
}

/// Compute the minimal exclusive upper bound for a byte prefix (lexicographic).
/// Returns None if no upper bound exists (all bytes are 0xFF).
fn upper_bound_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    if prefix.is_empty() { return None; }
    let mut ub = prefix.to_vec();
    for i in (0..ub.len()).rev() {
        if ub[i] != 0xFF {
            ub[i] += 1;
            ub.truncate(i + 1);
            return Some(ub);
        }
    }
    None
}

/// Minimal smoke tests (enable with `cargo test --features test` if you split crates).
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prefix_scan_basic() {
        let dir = TempDir::new().unwrap();
        let cfg = RocksConfig {
            path: dir.path().to_path_buf(),
            cfs: vec![
                CfConfig { name: "default".into(), fixed_prefix_len: None },
                CfConfig { name: "state".into(), fixed_prefix_len: Some(4) },
            ],
            create_if_missing: true,
            create_missing_cfs: true,
            block_cache_bytes: 64 * 1024 * 1024,
            bloom_bits_per_key: 10,
            use_partitioned_filters: true,
            compression: Some(DBCompressionType::Zstd),
            parallelism: 0,
            stats_dump_period_sec: 0,
        };
        let db = Rocks::open(&cfg).unwrap();

        // Keys with 4-byte prefix: b"acct"....
        db.put_cf("state", b"acct:0001", b"A", true).unwrap();
        db.put_cf("state", b"acct:0002", b"B", true).unwrap();
        db.put_cf("state", b"user:0001", b"C", true).unwrap();

        let rows = db.scan_prefix("state", b"acct:", None).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|(k, _)| k.starts_with(b"acct:")));
    }
}

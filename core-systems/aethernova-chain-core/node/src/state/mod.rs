//! State layer (versioned KV with snapshots and deterministic state root).
//!
//! Design goals:
//! - Deterministic, versioned, thread-safe key–value state for a blockchain node.
//! - Transactions with copy-on-write and journal of write ops.
//! - Snapshots with retention window (keep_last).
//! - Deterministic state root computed over a sorted map.
//!
//! Concurrency primitives:
//!   - Arc: thread-safe shared ownership. See Rust std docs. 
//!   - RwLock: reader-writer lock for concurrent reads and exclusive writes.
//! Sources: https://doc.rust-lang.org/std/sync/struct.Arc.html ; https://doc.rust-lang.org/std/sync/struct.RwLock.html
//!
//! Deterministic ordering: std::collections::BTreeMap is an ordered map (sorted by key).
//! Sources: https://doc.rust-lang.org/std/collections/struct.BTreeMap.html
//!
//! State root concept: deterministic root over key–value state. For production-grade cryptographic
//! roots use Merkle(-Patricia) tries (e.g., Ethereum Yellow Paper, TRIE(LS(σ))).
//! Sources: https://ethereum.github.io/yellowpaper/paper.pdf ; https://en.wikipedia.org/wiki/Merkle_tree

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};

/// Opaque key/value types.
/// Keys are arbitrary byte sequences; values are arbitrary bytes.
pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

/// Monotonic state version (height).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u64);

/// 32-byte root hash (not cryptographically secure in this module).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Root32(pub [u8; 32]);

/// Configuration of the state manager.
#[derive(Clone, Debug)]
pub struct StateConfig {
    /// How many recent snapshots to retain in memory (including latest).
    pub keep_last: usize,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self { keep_last: 16 }
    }
}

/// Write operation (journal entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOp {
    Put(Key, Value),
    Delete(Key),
}

/// Receipt returned after a successful commit.
#[derive(Clone, Debug)]
pub struct CommitReceipt {
    pub new_version: Version,
    pub new_root: Root32,
    pub writes: usize,
}

/// Immutable snapshot of the state at a version.
#[derive(Clone)]
pub struct Snapshot {
    version: Version,
    root: Root32,
    // Ordered map ensures deterministic iteration.
    map: Arc<BTreeMap<Key, Value>>,
}

impl Snapshot {
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn root(&self) -> Root32 {
        self.root
    }
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.map.get(key).map(|v| v.as_slice())
    }
    pub fn contains(&self, key: &[u8]) -> bool {
        self.map.contains_key(key)
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.map.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))
    }
}

/// Internal mutable state.
struct Inner {
    current: Snapshot,
    history: VecDeque<Snapshot>, // oldest .. newest (including current)
    next_version: Version,
    keep_last: usize,
}

/// Thread-safe state manager.
pub struct StateManager {
    inner: RwLock<Inner>,
}

impl StateManager {
    /// Create a new empty state at version 0.
    pub fn new(config: StateConfig) -> Self {
        let empty = Arc::new(BTreeMap::<Key, Value>::new());
        let root = compute_root(&empty);
        let genesis = Snapshot {
            version: Version(0),
            root,
            map: empty,
        };
        let mut history = VecDeque::new();
        history.push_back(genesis.clone());
        let inner = Inner {
            current: genesis,
            history,
            next_version: Version(1),
            keep_last: config.keep_last.max(1),
        };
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// Begin a new transaction on top of the latest snapshot.
    pub fn begin(&self) -> Transaction {
        let snap = self.latest();
        Transaction {
            base: snap,
            journal: Vec::new(),
            mgr: self,
        }
    }

    /// Latest immutable snapshot.
    pub fn latest(&self) -> Snapshot {
        let g = self.inner.read().expect("RwLock poisoned");
        g.current.clone()
    }

    /// Try to get a historical snapshot by exact version (if retained).
    pub fn snapshot(&self, version: Version) -> Option<Snapshot> {
        let g = self.inner.read().expect("RwLock poisoned");
        if g.current.version == version {
            return Some(g.current.clone());
        }
        g.history.iter().find(|s| s.version == version).cloned()
    }

    /// Current root.
    pub fn root(&self) -> Root32 {
        self.latest().root()
    }

    /// Current version.
    pub fn version(&self) -> Version {
        self.latest().version()
    }

    /// Apply a ready-made batch atomically (utility).
    pub fn apply_batch(&self, ops: &[WriteOp]) -> CommitReceipt {
        let mut tx = self.begin();
        for op in ops {
            match op {
                WriteOp::Put(k, v) => tx.put(k.clone(), v.clone()),
                WriteOp::Delete(k) => tx.delete(k.clone()),
            }
        }
        tx.commit()
    }
}

/// Transaction (copy-on-write).
pub struct Transaction<'a> {
    base: Snapshot,
    journal: Vec<WriteOp>,
    mgr: &'a StateManager,
}

impl<'a> Transaction<'a> {
    /// Read through transactional view (journal overrides base).
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        for op in self.journal.iter().rev() {
            match op {
                WriteOp::Put(k, v) if k.as_slice() == key => return Some(v.clone()),
                WriteOp::Delete(k) if k.as_slice() == key => return None,
                _ => {}
            }
        }
        self.base.get(key).map(|v| v.to_vec())
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    pub fn put(&mut self, key: Key, value: Value) {
        self.journal.push(WriteOp::Put(key, value));
    }

    pub fn delete(&mut self, key: Key) {
        self.journal.push(WriteOp::Delete(key));
    }

    /// Commit transactional changes:
    /// - clone-on-write from base map,
    /// - apply journal in order,
    /// - compute deterministic root,
    /// - bump version, install as current, rotate history by keep_last.
    pub fn commit(self) -> CommitReceipt {
        let writes = self.journal.len();
        // Fast-path: no writes -> just return latest view.
        if writes == 0 {
            let latest = self.mgr.latest();
            return CommitReceipt {
                new_version: latest.version(),
                new_root: latest.root(),
                writes: 0,
            };
        }

        let mut guard = self.mgr.inner.write().expect("RwLock poisoned");

        // Start from the actual current snapshot if base == current, else from base snapshot.
        // We always commit on top of latest to preserve linear history. If base is stale,
        // we rebase journal onto latest snapshot.
        let start_map = guard.current.map.clone();

        // Apply journal on a fresh owned map.
        let mut new_map: BTreeMap<Key, Value> = (*start_map).clone();
        for op in self.journal {
            match op {
                WriteOp::Put(k, v) => {
                    new_map.insert(k, v);
                }
                WriteOp::Delete(k) => {
                    new_map.remove(&k);
                }
            }
        }
        let new_map = Arc::new(new_map);
        let new_root = compute_root(&new_map);
        let new_version = guard.next_version;

        let new_snap = Snapshot {
            version: new_version,
            root: new_root,
            map: new_map,
        };

        // Rotate history
        guard.history.push_back(new_snap.clone());
        guard.current = new_snap.clone();
        guard.next_version = Version(new_version.0 + 1);
        while guard.history.len() > guard.keep_last {
            guard.history.pop_front();
        }

        CommitReceipt {
            new_version,
            new_root,
            writes,
        }
    }

    /// Drop changes.
    pub fn rollback(self) {
        // Intentionally empty: dropping the transaction discards journal.
    }
}

/// Compute deterministic root over the ordered map:
/// root = H( Σ for (k,v) in ascending key order: H(k || 0x00 || v) ) where H is a non-crypto 32-byte hash.
/// NOTE: Not cryptographically secure. Replace with a Merkle/MPT implementation for production.
/// Sources: Merkle trees & Ethereum state root formalization.
/// - https://en.wikipedia.org/wiki/Merkle_tree
/// - https://ethereum.github.io/yellowpaper/paper.pdf
fn compute_root(map: &BTreeMap<Key, Value>) -> Root32 {
    let mut acc = [0u8; 32];
    for (k, v) in map.iter() {
        let mut leaf = Vec::with_capacity(k.len() + 1 + v.len());
        leaf.extend_from_slice(k);
        leaf.push(0x00);
        leaf.extend_from_slice(v);
        let h = hash32(&leaf);
        for i in 0..32 {
            acc[i] ^= h[i].rotate_left((i % 8) as u32);
        }
    }
    Root32(acc)
}

/// Simple 32-byte deterministic hash (non-crypto). For production use a cryptographic hash.
/// Implemented to avoid external dependencies.
/// This is a mixing function inspired by non-cryptographic hashing.
/// (No security claims.)
fn hash32(data: &[u8]) -> [u8; 32] {
    let mut s0: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut s1: u64 = 0x4F1B_992E_9E37_79B9;
    let mut s2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    let mut s3: u64 = 0x1656_6789_ABCD_EF01;
    for &b in data {
        s0 = s0.rotate_left(5) ^ (b as u64) ^ s1.wrapping_mul(0x100_0000_01B3);
        s1 = s1.rotate_left(9) ^ s0.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        s2 = s2.rotate_left(11) ^ s1.wrapping_add(0x9E37_79B9);
        s3 = s3.rotate_left(13) ^ (s2 ^ 0x85EB_CA6B);
    }
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&s0.to_be_bytes());
    out[8..16].copy_from_slice(&s1.to_be_bytes());
    out[16..24].copy_from_slice(&s2.to_be_bytes());
    out[24..32].copy_from_slice(&s3.to_be_bytes());
    out
}

// ----------------------------- Tests -----------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_isolation_and_commit() {
        let mgr = StateManager::new(StateConfig { keep_last: 4 });

        // Initial state
        let s0 = mgr.latest();
        assert_eq!(s0.version(), Version(0));
        assert!(s0.is_empty());

        // Begin tx, write k1, but not yet committed
        let mut tx = mgr.begin();
        tx.put(b"k1".to_vec(), b"v1".to_vec());
        assert_eq!(tx.get(b"k1"), Some(b"v1".to_vec()));
        // Global state not changed yet
        assert_eq!(mgr.latest().get(b"k1"), None);

        // Commit
        let r = tx.commit();
        assert_eq!(r.new_version, Version(1));
        assert_eq!(r.writes, 1);
        let s1 = mgr.latest();
        assert_eq!(s1.version(), Version(1));
        assert_eq!(s1.get(b"k1"), Some(&b"v1"[..]));
        assert_ne!(s1.root(), Root32([0u8; 32])); // changed root
    }

    #[test]
    fn delete_and_reinsert_determinism() {
        let mgr = StateManager::new(StateConfig { keep_last: 8 });

        // Insert k1, k2
        {
            let mut tx = mgr.begin();
            tx.put(b"k1".to_vec(), b"v1".to_vec());
            tx.put(b"k2".to_vec(), b"v2".to_vec());
            tx.commit();
        }
        let s2 = mgr.latest();
        let root_after_insert = s2.root();

        // Delete k2, then reinsert same pair -> root should return to previous value
        {
            let mut tx = mgr.begin();
            tx.delete(b"k2".to_vec());
            tx.commit();
        }
        {
            let mut tx = mgr.begin();
            tx.put(b"k2".to_vec(), b"v2".to_vec());
            tx.commit();
        }
        let s4 = mgr.latest();
        assert_eq!(s4.get(b"k1"), Some(&b"v1"[..]));
        assert_eq!(s4.get(b"k2"), Some(&b"v2"[..]));
        assert_eq!(s4.root(), root_after_insert);
    }

    #[test]
    fn snapshot_retention() {
        let mgr = StateManager::new(StateConfig { keep_last: 3 });

        for i in 0..5u8 {
            let mut tx = mgr.begin();
            tx.put(vec![b'k', i], vec![b'v', i]);
            tx.commit();
        }
        // Versions: 0(genesis),1,2,3,4,5(latest). keep_last=3 retains 3 snapshots: v3,v4,v5
        assert!(mgr.snapshot(Version(2)).is_none());
        assert!(mgr.snapshot(Version(3)).is_some());
        assert!(mgr.snapshot(Version(4)).is_some());
        assert!(mgr.snapshot(Version(5)).is_some());
        assert_eq!(mgr.version(), Version(5));
    }
}

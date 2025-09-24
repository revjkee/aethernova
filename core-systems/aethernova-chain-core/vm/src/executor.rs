// Path: aethernova-chain-core/vm/src/executor.rs
//
// Parallel optimistic executor with read/write-sets and deterministic (index-ordered) commit.
// Design:
//  - Workers execute transactions speculatively and produce (read_set, write_set, output).
//  - A single commit coordinator validates read_set against current state versions.
//    If valid -> applies write_set (bumping versions) and commits in original tx order.
//    If invalid -> re-queues the tx for re-execution (bounded retries).
//
// Correctness & background:
//  - Optimistic Concurrency Control (OCC): execute without locks, then validate + retry on conflicts. :contentReference[oaicite:1]{index=1}
//  - Deterministic parallel execution for blockchains (speculative exec + ordered commit) as в Block-STM. :contentReference[oaicite:2]{index=2}
//
// No external deps; uses std::{sync, thread, mpsc}. Replace with your VM by implementing `Transaction`.
//
// --------------------------------------------------------------------------------------------

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc, Arc, RwLock,
};
use std::thread;
use std::time::Duration;

// -------- Types --------

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

#[derive(Clone, Debug)]
pub struct Entry {
    pub version: u64,
    pub value: Value,
}

#[derive(Default)]
pub struct VersionedState {
    inner: RwLock<HashMap<Key, Entry>>,
    global_commits: AtomicU64,
}

impl VersionedState {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            global_commits: AtomicU64::new(0),
        }
    }

    /// Read snapshot of a key: (value_opt, version). Missing key => (None, 0).
    pub fn read(&self, key: &[u8]) -> (Option<Value>, u64) {
        let g = self.inner.read().expect("state RwLock poisoned");
        if let Some(e) = g.get(key) {
            (Some(e.value.clone()), e.version)
        } else {
            (None, 0)
        }
    }

    /// Validate a read_set and, if valid, apply a write_set atomically.
    /// Returns true if committed, false if validation failed.
    pub fn validate_and_commit(
        &self,
        read_set: &BTreeMap<Key, u64>,
        write_set: &BTreeMap<Key, Value>,
    ) -> bool {
        // Acquire write lock for validate+commit section.
        let mut g = self.inner.write().expect("state RwLock poisoned");

        // Validate: versions must match.
        for (k, v) in read_set {
            match g.get(k) {
                Some(e) => {
                    if e.version != *v {
                        return false; // conflict
                    }
                }
                None => {
                    if *v != 0 {
                        return false; // read saw "absent", but key now exists
                    }
                }
            }
        }

        // Apply writes: bump per-key version (or set to global+1) and write value.
        let commit_id = self.global_commits.fetch_add(1, Ordering::SeqCst) + 1;
        for (k, val) in write_set {
            match g.get_mut(k) {
                Some(e) => {
                    e.value = val.clone();
                    // Either per-key +1 or monotonic commit id; choose commit_id for monotonicity.
                    e.version = commit_id;
                }
                None => {
                    g.insert(
                        k.clone(),
                        Entry {
                            version: commit_id,
                            value: val.clone(),
                        },
                    );
                }
            }
        }
        true
    }
}

// -------- Transaction & context --------

/// Your VM must implement this trait for a transaction.
/// Output format is opaque bytes; adapt as needed.
pub trait Transaction: Send + Sync {
    fn execute(&self, ctx: &mut TxnCtx<'_>) -> Result<Vec<u8>, String>;
}

/// Execution context passed to a transaction: tracks read/write sets.
pub struct TxnCtx<'a> {
    state: &'a VersionedState,
    // speculative buffers:
    read_set: BTreeMap<Key, u64>,
    write_set: BTreeMap<Key, Value>,
}

impl<'a> TxnCtx<'a> {
    fn new(state: &'a VersionedState) -> Self {
        Self {
            state,
            read_set: BTreeMap::new(),
            write_set: BTreeMap::new(),
        }
    }

    /// Read with write-buffer bypass and version capture.
    pub fn read(&mut self, key: &[u8]) -> Option<Value> {
        if let Some(v) = self.write_set.get(key) {
            return Some(v.clone());
        }
        let (val, ver) = self.state.read(key);
        // track version for validation (even if None -> version 0)
        self.read_set.insert(key.to_vec(), ver);
        val
    }

    /// Write to the speculative buffer.
    pub fn write(&mut self, key: &[u8], value: Value) {
        self.write_set.insert(key.to_vec(), value);
        // Note: we purposely don't update read_set here; if tx read before write,
        // read_set already captured the version; if write-only, no read-set entry is needed.
    }

    /// Export read/write sets after tx executes.
    fn finalize(self) -> (BTreeMap<Key, u64>, BTreeMap<Key, Value>) {
        (self.read_set, self.write_set)
    }
}

// -------- Executor --------

#[derive(Clone, Debug)]
pub enum CommitStatus {
    Committed,
    AbortedMaxRetries,
    VmError(String),
}

#[derive(Clone, Debug)]
pub struct TxOutcome {
    pub status: CommitStatus,
    pub retries: u32,
    pub output: Option<Vec<u8>>,
}

struct Job {
    index: usize,
    attempt: u32,
}

struct Candidate {
    index: usize,
    read_set: BTreeMap<Key, u64>,
    write_set: BTreeMap<Key, Value>,
    output: Vec<u8>,
    attempt: u32,
}

pub struct Executor {
    state: Arc<VersionedState>,
    max_retries: u32,
    workers: usize,
    backoff_base_ms: u64,
}

impl Executor {
    pub fn new(state: Arc<VersionedState>) -> Self {
        Self {
            state,
            max_retries: 8,
            workers: std::cmp::max(1, std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)),
            backoff_base_ms: 2,
        }
    }

    pub fn with_max_retries(mut self, r: u32) -> Self {
        self.max_retries = r;
        self
    }

    pub fn with_workers(mut self, n: usize) -> Self {
        self.workers = std::cmp::max(1, n);
        self
    }

    /// Execute transactions in parallel; commit deterministically (index order).
    pub fn execute_ordered<T: Transaction + 'static>(
        &self,
        txs: Vec<Arc<T>>,
    ) -> Vec<TxOutcome> {
        let n = txs.len();
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (cand_tx, cand_rx) = mpsc::channel::<Candidate>();

        // Seed jobs: one per tx index.
        for i in 0..n {
            job_tx.send(Job { index: i, attempt: 0 }).expect("queue seed");
        }

        // Spawn worker threads.
        for _ in 0..self.workers {
            let state = Arc::clone(&self.state);
            let job_rx = job_rx.clone();
            let cand_tx = cand_tx.clone();
            let txs = txs.clone();
            let backoff = self.backoff_base_ms;

            thread::spawn(move || {
                while let Ok(Job { index, attempt }) = job_rx.recv() {
                    let tx = &txs[index];
                    // Optional small backoff on retries to reduce live-lock.
                    if attempt > 0 {
                        let d = backoff.saturating_mul(1 << (attempt.min(5)));
                        thread::sleep(Duration::from_millis(d));
                    }
                    // Execute speculatively.
                    match Self::execute_once(tx, &state) {
                        Ok((rs, ws, out)) => {
                            let _ = cand_tx.send(Candidate {
                                index,
                                read_set: rs,
                                write_set: ws,
                                output: out,
                                attempt,
                            });
                        }
                        Err(e) => {
                            // Send as candidate with VmError via special write_set marker (empty) and attempt.
                            let _ = cand_tx.send(Candidate {
                                index,
                                read_set: BTreeMap::new(),
                                write_set: BTreeMap::new(),
                                output: format!("VM_ERROR: {e}").into_bytes(),
                                attempt,
                            });
                        }
                    }
                }
            });
        }

        drop(job_rx); // worker clones still hold receivers
        drop(cand_tx); // coordinator will own the last receiver

        // Commit coordinator: commits strictly in order [0..n).
        let mut outcomes = vec![
            TxOutcome {
                status: CommitStatus::AbortedMaxRetries,
                retries: 0,
                output: None
            };
            n
        ];
        let mut pending: HashMap<usize, Candidate> = HashMap::new();
        let mut retries: Vec<u32> = vec![0; n];
        let mut next_to_commit = 0;

        while next_to_commit < n {
            // Fetch candidates until the one for `next_to_commit` is available.
            let cand = loop {
                if let Some(c) = pending.remove(&next_to_commit) {
                    break c;
                }
                match cand_rx.recv() {
                    Ok(c) => {
                        // If worker signaled VM error (sent empty sets), record and advance.
                        let vm_err = c.read_set.is_empty() && c.write_set.is_empty() &&
                            String::from_utf8_lossy(&c.output).starts_with("VM_ERROR:");
                        if vm_err && c.index == next_to_commit {
                            outcomes[c.index] = TxOutcome {
                                status: CommitStatus::VmError(
                                    String::from_utf8_lossy(&c.output).to_string()
                                ),
                                retries: c.attempt,
                                output: None,
                            };
                            next_to_commit += 1;
                            continue; // proceed to next
                        } else if vm_err {
                            // VM error for out-of-order index; record and mark as done.
                            outcomes[c.index] = TxOutcome {
                                status: CommitStatus::VmError(
                                    String::from_utf8_lossy(&c.output).to_string()
                                ),
                                retries: c.attempt,
                                output: None,
                            };
                            // Skip further processing for this index.
                            // Ensure commit pointer will eventually pass this index.
                            pending.remove(&c.index);
                            continue;
                        }
                        pending.insert(c.index, c);
                    }
                    Err(_) => {
                        // No more candidates; should not happen unless all threads exited.
                        break;
                    }
                }
            };

            // Validate & commit (serial, deterministic).
            let ok = self
                .state
                .validate_and_commit(&cand.read_set, &cand.write_set);

            if ok {
                outcomes[cand.index] = TxOutcome {
                    status: CommitStatus::Committed,
                    retries: cand.attempt,
                    output: Some(cand.output),
                };
                next_to_commit += 1;
            } else {
                // Conflict: re-enqueue if retries remain.
                let r = retries[cand.index].saturating_add(1);
                retries[cand.index] = r;
                if r > self.max_retries {
                    outcomes[cand.index] = TxOutcome {
                        status: CommitStatus::AbortedMaxRetries,
                        retries: cand.attempt,
                        output: None,
                    };
                    next_to_commit += 1;
                } else {
                    let _ = job_tx.send(Job {
                        index: cand.index,
                        attempt: r,
                    });
                }
            }
        }

        outcomes
    }

    fn execute_once<T: Transaction>(
        tx: &T,
        state: &VersionedState,
    ) -> Result<(BTreeMap<Key, u64>, BTreeMap<Key, Value>, Vec<u8>), String> {
        let mut ctx = TxnCtx::new(state);
        let out = tx.execute(&mut ctx)?;
        let (rs, ws) = ctx.finalize();
        Ok((rs, ws, out))
    }
}

// -------- Optional test scaffold (enable in your workspace) --------

#[cfg(test)]
mod tests {
    use super::*;

    struct AddTx {
        k: Key,
        delta: i64,
    }

    impl Transaction for AddTx {
        fn execute(&self, ctx: &mut TxnCtx<'_>) -> Result<Vec<u8>, String> {
            let cur = ctx
                .read(&self.k)
                .map(|v| {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&v);
                    i64::from_be_bytes(a)
                })
                .unwrap_or(0);
            let new = cur + self.delta;
            ctx.write(&self.k, new.to_be_bytes().to_vec());
            Ok(new.to_be_bytes().to_vec())
        }
    }

    #[test]
    fn parallel_exec_ordered_commit() {
        let state = Arc::new(VersionedState::new());
        let exec = Executor::new(state.clone()).with_workers(4).with_max_retries(4);

        // 100 tx over same key -> many conflicts during validation, but deterministic final result.
        let key = b"balance".to_vec();
        let mut txs = Vec::new();
        for _ in 0..100 {
            txs.push(Arc::new(AddTx { k: key.clone(), delta: 1 }) as Arc<dyn Transaction>);
        }

        let outcomes = exec.execute_ordered(txs);
        assert!(outcomes.iter().all(|o| matches!(o.status, CommitStatus::Committed)));
        let (val, _) = state.read(&key);
        let res = i64::from_be_bytes(val.unwrap().try_into().unwrap());
        assert_eq!(res, 100);
    }
}

// aethernova-chain-core/node/src/state/utxo.rs
//! UTXO subsystem for BTC-like profile: thread-safe in-memory store,
//! batch apply/revert with undo logs, deterministic H256 commitment,
//! script type detection, snapshots, and basic metrics.
//!
//! Optional feature `sha2` enables cryptographic SHA-256 for commitments.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

/// 32-byte hash (H256).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct H256([u8; 32]);

impl H256 {
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(nibble_hex(b >> 4));
            s.push(nibble_hex(b & 0x0f));
        }
        s
    }
}
impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}
fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

/// Deterministic hashing into H256.
/// With feature `sha2` use SHA-256, otherwise stable fallback.
fn hash_bytes(bytes: &[u8]) -> H256 {
    #[cfg(feature = "sha2")]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out[..32]);
        H256::from_bytes(b)
    }
    #[cfg(not(feature = "sha2"))]
    {
        let mut acc = [0u8; 32];
        for (i, ch) in bytes.chunks(32).enumerate() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            i.hash(&mut hasher);
            ch.hash(&mut hasher);
            let v = hasher.finish().to_be_bytes();
            let off = (i % 4) * 8;
            for j in 0..8 {
                acc[off + j] ^= v[j];
            }
        }
        H256::from_bytes(acc)
    }
}

/// Transaction outpoint (txid, vout).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct OutPoint {
    pub txid: H256,
    pub vout: u32,
}
impl OutPoint {
    pub fn new(txid: H256, vout: u32) -> Self {
        Self { txid, vout }
    }
}

/// Minimal scriptPubKey classification for BTC-style scripts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    Unknown,
}

/// Detect script type by scriptPubKey bytes.
pub fn detect_script_type(spk: &[u8]) -> ScriptType {
    // P2PKH: OP_DUP OP_HASH160 0x14 <20B> OP_EQUALVERIFY OP_CHECKSIG
    if spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
    {
        return ScriptType::P2PKH;
    }
    // P2SH: OP_HASH160 0x14 <20B> OP_EQUAL
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        return ScriptType::P2SH;
    }
    // P2WPKH: 0x00 0x14 <20B>
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 {
        return ScriptType::P2WPKH;
    }
    // P2WSH: 0x00 0x20 <32B>
    if spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20 {
        return ScriptType::P2WSH;
    }
    // P2TR (v1 bech32m): 0x51 0x20 <32B>
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        return ScriptType::P2TR;
    }
    ScriptType::Unknown
}

/// Transaction output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}
impl TxOut {
    pub fn new(value_sat: u64, script_pubkey: Vec<u8>) -> Self {
        Self { value_sat, script_pubkey }
    }
    pub fn script_type(&self) -> ScriptType {
        detect_script_type(&self.script_pubkey)
    }
}

/// Coin in the UTXO set: TxOut + metadata.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Coin {
    pub out: TxOut,
    pub height: u32,
    pub coinbase: bool,
}
impl Coin {
    pub fn new(out: TxOut, height: u32, coinbase: bool) -> Self {
        Self { out, height, coinbase }
    }
}

/// Errors for UTXO operations.
#[derive(Debug)]
pub enum UtxoError {
    NotFound(OutPoint),
    AlreadyExists(OutPoint),
    InconsistentSpend(OutPoint),
    Internal(String),
}
impl fmt::Display for UtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtxoError::NotFound(op) => write!(f, "utxo not found: {:?}:{:?}", op.txid, op.vout),
            UtxoError::AlreadyExists(op) => write!(f, "utxo already exists: {:?}:{:?}", op.txid, op.vout),
            UtxoError::InconsistentSpend(op) => write!(f, "spend refers to non-existent or duplicate outpoint: {:?}:{:?}", op.txid, op.vout),
            UtxoError::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}
impl std::error::Error for UtxoError {}

/// Block update: new outputs created and prevouts spent.
#[derive(Clone, Debug)]
pub struct BlockUpdate {
    pub height: u32,
    pub created: Vec<(OutPoint, Coin)>,
    pub spent: Vec<OutPoint>,
}
impl BlockUpdate {
    pub fn new(height: u32) -> Self {
        Self { height, created: Vec::new(), spent: Vec::new() }
    }
    pub fn with_created(mut self, op: OutPoint, c: Coin) -> Self {
        self.created.push((op, c)); self
    }
    pub fn with_spent(mut self, op: OutPoint) -> Self {
        self.spent.push(op); self
    }
}

/// Undo entry for a block: to revert, delete all created and restore all spent.
#[derive(Clone, Debug)]
pub struct UndoEntry {
    pub height: u32,
    pub created: Vec<OutPoint>,             // delete these on revert
    pub spent_restore: Vec<(OutPoint, Coin)>, // restore these on revert
}

/// Read-only snapshot view.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub len: usize,
    pub commitment: H256,
    pub by_script_type: BTreeMap<ScriptType, usize>,
}

/// Storage trait for UTXO set.
pub trait UtxoStorage: Send + Sync + 'static {
    fn get(&self, op: &OutPoint) -> Option<Coin>;
    fn contains(&self, op: &OutPoint) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn apply_block(&self, upd: BlockUpdate) -> Result<UndoEntry, UtxoError>;
    fn revert(&self, undo: &UndoEntry) -> Result<(), UtxoError>;
    fn commitment(&self) -> H256;
    fn snapshot(&self) -> Snapshot;
    fn export_all(&self) -> Vec<(OutPoint, Coin)>;
    fn import_all(&self, entries: Vec<(OutPoint, Coin)>) -> Result<(), UtxoError>;
}

/// In-memory UTXO storage with script type counters.
#[derive(Default)]
pub struct InMemoryUtxo {
    inner: RwLock<State>,
}

#[derive(Default)]
struct State {
    map: HashMap<OutPoint, Coin>,
    by_script_type: BTreeMap<ScriptType, usize>,
    commitment: H256,
}

impl InMemoryUtxo {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: RwLock::new(State::default()) })
    }

    fn update_commitment_for_pair(acc: &mut [u8; 32], op: &OutPoint, c: &Coin, add: bool) {
        // Compute entry hash: op.txid || vout || value || height || coinbase || script bytes
        let mut buf = Vec::with_capacity(32 + 4 + 8 + 4 + 1 + c.out.script_pubkey.len());
        buf.extend_from_slice(op.txid.as_bytes());
        buf.extend_from_slice(&op.vout.to_be_bytes());
        buf.extend_from_slice(&c.out.value_sat.to_be_bytes());
        buf.extend_from_slice(&c.height.to_be_bytes());
        buf.push(if c.coinbase { 1 } else { 0 });
        buf.extend_from_slice(&c.out.script_pubkey);
        let h = hash_bytes(&buf);

        // XOR fold into acc (commutative for add/remove).
        let hb = h.as_bytes();
        for i in 0..32 {
            if add {
                acc[i] ^= hb[i];
            } else {
                // same as add (XOR is its own inverse)
                acc[i] ^= hb[i];
            }
        }
    }

    fn recalc_commitment(state: &State) -> H256 {
        let mut acc = [0u8; 32];
        for (op, c) in state.map.iter() {
            Self::update_commitment_for_pair(&mut acc, op, c, true);
        }
        H256::from_bytes(acc)
    }
}

impl UtxoStorage for InMemoryUtxo {
    fn get(&self, op: &OutPoint) -> Option<Coin> {
        self.inner.read().unwrap().map.get(op).cloned()
    }

    fn contains(&self, op: &OutPoint) -> bool {
        self.inner.read().unwrap().map.contains_key(op)
    }

    fn len(&self) -> usize {
        self.inner.read().unwrap().map.len()
    }

    fn apply_block(&self, upd: BlockUpdate) -> Result<UndoEntry, UtxoError> {
        let mut st = self.inner.write().unwrap();

        // Pre-validate spends exist and not double-spent in this batch
        {
            let mut seen_spends = HashSet::new();
            for op in &upd.spent {
                if !st.map.contains_key(op) {
                    return Err(UtxoError::NotFound(*op));
                }
                if !seen_spends.insert(*op) {
                    return Err(UtxoError::InconsistentSpend(*op));
                }
            }
        }

        // Pre-validate creates do not overwrite existing or duplicate in batch
        {
            let mut seen_creates = HashSet::new();
            for (op, _) in &upd.created {
                if st.map.contains_key(op) {
                    return Err(UtxoError::AlreadyExists(*op));
                }
                if !seen_creates.insert(*op) {
                    return Err(UtxoError::AlreadyExists(*op));
                }
            }
        }

        let mut undo = UndoEntry {
            height: upd.height,
            created: Vec::with_capacity(upd.created.len()),
            spent_restore: Vec::with_capacity(upd.spent.len()),
        };

        // Spend: remove and remember coins for undo; update counters & commitment
        let mut acc = st.commitment.as_bytes().clone();
        for op in &upd.spent {
            if let Some(coin) = st.map.remove(op) {
                // counters
                let ty = coin.out.script_type();
                if let Some(cnt) = st.by_script_type.get_mut(&ty) {
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 { st.by_script_type.remove(&ty); }
                }
                // commit
                Self::update_commitment_for_pair(&mut acc, op, &coin, false);
                // undo
                undo.spent_restore.push((*op, coin));
            } else {
                return Err(UtxoError::NotFound(*op));
            }
        }

        // Create: insert new coins; update counters & commitment
        for (op, coin) in &upd.created {
            match st.map.entry(*op) {
                Entry::Vacant(e) {
                    let ty = coin.out.script_type();
                    *st.by_script_type.entry(ty).or_insert(0) += 1;
                    Self::update_commitment_for_pair(&mut acc, op, coin, true);
                    e.insert(coin.clone());
                    undo.created.push(*op);
                }
                Entry::Occupied(_) => return Err(UtxoError::AlreadyExists(*op)),
            }
        }

        st.commitment = H256::from_bytes(acc);
        Ok(undo)
    }

    fn revert(&self, undo: &UndoEntry) -> Result<(), UtxoError> {
        let mut st = self.inner.write().unwrap();
        let mut acc = st.commitment.as_bytes().clone();

        // Delete created
        for op in &undo.created {
            if let Some(coin) = st.map.remove(op) {
                let ty = coin.out.script_type();
                if let Some(cnt) = st.by_script_type.get_mut(&ty) {
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 { st.by_script_type.remove(&ty); }
                }
                Self::update_commitment_for_pair(&mut acc, op, &coin, false);
            } else {
                // Created missing — inconsistent revert
                return Err(UtxoError::NotFound(*op));
            }
        }

        // Restore spent
        for (op, coin) in &undo.spent_restore {
            if st.map.contains_key(op) {
                return Err(UtxoError::AlreadyExists(*op));
            }
            let ty = coin.out.script_type();
            *st.by_script_type.entry(ty).or_insert(0) += 1;
            Self::update_commitment_for_pair(&mut acc, op, coin, true);
            st.map.insert(*op, coin.clone());
        }

        st.commitment = H256::from_bytes(acc);
        Ok(())
    }

    fn commitment(&self) -> H256 {
        self.inner.read().unwrap().commitment
    }

    fn snapshot(&self) -> Snapshot {
        let st = self.inner.read().unwrap();
        Snapshot {
            len: st.map.len(),
            commitment: st.commitment,
            by_script_type: st.by_script_type.clone(),
        }
    }

    fn export_all(&self) -> Vec<(OutPoint, Coin)> {
        let st = self.inner.read().unwrap();
        let mut v: Vec<(OutPoint, Coin)> = st.map.iter().map(|(k, v)| (*k, v.clone())).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    fn import_all(&self, entries: Vec<(OutPoint, Coin)>) -> Result<(), UtxoError> {
        let mut st = self.inner.write().unwrap();
        st.map.clear();
        st.by_script_type.clear();

        for (op, coin) in entries {
            if st.map.insert(op, coin.clone()).is_some() {
                return Err(UtxoError::AlreadyExists(op));
            }
            let ty = coin.out.script_type();
            *st.by_script_type.entry(ty).or_insert(0) += 1;
        }
        st.commitment = InMemoryUtxo::recalc_commitment(&st);
        Ok(())
    }
}

// ------------- std::collections used in pre-validation
use std::collections::HashSet;

// ------------------------------- Tests ---------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn h256(n: u64) -> H256 {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        H256::from_bytes(b)
    }

    fn op(tx: u64, vout: u32) -> OutPoint {
        OutPoint::new(h256(tx), vout)
    }

    fn p2wpkh_script() -> Vec<u8> {
        // 0x00 0x14 <20 bytes>
        let mut v = vec![0x00, 0x14];
        v.extend([0u8; 20]);
        v
    }

    #[test]
    fn script_detection() {
        // P2PKH
        let mut s = vec![0u8; 25];
        s[0] = 0x76; s[1] = 0xa9; s[2] = 0x14; s[23] = 0x88; s[24] = 0xac;
        assert_eq!(detect_script_type(&s), ScriptType::P2PKH);

        // P2SH
        let mut s2 = vec![0u8; 23];
        s2[0] = 0xa9; s2[1] = 0x14; s2[22] = 0x87;
        assert_eq!(detect_script_type(&s2), ScriptType::P2SH);

        // P2WPKH
        let mut s3 = vec![0x00, 0x14]; s3.extend([0u8; 20]);
        assert_eq!(detect_script_type(&s3), ScriptType::P2WPKH);

        // P2WSH
        let mut s4 = vec![0x00, 0x20]; s4.extend([0u8; 32]);
        assert_eq!(detect_script_type(&s4), ScriptType::P2WSH);

        // P2TR
        let mut s5 = vec![0x51, 0x20]; s5.extend([0u8; 32]);
        assert_eq!(detect_script_type(&s5), ScriptType::P2TR);
    }

    #[test]
    fn apply_and_revert_block() {
        let store = InMemoryUtxo::new();

        let c1 = Coin::new(TxOut::new(50_000, p2wpkh_script()), 1, true);
        let c2 = Coin::new(TxOut::new(25_000, p2wpkh_script()), 1, true);

        // Block 1: create two outputs
        let mut b1 = BlockUpdate::new(1);
        b1 = b1.with_created(op(1, 0), c1.clone());
        b1 = b1.with_created(op(1, 1), c2.clone());
        let u1 = store.apply_block(b1).unwrap();

        let snap1 = store.snapshot();
        assert_eq!(snap1.len, 2);
        let commit1 = store.commitment();
        assert_ne!(commit1, H256::zero());

        // Block 2: spend one, create change
        let c3 = Coin::new(TxOut::new(10_000, p2wpkh_script()), 2, false);
        let mut b2 = BlockUpdate::new(2);
        b2 = b2.with_spent(op(1, 0));
        b2 = b2.with_created(op(2, 0), c3.clone());
        let u2 = store.apply_block(b2).unwrap();

        let snap2 = store.snapshot();
        assert_eq!(snap2.len, 2); // one spent, one created
        let commit2 = store.commitment();
        assert_ne!(commit2, commit1);

        // Revert block 2
        store.revert(&u2).unwrap();
        let snap3 = store.snapshot();
        assert_eq!(snap3.len, 2);
        assert_eq!(store.commitment(), commit1);

        // Revert block 1
        store.revert(&u1).unwrap();
        assert_eq!(store.len(), 0);
        assert_eq!(store.commitment(), H256::zero());
    }

    #[test]
    fn rejects_double_spend_and_overwrite() {
        let store = InMemoryUtxo::new();

        let c = Coin::new(TxOut::new(1, p2wpkh_script()), 1, false);
        let b1 = BlockUpdate::new(1).with_created(op(1, 0), c.clone());
        store.apply_block(b1).unwrap();

        // Double create same outpoint
        let b2 = BlockUpdate::new(2).with_created(op(1, 0), c.clone());
        assert!(matches!(store.apply_block(b2), Err(UtxoError::AlreadyExists(_))));

        // Spend non-existent
        let b3 = BlockUpdate::new(3).with_spent(op(9, 0));
        assert!(matches!(store.apply_block(b3), Err(UtxoError::NotFound(_))));

        // Double spend in the same batch
        let mut b4 = BlockUpdate::new(4);
        b4 = b4.with_spent(op(1, 0)).with_spent(op(1, 0));
        assert!(matches!(store.apply_block(b4), Err(UtxoError::InconsistentSpend(_))));
    }
}

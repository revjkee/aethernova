//! File: aethernova-chain-core/node/src/consensus/finality/light_client.rs
//! Industrial-grade Light Client for finality & checkpoint verification.
//!
//! Design goals:
//! - Trust bootstrap via checkpoint (trusted header + validator set digest).
//! - Finality verification (generic trait for BFT/GRANDPA/Tendermint-like).
//! - Header chain tracking with reorg resistance (monotonic finalized height).
//! - Membership proofs (Merkle) for events/receipts/state digests in header.
//! - Minimal, auditable interfaces; cryptography abstracted behind traits.
//! - Pluggable storage (in-memory or persistent) via StorageAdapter.
//!
//! This module is `no_std`-friendly if collections/std features are gated in the
//! consumer crate; here we use std for simplicity in the node context.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::hash::Hash as StdHash;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

use thiserror::Error;

/// Block height type.
pub type Height = u64;
/// Binary blob type for hashes/keys/signatures.
pub type Bytes = Vec<u8>;

/// -------------------------------------------------------------------------------------
/// Errors
/// -------------------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum LightClientError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),
    #[error("header older than finalized: header={header_height}, finalized={finalized_height}")]
    NonMonotonic { header_height: Height, finalized_height: Height },
    #[error("parent hash mismatch")]
    ParentMismatch,
    #[error("hash mismatch")]
    HashMismatch,
    #[error("unknown parent")]
    UnknownParent,
    #[error("finality verification failed: {0}")]
    FinalityVerification(String),
    #[error("validator set changed unexpectedly")]
    UnexpectedValidatorSetChange,
    #[error("stale proof or time drift exceeds bound")]
    TimeDrift,
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
    #[error("not found")]
    NotFound,
}

/// -------------------------------------------------------------------------------------
/// Traits for pluggable cryptography, hashing, finality and storage
/// -------------------------------------------------------------------------------------

/// Abstract hash function for block headers / Merkle trees.
pub trait HashFn: Clone + Send + Sync + 'static {
    /// Hash leaf bytes.
    fn hash_leaf(data: &[u8]) -> Bytes;
    /// Hash three nodes, or generally concatenate then hash.
    fn hash_nodes(left: &[u8], right: &[u8]) -> Bytes;
}

/// Header structure expected by the light client.
pub trait Header: Clone + Send + Sync + 'static {
    /// Unique block hash.
    fn hash(&self) -> Bytes;
    /// Parent block hash (empty for genesis).
    fn parent_hash(&self) -> Bytes;
    /// Height of this block.
    fn height(&self) -> Height;
    /// Commitment to state root (for membership proofs).
    fn state_root(&self) -> Bytes;
    /// Commitment to receipts/events root.
    fn receipts_root(&self) -> Bytes;
    /// Timestamp (unix seconds).
    fn timestamp(&self) -> u64;
}

/// Finality proof type (e.g., GRANDPA commit, Tendermint commit, HotStuff QC).
pub trait FinalityProof: Clone + Send + Sync + 'static {
    /// Height proven finalized by this proof.
    fn target_height(&self) -> Height;
    /// Block hash proven finalized.
    fn target_hash(&self) -> Bytes;
    /// Optional proof carries new validator set digest (for dynamic sets).
    fn next_validator_set(&self) -> Option<ValidatorSetDigest>;
}

/// Verifier of finality proofs under a known validator set digest.
pub trait FinalityVerifier: Clone + Send + Sync + 'static {
    /// Verify proof under current validator set digest.
    fn verify(&self, proof: &impl FinalityProof, current_set: &ValidatorSetDigest) -> Result<(), String>;
    /// Optionally validate transitions to a new validator set digest.
    fn verify_next_set(
        &self,
        proof: &impl FinalityProof,
        current_set: &ValidatorSetDigest,
        next_set: &ValidatorSetDigest,
    ) -> Result<(), String>;
}

/// Digest (hash) of validator set, opaque to the client, produced by chain-specific logic.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatorSetDigest(pub Bytes);

impl Debug for ValidatorSetDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidatorSetDigest(0x{})", hex::encode(&self.0))
    }
}

/// Storage abstraction for trusted headers & metadata.
pub trait StorageAdapter<H: Header>: Clone + Send + Sync + 'static {
    fn get_trusted_finalized(&self) -> Result<Option<TrustedHeader<H>>, LightClientError>;
    fn put_trusted_finalized(&self, header: &TrustedHeader<H>) -> Result<(), LightClientError>;
    fn get_header(&self, hash: &[u8]) -> Result<Option<H>, LightClientError>;
    fn put_header(&self, header: &H) -> Result<(), LightClientError>;
    fn prune_below(&self, height: Height) -> Result<(), LightClientError>;
}

/// -------------------------------------------------------------------------------------
/// Data structures
/// -------------------------------------------------------------------------------------

/// Trusted header with auxiliary metadata maintained by the light client.
#[derive(Clone)]
pub struct TrustedHeader<H: Header> {
    pub header: H,
    pub finalized_at: SystemTime,
    pub validator_set: ValidatorSetDigest,
}

impl<H: Header> Debug for TrustedHeader<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TrustedHeader {{ height: {}, hash: 0x{}, finalized_at: {:?}, validator_set: {:?} }}",
            self.header.height(),
            hex::encode(self.header.hash()),
            self.finalized_at,
            self.validator_set
        )
    }
}

/// Bootstrap checkpoint to initialize trust.
#[derive(Clone, Debug)]
pub struct Checkpoint<H: Header> {
    pub trusted_header: H,
    pub validator_set: ValidatorSetDigest,
    pub issued_at: SystemTime,
    pub max_time_drift: Duration,
}

/// Merkle proof item (sibling hash and whether it is left or right).
#[derive(Clone, Debug)]
pub struct MerkleProofItem {
    pub sibling: Bytes,
    pub is_left: bool,
}

/// Merkle proof over a binary tree with known root.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub items: Vec<MerkleProofItem>,
    pub leaf: Bytes,
    pub expected_root: Bytes,
}

/// -------------------------------------------------------------------------------------
/// Light Client
/// -------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct LightClient<
    H: Header,
    HF: HashFn,
    F: FinalityVerifier,
    S: StorageAdapter<H>,
> {
    storage: S,
    hash_fn: HF,
    verifier: F,
    max_time_drift: Duration,
    _marker: PhantomData<H>,
}

impl<H, HF, F, S> LightClient<H, HF, F, S>
where
    H: Header,
    HF: HashFn,
    F: FinalityVerifier,
    S: StorageAdapter<H>,
{
    /// Initialize the client with a trusted checkpoint.
    pub fn init_with_checkpoint(
        storage: S,
        hash_fn: HF,
        verifier: F,
        checkpoint: Checkpoint<H>,
    ) -> Result<Self, LightClientError> {
        // Basic sanity: header's timestamp should not be too far in future vs issued_at/max drift.
        let hdr_ts = SystemTime::UNIX_EPOCH + Duration::from_secs(checkpoint.trusted_header.timestamp());
        if hdr_ts > checkpoint.issued_at + checkpoint.max_time_drift {
            return Err(LightClientError::InvalidCheckpoint(
                "checkpoint header timestamp exceeds allowed drift".into(),
            ));
        }

        let trusted = TrustedHeader {
            header: checkpoint.trusted_header.clone(),
            finalized_at: checkpoint.issued_at,
            validator_set: checkpoint.validator_set.clone(),
        };
        storage.put_header(&checkpoint.trusted_header)?;
        storage.put_trusted_finalized(&trusted)?;

        Ok(Self {
            storage,
            hash_fn,
            verifier,
            max_time_drift: checkpoint.max_time_drift,
            _marker: PhantomData,
        })
    }

    /// Return current trusted finalized header.
    pub fn trusted_finalized(&self) -> Result<TrustedHeader<H>, LightClientError> {
        self.storage
            .get_trusted_finalized()?
            .ok_or(LightClientError::NotFound)
    }

    /// Verify and import a new header with its finality proof.
    /// Rules:
    /// - header.parent must exist or equal current trusted header (no gaps).
    /// - proof must finalize exactly this header under the current validator set.
    /// - height must be strictly greater than the currently trusted finalized height.
    pub fn verify_and_update(
        &self,
        header: H,
        proof: impl FinalityProof,
        now: SystemTime,
    ) -> Result<TrustedHeader<H>, LightClientError> {
        let current = self.trusted_finalized()?;
        // Reject stale or far-future timestamps.
        let hdr_ts = SystemTime::UNIX_EPOCH + Duration::from_secs(header.timestamp());
        if hdr_ts > now + self.max_time_drift || hdr_ts + self.max_time_drift < now {
            return Err(LightClientError::TimeDrift);
        }

        // Parent sanity
        if header.height() <= current.header.height() {
            return Err(LightClientError::NonMonotonic {
                header_height: header.height(),
                finalized_height: current.header.height(),
            });
        }
        // Ensure parent known and matches link.
        match self.storage.get_header(&header.parent_hash())? {
            Some(parent) => {
                if parent.hash() != header.parent_hash() {
                    return Err(LightClientError::ParentMismatch);
                }
            }
            None => {
                // Allow linking to current finalized header (fast path).
                if current.header.hash() != header.parent_hash() {
                    return Err(LightClientError::UnknownParent);
                }
            }
        }

        // Persist candidate header before proof (useful for future parents).
        self.storage.put_header(&header)?;

        // Finality verification under current validator set.
        if proof.target_height() != header.height() || proof.target_hash() != header.hash() {
            return Err(LightClientError::FinalityVerification(
                "proof target does not match header".into(),
            ));
        }

        if let Some(next_set) = proof.next_validator_set() {
            // Verify transition (if your protocol rotates validators).
            self.verifier
                .verify_next_set(&proof, &current.validator_set, &next_set)
                .map_err(LightClientError::FinalityVerification)?;
            // Accept and update to new set after successful verification.
            let new_trusted = TrustedHeader {
                header: header.clone(),
                finalized_at: now,
                validator_set: next_set,
            };
            self.storage.put_trusted_finalized(&new_trusted)?;
            Ok(new_trusted)
        } else {
            // Verify under the same set.
            self.verifier
                .verify(&proof, &current.validator_set)
                .map_err(LightClientError::FinalityVerification)?;
            let new_trusted = TrustedHeader {
                header: header.clone(),
                finalized_at: now,
                validator_set: current.validator_set.clone(),
            };
            self.storage.put_trusted_finalized(&new_trusted)?;
            Ok(new_trusted)
        }
    }

    /// Verify a Merkle membership proof against a header commitment.
    /// `root_selector`: chooses which root to verify against (state_root or receipts_root).
    pub fn verify_membership_proof(
        &self,
        header_hash: &[u8],
        proof: &MerkleProof,
        root_selector: RootSelector,
    ) -> Result<(), LightClientError> {
        let header = self
            .storage
            .get_header(header_hash)?
            .ok_or(LightClientError::NotFound)?;

        let expected_root = match root_selector {
            RootSelector::State => header.state_root(),
            RootSelector::Receipts => header.receipts_root(),
        };

        if expected_root != proof.expected_root {
            return Err(LightClientError::HashMismatch);
        }

        let mut acc = HF::hash_leaf(&proof.leaf);
        for item in &proof.items {
            acc = if item.is_left {
                HF::hash_nodes(&item.sibling, &acc)
            } else {
                HF::hash_nodes(&acc, &item.sibling)
            };
        }

        if acc == expected_root {
            Ok(())
        } else {
            Err(LightClientError::InvalidMerkleProof)
        }
    }

    /// Prune headers below a given height (retain safety margin if desired).
    pub fn prune_below(&self, height: Height) -> Result<(), LightClientError> {
        self.storage.prune_below(height)
    }
}

/// Which root to verify a proof against.
#[derive(Clone, Copy, Debug)]
pub enum RootSelector {
    State,
    Receipts,
}

/// -------------------------------------------------------------------------------------
/// In-memory storage (reference implementation)
/// -------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct MemoryStorage<H: Header> {
    by_hash: std::sync::Arc<std::sync::RwLock<BTreeMap<Bytes, H>>>,
    trusted: std::sync::Arc<std::sync::RwLock<Option<TrustedHeader<H>>>>,
}

impl<H: Header> Default for MemoryStorage<H> {
    fn default() -> Self {
        Self {
            by_hash: Default::default(),
            trusted: Default::default(),
        }
    }
}

impl<H: Header> StorageAdapter<H> for MemoryStorage<H> {
    fn get_trusted_finalized(&self) -> Result<Option<TrustedHeader<H>>, LightClientError> {
        Ok(self.trusted.read().unwrap().clone())
    }

    fn put_trusted_finalized(&self, header: &TrustedHeader<H>) -> Result<(), LightClientError> {
        *self.trusted.write().unwrap() = Some(header.clone());
        Ok(())
    }

    fn get_header(&self, hash: &[u8]) -> Result<Option<H>, LightClientError> {
        Ok(self.by_hash.read().unwrap().get(hash).cloned())
    }

    fn put_header(&self, header: &H) -> Result<(), LightClientError> {
        self.by_hash
            .write()
            .unwrap()
            .insert(header.hash(), header.clone());
        Ok(())
    }

    fn prune_below(&self, height: Height) -> Result<(), LightClientError> {
        let mut map = self.by_hash.write().unwrap();
        let to_remove: Vec<Bytes> = map
            .iter()
            .filter_map(|(k, v)| if v.height() < height { Some(k.clone()) } else { None })
            .collect();
        for k in to_remove {
            map.remove(&k);
        }
        Ok(())
    }
}

/// -------------------------------------------------------------------------------------
/// Test scaffolding (mocks for Header/HashFn/FinalityVerifier)
/// -------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Simple HashFn mock: SHA-256 via sha2 crate for determinism.
    #[derive(Clone)]
    struct Sha2;
    impl HashFn for Sha2 {
        fn hash_leaf(data: &[u8]) -> Bytes {
            use sha2::{Digest, Sha256};
            Sha256::digest([b"L", data].concat()).to_vec()
        }
        fn hash_nodes(left: &[u8], right: &[u8]) -> Bytes {
            use sha2::{Digest, Sha256};
            Sha256::digest([b"I", left, right].concat()).to_vec()
        }
    }

    // Mock header
    #[derive(Clone)]
    struct MockHeader {
        hash: Bytes,
        parent: Bytes,
        height: Height,
        state_root: Bytes,
        receipts_root: Bytes,
        ts: u64,
    }
    impl Header for MockHeader {
        fn hash(&self) -> Bytes {
            self.hash.clone()
        }
        fn parent_hash(&self) -> Bytes {
            self.parent.clone()
        }
        fn height(&self) -> Height {
            self.height
        }
        fn state_root(&self) -> Bytes {
            self.state_root.clone()
        }
        fn receipts_root(&self) -> Bytes {
            self.receipts_root.clone()
        }
        fn timestamp(&self) -> u64 {
            self.ts
        }
    }

    // Simple finality proof and verifier that trusts any target signed by "digest"
    #[derive(Clone)]
    struct MockProof {
        target_h: Height,
        target_hash: Bytes,
        next: Option<ValidatorSetDigest>,
    }
    impl FinalityProof for MockProof {
        fn target_height(&self) -> Height {
            self.target_h
        }
        fn target_hash(&self) -> Bytes {
            self.target_hash.clone()
        }
        fn next_validator_set(&self) -> Option<ValidatorSetDigest> {
            self.next.clone()
        }
    }

    #[derive(Clone)]
    struct MockVerifier;
    impl FinalityVerifier for MockVerifier {
        fn verify(&self, _proof: &impl FinalityProof, _set: &ValidatorSetDigest) -> Result<(), String> {
            Ok(())
        }
        fn verify_next_set(
            &self,
            _proof: &impl FinalityProof,
            _current_set: &ValidatorSetDigest,
            _next_set: &ValidatorSetDigest,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn make_header(parent: &[u8], height: Height, ts: u64) -> MockHeader {
        let mut data = vec![];
        data.extend_from_slice(parent);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&ts.to_le_bytes());
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&data).to_vec()
        };
        MockHeader {
            hash,
            parent: parent.to_vec(),
            height,
            state_root: vec![1; 32],
            receipts_root: vec![2; 32],
            ts,
        }
    }

    #[test]
    fn init_and_update_finality() {
        let storage = MemoryStorage::<MockHeader>::default();
        let verifier = MockVerifier;
        let hash_fn = Sha2;

        let genesis = make_header(&[], 0, 1_700_000_000);
        let cp = Checkpoint {
            trusted_header: genesis.clone(),
            validator_set: ValidatorSetDigest(vec![7; 32]),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100),
            max_time_drift: Duration::from_secs(3600),
        };

        let client = super::LightClient::init_with_checkpoint(storage.clone(), hash_fn, verifier, cp).unwrap();
        let cur = client.trusted_finalized().unwrap();
        assert_eq!(cur.header.height(), 0);

        let h1 = make_header(&genesis.hash(), 1, 1_700_000_200);
        let proof = MockProof {
            target_h: 1,
            target_hash: h1.hash(),
            next: None,
        };
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_210);
        let updated = client.verify_and_update(h1.clone(), proof, now).unwrap();
        assert_eq!(updated.header.height(), 1);
        let cur2 = client.trusted_finalized().unwrap();
        assert_eq!(cur2.header.hash(), h1.hash());
    }

    #[test]
    fn reject_non_monotonic() {
        let storage = MemoryStorage::<MockHeader>::default();
        let verifier = MockVerifier;
        let hash_fn = Sha2;

        let g = make_header(&[], 0, 1_700_000_000);
        let cp = Checkpoint {
            trusted_header: g.clone(),
            validator_set: ValidatorSetDigest(vec![7; 32]),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            max_time_drift: Duration::from_secs(3600),
        };
        let client = super::LightClient::init_with_checkpoint(storage.clone(), hash_fn, verifier, cp).unwrap();

        let stale = make_header(&[], 0, 1_700_000_000);
        let p = MockProof { target_h: 0, target_hash: stale.hash(), next: None };
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_010);
        let err = client.verify_and_update(stale, p, now).unwrap_err();
        matches!(err, LightClientError::NonMonotonic { .. });
    }

    #[test]
    fn merkle_proof_ok() {
        let storage = MemoryStorage::<MockHeader>::default();
        let verifier = MockVerifier;
        let hash_fn = Sha2;
        let g = make_header(&[], 0, 1_700_000_000);
        let cp = Checkpoint {
            trusted_header: g.clone(),
            validator_set: ValidatorSetDigest(vec![7; 32]),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            max_time_drift: Duration::from_secs(3600),
        };
        let client = super::LightClient::init_with_checkpoint(storage.clone(), hash_fn.clone(), verifier, cp).unwrap();

        // Build a tiny tree of two leaves: leaf0 and leaf1.
        let leaf0 = Sha2::hash_leaf(b"event-0");
        let leaf1 = Sha2::hash_leaf(b"event-1");
        let root = Sha2::hash_nodes(&leaf0, &leaf1);

        // Fake a header that commits to receipts_root = root.
        let mut h1 = make_header(&g.hash(), 1, 1_700_000_100);
        h1.receipts_root = root.clone();
        storage.put_header(&h1).unwrap();

        // Prove membership of "event-1".
        let proof = MerkleProof {
            items: vec![MerkleProofItem { sibling: leaf0.clone(), is_left: true }],
            leaf: b"event-1".to_vec(),
            expected_root: root.clone(),
        };

        client
            .verify_membership_proof(&h1.hash(), &proof, RootSelector::Receipts)
            .unwrap();
    }

    #[test]
    fn merkle_proof_fail() {
        let storage = MemoryStorage::<MockHeader>::default();
        let verifier = MockVerifier;
        let hash_fn = Sha2;
        let g = make_header(&[], 0, 1_700_000_000);
        let cp = Checkpoint {
            trusted_header: g.clone(),
            validator_set: ValidatorSetDigest(vec![7; 32]),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            max_time_drift: Duration::from_secs(3600),
        };
        let client = super::LightClient::init_with_checkpoint(storage.clone(), hash_fn.clone(), verifier, cp).unwrap();

        let leaf0 = Sha2::hash_leaf(b"event-0");
        let leaf1 = Sha2::hash_leaf(b"event-1");
        let wrong_root = Sha2::hash_nodes(&leaf1, &leaf0); // swapped

        let mut h1 = make_header(&g.hash(), 1, 1_700_000_100);
        h1.receipts_root = wrong_root.clone();
        storage.put_header(&h1).unwrap();

        let proof = MerkleProof {
            items: vec![MerkleProofItem { sibling: leaf0.clone(), is_left: true }],
            leaf: b"event-1".to_vec(),
            expected_root: wrong_root.clone(),
        };

        let err = client
            .verify_membership_proof(&h1.hash(), &proof, RootSelector::Receipts)
            .unwrap_err();
        matches!(err, LightClientError::InvalidMerkleProof);
    }
}

/// -------------------------------------------------------------------------------------
/// External deps used:
/// - thiserror = "1"
/// - hex = "0.4"
/// - sha2 = "0.10" (tests)
/// Add to Cargo.toml of the node crate accordingly.
/// -------------------------------------------------------------------------------------

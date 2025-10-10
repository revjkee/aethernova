//! Merkle proofs for bridge relayer.
//!
//! Industrial features:
//! - Binary Merkle tree with two odd-node policies:
//!     * RFC6962-like (promote lone node to next level).
//!     * Bitcoin-like (duplicate last node).
//! - Domain separation (leaf=0x00, node=0x01) per RFC 6962 to prevent
//!   second-preimage confusions between leaves and interior nodes.
//! - Generic over any hash implementing `digest::Digest` (default: SHA-256).
//! - Inclusion proof generation & verification with explicit left/right steps.
//! - Deterministic roots; zero-copy-friendly APIs; serde for proofs; tests.
//!
//! Security rationale:
//! - RFC 6962 defines Merkle Tree Hash with domain-separated leaf/node prefixes,
//!   and audit paths (proofs) as minimal набор братьев по пути к корню. We follow it
//!   when `OddPolicy::Promote`. Bitcoin-style duplication is available via `OddPolicy::Duplicate`.
//!
//! Default hash: SHA-256 (FIPS 180-4) via `sha2::Sha256`. You can switch to Keccak/BLAKE2/BLAKE3
//! by plugging another `Digest` implementor if required by a target chain.
//!
//! References:
//! - RFC 6962 (Merkle Tree Hash, audit paths, 0x00/0x01 prefixes). 
//! - Bitcoin dev guide note on duplicating last hash in unbalanced trees.
//! - RustCrypto `digest::Digest` trait and `sha2` crate.
//!
//! See citations in module-level docs/comments and project documentation.

use core::fmt;
use serde::{Deserialize, Serialize};

use digest::Digest;

/// Default hash function (can be replaced in type params).
pub type DefaultHash = sha2::Sha256;

/// Policy for handling an odd number of nodes at a level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OddPolicy {
    /// RFC 6962–style: a lone node is promoted to the next level unchanged.
    Promote,
    /// Bitcoin-style: duplicate the last node and hash [last || last].
    Duplicate,
}

/// Merkle options controlling hashing and layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleOptions {
    /// Domain-separate leaves and internal nodes by prefixes.
    /// RFC 6962 uses 0x00 for leaves and 0x01 for interior nodes.
    pub domain_separation: bool,
    pub leaf_prefix: u8,
    pub node_prefix: u8,
    pub odd_policy: OddPolicy,
}

impl Default for MerkleOptions {
    fn default() -> Self {
        MerkleOptions {
            domain_separation: true,
            leaf_prefix: 0x00,
            node_prefix: 0x01,
            odd_policy: OddPolicy::Promote, // RFC 6962-style
        }
    }
}

/// Which side the sibling was on relative to the running hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiblingSide {
    Left,
    Right,
}

/// One step in a Merkle inclusion proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling: Vec<u8>,
    pub side: SiblingSide,
}

impl fmt::Debug for ProofStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = match self.side { SiblingSide::Left => "L", SiblingSide::Right => "R" };
        write!(f, "Step{{side:{}, sibling:0x{}}}", side, hex::encode(&self.sibling))
    }
}

/// Inclusion proof (audit path) from a leaf to the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: Vec<u8>,         // original leaf data (unhashed)
    pub steps: Vec<ProofStep>, // siblings upwards; promoted nodes simply have no step
    pub options: MerkleOptions,
}

impl MerkleProof {
    /// Verify this proof against the expected root using hash `H`.
    pub fn verify_with<H: Digest + Default + Clone>(&self, expected_root: &[u8]) -> bool {
        let mut acc = hash_leaf::<H>(&self.leaf, self.options);
        for step in &self.steps {
            acc = match step.side {
                SiblingSide::Left  => hash_node::<H>(&step.sibling, &acc, self.options),
                SiblingSide::Right => hash_node::<H>(&acc, &step.sibling, self.options),
            };
        }
        acc == expected_root
    }

    /// Convenience over the default hash.
    pub fn verify(&self, expected_root: &[u8]) -> bool {
        self.verify_with::<DefaultHash>(expected_root)
    }
}

/// Merkle root (and proofs) builder.
/// Stores per-level nodes to allow proof extraction by index.
pub struct MerkleTree {
    levels: Vec<Vec<Vec<u8>>>, // levels[0] = hashed leaves; last = root layer
    opts: MerkleOptions,
}

impl MerkleTree {
    /// Build a tree from raw leaves (unhashed data).
    pub fn build<H: Digest + Default + Clone>(leaves: &[impl AsRef<[u8]>], opts: MerkleOptions) -> Self {
        // Hash leaves with domain separation as needed.
        let mut level: Vec<Vec<u8>> = leaves.iter()
            .map(|d| hash_leaf::<H>(d.as_ref(), opts))
            .collect();

        let mut levels = vec![level.clone()];
        while level.len() > 1 {
            level = next_level::<H>(&level, opts);
            levels.push(level.clone());
        }
        Self { levels, opts }
    }

    /// Root bytes. For empty set, returns hash of empty leaf per RFC 6962 style when domain separation enabled.
    pub fn root(&self) -> Vec<u8> {
        self.levels.last().map(|v| v[0].clone()).unwrap_or_else(|| {
            // Empty tree root: hash of empty input as a leaf (consistent with RFC-6962 style constructions).
            hash_leaf::<DefaultHash>(&[], self.opts)
        })
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    /// Generate inclusion proof for leaf at `index` (0-based) using original raw leaf data.
    pub fn prove<H: Digest + Default + Clone>(&self, index: usize, leaf_raw: &[u8]) -> Option<MerkleProof> {
        if self.leaf_count() == 0 || index >= self.leaf_count() {
            return None;
        }
        let mut idx = index;
        let mut steps: Vec<ProofStep> = Vec::new();

        // Walk through levels from leaves up to (but not including) the top.
        for lvl in 0..self.levels.len() - 1 {
            let layer = &self.levels[lvl];
            let is_last_odd = layer.len() % 2 == 1;
            let pair_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            match (idx % 2, is_last_odd, self.opts.odd_policy) {
                // Right sibling exists -> add step
                (0, _, _) if pair_idx < layer.len() => {
                    steps.push(ProofStep {
                        sibling: layer[pair_idx].clone(),
                        side: SiblingSide::Right,
                    });
                }
                (1, _, _) => {
                    steps.push(ProofStep {
                        sibling: layer[pair_idx].clone(),
                        side: SiblingSide::Left,
                    });
                }
                // Lone last node (even index at end) and RFC-style promotion -> no step added.
                (0, true, OddPolicy::Promote) if pair_idx >= layer.len() => { /* promoted, nothing */ }
                // Lone last node and Bitcoin-style duplication -> sibling == self.
                (0, true, OddPolicy::Duplicate) if pair_idx >= layer.len() => {
                    steps.push(ProofStep {
                        sibling: layer[idx].clone(),
                        side: SiblingSide::Right,
                    });
                }
                _ => {}
            }

            // Move to parent index.
            idx /= 2;
        }

        Some(MerkleProof {
            leaf: leaf_raw.to_vec(),
            steps,
            options: self.opts,
        })
    }
}

/* ------------------------------ helpers ------------------------------ */

#[inline]
fn hash_leaf<H: Digest + Default + Clone>(data: &[u8], opts: MerkleOptions) -> Vec<u8> {
    let mut hasher = H::new();
    if opts.domain_separation {
        hasher.update([opts.leaf_prefix]);
    }
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[inline]
fn hash_node<H: Digest + Default + Clone>(left: &[u8], right: &[u8], opts: MerkleOptions) -> Vec<u8> {
    let mut hasher = H::new();
    if opts.domain_separation {
        hasher.update([opts.node_prefix]);
    }
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

fn next_level<H: Digest + Default + Clone>(nodes: &[Vec<u8>], opts: MerkleOptions) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0usize;
    while i < nodes.len() {
        if i + 1 < nodes.len() {
            out.push(hash_node::<H>(&nodes[i], &nodes[i + 1], opts));
            i += 2;
        } else {
            match opts.odd_policy {
                OddPolicy::Promote => {
                    // Promote the lone node unchanged to next level
                    out.push(nodes[i].clone());
                    i += 1;
                }
                OddPolicy::Duplicate => {
                    out.push(hash_node::<H>(&nodes[i], &nodes[i], opts));
                    i += 1;
                }
            }
        }
    }
    out
}

/* -------------------------------- tests -------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn opts_rfc() -> MerkleOptions {
        MerkleOptions { domain_separation: true, leaf_prefix: 0x00, node_prefix: 0x01, odd_policy: OddPolicy::Promote }
    }
    fn opts_btc() -> MerkleOptions {
        MerkleOptions { odd_policy: OddPolicy::Duplicate, ..Default::default() }
    }

    #[test]
    fn empty_tree_root_is_hash_of_empty_leaf() {
        // Root should be H(0x00 || "")
        let root = MerkleTree { levels: vec![], opts: opts_rfc() }.root();
        let expected = {
            let mut h = DefaultHash::new();
            h.update([0x00u8]);
            h.finalize().to_vec()
        };
        assert_eq!(root, expected);
    }

    #[test]
    fn single_leaf() {
        let leaves = [b"leaf0".as_ref()];
        let tree = MerkleTree::build::<DefaultHash>(&leaves, opts_rfc());
        assert_eq!(tree.leaf_count(), 1);
        let proof = tree.prove::<DefaultHash>(0, leaves[0]).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn rfc_promote_three_leaves() {
        let leaves = [b"a".as_ref(), b"b".as_ref(), b"c".as_ref()];
        let tree = MerkleTree::build::<DefaultHash>(&leaves, opts_rfc());
        for (i, l) in leaves.iter().enumerate() {
            let p = tree.prove::<DefaultHash>(i, l).unwrap();
            assert!(p.verify(&tree.root()));
        }
    }

    #[test]
    fn bitcoin_duplicate_three_leaves() {
        let leaves = [b"a".as_ref(), b"b".as_ref(), b"c".as_ref()];
        let tree = MerkleTree::build::<DefaultHash>(&leaves, opts_btc());
        for (i, l) in leaves.iter().enumerate() {
            let p = tree.prove::<DefaultHash>(i, l).unwrap();
            assert!(p.verify(&tree.root()));
        }
    }

    #[test]
    fn proof_contains_orientation() {
        let leaves = [b"L0".as_ref(), b"L1".as_ref(), b"L2".as_ref(), b"L3".as_ref()];
        let tree = MerkleTree::build::<DefaultHash>(&leaves, opts_rfc());
        let proof = tree.prove::<DefaultHash>(1, leaves[1]).unwrap();
        // First step must have a left sibling for index=1 (pair with index 0)
        assert_eq!(proof.steps.first().unwrap().side, SiblingSide::Left);
        assert!(proof.verify(&tree.root()));
    }
}

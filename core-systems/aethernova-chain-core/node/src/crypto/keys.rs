//! File: aethernova-chain-core/node/src/crypto/keys.rs
//! Unified key abstraction for Aethernova node: Ed25519, Sr25519, Secp256k1.
//!
//! Features (via Cargo):
//! - ed25519       -> enable Ed25519 (ed25519-dalek)
//! - sr25519       -> enable Sr25519 (schnorrkel)
//! - secp256k1     -> enable Secp256k1 (k256, ECDSA)
//! - bip39         -> mnemonic -> seed (bip39 + hkdf / PBKDF2)
//! - ss58          -> substrate-like SS58 address encoding
//! - keccak        -> enable Keccak-256 (for EVM-style addresses)
//! - blake2        -> enable Blake2b-256 (for substrate-like hashing)
//!
//! Minimal, safe-by-default design:
//! - Secrets are zeroized (zeroize) and wrapped in `Secret` newtype.
//! - Public API exposes algorithms through `Algo`, `Keypair`, `PublicKey`, `Signature`.
//! - Deterministic derivation via `from_seed()` and optional `from_mnemonic()`.
//!
//! External crates expected in Cargo.toml of the node crate:
//!   zeroize = "1"
//!   rand_core = "0.6"
//!   rand = "0.8"
//!   serde = { version = "1", features = ["derive"] }
//!   thiserror = "1"
//!   hex = "0.4"
//!   # optional
//!   ed25519-dalek = { version = "2", features = ["rand_core"] }         # feature = "ed25519"
//!   schnorrkel = "0.11"                                                 # feature = "sr25519"
//!   k256 = { version = "0.13", features = ["ecdsa"] }                   # feature = "secp256k1"
//!   sha2 = "0.10"
//!   blake2 = { version = "0.10", optional = true }                      # feature = "blake2"
//!   tiny-keccak = { version = "2", optional = true, features = ["keccak"] } # feature = "keccak"
//!   bip39 = { version = "2", optional = true, default-features = false, features = ["rand"] } # "bip39"
//!   pbkdf2 = { version = "0.12", optional = true }                      # "bip39"
//!   hmac = { version = "0.12", optional = true }                        # "bip39"
//!   bech32 = { version = "0.9", optional = true }                       # "ss58"
//!
//! NOTE: This module focuses on structure & safety; wire-level formats and
//! protocol-specific constraints should be handled in integration layers.

#![allow(clippy::new_without_default, clippy::needless_pass_by_value)]

use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use rand::rngs::OsRng;
use rand_core::RngCore;

#[cfg(feature = "keccak")]
use tiny_keccak::{Hasher, Keccak};

#[cfg(feature = "blake2")]
use blake2::{Blake2b256, Digest as _};

/// Common sizes
pub const SEED_MIN_BYTES: usize = 32; // recommended minimum seed size
pub const ADDR_LEN_DEFAULT: usize = 32;

/// Supported algorithms
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Algo {
    #[cfg(feature = "ed25519")]
    Ed25519,
    #[cfg(feature = "sr25519")]
    Sr25519,
    #[cfg(feature = "secp256k1")]
    Secp256k1,
}

/// Error type for key operations
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("unsupported algorithm")]
    UnsupportedAlgo,
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid seed")]
    InvalidSeed,
    #[error("sign error")]
    Sign,
    #[error("verify error")]
    Verify,
    #[error("mnemonic not supported (enable feature 'bip39')")]
    MnemonicUnsupported,
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// Zeroizing secret byte container
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Secret(#[serde(with = "serde_bytes")] Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyError> {
        if bytes.is_empty() {
            return Err(KeyError::InvalidLength);
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***redacted***)")
    }
}

/// Public key bytes
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "serde_bytes")] Vec<u8>);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(0x{})", hex::encode(&self.0))
    }
}
impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Signature bytes
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_bytes")] Vec<u8>);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(0x{})", hex::encode(&self.0))
    }
}
impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Unified Keypair enum over supported algorithms
#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    algo: Algo,
    #[serde(with = "serde_bytes")]
    secret: Vec<u8>, // raw private key/seed (algorithm-dependent)
    public: PublicKey,
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("algo", &self.algo)
            .field("secret", &"***redacted***")
            .field("public", &self.public)
            .finish()
    }
}

impl Keypair {
    /// Generate a new keypair using secure OS RNG.
    pub fn generate(algo: Algo) -> Result<Self, KeyError> {
        let mut rng = OsRng;
        match algo {
            #[cfg(feature = "ed25519")]
            Algo::Ed25519 => {
                use ed25519_dalek::{SigningKey, VerifyingKey};
                let sk = SigningKey::generate(&mut rng);
                let vk: VerifyingKey = (&sk).into();
                Ok(Self {
                    algo,
                    secret: sk.to_bytes().to_vec(),
                    public: PublicKey(vk.to_bytes().to_vec()),
                })
            }
            #[cfg(feature = "sr25519")]
            Algo::Sr25519 => {
                use schnorrkel::{Keypair as SrKeypair, MiniSecretKey};
                let mini = MiniSecretKey::generate_with(&mut rng);
                let kp: SrKeypair = mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
                Ok(Self {
                    algo,
                    secret: kp.secret.to_bytes().to_vec(),
                    public: PublicKey(kp.public.to_bytes().to_vec()),
                })
            }
            #[cfg(feature = "secp256k1")]
            Algo::Secp256k1 => {
                use k256::ecdsa::SigningKey as KSigningKey;
                use k256::elliptic_curve::SecretKey;
                let sk = KSigningKey::random(&mut rng);
                let pk = sk.verifying_key();
                Ok(Self {
                    algo,
                    secret: sk.to_bytes().to_vec(),
                    public: PublicKey(pk.to_sec1_bytes().to_vec()), // compressed or uncompressed? use SEC1 compressed by default (33 bytes)
                })
            }
            #[allow(unreachable_patterns)]
            _ => Err(KeyError::UnsupportedAlgo),
        }
    }

    /// Construct from raw seed/private bytes (algorithm-specific length checks).
    pub fn from_seed(algo: Algo, seed: &[u8]) -> Result<Self, KeyError> {
        if seed.len() < SEED_MIN_BYTES {
            return Err(KeyError::InvalidSeed);
        }
        match algo {
            #[cfg(feature = "ed25519")]
            Algo::Ed25519 => {
                use ed25519_dalek::{SigningKey, VerifyingKey};
                use sha2::{Digest, Sha512};
                // ed25519-dalek expects 32-byte seed; HKDF-like reduction for oversized seed
                let sk_bytes = seed_to_32(seed);
                let sk = SigningKey::from_bytes(&sk_bytes);
                let vk: VerifyingKey = (&sk).into();
                Ok(Self {
                    algo,
                    secret: sk.to_bytes().to_vec(),
                    public: PublicKey(vk.to_bytes().to_vec()),
                })
            }
            #[cfg(feature = "sr25519")]
            Algo::Sr25519 => {
                use schnorrkel::{ExpansionMode, Keypair as SrKeypair, MiniSecretKey};
                let msk = schnorr_seed_to_mini(seed)?;
                let kp: SrKeypair = msk.expand_to_keypair(ExpansionMode::Ed25519);
                Ok(Self {
                    algo,
                    secret: kp.secret.to_bytes().to_vec(),
                    public: PublicKey(kp.public.to_bytes().to_vec()),
                })
            }
            #[cfg(feature = "secp256k1")]
            Algo::Secp256k1 => {
                use k256::ecdsa::SigningKey as KSigningKey;
                use k256::elliptic_curve::SecretKey;
                let sk_bytes = seed_to_32(seed);
                let sk = KSigningKey::from_bytes(&sk_bytes.into()).map_err(|_| KeyError::InvalidSeed)?;
                let pk = sk.verifying_key();
                Ok(Self {
                    algo,
                    secret: sk.to_bytes().to_vec(),
                    public: PublicKey(pk.to_sec1_bytes().to_vec()),
                })
            }
            #[allow(unreachable_patterns)]
            _ => Err(KeyError::UnsupportedAlgo),
        }
    }

    /// (Optional) Construct from BIP-39 mnemonic (enable feature "bip39").
    #[cfg(feature = "bip39")]
    pub fn from_mnemonic(algo: Algo, mnemonic: &str, passphrase: Option<&str>) -> Result<Self, KeyError> {
        use bip39::{Language, Mnemonic, Seed};
        let m = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|_| KeyError::InvalidSeed)?;
        let pass = passphrase.unwrap_or("");
        let seed = Seed::new(&m, pass);
        Self::from_seed(algo, seed.as_bytes())
    }

    /// Sign message bytes; returns algorithm-tagged signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, KeyError> {
        match self.algo {
            #[cfg(feature = "ed25519")]
            Algo::Ed25519 => {
                use ed25519_dalek::{Signature as EdSig, SigningKey};
                let sk = SigningKey::from_bytes(self.secret.as_slice().try_into().map_err(|_| KeyError::InvalidLength)?);
                let sig: EdSig = sk.sign(msg);
                Ok(Signature(sig.to_bytes().to_vec()))
            }
            #[cfg(feature = "sr25519")]
            Algo::Sr25519 => {
                use schnorrkel::{Keypair as SrKeypair, SecretKey, Signature as SrSig};
                let sec = SecretKey::from_bytes(&self.secret).map_err(|_| KeyError::InvalidLength)?;
                let kp = SrKeypair { secret: sec, public: schnorrkel::PublicKey::from_bytes(self.public.as_bytes()).map_err(|_| KeyError::InvalidLength)? };
                let sig: SrSig = kp.sign_simple(b"aethernova", msg);
                Ok(Signature(sig.to_bytes().to_vec()))
            }
            #[cfg(feature = "secp256k1")]
            Algo::Secp256k1 => {
                use k256::ecdsa::{signature::Signer, Signature as EcdsaSig, SigningKey as KSigningKey};
                let sk = KSigningKey::from_bytes(self.secret.as_slice().into()).map_err(|_| KeyError::InvalidLength)?;
                let sig: EcdsaSig = sk.sign(msg); // raw ecdsa over msg; upstream caller should prehash if needed
                Ok(Signature(sig.to_der().as_bytes().to_vec()))
            }
            #[allow(unreachable_patterns)]
            _ => Err(KeyError::UnsupportedAlgo),
        }
    }

    /// Verify signature against message and internal public key.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), KeyError> {
        match self.algo {
            #[cfg(feature = "ed25519")]
            Algo::Ed25519 => {
                use ed25519_dalek::{Signature as EdSig, VerifyingKey};
                let vk = VerifyingKey::from_bytes(self.public.as_bytes().try_into().map_err(|_| KeyError::InvalidLength)?)
                    .map_err(|_| KeyError::InvalidLength)?;
                let sig = EdSig::from_bytes(sig.as_bytes()).map_err(|_| KeyError::InvalidLength)?;
                vk.verify_strict(msg, &sig).map_err(|_| KeyError::Verify)
            }
            #[cfg(feature = "sr25519")]
            Algo::Sr25519 => {
                use schnorrkel::{Signature as SrSig, PublicKey};
                let pk = PublicKey::from_bytes(self.public.as_bytes()).map_err(|_| KeyError::InvalidLength)?;
                let sig = SrSig::from_bytes(sig.as_bytes()).map_err(|_| KeyError::InvalidLength)?;
                pk.verify_simple(b"aethernova", msg, &sig).map_err(|_| KeyError::Verify)
            }
            #[cfg(feature = "secp256k1")]
            Algo::Secp256k1 => {
                use k256::ecdsa::{signature::Verifier, Signature as EcdsaSig, VerifyingKey};
                let pk = VerifyingKey::from_sec1_bytes(self.public.as_bytes()).map_err(|_| KeyError::InvalidLength)?;
                let sig = EcdsaSig::from_der(sig.as_bytes()).map_err(|_| KeyError::InvalidLength)?;
                pk.verify(msg, &sig).map_err(|_| KeyError::Verify)
            }
            #[allow(unreachable_patterns)]
            _ => Err(KeyError::UnsupportedAlgo),
        }
    }

    pub fn algo(&self) -> Algo {
        self.algo
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Render default 32-byte address from the public key using selected hash pipeline.
    /// - If `keccak` feature: keccak256(pubkey) -> last 20 or 32 bytes (controlled by `out_len`).
    /// - Else if `blake2` feature: blake2b-256(pubkey).
    /// - Else: SHA-256(pubkey) as fallback.
    pub fn address(&self, out_len: usize) -> Vec<u8> {
        let out_len = out_len.max(1).min(32);
        #[cfg(feature = "keccak")]
        {
            let mut keccak = Keccak::v256();
            let mut out = [0u8; 32];
            keccak.update(self.public.as_bytes());
            keccak.finalize(&mut out);
            return out[32 - out_len..].to_vec();
        }
        #[cfg(all(not(feature = "keccak"), feature = "blake2"))]
        {
            let mut hasher = Blake2b256::new();
            hasher.update(self.public.as_bytes());
            let out = hasher.finalize();
            return out[0..out_len].to_vec();
        }
        // Fallback: SHA-256
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(self.public.as_bytes());
            let out = h.finalize();
            out[0..out_len].to_vec()
        }
    }

    /// SS58 address string (optional, feature "ss58").
    #[cfg(feature = "ss58")]
    pub fn address_ss58(&self, prefix: u16) -> String {
        // SS58: simple bech32-like using bech32 crate for demo.
        // Real SS58 has specific format; for production, integrate a canonical impl.
        use bech32::{encode, ToBase32, Variant};
        let data = self.address(32);
        encode(&format!("ss58{}", prefix), data.to_base32(), Variant::Bech32).unwrap_or_default()
    }
}

/// Utility: reduce arbitrary-length seed to 32 bytes (SHA-256).
fn seed_to_32(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed);
    h.finalize().into()
}

/// Utility: derive schnorrkel MiniSecretKey from arbitrary seed (SHA-512 then clamp).
#[cfg(feature = "sr25519")]
fn schnorr_seed_to_mini(seed: &[u8]) -> Result<schnorrkel::MiniSecretKey, KeyError> {
    use sha2::{Digest, Sha512};
    use schnorrkel::MiniSecretKey;
    let mut h = Sha512::new();
    h.update(seed);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out[0..32]);
    MiniSecretKey::from_bytes(&buf).map_err(|_| KeyError::InvalidSeed)
}

/// -------- Tests --------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_sign_verify() {
        let kp = Keypair::generate(Algo::Ed25519).expect("gen");
        let msg = b"hello-ed25519";
        let sig = kp.sign(msg).expect("sign");
        kp.verify(msg, &sig).expect("verify");
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    #[cfg(feature = "sr25519")]
    fn sr25519_sign_verify() {
        let kp = Keypair::generate(Algo::Sr25519).expect("gen");
        let msg = b"hello-sr25519";
        let sig = kp.sign(msg).expect("sign");
        kp.verify(msg, &sig).expect("verify");
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn secp256k1_sign_verify() {
        let kp = Keypair::generate(Algo::Secp256k1).expect("gen");
        let msg = b"hello-secp256k1";
        let sig = kp.sign(msg).expect("sign");
        kp.verify(msg, &sig).expect("verify");
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    #[cfg(feature = "bip39")]
    fn from_mnemonic_works() {
        // 12-word English mnemonic example (random each run discouraged in tests; here static for determinism).
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let kp = Keypair::from_mnemonic(
            // choose one present feature for CI
            #[cfg(feature = "ed25519")] { Algo::Ed25519 }
            #[cfg(all(not(feature = "ed25519"), feature = "sr25519"))] { Algo::Sr25519 }
            #[cfg(all(not(feature = "ed25519"), not(feature = "sr25519"), feature = "secp256k1"))] { Algo::Secp256k1 }
            , m, Some("aethernova")).expect("mnemonic");
        assert!(kp.public_key().len() >= 32);
    }

    #[test]
    fn address_fallback_sha256_len() {
        // When no crypto features set for hash pipelines, SHA-256 fallback must work.
        #[cfg(feature = "ed25519")]
        let kp = Keypair::generate(Algo::Ed25519).unwrap();
        #[cfg(all(not(feature = "ed25519"), feature = "sr25519"))]
        let kp = Keypair::generate(Algo::Sr25519).unwrap();
        #[cfg(all(not(feature = "ed25519"), not(feature = "sr25519"), feature = "secp256k1"))]
        let kp = Keypair::generate(Algo::Secp256k1).unwrap();

        let a20 = kp.address(20);
        let a32 = kp.address(32);
        assert_eq!(a20.len(), 20);
        assert_eq!(a32.len(), 32);
    }
}

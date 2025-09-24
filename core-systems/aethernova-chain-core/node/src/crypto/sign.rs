//! Aethernova Crypto: Signing module
//!
//! Industrial-grade signing primitives with unified API over Ed25519 and secp256k1 (ECDSA).
//!
//! Features (toggle via Cargo features):
//! - "ed25519": enable Ed25519 (ed25519-dalek)
//! - "secp256k1": enable ECDSA over secp256k1 (k256)
//! - "keystore": enable encrypted keystore (scrypt + chacha20poly1305)
//! - "serde": enable serde Serialize/Deserialize for public types
//! - "bech32": enable Bech32 encoding helpers for addresses
//! - "sha3": enable Keccak-256 (preferred for address derivation); fallback to SHA-256 if disabled
//!
//! Notes:
//! - Domain separation via `SignContext` to avoid cross-protocol signature reuse.
//! - Message prehashing (SHA-256 by default, Keccak-256 if "sha3" enabled).
//! - Secrets are zeroized on drop.
//! - ECDSA signatures are emitted in DER; Ed25519 — raw 64 bytes.
//!
//! This module is self-contained; adjust Cargo.toml accordingly.

#![allow(clippy::result_large_err)]

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::OsRng;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "sha3")]
use sha3::{Digest as Sha3Digest, Keccak256};

use sha2::{Digest as Sha2Digest, Sha256};

#[cfg(feature = "bech32")]
use bech32::{self, ToBase32, Variant};

#[cfg(feature = "ed25519")]
use ed25519_dalek::{Signer as _, Verifier as _, SigningKey as Ed25519Secret, VerifyingKey as Ed25519Public};

#[cfg(feature = "secp256k1")]
use k256::{
    ecdsa::{
        signature::{Signer as _, Verifier as _},
        Signature as SecpSignatureDer, SigningKey as Secp256k1Secret, VerifyingKey as Secp256k1Public,
    },
    EncodedPoint,
};

#[cfg(feature = "keystore")]
use {
    chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key as AeadKey, Nonce},
    scrypt::{errors::InvalidParams, Params as ScryptParams, ScryptParamsBuilder},
    rand_core::RngCore,
};

use thiserror::Error;

/// Supported key kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyKind {
    #[cfg(feature = "ed25519")]
    Ed25519,
    #[cfg(feature = "secp256k1")]
    Secp256k1,
}

/// Uniquely identifies a key (20 bytes).
/// By default derived as the first 20 bytes of Keccak-256(pubkey) if "sha3" enabled,
/// otherwise first 20 bytes of SHA-256(pubkey).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyId(pub [u8; 20]);

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Address type (20 bytes); identical derivation to KeyId.
pub type Address = KeyId;

/// Domain separation context for signatures.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignContext {
    /// Human-readable domain, e.g. "AETHERNOVA-TX-V1".
    pub domain: &'static str,
    /// Optional chain or network id bytes.
    pub domain_tag: &'static [u8],
}

impl SignContext {
    pub const fn new(domain: &'static str, domain_tag: &'static [u8]) -> Self {
        Self { domain, domain_tag }
    }

    fn prehash(&self, message: &[u8]) -> [u8; 32] {
        // H = HASH( "AETHERNOVA|" + domain + "|" + domain_tag + "|" + message )
        let mut hasher = Sha256::new();
        hasher.update(b"AETHERNOVA|");
        hasher.update(self.domain.as_bytes());
        hasher.update(b"|");
        hasher.update(self.domain_tag);
        hasher.update(b"|");
        hasher.update(message);
        let out = hasher.finalize();

        let mut h = [0u8; 32];
        h.copy_from_slice(&out);
        h
    }
}

/// Signature container.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Signature {
    #[cfg(feature = "ed25519")]
    Ed25519([u8; 64]),
    #[cfg(feature = "secp256k1")]
    Secp256k1Der(Vec<u8>), // DER-encoded ECDSA signature
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "ed25519")]
            Signature::Ed25519(_) => write!(f, "Signature::Ed25519(64 bytes)"),
            #[cfg(feature = "secp256k1")]
            Signature::Secp256k1Der(v) => write!(f, "Signature::Secp256k1Der({} bytes)", v.len()),
        }
    }
}

/// Public key container.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PublicKey {
    #[cfg(feature = "ed25519")]
    Ed25519([u8; 32]),
    #[cfg(feature = "secp256k1")]
    Secp256k1Uncompressed([u8; 65]), // 0x04 || X(32) || Y(32)
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "ed25519")]
            PublicKey::Ed25519(_) => write!(f, "PublicKey::Ed25519(32 bytes)"),
            #[cfg(feature = "secp256k1")]
            PublicKey::Secp256k1Uncompressed(_) => write!(f, "PublicKey::Secp256k1Uncompressed(65 bytes)"),
        }
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "ed25519")]
            PublicKey::Ed25519(b) => b,
            #[cfg(feature = "secp256k1")]
            PublicKey::Secp256k1Uncompressed(b) => b,
        }
    }

    /// Derive address/id from public key.
    pub fn to_address(&self) -> Address {
        #[cfg(feature = "sha3")]
        {
            let mut hasher = Keccak256::new();
            hasher.update(self.as_bytes());
            let out = hasher.finalize();
            let mut id = [0u8; 20];
            id.copy_from_slice(&out[12..32]);
            Address(id)
        }
        #[cfg(not(feature = "sha3"))]
        {
            let mut hasher = Sha256::new();
            hasher.update(self.as_bytes());
            let out = hasher.finalize();
            let mut id = [0u8; 20];
            id.copy_from_slice(&out[0..20]);
            Address(id)
        }
    }

    /// Bech32 encoding for addresses (optional).
    #[cfg(feature = "bech32")]
    pub fn bech32_address(&self, hrp: &str) -> Result<String, SignError> {
        let addr = self.to_address();
        let s = bech32::encode(hrp, addr.0.to_base32(), Variant::Bech32).map_err(|e| SignError::Encoding(e.to_string()))?;
        Ok(s)
    }
}

/// Secret key container. Secrets are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SecretKey {
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519Secret),
    #[cfg(feature = "secp256k1")]
    Secp256k1(Secp256k1Secret),
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(_) => write!(f, "SecretKey::Ed25519(..)"),
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(_) => write!(f, "SecretKey::Secp256k1(..)"),
        }
    }
}

impl SecretKey {
    pub fn kind(&self) -> KeyKind {
        match self {
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(_) => KeyKind::Ed25519,
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(_) => KeyKind::Secp256k1,
        }
    }

    pub fn generate(kind: KeyKind) -> Result<Self, SignError> {
        match kind {
            #[cfg(feature = "ed25519")]
            KeyKind::Ed25519 => {
                let sk = Ed25519Secret::generate(&mut OsRng);
                Ok(SecretKey::Ed25519(sk))
            }
            #[cfg(feature = "secp256k1")]
            KeyKind::Secp256k1 => {
                let sk = Secp256k1Secret::random(&mut OsRng);
                Ok(SecretKey::Secp256k1(sk))
            }
            #[allow(unreachable_patterns)]
            _ => Err(SignError::Unsupported("key kind not enabled".into())),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(sk) => {
                let pk: Ed25519Public = sk.verifying_key();
                PublicKey::Ed25519(pk.to_bytes())
            }
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(sk) => {
                let pk: Secp256k1Public = sk.verifying_key();
                let pt: EncodedPoint = pk.to_encoded_point(false);
                let b = pt.as_bytes();
                let mut out = [0u8; 65];
                out.copy_from_slice(b);
                PublicKey::Secp256k1Uncompressed(out)
            }
        }
    }

    /// Export secret key bytes in a stable, raw format:
    /// - Ed25519: 32 bytes seed
    /// - Secp256k1: 32 bytes scalar
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(sk) => sk.to_bytes().to_vec(),
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(sk) => sk.to_bytes().to_vec(),
        }
    }

    /// Import from raw bytes (32 bytes).
    pub fn from_bytes(kind: KeyKind, bytes: &[u8]) -> Result<Self, SignError> {
        match kind {
            #[cfg(feature = "ed25519")]
            KeyKind::Ed25519 => {
                if bytes.len() != 32 {
                    return Err(SignError::Encoding("invalid length for Ed25519 secret".into()));
                }
                let mut b = [0u8; 32];
                b.copy_from_slice(bytes);
                Ok(SecretKey::Ed25519(Ed25519Secret::from_bytes(&b)))
            }
            #[cfg(feature = "secp256k1")]
            KeyKind::Secp256k1 => {
                let sk = Secp256k1Secret::from_bytes(bytes.into()).map_err(|e| SignError::Encoding(e.to_string()))?;
                Ok(SecretKey::Secp256k1(sk))
            }
            #[allow(unreachable_patterns)]
            _ => Err(SignError::Unsupported("key kind not enabled".into())),
        }
    }

    /// Sign a message using domain-separated prehash.
    pub fn sign(&self, ctx: &SignContext, message: &[u8]) -> Result<Signature, SignError> {
        let h = ctx.prehash(message);
        match self {
            #[cfg(feature = "ed25519")]
            SecretKey::Ed25519(sk) => {
                let sig = sk.sign(&h);
                Ok(Signature::Ed25519(sig.to_bytes()))
            }
            #[cfg(feature = "secp256k1")]
            SecretKey::Secp256k1(sk) => {
                let sig: SecpSignatureDer = sk.sign(&h);
                Ok(Signature::Secp256k1Der(sig.to_der().as_bytes().to_vec()))
            }
        }
    }
}

impl PublicKey {
    /// Verify signature over message using same prehash/domain rules.
    pub fn verify(&self, ctx: &SignContext, message: &[u8], sig: &Signature) -> Result<(), VerifyError> {
        let h = ctx.prehash(message);
        match (self, sig) {
            #[cfg(feature = "ed25519")]
            (PublicKey::Ed25519(pk_bytes), Signature::Ed25519(sig_bytes)) => {
                let pk = Ed25519Public::from_bytes(pk_bytes).map_err(|e| VerifyError::Format(e.to_string()))?;
                let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
                pk.verify_strict(&h, &sig).map_err(|_| VerifyError::BadSignature)
            }
            #[cfg(feature = "secp256k1")]
            (PublicKey::Secp256k1Uncompressed(uncomp), Signature::Secp256k1Der(der)) => {
                let pk = Secp256k1Public::from_sec1_bytes(uncomp).map_err(|e| VerifyError::Format(e.to_string()))?;
                let sig = SecpSignatureDer::from_der(der).map_err(|e| VerifyError::Format(e.to_string()))?;
                pk.verify(&h, &sig).map_err(|_| VerifyError::BadSignature)
            }
            _ => Err(VerifyError::KeySigMismatch),
        }
    }

    pub fn key_id(&self) -> KeyId {
        self.to_address()
    }
}

/// High-level signer interface for engine abstraction (optional).
pub trait SignerEngine {
    fn kind(&self) -> KeyKind;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, ctx: &SignContext, message: &[u8]) -> Result<Signature, SignError>;
}

impl SignerEngine for SecretKey {
    fn kind(&self) -> KeyKind { self.kind() }
    fn public_key(&self) -> PublicKey { self.public_key() }
    fn sign(&self, ctx: &SignContext, message: &[u8]) -> Result<Signature, SignError> { self.sign(ctx, message) }
}

/// Errors
#[derive(Error, Debug)]
pub enum SignError {
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("keystore error: {0}")]
    Keystore(String),
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("signature format error: {0}")]
    Format(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("key/signature kind mismatch")]
    KeySigMismatch,
}

/// Simple encrypted keystore (optional feature).
/// Scheme: key_bytes (32) -> scrypt(N=2^15, r=8, p=1, 32 bytes) -> ChaCha20-Poly1305(key)
/// Stored envelope contains params, salt, nonce, ciphertext.
#[cfg(feature = "keystore")]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Keystore {
    pub kind: KeyKind,
    pub scrypt_n: u8, // log2(N), e.g. 15 for 2^15
    pub scrypt_r: u32,
    pub scrypt_p: u32,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
}

#[cfg(feature = "keystore")]
impl Keystore {
    pub fn encrypt(secret: &SecretKey, password: &[u8]) -> Result<Self, SignError> {
        let kind = secret.kind();
        let key_bytes = secret.to_bytes();

        // Parameters
        let n_log = 15u8; // 2^15
        let r = 8u32;
        let p = 1u32;

        let params = scrypt_params(n_log, r, p).map_err(|e| SignError::Keystore(e.to_string()))?;

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let mut dk = [0u8; 32];
        scrypt::scrypt(password, &salt, &params, &mut dk).map_err(|e| SignError::Keystore(e.to_string()))?;

        let aead = ChaCha20Poly1305::new(AeadKey::from_slice(&dk));
        let ciphertext = aead.encrypt(Nonce::from_slice(&nonce), key_bytes.as_ref())
            .map_err(|e| SignError::Keystore(e.to_string()))?;

        // Zeroize sensitive material
        let mut kb = key_bytes;
        kb.zeroize();
        dk.zeroize();

        Ok(Self { kind, scrypt_n: n_log, scrypt_r: r, scrypt_p: p, salt, nonce, ct: ciphertext })
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<SecretKey, SignError> {
        let params = scrypt_params(self.scrypt_n, self.scrypt_r, self.scrypt_p)
            .map_err(|e| SignError::Keystore(e.to_string()))?;

        let mut dk = [0u8; 32];
        scrypt::scrypt(password, &self.salt, &params, &mut dk).map_err(|e| SignError::Keystore(e.to_string()))?;
        let aead = ChaCha20Poly1305::new(AeadKey::from_slice(&dk));
        let pt = aead.decrypt(Nonce::from_slice(&self.nonce), self.ct.as_ref())
            .map_err(|e| SignError::Keystore(e.to_string()))?;
        dk.zeroize();

        // Reconstruct secret
        SecretKey::from_bytes(self.kind, &pt)
    }
}

#[cfg(feature = "keystore")]
fn scrypt_params(n_log: u8, r: u32, p: u32) -> Result<ScryptParams, InvalidParams> {
    ScryptParamsBuilder::new()
        .n_log2(n_log)
        .r(r)
        .p(p)
        .build()
}

//
// -------------------------- Tests --------------------------
//

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SignContext {
        SignContext::new("AETHERNOVA-TX-V1", b"chain-mainnet")
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_sign_verify() {
        let sk = SecretKey::generate(KeyKind::Ed25519).unwrap();
        let pk = sk.public_key();
        let msg = b"hello";
        let sig = sk.sign(&ctx(), msg).unwrap();
        pk.verify(&ctx(), msg, &sig).unwrap();
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn secp256k1_sign_verify() {
        let sk = SecretKey::generate(KeyKind::Secp256k1).unwrap();
        let pk = sk.public_key();
        let msg = b"world";
        let sig = sk.sign(&ctx(), msg).unwrap();
        pk.verify(&ctx(), msg, &sig).unwrap();
    }

    #[cfg(all(feature = "keystore", feature = "ed25519"))]
    #[test]
    fn keystore_cycle_ed25519() {
        let sk = SecretKey::generate(KeyKind::Ed25519).unwrap();
        let ks = Keystore::encrypt(&sk, b"pass").unwrap();
        let sk2 = ks.decrypt(b"pass").unwrap();
        let pk1 = sk.public_key();
        let pk2 = sk2.public_key();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[cfg(all(feature = "keystore", feature = "secp256k1"))]
    #[test]
    fn keystore_cycle_secp() {
        let sk = SecretKey::generate(KeyKind::Secp256k1).unwrap();
        let ks = Keystore::encrypt(&sk, b"pass").unwrap();
        let sk2 = ks.decrypt(b"pass").unwrap();
        let pk1 = sk.public_key();
        let pk2 = sk2.public_key();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[cfg(feature = "bech32")]
    #[test]
    fn bech32_addr() {
        #[cfg(feature = "ed25519")]
        let sk = SecretKey::generate(KeyKind::Ed25519).unwrap();
        #[cfg(all(not(feature = "ed25519"), feature = "secp256k1"))]
        let sk = SecretKey::generate(KeyKind::Secp256k1).unwrap();
        let pk = sk.public_key();
        let s = pk.bech32_address("aeth").unwrap();
        assert!(s.starts_with("aeth1"));
    }
}

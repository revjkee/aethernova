//! Aethernova Crypto Module (industrial grade)
//!
//! Implements unified traits and production-ready primitives:
//! - Signatures: Ed25519 (RFC 8032) via ed25519-dalek
//! - Key Agreement: X25519 (RFC 7748) via x25519-dalek + HKDF-SHA256 (RFC 5869)
//! - AEAD: ChaCha20-Poly1305 / XChaCha20-Poly1305 (RFC 8439) via RustCrypto
//! - Hash: SHA-256 (FIPS 180-4) and BLAKE2b-512 (RFC 7693)
//!
//! Security properties:
//! - Secret material implements Zeroize/ZeroizeOnDrop
//! - Constant-time comparisons where applicable (subtle)
//! - OS CSPRNG for key generation (rand_core::OsRng / getrandom)
//!
//! NOTE: add corresponding dependencies in Cargo.toml (see block below).
#![forbid(unsafe_code)]
#![doc(html_root_url = "https://docs.rs")]

/*
[dependencies]
zeroize = { version = "1", features = ["zeroize_derive"] }
subtle  = "2"
rand_core = "0.6"
getrandom = "0.2"

# Signatures
ed25519-dalek = { version = "2", features = ["rand_core","zeroize"] }

# X25519 ECDH
x25519-dalek = "2"

# AEAD
aead = "0.5"
chacha20poly1305 = { version = "0.10", features = ["std"] } # provides ChaCha20Poly1305 & XChaCha20Poly1305

# KDF / Hash
hkdf = "0.12"
sha2 = "0.10"
blake2 = "0.10"
*/

use core::fmt;
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// -------- Errors --------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKey,
    InvalidSignature,
    InvalidNonce,
    InvalidTag,
    KdfError,
    AeadError,
    AgreementError,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CryptoError::*;
        match self {
            InvalidKey => write!(f, "invalid key"),
            InvalidSignature => write!(f, "invalid signature"),
            InvalidNonce => write!(f, "invalid nonce"),
            InvalidTag => write!(f, "invalid authentication tag"),
            KdfError => write!(f, "key derivation failed"),
            AeadError => write!(f, "AEAD operation failed"),
            AgreementError => write!(f, "key agreement failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// -------- Traits --------

/// Signature scheme trait.
pub trait SignatureScheme {
    type Public: Clone + Send + Sync + 'static;
    type Secret: Zeroize + ZeroizeOnDrop + Send + Sync + 'static;
    type Signature: Clone + Send + Sync + 'static;

    fn generate() -> (Self::Public, Self::Secret);
    fn public_from_secret(sk: &Self::Secret) -> Result<Self::Public, CryptoError>;
    fn sign(sk: &Self::Secret, msg: &[u8]) -> Result<Self::Signature, CryptoError>;
    fn verify(pk: &Self::Public, msg: &[u8], sig: &Self::Signature) -> Result<(), CryptoError>;
}

/// AEAD interface (seal/open with associated data).
pub trait AeadCipher {
    type Key: Zeroize + ZeroizeOnDrop + Send + Sync + 'static;
    type Nonce: Clone + Send + Sync + 'static; // size depends on cipher (12B or 24B)
    fn seal(key: &Self::Key, nonce: &Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn open(key: &Self::Key, nonce: &Self::Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Key Derivation Function (HKDF-like).
pub trait Kdf {
    fn extract_and_expand(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoError>;
}

/// Hash functions.
pub trait Hash {
    fn digest(data: &[u8]) -> Vec<u8>;
}

/// -------- Implementations --------

/// Ed25519 (RFC 8032) signatures
pub mod ed25519 {
    use super::{CryptoError, SignatureScheme};
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SignatureError, Signer, Verifier};
    use rand_core::OsRng;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Clone)]
    pub struct Public(pub VerifyingKey);

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct Secret(pub SigningKey);

    impl super::SignatureScheme for crate::crypto::ed25519::Ed25519 {
        type Public = Public;
        type Secret = Secret;
        type Signature = Signature;

        fn generate() -> (Self::Public, Self::Secret) {
            let sk = SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key();
            (Public(pk), Secret(sk))
        }

        fn public_from_secret(sk: &Self::Secret) -> Result<Self::Public, CryptoError> {
            Ok(Public(sk.0.verifying_key()))
        }

        fn sign(sk: &Self::Secret, msg: &[u8]) -> Result<Self::Signature, CryptoError> {
            Ok(sk.0.sign(msg))
        }

        fn verify(pk: &Self::Public, msg: &[u8], sig: &Self::Signature) -> Result<(), CryptoError> {
            pk.0.verify(msg, sig).map_err(|_e: SignatureError| CryptoError::InvalidSignature)
        }
    }

    /// Marker type
    pub struct Ed25519;
}

/// X25519 ECDH + HKDF-SHA256
pub mod x25519hkdf {
    use super::{CryptoError, Kdf};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Clone)]
    pub struct Public(pub PublicKey);

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct Secret(pub StaticSecret);

    pub fn generate_static() -> (Public, Secret) {
        let sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let pk = PublicKey::from(&sk);
        (Public(pk), Secret(sk))
    }

    pub fn generate_ephemeral() -> (PublicKey, EphemeralSecret) {
        let esk = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let epk = PublicKey::from(&esk);
        (epk, esk)
    }

    /// Derive a shared secret via ECDH and expand via HKDF-SHA256 to `out_len` bytes.
    pub fn agree_and_kdf(my_secret: &StaticSecret, peer_public: &PublicKey, salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoError> {
        let ss = my_secret.diffie_hellman(peer_public);
        let okm = Hkdf::<Sha256>::new(Some(salt), ss.as_bytes())
            .expand(info, vec![0u8; out_len].as_mut_slice())
            .map_err(|_| CryptoError::KdfError)
            .map(|_| ())?;
        // Above expand writes into supplied buf; re-run to actually collect
        let hk = Hkdf::<Sha256>::new(Some(salt), ss.as_bytes());
        let mut out = vec![0u8; out_len];
        hk.expand(info, &mut out).map_err(|_| CryptoError::KdfError)?;
        Ok(out)
    }

    impl Kdf for super::HkdfSha256 {
        fn extract_and_expand(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoError> {
            let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
            let mut out = vec![0u8; out_len];
            hk.expand(info, &mut out).map_err(|_| CryptoError::KdfError)?;
            Ok(out)
        }
    }

    /// Marker type for trait Kdf impl
    pub struct HkdfSha256;
}

/// AEAD: ChaCha20-Poly1305 (96-bit nonce) and XChaCha20-Poly1305 (192-bit nonce)
pub mod aeads {
    use super::{AeadCipher, CryptoError};
    use aead::{Aead, KeyInit, generic_array::GenericArray};
    use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, Key, XNonce, ChaChaPoly1305};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct Key32(pub Key); // 256-bit

    #[derive(Clone)]
    pub struct Nonce12(pub [u8; 12]);

    #[derive(Clone)]
    pub struct Nonce24(pub [u8; 24]);

    impl AeadCipher for super::ChaCha20Poly1305Impl {
        type Key = Key32;
        type Nonce = Nonce12;

        fn seal(key: &Self::Key, nonce: &Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let cipher = ChaCha20Poly1305::new(&key.0);
            cipher.encrypt(GenericArray::from_slice(&nonce.0), aead::Payload { msg: plaintext, aad })
                  .map_err(|_| CryptoError::AeadError)
        }
        fn open(key: &Self::Key, nonce: &Self::Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let cipher = ChaCha20Poly1305::new(&key.0);
            cipher.decrypt(GenericArray::from_slice(&nonce.0), aead::Payload { msg: ciphertext, aad })
                  .map_err(|_| CryptoError::AeadError)
        }
    }

    impl AeadCipher for super::XChaCha20Poly1305Impl {
        type Key = Key32;
        type Nonce = Nonce24;

        fn seal(key: &Self::Key, nonce: &Self::Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let cipher = XChaCha20Poly1305::new(&key.0);
            cipher.encrypt(XNonce::from_slice(&nonce.0), aead::Payload { msg: plaintext, aad })
                  .map_err(|_| CryptoError::AeadError)
        }
        fn open(key: &Self::Key, nonce: &Self::Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let cipher = XChaCha20Poly1305::new(&key.0);
            cipher.decrypt(XNonce::from_slice(&nonce.0), aead::Payload { msg: ciphertext, aad })
                  .map_err(|_| CryptoError::AeadError)
        }
    }

    pub fn gen_key() -> Key32 {
        use rand_core::RngCore;
        let mut k = [0u8; 32];
        let mut rng = rand_core::OsRng;
        rng.fill_bytes(&mut k);
        Key32(Key::from_slice(&k).to_owned())
    }
    pub fn gen_nonce12() -> Nonce12 {
        use rand_core::RngCore;
        let mut n = [0u8; 12];
        let mut rng = rand_core::OsRng;
        rng.fill_bytes(&mut n);
        Nonce12(n)
    }
    pub fn gen_nonce24() -> Nonce24 {
        use rand_core::RngCore;
        let mut n = [0u8; 24];
        let mut rng = rand_core::OsRng;
        rng.fill_bytes(&mut n);
        Nonce24(n)
    }
}

/// Hashes: SHA-256 (FIPS 180-4) and BLAKE2b-512 (RFC 7693)
pub mod hash {
    use super::Hash;
    use sha2::{Sha256, Digest as _};
    use blake2::Blake2b512;

    pub struct Sha256Hash;
    impl Hash for Sha256Hash {
        fn digest(data: &[u8]) -> Vec<u8> {
            Sha256::new_with_prefix(data).finalize().to_vec()
        }
    }

    pub struct Blake2b512Hash;
    impl Hash for Blake2b512Hash {
        fn digest(data: &[u8]) -> Vec<u8> {
            use blake2::digest::{Update, VariableOutput};
            use blake2::digest::typenum::U64;
            let mut hasher = Blake2b512::default();
            hasher.update(data);
            let out = hasher.finalize();
            out.to_vec()
        }
    }
}

/// High-level sealed box (ephemeral X25519 + XChaCha20-Poly1305).
/// Sender: generates ephemeral keypair, does ECDH with recipient public key,
/// derives 32-byte AEAD key via HKDF-SHA256, uses random 24-byte nonce.
pub mod sealedbox {
    use super::{CryptoError};
    use crate::crypto::x25519hkdf::{agree_and_kdf};
    use crate::crypto::aeads::{self, AeadCipher, Nonce24, XChaCha20Poly1305Impl};
    use x25519_dalek::{PublicKey, EphemeralSecret};
    use rand_core::RngCore;
    use zeroize::Zeroize;

    /// Encrypt to recipient's X25519 public key; returns (ephemeral_pub, nonce, ciphertext).
    pub fn seal(recipient_pk: &PublicKey, aad: &[u8], plaintext: &[u8]) -> Result<([u8;32],[u8;24],Vec<u8>), CryptoError> {
        let (epk, esk) = crate::crypto::x25519hkdf::generate_ephemeral();
        let key = agree_and_kdf(&esk, recipient_pk, b"sbx-salt", b"sbx-info", 32)?;
        let mut k32 = [0u8; 32];
        k32.copy_from_slice(&key);
        let key = aeads::Key32(chacha20poly1305::Key::from_slice(&k32).to_owned());
        let nonce = aeads::gen_nonce24();
        let ct = <XChaCha20Poly1305Impl as aeads::AeadCipher>::seal(&key, &nonce, aad, plaintext)?;
        let mut epk_bytes = [0u8;32];
        epk_bytes.copy_from_slice(epk.as_bytes());
        Ok((epk_bytes, nonce.0, ct))
    }

    /// Decrypt with recipient's X25519 static secret and sender's ephemeral pubkey.
    pub fn open(my_sk: &x25519_dalek::StaticSecret, sender_ephemeral_pk: &[u8;32], aad: &[u8], nonce: &[u8;24], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let epk = x25519_dalek::PublicKey::from(*sender_ephemeral_pk);
        let key = agree_and_kdf(my_sk, &epk, b"sbx-salt", b"sbx-info", 32)?;
        let mut k32 = [0u8; 32];
        k32.copy_from_slice(&key);
        let key = aeads::Key32(chacha20poly1305::Key::from_slice(&k32).to_owned());
        let nonce = aeads::Nonce24(*nonce);
        <aeads::XChaCha20Poly1305Impl as aeads::AeadCipher>::open(&key, &nonce, aad, ciphertext)
    }

    /// Marker types for AEAD trait binding
    pub struct XChaCha20Poly1305Impl;
}

/// Marker types (bind implementations to traits)
pub struct ChaCha20Poly1305Impl;
pub struct XChaCha20Poly1305Impl;

/// Re-export namespaces
pub mod prelude {
    pub use super::CryptoError;
    pub use super::SignatureScheme;
    pub use super::AeadCipher;
    pub use super::Kdf;
    pub use super::Hash;

    pub use super::ed25519::Ed25519;
    pub use super::x25519hkdf::{HkdfSha256, Public as X25519Public, Secret as X25519Secret, generate_static as x25519_generate};
    pub use super::aeads::{Key32 as AeadKey32, Nonce12, Nonce24};
    pub use super::hash::{Sha256Hash, Blake2b512Hash};
    pub use super::sealedbox;
}

// ------------------------------ Tests ---------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify() {
        let (pk, sk) = ed25519::Ed25519::generate();
        let msg = b"test message";
        let sig = ed25519::Ed25519::sign(&sk, msg).unwrap();
        ed25519::Ed25519::verify(&pk, msg, &sig).unwrap();
        // Negative
        assert!(ed25519::Ed25519::verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn hkdf_extract_expand() {
        let ikm = b"input keying material";
        let okm = x25519hkdf::HkdfSha256::extract_and_expand(ikm, b"salt", b"info", 42).unwrap();
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn aead_chacha20poly1305_roundtrip() {
        use aeads::{gen_key, gen_nonce12};
        let key = gen_key();
        let nonce = gen_nonce12();
        let aad = b"header";
        let pt = b"plaintext";
        let ct = <ChaCha20Poly1305Impl as aeads::AeadCipher>::seal(&key, &nonce, aad, pt).unwrap();
        let dec = <ChaCha20Poly1305Impl as aeads::AeadCipher>::open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(&dec, pt);
    }

    #[test]
    fn sealed_box_roundtrip() {
        let (pk_r, sk_r) = x25519hkdf::generate_static();
        let aad = b"context";
        let pt = b"payload";
        let (epk, nonce, ct) = sealedbox::seal(&pk_r.0, aad, pt).unwrap();
        let dec = sealedbox::open(&sk_r.0, &epk, aad, &nonce, &ct).unwrap();
        assert_eq!(&dec, pt);
    }

    #[test]
    fn hashes() {
        use hash::{Sha256Hash, Blake2b512Hash};
        let d1 = Sha256Hash::digest(b"abc");
        let d2 = Blake2b512Hash::digest(b"abc");
        assert_eq!(d1.len(), 32);
        assert_eq!(d2.len(), 64);
    }
}

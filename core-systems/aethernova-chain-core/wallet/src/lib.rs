//! Aethernova Wallet Library
//!
//! Функционал:
//! - BIP-39 мнемоника и seed
//! - BIP-32 деривация ключей secp256k1 (ECDSA) для EVM-совместимых адресов
//! - SLIP-0010 деривация ed25519 ключей для подписи
//! - Подпись и верификация сообщений
//! - Вычисление Ethereum-адреса (Keccak-256(pubkey[1..]) → последние 20 байт)
//!
//! Проверяемые источники:
//! - `bip32` (реэкспорт BIP-39, пример end-to-end, XPrv/XPub, private_key/public_key) — docs.rs: bip32 0.5.x. См. секцию Usage и пример кода.  // :contentReference[oaicite:4]{index=4}
//! - ed25519-dalek: создание SigningKey/VerifyingKey, подпись/верификация — docs.rs: ed25519-dalek 2.x.  // :contentReference[oaicite:5]{index=5}
//! - SLIP-0010 для ed25519: `slip10_ed25519::derive_ed25519_private_key(seed, indexes)` — сигнатура и пример. // :contentReference[oaicite:6]{index=6}
//! - Keccak-256 из `sha3` (вариант Keccak256; поддержка указана в описании) — docs.rs: sha3. // :contentReference[oaicite:7]{index=7}
//! - ETH-адрес = последние 20 байт Keccak-256 от нежатого pubkey без первого байта 0x04 — разъяснение (Ethereum StackExchange). // :contentReference[oaicite:8]{index=8}
//!
//! Примечание: формат адресов для ed25519 специфичен для конкретной сети (bech32 и т.п.). В этой библиотеке для ed25519 возвращается публичный ключ в hex
//! как «адрес-представление». Не могу подтвердить это: универсальный стандарт отображения ed25519-пубключа в адрес во всех сетях.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rust_2018_idioms)]

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Кривые, поддерживаемые кошельком.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    /// secp256k1 (ECDSA), стандарт для Ethereum.
    Secp256k1,
    /// ed25519 (EdDSA), востребована вне EVM-контекста.
    Ed25519,
}

/// Ошибки кошелька.
#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("bip32 error: {0}")]
    Bip32(#[from] bip32::Error),
    #[error("invalid derivation path")]
    InvalidPath,
    #[error("ed25519 error: {0}")]
    Ed25519(String),
    #[error("slip10 ed25519 derivation error")]
    Slip10,
    #[error("unsupported curve")]
    UnsupportedCurve,
}

/// Результат подписи.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Сырые байты подписи (формат зависит от кривой).
    pub bytes: Vec<u8>,
}

/// Общий интерфейс подписанта.
pub trait Signer {
    /// Публичный ключ в сыром виде.
    fn public_key(&self) -> Vec<u8>;
    /// Подпись произвольного сообщения (байты).
    fn sign(&self, msg: &[u8]) -> Result<Signature, WalletError>;
}

/// Представление адреса для разных кривых.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressRepr {
    /// 20 байт для EVM (Ethereum).
    Eth([u8; 20]),
    /// 32-байтовый публичный ключ для ed25519.
    Ed25519Pk([u8; 32]),
}

mod util {
    use sha3::{Digest, Keccak256}; // Keccak256 доступен в crate `sha3` // :contentReference[oaicite:9]{index=9}

    /// ETH-адрес: Keccak-256 от нежатого pubkey без первого байта 0x04, последние 20 байт.
    /// См. разъяснение методики на Ethereum StackExchange. // :contentReference[oaicite:10]{index=10}
    pub fn eth_address_from_uncompressed_pubkey(uncompressed: &[u8]) -> [u8; 20] {
        assert!(
            uncompressed.len() == 65 && uncompressed[0] == 0x04,
            "expect uncompressed SEC1 key 65 bytes starting with 0x04"
        );
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed[1..]); // без префикса 0x04
        let out = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&out[12..32]);
        addr
    }
}

#[cfg(feature = "secp256k1")]
mod secp {
    use super::{AddressRepr, Signature, Signer, WalletError};
    use bip32::{DerivationPath, Mnemonic, XPrv}; // BIP-32/39 API и пример использования // :contentReference[oaicite:11]{index=11}
    use k256::ecdsa::{
        signature::{Signer as _, Verifier as _},
        Signature as EcdsaSignature, SigningKey, VerifyingKey,
    };
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Кошелёк secp256k1.
    #[derive(ZeroizeOnDrop)]
    pub struct SecpWallet {
        sk: SigningKey,
        vk: VerifyingKey,
        eth_addr: [u8; 20],
    }

    impl core::fmt::Debug for SecpWallet {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "SecpWallet(eth=0x{})", hex::encode(self.eth_addr))
        }
    }

    impl SecpWallet {
        /// Создать из мнемоники BIP-39 и пути BIP-32 (например, m/44'/60'/0'/0/0).
        pub fn from_mnemonic_path(mnemonic: &Mnemonic, passphrase: &str, path: &str) -> Result<Self, WalletError> {
            let seed = mnemonic.to_seed(passphrase);
            let derivation: DerivationPath = path.parse().map_err(|_| WalletError::InvalidPath)?;
            let xprv = XPrv::derive_from_path(&seed, &derivation)?; // пример в доке // :contentReference[oaicite:12]{index=12}
            let sk: SigningKey = xprv.private_key(); // возвращает k256::ecdsa::SigningKey // :contentReference[oaicite:13]{index=13}
            let vk: VerifyingKey = xprv.public_key().public_key();
            let uncompressed = vk.to_encoded_point(false);
            let eth_addr = crate::util::eth_address_from_uncompressed_pubkey(uncompressed.as_bytes());
            Ok(Self { sk, vk, eth_addr })
        }

        /// ETH-адрес (20 байт).
        pub fn address(&self) -> [u8; 20] {
            self.eth_addr
        }

        /// Проверка подписи (ECDSA) для тестов/интеграции.
        pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
            if let Ok(sig) = EcdsaSignature::from_der(sig.bytes.as_slice()) {
                self.vk.verify(msg, &sig).is_ok()
            } else {
                false
            }
        }
    }

    impl Signer for SecpWallet {
        fn public_key(&self) -> Vec<u8> {
            self.vk.to_encoded_point(false).as_bytes().to_vec()
        }
        fn sign(&self, msg: &[u8]) -> Result<Signature, WalletError> {
            // Подпись «как есть» (DER). Формирование v,r,s для ETH — функция уровня RPC/SDK.
            let sig: EcdsaSignature = self.sk.sign(msg);
            Ok(Signature { bytes: sig.to_der().as_bytes().to_vec() })
        }
    }

    impl Drop for SecpWallet {
        fn drop(&mut self) {
            // SigningKey и так ZeroizeOnDrop через k256; на всякий случай «шумим» публичные представления
            let mut tmp = [0u8; 33];
            tmp.copy_from_slice(&self.vk.to_encoded_point(true).as_bytes()[..33]);
            tmp.zeroize();
        }
    }

    pub use SecpWallet as WalletImpl;
}

#[cfg(feature = "ed25519")]
mod eddsa {
    use super::{AddressRepr, Signature, Signer, WalletError};
    use bip32::Mnemonic; // Mnemonic/seed из bip32 (реэкспорт BIP-39) // :contentReference[oaicite:14]{index=14}
    use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey}; // API подписи/ключей // :contentReference[oaicite:15]{index=15}
    use slip10_ed25519::derive_ed25519_private_key; // сигнатура функции и пример // :contentReference[oaicite:16]{index=16}
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Кошелёк ed25519 (SLIP-0010).
    #[derive(ZeroizeOnDrop)]
    pub struct Ed25519Wallet {
        sk: SigningKey,
        vk: VerifyingKey,
    }

    impl core::fmt::Debug for Ed25519Wallet {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "Ed25519Wallet(pk=0x{})", hex::encode(self.vk.to_bytes()))
        }
    }

    impl Ed25519Wallet {
        /// Создать из мнемоники BIP-39 и SLIP-0010 пути «m/…» (только hardened компоненты).
        /// Пример космос-совместимого пути: m/44'/118'/0'/0/0 (все индексы трактуются как hardened).
        pub fn from_mnemonic_slip10(mnemonic: &Mnemonic, passphrase: &str, path: &str) -> Result<Self, WalletError> {
            let seed = mnemonic.to_seed(passphrase);
            let indexes = parse_slip10_hardened_indexes(path).ok_or(WalletError::InvalidPath)?;
            let sk_bytes = derive_ed25519_private_key(seed.as_bytes(), &indexes);
            // ed25519_dalek::SigningKey::from_bytes ожидает [u8; 32] // :contentReference[oaicite:17]{index=17}
            let sk = SigningKey::from_bytes(&sk_bytes);
            let vk = sk.verifying_key();
            Ok(Self { sk, vk })
        }

        /// Адрес-представление для ed25519 — 32-байтовый публичный ключ (hex).
        pub fn address(&self) -> [u8; 32] {
            self.vk.to_bytes()
        }

        /// Проверка подписи.
        pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
            use ed25519_dalek::{Signature as DalekSig, Verifier as _};
            match DalekSig::from_slice(&sig.bytes) {
                Ok(s) => self.vk.verify(msg, &s).is_ok(),
                Err(_) => false,
            }
        }
    }

    impl Signer for Ed25519Wallet {
        fn public_key(&self) -> Vec<u8> {
            self.vk.to_bytes().to_vec()
        }
        fn sign(&self, msg: &[u8]) -> Result<Signature, WalletError> {
            let sig = self.sk.sign(msg);
            Ok(Signature { bytes: sig.to_bytes().to_vec() })
        }
    }

    impl Drop for Ed25519Wallet {
        fn drop(&mut self) {
            // SigningKey реализует Zeroize; VK не секректен.
            let mut buf = self.sk.to_keypair_bytes();
            buf.zeroize();
        }
    }

    /// Разбор SLIP-0010 пути "m/44'/.../…'". Возвращает вектор индексов без "hardened-бита";
    /// `derive_ed25519_private_key` трактует их как hardened. // :contentReference[oaicite:18]{index=18}
    fn parse_slip10_hardened_indexes(path: &str) -> Option<Vec<u32>> {
        let p = path.trim();
        if !p.starts_with("m/") { return None; }
        let mut out = Vec::new();
        for comp in p[2..].split('/') {
            let c = comp.trim_end_matches('\'');
            let idx: u32 = c.parse().ok()?;
            out.push(idx);
        }
        Some(out)
    }

    pub use Ed25519Wallet as WalletImpl;
}

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
/// API верхнего уровня: универсальный кошелек.
pub struct Wallet {
    inner: WalletInner,
}

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
enum WalletInner {
    #[cfg(feature = "secp256k1")]
    Secp(secp::WalletImpl),
    #[cfg(feature = "ed25519")]
    Ed25519(eddsa::WalletImpl),
}

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            WalletInner::Secp(w) => write!(f, "{w:?}"),
            #[cfg(feature = "ed25519")]
            WalletInner::Ed25519(w) => write!(f, "{w:?}"),
        }
    }
}

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
impl Wallet {
    /// Создать кошелёк из BIP-39 мнемоники и пути.
    /// - Для secp256k1 используйте `bip32`-путь (например, m/44'/60'/0'/0/0).
    /// - Для ed25519 используйте SLIP-0010 путь (например, m/44'/118'/0'/0/0).
    pub fn from_mnemonic(curve: Curve, mnemonic: &bip32::Mnemonic, passphrase: &str, path: &str) -> Result<Self, WalletError> {
        Ok(match curve {
            #[cfg(feature = "secp256k1")]
            Curve::Secp256k1 => Self { inner: WalletInner::Secp(secp::WalletImpl::from_mnemonic_path(mnemonic, passphrase, path)?) },
            #[cfg(feature = "ed25519")]
            Curve::Ed25519 => Self { inner: WalletInner::Ed25519(eddsa::WalletImpl::from_mnemonic_slip10(mnemonic, passphrase, path)?) },
            #[allow(unreachable_patterns)]
            _ => return Err(WalletError::UnsupportedCurve),
        })
    }

    /// Публичный ключ.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            WalletInner::Secp(w) => w.public_key(),
            #[cfg(feature = "ed25519")]
            WalletInner::Ed25519(w) => w.public_key(),
        }
    }

    /// Подпись сообщения.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, WalletError> {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            WalletInner::Secp(w) => w.sign(msg),
            #[cfg(feature = "ed25519")]
            WalletInner::Ed25519(w) => w.sign(msg),
        }
    }

    /// Представление адреса:
    /// - Для secp256k1 — Ethereum-адрес (20 байт).
    /// - Для ed25519 — 32-байтовый публичный ключ (hex-адрес-представление).
    pub fn address(&self) -> AddressRepr {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            WalletInner::Secp(w) => AddressRepr::Eth(w.address()),
            #[cfg(feature = "ed25519")]
            WalletInner::Ed25519(w) => AddressRepr::Ed25519Pk(w.address()),
        }
    }
}

/* ----------------------------- Утилиты BIP-39 ------------------------------ */

/// Сгенерировать 24-словную мнемонику (английский словарь — по умолчанию в `bip32`).
/// В `bip32` приведен пример генерации и работы с `Mnemonic`/`Seed`. // :contentReference[oaicite:19]{index=19}
pub fn generate_mnemonic() -> bip32::Mnemonic {
    use rand_core::OsRng; // см. раздел Accessing OsRng в доках bip32 // :contentReference[oaicite:20]{index=20}
    bip32::Mnemonic::random(&mut OsRng, Default::default())
}

/* ---------------------------------- Тесты ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;

    #[cfg(feature = "secp256k1")]
    #[test]
    fn secp_end_to_end() {
        let m = generate_mnemonic();
        let w = Wallet::from_mnemonic(Curve::Secp256k1, &m, "", "m/44'/60'/0'/0/0").unwrap();
        let pk = w.public_key();
        assert!(pk.len() == 65 && pk[0] == 0x04, "uncompressed SEC1 pubkey expected");
        if let AddressRepr::Eth(addr) = w.address() {
            // просто проверим длину/формат
            assert_eq!(addr.len(), 20);
        } else {
            panic!("expected ETH address")
        }
        let msg = b"hello eth";
        let sig = w.sign(msg).unwrap();
        assert!(!sig.bytes.is_empty());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_end_to_end() {
        let m = generate_mnemonic();
        let w = Wallet::from_mnemonic(Curve::Ed25519, &m, "", "m/44'/118'/0'/0/0").unwrap();
        let pk = w.public_key();
        assert_eq!(pk.len(), 32);
        let msg = b"hello ed25519";
        let sig = w.sign(msg).unwrap();
        assert!(!sig.bytes.is_empty());
        if let AddressRepr::Ed25519Pk(pk32) = w.address() {
            assert_eq!(pk32.len(), 32);
        } else {
            panic!("expected ed25519 pk address repr");
        }
    }
}

// aethernova-chain-core/wallet/src/hd.rs
//! Industrial HD Wallet for Rust: BIP39 → BIP32 → BIP44 with BTC (P2WPKH) & ETH addresses.
//!
//! Dependencies expected in Cargo.toml (examples):
//!   bip39 = "2"
//!   pbkdf2 = "0.12"
//!   hmac = "0.12"
//!   sha2 = "0.10"
//!   secp256k1 = { version = "0.28", features = ["rand"] }
//!   bech32 = "0.9"
//!   bs58 = "0.5"
//!   ripemd = "0.1"
//!   tiny-keccak = { version = "2", features = ["keccak"] }
//!   rand = "0.8"
//!
//! This module focuses on correctness, explicit errors, and explicit network handling.

use bech32::{u5, ToBase32, Variant};
use bip39::{Language, Mnemonic as Bip39Mnemonic, MnemonicType, Seed as Bip39Seed};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use tiny_keccak::{Hasher, Keccak};

use std::fmt;
use std::str::FromStr;

/// 32-byte hash
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct H256(pub [u8; 32]);

impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("invalid path segment: {0}")]
    InvalidPath(String),
    #[error("invalid array length")]
    InvalidLen,
    #[error("sec256k1 key error")]
    Secp256k1,
    #[error("invalid network version")]
    InvalidVersion,
    #[error("invalid base58 payload")]
    Base58,
    #[error("checksum mismatch")]
    Checksum,
    #[error("address encoding failed")]
    AddressEncoding,
    #[error("unsupported operation")]
    Unsupported,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let s = sha256(data);
    let mut r = Ripemd160::new();
    r.update(s);
    let out = r.finalize();
    let mut b = [0u8; 20];
    b.copy_from_slice(&out);
    b
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut b = [0u8; 64];
    b.copy_from_slice(&out);
    b
}

/// Base58Check encode
fn base58check_encode(version: [u8; 4], payload: &[u8]) -> String {
    let mut v = Vec::with_capacity(4 + payload.len() + 4);
    v.extend_from_slice(&version);
    v.extend_from_slice(payload);
    let checksum_full = double_sha256(&v);
    v.extend_from_slice(&checksum_full[..4]);
    bs58::encode(v).with_check(None).into_string()
}

/// Base58Check decode returning (version, payload)
fn base58check_decode(s: &str) -> Result<([u8; 4], Vec<u8>), HdError> {
    let raw = bs58::decode(s).with_check(None).into_vec().map_err(|_| HdError::Base58)?;
    if raw.len() < 8 {
        return Err(HdError::InvalidLen);
    }
    let mut ver = [0u8; 4];
    ver.copy_from_slice(&raw[..4]);
    let payload = raw[4..].to_vec();
    Ok((ver, payload))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    Testnet,
    Ethereum, // for address HRP/encoding decisions
}

impl Network {
    pub fn btc_hrp(&self) -> Result<&'static str, HdError> {
        match self {
            Network::Bitcoin => Ok("bc"),
            Network::Testnet => Ok("tb"),
            Network::Ethereum => Err(HdError::Unsupported),
        }
    }
}

/// Child number with hardened bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildNumber(u32);
impl ChildNumber {
    pub fn new(index: u32, hardened: bool) -> Self {
        let bit = if hardened { 0x8000_0000 } else { 0 };
        ChildNumber(index | bit)
    }
    pub fn index(self) -> u32 {
        self.0 & 0x7fff_ffff
    }
    pub fn hardened(self) -> bool {
        (self.0 & 0x8000_0000) != 0
    }
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(Vec<ChildNumber>);

impl DerivationPath {
    pub fn new(path: Vec<ChildNumber>) -> Self {
        Self(path)
    }
    pub fn as_ref(&self) -> &[ChildNumber] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = HdError;

    /// Parse "m/44'/0'/0'/0/0" style.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self(vec![]));
        }
        let mut parts = s.split('/');

        // optional leading 'm'
        if let Some(first) = parts.next() {
            if !first.is_empty() && first != "m" {
                return Err(HdError::InvalidPath(s.into()));
            }
        }

        let mut out = Vec::new();
        for seg in parts {
            if seg.is_empty() {
                return Err(HdError::InvalidPath(s.into()));
            }
            let hardened = seg.ends_with('\'') || seg.ends_with('h') || seg.ends_with('H');
            let core = if hardened { &seg[..seg.len() - 1] } else { seg };
            let idx: u32 = core.parse().map_err(|_| HdError::InvalidPath(seg.into()))?;
            if idx > 0x7fff_ffff {
                return Err(HdError::InvalidPath(seg.into()));
            }
            out.push(ChildNumber::new(idx, hardened));
        }
        Ok(Self(out))
    }
}

/// Versions for xprv/xpub (mainnet/testnet)
#[derive(Clone, Copy, Debug)]
struct Versions {
    xprv: [u8; 4],
    xpub: [u8; 4],
}

const VERS_MAIN: Versions = Versions { xprv: [0x04, 0x88, 0xAD, 0xE4], xpub: [0x04, 0x88, 0xB2, 0x1E] };
const VERS_TEST: Versions = Versions { xprv: [0x04, 0x35, 0x83, 0x94], xpub: [0x04, 0x35, 0x87, 0xCF] };

fn versions_for(network: Network) -> Versions {
    match network {
        Network::Bitcoin | Network::Ethereum => VERS_MAIN,
        Network::Testnet => VERS_TEST,
    }
}

/// Extended Private Key (BIP32)
#[derive(Clone)]
pub struct ExtendedPrivKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub private_key: SecretKey,
}

impl fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedPrivKey")
            .field("depth", &self.depth)
            .field("parent_fingerprint", &format_args!("{:02x?}", self.parent_fingerprint))
            .field("child_number", &self.child_number)
            .field("chain_code", &format_args!("{:02x?}", &self.chain_code[..]))
            .finish()
    }
}

/// Extended Public Key (BIP32)
#[derive(Clone)]
pub struct ExtendedPubKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub public_key: PublicKey, // compressed
}

impl fmt::Debug for ExtendedPubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedPubKey")
            .field("depth", &self.depth)
            .field("parent_fingerprint", &format_args!("{:02x?}", self.parent_fingerprint))
            .field("child_number", &self.child_number)
            .field("chain_code", &format_args!("{:02x?}", &self.chain_code[..]))
            .finish()
    }
}

fn ser_u32_be(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

fn fingerprint_from_pubkey(pk: &PublicKey) -> [u8; 4] {
    let hash = hash160(&pk.serialize());
    [hash[0], hash[1], hash[2], hash[3]]
}

impl ExtendedPrivKey {
    /// BIP32 master key from seed (64-byte typically)
    pub fn from_seed(seed: &[u8]) -> Result<Self, HdError> {
        let I = hmac_sha512(b"Bitcoin seed", seed);
        let mut il = [0u8; 32];
        il.copy_from_slice(&I[..32]);
        let mut ir = [0u8; 32];
        ir.copy_from_slice(&I[32..]);

        let sk = SecretKey::from_slice(&il).map_err(|_| HdError::Secp256k1)?;
        Ok(Self {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
            chain_code: ir,
            private_key: sk,
        })
    }

    pub fn to_extended_pub(&self, secp: &Secp256k1<All>) -> ExtendedPubKey {
        let pk = PublicKey::from_secret_key(secp, &self.private_key);
        ExtendedPubKey {
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            public_key: pk,
        }
    }

    /// CKDpriv (child derived key)
    pub fn ckd_priv(&self, secp: &Secp256k1<All>, child: ChildNumber) -> Result<Self, HdError> {
        let mut data = Vec::with_capacity(37);
        if child.hardened() {
            data.push(0u8);
            data.extend_from_slice(&self.private_key[..]);
        } else {
            let pk = PublicKey::from_secret_key(secp, &self.private_key);
            data.extend_from_slice(&pk.serialize());
        }
        data.extend_from_slice(&child.to_u32().to_be_bytes());

        let I = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        il.copy_from_slice(&I[..32]);
        let mut ir = [0u8; 32];
        ir.copy_from_slice(&I[32..]);

        // child key = parse256(IL) + kpar (mod n)
        let mut sk = SecretKey::from_slice(&il).map_err(|_| HdError::Secp256k1)?;
        sk.add_assign(&self.private_key[..]).map_err(|_| HdError::Secp256k1)?;

        let parent_pub = PublicKey::from_secret_key(secp, &self.private_key);
        let fp = fingerprint_from_pubkey(&parent_pub);

        Ok(Self {
            depth: self.depth + 1,
            parent_fingerprint: fp,
            child_number: child.to_u32(),
            chain_code: ir,
            private_key: sk,
        })
    }

    /// Serialize to xprv Base58Check (78-byte payload).
    pub fn to_xprv(&self, network: Network) -> String {
        let vers = versions_for(network).xprv;
        let mut payload = Vec::with_capacity(78);
        payload.extend_from_slice(&self.depth.to_be_bytes()); // depth (1B)
        payload.extend_from_slice(&self.parent_fingerprint);  // parent fp (4B)
        payload.extend_from_slice(&self.child_number.to_be_bytes()); // child number (4B)
        payload.extend_from_slice(&self.chain_code); // chain code (32B)
        payload.push(0u8); // leading zero for private key
        payload.extend_from_slice(&self.private_key[..]); // 32B
        base58check_encode(vers, &payload)
    }

    /// Derive along a full path.
    pub fn derive_path(&self, secp: &Secp256k1<All>, path: &DerivationPath) -> Result<Self, HdError> {
        let mut x = self.clone();
        for c in path.as_ref() {
            x = x.ckd_priv(secp, *c)?;
        }
        Ok(x)
    }
}

impl ExtendedPubKey {
    /// CKDpub (non-hardened only)
    pub fn ckd_pub(&self, secp: &Secp256k1<All>, child: ChildNumber) -> Result<Self, HdError> {
        if child.hardened() {
            return Err(HdError::Unsupported);
        }
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.public_key.serialize());
        data.extend_from_slice(&child.to_u32().to_be_bytes());

        let I = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        il.copy_from_slice(&I[..32]);
        let mut ir = [0u8; 32];
        ir.copy_from_slice(&I[32..]);

        let tweak = SecretKey::from_slice(&il).map_err(|_| HdError::Secp256k1)?;
        let mut pk = self.public_key;
        pk.add_exp_assign(secp, &tweak[..]).map_err(|_| HdError::Secp256k1)?;

        let fp = self.parent_fingerprint;

        Ok(Self {
            depth: self.depth + 1,
            parent_fingerprint: fp,
            child_number: child.to_u32(),
            chain_code: ir,
            public_key: pk,
        })
    }

    /// Serialize to xpub Base58Check.
    pub fn to_xpub(&self, network: Network) -> String {
        let vers = versions_for(network).xpub;
        let mut payload = Vec::with_capacity(78);
        payload.extend_from_slice(&self.depth.to_be_bytes()); // 1B
        payload.extend_from_slice(&self.parent_fingerprint);  // 4B
        payload.extend_from_slice(&self.child_number.to_be_bytes()); // 4B
        payload.extend_from_slice(&self.chain_code); // 32B
        payload.extend_from_slice(&self.public_key.serialize()); // 33B
        base58check_encode(vers, &payload)
    }
}

/// High-level HD wallet facade
pub struct HdWallet {
    secp: Secp256k1<All>,
    network: Network,
    root: ExtendedPrivKey,
}

impl HdWallet {
    /// Generate new mnemonic and wallet with random entropy (128/256 bits).
    pub fn generate(network: Network, strength_bits: usize, passphrase: Option<&str>) -> (String, Self) {
        let ty = match strength_bits {
            128 => MnemonicType::Words12,
            160 => MnemonicType::Words15,
            192 => MnemonicType::Words18,
            224 => MnemonicType::Words21,
            256 => MnemonicType::Words24,
            _ => MnemonicType::Words12,
        };
        let mut entropy = vec![0u8; ty.entropy_bits() / 8];
        rand::thread_rng().fill_bytes(&mut entropy);

        let mnemonic = Bip39Mnemonic::from_entropy_in(Language::English, &entropy)
            .expect("entropy size matched mnemonic type");
        let phrase = mnemonic.to_string();

        let seed = wallet_seed(&mnemonic, passphrase.unwrap_or(""));
        let root = ExtendedPrivKey::from_seed(seed.as_bytes()).expect("seed to root xprv");
        let secp = Secp256k1::new();
        (phrase, Self { secp, network, root })
    }

    /// Restore from mnemonic phrase.
    pub fn from_mnemonic(network: Network, phrase: &str, passphrase: Option<&str>) -> Result<Self, HdError> {
        let mnemonic = Bip39Mnemonic::from_str(phrase).map_err(|_| HdError::InvalidLen)?;
        let seed = wallet_seed(&mnemonic, passphrase.unwrap_or(""));
        let root = ExtendedPrivKey::from_seed(seed.as_bytes()).map_err(|_| HdError::InvalidLen)?;
        Ok(Self { secp: Secp256k1::new(), network, root })
    }

    /// Master xprv/xpub
    pub fn master_xprv(&self) -> String {
        self.root.to_xprv(self.network)
    }
    pub fn master_xpub(&self) -> String {
        self.root.to_extended_pub(&self.secp).to_xpub(self.network)
    }

    /// Derive child private/public at path.
    pub fn derive_xprv(&self, path: &DerivationPath) -> Result<ExtendedPrivKey, HdError> {
        self.root.derive_path(&self.secp, path)
    }
    pub fn derive_xpub(&self, path: &DerivationPath) -> Result<ExtendedPubKey, HdError> {
        let xprv = self.root.derive_path(&self.secp, path)?;
        Ok(xprv.to_extended_pub(&self.secp))
    }

    /// BTC bech32 P2WPKH address (v0)
    pub fn btc_p2wpkh_address(&self, path: &DerivationPath) -> Result<String, HdError> {
        let xpub = self.derive_xpub(path)?;
        let hrp = self.network.btc_hrp()?;
        let pubkey_hash = hash160(&xpub.public_key.serialize());
        let mut prog = Vec::with_capacity(1 + 20);
        // witness version 0 -> bech32 with program as 20 bytes
        let data = std::iter::once(u5::try_from_u8(0).map_err(|_| HdError::AddressEncoding)?)
            .chain(pubkey_hash.to_base32())
            .collect::<Vec<_>>();
        bech32::encode(hrp, data, Variant::Bech32).map_err(|_| HdError::AddressEncoding)
    }

    /// ETH EIP-55 address (0x + 40 hex, checksummed)
    pub fn eth_address(&self, path: &DerivationPath) -> Result<String, HdError> {
        if self.network != Network::Ethereum {
            return Err(HdError::Unsupported);
        }
        let xpub = self.derive_xpub(path)?;
        // uncompressed pubkey (skip 0x04 prefix) → keccak256 → last 20 bytes
        let uncompressed = xpub.public_key.serialize_uncompressed();
        let mut keccak = Keccak::v256();
        let mut out = [0u8; 32];
        keccak.update(&uncompressed[1..]);
        keccak.finalize(&mut out);
        let addr_bytes = &out[12..]; // 20 bytes

        // EIP-55 checksum
        let hex_lower = hex_lower(addr_bytes);
        let mut keccak2 = Keccak::v256();
        let mut eip = [0u8; 32];
        keccak2.update(hex_lower.as_bytes());
        keccak2.finalize(&mut eip);
        let mut checksummed = String::with_capacity(42);
        checksummed.push_str("0x");
        for (i, ch) in hex_lower.chars().enumerate() {
            let v = (eip[i / 2] >> (4 * (1 - (i % 2)))) & 0x0f;
            if ch.is_ascii_hexdigit() && ch.is_ascii_lowercase() && v >= 8 {
                checksummed.push(ch.to_ascii_uppercase());
            } else {
                checksummed.push(ch);
            }
        }
        Ok(checksummed)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble_hex(b >> 4));
        s.push(nibble_hex(b & 0x0f));
    }
    s
}
fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

/// BIP39 seed (PBKDF2-HMAC-SHA512 over mnemonic+passphrase)
fn wallet_seed(m: &Bip39Mnemonic, passphrase: &str) -> Bip39Seed {
    // bip39::Seed already implements spec derivation, but provide explicit call for clarity
    Bip39Seed::new(m, passphrase)
}

/// Helper: build common BIP44 path
pub fn bip44_path(coin_type: u32, account: u32, change: u32, index: u32) -> DerivationPath {
    // m/44'/coin'/account'/change/index
    DerivationPath::new(vec![
        ChildNumber::new(44, true),
        ChildNumber::new(coin_type, true),
        ChildNumber::new(account, true),
        ChildNumber::new(change, false),
        ChildNumber::new(index, false),
    ])
}

/// Standard coin types (SLIP-44 subset)
pub mod coin {
    pub const BTC: u32 = 0;
    pub const TESTNET: u32 = 1;
    pub const ETH: u32 = 60;
}

/* --------------------------------- Tests ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_paths() {
        let p: DerivationPath = "m/44'/0'/0'/0/0".parse().unwrap();
        assert_eq!(p.as_ref().len(), 5);
        assert!(p.as_ref()[0].hardened());
        assert!(!p.as_ref()[3].hardened());
    }

    #[test]
    fn master_xpub_roundtrip_versions() {
        // deterministic seed from known mnemonic (English)
        let mnemonic = Bip39Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Language::English).unwrap();
        let seed = wallet_seed(&mnemonic, "");
        let root = ExtendedPrivKey::from_seed(seed.as_bytes()).unwrap();
        let secp = Secp256k1::new();
        let xpub = root.to_extended_pub(&secp);
        let xpub_str = xpub.to_xpub(Network::Bitcoin);
        // decode back version
        let (ver, _payload) = super::base58check_decode(&xpub_str).unwrap();
        assert_eq!(ver, super::versions_for(Network::Bitcoin).xpub);
    }

    #[test]
    fn btc_bech32_address_shape() {
        let (_phrase, w) = HdWallet::generate(Network::Bitcoin, 128, Some(""));
        let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap_or_else(|_| bip44_path(coin::BTC, 0, 0, 0)); // fallback to 44' if needed
        let addr = w.btc_p2wpkh_address(&path).unwrap();
        assert!(addr.starts_with("bc1"));
        assert!(addr.len() >= 14);
    }

    #[test]
    fn eth_address_eip55_len() {
        let (_phrase, w) = HdWallet::generate(Network::Ethereum, 128, Some(""));
        let path = bip44_path(coin::ETH, 0, 0, 0);
        let addr = w.eth_address(&path).unwrap();
        assert!(addr.starts_with("0x") && addr.len() == 42);
    }
}

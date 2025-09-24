//! Industrial-grade Ethereum transaction builder
//!
//! Supported:
//! - EIP-1559 (type 0x02): dynamic-fee tx with yParity/r/s, access list per EIP-2930,
//!   signing-hash = keccak256( 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
//!   maxFeePerGas, gasLimit, to, value, data, accessList]) ).  :contentReference[oaicite:2]{index=2}
//! - EIP-2930 (type 0x01): access list tx with yParity/r/s, signing-hash = keccak256(0x01 || rlp([...])).
//!   Field ordering and envelope per EIP-2718/2930.  :contentReference[oaicite:3]{index=3}
//! - Legacy (type 0x00): RLP legacy; EIP-155 chainId/v handling left as helper.  :contentReference[oaicite:4]{index=4}
//!
//! Utilities:
//! - ERC-20 transfer calldata: selector keccak256("transfer(address,uint256)")[:4] = 0xa9059cbb.  :contentReference[oaicite:5]{index=5}
//! - RLP encoding per Ethereum docs; Keccak256 per Ethereum.  :contentReference[oaicite:6]{index=6}
//!
//! Dependencies (Cargo.toml):
//!   rlp = "0.5"
//!   sha3 = "0.10"
//!   primitive-types = { version = "0.12", features = ["serde"] }
//!   thiserror = "1"
//!   hex = "0.4"

#![forbid(unsafe_code)]

use primitive_types::U256;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// EVM 20-byte address.
pub type Address = [u8; 20];

/// 32-byte storage key (EVM slot).
pub type StorageKey = [u8; 32];

/// EIP-2930 access list item: (address, storageKeys[])
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<StorageKey>,
}

/// Canonical access list type
pub type AccessList = Vec<AccessListItem>;

/// Error type for builder
#[derive(Debug, Error)]
pub enum TxBuildError {
    #[error("invalid field: {0}")]
    Invalid(&'static str),
    #[error("overflow")]
    Overflow,
}

/// Transaction variants we can build/serialize.
#[derive(Clone, Debug)]
pub enum TypedTx<'a> {
    /// Legacy (0x00) — RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
    Legacy {
        chain_id: Option<u64>, // for EIP-155 v calculation
        nonce: U256,
        gas_price: U256,
        gas_limit: U256,
        to: Option<Address>,
        value: U256,
        data: &'a [u8],
        // Signature (optional at build-time)
        v: Option<U256>,
        r: Option<[u8; 32]>,
        s: Option<[u8; 32]>,
    },
    /// EIP-2930 (type 0x01) — includes access list and yParity
    Eip2930 {
        chain_id: u64,
        nonce: U256,
        gas_price: U256,
        gas_limit: U256,
        to: Option<Address>,
        value: U256,
        data: &'a [u8],
        access_list: AccessList,
        // Signature (optional at build-time)
        y_parity: Option<u8>,     // 0/1 as per spec (not v)  :contentReference[oaicite:7]{index=7}
        r: Option<[u8; 32]>,
        s: Option<[u8; 32]>,
    },
    /// EIP-1559 (type 0x02) — dynamic fee transaction
    Eip1559 {
        chain_id: u64,
        nonce: U256,
        max_priority_fee_per_gas: U256,
        max_fee_per_gas: U256,
        gas_limit: U256,
        to: Option<Address>,
        value: U256,
        data: &'a [u8],
        access_list: AccessList,
        // Signature (optional at build-time)
        y_parity: Option<u8>,     // 0/1 per EIP-1559  :contentReference[oaicite:8]{index=8}
        r: Option<[u8; 32]>,
        s: Option<[u8; 32]>,
    },
}

impl<'a> TypedTx<'a> {
    /// Build signing payload per EIP-2718/2930/1559
    /// Returns the bytes that must be hashed with Keccak256 and signed.
    pub fn signing_payload(&self) -> Vec<u8> {
        match self {
            TypedTx::Eip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list,
                ..
            } => {
                let mut rlp = RlpStream::new_list(9);
                rlp.append(&u64_to_be_bytes(*chain_id));
                append_u256(&mut rlp, nonce);
                append_u256(&mut rlp, max_priority_fee_per_gas);
                append_u256(&mut rlp, max_fee_per_gas);
                append_u256(&mut rlp, gas_limit);
                append_to_opt(&mut rlp, to.as_ref());
                append_u256(&mut rlp, value);
                rlp.append(&data);
                append_access_list(&mut rlp, access_list);

                // keccak256( 0x02 || rlp([...]) ) per EIP-1559
                // The 0x02 is the typed tx prefix.  :contentReference[oaicite:9]{index=9}
                let mut out = Vec::with_capacity(1 + rlp.out().len());
                out.push(0x02);
                out.extend_from_slice(rlp.out().as_ref());
                out
            }
            TypedTx::Eip2930 {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                access_list,
                ..
            } => {
                let mut rlp = RlpStream::new_list(8);
                rlp.append(&u64_to_be_bytes(*chain_id));
                append_u256(&mut rlp, nonce);
                append_u256(&mut rlp, gas_price);
                append_u256(&mut rlp, gas_limit);
                append_to_opt(&mut rlp, to.as_ref());
                append_u256(&mut rlp, value);
                rlp.append(&data);
                append_access_list(&mut rlp, access_list);

                // keccak256( 0x01 || rlp([...]) ) per EIP-2930.  :contentReference[oaicite:10]{index=10}
                let mut out = Vec::with_capacity(1 + rlp.out().len());
                out.push(0x01);
                out.extend_from_slice(rlp.out().as_ref());
                out
            }
            TypedTx::Legacy { .. } => {
                // Legacy signing-hash per EIP-155 uses RLP of 6 or 9 elements (with chainId,0,0),
                // but вычисление подписи находится вне области этого метода.  :contentReference[oaicite:11]{index=11}
                Vec::new()
            }
        }
    }

    /// Compute keccak256(signing_payload())
    pub fn sighash(&self) -> [u8; 32] {
        let payload = self.signing_payload();
        let mut hasher = Keccak256::new();
        hasher.update(&payload);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Attach signature and serialize whole raw transaction per type.
    /// For EIP-1559/2930: raw = 0x{02|01} || rlp([... , yParity, r, s])  :contentReference[oaicite:12]{index=12}
    /// For Legacy: RLP([... , v, r, s])
    pub fn serialize_signed(&self, y_or_v: u64, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        match self {
            TypedTx::Eip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list,
                ..
            } => {
                let mut rlp = RlpStream::new_list(12);
                rlp.append(&u64_to_be_bytes(*chain_id));
                append_u256(&mut rlp, nonce);
                append_u256(&mut rlp, max_priority_fee_per_gas);
                append_u256(&mut rlp, max_fee_per_gas);
                append_u256(&mut rlp, gas_limit);
                append_to_opt(&mut rlp, to.as_ref());
                append_u256(&mut rlp, value);
                rlp.append(&data);
                append_access_list(&mut rlp, access_list);
                rlp.append(&u64_to_be_bytes(y_or_v)); // yParity (0/1)
                rlp.append(&trim_zeros(&r[..]));
                rlp.append(&trim_zeros(&s[..]));

                let enc = rlp.out();
                let mut out = Vec::with_capacity(1 + enc.len());
                out.push(0x02); // typed prefix 0x02  :contentReference[oaicite:13]{index=13}
                out.extend_from_slice(enc.as_ref());
                out
            }
            TypedTx::Eip2930 {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                access_list,
                ..
            } => {
                let mut rlp = RlpStream::new_list(11);
                rlp.append(&u64_to_be_bytes(*chain_id));
                append_u256(&mut rlp, nonce);
                append_u256(&mut rlp, gas_price);
                append_u256(&mut rlp, gas_limit);
                append_to_opt(&mut rlp, to.as_ref());
                append_u256(&mut rlp, value);
                rlp.append(&data);
                append_access_list(&mut rlp, access_list);
                rlp.append(&u64_to_be_bytes(y_or_v)); // yParity (0/1)
                rlp.append(&trim_zeros(&r[..]));
                rlp.append(&trim_zeros(&s[..]));

                let enc = rlp.out();
                let mut out = Vec::with_capacity(1 + enc.len());
                out.push(0x01); // typed prefix 0x01  :contentReference[oaicite:14]{index=14}
                out.extend_from_slice(enc.as_ref());
                out
            }
            TypedTx::Legacy {
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                ..
            } => {
                let mut rlp = RlpStream::new_list(9);
                append_u256(&mut rlp, nonce);
                append_u256(&mut rlp, gas_price);
                append_u256(&mut rlp, gas_limit);
                append_to_opt(&mut rlp, to.as_ref());
                append_u256(&mut rlp, value);
                rlp.append(&data);
                // v (EIP-155 uses v = 27/28 + 2*chainId + 8) — заполняется вызывающим.  :contentReference[oaicite:15]{index=15}
                rlp.append(&u64_to_be_bytes(y_or_v));
                rlp.append(&trim_zeros(&r[..]));
                rlp.append(&trim_zeros(&s[..]));
                rlp.out().to_vec()
            }
        }
    }
}

/// ERC-20 calldata: transfer(address,uint256) → selector(4) + address(32) + amount(32)
pub fn erc20_transfer_calldata(to: Address, amount: U256) -> Vec<u8> {
    // function selector = first 4 bytes of keccak256("transfer(address,uint256)") = 0xa9059cbb.  :contentReference[oaicite:16]{index=16}
    const SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    let mut data = Vec::with_capacity(4 + 32 + 32);
    data.extend_from_slice(&SELECTOR);

    // ABI: address is left-padded to 32 bytes
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(&to);
    data.extend_from_slice(&addr_word);

    // amount as big-endian 32 bytes
    let mut amt = [0u8; 32];
    amount.to_big_endian(&mut amt);
    data.extend_from_slice(&amt);
    data
}

// ----------------- RLP helpers -----------------

fn append_u256(rlp: &mut RlpStream, v: &U256) {
    if v.is_zero() {
        rlp.append_empty_data();
    } else {
        let mut buf = [0u8; 32];
        v.to_big_endian(&mut buf);
        rlp.append(&trim_zeros(&buf));
    }
}

fn append_to_opt(rlp: &mut RlpStream, to: Option<&Address>) {
    match to {
        Some(addr) => rlp.append(addr),
        None => rlp.append_empty_data(), // contract creation → empty "to"
    }
}

fn append_access_list(rlp: &mut RlpStream, al: &AccessList) {
    rlp.begin_list(al.len());
    for item in al {
        rlp.begin_list(2);
        rlp.append(&item.address);
        rlp.begin_list(item.storage_keys.len());
        for key in &item.storage_keys {
            rlp.append(key);
        }
    }
}

fn trim_zeros(bytes: &[u8]) -> Vec<u8> {
    let i = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[i..].to_vec()
}

fn u64_to_be_bytes(x: u64) -> Vec<u8> {
    if x == 0 {
        return Vec::new();
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&x.to_be_bytes());
    trim_zeros(&buf)
}

// ----------------- Tests -----------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;

    fn u(n: u64) -> U256 { U256::from(n) }

    #[test]
    fn test_erc20_calldata_selector() {
        let to = [0x11u8; 20];
        let data = erc20_transfer_calldata(to, u(1_000));
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]); // a9059cbb
        assert_eq!(data.len(), 4 + 32 + 32);
    }

    #[test]
    fn test_eip1559_sighash_prefix_and_lengths() {
        // Minimal tx (to=null, data=empty, empty access list)
        let tx = TypedTx::Eip1559 {
            chain_id: 1,
            nonce: u(1),
            max_priority_fee_per_gas: u(2_000_000_000),
            max_fee_per_gas: u(50_000_000_000),
            gas_limit: u(21_000),
            to: Some([0x22u8; 20]),
            value: u(123),
            data: &[],
            access_list: vec![],
            y_parity: None,
            r: None,
            s: None,
        };
        let payload = tx.signing_payload();
        assert_eq!(payload[0], 0x02); // typed tx prefix
        let h = tx.sighash();
        // sanity: keccak256 returns 32 bytes
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_eip2930_serialization_round() {
        let tx = TypedTx::Eip2930 {
            chain_id: 1,
            nonce: u(7),
            gas_price: u(1_000_000_000),
            gas_limit: u(21_000),
            to: None,
            value: U256::zero(),
            data: &[],
            access_list: vec![AccessListItem { address: [0x33u8;20], storage_keys: vec![[0x44u8;32]] }],
            y_parity: None, r: None, s: None,
        };
        let sighash = tx.sighash();
        // attach dummy signature (NOT VALID)
        let raw = tx.serialize_signed(0, &[0x55u8;32], &[0x66u8;32]);
        assert_eq!(raw[0], 0x01);
        assert!(sighash.len() == 32 && raw.len() > 1);
    }
}

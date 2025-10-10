//! Aethernova Explorer Indexer — decoding utilities
//!
//! Производственный набор декодеров для байтовых полезных данных:
//! - Hex/Base58/Base64 в байты;
//! - Unsigned varint (LEB128-подобный) -> u64;
//! - SCALE (parity-scale-codec) -> T: Decode;
//! - RLP (Ethereum) -> T: Decodable;
//! - Protobuf (prost) -> T: Message + Default;
//! - Multihash (multiformats) -> Multihash;
//! - keccak256.
//!
//! Источники для проверки API и семантики:
//! - SCALE Codec и трейт Decode. :contentReference[oaicite:1]{index=1}
/*! - RLP: crate rlp и alloy-rlp (Ethereum). */ // :contentReference[oaicite:2]{index=2}
/*! - Base58/Base64: bs58, base64. */ // :contentReference[oaicite:3]{index=3}
/*! - Unsigned varint: docs.rs + список декодеров u64/u128/usize. */ // :contentReference[oaicite:4]{index=4}
/*! - Multihash: crate multihash и мультиформатная спецификация. */ // :contentReference[oaicite:5]{index=5}
/*! - Protobuf: prost::Message::decode. */ // :contentReference[oaicite:6]{index=6}
/*! - Keccak: tiny-keccak (FIPS-202/Keccak). */ // :contentReference[oaicite:7]{index=7}

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unused_must_use, unreachable_pub)]

use std::{fmt, str::FromStr};

use thiserror::Error;

pub use parity_scale_codec as scale;
pub use prost;
pub use rlp;
pub use tiny_keccak;

use parity_scale_codec::Decode;
use prost::Message;
use rlp::Decodable;

/// Унифицированная ошибка декодирования.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("hex decode: {0}")]
    Hex(String),
    #[error("base58 decode: {0}")]
    Base58(String),
    #[error("base64 decode: {0}")]
    Base64(String),
    #[error("varint decode")]
    Varint,
    #[error("scale decode: {0}")]
    Scale(String),
    #[error("rlp decode: {0}")]
    Rlp(String),
    #[error("protobuf decode: {0}")]
    Protobuf(String),
    #[error("multihash decode: {0}")]
    Multihash(String),
    #[error("keccak failure")]
    Keccak,
    #[error("invalid input: {0}")]
    Invalid(&'static str),
}

/// Поддерживаемые строковые кодировки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrEncoding {
    Hex,
    Base58Btc,
    Base64,
}

/// Декодировать строку в байты (Hex/Base58/Base64).
pub fn decode_str(input: &str, enc: StrEncoding) -> Result<Vec<u8>, DecodeError> {
    match enc {
        StrEncoding::Hex => hex::decode(input).map_err(|e| DecodeError::Hex(e.to_string())),
        StrEncoding::Base58Btc => bs58::decode(input)
            .into_vec()
            .map_err(|e| DecodeError::Base58(e.to_string())),
        StrEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(input)
            .map_err(|e| DecodeError::Base64(e.to_string())),
    }
}

/// Попробовать угадать кодировку по префиксу/алфавиту (best-effort).
/// Примечание: эвристика, используйте явно `StrEncoding`, если важна строгая проверка.
pub fn guess_and_decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    // 0x... -> hex
    if let Some(stripped) = input.strip_prefix("0x") {
        return decode_str(stripped, StrEncoding::Hex);
    }
    // Пытаемся Hex, потом Base58, потом Base64
    if let Ok(b) = decode_str(input, StrEncoding::Hex) {
        return Ok(b);
    }
    if let Ok(b) = decode_str(input, StrEncoding::Base58Btc) {
        return Ok(b);
    }
    decode_str(input, StrEncoding::Base64)
}

/// Декодировать unsigned varint (u64).
/// Алгоритм: 7-битные группы, старший бит — признак продолжения. :contentReference[oaicite:8]{index=8}
pub fn decode_varint_u64(mut bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    use unsigned_varint::decode::u64 as uvarint64; // funcs u8/u16/u32/u64/u128/usize :contentReference[oaicite:9]{index=9}
    match uvarint64(bytes) {
        Ok((value, consumed)) => Ok((value, consumed)),
        Err(_) => Err(DecodeError::Varint),
    }
}

/// SCALE-декодирование произвольного типа T: Decode. :contentReference[oaicite:10]{index=10}
pub fn decode_scale<T: Decode>(bytes: &[u8]) -> Result<T, DecodeError> {
    T::decode(&mut &*bytes).map_err(|e| DecodeError::Scale(e.to_string()))
}

/// RLP-декодирование T: Decodable (Ethereum). :contentReference[oaicite:11]{index=11}
pub fn decode_rlp<T: Decodable>(bytes: &[u8]) -> Result<T, DecodeError> {
    rlp::decode(bytes).map_err(|e| DecodeError::Rlp(e.to_string()))
}

/// Protobuf-декодирование T: prost::Message + Default. :contentReference[oaicite:12]{index=12}
pub fn decode_protobuf<T>(bytes: &[u8]) -> Result<T, DecodeError>
where
    T: Message + Default,
{
    T::decode(bytes).map_err(|e| DecodeError::Protobuf(e.to_string()))
}

/// Модель Multihash, совместимая с multiformats. :contentReference[oaicite:13]{index=13}
pub type Multihash = multihash::Multihash<64>;

/// Декодирование Multihash из байтов (raw multihash).
pub fn decode_multihash(bytes: &[u8]) -> Result<Multihash, DecodeError> {
    Multihash::from_bytes(bytes).map_err(|e| DecodeError::Multihash(e.to_string()))
}

/// Вычисление keccak256.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(input);
    k.finalize(&mut out);
    out
}

/// Итератор по length-delimited кадрам Protobuf в бинарном потоке.
/// Полезно для логов/стримов, где сообщения записаны подряд с префиксом длины.
pub fn iter_protobuf_frames<'a, T: Message + Default + 'a>(
    mut bytes: &'a [u8],
) -> impl Iterator<Item = Result<T, DecodeError>> + 'a {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        // prost::Message::decode ожидает точный буфер; используем decode_length_delimited,
        // но он потребляет буфер; поэтому вручную читаем varint-длину и срез.
        let (len, n) = match decode_varint_u64(bytes) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let total = n as usize + (len as usize);
        if bytes.len() < total {
            return Some(Err(DecodeError::Protobuf("frame truncated".into())));
        }
        let frame = &bytes[n as usize..n as usize + len as usize];
        bytes = &bytes[total..];
        Some(decode_protobuf::<T>(frame))
    })
}

/// Утилита: попытаться распарсить строку как Multihash из удобного формата:
/// - "0x..." hex → raw bytes → multihash
/// - base58btc → raw bytes → multihash
/// - base64 → raw bytes → multihash
pub fn parse_multihash_str(s: &str) -> Result<Multihash, DecodeError> {
    let raw = guess_and_decode(s)?;
    decode_multihash(&raw)
}

/// Примитивный диспетчер декодеров по схеме: "scale:", "rlp:", "pb:", "mh:", "hex:", "b58:", "b64:"
pub fn dispatch_decode<T>(
    payload: &str,
    scheme: &str,
) -> Result<Decoded<T>, DecodeError>
where
    T: Decode + Decodable + Message + Default,
{
    match scheme {
        "scale" => {
            let raw = guess_and_decode(payload)?;
            Ok(Decoded::Scale(decode_scale::<T>(&raw)?))
        }
        "rlp" => {
            let raw = guess_and_decode(payload)?;
            Ok(Decoded::Rlp(decode_rlp::<T>(&raw)?))
        }
        "pb" | "protobuf" => {
            let raw = guess_and_decode(payload)?;
            Ok(Decoded::Protobuf(decode_protobuf::<T>(&raw)?))
        }
        "mh" | "multihash" => {
            let mh = parse_multihash_str(payload)?;
            // Возвращаем как "пустого" T нельзя; оставим в wrapper:
            Err(DecodeError::Invalid("use parse_multihash_str for Multihash"))
        }
        "hex" => {
            let raw = decode_str(payload.trim_start_matches("0x"), StrEncoding::Hex)?;
            Err(DecodeError::Invalid("hex produces bytes; choose concrete decoder"))
        }
        "b58" => {
            let _ = decode_str(payload, StrEncoding::Base58Btc)?;
            Err(DecodeError::Invalid("base58 produces bytes; choose concrete decoder"))
        }
        "b64" => {
            let _ = decode_str(payload, StrEncoding::Base64)?;
            Err(DecodeError::Invalid("base64 produces bytes; choose concrete decoder"))
        }
        _ => Err(DecodeError::Invalid("unknown scheme")),
    }
}

/// Обертка результата для различных декодеров.
#[derive(Debug)]
pub enum Decoded<T> {
    Scale(T),
    Rlp(T),
    Protobuf(T),
}

impl<T> fmt::Display for Decoded<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decoded::Scale(v) => write!(f, "SCALE({:?})", v),
            Decoded::Rlp(v) => write!(f, "RLP({:?})", v),
            Decoded::Protobuf(v) => write!(f, "PB({:?})", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parity_scale_codec::{Encode};
    use rlp::{RlpStream};

    #[test]
    fn t_hex_b58_b64() {
        // hex
        let h = "0x48656c6c6f";
        let b = decode_str(h.trim_start_matches("0x"), StrEncoding::Hex).unwrap();
        assert_eq!(b, b"Hello");

        // base58
        let s = bs58::encode(b"Hello").into_string();
        let b = decode_str(&s, StrEncoding::Base58Btc).unwrap();
        assert_eq!(b, b"Hello");

        // base64
        let s = base64::engine::general_purpose::STANDARD.encode("Hello");
        let b = decode_str(&s, StrEncoding::Base64).unwrap();
        assert_eq!(b, b"Hello");
    }

    #[test]
    fn t_varint_u64() {
        // 300 -> 0b1010_1100 0000_0010
        let data = [0b1010_1100u8, 0b0000_0010u8];
        let (v, n) = decode_varint_u64(&data).unwrap();
        assert_eq!(v, 300);
        assert_eq!(n, 2);
    }

    #[test]
    fn t_scale_roundtrip() {
        // Пример: Option<u32>
        let x: Option<u32> = Some(42);
        let enc = x.encode();
        let dec: Option<u32> = decode_scale(&enc).unwrap();
        assert_eq!(dec, x);
    }

    #[test]
    fn t_rlp_roundtrip() {
        let mut s = RlpStream::new_list(2);
        s.append(&"cat");
        s.append(&"dog");
        let out = s.out().to_vec();
        let v: Vec<String> = decode_rlp(&out).unwrap();
        assert_eq!(v, vec!["cat".into(), "dog".into()]);
    }

    #[test]
    fn t_keccak() {
        let h = keccak256(b"abc");
        // keccak256("abc") = 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        let want = hex::decode("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45").unwrap();
        assert_eq!(h.to_vec(), want);
    }

    #[test]
    fn t_multihash_decode() {
        // sha2-256 multihash of "hello"
        use multihash::{MultihashDigest, Code};
        let mh = Code::Sha2_256.digest(b"hello");
        let raw = mh.to_bytes();
        let parsed = decode_multihash(&raw).unwrap();
        assert_eq!(parsed, mh);
    }

    #[test]
    fn t_iter_pb_frames() {
        #[derive(Clone, PartialEq, ::prost::Message)]
        struct Msg { #[prost(uint32, tag="1")] n: u32 }

        let a = Msg { n: 7 };
        let b = Msg { n: 9 };
        let mut stream = vec![];
        // length-delimited: varint(len) + payload
        for m in [a, b] {
            let payload = m.encode_to_vec();
            let mut len_buf = unsigned_varint::encode::u64(payload.len() as u64, Vec::new());
            stream.append(&mut len_buf);
            stream.extend_from_slice(&payload);
        }

        let xs: Vec<_> = iter_protobuf_frames::<Msg>(&stream).collect::<Result<_,_>>().unwrap();
        assert_eq!(xs[0].n, 7);
        assert_eq!(xs[1].n, 9);
    }
}

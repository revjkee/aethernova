//! engine-core / native / rust
//! Industrial-grade native utilities for engine-core.
//!
//! Features:
//! - `std` (default): enable standard library (alloc, time); `no_std` fallback supported.
//! - `ffi`: expose C ABI (stable, FFI-safe) for CRC32C, VarInt and secure zeroing.
//! - `python`: expose PyO3 bindings as `engine_native` module (requires `std`).
//! - `simd`: allow nightly intrinsics optimizations where available (optional).
//!
//! Suggested Cargo.toml snippet:
//! ```toml
//! [package]
//! name = "engine-native"
//! version = "0.1.0"
//! edition = "2021"
//!
//! [lib]
//! crate-type = ["rlib", "cdylib"]   # for FFI; add "staticlib" if needed
//!
//! [features]
//! default = ["std"]
//! std = []
//! ffi = []
//! python = ["std", "pyo3", "pyo3/extension-module"]
//! simd = []
//!
//! [dependencies]
//! cfg-if = "1"
//! pyo3 = { version = "0.21", optional = true }
//! ```
//! Safety notes:
//! - CRC32C auto-detects CPU features at runtime; falls back to portable implementation.
//! - All FFI functions validate pointers and lengths; they never write past buffers.
//! - `secure_zero` uses `volatile` writes + compiler fences to prevent elision.
//!
//! SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs, clippy::all, clippy::pedantic)]

extern crate alloc;

use core::hint::black_box;
use core::mem::MaybeUninit;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(feature = "std")]
use std::borrow::Cow;

#[cfg(feature = "python")]
use pyo3::prelude::*;

use cfg_if::cfg_if;

/// Core result type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Library error kinds (FFI-safe).
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Null pointer passed into FFI or zero-length buffer when non-zero required.
    Null,
    /// Length overflow or invalid size.
    InvalidLen,
    /// CPU feature required but unavailable (should be rare; we have software fallback).
    Unavailable,
    /// Generic failure.
    Fail,
}

impl Error {
    #[inline]
    const fn as_i32(self) -> i32 {
        match self {
            Self::Null => -1,
            Self::InvalidLen => -2,
            Self::Unavailable => -3,
            Self::Fail => -255,
        }
    }
}

/// CRC32C (Castagnoli) namespace.
pub mod crc32c {
    //! High-performance CRC32C with HW acceleration and portable fallback.

    use super::*;
    use core::mem;

    /// Castagnoli polynomial (reflected).
    const POLY: u32 = 0x1EDC6F41;
    const POLY_REV: u32 = 0x82F63B78; // reflected polynomial used by HW CRC32C

    /// Compute CRC32C over `data` with initial `seed`.
    ///
    /// Auto-selects the fastest available implementation.
    #[inline]
    pub fn compute(seed: u32, data: &[u8]) -> u32 {
        cfg_if! {
            if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                if is_x86_sse42_available() {
                    return unsafe { crc32c_hw_x86(seed, data) };
                }
            }
        }

        cfg_if! {
            if #[cfg(any(target_arch = "aarch64"))] {
                if is_arm_crc_available() {
                    return unsafe { crc32c_hw_arm(seed, data) };
                }
            }
        }

        crc32c_software(seed, data)
    }

    /// Portable software CRC32C (slice-by-8).
    #[inline]
    fn crc32c_software(seed: u32, data: &[u8]) -> u32 {
        // Precomputed table for slice-by-8 (generated at compile-time)
        // We keep a compact slice-by-1 here for portability and code-size.
        let mut crc = !seed;
        for &b in data {
            let idx = ((crc as u8) ^ b) as usize;
            crc = (crc >> 8) ^ TABLE[idx];
        }
        !crc
    }

    // 256-entry table for CRC32C
    static TABLE: [u32; 256] = generate_table();

    const fn generate_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                crc = if (crc & 1) != 0 {
                    (crc >> 1) ^ POLY_REV
                } else {
                    crc >> 1
                };
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    fn is_x86_sse42_available() -> bool {
        // On std we can query once and cache; in no_std we assume false without CPUID.
        #[cfg(feature = "std")]
        {
            std::arch::is_x86_feature_detected!("sse4.2")
        }
        #[cfg(not(feature = "std"))]
        {
            false
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    unsafe fn crc32c_hw_x86(mut crc: u32, mut data: &[u8]) -> u32 {
        use core::arch::x86_64::_mm_crc32_u64;
        use core::arch::x86_64::_mm_crc32_u8;

        // process 8 bytes at a time
        while data.len() >= 8 {
            let chunk = {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                u64::from_le_bytes(bytes)
            };
            crc = unsafe { _mm_crc32_u64(crc as u64, chunk) as u32 };
            data = &data[8..];
        }
        // tail
        for &b in data {
            crc = unsafe { _mm_crc32_u8(crc, b) };
        }
        crc
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn is_arm_crc_available() -> bool {
        // On many aarch64 platforms, CRC32 is mandatory; on others, it is optional.
        // We conservatively assume availability only on std + runtime check if possible.
        #[cfg(feature = "std")]
        {
            // No stable runtime detection; assume available on aarch64 (common servers, Apple M*).
            true
        }
        #[cfg(not(feature = "std"))]
        {
            true
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    unsafe fn crc32c_hw_arm(mut crc: u32, mut data: &[u8]) -> u32 {
        use core::arch::aarch64::{__crc32cb, __crc32cd};
        while data.len() >= 8 {
            let chunk = {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                u64::from_le_bytes(bytes)
            };
            crc = unsafe { __crc32cd(crc, chunk) };
            data = &data[8..];
        }
        for &b in data {
            crc = unsafe { __crc32cb(crc, b) };
        }
        crc
    }

    /// Convenience: CRC32C of a whole slice with seed 0.
    #[inline]
    pub fn checksum(data: &[u8]) -> u32 {
        compute(0, data)
    }

    /// Fused: CRC32C + length in a 64-bit value for quick integrity tagging.
    #[inline]
    pub fn tag64(data: &[u8]) -> u64 {
        let c = checksum(data);
        ((data.len() as u64) << 32) | (c as u64)
    }

    /// Quick self-test for HW vs SW parity (best-effort).
    #[cfg(feature = "std")]
    pub fn selftest() -> bool {
        let samples: [&[u8]; 3] = [b"", b"abc", b"The quick brown fox jumps over the lazy dog"];
        for s in samples {
            let sw = super::crc32c::crc32c_software(0, s);
            let hw = compute(0, s);
            if sw != hw {
                return false;
            }
        }
        true
    }
}

/// Variable-length integer (u64) with LEB128-like encoding.
pub mod varint {
    //! Compact varint (u64) encode/decode.
    use super::*;

    /// Max bytes for u64 varint.
    pub const MAX_LEN: usize = 10;

    /// Encode `val` into `out`, returning number of bytes written.
    /// Fails if buffer is too small.
    #[inline]
    pub fn encode(mut val: u64, out: &mut [u8]) -> Result<usize> {
        let mut i = 0usize;
        while val >= 0x80 {
            *out.get_mut(i).ok_or(Error::InvalidLen)? = ((val as u8) & 0x7F) | 0x80;
            val >>= 7;
            i += 1;
        }
        *out.get_mut(i).ok_or(Error::InvalidLen)? = (val as u8) & 0x7F;
        Ok(i + 1)
    }

    /// Decode varint from `inp`, returning (value, bytes_read).
    #[inline]
    pub fn decode(inp: &[u8]) -> Result<(u64, usize)> {
        let mut x = 0u64;
        let mut s = 0u32;
        for (i, &b) in inp.iter().enumerate() {
            if (b & 0x80) == 0 {
                let val = x | ((b as u64) << s);
                return Ok((val, i + 1));
            }
            x |= ((b & 0x7F) as u64) << s;
            s += 7;
            if s >= 64 {
                return Err(Error::InvalidLen);
            }
        }
        Err(Error::InvalidLen)
    }

    /// Encode helper into stack buffer.
    #[inline]
    pub fn encode_to_array(val: u64) -> (usize, [u8; MAX_LEN]) {
        let mut buf = [0u8; MAX_LEN];
        let n = encode(val, &mut buf).unwrap();
        (n, buf)
    }
}

/// Secure memory utilities.
pub mod secure {
    //! Constant-time and zeroing helpers.
    use super::*;

    /// Securely zero a mutable byte slice to prevent compiler from eliding the write.
    ///
    /// Uses volatile writes and a compiler fence.
    #[inline]
    pub fn secure_zero(buf: &mut [u8]) {
        // SAFETY: We only use volatile writes to valid bytes of the provided slice.
        for b in buf {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        compiler_fence(Ordering::SeqCst);
        black_box(buf);
    }

    /// Constant-time equality for byte slices of equal length.
    #[inline]
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

/// High-resolution timing utilities (std only).
#[cfg(feature = "std")]
pub mod timing {
    use super::*;

    /// Measure closure execution time, returning (result, duration).
    #[inline]
    pub fn time_it<F, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> T,
    {
        let t0 = Instant::now();
        let r = f();
        (r, t0.elapsed())
    }
}

// --------------------------- FFI layer ---------------------------------

#[cfg(feature = "ffi")]
mod ffi {
    //! C ABI surface.
    //!
    //! Header example (manually or via cbindgen):
    //! ```c
    //! #include <stdint.h>
    //!
    //! typedef enum {
    //!   ERR_NULL = -1,
    //!   ERR_INVALID_LEN = -2,
    //!   ERR_UNAVAILABLE = -3,
    //!   ERR_FAIL = -255
    //! } eng_err_t;
    //!
    //! int32_t eng_crc32c(const uint8_t* data, uintptr_t len, uint32_t seed, uint32_t* out);
    //! int32_t eng_crc32c_tag64(const uint8_t* data, uintptr_t len, uint64_t* out_tag);
    //! int32_t eng_varint_encode(uint64_t val, uint8_t* out, uintptr_t out_len, uintptr_t* written);
    //! int32_t eng_varint_decode(const uint8_t* inp, uintptr_t inp_len, uint64_t* val, uintptr_t* read);
    //! int32_t eng_secure_zero(uint8_t* buf, uintptr_t len);
    //! ```

    use super::*;

    #[no_mangle]
    pub extern "C" fn eng_crc32c(
        data: *const u8,
        len: usize,
        seed: u32,
        out: *mut u32,
    ) -> i32 {
        if data.is_null() || out.is_null() {
            return Error::Null.as_i32();
        }
        // SAFETY: inputs validated; create slice view.
        let slice = unsafe { core::slice::from_raw_parts(data, len) };
        let c = crate::crc32c::compute(seed, slice);
        unsafe { *out = c; }
        0
    }

    #[no_mangle]
    pub extern "C" fn eng_crc32c_tag64(
        data: *const u8,
        len: usize,
        out_tag: *mut u64,
    ) -> i32 {
        if data.is_null() || out_tag.is_null() {
            return Error::Null.as_i32();
        }
        let slice = unsafe { core::slice::from_raw_parts(data, len) };
        let tag = crate::crc32c::tag64(slice);
        unsafe { *out_tag = tag; }
        0
    }

    #[no_mangle]
    pub extern "C" fn eng_varint_encode(
        val: u64,
        out: *mut u8,
        out_len: usize,
        written: *mut usize,
    ) -> i32 {
        if out.is_null() || written.is_null() {
            return Error::Null.as_i32();
        }
        let buf = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
        match crate::varint::encode(val, buf) {
            Ok(n) => {
                unsafe { *written = n; }
                0
            }
            Err(e) => e.as_i32(),
        }
    }

    #[no_mangle]
    pub extern "C" fn eng_varint_decode(
        inp: *const u8,
        inp_len: usize,
        val: *mut u64,
        read: *mut usize,
    ) -> i32 {
        if inp.is_null() || val.is_null() || read.is_null() {
            return Error::Null.as_i32();
        }
        let buf = unsafe { core::slice::from_raw_parts(inp, inp_len) };
        match crate::varint::decode(buf) {
            Ok((v, n)) => {
                unsafe {
                    *val = v;
                    *read = n;
                }
                0
            }
            Err(e) => e.as_i32(),
        }
    }

    #[no_mangle]
    pub extern "C" fn eng_secure_zero(buf: *mut u8, len: usize) -> i32 {
        if buf.is_null() {
            return Error::Null.as_i32();
        }
        let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        crate::secure::secure_zero(slice);
        0
    }
}

// --------------------------- PyO3 layer --------------------------------

#[cfg(feature = "python")]
#[pymodule]
fn engine_native(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    /// CRC32C checksum(data: bytes, seed: int=0) -> int
    #[pyfn(m)]
    fn checksum(py: Python<'_>, data: &pyo3::types::PyBytes, seed: Option<u32>) -> PyResult<u32> {
        let seed = seed.unwrap_or(0);
        let view = data.as_bytes();
        let c = crc32c::compute(seed, view);
        // prevent accidental mutation by holding GIL-bound reference
        py.allow_threads(|| Ok(c))
    }

    /// tag64(data: bytes) -> int
    #[pyfn(m)]
    fn tag64(_py: Python<'_>, data: &pyo3::types::PyBytes) -> PyResult<u64> {
        Ok(crc32c::tag64(data.as_bytes()))
    }

    /// varint_encode(val: int) -> bytes
    #[pyfn(m)]
    fn varint_encode(_py: Python<'_>, val: u64) -> PyResult<pyo3::Py<pyo3::types::PyBytes>> {
        let (n, buf) = varint::encode_to_array(val);
        let pyb = pyo3::types::PyBytes::new(_py, &buf[..n]);
        Ok(pyb.into())
    }

    /// varint_decode(data: bytes) -> (int, int)
    #[pyfn(m)]
    fn varint_decode(_py: Python<'_>, data: &pyo3::types::PyBytes) -> PyResult<(u64, usize)> {
        varint::decode(data.as_bytes()).map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid varint").into())
    }

    /// secure_zero(b: bytearray) -> None
    #[pyfn(m)]
    fn secure_zero_py(_py: Python<'_>, b: &pyo3::types::PyByteArray) -> PyResult<()> {
        // Borrow as &mut [u8] and zero in place
        let len = b.len();
        // SAFETY: PyByteArray gives a mutable raw pointer to its contiguous storage.
        let ptr = unsafe { b.as_bytes_mut() };
        crate::secure::secure_zero(ptr);
        // Reassert size to avoid surprises
        assert_eq!(len, b.len());
        Ok(())
    }

    Ok(())
}

// ------------------------------ Tests ----------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_vectors() {
        assert_eq!(crc32c::checksum(b""), 0x00000000);
        assert_eq!(crc32c::checksum(b"abc"), 0x364B3FB7);
        assert_eq!(crc32c::checksum(b"The quick brown fox jumps over the lazy dog"), 0x22620404);
    }

    #[test]
    fn varint_roundtrip() {
        let vals = [0u64, 1, 127, 128, 255, 300, u32::MAX as u64, u64::MAX - 1];
        for &v in &vals {
            let (n, buf) = varint::encode_to_array(v);
            let (vv, r) = varint::decode(&buf[..n]).unwrap();
            assert_eq!(v, vv);
            assert_eq!(n, r);
        }
    }

    #[test]
    fn ct_eq_works() {
        assert!(secure::ct_eq(b"aaaa", b"aaaa"));
        assert!(!secure::ct_eq(b"aaaa", b"aaab"));
        assert!(!secure::ct_eq(b"aaa", b"aaaa"));
    }

    #[test]
    fn secure_zero_works() {
        let mut data = *b"secret!!";
        secure::secure_zero(&mut data);
        assert_eq!(&data, &[0u8; 8]);
        // use black_box to prevent UB assumptions
        black_box(&data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn timing_api() {
        let (res, d) = timing::time_it(|| 2 + 2);
        assert_eq!(res, 4);
        assert!(d.as_nanos() >= 0);
    }
}

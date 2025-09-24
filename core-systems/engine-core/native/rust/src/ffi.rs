//! engine-core / native / rust / FFI layer
//! Стабильный C ABI поверх нативных утилит (CRC32C, VarInt, Secure Zero).
//!
//! Рекомендуемый Cargo.toml фрагмент:
//! ```toml
//! [lib]
//! crate-type = ["rlib", "cdylib", "staticlib"]
//!
//! [features]
//! default = ["std"]
//! std = []
//! ffi = []
//!
//! [dependencies]
//! cfg-if = "1"
//!
//! [build-dependencies]
//! # по желанию: cbindgen = "0.26"
//! ```
//!
//! Пример заголовка (может быть сгенерирован cbindgen либо использован как основа):
//! ```c
//! #pragma once
//! #include <stdint.h>
//! #include <stddef.h>
//!
//! #ifdef _WIN32
//!   #define ENG_API __declspec(dllexport)
//! #else
//!   #define ENG_API
//! #endif
//!
//! #ifdef __cplusplus
//! extern "C" {
//! #endif
//!
//! // Коды ошибок (отрицательные):
//! //  0         — OK
//! // -1 (NULL)  — нулевой указатель
//! // -2 (LEN)   — некорректная длина/переполнение
//! // -3 (UNAV)  — недоступно
//! // -255 (FAIL) — общая ошибка
//!
//! ENG_API const char* eng_version(void);              // "engine-native/1.x.y"
//! ENG_API const char* eng_build_flags(void);          // строка с флагами сборки
//! ENG_API const char* eng_error_message(int32_t ec);  // текстовое пояснение к коду ошибки
//!
//! ENG_API int32_t eng_crc32c(const uint8_t* data, size_t len, uint32_t seed, uint32_t* out);
//! ENG_API int32_t eng_crc32c_tag64(const uint8_t* data, size_t len, uint64_t* out_tag);
//!
//! ENG_API int32_t eng_varint_encode(uint64_t val, uint8_t* out, size_t out_len, size_t* written);
//! ENG_API int32_t eng_varint_decode(const uint8_t* inp, size_t inp_len, uint64_t* val, size_t* read);
//!
//! ENG_API int32_t eng_secure_zero(uint8_t* buf, size_t len);
//! ENG_API int32_t eng_ct_eq(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t* out_equal);
//!
//! #ifdef __cplusplus
//! } // extern "C"
//! #endif
//! ```
//!
//! Безопасность:
//! - Все указатели проверяются на NULL; буферы не выходят за границы.
//! - Никаких паник: ошибки мапятся в отрицательные коды.
//! - Совместим с `no_std` (кроме строк версий — они константны в .rodata).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::all, clippy::pedantic)]

use core::ffi::c_char;
use core::mem::MaybeUninit;
use core::ptr;

use cfg_if::cfg_if;

// Подтягиваем типы/ошибки/модули из корневой библиотеки.
use crate::{crc32c, secure, varint, Error};

/// Версия и флаги сборки компилируются в константные C‑строки.
///
/// Гарантируется NUL‑терминация и стабильный адрес в .rodata.
const VERSION_STR: &str = concat!("engine-native/", env!("CARGO_PKG_VERSION"), "\0");

const BUILD_FLAGS_STR: &str = concat!(
    "features:",
    " std=", if cfg!(feature = "std") { "1" } else { "0" },
    " ffi=", if cfg!(feature = "ffi") { "1" } else { "0" },
    " python=", if cfg!(feature = "python") { "1" } else { "0" },
    " simd=", if cfg!(feature = "simd") { "1" } else { "0" },
    "; target=", env!("TARGET"),
    "; profile=", env!("PROFILE"),
    "\0"
);

#[inline]
fn err(ec: Error) -> i32 { ec.as_i32() }

/// Преобразование числового кода в человекочитаемую строку.
fn error_to_str(ec: i32) -> &'static [u8] {
    match ec {
        0 => b"OK\0",
        -1 => b"Null pointer\0",
        -2 => b"Invalid length\0",
        -3 => b"Unavailable\0",
        -255 => b"Failure\0",
        _ => b"Unknown error\0",
    }
}

// ----------------------------- C ABI -----------------------------------

#[no_mangle]
pub extern "C" fn eng_version() -> *const c_char {
    VERSION_STR.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn eng_build_flags() -> *const c_char {
    BUILD_FLAGS_STR.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn eng_error_message(code: i32) -> *const c_char {
    error_to_str(code).as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn eng_crc32c(
    data: *const u8,
    len: usize,
    seed: u32,
    out: *mut u32,
) -> i32 {
    if data.is_null() || out.is_null() {
        return err(Error::Null);
    }
    // SAFETY: валидируем указатели и длины до разыменования.
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    let c = crc32c::compute(seed, slice);
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
        return err(Error::Null);
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    let tag = crc32c::tag64(slice);
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
        return err(Error::Null);
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
    match varint::encode(val, buf) {
        Ok(n) => {
            unsafe { *written = n; }
            0
        }
        Err(e) => err(e),
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
        return err(Error::Null);
    }
    let buf = unsafe { core::slice::from_raw_parts(inp, inp_len) };
    match varint::decode(buf) {
        Ok((v, n)) => {
            unsafe {
                *val = v;
                *read = n;
            }
            0
        }
        Err(e) => err(e),
    }
}

#[no_mangle]
pub extern "C" fn eng_secure_zero(buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() {
        return err(Error::Null);
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    secure::secure_zero(slice);
    0
}

#[no_mangle]
pub extern "C" fn eng_ct_eq(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out_equal: *mut u8,
) -> i32 {
    if a.is_null() || b.is_null() || out_equal.is_null() {
        return err(Error::Null);
    }
    let aslice = unsafe { core::slice::from_raw_parts(a, a_len) };
    let bslice = unsafe { core::slice::from_raw_parts(b, b_len) };
    let eq = secure::ct_eq(aslice, bslice);
    unsafe { *out_equal = if eq { 1 } else { 0 }; }
    0
}

// ------------------------- no_std паник-хук -----------------------------

// В FFI мы не хотим паник — лучше аборт, чем UB и "тихие" падения.
cfg_if! {
    if #[cfg(not(feature = "std"))] {
        use core::panic::PanicInfo;
        #[panic_handler]
        fn panic(_info: &PanicInfo) -> ! {
            // Без std лучшая стратегия — немедленный abort.
            loop {
                // пробуем создать "заморозку" — аппаратный abort недоступен в no_std без платформоспецифичных вызовов
            }
        }
    }
}

// ------------------------------- Тесты ----------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_flags_nonnull() {
        assert!(!eng_version().is_null());
        assert!(!eng_build_flags().is_null());
    }

    #[test]
    fn crc_ffi_ok() {
        let mut out = 0u32;
        let ec = eng_crc32c(b"abc".as_ptr(), 3, 0, &mut out as *mut u32);
        assert_eq!(ec, 0);
        assert_eq!(out, 0x364B3FB7);
    }

    #[test]
    fn varint_roundtrip_ffi() {
        let mut buf = [0u8; 10];
        let mut written: usize = 0;
        let ec = eng_varint_encode(300, buf.as_mut_ptr(), buf.len(), &mut written);
        assert_eq!(ec, 0);
        assert!(written > 0);

        let mut val: u64 = 0;
        let mut read: usize = 0;
        let ec2 = eng_varint_decode(buf.as_ptr(), written, &mut val, &mut read);
        assert_eq!(ec2, 0);
        assert_eq!(val, 300);
        assert_eq!(read, written);
    }

    #[test]
    fn secure_zero_ffi() {
        let mut data = *b"secret!!";
        let ec = eng_secure_zero(data.as_mut_ptr(), data.len());
        assert_eq!(ec, 0);
        assert_eq!(&data, &[0u8; 8]);
    }

    #[test]
    fn ct_eq_ffi() {
        let mut out = 2u8;
        let ec = eng_ct_eq(b"aaaa".as_ptr(), 4, b"aaaa".as_ptr(), 4, &mut out as *mut u8);
        assert_eq!(ec, 0);
        assert_eq!(out, 1);
        let ec2 = eng_ct_eq(b"aaaa".as_ptr(), 4, b"aaab".as_ptr(), 4, &mut out as *mut u8);
        assert_eq!(ec2, 0);
        assert_eq!(out, 0);
    }
}

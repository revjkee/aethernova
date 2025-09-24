//! DataFabric FFI (C-ABI) — безопасная граница между Rust и внешними языками.
//!
//! Дизайн:
//! - Стабильные repr(C) структуры и enum кодов ошибок.
//! - Жёсткое правило памяти: все буферы, выделенные библиотекой, освобождать через df_free_bytes().
//! - Паник-защита: любая паника Rust не «протечёт» за FFI, возвращается DF_ERR_INTERNAL.
//! - Потокобезопасный контекст (Arc). Допускается параллельная обработка.
//! - Детерминированные ответы в UTF‑8 JSON без NUL.
//! - Кроссплатформенность: Linux/macOS/Windows.
//!
//! Пример C-хедера (генерируется cbindgen или пишется вручную):
//! -----------------------------------------------------------
//! typedef struct { unsigned char* ptr; size_t len; } DFBytes;
//! typedef enum {
//!   DF_OK = 0, DF_ERR_INVALID_ARGUMENT = 1, DF_ERR_INTERNAL = 2, DF_ERR_NO_MEMORY = 3
//! } DFCode;
//! // Версия/билд: владелец — библиотека; освобождать через df_free_bytes
//! DFBytes df_version(void);
//! DFBytes df_build_info(void);
//! const char* df_code_message(DFCode code); // статическая строка, не освобождать
//!
//! typedef struct DFContext DFContext; // opaque
//! DFCode df_context_new(const unsigned char* cfg_json, size_t cfg_len, DFContext** out_ctx);
//! DFCode df_context_free(DFContext* ctx);
//!
//! // Обработка: вход — произвольные байты, результат — JSON (DFBytes), ошибка — UTF-8 текст (DFBytes)
//! DFCode df_process(DFContext* ctx,
//!                   const unsigned char* in_ptr, size_t in_len,
//!                   DFBytes* out_json, DFBytes* out_err);
//!
//! // Освобождение буферов, выделенных библиотекой
//! void df_free_bytes(DFBytes b);
//! -----------------------------------------------------------

#![cfg_attr(not(test), deny(warnings))]
#![forbid(unsafe_op_in_unsafe_fn)]
use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;

use once_cell::sync::Lazy;

#[cfg(feature = "gzip")]
use flate2::{write::GzEncoder, Compression};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

// ===========================
// repr(C) типы и коды ошибок
// ===========================

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DFBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DFCode {
    DF_OK = 0,
    DF_ERR_INVALID_ARGUMENT = 1,
    DF_ERR_INTERNAL = 2,
    DF_ERR_NO_MEMORY = 3,
}

impl DFCode {
    fn as_str(self) -> &'static str {
        match self {
            DFCode::DF_OK => "ok",
            DFCode::DF_ERR_INVALID_ARGUMENT => "invalid_argument",
            DFCode::DF_ERR_INTERNAL => "internal",
            DFCode::DF_ERR_NO_MEMORY => "no_memory",
        }
    }
}

static VERSION_JSON: Lazy<Vec<u8>> = Lazy::new(|| {
    // Детерминированный JSON без пробелов
    format!(
        "{{\"name\":\"{}\",\"version\":\"{}\"}}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
});

static BUILD_INFO_JSON: Lazy<Vec<u8>> = Lazy::new(|| {
    let target = option_env!("TARGET").unwrap_or("unknown");
    let profile = option_env!("PROFILE").unwrap_or("release");
    let rustc = option_env!("RUSTC_VERSION").unwrap_or("rustc");
    format!(
        "{{\"name\":\"{}\",\"version\":\"{}\",\"target\":\"{}\",\"profile\":\"{}\",\"rustc\":\"{}\"}}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        target,
        profile,
        rustc
    )
    .into_bytes()
});

// ====================================
// Контекст и конфигурация трансформов
// ====================================

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ContextConfig {
    /// digest: "sha256" | "sha512"
    digest: String,
    /// include_gzip: если true — добавляем в ответ base64(gzip(input))
    include_gzip: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            digest: "sha256".to_string(),
            include_gzip: false,
        }
    }
}

#[derive(Clone)]
struct Context {
    cfg: Arc<ContextConfig>,
}

impl Context {
    fn new(cfg: ContextConfig) -> Self {
        Self { cfg: Arc::new(cfg) }
    }

    fn process(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        // Вычисляем хеш детерминированно
        let (digest_alg, digest_hex) = match self.cfg.digest.as_str() {
            "sha512" => {
                let mut h = Sha512::new();
                h.update(input);
                ("sha512", hex::encode(h.finalize()))
            }
            _ => {
                let mut h = Sha256::new();
                h.update(input);
                ("sha256", hex::encode(h.finalize()))
            }
        };

        // Опционально gzip вход (feature + флаг)
        #[cfg(feature = "gzip")]
        let gz_b64 = if self.cfg.include_gzip {
            let mut enc = GzEncoder::new(Vec::with_capacity(input.len() / 2 + 64), Compression::default());
            use std::io::Write;
            enc.write_all(input).map_err(|e| e.to_string())?;
            let compressed = enc.finish().map_err(|e| e.to_string())?;
            Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(&compressed))
        } else {
            None
        };

        #[cfg(not(feature = "gzip"))]
        let gz_b64: Option<String> = None;

        #[derive(Serialize)]
        struct Out<'a> {
            version: &'a str,
            digest_alg: &'a str,
            digest_hex: String,
            len: usize,
            #[cfg(feature = "gzip")]
            gzip_b64: Option<String>,
        }

        let out = Out {
            version: env!("CARGO_PKG_VERSION"),
            digest_alg,
            digest_hex,
            len: input.len(),
            #[cfg(feature = "gzip")]
            gzip_b64: gz_b64,
        };

        // Детерминированная сериализация JSON: сортировка ключей, компактно.
        let mut buf = serde_json::to_vec(&out).map_err(|e| e.to_string())?;
        // serde_json не гарантирует порядок; пересериализуем в канон.
        let v: serde_json::Value = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
        buf = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
        Ok(buf)
    }
}

// Оpaque тип для C
#[repr(C)]
pub struct DFContext {
    inner: Context,
}

// =======================
// Вспомогательные утилы
// =======================

fn to_dfbytes_owned(mut v: Vec<u8>) -> DFBytes {
    // Преобразуем Vec<u8> -> Box<[u8]> -> raw
    let b = v.into_boxed_slice();
    let len = b.len();
    let ptr = Box::into_raw(b) as *mut u8;
    DFBytes { ptr, len }
}

fn dup_bytes(b: &[u8]) -> Result<DFBytes, DFCode> {
    let mut v = Vec::with_capacity(b.len());
    v.extend_from_slice(b);
    Ok(to_dfbytes_owned(v))
}

unsafe fn free_dfbytes(b: DFBytes) {
    if !b.ptr.is_null() && b.len > 0 {
        // Воссоздаём Box<[u8]> и отпускаем
        let slice = std::slice::from_raw_parts_mut(b.ptr, b.len);
        drop(Box::from_raw(slice));
    }
}

fn err_to_bytes(msg: &str) -> DFBytes {
    // Возвращаем UTF-8 без NUL. Клиент освобождает.
    to_dfbytes_owned(msg.as_bytes().to_vec())
}

// =======================
// Экспортируемые функции
// =======================

#[no_mangle]
pub extern "C" fn df_version() -> DFBytes {
    dup_bytes(&VERSION_JSON).unwrap_or_else(|_| DFBytes { ptr: ptr::null_mut(), len: 0 })
}

#[no_mangle]
pub extern "C" fn df_build_info() -> DFBytes {
    dup_bytes(&BUILD_INFO_JSON).unwrap_or_else(|_| DFBytes { ptr: ptr::null_mut(), len: 0 })
}

#[no_mangle]
pub extern "C" fn df_code_message(code: DFCode) -> *const c_char {
    // Возвращает статическую C‑строку; не освобождать
    match code {
        DFCode::DF_OK => c_str!("DF_OK"),
        DFCode::DF_ERR_INVALID_ARGUMENT => c_str!("DF_ERR_INVALID_ARGUMENT"),
        DFCode::DF_ERR_INTERNAL => c_str!("DF_ERR_INTERNAL"),
        DFCode::DF_ERR_NO_MEMORY => c_str!("DF_ERR_NO_MEMORY"),
    }
}

// Создание контекста
#[no_mangle]
pub extern "C" fn df_context_new(cfg_json_ptr: *const u8, cfg_len: usize, out_ctx: *mut *mut DFContext) -> DFCode {
    if out_ctx.is_null() {
        return DFCode::DF_ERR_INVALID_ARGUMENT;
    }
    // Безопасность: допускаем пустой конфиг = default
    let res = catch_unwind(AssertUnwindSafe(|| -> Result<*mut DFContext, DFCode> {
        let cfg = if cfg_json_ptr.is_null() || cfg_len == 0 {
            ContextConfig::default()
        } else {
            let slice = unsafe { std::slice::from_raw_parts(cfg_json_ptr, cfg_len) };
            serde_json::from_slice::<ContextConfig>(slice).map_err(|_| DFCode::DF_ERR_INVALID_ARGUMENT)?
        };
        let ctx = DFContext { inner: Context::new(cfg) };
        let boxed = Box::new(ctx);
        Ok(Box::into_raw(boxed))
    }));

    match res {
        Ok(Ok(ptr_ctx)) => {
            unsafe { *out_ctx = ptr_ctx; }
            DFCode::DF_OK
        }
        Ok(Err(code)) => code,
        Err(_) => DFCode::DF_ERR_INTERNAL,
    }
}

// Освобождение контекста
#[no_mangle]
pub extern "C" fn df_context_free(ctx: *mut DFContext) -> DFCode {
    if ctx.is_null() {
        return DFCode::DF_ERR_INVALID_ARGUMENT;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        unsafe { drop(Box::from_raw(ctx)); }
    }));
    DFCode::DF_OK
}

/// Основная обработка: принимает произвольные байты и возвращает JSON‑ответ.
/// out_json/out_err — выходные буферы; вызывающая сторона обязана вызвать df_free_bytes для каждого, чей ptr != NULL.
///
/// Возвращаемый DFCode:
/// - DF_OK: out_json содержит результат, out_err.ptr == NULL
/// - DF_ERR_INVALID_ARGUMENT: вход некорректен; out_err содержит текст
/// - DF_ERR_INTERNAL: внутренняя ошибка/паника; out_err содержит текст
#[no_mangle]
pub extern "C" fn df_process(
    ctx: *mut DFContext,
    in_ptr: *const u8,
    in_len: usize,
    out_json: *mut DFBytes,
    out_err: *mut DFBytes,
) -> DFCode {
    // Инициализация выходов нулями, чтобы освобождение было идемпотентным на стороне клиента
    if !out_json.is_null() {
        unsafe { (*out_json).ptr = ptr::null_mut(); (*out_json).len = 0; }
    }
    if !out_err.is_null() {
        unsafe { (*out_err).ptr = ptr::null_mut(); (*out_err).len = 0; }
    }

    if ctx.is_null() || (in_ptr.is_null() && in_len != 0) || out_json.is_null() || out_err.is_null() {
        return DFCode::DF_ERR_INVALID_ARGUMENT;
    }

    let res = catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, String> {
        let ctx_ref = unsafe { &*ctx };
        let input = if in_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(in_ptr, in_len) }
        };
        ctx_ref.inner.process(input)
    }));

    match res {
        Ok(Ok(json_buf)) => {
            let b = to_dfbytes_owned(json_buf);
            unsafe { *out_json = b; }
            DFCode::DF_OK
        }
        Ok(Err(msg)) => {
            let e = err_to_bytes(&msg);
            unsafe { *out_err = e; }
            DFCode::DF_ERR_INVALID_ARGUMENT
        }
        Err(_) => {
            let e = err_to_bytes("panic: internal error");
            unsafe { *out_err = e; }
            DFCode::DF_ERR_INTERNAL
        }
    }
}

/// Освобождение буфера, выделенного библиотекой (любой DFBytes из функций df_*).
#[no_mangle]
pub extern "C" fn df_free_bytes(b: DFBytes) {
    // безопасно для b.ptr == NULL
    if b.ptr.is_null() || b.len == 0 {
        return;
    }
    unsafe { free_dfbytes(b) }
}

// =======================
// Внутренние макросы
// =======================

#[macro_export]
macro_rules! c_str {
    ($lit:expr) => {
        concat!($lit, "\0").as_ptr() as *const ::std::ffi::c_char
    };
}

// =======================
// Тесты (не попадают в релиз)
// =======================
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let mut ctx_ptr: *mut DFContext = std::ptr::null_mut();
        let cfg = br#"{"digest":"sha256","include_gzip":false}"#;
        assert_eq!(DFCode::DF_OK, df_context_new(cfg.as_ptr(), cfg.len(), &mut ctx_ptr));
        assert!(!ctx_ptr.is_null());

        let input = b"hello";
        let mut out = DFBytes { ptr: std::ptr::null_mut(), len: 0 };
        let mut err = DFBytes { ptr: std::ptr::null_mut(), len: 0 };
        let code = df_process(ctx_ptr, input.as_ptr(), input.len(), &mut out, &mut err);
        assert_eq!(DFCode::DF_OK, code);
        assert!(err.ptr.is_null());
        let s = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(out.ptr, out.len)) };
        assert!(s.contains("\"digest_alg\":\"sha256\""));
        df_free_bytes(out);

        assert_eq!(DFCode::DF_OK, df_context_free(ctx_ptr));
    }
}

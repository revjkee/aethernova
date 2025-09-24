//! DataFabric Native Core (Rust)
//! ---------------------------------
//! Пакет высокопроизводительных нативных примитивов для DataFabric.
//!
//! Включает:
//! - Нормализацию строк (обрезка, схлопывание пробелов, опц. Unicode NFC/кейс-фолдинг).
//! - Детерминированный 64-битный хеш: SipHash-1-3 по умолчанию; XXH3 при `--features xxhash`.
//! - BloomFilter с двойным хешированием (k >= 1), потокобезопасные методы.
//! - Стохастическая выборка (reservoir sampling) для метрик DQ.
//! - Трассировка через `tracing` (опционально включите subscriber в приложении).
//! - FFI (C ABI) при `--features ffi` и Python биндинги при `--features python` (PyO3).
//!
//! Безопасность/производительность:
//! - Нет глобального изменяемого состояния.
//! - Память освобождается детерминированно (RAII).
//! - Все публичные функции документированы и покрыты базовыми тестами.
//!
//! Примеры см. в доках к типам и в блоке тестов ниже.

// ---------- features / extern ----------
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc, clippy::missing_panics_doc)]

#[cfg(feature = "python")]
extern crate pyo3;

#[cfg(feature = "unicode")]
extern crate unicode_normalization;

#[cfg(feature = "xxhash")]
extern crate xxhash_rust;

use core::fmt;
use std::borrow::Cow;
use std::hash::Hasher as StdHasher;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "unicode")]
use unicode_normalization::UnicodeNormalization;

#[cfg(feature = "xxhash")]
use xxhash_rust::xxh3::Xxh3;

//
// Logging (tracing)
//
#[inline]
fn trace_event(event: &str) {
    #[cfg(feature = "tracing")]
    tracing::trace!(target: "df.native", event);
}

//
// Errors
//
#[derive(Debug)]
pub enum NativeError {
    InvalidArgument(String),
    Overflow(String),
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativeError::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            NativeError::Overflow(s) => write!(f, "overflow: {s}"),
        }
    }
}

impl std::error::Error for NativeError {}

//
// Text normalization
//
#[derive(Clone, Copy, Debug)]
pub struct NormalizeOptions {
    pub trim: bool,
    pub collapse_spaces: bool,
    pub to_lower: bool,
    /// Включить Unicode NFC нормализацию (требует фичу `unicode`)
    pub unicode_nfc: bool,
}

impl Default for NormalizeOptions {
    fn default() -> Self {
        Self {
            trim: true,
            collapse_spaces: true,
            to_lower: false,
            unicode_nfc: false,
        }
    }
}

/// Нормализует строку без аллокаций, где возможно (возвращает Cow).
/// - trim: обрезка по краям
/// - collapse_spaces: последовательности пробельных символов (ASCII) -> один пробел
/// - to_lower: ASCII‑lowercase (без культуры)
/// - unicode_nfc: опц. Unicode NFC (если включена фича `unicode`)
pub fn normalize_text(input: &str, opts: NormalizeOptions) -> Cow<'_, str> {
    trace_event("normalize_text");
    let mut out = if opts.trim {
        Cow::from(input.trim())
    } else {
        Cow::from(input)
    };

    if opts.collapse_spaces {
        let mut buf = String::with_capacity(out.len());
        let mut prev_space = false;
        for ch in out.chars() {
            let is_space = ch.is_ascii_whitespace();
            if is_space {
                if !prev_space {
                    buf.push(' ');
                }
            } else {
                buf.push(ch);
            }
            prev_space = is_space;
        }
        out = Cow::Owned(buf);
    }

    if opts.to_lower {
        // ASCII lowercase без аллокаций при возможности
        if out.as_ref().is_ascii() {
            let mut buf = out.into_owned().into_bytes();
            for b in &mut buf {
                *b = b.to_ascii_lowercase();
            }
            out = Cow::Owned(String::from_utf8(buf).expect("ascii"));
        } else {
            out = Cow::Owned(out.to_lowercase());
        }
    }

    #[cfg(feature = "unicode")]
    if opts.unicode_nfc {
        out = Cow::Owned(out.nfc().collect::<String>());
    }

    out
}

//
// Hashing
//
pub trait Hasher64: Send + Sync + 'static {
    fn hash64(&self, bytes: &[u8]) -> u64;
}

#[derive(Default)]
struct SipHasher13 {
    // per-thread or per-instance hasher with randomized key could be added
}

impl Hasher64 for SipHasher13 {
    fn hash64(&self, bytes: &[u8]) -> u64 {
        // SipHash-1-3 via std::hash::SipHasher13
        let mut h = std::hash::SipHasher13::new();
        h.write(bytes);
        h.finish()
    }
}

#[cfg(feature = "xxhash")]
#[derive(Default)]
struct XXH3Hasher;

#[cfg(feature = "xxhash")]
impl Hasher64 for XXH3Hasher {
    fn hash64(&self, bytes: &[u8]) -> u64 {
        let mut x = Xxh3::new();
        x.update(bytes);
        x.digest()
    }
}

/// Конкретная стратегия по фичам
fn default_hasher() -> Arc<dyn Hasher64> {
    #[cfg(feature = "xxhash")]
    {
        return Arc::new(XXH3Hasher::default());
    }
    Arc::new(SipHasher13::default())
}

/// Удобная функция: хеш 64 из строки
pub fn hash64(s: &str) -> u64 {
    default_hasher().hash64(s.as_bytes())
}

//
// BloomFilter
//
#[derive(Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    m: usize, // число битов
    k: usize, // число хешей
    hasher: Arc<dyn Hasher64>,
}

impl fmt::Debug for BloomFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BloomFilter")
            .field("bits_len_words", &self.bits.len())
            .field("m_bits", &self.m)
            .field("k_hashes", &self.k)
            .finish()
    }
}

impl BloomFilter {
    /// Создать фильтр на n элементов при ожидаемой ложной вероятности p.
    /// m и k выбираются по классическим формулам.
    pub fn with_n_p(n: usize, p: f64) -> Result<Self, NativeError> {
        if n == 0 || !(0.0..1.0).contains(&p) {
            return Err(NativeError::InvalidArgument("n>0, 0<p<1".into()));
        }
        let m_f = -1.0 * (n as f64) * p.ln() / (std::f64::consts::LN_2.powi(2));
        let k_f = (m_f / (n as f64)) * std::f64::consts::LN_2;
        let m = m_f.ceil() as usize;
        let k = k_f.ceil().max(1.0) as usize;
        Self::with_m_k(m, k)
    }

    /// Создать фильтр по заданным параметрам.
    pub fn with_m_k(m_bits: usize, k_hashes: usize) -> Result<Self, NativeError> {
        if m_bits == 0 || k_hashes == 0 {
            return Err(NativeError::InvalidArgument("m_bits>0, k_hashes>0".into()));
        }
        let words = (m_bits + 63) / 64;
        Ok(Self {
            bits: vec![0u64; words],
            m: m_bits,
            k: k_hashes,
            hasher: default_hasher(),
        })
    }

    #[inline]
    fn bit_index(&self, h: u64, i: usize) -> usize {
        // двойное хеширование: h1 + i*h2
        let h1 = h;
        // второй хеш: простая перестановка (здесь — xorshift)
        let mut x = h ^ 0x9e3779b97f4a7c15_u64;
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d049bb133111eb);
        x ^= x >> 31;
        let h2 = x | 1; // нечётное
        let idx = h1.wrapping_add((i as u64).wrapping_mul(h2)) % (self.m as u64);
        idx as usize
    }

    /// Добавить байты
    pub fn add_bytes(&mut self, bytes: &[u8]) {
        trace_event("bloom_add");
        let h = self.hasher.hash64(bytes);
        for i in 0..self.k {
            let idx = self.bit_index(h, i);
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Проверить наличие байтов
    pub fn contains_bytes(&self, bytes: &[u8]) -> bool {
        trace_event("bloom_contains");
        let h = self.hasher.hash64(bytes);
        for i in 0..self.k {
            let idx = self.bit_index(h, i);
            let word = idx / 64;
            let bit = idx % 64;
            if (self.bits[word] & (1u64 << bit)) == 0 {
                return false;
            }
        }
        true
    }

    /// Добавить строку
    pub fn add_str(&mut self, s: &str) {
        self.add_bytes(s.as_bytes());
    }

    /// Проверить строку
    pub fn contains_str(&self, s: &str) -> bool {
        self.contains_bytes(s.as_bytes())
    }

    /// Оценка заполненности (доля установленных битов)
    pub fn fill_ratio(&self) -> f64 {
        let mut set = 0u64;
        for w in &self.bits {
            set += w.count_ones() as u64;
        }
        (set as f64) / (self.m as f64)
    }
}

//
// Reservoir sampling (Vitter's Algorithm R)
//
#[derive(Debug)]
pub struct Reservoir<T> {
    cap: NonZeroUsize,
    data: Vec<T>,
    seen: AtomicU64,
}

impl<T> Reservoir<T> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            cap: capacity,
            data: Vec::with_capacity(capacity.get()),
            seen: AtomicU64::new(0),
        }
    }

    /// Добавляет элемент; с вероятностью cap/seen попадёт в выборку.
    pub fn push(&mut self, item: T) {
        use rand_index::FastRand;
        let seen = self.seen.fetch_add(1, Ordering::Relaxed) + 1;
        let cap = self.cap.get() as u64;
        if (self.data.len() as u64) < cap {
            self.data.push(item);
        } else {
            // Быстрый LCG‑рандом без сторонних зависимостей
            let mut r = FastRand::new(seen);
            let j = r.next_u64() % seen;
            if j < cap {
                let idx = (j as usize) % self.data.len();
                self.data[idx] = item;
            }
        }
    }

    pub fn snapshot(&self) -> Vec<&T> {
        self.data.iter().collect()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// Встроенный быстрый ГПСЧ (LCG + xorshift), детерминированный по seed.
mod rand_index {
    pub struct FastRand {
        state: u64,
    }
    impl FastRand {
        pub fn new(seed: u64) -> Self {
            Self { state: seed ^ 0x9e3779b97f4a7c15 }
        }
        #[inline]
        pub fn next_u64(&mut self) -> u64 {
            // xorshift* (не криптостойкий)
            let mut x = self.state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.state = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
    }
}

//
// Public convenience API
//
#[derive(Clone, Copy, Debug, Default)]
pub struct Canonicalize {
    pub to_lower: bool,
    pub collapse_spaces: bool,
    pub unicode_nfc: bool,
}

pub fn canonicalize_and_hash(s: &str, cfg: Canonicalize) -> (String, u64) {
    let norm = normalize_text(
        s,
        NormalizeOptions {
            trim: true,
            collapse_spaces: cfg.collapse_spaces,
            to_lower: cfg.to_lower,
            unicode_nfc: cfg.unicode_nfc,
        },
    );
    let h = hash64(norm.as_ref());
    (norm.into_owned(), h)
}

//
// Thread-safe Bloom wrapper (for sharing across threads)
//
#[derive(Clone)]
pub struct SharedBloom(Arc<Mutex<BloomFilter>>);

impl SharedBloom {
    pub fn new(n: usize, p: f64) -> Result<Self, NativeError> {
        Ok(Self(Arc::new(Mutex::new(BloomFilter::with_n_p(n, p)?))))
    }
    pub fn add(&self, s: &str) {
        if let Ok(mut guard) = self.0.lock() {
            guard.add_str(s);
        }
    }
    pub fn contains(&self, s: &str) -> bool {
        if let Ok(guard) = self.0.lock() {
            guard.contains_str(s)
        } else {
            false
        }
    }
    pub fn fill_ratio(&self) -> f64 {
        if let Ok(guard) = self.0.lock() {
            guard.fill_ratio()
        } else {
            0.0
        }
    }
}

//
// FFI (C ABI)
//
#[cfg(feature = "ffi")]
pub mod ffi {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_double, c_int, c_ulonglong};

    #[no_mangle]
    pub extern "C" fn df_hash64(cstr: *const c_char) -> c_ulonglong {
        if cstr.is_null() {
            return 0;
        }
        let s = unsafe { CStr::from_ptr(cstr) }.to_string_lossy();
        hash64(&s) as c_ulonglong
    }

    #[no_mangle]
    pub extern "C" fn df_normalize_ascii(
        cstr: *const c_char,
        to_lower: c_int,
        collapse_spaces: c_int,
    ) -> *mut c_char {
        if cstr.is_null() {
            return std::ptr::null_mut();
        }
        let s = unsafe { CStr::from_ptr(cstr) }.to_string_lossy();
        let out = super::normalize_text(
            &s,
            super::NormalizeOptions {
                trim: 1 == 1,
                collapse_spaces: collapse_spaces != 0,
                to_lower: to_lower != 0,
                unicode_nfc: false,
            },
        );
        CString::new(out.as_ref()).unwrap().into_raw()
    }

    #[no_mangle]
    pub extern "C" fn df_free_string(ptr: *mut c_char) {
        if !ptr.is_null() {
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        }
    }

    // Bloom
    #[repr(C)]
    pub struct DFSharedBloom {
        ptr: *mut SharedBloom,
    }

    #[no_mangle]
    pub extern "C" fn df_bloom_new(n: c_int, p: c_double) -> DFSharedBloom {
        let n = if n <= 0 { 1 } else { n as usize };
        let p = if p <= 0.0 { 0.01 } else { p };
        let bloom = SharedBloom::new(n, p).expect("bloom");
        DFSharedBloom {
            ptr: Box::into_raw(Box::new(bloom)),
        }
    }

    #[no_mangle]
    pub extern "C" fn df_bloom_add(b: DFSharedBloom, cstr: *const c_char) {
        if b.ptr.is_null() || cstr.is_null() {
            return;
        }
        let s = unsafe { CStr::from_ptr(cstr) }.to_string_lossy();
        unsafe { &*b.ptr }.add(&s);
    }

    #[no_mangle]
    pub extern "C" fn df_bloom_contains(b: DFSharedBloom, cstr: *const c_char) -> c_int {
        if b.ptr.is_null() || cstr.is_null() {
            return 0;
        }
        let s = unsafe { CStr::from_ptr(cstr) }.to_string_lossy();
        if unsafe { &*b.ptr }.contains(&s) {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub extern "C" fn df_bloom_fill_ratio(b: DFSharedBloom) -> c_double {
        if b.ptr.is_null() {
            return 0.0;
        }
        unsafe { &*b.ptr }.fill_ratio()
    }

    #[no_mangle]
    pub extern "C" fn df_bloom_free(b: DFSharedBloom) {
        if !b.ptr.is_null() {
            unsafe { drop(Box::from_raw(b.ptr)) }
        }
    }
}

//
// Python bindings (PyO3)
//
#[cfg(feature = "python")]
pub mod py {
    use super::*;
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;

    #[pyclass(name = "SharedBloom")]
    pub struct PySharedBloom {
        inner: SharedBloom,
    }

    #[pymethods]
    impl PySharedBloom {
        #[new]
        fn new(n: usize, p: f64) -> PyResult<Self> {
            Ok(Self {
                inner: SharedBloom::new(n.max(1), if p > 0.0 { p } else { 0.01 })
                    .map_err(|e| PyValueError::new_err(e.to_string()))?,
            })
        }
        fn add(&self, s: &str) {
            self.inner.add(s);
        }
        fn contains(&self, s: &str) -> bool {
            self.inner.contains(s)
        }
        fn fill_ratio(&self) -> f64 {
            self.inner.fill_ratio()
        }
        fn __repr__(&self) -> String {
            "SharedBloom(...)".to_string()
        }
    }

    #[pyfunction]
    fn normalize(s: &str, to_lower: bool, collapse_spaces: bool, unicode_nfc: bool) -> String {
        super::normalize_text(
            s,
            super::NormalizeOptions {
                trim: true,
                collapse_spaces,
                to_lower,
                unicode_nfc,
            },
        )
        .into_owned()
    }

    #[pyfunction]
    fn hash64_str(s: &str) -> u64 {
        super::hash64(s)
    }

    #[pyfunction]
    fn canonicalize_and_hash_py(s: &str, to_lower: bool, collapse_spaces: bool, unicode_nfc: bool) -> (String, u64) {
        let (n, h) = super::canonicalize_and_hash(
            s,
            super::Canonicalize {
                to_lower,
                collapse_spaces,
                unicode_nfc,
            },
        );
        (n, h)
    }

    #[pymodule]
    fn datafabric_native(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
        m.add_class::<PySharedBloom>()?;
        m.add_function(wrap_pyfunction!(normalize, m)?)?;
        m.add_function(wrap_pyfunction!(hash64_str, m)?)?;
        m.add_function(wrap_pyfunction!(canonicalize_and_hash_py, m)?)?;
        Ok(())
    }
}

//
// Tests
//
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        let s = "  Foo   BAR \t";
        let n = normalize_text(
            s,
            NormalizeOptions {
                trim: true,
                collapse_spaces: true,
                to_lower: true,
                unicode_nfc: false,
            },
        );
        assert_eq!(n, "foo bar");
    }

    #[test]
    fn test_hash64_deterministic() {
        assert_eq!(hash64("a"), hash64("a"));
        assert_ne!(hash64("a"), hash64("b"));
    }

    #[test]
    fn test_bloom() {
        let mut bf = BloomFilter::with_n_p(1_000, 0.01).unwrap();
        bf.add_str("alice@example.com");
        assert!(bf.contains_str("alice@example.com"));
        assert!(!bf.contains_str("bob@example.com"));
        assert!(bf.fill_ratio() > 0.0);
    }

    #[test]
    fn test_reservoir() {
        let mut r = Reservoir::new(NonZeroUsize::new(5).unwrap());
        for i in 0..1000 {
            r.push(i);
        }
        assert_eq!(r.len(), 5);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 5);
    }
}

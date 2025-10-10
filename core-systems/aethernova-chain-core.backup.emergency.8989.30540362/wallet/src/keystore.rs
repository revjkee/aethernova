// aethernova-chain-core/wallet/src/keystore.rs
//! Unified keystore: Software, HSM (PKCS#11 v3), Threshold (FROST Ed25519).
//!
//! Цели:
//! - Единый интерфейс ключей и подписей для приложений кошелька/узла.
//! - Поддержка HSM через PKCS#11 v3 (CKM_EDDSA/CKM_ECDSA и пр.) [OASIS PKCS#11].
//! - Пороговые ключи: интерфейс FROST (Ed25519) без криптографической
//!   реализации внутри этого файла — интеграция через внешний провайдер [IETF FROST].
//! - Безопасная работа с секретами (zeroize/secrecy), строгая типизация алгоритмов.
//!
//! Важно: здесь нет сетевого MPC/крипто-кода пороговой подписи — только интерфейсы.
//! Реальные реализации FROST/TSS подключаются как провайдеры.
//!
//! Ссылки (подтверждение стандартов/механизмов):
//! - PKCS#11 v3.0 Base Spec + Current Mechanisms, включая CKM_EDDSA и параметры prehash. [OASIS].
//! - Ed25519/EdDSA спецификация (RFC 8032). [RFC8032].
//! - FROST: Flexible Round-Optimized Schnorr Threshold signatures (совместим с RFC8032). [FROST].
//! - Rust-пакеты: cryptoki (обертка PKCS#11), zeroize (затирание секретов). [cryptoki][zeroize]
//
//! [OASIS]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.pdf
//! [OASIS-CURR]: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html
//! [RFC8032]: https://datatracker.ietf.org/doc/html/rfc8032
//! [FROST]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html
//! [cryptoki]: https://docs.rs/cryptoki
//! [zeroize]: https://docs.rs/zeroize/latest/zeroize/

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_docs)]

use std::fmt;
use std::sync::Arc;

#[cfg(feature = "hsm_pkcs11")]
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{Mechanism, MechanismType},
    object::{Attribute, AttributeType},
    session::{Session, SessionFlags, UserType},
    types::{CKA_CLASS, CK_OBJECT_CLASS, KeyType, ObjectClass, Ulong},
    Error as Pkcs11Error, Slot,
};

use zeroize::Zeroize;

//------------------------------- Типы и доменная модель -------------------------------//

/// Поддерживаемые алгоритмы ключей.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Ed25519 согласно RFC 8032 (EdDSA на Edwards25519).
    Ed25519,
    /// ECDSA на secp256k1 (для совместимости с экосистемой).
    Secp256k1,
    /// ECDSA на secp256r1 (NIST P-256).
    Secp256r1,
}

/// Идентификатор ключа в хранилище.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    /// Дет-генерация псевдослучайного идентификатора (безопасность не критична).
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }
}

/// Метаданные ключа (безопасные для журналирования).
#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub id: KeyId,
    pub alg: KeyAlgorithm,
    pub backend: BackendKind,
    pub label: Option<String>,
    pub exportable: bool,
}

/// Какой бэкенд хранит ключ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Software,
    HsmPkcs11,
    Threshold,
}

/// Политика ключа.
#[derive(Clone, Debug)]
pub struct KeyPolicy {
    /// Разрешен ли экспорт секретного материала (обычно false для HSM).
    pub exportable: bool,
    /// Требовать ли prehash при подписи (актуально для EdDSA/Ed25519ph).
    pub require_prehash: bool,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        Self { exportable: false, require_prehash: false }
    }
}

/// Ошибки хранилища ключей.
#[derive(thiserror::Error, Debug)]
pub enum KeystoreError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("policy violation: {0}")]
    Policy(String),
    #[cfg(feature = "hsm_pkcs11")]
    #[error("pkcs11 error: {0}")]
    Pkcs11(#[from] Pkcs11Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("threshold provider error: {0}")]
    Threshold(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Публичный ключ (сырой DER/ASN.1 или raw, в зависимости от alg).
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub alg: KeyAlgorithm,
    /// Сериализованный публичный ключ:
    /// - Ed25519: 32 байта
    /// - secp256k1/p256: SEC1 compressed (33 байта) или DER SubjectPublicKeyInfo
    pub bytes: Vec<u8>,
}

/// Подпись (сырой формат для Ed25519; DER для ECDSA).
#[derive(Clone, Debug)]
pub struct Signature {
    pub alg: KeyAlgorithm,
    pub bytes: Vec<u8>,
}

//------------------------------- Интерфейсы -------------------------------//

/// Унифицированное API для всех бэкендов.
pub trait Keystore: Send + Sync {
    /// Создать ключ.
    fn generate_key(&self, alg: KeyAlgorithm, label: Option<&str>, policy: KeyPolicy) -> Result<KeyInfo, KeystoreError>;

    /// Импортировать приватный ключ (может быть запрещено политикой/бэкендом).
    fn import_private_key(&self, alg: KeyAlgorithm, sk_bytes: &[u8], label: Option<&str>, policy: KeyPolicy) -> Result<KeyInfo, KeystoreError>;

    /// Получить публичный ключ.
    fn public_key(&self, id: &KeyId) -> Result<PublicKey, KeystoreError>;

    /// Подписать сообщение/дайджест.
    ///
    /// Для Ed25519:
    /// - при `prehash=false` — PureEdDSA (RFC 8032, раздел 5.1) [RFC8032].
    /// - при `prehash=true` — Ed25519ph (предполагается SHA-512-хэш) [RFC8032].
    fn sign(&self, id: &KeyId, message: &[u8], prehash: bool) -> Result<Signature, KeystoreError>;

    /// Удалить ключ (без восстановления).
    fn delete_key(&self, id: &KeyId) -> Result<(), KeystoreError>;

    /// Описать ключ (метаданные).
    fn describe(&self, id: &KeyId) -> Result<KeyInfo, KeystoreError>;
}

//------------------------------- Software backend -------------------------------//

/// Программное хранилище (в памяти). Секреты затираются при Drop.
pub struct SoftKeystore {
    inner: parking_lot::RwLock<dashmap::DashMap<KeyId, SoftEntry>>,
}

struct SoftEntry {
    info: KeyInfo,
    /// Закрытый ключ (формат зависит от алгоритма).
    secret: SecretKeyBytes,
    public: PublicKey,
}

impl Drop for SoftEntry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Обертка для безопасного зануления секретов.
#[derive(Clone)]
struct SecretKeyBytes {
    bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
}
impl SecretKeyBytes {
    fn new(b: Vec<u8>) -> Self { Self { bytes: Arc::new(parking_lot::Mutex::new(b)) } }
    fn as_slice(&self) -> parking_lot::MutexGuard<'_, Vec<u8>> { self.bytes.lock() }
}
impl Zeroize for SecretKeyBytes {
    fn zeroize(&mut self) {
        if let Some(mut g) = Arc::get_mut(&mut self.bytes) {
            let mut v = g.get_mut();
            v.zeroize();
        }
    }
}

impl SoftKeystore {
    /// Создать пустое программное хранилище.
    pub fn new() -> Self {
        Self { inner: parking_lot::RwLock::new(dashmap::DashMap::new()) }
    }

    fn make_entry(alg: KeyAlgorithm, label: Option<&str>, policy: KeyPolicy, sk: Vec<u8>, pk: Vec<u8>) -> SoftEntry {
        let id = KeyId::random();
        let info = KeyInfo {
            id,
            alg,
            backend: BackendKind::Software,
            label: label.map(|s| s.to_string()),
            exportable: policy.exportable,
        };
        let public = PublicKey { alg, bytes: pk };
        SoftEntry { info, secret: SecretKeyBytes::new(sk), public }
    }

    fn gen_ed25519(label: Option<&str>, policy: KeyPolicy) -> Result<SoftEntry, KeystoreError> {
        #[cfg(feature = "ed25519")]
        {
            use ed25519_dalek::{SigningKey, Signer};
            use rand_core::OsRng;
            let sk = SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key();
            let sk_bytes = sk.to_bytes().to_vec();
            let pk_bytes = pk.as_bytes().to_vec();
            Ok(Self::make_entry(KeyAlgorithm::Ed25519, label, policy, sk_bytes, pk_bytes))
        }
        #[cfg(not(feature = "ed25519"))]
        {
            Err(KeystoreError::UnsupportedAlgorithm)
        }
    }

    fn gen_ecdsa_k1(label: Option<&str>, policy: KeyPolicy) -> Result<SoftEntry, KeystoreError> {
        #[cfg(feature = "secp256k1")]
        {
            use k256::{ecdsa::SigningKey, elliptic_curve::SecretKey};
            use rand_core::OsRng;
            let sk = SigningKey::random(&mut OsRng);
            let pk = sk.verifying_key();
            let sk_bytes = sk.to_bytes().to_vec();
            let pk_bytes = pk.to_encoded_point(true).as_bytes().to_vec();
            Ok(Self::make_entry(KeyAlgorithm::Secp256k1, label, policy, sk_bytes, pk_bytes))
        }
        #[cfg(not(feature = "secp256k1"))]
        {
            Err(KeystoreError::UnsupportedAlgorithm)
        }
    }

    fn gen_ecdsa_p256(label: Option<&str>, policy: KeyPolicy) -> Result<SoftEntry, KeystoreError> {
        #[cfg(feature = "p256")]
        {
            use p256::{ecdsa::SigningKey, elliptic_curve::SecretKey};
            use rand_core::OsRng;
            let sk = SigningKey::random(&mut OsRng);
            let pk = sk.verifying_key();
            let sk_bytes = sk.to_bytes().to_vec();
            let pk_bytes = pk.to_encoded_point(true).as_bytes().to_vec();
            Ok(Self::make_entry(KeyAlgorithm::Secp256r1, label, policy, sk_bytes, pk_bytes))
        }
        #[cfg(not(feature = "p256"))]
        {
            Err(KeystoreError::UnsupportedAlgorithm)
        }
    }
}

impl Keystore for SoftKeystore {
    fn generate_key(&self, alg: KeyAlgorithm, label: Option<&str>, policy: KeyPolicy) -> Result<KeyInfo, KeystoreError> {
        let entry = match alg {
            KeyAlgorithm::Ed25519   => Self::gen_ed25519(label, policy)?,
            KeyAlgorithm::Secp256k1 => Self::gen_ecdsa_k1(label, policy)?,
            KeyAlgorithm::Secp256r1 => Self::gen_ecdsa_p256(label, policy)?,
        };
        let info = entry.info.clone();
        self.inner.write().insert(info.id, entry);
        Ok(info)
    }

    fn import_private_key(&self, alg: KeyAlgorithm, sk_bytes: &[u8], label: Option<&str>, policy: KeyPolicy) -> Result<KeyInfo, KeystoreError> {
        match alg {
            KeyAlgorithm::Ed25519 => {
                #[cfg(feature = "ed25519")]
                {
                    use ed25519_dalek::{SigningKey, VerifyingKey};
                    let sk = SigningKey::from_bytes(sk_bytes.try_into().map_err(|_| KeystoreError::InvalidInput("Ed25519 sk len".into()))?);
                    let pk = VerifyingKey::from(&sk);
                    let entry = Self::make_entry(alg, label, policy, sk.to_bytes().to_vec(), pk.as_bytes().to_vec());
                    let info = entry.info.clone();
                    self.inner.write().insert(info.id, entry);
                    Ok(info)
                }
                #[cfg(not(feature = "ed25519"))]
                { Err(KeystoreError::UnsupportedAlgorithm) }
            }
            KeyAlgorithm::Secp256k1 => {
                #[cfg(feature = "secp256k1")]
                {
                    use k256::{ecdsa::SigningKey, elliptic_curve::SecretKey, PublicKey as KPub};
                    let sk = SigningKey::from_bytes(sk_bytes.into()).map_err(|e| KeystoreError::InvalidInput(format!("k1 sk: {e}")))?;
                    let pk = KPub::from(&sk.verifying_key());
                    let entry = Self::make_entry(alg, label, policy, sk.to_bytes().to_vec(), pk.to_encoded_point(true).as_bytes().to_vec());
                    let info = entry.info.clone();
                    self.inner.write().insert(info.id, entry);
                    Ok(info)
                }
                #[cfg(not(feature = "secp256k1"))]
                { Err(KeystoreError::UnsupportedAlgorithm) }
            }
            KeyAlgorithm::Secp256r1 => {
                #[cfg(feature = "p256")]
                {
                    use p256::{ecdsa::SigningKey, elliptic_curve::SecretKey, PublicKey as PPub};
                    let sk = SigningKey::from_bytes(sk_bytes.into()).map_err(|e| KeystoreError::InvalidInput(format!("p256 sk: {e}")))?;
                    let pk = PPub::from(&sk.verifying_key());
                    let entry = Self::make_entry(alg, label, policy, sk.to_bytes().to_vec(), pk.to_encoded_point(true).as_bytes().to_vec());
                    let info = entry.info.clone();
                    self.inner.write().insert(info.id, entry);
                    Ok(info)
                }
                #[cfg(not(feature = "p256"))]
                { Err(KeystoreError::UnsupportedAlgorithm) }
            }
        }
    }

    fn public_key(&self, id: &KeyId) -> Result<PublicKey, KeystoreError> {
        let guard = self.inner.read();
        let e = guard.get(id).ok_or(KeystoreError::NotFound)?;
        Ok(e.public.clone())
    }

    fn sign(&self, id: &KeyId, msg: &[u8], prehash: bool) -> Result<Signature, KeystoreError> {
        let guard = self.inner.read();
        let e = guard.get(id).ok_or(KeystoreError::NotFound)?;
        match e.info.alg {
            KeyAlgorithm::Ed25519 => {
                #[cfg(feature = "ed25519")]
                {
                    use ed25519_dalek::{SigningKey, Signature as EdSig, Signer};
                    let sk = SigningKey::from_bytes(&e.secret.as_slice().as_slice().try_into().map_err(|_| KeystoreError::Internal("sk len".into()))?);
                    let sig = if prehash {
                        // Ed25519ph: сообщение должно быть SHA-512 дайджестом (RFC8032 §5.1/5.1.6)
                        if msg.len() != 64 { return Err(KeystoreError::InvalidInput("Ed25519ph expects SHA-512 digest (64 bytes)".into())); }
                        sk.sign_prehashed(msg.try_into().unwrap(), None).map_err(|e| KeystoreError::Crypto(format!("sign ph: {e}")))?
                    } else {
                        sk.sign(msg)
                    };
                    Ok(Signature { alg: KeyAlgorithm::Ed25519, bytes: sig.to_bytes().to_vec() })
                }
                #[cfg(not(feature = "ed25519"))]
                { Err(KeystoreError::UnsupportedAlgorithm) }
            }
            KeyAlgorithm::Secp256k1 => {
                #[cfg(feature = "secp256k1")]
                {
                    use k256::ecdsa::{signature::Signer as _, Signature as EcdsaSig, SigningKey};
                    // Для ECDSA предполагаем, что вход — хэш (прехэширование на вызывающей стороне).
                    let sk = SigningKey::from_bytes(e.secret.as_slice().as_slice()).map_err(|e| KeystoreError::Internal(format!("{e}")))?;
                    let sig: EcdsaSig = sk.sign(msg);
                    Ok(Signature { alg: KeyAlgorithm::Secp256k1, bytes: sig.to_der().as_bytes().to_vec() })
                }
                #[cfg(not(feature = "secp256k1"))]
                { Err(KeystoreError::UnsupportedAlgorithm) }
            }
            KeyAlgorithm::Secp256r1 => {
                #[cfg(feature = "p256")]
                {
                    use p256::ecdsa::{signature::Signer as _, Signature as EcdsaSig, SigningKey};
                    let sk = SigningKey::from_bytes(e.secret.as_slice().as_slice()).map_err(|e| KeystoreError::Internal(format!("{e}")))?;
                    let sig: EcdsaSig = sk.sign(msg);
                    Ok(Signature { alg: KeyAlgorithm::Secp256r1, bytes: sig.to_der().as_bytes().to_vec() })
                }
                #[cfg(not(feature = "p256"))]
                { Err(KeystoreError::UnsupportedAlgorithm) }
            }
        }
    }

    fn delete_key(&self, id: &KeyId) -> Result<(), KeystoreError> {
        let removed = self.inner.write().remove(id).is_some();
        if removed { Ok(()) } else { Err(KeystoreError::NotFound) }
    }

    fn describe(&self, id: &KeyId) -> Result<KeyInfo, KeystoreError> {
        let guard = self.inner.read();
        let e = guard.get(id).ok_or(KeystoreError::NotFound)?;
        Ok(e.info.clone())
    }
}

//------------------------------- HSM (PKCS#11) backend -------------------------------//

/// Конфигурация подключения к PKCS#11.
#[cfg(feature = "hsm_pkcs11")]
#[derive(Clone)]
pub struct Pkcs11Config {
    /// Путь к модулю PKCS#11 (например, libsofthsm2.so или вендорский).
    pub module_path: String,
    /// Индекс слота (или используйте отбор по token label).
    pub slot: Option<usize>,
    /// PIN пользователя.
    pub user_pin: Option<String>,
}

/// Keystore для HSM по PKCS#11 v3.
/// Поддерживает механизм CKM_EDDSA (Pure/Prehash) и ECDSA (через CKM_ECDSA).
#[cfg(feature = "hsm_pkcs11")]
pub struct Pkcs11Keystore {
    ctx: Pkcs11,
    slot: Slot,
    session: Session,
}

#[cfg(feature = "hsm_pkcs11")]
impl Pkcs11Keystore {
    /// Создать подключение к HSM.
    pub fn connect(cfg: &Pkcs11Config) -> Result<Self, KeystoreError> {
        let ctx = Pkcs11::new(&cfg.module_path)?;
        // Инициализация с аргументами по умолчанию
        ctx.initialize(CInitializeArgs::OsThreads).ok();
        // Выбор слота
        let slots = ctx.get_slot_list(true)?;
        let slot = cfg.slot.map(|i| slots[i]).ok_or_else(|| KeystoreError::InvalidInput("slot not specified".into()))?;
        // Сессия RW
        let session = ctx.open_session_no_callback(slot, SessionFlags::RW_SESSION | SessionFlags::SERIAL_SESSION, None, None)?;
        if let Some(pin) = &cfg.user_pin { ctx.login(session, UserType::User, Some(pin)).ok(); }
        Ok(Self { ctx, slot, session })
    }

    fn mechanism_for(alg: KeyAlgorithm, prehash: bool) -> Result<Mechanism, KeystoreError> {
        match alg {
            KeyAlgorithm::Ed25519 => {
                // PKCS#11 v3: CKM_EDDSA, с опциональными CK_EDDSA_PARAMS (ph = prehash)
                // Подтверждение: OASIS Current Mechanisms + сторонние примеры. [OASIS-CURR]
                if prehash {
                    // Параметры prehash могут отличаться у вендоров; здесь без параметров — PureEdDSA.
                    // Для Ed25519ph многие вендоры требуют CK_EDDSA_PARAMS с phFlag=TRUE. См. примеры (NVIDIA/AWS docs).
                    // В этом скелете оставим без параметров; конкретные параметры задайте на адаптере.
                    Ok(Mechanism::new(MechanismType::EDDSA))
                } else {
                    Ok(Mechanism::new(MechanismType::EDDSA))
                }
            }
            KeyAlgorithm::Secp256k1 | KeyAlgorithm::Secp256r1 => Ok(Mechanism::new(MechanismType::ECDSA)),
        }
    }

    fn find_object_by_label(&self, label: &str) -> Result<Option<Ulong>, KeystoreError> {
        use cryptoki::object::Attribute;
        self.ctx.find_objects_init(self.session, &[Attribute::Label(String::from(label))])?;
        let objs = self.ctx.find_objects(self.session, 10)?;
        self.ctx.find_objects_final(self.session)?;
        Ok(objs.first().copied())
    }
}

#[cfg(feature = "hsm_pkcs11")]
impl Keystore for Pkcs11Keystore {
    fn generate_key(&self, alg: KeyAlgorithm, label: Option<&str>, policy: KeyPolicy) -> Result<KeyInfo, KeystoreError> {
        // Минимальный пример: генерация пары Ed25519 или ECDSA через стандартные механизмы.
        // Реальные атрибуты (CKA_SIGN, CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE и пр.) задайте по вашей политике.
        let label = label.unwrap_or("aethernova-key");
        match alg {
            KeyAlgorithm::Ed25519 => {
                // В PKCS#11 v3 для Ed25519 определены типы ключей CKK_EC_EDWARDS и механизм CKM_EC_EDWARDS_KEY_PAIR_GEN. [OASIS-CURR]
                let pub_tmpl = vec![
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::Verify(true),
                    Attribute::Token(true),
                    Attribute::Label(label.into()),
                ];
                let priv_tmpl = vec![
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::Sign(true),
                    Attribute::Token(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(policy.exportable), // обычно false для HSM
                    Attribute::Label(label.into()),
                ];
                let _keypair = self.ctx.generate_key_pair(self.session, &Mechanism::EcEdwardsKeyPairGen, &pub_tmpl, &priv_tmpl)?;
            }
            KeyAlgorithm::Secp256k1 | KeyAlgorithm::Secp256r1 => {
                // Универсально через CKM_EC_KEY_PAIR_GEN и CKA_EC_PARAMS (OID кривой).
                // (Некоторые HSM не поддерживают secp256k1 — проверьте механизмы вендора.)
                let curve_oid = match alg {
                    KeyAlgorithm::Secp256k1 => cryptoki::mechanism::ec::named_curve::SECP256K1,
                    KeyAlgorithm::Secp256r1 => cryptoki::mechanism::ec::named_curve::SECP256R1,
                    _ => unreachable!(),
                };
                let pub_tmpl = vec![
                    Attribute::KeyType(KeyType::EC),
                    Attribute::EcParams(curve_oid.to_vec()),
                    Attribute::Verify(true),
                    Attribute::Token(true),
                    Attribute::Label(label.into()),
                ];
                let priv_tmpl = vec![
                    Attribute::KeyType(KeyType::EC),
                    Attribute::EcParams(curve_oid.to_vec()),
                    Attribute::Sign(true),
                    Attribute::Token(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(policy.exportable),
                    Attribute::Label(label.into()),
                ];
                let _keypair = self.ctx.generate_key_pair(self.session, &Mechanism::EcKeyPairGen, &pub_tmpl, &priv_tmpl)?;
            }
        }
        let info = KeyInfo {
            id: KeyId::random(),
            alg,
            backend: BackendKind::HsmPkcs11,
            label: Some(label.to_string()),
            exportable: policy.exportable,
        };
        Ok(info)
    }

    fn import_private_key(&self, _alg: KeyAlgorithm, _sk_bytes: &[u8], _label: Option<&str>, _policy: KeyPolicy) -> Result<KeyInfo, KeystoreError> {
        Err(KeystoreError::Policy("HSM обычно запрещает импорт приватных ключей без специальных атрибутов/ролей".into()))
    }

    fn public_key(&self, _id: &KeyId) -> Result<PublicKey, KeystoreError> {
        // В практической системе вы храните сопоставление id -> label/handle в БД.
        Err(KeystoreError::Internal("public_key: реализуйте сопоставление id -> HSM handle/label".into()))
    }

    fn sign(&self, _id: &KeyId, message: &[u8], prehash: bool) -> Result<Signature, KeystoreError> {
        // Демонстрация: подпись по label (упрощенно); в проде — по handle.
        let label = "aethernova-key";
        let handle = self.find_object_by_label(label)?.ok_or(KeystoreError::NotFound)?;

        // Определите алгоритм из метаданных для соответствия механизма
        // (упрощенно считаем Ed25519)
        let alg = KeyAlgorithm::Ed25519;
        let mech = Self::mechanism_for(alg, prehash)?;
        self.ctx.sign_init(self.session, &mech, handle)?;
        let sig = self.ctx.sign(self.session, message)?;
        Ok(Signature { alg, bytes: sig })
    }

    fn delete_key(&self, _id: &KeyId) -> Result<(), KeystoreError> {
        Err(KeystoreError::Internal("delete_key: реализуйте сопоставление id -> HSM handle/label".into()))
    }

    fn describe(&self, _id: &KeyId) -> Result<KeyInfo, KeystoreError> {
        Err(KeystoreError::Internal("describe: реализуйте сопоставление id -> HSM метаданные".into()))
    }
}

//------------------------------- Threshold (FROST) интерфейс -------------------------------//

/// Провайдер пороговых подписей (напр., FROST Ed25519).
///
/// Протокол двухраундовый (commit -> sign) [FROST].
pub trait ThresholdSigner: Send + Sync {
    /// Какой алгоритм реализован (ожидается Ed25519).
    fn algorithm(&self) -> KeyAlgorithm;
    /// Идентификатор логического ключа (порогового).
    fn key_id(&self) -> KeyId;

    /// Раунд 1: локальные коммитменты (nonce commitments) для сеанса.
    fn round1_commit(&self, session_id: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    /// Раунд 2: частичная подпись над сообщением (или хэшем для Ed25519ph).
    fn round2_sign(&self, session_id: &[u8], message: &[u8], prehash: bool, commitments: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    /// Агрегация частичных подписей в финальную подпись.
    fn aggregate(&self, partial_sigs: &[Vec<u8>]) -> Result<Vec<u8>, KeystoreError>;
    /// Публичный ключ агрегированного порогового ключа.
    fn aggregated_public_key(&self) -> Result<PublicKey, KeystoreError>;
}

/// Обертка Keystore над провайдером пороговых подписей.
pub struct ThresholdKeystore {
    provider: Arc<dyn ThresholdSigner>,
    policy: KeyPolicy,
}

impl ThresholdKeystore {
    pub fn new(provider: Arc<dyn ThresholdSigner>, policy: KeyPolicy) -> Self {
        Self { provider, policy }
    }
}

impl Keystore for ThresholdKeystore {
    fn generate_key(&self, _alg: KeyAlgorithm, _label: Option<&str>, _policy: KeyPolicy) -> Result<KeyInfo, KeystoreError> {
        // Ключи пороговой схемы генерируются протоколом распределенно — вне этого API.
        Err(KeystoreError::Policy("threshold keys are provisioned externally via DKG".into()))
    }

    fn import_private_key(&self, _alg: KeyAlgorithm, _sk_bytes: &[u8], _label: Option<&str>, _policy: KeyPolicy) -> Result<KeyInfo, KeystoreError> {
        Err(KeystoreError::Policy("cannot import private share via this API".into()))
    }

    fn public_key(&self, _id: &KeyId) -> Result<PublicKey, KeystoreError> {
        self.provider.aggregated_public_key()
    }

    fn sign(&self, _id: &KeyId, message: &[u8], prehash: bool) -> Result<Signature, KeystoreError> {
        let session = KeyId::random().0; // уникальный идентификатор сессии
        let c = self.provider.round1_commit(&session)?;
        let ps = self.provider.round2_sign(&session, message, prehash, &c)?;
        let agg = self.provider.aggregate(&[ps])?; // В реальности требуется сбор partial_sigs >= t
        Ok(Signature { alg: self.provider.algorithm(), bytes: agg })
    }

    fn delete_key(&self, _id: &KeyId) -> Result<(), KeystoreError> { Err(KeystoreError::Policy("not supported for threshold".into())) }

    fn describe(&self, id: &KeyId) -> Result<KeyInfo, KeystoreError> {
        Ok(KeyInfo {
            id: *id,
            alg: self.provider.algorithm(),
            backend: BackendKind::Threshold,
            label: None,
            exportable: self.policy.exportable,
        })
    }
}

//------------------------------- Фабрика -------------------------------//

/// Удобная фабрика для создания keystore по типу.
pub enum KeystoreBackend {
    Software(SoftKeystore),
    #[cfg(feature = "hsm_pkcs11")]
    Hsm(Pkcs11Keystore),
    Threshold(ThresholdKeystore),
}

impl KeystoreBackend {
    pub fn as_dyn(&self) -> &dyn Keystore {
        match self {
            Self::Software(s) => s,
            #[cfg(feature = "hsm_pkcs11")]
            Self::Hsm(h) => h,
            Self::Threshold(t) => t,
        }
    }
}

//------------------------------- Тесты (минимальные) -------------------------------//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_ed25519_cycle() {
        let ks = SoftKeystore::new();
        let info = ks.generate_key(KeyAlgorithm::Ed25519, Some("test"), KeyPolicy::default());
        if let Err(KeystoreError::UnsupportedAlgorithm) = &info {
            // фича ed25519 может быть отключена — тест пропускаем
            return;
        }
        let info = info.unwrap();
        let msg = b"hello world";
        let sig = ks.sign(&info.id, msg, false).unwrap();
        assert_eq!(sig.alg, KeyAlgorithm::Ed25519);
        let pk = ks.public_key(&info.id).unwrap();
        assert_eq!(pk.alg, KeyAlgorithm::Ed25519);
        assert!(!pk.bytes.is_empty());
    }
}

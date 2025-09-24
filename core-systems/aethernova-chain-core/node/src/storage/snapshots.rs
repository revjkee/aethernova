//! Aethernova Node — State Snapshots for Light Clients
//! ---------------------------------------------------
//! Назначение:
//!   • Стриминговая сборка снапшота состояния (K/V) в чанки фиксированного размера.
//!   • Файловый бэкенд: сохранение manifest + чанки + хэши.
//!   • Проверка целостности: хэши чанков + корень Меркла по RFC-подобной схеме (двухветвевой).
//!   • Восстановление по чанкам с онлайновой верификацией.
//!   • Совместимая модель метаданных: height/format/chunks/hash/metadata (см. Cosmos SDK).
//!
//! ВНИМАНИЕ (крипто):
//!   По умолчанию используется некриптографический хеш (`DefaultHasher`), пригодный для
//!   демонстрации и оффлайн-проверок, но НЕ для криптографической аутентичности.
//!   Для продакшена подключите SHA-256/Blake2 и замените `HasherImpl`.
//!
//! Ссылки (спецификации/термины):
//!   • Tendermint/CometBFT Light Client: мерклизуемая верификация состояния из корня приложения,
//!     state sync использует ABCI снапшоты (height/format/chunks/hash/metadata).
//!   • Cosmos SDK snapshots API отражает это в типе Snapshot{height,format,chunks,hash,metadata}.
//!   • Для дерева Меркла (двухветвевое, конкатенация дочерних хешей) ориентир — RFC 6962.
//!
//! Без внешних зависимостей. Файл автономен.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Версия формата снапшота (совместимость с внешними инструментами).
pub const SNAPSHOT_FORMAT_V1: u32 = 1;

/// Размер чанка по умолчанию (байт). 2 MiB — безопасный дефолт для большинства дисков/сетей.
/// Подбирайте под ваш профиль (IOPS/MTU/latency). Значение не «жёсткое».
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Встроенная простая метка времени (мс от UNIX EPOCH).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Некриптографический 64-битный хеш (замените в продакшене).
#[derive(Clone, Copy, Default)]
pub struct NonCrypto64;

impl NonCrypto64 {
    pub fn hash_slice(data: &[u8]) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        data.hash(&mut h);
        h.finish()
    }
}

/// Интерфейс «провайдера» ключ/значение для построения снапшота.
/// Итератор должен возвращать пары в детерминированном порядке.
pub trait SnapshotSource {
    /// Возвращает детерминированный итератор по (key, value).
    fn iter(&self) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + Send>;
    /// Высота состояния (для метаданных/корреляции с блоком).
    fn height(&self) -> u64;
    /// Хеш предыдущего состояния/апп-хеш (опционально).
    fn app_hash(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Дополнительные метаданные снапшота (свободная форма).
#[derive(Clone, Debug, Default)]
pub struct SnapshotMetadata {
    pub app_version: u64,                // версия приложения/схемы
    pub timestamp_ms: u128,              // момент сборки
    pub extra: BTreeMap<String, String>, // произвольные пары
}

/// Заголовок снапшота в духе Cosmos SDK: height/format/chunks/hash.
#[derive(Clone, Debug)]
pub struct SnapshotHeader {
    pub height: u64,
    pub format: u32,
    pub chunks: u32,
    /// Корень Меркла по хешам чанков (u64 по умолчанию; замените на SHA-256 для продакшена).
    pub merkle_root: u64,
}

/// Полное описание снапшота.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub header: SnapshotHeader,
    pub metadata: SnapshotMetadata,
    /// Индивидуальные хеши чанков (для ускоренной верификации).
    pub chunk_hashes: Vec<u64>,
    /// Хеш исходного `app_hash`/корня приложения, если известен.
    pub app_hash_hint: Option<Vec<u8>>,
}

/// Конфигурация сборки снапшота.
#[derive(Clone, Debug)]
pub struct SnapshotBuildConfig {
    pub chunk_size: usize,
    pub output_dir: PathBuf,
}

impl Default for SnapshotBuildConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            output_dir: PathBuf::from("snapshots"),
        }
    }
}

/// Ошибки подсистемы снапшотов.
#[derive(thiserror::Error, Debug)]
pub enum SnapshotError {
    #[error("io error: {0}")]
    Io(String),
    #[error("invalid snapshot: {0}")]
    Invalid(String),
    #[error("integrity error: {0}")]
    Integrity(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl From<std::io::Error> for SnapshotError {
    fn from(e: std::io::Error) -> Self {
        SnapshotError::Io(e.to_string())
    }
}

/// Запись для стримингового файла чанка: [k_len u32][v_len u32][key..][value..]
fn write_record(mut out: &File, k: &[u8], v: &[u8]) -> Result<(), SnapshotError> {
    let k_len = k.len() as u32;
    let v_len = v.len() as u32;
    out.write_all(&k_len.to_le_bytes())?;
    out.write_all(&v_len.to_le_bytes())?;
    out.write_all(k)?;
    out.write_all(v)?;
    Ok(())
}

/// Чтение записи; возвращает None при достижении EOF между записями.
fn read_record(mut f: &File) -> Result<Option<(Vec<u8>, Vec<u8>)>, SnapshotError> {
    let mut len_buf = [0u8; 4];
    let n = f.read(&mut len_buf)?;
    if n == 0 {
        return Ok(None);
    }
    if n < 4 {
        return Err(SnapshotError::Invalid("truncated key length".into()));
    }
    let k_len = u32::from_le_bytes(len_buf) as usize;
    f.read_exact(&mut len_buf)?;
    let v_len = u32::from_le_bytes(len_buf) as usize;
    let mut k = vec![0u8; k_len];
    let mut v = vec![0u8; v_len];
    f.read_exact(&mut k)?;
    f.read_exact(&mut v)?;
    Ok(Some((k, v)))
}

/// Структура для сборки снапшота.
pub struct SnapshotBuilder {
    cfg: SnapshotBuildConfig,
}

impl SnapshotBuilder {
    pub fn new(cfg: SnapshotBuildConfig) -> Self {
        Self { cfg }
    }

    /// Сборка снапшота из источника.
    /// Создаёт каталог: {output_dir}/h{height}.f{format}/
    /// Внутри:
    ///   manifest.txt
    ///   chunks/00000000.chk, 00000001.chk, ...
    ///   chunk_hashes.bin  (u64 LE на каждый чанк)
    pub fn build<S: SnapshotSource>(&self, src: &S) -> Result<Snapshot, SnapshotError> {
        let height = src.height();
        let format = SNAPSHOT_FORMAT_V1;

        let base = self
            .cfg
            .output_dir
            .join(format!("h{}.f{}", height, format));
        let chunk_dir = base.join("chunks");
        fs::create_dir_all(&chunk_dir)?;

        let mut chunk_idx: u32 = 0;
        let mut chunk_buf: Vec<u8> = Vec::with_capacity(self.cfg.chunk_size);
        let mut chunk_hashes: Vec<u64> = Vec::new();

        // Потоковая запись записей, ротация чанка по размеру.
        for (k, v) in src.iter() {
            // Оценим размер записи:
            let record_size = 8 + k.len() + v.len(); // 2×u32 + key + value
            if chunk_buf.len() + record_size > self.cfg.chunk_size && !chunk_buf.is_empty() {
                // сбросить текущий чанк
                let p = chunk_dir.join(format!("{:08}.chk", chunk_idx));
                let mut f = File::create(&p)?;
                f.write_all(&chunk_buf)?;
                // хеш чанка
                let h = NonCrypto64::hash_slice(&chunk_buf);
                chunk_hashes.push(h);
                chunk_idx += 1;
                chunk_buf.clear();
            }
            // сериализуем запись во временный буфер
            let mut tmp = Vec::with_capacity(record_size);
            tmp.extend_from_slice(&(k.len() as u32).to_le_bytes());
            tmp.extend_from_slice(&(v.len() as u32).to_le_bytes());
            tmp.extend_from_slice(&k);
            tmp.extend_from_slice(&v);
            chunk_buf.extend_from_slice(&tmp);
        }

        // Финальный чанк.
        if !chunk_buf.is_empty() || chunk_idx == 0 {
            let p = chunk_dir.join(format!("{:08}.chk", chunk_idx));
            let mut f = File::create(&p)?;
            f.write_all(&chunk_buf)?;
            let h = NonCrypto64::hash_slice(&chunk_buf);
            chunk_hashes.push(h);
        }

        let chunks = chunk_hashes.len() as u32;
        // Построение корня Меркла по хешам чанков.
        let merkle_root = merkle_root_u64(&chunk_hashes);

        // Сохраняем список хешей (u64 LE) для быстрой верификации.
        {
            let mut f = File::create(base.join("chunk_hashes.bin"))?;
            for h in &chunk_hashes {
                f.write_all(&h.to_le_bytes())?;
            }
        }

        // Пишем манифест в простом, человекочитаемом виде.
        let meta = SnapshotMetadata {
            app_version: 1,
            timestamp_ms: now_ms(),
            extra: BTreeMap::new(),
        };
        write_manifest(
            &base.join("manifest.txt"),
            height,
            format,
            chunks,
            merkle_root,
            &meta,
            src.app_hash(),
        )?;

        Ok(Snapshot {
            header: SnapshotHeader {
                height,
                format,
                chunks,
                merkle_root,
            },
            metadata: meta,
            chunk_hashes,
            app_hash_hint: src.app_hash(),
        })
    }
}

/// Читатель снапшота (файловый).
pub struct SnapshotReader {
    base: PathBuf,
    chunks: u32,
    chunk_dir: PathBuf,
    chunk_hashes: Vec<u64>,
    merkle_root: u64,
}

impl SnapshotReader {
    pub fn open(base_dir: &Path) -> Result<Self, SnapshotError> {
        // Прочесть manifest и chunk_hashes.bin
        let manifest = fs::read_to_string(base_dir.join("manifest.txt"))?;
        let (height, format, chunks, merkle_root) = parse_manifest_header(&manifest)?;
        let chunk_dir = base_dir.join("chunks");
        let chunk_hashes = read_chunk_hashes(base_dir.join("chunk_hashes.bin"))?;
        if chunk_hashes.len() as u32 != chunks {
            return Err(SnapshotError::Invalid(
                "manifest/chunk_hashes mismatch".into(),
            ));
        }
        Ok(Self {
            base: base_dir.to_path_buf(),
            chunks,
            chunk_dir,
            chunk_hashes,
            merkle_root,
        })
    }

    pub fn chunks(&self) -> u32 {
        self.chunks
    }

    /// Читает чанк и возвращает его байты (без декомпрессии).
    pub fn read_chunk(&self, index: u32) -> Result<Vec<u8>, SnapshotError> {
        if index >= self.chunks {
            return Err(SnapshotError::NotFound(format!("chunk {}", index)));
        }
        let p = self.chunk_dir.join(format!("{:08}.chk", index));
        let data = fs::read(&p)?;
        Ok(data)
    }

    /// Проверяет хеш чанка и корректность корня Меркла.
    pub fn verify_chunk(&self, index: u32, chunk_bytes: &[u8]) -> Result<(), SnapshotError> {
        if index >= self.chunks {
            return Err(SnapshotError::Invalid("chunk index out of range".into()));
        }
        let h = NonCrypto64::hash_slice(chunk_bytes);
        let expected = self.chunk_hashes[index as usize];
        if h != expected {
            return Err(SnapshotError::Integrity(format!(
                "chunk {} hash mismatch",
                index
            )));
        }
        // Проверить, что корень Меркла соответствует списку хешей (доп.проверка, O(n))
        let root = merkle_root_u64(&self.chunk_hashes);
        if root != self.merkle_root {
            return Err(SnapshotError::Integrity(
                "merkle root mismatch in manifest".into(),
            ));
        }
        Ok(())
    }

    /// Возвращает Merkle-proof (путь) для заданного чанка (инклюзия).
    /// В продакшене замените у64-хеши на криптографические и сериализуйте путь.
    pub fn inclusion_proof(&self, index: u32) -> Result<Vec<u64>, SnapshotError> {
        if index >= self.chunks {
            return Err(SnapshotError::Invalid("chunk index out of range".into()));
        }
        Ok(merkle_proof_u64(&self.chunk_hashes, index as usize))
    }
}

/// Писатель снапшота (восстановление) с верификацией.
pub struct SnapshotWriter {
    base: PathBuf,
    chunk_dir: PathBuf,
    expected_chunk_hashes: Vec<u64>,
    expected_merkle_root: u64,
    received: Vec<bool>,
}

impl SnapshotWriter {
    pub fn create(target_dir: &Path, expected_chunk_hashes: Vec<u64>, expected_merkle_root: u64) -> Result<Self, SnapshotError> {
        fs::create_dir_all(target_dir)?;
        let chunk_dir = target_dir.join("chunks");
        fs::create_dir_all(&chunk_dir)?;
        let received = vec![false; expected_chunk_hashes.len()];
        Ok(Self {
            base: target_dir.to_path_buf(),
            chunk_dir,
            expected_chunk_hashes,
            expected_merkle_root,
            received,
        })
    }

    /// Записывает и проверяет чанк. Повторная запись того же индекса разрешена (идемпотентна при совпадении).
    pub fn write_chunk(&mut self, index: u32, bytes: &[u8]) -> Result<(), SnapshotError> {
        let idx = index as usize;
        if idx >= self.expected_chunk_hashes.len() {
            return Err(SnapshotError::Invalid("chunk index out of range".into()));
        }
        let h = NonCrypto64::hash_slice(bytes);
        if h != self.expected_chunk_hashes[idx] {
            return Err(SnapshotError::Integrity(format!(
                "chunk {} hash mismatch", index
            )));
        }
        let p = self.chunk_dir.join(format!("{:08}.chk", index));
        if p.exists() {
            // Сравним существующий файл, чтобы избежать случайной подмены
            let existing = fs::read(&p)?;
            let hh = NonCrypto64::hash_slice(&existing);
            if hh != h {
                return Err(SnapshotError::Integrity("conflicting chunk content".into()));
            }
        } else {
            let mut f = File::create(&p)?;
            f.write_all(bytes)?;
        }
        self.received[idx] = true;
        Ok(())
    }

    /// Финализирует сборку: проверяет полноту и корень Меркла.
    pub fn finalize(self) -> Result<(), SnapshotError> {
        if self.received.iter().any(|&r| !r) {
            return Err(SnapshotError::Invalid("not all chunks received".into()));
        }
        let root = merkle_root_u64(&self.expected_chunk_hashes);
        if root != self.expected_merkle_root {
            return Err(SnapshotError::Integrity("merkle root mismatch".into()));
        }
        // Сохраним chunk_hashes.bin для совместимости
        let mut f = File::create(self.base.join("chunk_hashes.bin"))?;
        for h in &self.expected_chunk_hashes {
            f.write_all(&h.to_le_bytes())?;
        }
        Ok(())
    }
}

/* -------------------------- MANIFEST I/O --------------------------- */

fn write_manifest(
    path: &Path,
    height: u64,
    format: u32,
    chunks: u32,
    merkle_root: u64,
    meta: &SnapshotMetadata,
    app_hash_opt: Option<Vec<u8>>,
) -> Result<(), SnapshotError> {
    let mut s = String::new();
    s.push_str(&format!("height={}\n", height));
    s.push_str(&format!("format={}\n", format));
    s.push_str(&format!("chunks={}\n", chunks));
    s.push_str(&format!("merkle_root_u64={}\n", merkle_root));
    if let Some(app_hash) = app_hash_opt {
        s.push_str(&format!("app_hash_hint_hex={}\n", hex(&app_hash)));
    }
    s.push_str(&format!("meta.app_version={}\n", meta.app_version));
    s.push_str(&format!("meta.timestamp_ms={}\n", meta.timestamp_ms));
    for (k, v) in &meta.extra {
        s.push_str(&format!("meta.extra.{}={}\n", k, v));
    }
    fs::write(path, s)?;
    Ok(())
}

fn parse_manifest_header(manifest: &str) -> Result<(u64, u32, u32, u64), SnapshotError> {
    let mut height = None;
    let mut format = None;
    let mut chunks = None;
    let mut root = None;
    for line in manifest.lines() {
        if let Some(v) = line.strip_prefix("height=") {
            height = Some(v.parse::<u64>().map_err(|_| SnapshotError::Invalid("bad height".into()))?);
        } else if let Some(v) = line.strip_prefix("format=") {
            format = Some(v.parse::<u32>().map_err(|_| SnapshotError::Invalid("bad format".into()))?);
        } else if let Some(v) = line.strip_prefix("chunks=") {
            chunks = Some(v.parse::<u32>().map_err(|_| SnapshotError::Invalid("bad chunks".into()))?);
        } else if let Some(v) = line.strip_prefix("merkle_root_u64=") {
            root = Some(v.parse::<u64>().map_err(|_| SnapshotError::Invalid("bad merkle_root".into()))?);
        }
    }
    match (height, format, chunks, root) {
        (Some(h), Some(f), Some(c), Some(r)) => Ok((h, f, c, r)),
        _ => Err(SnapshotError::Invalid("manifest header incomplete".into())),
    }
}

fn read_chunk_hashes(path: PathBuf) -> Result<Vec<u64>, SnapshotError> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    if buf.len() % 8 != 0 {
        return Err(SnapshotError::Invalid("chunk_hashes.bin truncated".into()));
    }
    let mut out = Vec::with_capacity(buf.len() / 8);
    for c in buf.chunks_exact(8) {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(c);
        out.push(u64::from_le_bytes(arr));
    }
    Ok(out)
}

/* --------------------------- MERKLE (u64) -------------------------- */

/// Двухветвевое дерево Меркла над u64-листами.
/// Лист — hash(chunk_i). Узел — H(left||right), где H — здесь NonCrypto64 над LE-байтами.
/// Для нечётного количества листьев последний поднимается вверх (копирование правого = левого).
fn merkle_root_u64(leaves: &[u64]) -> u64 {
    if leaves.is_empty() {
        return 0;
    }
    let mut level: Vec<u64> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let h = if pair.len() == 2 {
                hash_pair_u64(pair[0], pair[1])
            } else {
                // последняя «сирота»
                hash_pair_u64(pair[0], pair[0])
            };
            next.push(h);
        }
        level = next;
    }
    level[0]
}

fn hash_pair_u64(a: u64, b: u64) -> u64 {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&a.to_le_bytes());
    buf[8..].copy_from_slice(&b.to_le_bytes());
    NonCrypto64::hash_slice(&buf)
}

/// Возвращает список «соседних» хешей (аудит-путь) от листа до корня.
fn merkle_proof_u64(leaves: &[u64], index: usize) -> Vec<u64> {
    if leaves.is_empty() || index >= leaves.len() {
        return vec![];
    }
    let mut proof = Vec::new();
    let mut idx = index;
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let is_right = idx % 2 == 1;
        let pair_idx = if is_right { idx - 1 } else { idx + 1 };
        if pair_idx < level.len() {
            proof.push(level[pair_idx]);
        } else {
            // сирота — его «сосед» равен самому себе
            proof.push(level[idx]);
        }
        // переход на следующий уровень
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let h = if pair.len() == 2 {
                hash_pair_u64(pair[0], pair[1])
            } else {
                hash_pair_u64(pair[0], pair[0])
            };
            next.push(h);
        }
        idx /= 2;
        level = next;
    }
    proof
}

/* ------------------------------ UTILS ------------------------------ */

fn hex(b: &[u8]) -> String {
    const TBL: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &bb in b {
        s.push(TBL[(bb >> 4) as usize] as char);
        s.push(TBL[(bb & 0x0f) as usize] as char);
    }
    s
}

/* ------------------------------- TESTS ----------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    struct MapSource {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        h: u64,
        app: Option<Vec<u8>>,
    }
    impl SnapshotSource for MapSource {
        fn iter(&self) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + Send> {
            let it = self.kv.clone().into_iter();
            Box::new(it)
        }
        fn height(&self) -> u64 { self.h }
        fn app_hash(&self) -> Option<Vec<u8>> { self.app.clone() }
    }

    #[test]
    fn build_and_read_snapshot() {
        let mut kv = BTreeMap::new();
        for i in 0..10_000 {
            kv.insert(format!("key{:05}", i).into_bytes(), vec![i as u8; (i % 113) as usize]);
        }
        let src = MapSource { kv, h: 42, app: Some(vec![0xaa, 0xbb, 0xcc]) };
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("snaps");
        let builder = SnapshotBuilder::new(SnapshotBuildConfig { chunk_size: 128 * 1024, output_dir: out.clone() });
        let snap = builder.build(&src).unwrap();

        // Открыть, прочитать один чанк, проверить инклюзию
        let base = out.join(format!("h{}.f{}", snap.header.height, snap.header.format));
        let reader = SnapshotReader::open(&base).unwrap();
        assert_eq!(reader.chunks(), snap.header.chunks);
        let c0 = reader.read_chunk(0).unwrap();
        reader.verify_chunk(0, &c0).unwrap();
        let proof = reader.inclusion_proof(0).unwrap();
        assert!(!proof.is_empty());

        // Воссоздать на другой стороне
        let restore_dir = tmp.path().join("restore");
        let mut writer = SnapshotWriter::create(
            &restore_dir,
            snap.chunk_hashes.clone(),
            snap.header.merkle_root,
        ).unwrap();

        for idx in 0..reader.chunks() {
            let c = reader.read_chunk(idx).unwrap();
            writer.write_chunk(idx, &c).unwrap();
        }
        writer.finalize().unwrap();

        // Проверим chunk_hashes.bin
        let hs = read_chunk_hashes(restore_dir.join("chunk_hashes.bin")).unwrap();
        assert_eq!(hs, snap.chunk_hashes);
    }

    #[test]
    fn merkle_roundtrip() {
        let leaves: Vec<u64> = (0..17).map(|i| NonCrypto64::hash_slice(&i.to_le_bytes())).collect();
        let root = super::merkle_root_u64(&leaves);
        // аудит-путь для каждого листа должен быть валиден
        for (i, _) in leaves.iter().enumerate() {
            let proof = super::merkle_proof_u64(&leaves, i);
            // верификация: свернуть путь вручную
            let mut idx = i;
            let mut h = leaves[i];
            let mut level = leaves.clone();
            while level.len() > 1 {
                let sib = proof.remove(0);
                let combined = if idx % 2 == 0 {
                    super::hash_pair_u64(h, sib)
                } else {
                    super::hash_pair_u64(sib, h)
                };
                // перейти на верхний уровень
                let mut next = Vec::with_capacity((level.len() + 1)/2);
                for pair in level.chunks(2) {
                    let hh = if pair.len() == 2 { super::hash_pair_u64(pair[0], pair[1]) } else { super::hash_pair_u64(pair[0], pair[0]) };
                    next.push(hh);
                }
                idx /= 2;
                h = combined;
                level = next;
            }
            assert_eq!(h, root);
        }
    }
}

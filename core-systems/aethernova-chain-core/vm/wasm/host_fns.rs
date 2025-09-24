//! Host functions for zk-proofs (Groth16 over BN254) and helpers for WASM modules.
//!
//! ABI (stable):
//! - fn zk_groth16_bn254_verify(proof_ptr:u32, proof_len:u32,
//!                              vk_ptr:u32, vk_len:u32,
//!                              inputs_ptr:u32, inputs_len:u32, inputs_count:u32) -> i32
//!     Inputs:
//!       proof:    ark-serialize canonical (uncompressed) bytes of ark_groth16::Proof<Bn254>
//!       vk:       ark-serialize canonical (uncompressed) bytes of ark_groth16::VerifyingKey<Bn254>
//!       inputs:   concatenation of `inputs_count` field elements Fr (BN254 scalar field),
//!                 each exactly 32 bytes little-endian; total = 32 * inputs_count
//!     Return codes:
//!       0 = OK (valid proof), 1 = invalid proof, 2 = parse error, 3 = inputs format error,
//!       4 = OOB memory, 5 = missing memory export, 6 = internal error
//!
//! - fn sha256(data_ptr:u32, data_len:u32, out32_ptr:u32) -> i32
//!     Writes 32-byte digest to out32_ptr. Returns 0 on success.
//!
//! - fn merkle_verify_sha256(leaf_ptr:u32, leaf_len:u32,
//!                           root_ptr:u32,          // 32 bytes
//!                           proof_ptr:u32, proof_len:u32, // concatenated 32-byte siblings
//!                           dirs_ptr:u32, dirs_len:u32     // each byte: 0 = leaf||sib, 1 = sib||leaf
//!                          ) -> i32
//!     Returns 0 if inclusion proof verifies, 1 otherwise; same error codes as выше (4..6).
//!
//! Implementation notes (verifiable sources):
//! - Доступ к линейной памяти WASM осуществляется через wasmtime::Caller и экспорт памяти "memory". :contentReference[oaicite:1]{index=1}
//! - Линейная память в WebAssembly — непрерывный изменяемый массив байтов; обязателен контроль границ. :contentReference[oaicite:2]{index=2}
//! - Groth16: verify_proof/prepare_verifying_key и структуры Proof/VerifyingKey/PreparedVerifyingKey из ark-groth16. :contentReference[oaicite:3]{index=3}
//! - Публичные входы Fr читаются как 32-байтовые little-endian слова через ark_ff::PrimeField::from_le_bytes_mod_order. :contentReference[oaicite:4]{index=4}
//! - Каноническая (де)сериализация криптообъектов — ark-serialize (CanonicalDeserialize). :contentReference[oaicite:5]{index=5}

use std::convert::TryInto;

use wasmtime::{Caller, Extern, Linker, Memory};

use sha2::{Digest, Sha256};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::verifier::prepare_verifying_key;
use ark_serialize::CanonicalDeserialize;
use ark_ff::PrimeField;

/// Хранитель состояния стора (при необходимости можно расширить).
#[derive(Default)]
pub struct HostState;

/// Регистрация всех хост-функций в указанном linker.
pub fn register_host_fns(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    linker.func_wrap(
        "env",
        "zk_groth16_bn254_verify",
        zk_groth16_bn254_verify,
    )?;

    linker.func_wrap(
        "env",
        "sha256",
        sha256_host,
    )?;

    linker.func_wrap(
        "env",
        "merkle_verify_sha256",
        merkle_verify_sha256_host,
    )?;

    Ok(())
}

const RET_OK: i32 = 0;
const RET_INVALID: i32 = 1;
const RET_PARSE: i32 = 2;
const RET_INPUTS: i32 = 3;
const RET_OOB: i32 = 4;
const RET_NO_MEM: i32 = 5;
const RET_INTERNAL: i32 = 6;

/// --- Host: Groth16 verifier over BN254 ---
/// ABI: см. верх комментария.
fn zk_groth16_bn254_verify(
    mut caller: Caller<'_, HostState>,
    proof_ptr: u32,
    proof_len: u32,
    vk_ptr: u32,
    vk_len: u32,
    inputs_ptr: u32,
    inputs_len: u32,
    inputs_count: u32,
) -> i32 {
    // 1) Read memory
    let mem = match get_memory(&mut caller) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let proof_bytes = match read_mem(&mut caller, &mem, proof_ptr, proof_len) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let vk_bytes = match read_mem(&mut caller, &mem, vk_ptr, vk_len) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let inputs_bytes = match read_mem(&mut caller, &mem, inputs_ptr, inputs_len) {
        Ok(v) => v,
        Err(code) => return code,
    };

    // 2) Deserialize Proof and VK (ark-serialize canonical, uncompressed)
    let proof: Proof<Bn254> = match Proof::deserialize_uncompressed(&*proof_bytes) {
        Ok(p) => p,
        Err(_) => return RET_PARSE,
    };
    let vk: VerifyingKey<Bn254> = match VerifyingKey::deserialize_uncompressed(&*vk_bytes) {
        Ok(v) => v,
        Err(_) => return RET_PARSE,
    };
    let pvk = prepare_verifying_key(&vk);

    // 3) Public inputs as 32-byte LE chunks
    let expected_len = inputs_count as usize * 32;
    if inputs_bytes.len() != expected_len {
        return RET_INPUTS;
    }
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(inputs_count as usize);
    for i in 0..(inputs_count as usize) {
        let off = i * 32;
        let chunk: &[u8; 32] = match inputs_bytes[off..off + 32].try_into() {
            Ok(c) => c,
            Err(_) => return RET_INPUTS,
        };
        public_inputs.push(Fr::from_le_bytes_mod_order(chunk));
    }

    // 4) Verify (ark_groth16)
    match Groth16::<Bn254, LibsnarkReduction>::verify_proof(&pvk, &proof, &public_inputs) {
        Ok(true) => RET_OK,
        Ok(false) => RET_INVALID,
        Err(_) => RET_INTERNAL,
    }
}

/// --- Host: SHA-256(data) -> 32 bytes ---
fn sha256_host(
    mut caller: Caller<'_, HostState>,
    data_ptr: u32,
    data_len: u32,
    out32_ptr: u32,
) -> i32 {
    let mem = match get_memory(&mut caller) {
        Ok(m) => m,
        Err(code) => return code,
    };
    let data = match read_mem(&mut caller, &mem, data_ptr, data_len) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let digest = Sha256::digest(&data);
    if write_mem(&mut caller, &mem, out32_ptr, &digest) {
        RET_OK
    } else {
        RET_OOB
    }
}

/// --- Host: Merkle (SHA-256) inclusion verification ---
/// proof = concat of 32-byte siblings; dirs[i]=0 => hash(cur||sib), 1 => hash(sib||cur)
fn merkle_verify_sha256_host(
    mut caller: Caller<'_, HostState>,
    leaf_ptr: u32,
    leaf_len: u32,
    root_ptr: u32,
    proof_ptr: u32,
    proof_len: u32,
    dirs_ptr: u32,
    dirs_len: u32,
) -> i32 {
    let mem = match get_memory(&mut caller) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let leaf = match read_mem(&mut caller, &mem, leaf_ptr, leaf_len) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let root = match read_mem(&mut caller, &mem, root_ptr, 32) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if proof_len % 32 != 0 {
        return RET_INPUTS;
    }
    let sibs = match read_mem(&mut caller, &mem, proof_ptr, proof_len) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let dirs = match read_mem(&mut caller, &mem, dirs_ptr, dirs_len) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let steps = (proof_len / 32) as usize;
    if dirs.len() != steps {
        return RET_INPUTS;
    }

    let mut cur = Sha256::digest(&leaf).to_vec();
    for (i, dir) in dirs.iter().enumerate() {
        let sib = &sibs[i * 32..(i + 1) * 32];
        let mut hasher = Sha256::new();
        match *dir {
            0 => {
                hasher.update(&cur);
                hasher.update(sib);
            }
            1 => {
                hasher.update(sib);
                hasher.update(&cur);
            }
            _ => return RET_INPUTS,
        }
        cur = hasher.finalize().to_vec();
    }
    if cur.as_slice() == root.as_slice() {
        RET_OK
    } else {
        RET_INVALID
    }
}

/// ---- Low-level memory helpers (bounds-checked) ----

fn get_memory<'a>(caller: &mut Caller<'a, HostState>) -> Result<Memory, i32> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(RET_NO_MEM),
    }
}

fn read_mem(
    caller: &mut Caller<'_, HostState>,
    mem: &Memory,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, i32> {
    let start = ptr as usize;
    let end = start.checked_add(len as usize).ok_or(RET_OOB)?;
    let data = mem.data(caller);
    if end > data.len() {
        return Err(RET_OOB);
    }
    Ok(data[start..end].to_vec())
}

fn write_mem(
    caller: &mut Caller<'_, HostState>,
    mem: &Memory,
    ptr: u32,
    bytes: &[u8],
) -> bool {
    let start = ptr as usize;
    let end = match start.checked_add(bytes.len()) {
        Some(v) => v,
        None => return false,
    };
    let data = mem.data_mut(caller);
    if end > data.len() {
        return false;
    }
    data[start..end].copy_from_slice(bytes);
    true
}

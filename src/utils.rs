use std::{fs, path::Path};

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolValue;
use anyhow::Context;
use p3_field::{BasedVectorSpace, PrimeField32};
use serde::Serialize;
use spartan_whir::{digest_to_bytes, engine::F};

use crate::DIGEST_ELEMS;

pub fn to_u256_usize(value: usize) -> U256 {
    U256::from(value)
}

pub fn to_u256_base(value: F) -> U256 {
    U256::from(value.as_canonical_u32())
}

pub fn to_bytes32_digest(digest: &[u64; DIGEST_ELEMS]) -> FixedBytes<32> {
    digest_to_bytes(digest).into()
}

pub fn extension_coeffs_u32<EF>(value: &EF) -> Vec<u32>
where
    EF: BasedVectorSpace<F>,
{
    value
        .as_basis_coefficients_slice()
        .iter()
        .map(|coeff| coeff.as_canonical_u32())
        .collect()
}

pub fn pack_extension_u256<EF>(value: &EF) -> U256
where
    EF: BasedVectorSpace<F>,
{
    let coeffs = value.as_basis_coefficients_slice();
    assert!(coeffs.len() <= 8, "only up to octic packing is supported");

    let mut bytes = [0_u8; 32];
    for (i, coeff) in coeffs.iter().enumerate() {
        let offset = i * 4;
        bytes[offset..offset + 4].copy_from_slice(&coeff.as_canonical_u32().to_be_bytes());
    }

    U256::from_be_bytes(bytes)
}

pub fn u256_hex(value: U256) -> String {
    let bytes = value.to_be_bytes::<32>();
    bytes_hex(&bytes)
}

pub fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn digest_hex(digest: &[u64; DIGEST_ELEMS]) -> String {
    bytes_hex(&digest_to_bytes(digest))
}

pub fn write_abi_file<T: SolValue>(path: &Path, value: &T) -> anyhow::Result<()> {
    fs::write(path, value.abi_encode())
        .with_context(|| format!("failed to write ABI fixture {}", path.display()))
}

pub fn write_json_file<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec_pretty(value)?;
    fs::write(path, encoded)
        .with_context(|| format!("failed to write JSON fixture {}", path.display()))
}

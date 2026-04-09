use std::{fs, path::PathBuf};

use alloy_sol_types::SolValue;
use anyhow::Context;
use spartan_whir_export::{
    whir_blob_export::encode_quartic_whir_blob_v1_from_abi, WhirProof, WhirStatement,
};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os();
    let _bin = args.next();
    let out_dir = args
        .next()
        .map(PathBuf::from)
        .context("usage: reencode-stage4-blobs-from-abi <testdata-dir>")?;

    let statement_raw = fs::read(out_dir.join("quartic_whir_success_statement.abi"))
        .with_context(|| "failed to read quartic_whir_success_statement.abi")?;
    let statement = WhirStatement::abi_decode(&statement_raw, true)
        .context("failed to decode quartic statement ABI")?;

    reencode_blob(
        &out_dir,
        &statement,
        "quartic_whir_success_proof.abi",
        "quartic_whir_success.blob",
    )?;
    reencode_blob(
        &out_dir,
        &statement,
        "quartic_whir_failure_bad_commitment_proof.abi",
        "quartic_whir_failure_bad_commitment.blob",
    )?;
    reencode_blob(
        &out_dir,
        &statement,
        "quartic_whir_failure_bad_stir_query_proof.abi",
        "quartic_whir_failure_bad_stir_query.blob",
    )?;
    reencode_blob(
        &out_dir,
        &statement,
        "quartic_whir_failure_bad_ood_or_transcript_mismatch_proof.abi",
        "quartic_whir_failure_bad_ood_or_transcript_mismatch.blob",
    )?;

    Ok(())
}

fn reencode_blob(
    out_dir: &PathBuf,
    statement: &WhirStatement,
    proof_name: &str,
    blob_name: &str,
) -> anyhow::Result<()> {
    let proof_raw = fs::read(out_dir.join(proof_name))
        .with_context(|| format!("failed to read {proof_name}"))?;
    let proof =
        WhirProof::abi_decode(&proof_raw, true).with_context(|| format!("failed to decode {proof_name}"))?;
    let blob = encode_quartic_whir_blob_v1_from_abi(statement, &proof, 20)
        .with_context(|| format!("failed to encode {blob_name}"))?;
    fs::write(out_dir.join(blob_name), blob)
        .with_context(|| format!("failed to write {blob_name}"))?;
    Ok(())
}

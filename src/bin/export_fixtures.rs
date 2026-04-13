use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_primitives::FixedBytes;
use anyhow::Context;
use serde::Serialize;
use spartan_whir::effective_digest_bytes_for_security_bits;
use spartan_whir_export::{
    abi_export::{
        placeholder_spartan_instance, placeholder_spartan_proof, proof_to_abi, statement_to_abi,
    },
    fixed_config_codegen::generate_quartic_fixed_config_source,
    quartic_fixture::{
        build_quartic_fixture, tamper_first_initial_ood_answer, tamper_first_stir_query,
    },
    spartan_context_fixture::{build_spartan_context_fixture, soundness_assumption_byte},
    transcript::{events_to_abi, TranscriptTraceFile},
    utils::{extension_coeffs_u32, to_u256_base, to_u256_usize, write_abi_file, write_json_file},
    vectors::{generate_field_vectors, generate_merkle_vectors},
    whir_blob_export::encode_quartic_whir_blob_v1,
    ChallengerTranscriptTrace, MerkleLeafHashFixture, MerkleMultiproofFixture,
    MerkleNodeCompressionFixture, MerkleVectorFixture, SpartanTranscriptContextFixture,
    KOALABEAR_MODULUS,
};

/// Summary metadata written alongside the fixtures for human inspection.
#[derive(Debug, Serialize)]
struct Metadata {
    schema_version: &'static str,
    koalabear_modulus: u32,
    whir_fs_pattern_length: usize,
    fixture_family: &'static str,
    notes: Vec<&'static str>,
}

fn bytes32_from_hex(hex_str: &str) -> anyhow::Result<FixedBytes<32>> {
    let encoded = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(encoded)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "expected 32-byte hex digest, got {} bytes",
            encoded.len() / 2
        )
    })?;
    Ok(array.into())
}

fn write_fixture_outputs(out_dir: &Path) -> anyhow::Result<()> {
    let quartic = build_quartic_fixture()?;
    write_quartic_fixed_config(out_dir, &quartic)?;

    let abi_statement = statement_to_abi(&quartic.statement_points, &quartic.statement_evaluations);
    let abi_proof = proof_to_abi(&quartic.proof)?;

    let mut tampered_raw_proof = quartic.proof.clone();
    tampered_raw_proof.initial_commitment[0] ^= 1;
    let tampered_abi_proof = proof_to_abi(&tampered_raw_proof)?;
    let tampered_stir_proof = tamper_first_stir_query(&quartic.proof)?;
    let tampered_stir_abi_proof = proof_to_abi(&tampered_stir_proof)?;
    let tampered_ood_proof = tamper_first_initial_ood_answer(&quartic.proof)?;
    let tampered_ood_abi_proof = proof_to_abi(&tampered_ood_proof)?;
    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(quartic.security.merkle_security_bits as usize);
    let success_blob = encode_quartic_whir_blob_v1(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &quartic.proof,
        effective_digest_bytes,
    )?;
    let tampered_commitment_blob = encode_quartic_whir_blob_v1(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &tampered_raw_proof,
        effective_digest_bytes,
    )?;
    let tampered_stir_blob = encode_quartic_whir_blob_v1(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &tampered_stir_proof,
        effective_digest_bytes,
    )?;
    let tampered_ood_blob = encode_quartic_whir_blob_v1(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &tampered_ood_proof,
        effective_digest_bytes,
    )?;

    write_abi_file(
        &out_dir.join("quartic_whir_success_statement.abi"),
        &abi_statement,
    )?;
    write_abi_file(&out_dir.join("quartic_whir_success_proof.abi"), &abi_proof)?;
    write_abi_file(
        &out_dir.join("quartic_whir_failure_bad_commitment_proof.abi"),
        &tampered_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join("quartic_whir_failure_bad_stir_query_proof.abi"),
        &tampered_stir_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join("quartic_whir_failure_bad_ood_or_transcript_mismatch_proof.abi"),
        &tampered_ood_abi_proof,
    )?;
    fs::write(out_dir.join("quartic_whir_success.blob"), success_blob).with_context(|| {
        format!(
            "failed to write blob fixture {}",
            out_dir.join("quartic_whir_success.blob").display()
        )
    })?;
    fs::write(
        out_dir.join("quartic_whir_failure_bad_commitment.blob"),
        tampered_commitment_blob,
    )
    .with_context(|| {
        format!(
            "failed to write blob fixture {}",
            out_dir
                .join("quartic_whir_failure_bad_commitment.blob")
                .display()
        )
    })?;
    fs::write(
        out_dir.join("quartic_whir_failure_bad_stir_query.blob"),
        tampered_stir_blob,
    )
    .with_context(|| {
        format!(
            "failed to write blob fixture {}",
            out_dir
                .join("quartic_whir_failure_bad_stir_query.blob")
                .display()
        )
    })?;
    fs::write(
        out_dir.join("quartic_whir_failure_bad_ood_or_transcript_mismatch.blob"),
        tampered_ood_blob,
    )
    .with_context(|| {
        format!(
            "failed to write blob fixture {}",
            out_dir
                .join("quartic_whir_failure_bad_ood_or_transcript_mismatch.blob")
                .display()
        )
    })?;

    let field_vectors = generate_field_vectors();
    write_json_file(&out_dir.join("field_vectors.json"), &field_vectors)?;

    let merkle_vectors = generate_merkle_vectors(effective_digest_bytes)?;
    write_json_file(&out_dir.join("merkle_vectors.json"), &merkle_vectors)?;
    let merkle_vectors_abi = MerkleVectorFixture {
        effectiveDigestBytes: to_u256_usize(merkle_vectors.effective_digest_bytes),
        leafHashes: merkle_vectors
            .leaf_hashes
            .iter()
            .map(|vector| MerkleLeafHashFixture {
                values: vector
                    .values
                    .iter()
                    .copied()
                    .map(|value| alloy_primitives::U256::from(value as usize))
                    .collect(),
                digest: bytes32_from_hex(&vector.digest).expect("valid leaf digest"),
            })
            .collect(),
        nodeCompressions: merkle_vectors
            .node_compressions
            .iter()
            .map(|vector| MerkleNodeCompressionFixture {
                left: bytes32_from_hex(&vector.left).expect("valid node left digest"),
                right: bytes32_from_hex(&vector.right).expect("valid node right digest"),
                parent: bytes32_from_hex(&vector.parent).expect("valid node parent digest"),
            })
            .collect(),
        multiproof: MerkleMultiproofFixture {
            depth: to_u256_usize(merkle_vectors.multiproof.depth),
            indices: merkle_vectors
                .multiproof
                .indices
                .iter()
                .copied()
                .map(to_u256_usize)
                .collect(),
            openedRows: merkle_vectors
                .multiproof
                .opened_rows
                .iter()
                .map(|row| {
                    row.iter()
                        .copied()
                        .map(|value| alloy_primitives::U256::from(value as usize))
                        .collect()
                })
                .collect(),
            decommitments: merkle_vectors
                .multiproof
                .decommitments
                .iter()
                .map(|digest| bytes32_from_hex(digest).expect("valid decommitment digest"))
                .collect(),
            expectedRoot: bytes32_from_hex(&merkle_vectors.multiproof.expected_root)
                .expect("valid multiproof root"),
        },
    };
    write_abi_file(&out_dir.join("merkle_vectors.abi"), &merkle_vectors_abi)?;

    let transcript_trace = TranscriptTraceFile {
        prover_events: quartic.prover_trace.clone(),
        verifier_events: quartic.verifier_trace.clone(),
        checkpoint_prover: extension_coeffs_u32(&quartic.checkpoint_prover),
        checkpoint_verifier: extension_coeffs_u32(&quartic.checkpoint_verifier),
        checkpoint_match: quartic.checkpoint_prover == quartic.checkpoint_verifier,
    };
    write_json_file(
        &out_dir.join("transcript_trace_quartic.json"),
        &transcript_trace,
    )?;
    let transcript_trace_abi = ChallengerTranscriptTrace {
        proverEvents: events_to_abi(quartic.prover_trace),
        verifierEvents: events_to_abi(quartic.verifier_trace),
        checkpointProver: extension_coeffs_u32(&quartic.checkpoint_prover)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
        checkpointVerifier: extension_coeffs_u32(&quartic.checkpoint_verifier)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
        checkpointMatch: quartic.checkpoint_prover == quartic.checkpoint_verifier,
    };
    write_abi_file(
        &out_dir.join("transcript_trace_quartic.abi"),
        &transcript_trace_abi,
    )?;

    let spartan_context = build_spartan_context_fixture()?;
    let spartan_context_abi = SpartanTranscriptContextFixture {
        numCons: to_u256_usize(spartan_context.num_cons),
        numVars: to_u256_usize(spartan_context.num_vars),
        numIo: to_u256_usize(spartan_context.num_io),
        securityLevelBits: spartan_context.security.security_level_bits,
        merkleSecurityBits: spartan_context.security.merkle_security_bits,
        soundnessAssumption: soundness_assumption_byte(
            spartan_context.security.soundness_assumption,
        ),
        powBits: spartan_context.whir_params.pow_bits,
        foldingFactor: to_u256_usize(spartan_context.whir_params.folding_factor),
        startingLogInvRate: to_u256_usize(spartan_context.whir_params.starting_log_inv_rate),
        rsDomainInitialReductionFactor: to_u256_usize(
            spartan_context
                .whir_params
                .rs_domain_initial_reduction_factor,
        ),
        publicInputs: spartan_context
            .public_inputs
            .iter()
            .copied()
            .map(to_u256_base)
            .collect(),
        preimage: alloy_primitives::Bytes::from(spartan_context.preimage),
        digest: spartan_context.digest.into(),
        checkpoint: extension_coeffs_u32(&spartan_context.checkpoint)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
    };
    write_abi_file(
        &out_dir.join("spartan_transcript_context_quartic.abi"),
        &spartan_context_abi,
    )?;

    let metadata = Metadata {
        schema_version: "fixtures-v1",
        koalabear_modulus: KOALABEAR_MODULUS,
        whir_fs_pattern_length: quartic.whir_fs_pattern.len(),
        fixture_family: "quartic-standalone-whir",
        notes: vec![
            "Fixtures are generated from a real quartic WHIR proving flow.",
            "Failure fixture mutates initial commitment to force commitment mismatch.",
            "Failure fixture mutates one STIR query opening while keeping commitments and OOD answers intact.",
            "Failure fixture mutates one initial OOD answer, which also changes the downstream transcript.",
            "Blob fixtures encode the current fixed-shape quartic standalone WHIR proof family.",
            "Transcript trace records every observe/sample call in canonical replay form.",
            "Spartan transcript fixture records domain-separator preimage, digest, public inputs, and checkpoint.",
            "Field vectors include base/quartic/octic arithmetic tuples.",
            "Merkle vectors include leaf hashes, node compression, and multiproof root checks.",
        ],
    };
    write_json_file(&out_dir.join("metadata.json"), &metadata)?;

    write_abi_file(
        &out_dir.join("spartan_placeholder_instance.abi"),
        &placeholder_spartan_instance(),
    )?;
    write_abi_file(
        &out_dir.join("spartan_placeholder_proof.abi"),
        &placeholder_spartan_proof(abi_proof),
    )?;

    Ok(())
}

fn write_quartic_fixed_config(
    out_dir: &Path,
    quartic: &spartan_whir_export::quartic_fixture::QuarticFixture,
) -> anyhow::Result<()> {
    let project_root = out_dir
        .parent()
        .context("fixture output directory must be nested under a project root")?;
    let generated_dir = project_root.join("src/generated");
    fs::create_dir_all(&generated_dir).with_context(|| {
        format!(
            "failed to create generated Solidity directory {}",
            generated_dir.display()
        )
    })?;

    let source = generate_quartic_fixed_config_source(quartic);
    fs::write(generated_dir.join("QuarticWhirFixedConfig.sol"), source)
        .context("failed to write QuarticWhirFixedConfig.sol")?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: export_fixtures <output-dir>")?,
    );
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;

    write_fixture_outputs(&out_dir)
}

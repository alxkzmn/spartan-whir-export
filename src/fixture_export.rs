use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_primitives::FixedBytes;
use anyhow::Context;
use serde::Serialize;
use spartan_whir::{effective_digest_bytes_for_security_bits, WhirParams};

use crate::{
    abi_export::{
        placeholder_spartan_instance, placeholder_spartan_proof, proof_to_abi, statement_to_abi,
    },
    fixed_config_codegen::{
        generate_fixed_config_source_named, generate_octic_fixed_config_source_named,
        generate_quartic_fixed_config_source, generate_quartic_fixed_config_source_named,
    },
    octic_fixture::{
        build_octic_k22_jb100_fixture, tamper_first_initial_ood_answer_octic,
        tamper_first_stir_query_octic, OcticFixture, RawWhirProof8, EF8,
    },
    quartic_fixture::{
        build_quartic_fixture_with_params, tamper_first_initial_ood_answer,
        tamper_first_stir_query, QuarticFixture, RawWhirProof4, EF4,
    },
    quintic_fixture::{
        build_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28_fixture,
        build_quintic_k22_jb100_ext5_lir4_ff4_rsv4_fixture,
        tamper_first_initial_ood_answer_quintic, tamper_first_stir_query_quintic, QuinticFixture,
        RawWhirProof5, EF5,
    },
    spartan_context_fixture::{
        build_spartan_context_fixture_octic_k22_jb100, build_spartan_context_fixture_with_params,
        soundness_assumption_byte,
    },
    transcript::{events_to_abi, TranscriptTraceFile},
    utils::{extension_coeffs_u32, to_u256_base, to_u256_usize, write_abi_file, write_json_file},
    vectors::{generate_field_vectors, generate_merkle_vectors},
    whir_blob_export::{
        encode_octic_whir_k22_jb100_blob_v1, encode_quartic_whir_blob_v1,
        encode_quartic_whir_lir11_blob_v1,
        encode_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_blob_v1,
        encode_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv4_blob_v1,
    },
    ChallengerTranscriptTrace, MerkleLeafHashFixture, MerkleMultiproofFixture,
    MerkleNodeCompressionFixture, MerkleVectorFixture, SpartanTranscriptContextFixture,
    FIXTURE_WHIR_PARAMS, FIXTURE_WHIR_PARAMS_LIR11, KOALABEAR_MODULUS,
};

type QuarticBlobEncoder = fn(&[Vec<EF4>], &[EF4], &RawWhirProof4, usize) -> anyhow::Result<Vec<u8>>;
type OcticBlobEncoder = fn(&[Vec<EF8>], &[EF8], &RawWhirProof8, usize) -> anyhow::Result<Vec<u8>>;
type QuinticBlobEncoder = fn(&[Vec<EF5>], &[EF5], &RawWhirProof5, usize) -> anyhow::Result<Vec<u8>>;

/// Summary metadata written alongside the fixtures for human inspection.
#[derive(Debug, Serialize)]
struct Metadata {
    schema_version: &'static str,
    koalabear_modulus: u32,
    whir_fs_pattern_length: usize,
    fixture_family: &'static str,
    notes: Vec<&'static str>,
}

pub fn prepare_output_dir(bin_name: &str) -> anyhow::Result<PathBuf> {
    let out_dir_arg = std::env::args()
        .nth(1)
        .with_context(|| format!("usage: {bin_name} <output-dir>"))?;
    anyhow::ensure!(
        !out_dir_arg.starts_with('-'),
        "output directory must be a path, not an option-like argument: {out_dir_arg}"
    );

    let out_dir = PathBuf::from(&out_dir_arg);
    let parent = out_dir
        .parent()
        .context("output directory must be nested under a project root")?;
    anyhow::ensure!(
        !parent.as_os_str().is_empty(),
        "output directory must be nested under a project root, for example sol-spartan-whir/testdata"
    );

    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;
    Ok(out_dir)
}

pub fn export_current_fixtures(out_dir: &Path) -> anyhow::Result<()> {
    let quartic = build_quartic_fixture_with_params(FIXTURE_WHIR_PARAMS)?;
    write_quartic_fixed_config_named(
        out_dir,
        &quartic,
        "QuarticWhirFixedConfig_lir6_ff5_rsv1.sol",
        "QuarticWhirFixedConfig",
    )?;
    write_schedule_outputs(
        out_dir,
        &quartic,
        FIXTURE_WHIR_PARAMS,
        "quartic_whir_lir6_ff5_rsv1",
        "transcript_trace_quartic_lir6_ff5_rsv1.json",
        "transcript_trace_quartic_lir6_ff5_rsv1.abi",
        "spartan_transcript_context_quartic_lir6_ff5_rsv1.abi",
        "spartan_placeholder_proof_quartic_lir6_ff5_rsv1.abi",
        encode_quartic_whir_blob_v1,
    )?;
    write_common_outputs(out_dir, &quartic)
}

pub fn export_lir11_fixtures(out_dir: &Path) -> anyhow::Result<()> {
    let quartic = build_quartic_fixture_with_params(FIXTURE_WHIR_PARAMS_LIR11)?;
    write_quartic_fixed_config_named(
        out_dir,
        &quartic,
        "QuarticWhirFixedConfig_lir11_ff5_rsv3.sol",
        "QuarticWhirLir11FixedConfig",
    )?;
    write_schedule_outputs(
        out_dir,
        &quartic,
        FIXTURE_WHIR_PARAMS_LIR11,
        "quartic_whir_lir11_ff5_rsv3",
        "transcript_trace_quartic_lir11_ff5_rsv3.json",
        "transcript_trace_quartic_lir11_ff5_rsv3.abi",
        "spartan_transcript_context_quartic_lir11_ff5_rsv3.abi",
        "spartan_placeholder_proof_quartic_lir11_ff5_rsv3.abi",
        encode_quartic_whir_lir11_blob_v1,
    )
}

pub fn export_octic_k22_jb100_fixtures(out_dir: &Path) -> anyhow::Result<()> {
    let octic = build_octic_k22_jb100_fixture()?;
    write_octic_fixed_config_named(
        out_dir,
        &octic,
        "OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1.sol",
        "OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1",
    )?;
    write_octic_schedule_outputs(
        out_dir,
        &octic,
        "octic_whir_k22_jb100_lir6_ff4_rsv1",
        "transcript_trace_octic_k22_jb100_lir6_ff4_rsv1.json",
        "transcript_trace_octic_k22_jb100_lir6_ff4_rsv1.abi",
        "spartan_transcript_context_octic_k22_jb100_lir6_ff4_rsv1.abi",
        "spartan_placeholder_proof_octic_k22_jb100_lir6_ff4_rsv1.abi",
        encode_octic_whir_k22_jb100_blob_v1,
    )
}

pub fn export_quintic_k22_jb100_ext5_lir4_ff4_rsv4_fixtures(out_dir: &Path) -> anyhow::Result<()> {
    let quintic = build_quintic_k22_jb100_ext5_lir4_ff4_rsv4_fixture()?;
    write_quintic_fixed_config_named(
        out_dir,
        &quintic,
        "QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv4.sol",
        "QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv4",
    )?;
    write_quintic_schedule_outputs(
        out_dir,
        &quintic,
        "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv4",
        "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv4.json",
        "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv4.abi",
        encode_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv4_blob_v1,
    )
}

pub fn export_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28_fixtures(
    out_dir: &Path,
) -> anyhow::Result<()> {
    let quintic = build_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28_fixture()?;
    write_quintic_fixed_config_named(
        out_dir,
        &quintic,
        "QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol",
        "QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28",
    )?;
    write_quintic_schedule_outputs(
        out_dir,
        &quintic,
        "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28",
        "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28.json",
        "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28.abi",
        encode_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_blob_v1,
    )
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

fn write_common_outputs(out_dir: &Path, quartic: &QuarticFixture) -> anyhow::Result<()> {
    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(quartic.security.merkle_security_bits as usize);

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

    let metadata = Metadata {
        schema_version: "fixtures-v1",
        koalabear_modulus: KOALABEAR_MODULUS,
        whir_fs_pattern_length: quartic.whir_fs_pattern.len(),
        fixture_family: "quartic-standalone-whir",
        notes: vec![
            "Fixtures are generated from real quartic WHIR proving flows.",
            "Failure fixture mutates initial commitment to force commitment mismatch.",
            "Failure fixture mutates one STIR query opening while keeping commitments and OOD answers intact.",
            "Failure fixture mutates one initial OOD answer, which also changes the downstream transcript.",
            "Schedule-specific WHIR fixtures are emitted by separate exporter binaries.",
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

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_schedule_outputs(
    out_dir: &Path,
    quartic: &QuarticFixture,
    whir_params: WhirParams,
    prefix: &str,
    transcript_trace_json_name: &str,
    transcript_trace_abi_name: &str,
    spartan_context_abi_name: &str,
    spartan_placeholder_proof_abi_name: &str,
    encode_blob: QuarticBlobEncoder,
) -> anyhow::Result<()> {
    write_quartic_whir_family_outputs(out_dir, prefix, quartic, encode_blob)?;

    let transcript_trace = TranscriptTraceFile {
        prover_events: quartic.prover_trace.clone(),
        verifier_events: quartic.verifier_trace.clone(),
        checkpoint_prover: extension_coeffs_u32(&quartic.checkpoint_prover),
        checkpoint_verifier: extension_coeffs_u32(&quartic.checkpoint_verifier),
        checkpoint_match: quartic.checkpoint_prover == quartic.checkpoint_verifier,
    };
    write_json_file(&out_dir.join(transcript_trace_json_name), &transcript_trace)?;
    let transcript_trace_abi = ChallengerTranscriptTrace {
        proverEvents: events_to_abi(quartic.prover_trace.clone()),
        verifierEvents: events_to_abi(quartic.verifier_trace.clone()),
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
        &out_dir.join(transcript_trace_abi_name),
        &transcript_trace_abi,
    )?;

    let spartan_context = build_spartan_context_fixture_with_params(whir_params)?;
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
        &out_dir.join(spartan_context_abi_name),
        &spartan_context_abi,
    )?;

    write_abi_file(
        &out_dir.join(spartan_placeholder_proof_abi_name),
        &placeholder_spartan_proof(proof_to_abi(&quartic.proof)?),
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_octic_schedule_outputs(
    out_dir: &Path,
    octic: &OcticFixture,
    prefix: &str,
    transcript_trace_json_name: &str,
    transcript_trace_abi_name: &str,
    spartan_context_abi_name: &str,
    spartan_placeholder_proof_abi_name: &str,
    encode_blob: OcticBlobEncoder,
) -> anyhow::Result<()> {
    write_octic_whir_family_outputs(out_dir, prefix, octic, encode_blob)?;

    let transcript_trace = TranscriptTraceFile {
        prover_events: octic.prover_trace.clone(),
        verifier_events: octic.verifier_trace.clone(),
        checkpoint_prover: extension_coeffs_u32(&octic.checkpoint_prover),
        checkpoint_verifier: extension_coeffs_u32(&octic.checkpoint_verifier),
        checkpoint_match: octic.checkpoint_prover == octic.checkpoint_verifier,
    };
    write_json_file(&out_dir.join(transcript_trace_json_name), &transcript_trace)?;
    let transcript_trace_abi = ChallengerTranscriptTrace {
        proverEvents: events_to_abi(octic.prover_trace.clone()),
        verifierEvents: events_to_abi(octic.verifier_trace.clone()),
        checkpointProver: extension_coeffs_u32(&octic.checkpoint_prover)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
        checkpointVerifier: extension_coeffs_u32(&octic.checkpoint_verifier)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
        checkpointMatch: octic.checkpoint_prover == octic.checkpoint_verifier,
    };
    write_abi_file(
        &out_dir.join(transcript_trace_abi_name),
        &transcript_trace_abi,
    )?;

    let spartan_context = build_spartan_context_fixture_octic_k22_jb100()?;
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
        &out_dir.join(spartan_context_abi_name),
        &spartan_context_abi,
    )?;

    write_abi_file(
        &out_dir.join(spartan_placeholder_proof_abi_name),
        &placeholder_spartan_proof(proof_to_abi(&octic.proof)?),
    )?;

    Ok(())
}

fn write_quintic_schedule_outputs(
    out_dir: &Path,
    quintic: &QuinticFixture,
    prefix: &str,
    transcript_trace_json_name: &str,
    transcript_trace_abi_name: &str,
    encode_blob: QuinticBlobEncoder,
) -> anyhow::Result<()> {
    write_quintic_whir_family_outputs(out_dir, prefix, quintic, encode_blob)?;

    let transcript_trace = TranscriptTraceFile {
        prover_events: quintic.prover_trace.clone(),
        verifier_events: quintic.verifier_trace.clone(),
        checkpoint_prover: extension_coeffs_u32(&quintic.checkpoint_prover),
        checkpoint_verifier: extension_coeffs_u32(&quintic.checkpoint_verifier),
        checkpoint_match: quintic.checkpoint_prover == quintic.checkpoint_verifier,
    };
    write_json_file(&out_dir.join(transcript_trace_json_name), &transcript_trace)?;
    let transcript_trace_abi = ChallengerTranscriptTrace {
        proverEvents: events_to_abi(quintic.prover_trace.clone()),
        verifierEvents: events_to_abi(quintic.verifier_trace.clone()),
        checkpointProver: extension_coeffs_u32(&quintic.checkpoint_prover)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
        checkpointVerifier: extension_coeffs_u32(&quintic.checkpoint_verifier)
            .into_iter()
            .map(|value| alloy_primitives::U256::from(value as usize))
            .collect(),
        checkpointMatch: quintic.checkpoint_prover == quintic.checkpoint_verifier,
    };
    write_abi_file(
        &out_dir.join(transcript_trace_abi_name),
        &transcript_trace_abi,
    )?;

    Ok(())
}

fn write_quartic_fixed_config_named(
    out_dir: &Path,
    quartic: &QuarticFixture,
    file_name: &str,
    library_name: &str,
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

    let source = if library_name == "QuarticWhirFixedConfig" {
        generate_quartic_fixed_config_source(quartic)
    } else {
        generate_quartic_fixed_config_source_named(quartic, library_name)
    };
    fs::write(generated_dir.join(file_name), source)
        .with_context(|| format!("failed to write {file_name}"))?;

    Ok(())
}

fn write_octic_fixed_config_named(
    out_dir: &Path,
    octic: &OcticFixture,
    file_name: &str,
    library_name: &str,
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

    let source = generate_octic_fixed_config_source_named(octic, library_name);
    fs::write(generated_dir.join(file_name), source)
        .with_context(|| format!("failed to write {file_name}"))?;

    Ok(())
}

fn write_quintic_fixed_config_named(
    out_dir: &Path,
    quintic: &QuinticFixture,
    file_name: &str,
    library_name: &str,
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

    let source = generate_fixed_config_source_named(quintic, library_name);
    fs::write(generated_dir.join(file_name), source)
        .with_context(|| format!("failed to write {file_name}"))?;

    Ok(())
}

fn write_quartic_whir_family_outputs(
    out_dir: &Path,
    prefix: &str,
    quartic: &QuarticFixture,
    encode_blob: QuarticBlobEncoder,
) -> anyhow::Result<()> {
    let abi_statement = statement_to_abi(&quartic.statement_points, &quartic.statement_evaluations);
    let abi_proof = proof_to_abi(&quartic.proof)?;

    let mut tampered_raw_proof = quartic.proof.clone();
    tampered_raw_proof.initial_commitment[0] ^= 1;
    let tampered_abi_proof = proof_to_abi(&tampered_raw_proof)?;
    let tampered_stir_proof = tamper_first_stir_query(&quartic.proof)?;
    let tampered_stir_abi_proof = proof_to_abi(&tampered_stir_proof)?;
    let tampered_ood_proof = tamper_first_initial_ood_answer(&quartic.proof)?;
    let tampered_ood_abi_proof = proof_to_abi(&tampered_ood_proof)?;

    write_abi_file(
        &out_dir.join(format!("{prefix}_success_statement.abi")),
        &abi_statement,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_success_proof.abi")),
        &abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_failure_bad_commitment_proof.abi")),
        &tampered_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_failure_bad_stir_query_proof.abi")),
        &tampered_stir_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!(
            "{prefix}_failure_bad_ood_or_transcript_mismatch_proof.abi"
        )),
        &tampered_ood_abi_proof,
    )?;

    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(quartic.security.merkle_security_bits as usize);
    let success_blob = encode_blob(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &quartic.proof,
        effective_digest_bytes,
    )?;
    let tampered_commitment_blob = encode_blob(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &tampered_raw_proof,
        effective_digest_bytes,
    )?;
    let tampered_stir_blob = encode_blob(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &tampered_stir_proof,
        effective_digest_bytes,
    )?;
    let tampered_ood_blob = encode_blob(
        &quartic.statement_points,
        &quartic.statement_evaluations,
        &tampered_ood_proof,
        effective_digest_bytes,
    )?;

    fs::write(out_dir.join(format!("{prefix}_success.blob")), success_blob)
        .with_context(|| format!("failed to write blob fixture {prefix}_success.blob"))?;
    fs::write(
        out_dir.join(format!("{prefix}_failure_bad_commitment.blob")),
        tampered_commitment_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_commitment.blob")
    })?;
    fs::write(
        out_dir.join(format!("{prefix}_failure_bad_stir_query.blob")),
        tampered_stir_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_stir_query.blob")
    })?;
    fs::write(
        out_dir.join(format!(
            "{prefix}_failure_bad_ood_or_transcript_mismatch.blob"
        )),
        tampered_ood_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_ood_or_transcript_mismatch.blob")
    })?;

    Ok(())
}

fn write_octic_whir_family_outputs(
    out_dir: &Path,
    prefix: &str,
    octic: &OcticFixture,
    encode_blob: OcticBlobEncoder,
) -> anyhow::Result<()> {
    let abi_statement = statement_to_abi(&octic.statement_points, &octic.statement_evaluations);
    let abi_proof = proof_to_abi(&octic.proof)?;

    let mut tampered_raw_proof = octic.proof.clone();
    tampered_raw_proof.initial_commitment[0] ^= 1;
    let tampered_abi_proof = proof_to_abi(&tampered_raw_proof)?;
    let tampered_stir_proof = tamper_first_stir_query_octic(&octic.proof)?;
    let tampered_stir_abi_proof = proof_to_abi(&tampered_stir_proof)?;
    let tampered_ood_proof = tamper_first_initial_ood_answer_octic(&octic.proof)?;
    let tampered_ood_abi_proof = proof_to_abi(&tampered_ood_proof)?;

    write_abi_file(
        &out_dir.join(format!("{prefix}_success_statement.abi")),
        &abi_statement,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_success_proof.abi")),
        &abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_failure_bad_commitment_proof.abi")),
        &tampered_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_failure_bad_stir_query_proof.abi")),
        &tampered_stir_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!(
            "{prefix}_failure_bad_ood_or_transcript_mismatch_proof.abi"
        )),
        &tampered_ood_abi_proof,
    )?;

    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(octic.security.merkle_security_bits as usize);
    let success_blob = encode_blob(
        &octic.statement_points,
        &octic.statement_evaluations,
        &octic.proof,
        effective_digest_bytes,
    )?;
    let tampered_commitment_blob = encode_blob(
        &octic.statement_points,
        &octic.statement_evaluations,
        &tampered_raw_proof,
        effective_digest_bytes,
    )?;
    let tampered_stir_blob = encode_blob(
        &octic.statement_points,
        &octic.statement_evaluations,
        &tampered_stir_proof,
        effective_digest_bytes,
    )?;
    let tampered_ood_blob = encode_blob(
        &octic.statement_points,
        &octic.statement_evaluations,
        &tampered_ood_proof,
        effective_digest_bytes,
    )?;

    fs::write(out_dir.join(format!("{prefix}_success.blob")), success_blob)
        .with_context(|| format!("failed to write blob fixture {prefix}_success.blob"))?;
    fs::write(
        out_dir.join(format!("{prefix}_failure_bad_commitment.blob")),
        tampered_commitment_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_commitment.blob")
    })?;
    fs::write(
        out_dir.join(format!("{prefix}_failure_bad_stir_query.blob")),
        tampered_stir_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_stir_query.blob")
    })?;
    fs::write(
        out_dir.join(format!(
            "{prefix}_failure_bad_ood_or_transcript_mismatch.blob"
        )),
        tampered_ood_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_ood_or_transcript_mismatch.blob")
    })?;

    Ok(())
}

fn write_quintic_whir_family_outputs(
    out_dir: &Path,
    prefix: &str,
    quintic: &QuinticFixture,
    encode_blob: QuinticBlobEncoder,
) -> anyhow::Result<()> {
    let abi_statement = statement_to_abi(&quintic.statement_points, &quintic.statement_evaluations);
    let abi_proof = proof_to_abi(&quintic.proof)?;

    let mut tampered_raw_proof = quintic.proof.clone();
    tampered_raw_proof.initial_commitment[0] ^= 1;
    let tampered_abi_proof = proof_to_abi(&tampered_raw_proof)?;
    let tampered_stir_proof = tamper_first_stir_query_quintic(&quintic.proof)?;
    let tampered_stir_abi_proof = proof_to_abi(&tampered_stir_proof)?;
    let tampered_ood_proof = tamper_first_initial_ood_answer_quintic(&quintic.proof)?;
    let tampered_ood_abi_proof = proof_to_abi(&tampered_ood_proof)?;

    write_abi_file(
        &out_dir.join(format!("{prefix}_success_statement.abi")),
        &abi_statement,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_success_proof.abi")),
        &abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_failure_bad_commitment_proof.abi")),
        &tampered_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!("{prefix}_failure_bad_stir_query_proof.abi")),
        &tampered_stir_abi_proof,
    )?;
    write_abi_file(
        &out_dir.join(format!(
            "{prefix}_failure_bad_ood_or_transcript_mismatch_proof.abi"
        )),
        &tampered_ood_abi_proof,
    )?;

    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(quintic.security.merkle_security_bits as usize);
    let success_blob = encode_blob(
        &quintic.statement_points,
        &quintic.statement_evaluations,
        &quintic.proof,
        effective_digest_bytes,
    )?;
    let tampered_commitment_blob = encode_blob(
        &quintic.statement_points,
        &quintic.statement_evaluations,
        &tampered_raw_proof,
        effective_digest_bytes,
    )?;
    let tampered_stir_blob = encode_blob(
        &quintic.statement_points,
        &quintic.statement_evaluations,
        &tampered_stir_proof,
        effective_digest_bytes,
    )?;
    let tampered_ood_blob = encode_blob(
        &quintic.statement_points,
        &quintic.statement_evaluations,
        &tampered_ood_proof,
        effective_digest_bytes,
    )?;

    fs::write(out_dir.join(format!("{prefix}_success.blob")), success_blob)
        .with_context(|| format!("failed to write blob fixture {prefix}_success.blob"))?;
    fs::write(
        out_dir.join(format!("{prefix}_failure_bad_commitment.blob")),
        tampered_commitment_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_commitment.blob")
    })?;
    fs::write(
        out_dir.join(format!("{prefix}_failure_bad_stir_query.blob")),
        tampered_stir_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_stir_query.blob")
    })?;
    fs::write(
        out_dir.join(format!(
            "{prefix}_failure_bad_ood_or_transcript_mismatch.blob"
        )),
        tampered_ood_blob,
    )
    .with_context(|| {
        format!("failed to write blob fixture {prefix}_failure_bad_ood_or_transcript_mismatch.blob")
    })?;

    Ok(())
}

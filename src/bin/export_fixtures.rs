use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::Serialize;
use spartan_whir::effective_digest_bytes_for_security_bits;
use spartan_whir_export::{
    abi_export::{
        placeholder_spartan_instance, placeholder_spartan_proof, proof_to_abi, statement_to_abi,
    },
    quartic_fixture::{
        build_quartic_fixture, tamper_first_initial_ood_answer, tamper_first_stir_query,
    },
    spartan_context_fixture::{build_spartan_context_fixture, soundness_assumption_byte},
    transcript::{events_to_abi, TranscriptTraceFile},
    utils::{extension_coeffs_u32, to_u256_base, to_u256_usize, write_abi_file, write_json_file},
    vectors::{generate_field_vectors, generate_merkle_vectors},
    ChallengerTranscriptTrace, SpartanTranscriptContextFixture, KOALABEAR_MODULUS,
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

fn write_fixture_outputs(out_dir: &Path) -> anyhow::Result<()> {
    let quartic = build_quartic_fixture()?;

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

    let field_vectors = generate_field_vectors();
    write_json_file(&out_dir.join("field_vectors.json"), &field_vectors)?;

    let effective_digest_bytes =
        effective_digest_bytes_for_security_bits(quartic.security.merkle_security_bits as usize);
    let merkle_vectors = generate_merkle_vectors(effective_digest_bytes)?;
    write_json_file(&out_dir.join("merkle_vectors.json"), &merkle_vectors)?;

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

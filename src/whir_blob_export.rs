use alloy_primitives::{FixedBytes, U256};
use anyhow::{ensure, Context};
use p3_field::{BasedVectorSpace, PrimeField32};
use spartan_whir::{digest_to_bytes, engine::F};
use whir_p3::whir::proof::QueryBatchOpening as RawQueryBatchOpening;

use crate::{
    quartic_fixture::{RawWhirProof4, EF4},
    utils::pack_extension_u256,
    QueryBatchOpening, WhirProof, WhirRoundProof, WhirStatement, DIGEST_ELEMS,
};

const MAGIC: &[u8; 4] = b"WHRB";
const VERSION_V1: u16 = 1;
const EXTENSION_DEGREE: u8 = 4;
const ROUND_COUNT: u8 = 2;
const FLAGS_V1: u8 = 0x03; // final query batch + final sumcheck present

const STATEMENT_POINTS: usize = 1;
const STATEMENT_POINT_ARITY: usize = 16;
const STATEMENT_EVALUATIONS: usize = 1;
const INITIAL_OOD_SAMPLES: usize = 2;
const ROUND_OOD_SAMPLES: usize = 2;
const INITIAL_SUMCHECK_EVALS: usize = 8;
const ROUND_SUMCHECK_EVALS: usize = 8;
const FINAL_SUMCHECK_EVALS: usize = 8;
const ROUND0_NUM_QUERIES: usize = 9;
const ROUND1_NUM_QUERIES: usize = 6;
const FINAL_NUM_QUERIES: usize = 5;
const ROW_LEN: usize = 16;
const ROUND1_SUMCHECK_POW_WITNESSES: usize = 4;
const FINAL_POLY_LEN: usize = 16;

pub fn encode_quartic_whir_blob_v1(
    statement_points: &[Vec<EF4>],
    statement_evaluations: &[EF4],
    raw_proof: &RawWhirProof4,
    effective_digest_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        effective_digest_bytes == 20,
        "fixed quartic WHIR blob currently expects 20 effective digest bytes"
    );
    ensure!(
        statement_points.len() == STATEMENT_POINTS,
        "expected exactly one statement point"
    );
    ensure!(
        statement_points[0].len() == STATEMENT_POINT_ARITY,
        "expected statement point arity 16"
    );
    ensure!(
        statement_evaluations.len() == STATEMENT_EVALUATIONS,
        "expected exactly one statement evaluation"
    );
    ensure!(
        raw_proof.initial_ood_answers.len() == INITIAL_OOD_SAMPLES,
        "expected exactly two initial OOD answers"
    );
    ensure!(
        raw_proof.initial_sumcheck.polynomial_evaluations.len() == INITIAL_SUMCHECK_EVALS / 2,
        "expected exactly four initial sumcheck rounds"
    );
    ensure!(
        raw_proof.initial_sumcheck.pow_witnesses.is_empty(),
        "initial sumcheck should not contain PoW witnesses"
    );
    ensure!(
        raw_proof.rounds.len() == ROUND_COUNT as usize,
        "expected exactly two non-final WHIR rounds"
    );

    let round0 = &raw_proof.rounds[0];
    let round1 = &raw_proof.rounds[1];

    ensure!(
        round0.ood_answers.len() == ROUND_OOD_SAMPLES,
        "round 0 expected exactly two OOD answers"
    );
    ensure!(
        round1.ood_answers.len() == ROUND_OOD_SAMPLES,
        "round 1 expected exactly two OOD answers"
    );
    ensure!(
        round0.sumcheck.polynomial_evaluations.len() == ROUND_SUMCHECK_EVALS / 2,
        "round 0 expected exactly four sumcheck rounds"
    );
    ensure!(
        round0.sumcheck.pow_witnesses.is_empty(),
        "round 0 sumcheck should not contain PoW witnesses"
    );
    ensure!(
        round1.sumcheck.polynomial_evaluations.len() == ROUND_SUMCHECK_EVALS / 2,
        "round 1 expected exactly four sumcheck rounds"
    );
    ensure!(
        round1.sumcheck.pow_witnesses.len() == ROUND1_SUMCHECK_POW_WITNESSES,
        "round 1 expected exactly four sumcheck PoW witnesses"
    );

    let final_poly = raw_proof
        .final_poly
        .as_ref()
        .context("missing final polynomial in fixed WHIR blob export")?;
    ensure!(
        final_poly.num_evals() == FINAL_POLY_LEN,
        "expected final polynomial length 16"
    );

    let final_query_batch = raw_proof
        .final_query_batch
        .as_ref()
        .context("missing final query batch in fixed WHIR blob export")?;
    let final_sumcheck = raw_proof
        .final_sumcheck
        .as_ref()
        .context("missing final sumcheck in fixed WHIR blob export")?;
    ensure!(
        final_sumcheck.polynomial_evaluations.len() == FINAL_SUMCHECK_EVALS / 2,
        "expected exactly four final sumcheck rounds"
    );
    ensure!(
        final_sumcheck.pow_witnesses.is_empty(),
        "final sumcheck should not contain PoW witnesses"
    );

    let round0_decomm_len = validate_round0_query_batch(round0)?;
    let round1_decomm_len = validate_round1_query_batch(round1)?;
    let final_decomm_len = validate_final_query_batch(final_query_batch)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION_V1);
    put_u8(
        &mut out,
        u8::try_from(effective_digest_bytes).expect("20 fits in u8"),
    );
    put_u8(&mut out, EXTENSION_DEGREE);
    put_u8(&mut out, ROUND_COUNT);
    put_u8(&mut out, FLAGS_V1);
    put_u16(
        &mut out,
        u16::try_from(round0_decomm_len).context("round0 decommitment count exceeds u16")?,
    );
    put_u16(
        &mut out,
        u16::try_from(round1_decomm_len).context("round1 decommitment count exceeds u16")?,
    );
    put_u16(
        &mut out,
        u16::try_from(final_decomm_len).context("final decommitment count exceeds u16")?,
    );

    for point_value in &statement_points[0] {
        put_ext4(&mut out, point_value);
    }
    put_ext4(&mut out, &statement_evaluations[0]);

    put_digest(
        &mut out,
        &raw_proof.initial_commitment,
        effective_digest_bytes,
    );
    for answer in &raw_proof.initial_ood_answers {
        put_ext4_le(&mut out, answer);
    }
    put_sumcheck_evals_le(&mut out, &raw_proof.initial_sumcheck.polynomial_evaluations);

    encode_round0(&mut out, round0, effective_digest_bytes);
    encode_round1(&mut out, round1, effective_digest_bytes);

    for value in final_poly.as_slice() {
        put_ext4(&mut out, value);
    }
    put_base_le(&mut out, raw_proof.final_pow_witness);
    encode_final_query_batch(&mut out, final_query_batch, effective_digest_bytes);
    put_sumcheck_evals_le(&mut out, &final_sumcheck.polynomial_evaluations);

    Ok(out)
}

pub fn encode_quartic_whir_blob_v1_from_abi(
    statement: &WhirStatement,
    proof: &WhirProof,
    effective_digest_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        effective_digest_bytes == 20,
        "fixed quartic WHIR blob currently expects 20 effective digest bytes"
    );
    ensure!(
        statement.points.len() == STATEMENT_POINTS,
        "expected exactly one statement point"
    );
    ensure!(
        statement.points[0].len() == STATEMENT_POINT_ARITY,
        "expected statement point arity 16"
    );
    ensure!(
        statement.evaluations.len() == STATEMENT_EVALUATIONS,
        "expected exactly one statement evaluation"
    );
    ensure!(
        proof.initialOodAnswers.len() == INITIAL_OOD_SAMPLES,
        "expected exactly two initial OOD answers"
    );
    ensure!(
        proof.initialSumcheck.polynomialEvals.len() == INITIAL_SUMCHECK_EVALS,
        "expected exactly eight initial sumcheck evaluations"
    );
    ensure!(
        proof.initialSumcheck.powWitnesses.is_empty(),
        "initial sumcheck should not contain PoW witnesses"
    );
    ensure!(
        proof.rounds.len() == ROUND_COUNT as usize,
        "expected exactly two non-final WHIR rounds"
    );
    ensure!(
        proof.finalQueryBatchPresent,
        "missing final query batch in fixed WHIR blob export"
    );
    ensure!(
        proof.finalSumcheckPresent,
        "missing final sumcheck in fixed WHIR blob export"
    );
    ensure!(
        proof.finalPoly.len() == FINAL_POLY_LEN,
        "expected final polynomial length 16"
    );
    ensure!(
        proof.finalSumcheck.polynomialEvals.len() == FINAL_SUMCHECK_EVALS,
        "expected exactly eight final sumcheck evaluations"
    );
    ensure!(
        proof.finalSumcheck.powWitnesses.is_empty(),
        "final sumcheck should not contain PoW witnesses"
    );

    let round0 = &proof.rounds[0];
    let round1 = &proof.rounds[1];
    ensure!(
        round0.oodAnswers.len() == ROUND_OOD_SAMPLES,
        "round 0 expected exactly two OOD answers"
    );
    ensure!(
        round1.oodAnswers.len() == ROUND_OOD_SAMPLES,
        "round 1 expected exactly two OOD answers"
    );
    ensure!(
        round0.sumcheck.polynomialEvals.len() == ROUND_SUMCHECK_EVALS,
        "round 0 expected exactly eight sumcheck evaluations"
    );
    ensure!(
        round0.sumcheck.powWitnesses.is_empty(),
        "round 0 sumcheck should not contain PoW witnesses"
    );
    ensure!(
        round1.sumcheck.polynomialEvals.len() == ROUND_SUMCHECK_EVALS,
        "round 1 expected exactly eight sumcheck evaluations"
    );
    ensure!(
        round1.sumcheck.powWitnesses.len() == ROUND1_SUMCHECK_POW_WITNESSES,
        "round 1 expected exactly four sumcheck PoW witnesses"
    );

    let round0_decomm_len = validate_abi_round0_query_batch(round0)?;
    let round1_decomm_len = validate_abi_round1_query_batch(round1)?;
    let final_decomm_len = validate_abi_final_query_batch(&proof.finalQueryBatch)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION_V1);
    put_u8(
        &mut out,
        u8::try_from(effective_digest_bytes).expect("20 fits in u8"),
    );
    put_u8(&mut out, EXTENSION_DEGREE);
    put_u8(&mut out, ROUND_COUNT);
    put_u8(&mut out, FLAGS_V1);
    put_u16(
        &mut out,
        u16::try_from(round0_decomm_len).context("round0 decommitment count exceeds u16")?,
    );
    put_u16(
        &mut out,
        u16::try_from(round1_decomm_len).context("round1 decommitment count exceeds u16")?,
    );
    put_u16(
        &mut out,
        u16::try_from(final_decomm_len).context("final decommitment count exceeds u16")?,
    );

    for point_value in &statement.points[0] {
        put_ext4_abi(&mut out, *point_value)?;
    }
    put_ext4_abi(&mut out, statement.evaluations[0])?;

    put_digest_abi(&mut out, &proof.initialCommitment, effective_digest_bytes);
    for answer in &proof.initialOodAnswers {
        put_ext4_abi(&mut out, *answer)?;
    }
    put_sumcheck_evals_abi(&mut out, &proof.initialSumcheck.polynomialEvals)?;

    encode_round0_abi(&mut out, round0, effective_digest_bytes)?;
    encode_round1_abi(&mut out, round1, effective_digest_bytes)?;

    for value in &proof.finalPoly {
        put_ext4_abi(&mut out, *value)?;
    }
    put_base_abi(&mut out, proof.finalPowWitness)?;
    encode_final_query_batch_abi(&mut out, &proof.finalQueryBatch, effective_digest_bytes)?;
    put_sumcheck_evals_abi(&mut out, &proof.finalSumcheck.polynomialEvals)?;

    Ok(out)
}

fn encode_round0(
    out: &mut Vec<u8>,
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) {
    put_digest(out, &round.commitment, effective_digest_bytes);
    for answer in &round.ood_answers {
        put_ext4_le(out, answer);
    }
    put_base_le(out, round.pow_witness);

    match round
        .query_batch
        .as_ref()
        .expect("validated round0 query batch presence")
    {
        RawQueryBatchOpening::Base { values, proof } => {
            for row in values {
                for value in row {
                    put_base(out, *value);
                }
            }
            for digest in &proof.decommitments {
                put_digest(out, digest, effective_digest_bytes);
            }
        }
        RawQueryBatchOpening::Extension { .. } => unreachable!(),
    }

    put_sumcheck_evals_le(out, &round.sumcheck.polynomial_evaluations);
}

fn encode_round1(
    out: &mut Vec<u8>,
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) {
    put_digest(out, &round.commitment, effective_digest_bytes);
    for answer in &round.ood_answers {
        put_ext4_le(out, answer);
    }
    put_base_le(out, round.pow_witness);

    match round
        .query_batch
        .as_ref()
        .expect("validated round1 query batch presence")
    {
        RawQueryBatchOpening::Extension { values, proof } => {
            for row in values {
                for value in row {
                    put_ext4(out, value);
                }
            }
            for digest in &proof.decommitments {
                put_digest(out, digest, effective_digest_bytes);
            }
        }
        RawQueryBatchOpening::Base { .. } => unreachable!(),
    }

    put_sumcheck_evals_le(out, &round.sumcheck.polynomial_evaluations);
    for witness in &round.sumcheck.pow_witnesses {
        put_base_le(out, *witness);
    }
}

fn encode_final_query_batch(
    out: &mut Vec<u8>,
    query_batch: &RawQueryBatchOpening<F, EF4, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) {
    match query_batch {
        RawQueryBatchOpening::Extension { values, proof } => {
            for row in values {
                for value in row {
                    put_ext4(out, value);
                }
            }
            for digest in &proof.decommitments {
                put_digest(out, digest, effective_digest_bytes);
            }
        }
        RawQueryBatchOpening::Base { .. } => unreachable!(),
    }
}

fn validate_round0_query_batch(
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
) -> anyhow::Result<usize> {
    let query_batch = round
        .query_batch
        .as_ref()
        .context("round 0 missing query batch")?;
    match query_batch {
        RawQueryBatchOpening::Base { values, proof } => {
            ensure!(
                values.len() == ROUND0_NUM_QUERIES,
                "round 0 expected 9 base query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == ROW_LEN),
                "round 0 expected base row length 16"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Extension { .. } => {
            anyhow::bail!("round 0 expected base query batch")
        }
    }
}

fn validate_round1_query_batch(
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
) -> anyhow::Result<usize> {
    let query_batch = round
        .query_batch
        .as_ref()
        .context("round 1 missing query batch")?;
    match query_batch {
        RawQueryBatchOpening::Extension { values, proof } => {
            ensure!(
                values.len() == ROUND1_NUM_QUERIES,
                "round 1 expected 6 extension query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == ROW_LEN),
                "round 1 expected extension row length 16"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Base { .. } => {
            anyhow::bail!("round 1 expected extension query batch")
        }
    }
}

fn validate_final_query_batch(
    query_batch: &RawQueryBatchOpening<F, EF4, u64, DIGEST_ELEMS>,
) -> anyhow::Result<usize> {
    match query_batch {
        RawQueryBatchOpening::Extension { values, proof } => {
            ensure!(
                values.len() == FINAL_NUM_QUERIES,
                "final expected 5 extension query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == ROW_LEN),
                "final expected extension row length 16"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Base { .. } => {
            anyhow::bail!("final expected extension query batch")
        }
    }
}

fn validate_abi_round0_query_batch(round: &WhirRoundProof) -> anyhow::Result<usize> {
    validate_abi_query_batch(&round.queryBatch, 0, ROUND0_NUM_QUERIES, "round 0")
}

fn validate_abi_round1_query_batch(round: &WhirRoundProof) -> anyhow::Result<usize> {
    validate_abi_query_batch(&round.queryBatch, 1, ROUND1_NUM_QUERIES, "round 1")
}

fn validate_abi_final_query_batch(query_batch: &QueryBatchOpening) -> anyhow::Result<usize> {
    validate_abi_query_batch(query_batch, 1, FINAL_NUM_QUERIES, "final")
}

fn validate_abi_query_batch(
    query_batch: &QueryBatchOpening,
    expected_kind: u8,
    expected_queries: usize,
    label: &str,
) -> anyhow::Result<usize> {
    ensure!(
        query_batch.kind == expected_kind,
        "{label} expected query batch kind {expected_kind}"
    );
    ensure!(
        query_batch.numQueries.to::<usize>() == expected_queries,
        "{label} expected {expected_queries} query rows"
    );
    ensure!(
        query_batch.rowLen.to::<usize>() == ROW_LEN,
        "{label} expected row length 16"
    );
    ensure!(
        query_batch.values.len() == expected_queries * ROW_LEN,
        "{label} expected flattened query values length {}",
        expected_queries * ROW_LEN
    );
    Ok(query_batch.decommitments.len())
}

fn encode_round0_abi(
    out: &mut Vec<u8>,
    round: &WhirRoundProof,
    effective_digest_bytes: usize,
) -> anyhow::Result<()> {
    put_digest_abi(out, &round.commitment, effective_digest_bytes);
    for answer in &round.oodAnswers {
        put_ext4_abi(out, *answer)?;
    }
    put_base_abi(out, round.powWitness)?;
    encode_query_values_base_abi(out, &round.queryBatch)?;
    for digest in &round.queryBatch.decommitments {
        put_digest_abi(out, digest, effective_digest_bytes);
    }
    put_sumcheck_evals_abi(out, &round.sumcheck.polynomialEvals)?;
    Ok(())
}

fn encode_round1_abi(
    out: &mut Vec<u8>,
    round: &WhirRoundProof,
    effective_digest_bytes: usize,
) -> anyhow::Result<()> {
    put_digest_abi(out, &round.commitment, effective_digest_bytes);
    for answer in &round.oodAnswers {
        put_ext4_abi(out, *answer)?;
    }
    put_base_abi(out, round.powWitness)?;
    encode_query_values_ext4_abi(out, &round.queryBatch)?;
    for digest in &round.queryBatch.decommitments {
        put_digest_abi(out, digest, effective_digest_bytes);
    }
    put_sumcheck_evals_abi(out, &round.sumcheck.polynomialEvals)?;
    for witness in &round.sumcheck.powWitnesses {
        put_base_abi(out, *witness)?;
    }
    Ok(())
}

fn encode_final_query_batch_abi(
    out: &mut Vec<u8>,
    query_batch: &QueryBatchOpening,
    effective_digest_bytes: usize,
) -> anyhow::Result<()> {
    encode_query_values_ext4_abi(out, query_batch)?;
    for digest in &query_batch.decommitments {
        put_digest_abi(out, digest, effective_digest_bytes);
    }
    Ok(())
}

fn encode_query_values_base_abi(
    out: &mut Vec<u8>,
    query_batch: &QueryBatchOpening,
) -> anyhow::Result<()> {
    for value in &query_batch.values {
        put_base_abi(out, *value)?;
    }
    Ok(())
}

fn encode_query_values_ext4_abi(
    out: &mut Vec<u8>,
    query_batch: &QueryBatchOpening,
) -> anyhow::Result<()> {
    for value in &query_batch.values {
        put_ext4_abi(out, *value)?;
    }
    Ok(())
}

fn put_sumcheck_evals_le(out: &mut Vec<u8>, polynomial_evaluations: &[[EF4; 2]]) {
    for [c0, c2] in polynomial_evaluations {
        put_ext4_le(out, c0);
        put_ext4_le(out, c2);
    }
}

fn put_sumcheck_evals_abi(
    out: &mut Vec<u8>,
    polynomial_evaluations: &[U256],
) -> anyhow::Result<()> {
    ensure!(
        polynomial_evaluations.len() % 2 == 0,
        "sumcheck polynomial evaluations must be c0/c2 pairs"
    );
    for value in polynomial_evaluations {
        put_ext4_abi(out, *value)?;
    }
    Ok(())
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_base(out: &mut Vec<u8>, value: F) {
    out.extend_from_slice(&value.as_canonical_u32().to_be_bytes());
}

fn put_base_abi(out: &mut Vec<u8>, value: U256) -> anyhow::Result<()> {
    ensure!(
        value <= U256::from(u32::MAX),
        "base field value exceeds 32 bits"
    );
    let bytes = value.to_be_bytes::<32>();
    out.extend_from_slice(&bytes[28..]);
    Ok(())
}

fn put_base_le(out: &mut Vec<u8>, value: F) {
    out.extend_from_slice(&value.as_canonical_u32().to_le_bytes());
}

fn put_ext4<EF>(out: &mut Vec<u8>, value: &EF)
where
    EF: BasedVectorSpace<F> + Copy,
{
    let bytes = pack_extension_u256(value).to_be_bytes::<32>();
    out.extend_from_slice(&bytes[..16]);
}

fn put_ext4_abi(out: &mut Vec<u8>, value: U256) -> anyhow::Result<()> {
    let bytes = value.to_be_bytes::<32>();
    ensure!(
        bytes[16..].iter().all(|&byte| byte == 0),
        "packed ext4 has non-zero low half"
    );
    out.extend_from_slice(&bytes[..16]);
    Ok(())
}

fn put_ext4_le<EF>(out: &mut Vec<u8>, value: &EF)
where
    EF: BasedVectorSpace<F> + Copy,
{
    for coeff in value.as_basis_coefficients_slice() {
        out.extend_from_slice(&coeff.as_canonical_u32().to_le_bytes());
    }
}

fn put_digest(out: &mut Vec<u8>, digest: &[u64; DIGEST_ELEMS], effective_digest_bytes: usize) {
    let bytes = digest_to_bytes(digest);
    out.extend_from_slice(&bytes[..effective_digest_bytes]);
}

fn put_digest_abi(out: &mut Vec<u8>, digest: &FixedBytes<32>, effective_digest_bytes: usize) {
    out.extend_from_slice(&digest[..effective_digest_bytes]);
}

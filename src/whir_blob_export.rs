use anyhow::{ensure, Context};
use p3_field::{BasedVectorSpace, PrimeField32};
use spartan_whir::{digest_to_bytes, engine::F};
use whir_p3::whir::proof::QueryBatchOpening as RawQueryBatchOpening;

use crate::{
    octic_fixture::{RawWhirProof8, EF8},
    quartic_fixture::{RawWhirProof4, EF4},
    utils::pack_extension_u256,
    DIGEST_ELEMS,
};

const MAGIC: &[u8; 4] = b"WHRB";
const VERSION_V1: u16 = 1;
const EXTENSION_DEGREE: u8 = 4;
const FLAGS_V1: u8 = 0x03; // final query batch + final sumcheck present

const STATEMENT_POINTS: usize = 1;
const STATEMENT_POINT_ARITY: usize = 16;
const STATEMENT_EVALUATIONS: usize = 1;
const INITIAL_OOD_SAMPLES: usize = 2;
const ROUND_OOD_SAMPLES: usize = 2;

const ROUND_COUNT: u8 = 1;
const INITIAL_SUMCHECK_EVALS: usize = 10;
const ROUND_SUMCHECK_EVALS: usize = 10;
const FINAL_SUMCHECK_EVALS: usize = 12;
const ROUND0_NUM_QUERIES: usize = 9;
const FINAL_NUM_QUERIES: usize = 6;
const ROW_LEN: usize = 32;
const ROUND0_SUMCHECK_POW_WITNESSES: usize = 5;
const FINAL_POLY_LEN: usize = 64;

const ROUND_COUNT_LIR11: u8 = 1;
const INITIAL_SUMCHECK_EVALS_LIR11: usize = 10;
const INITIAL_SUMCHECK_POW_WITNESSES_LIR11: usize = 5;
const ROUND_SUMCHECK_EVALS_LIR11: usize = 10;
const ROUND0_NUM_QUERIES_LIR11: usize = 5;
const FINAL_NUM_QUERIES_LIR11: usize = 4;
const ROW_LEN_LIR11: usize = 32;
const ROUND0_SUMCHECK_POW_WITNESSES_LIR11: usize = 5;
const FINAL_SUMCHECK_EVALS_LIR11: usize = 12;
const FINAL_POLY_LEN_LIR11: usize = 64;

const OCTIC_EXTENSION_DEGREE: u8 = 8;
const OCTIC_STATEMENT_POINTS: usize = 1;
const OCTIC_STATEMENT_POINT_ARITY: usize = 22;
const OCTIC_STATEMENT_EVALUATIONS: usize = 1;
const OCTIC_INITIAL_OOD_SAMPLES: usize = 1;
const OCTIC_ROUND_OOD_SAMPLES: usize = 1;
const OCTIC_ROUND_COUNT: u8 = 3;
const OCTIC_INITIAL_SUMCHECK_EVALS: usize = 8;
const OCTIC_ROUND_SUMCHECK_EVALS: usize = 8;
const OCTIC_FINAL_SUMCHECK_EVALS: usize = 12;
const OCTIC_ROUND0_NUM_QUERIES: usize = 24;
const OCTIC_ROUND1_NUM_QUERIES: usize = 16;
const OCTIC_ROUND2_NUM_QUERIES: usize = 12;
const OCTIC_FINAL_NUM_QUERIES: usize = 10;
const OCTIC_ROW_LEN: usize = 16;
const OCTIC_FINAL_POLY_LEN: usize = 64;

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
        "expected exactly five initial sumcheck rounds"
    );
    ensure!(
        raw_proof.initial_sumcheck.pow_witnesses.is_empty(),
        "initial sumcheck should not contain PoW witnesses"
    );
    ensure!(
        raw_proof.rounds.len() == ROUND_COUNT as usize,
        "expected exactly one non-final WHIR round"
    );

    let round0 = &raw_proof.rounds[0];
    ensure!(
        round0.ood_answers.len() == ROUND_OOD_SAMPLES,
        "round 0 expected exactly two OOD answers"
    );
    ensure!(
        round0.sumcheck.polynomial_evaluations.len() == ROUND_SUMCHECK_EVALS / 2,
        "round 0 expected exactly five sumcheck rounds"
    );
    ensure!(
        round0.sumcheck.pow_witnesses.len() == ROUND0_SUMCHECK_POW_WITNESSES,
        "round 0 expected exactly five sumcheck PoW witnesses"
    );

    let final_poly = raw_proof
        .final_poly
        .as_ref()
        .context("missing final polynomial in fixed WHIR blob export")?;
    ensure!(
        final_poly.num_evals() == FINAL_POLY_LEN,
        "expected final polynomial length 64"
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
        "expected exactly six final sumcheck rounds"
    );
    ensure!(
        final_sumcheck.pow_witnesses.is_empty(),
        "final sumcheck should not contain PoW witnesses"
    );

    let round0_decomm_len = validate_round0_query_batch(round0)?;
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
    put_u16(&mut out, 0);
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

    encode_round0_with_sumcheck_pow(&mut out, round0, effective_digest_bytes);

    for value in final_poly.as_slice() {
        put_ext4(&mut out, value);
    }
    put_base_le(&mut out, raw_proof.final_pow_witness);
    encode_extension_query_batch(&mut out, final_query_batch, effective_digest_bytes);
    put_sumcheck_evals_le(&mut out, &final_sumcheck.polynomial_evaluations);

    Ok(out)
}

pub fn encode_quartic_whir_lir11_blob_v1(
    statement_points: &[Vec<EF4>],
    statement_evaluations: &[EF4],
    raw_proof: &RawWhirProof4,
    effective_digest_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        effective_digest_bytes == 20,
        "fixed quartic lir=11 blob currently expects 20 effective digest bytes"
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
        raw_proof.initial_sumcheck.polynomial_evaluations.len() == INITIAL_SUMCHECK_EVALS_LIR11 / 2,
        "expected exactly five initial sumcheck rounds"
    );
    ensure!(
        raw_proof.initial_sumcheck.pow_witnesses.len() == INITIAL_SUMCHECK_POW_WITNESSES_LIR11,
        "initial sumcheck expected exactly five PoW witnesses"
    );
    ensure!(
        raw_proof.rounds.len() == ROUND_COUNT_LIR11 as usize,
        "expected exactly one non-final WHIR round"
    );

    let round0 = &raw_proof.rounds[0];
    ensure!(
        round0.ood_answers.len() == ROUND_OOD_SAMPLES,
        "round 0 expected exactly two OOD answers"
    );
    ensure!(
        round0.sumcheck.polynomial_evaluations.len() == ROUND_SUMCHECK_EVALS_LIR11 / 2,
        "round 0 expected exactly five sumcheck rounds"
    );
    ensure!(
        round0.sumcheck.pow_witnesses.len() == ROUND0_SUMCHECK_POW_WITNESSES_LIR11,
        "round 0 expected exactly five sumcheck PoW witnesses"
    );

    let final_poly = raw_proof
        .final_poly
        .as_ref()
        .context("missing final polynomial in fixed lir=11 blob export")?;
    ensure!(
        final_poly.num_evals() == FINAL_POLY_LEN_LIR11,
        "expected final polynomial length 64"
    );

    let final_query_batch = raw_proof
        .final_query_batch
        .as_ref()
        .context("missing final query batch in fixed lir=11 blob export")?;
    let final_sumcheck = raw_proof
        .final_sumcheck
        .as_ref()
        .context("missing final sumcheck in fixed lir=11 blob export")?;
    ensure!(
        final_sumcheck.polynomial_evaluations.len() == FINAL_SUMCHECK_EVALS_LIR11 / 2,
        "expected exactly six final sumcheck rounds"
    );
    ensure!(
        final_sumcheck.pow_witnesses.is_empty(),
        "final sumcheck should not contain PoW witnesses"
    );

    let round0_decomm_len = validate_round0_query_batch_lir11(round0)?;
    let final_decomm_len = validate_final_query_batch_lir11(final_query_batch)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION_V1);
    put_u8(
        &mut out,
        u8::try_from(effective_digest_bytes).expect("20 fits in u8"),
    );
    put_u8(&mut out, EXTENSION_DEGREE);
    put_u8(&mut out, ROUND_COUNT_LIR11);
    put_u8(&mut out, FLAGS_V1);
    put_u16(
        &mut out,
        u16::try_from(round0_decomm_len).context("round0 decommitment count exceeds u16")?,
    );
    put_u16(&mut out, 0);
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
    for witness in &raw_proof.initial_sumcheck.pow_witnesses {
        put_base_le(&mut out, *witness);
    }

    encode_round0_with_sumcheck_pow(&mut out, round0, effective_digest_bytes);

    for value in final_poly.as_slice() {
        put_ext4(&mut out, value);
    }
    put_base_le(&mut out, raw_proof.final_pow_witness);
    encode_extension_query_batch(&mut out, final_query_batch, effective_digest_bytes);
    put_sumcheck_evals_le(&mut out, &final_sumcheck.polynomial_evaluations);

    Ok(out)
}

pub fn encode_octic_whir_k22_jb100_blob_v1(
    statement_points: &[Vec<EF8>],
    statement_evaluations: &[EF8],
    raw_proof: &RawWhirProof8,
    effective_digest_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        effective_digest_bytes == 20,
        "fixed octic WHIR blob currently expects 20 effective digest bytes"
    );
    ensure!(
        statement_points.len() == OCTIC_STATEMENT_POINTS,
        "expected exactly one statement point"
    );
    ensure!(
        statement_points[0].len() == OCTIC_STATEMENT_POINT_ARITY,
        "expected statement point arity 22"
    );
    ensure!(
        statement_evaluations.len() == OCTIC_STATEMENT_EVALUATIONS,
        "expected exactly one statement evaluation"
    );
    ensure!(
        raw_proof.initial_ood_answers.len() == OCTIC_INITIAL_OOD_SAMPLES,
        "expected exactly one initial OOD answer"
    );
    ensure!(
        raw_proof.initial_sumcheck.polynomial_evaluations.len() == OCTIC_INITIAL_SUMCHECK_EVALS / 2,
        "expected exactly four initial sumcheck rounds"
    );
    ensure!(
        raw_proof.initial_sumcheck.pow_witnesses.is_empty(),
        "initial sumcheck should not contain PoW witnesses"
    );
    ensure!(
        raw_proof.rounds.len() == OCTIC_ROUND_COUNT as usize,
        "expected exactly three non-final WHIR rounds"
    );

    let round0 = &raw_proof.rounds[0];
    let round1 = &raw_proof.rounds[1];
    let round2 = &raw_proof.rounds[2];
    let round0_decomm_len =
        validate_octic_round_query_batch(round0, OCTIC_ROUND0_NUM_QUERIES, true)?;
    let round1_decomm_len =
        validate_octic_round_query_batch(round1, OCTIC_ROUND1_NUM_QUERIES, false)?;
    let round2_decomm_len =
        validate_octic_round_query_batch(round2, OCTIC_ROUND2_NUM_QUERIES, false)?;

    let final_poly = raw_proof
        .final_poly
        .as_ref()
        .context("missing final polynomial in fixed octic WHIR blob export")?;
    ensure!(
        final_poly.num_evals() == OCTIC_FINAL_POLY_LEN,
        "expected final polynomial length 64"
    );

    let final_query_batch = raw_proof
        .final_query_batch
        .as_ref()
        .context("missing final query batch in fixed octic WHIR blob export")?;
    let final_sumcheck = raw_proof
        .final_sumcheck
        .as_ref()
        .context("missing final sumcheck in fixed octic WHIR blob export")?;
    ensure!(
        final_sumcheck.polynomial_evaluations.len() == OCTIC_FINAL_SUMCHECK_EVALS / 2,
        "expected exactly six final sumcheck rounds"
    );
    ensure!(
        final_sumcheck.pow_witnesses.is_empty(),
        "final sumcheck should not contain PoW witnesses"
    );
    let final_decomm_len = validate_octic_final_query_batch(final_query_batch)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION_V1);
    put_u8(
        &mut out,
        u8::try_from(effective_digest_bytes).expect("20 fits in u8"),
    );
    put_u8(&mut out, OCTIC_EXTENSION_DEGREE);
    put_u8(&mut out, OCTIC_ROUND_COUNT);
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
        u16::try_from(round2_decomm_len).context("round2 decommitment count exceeds u16")?,
    );
    put_u16(
        &mut out,
        u16::try_from(final_decomm_len).context("final decommitment count exceeds u16")?,
    );

    for point_value in &statement_points[0] {
        put_ext_be(&mut out, point_value);
    }
    put_ext_be(&mut out, &statement_evaluations[0]);

    put_digest(
        &mut out,
        &raw_proof.initial_commitment,
        effective_digest_bytes,
    );
    put_ext_le(&mut out, &raw_proof.initial_ood_answers[0]);
    put_sumcheck_evals_le_generic(&mut out, &raw_proof.initial_sumcheck.polynomial_evaluations);

    encode_octic_round(&mut out, round0, effective_digest_bytes, true);
    encode_octic_round(&mut out, round1, effective_digest_bytes, false);
    encode_octic_round(&mut out, round2, effective_digest_bytes, false);

    for value in final_poly.as_slice() {
        put_ext_be(&mut out, value);
    }
    put_base_le(&mut out, raw_proof.final_pow_witness);
    encode_extension_query_batch_generic(&mut out, final_query_batch, effective_digest_bytes);
    put_sumcheck_evals_le_generic(&mut out, &final_sumcheck.polynomial_evaluations);

    Ok(out)
}

fn encode_round0_with_sumcheck_pow(
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
    for witness in &round.sumcheck.pow_witnesses {
        put_base_le(out, *witness);
    }
}

fn encode_extension_query_batch(
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

fn encode_octic_round(
    out: &mut Vec<u8>,
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF8, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
    expect_base: bool,
) {
    put_digest(out, &round.commitment, effective_digest_bytes);
    put_ext_le(out, &round.ood_answers[0]);
    put_base_le(out, round.pow_witness);
    if expect_base {
        encode_base_query_batch_generic(
            out,
            round
                .query_batch
                .as_ref()
                .expect("validated round query batch"),
            effective_digest_bytes,
        );
    } else {
        encode_extension_query_batch_generic(
            out,
            round
                .query_batch
                .as_ref()
                .expect("validated round query batch"),
            effective_digest_bytes,
        );
    }
    put_sumcheck_evals_le_generic(out, &round.sumcheck.polynomial_evaluations);
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
                "round 0 expected base row length 32"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Extension { .. } => {
            anyhow::bail!("round 0 expected base query batch")
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
                "final expected 6 extension query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == ROW_LEN),
                "final expected extension row length 32"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Base { .. } => {
            anyhow::bail!("final expected extension query batch")
        }
    }
}

fn validate_round0_query_batch_lir11(
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
) -> anyhow::Result<usize> {
    let query_batch = round
        .query_batch
        .as_ref()
        .context("round 0 missing query batch")?;
    match query_batch {
        RawQueryBatchOpening::Base { values, proof } => {
            ensure!(
                values.len() == ROUND0_NUM_QUERIES_LIR11,
                "round 0 expected 5 base query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == ROW_LEN_LIR11),
                "round 0 expected base row length 32"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Extension { .. } => {
            anyhow::bail!("round 0 expected base query batch")
        }
    }
}

fn validate_final_query_batch_lir11(
    query_batch: &RawQueryBatchOpening<F, EF4, u64, DIGEST_ELEMS>,
) -> anyhow::Result<usize> {
    match query_batch {
        RawQueryBatchOpening::Extension { values, proof } => {
            ensure!(
                values.len() == FINAL_NUM_QUERIES_LIR11,
                "final expected 4 extension query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == ROW_LEN_LIR11),
                "final expected extension row length 32"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Base { .. } => {
            anyhow::bail!("final expected extension query batch")
        }
    }
}

fn validate_octic_round_query_batch(
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF8, u64, DIGEST_ELEMS>,
    expected_queries: usize,
    expect_base: bool,
) -> anyhow::Result<usize> {
    ensure!(
        round.ood_answers.len() == OCTIC_ROUND_OOD_SAMPLES,
        "round expected exactly one OOD answer"
    );
    ensure!(
        round.sumcheck.polynomial_evaluations.len() == OCTIC_ROUND_SUMCHECK_EVALS / 2,
        "round expected exactly four sumcheck rounds"
    );
    ensure!(
        round.sumcheck.pow_witnesses.is_empty(),
        "round sumcheck should not contain PoW witnesses"
    );

    let query_batch = round
        .query_batch
        .as_ref()
        .context("round missing query batch")?;
    match (expect_base, query_batch) {
        (true, RawQueryBatchOpening::Base { values, proof }) => {
            ensure!(
                values.len() == expected_queries,
                "round expected fixed base query count"
            );
            ensure!(
                values.iter().all(|row| row.len() == OCTIC_ROW_LEN),
                "round expected base row length 16"
            );
            Ok(proof.decommitments.len())
        }
        (false, RawQueryBatchOpening::Extension { values, proof }) => {
            ensure!(
                values.len() == expected_queries,
                "round expected fixed extension query count"
            );
            ensure!(
                values.iter().all(|row| row.len() == OCTIC_ROW_LEN),
                "round expected extension row length 16"
            );
            Ok(proof.decommitments.len())
        }
        (true, RawQueryBatchOpening::Extension { .. }) => {
            anyhow::bail!("round 0 expected base query batch")
        }
        (false, RawQueryBatchOpening::Base { .. }) => {
            anyhow::bail!("round expected extension query batch")
        }
    }
}

fn validate_octic_final_query_batch(
    query_batch: &RawQueryBatchOpening<F, EF8, u64, DIGEST_ELEMS>,
) -> anyhow::Result<usize> {
    match query_batch {
        RawQueryBatchOpening::Extension { values, proof } => {
            ensure!(
                values.len() == OCTIC_FINAL_NUM_QUERIES,
                "final expected 10 extension query rows"
            );
            ensure!(
                values.iter().all(|row| row.len() == OCTIC_ROW_LEN),
                "final expected extension row length 16"
            );
            Ok(proof.decommitments.len())
        }
        RawQueryBatchOpening::Base { .. } => anyhow::bail!("final expected extension query batch"),
    }
}

fn put_sumcheck_evals_le(out: &mut Vec<u8>, polynomial_evaluations: &[[EF4; 2]]) {
    for [c0, c2] in polynomial_evaluations {
        put_ext_le(out, c0);
        put_ext_le(out, c2);
    }
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

fn put_ext_be<EF>(out: &mut Vec<u8>, value: &EF)
where
    EF: BasedVectorSpace<F> + Copy,
{
    let bytes = pack_extension_u256(value).to_be_bytes::<32>();
    out.extend_from_slice(&bytes[..EF::DIMENSION * 4]);
}

fn put_ext4_le<EF>(out: &mut Vec<u8>, value: &EF)
where
    EF: BasedVectorSpace<F> + Copy,
{
    put_ext_le(out, value);
}

fn put_ext_le<EF>(out: &mut Vec<u8>, value: &EF)
where
    EF: BasedVectorSpace<F> + Copy,
{
    for coeff in value.as_basis_coefficients_slice() {
        out.extend_from_slice(&coeff.as_canonical_u32().to_le_bytes());
    }
}

fn put_sumcheck_evals_le_generic<EF>(out: &mut Vec<u8>, polynomial_evaluations: &[[EF; 2]])
where
    EF: BasedVectorSpace<F> + Copy,
{
    for [c0, c2] in polynomial_evaluations {
        put_ext_le(out, c0);
        put_ext_le(out, c2);
    }
}

fn encode_base_query_batch_generic<EF>(
    out: &mut Vec<u8>,
    query_batch: &RawQueryBatchOpening<F, EF, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) where
    EF: BasedVectorSpace<F> + Copy,
{
    match query_batch {
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
}

fn encode_extension_query_batch_generic<EF>(
    out: &mut Vec<u8>,
    query_batch: &RawQueryBatchOpening<F, EF, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) where
    EF: BasedVectorSpace<F> + Copy,
{
    match query_batch {
        RawQueryBatchOpening::Extension { values, proof } => {
            for row in values {
                for value in row {
                    put_ext_be(out, value);
                }
            }
            for digest in &proof.decommitments {
                put_digest(out, digest, effective_digest_bytes);
            }
        }
        RawQueryBatchOpening::Base { .. } => unreachable!(),
    }
}

fn put_digest(out: &mut Vec<u8>, digest: &[u64; DIGEST_ELEMS], effective_digest_bytes: usize) {
    let bytes = digest_to_bytes(digest);
    out.extend_from_slice(&bytes[..effective_digest_bytes]);
}

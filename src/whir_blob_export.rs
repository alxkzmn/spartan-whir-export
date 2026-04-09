use anyhow::{ensure, Context};
use p3_field::{BasedVectorSpace, PrimeField32};
use spartan_whir::{digest_to_bytes, engine::F};
use whir_p3::whir::proof::QueryBatchOpening as RawQueryBatchOpening;

use crate::{
    quartic_fixture::{RawWhirProof4, EF4},
    utils::pack_extension_u256,
    DIGEST_ELEMS,
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
        put_ext4(&mut out, answer);
    }
    put_sumcheck_evals(&mut out, &raw_proof.initial_sumcheck.polynomial_evaluations);

    encode_round0(&mut out, round0, effective_digest_bytes);
    encode_round1(&mut out, round1, effective_digest_bytes);

    for value in final_poly.as_slice() {
        put_ext4(&mut out, value);
    }
    put_base(&mut out, raw_proof.final_pow_witness);
    encode_final_query_batch(&mut out, final_query_batch, effective_digest_bytes);
    put_sumcheck_evals(&mut out, &final_sumcheck.polynomial_evaluations);

    Ok(out)
}

fn encode_round0(
    out: &mut Vec<u8>,
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) {
    put_digest(out, &round.commitment, effective_digest_bytes);
    for answer in &round.ood_answers {
        put_ext4(out, answer);
    }
    put_base(out, round.pow_witness);

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

    put_sumcheck_evals(out, &round.sumcheck.polynomial_evaluations);
}

fn encode_round1(
    out: &mut Vec<u8>,
    round: &whir_p3::whir::proof::WhirRoundProof<F, EF4, u64, DIGEST_ELEMS>,
    effective_digest_bytes: usize,
) {
    put_digest(out, &round.commitment, effective_digest_bytes);
    for answer in &round.ood_answers {
        put_ext4(out, answer);
    }
    put_base(out, round.pow_witness);

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

    put_sumcheck_evals(out, &round.sumcheck.polynomial_evaluations);
    for witness in &round.sumcheck.pow_witnesses {
        put_base(out, *witness);
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

fn put_sumcheck_evals(out: &mut Vec<u8>, polynomial_evaluations: &[[EF4; 2]]) {
    for [c0, c2] in polynomial_evaluations {
        put_ext4(out, c0);
        put_ext4(out, c2);
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

fn put_ext4<EF>(out: &mut Vec<u8>, value: &EF)
where
    EF: BasedVectorSpace<F> + Copy,
{
    let bytes = pack_extension_u256(value).to_be_bytes::<32>();
    out.extend_from_slice(&bytes[..16]);
}

fn put_digest(out: &mut Vec<u8>, digest: &[u64; DIGEST_ELEMS], effective_digest_bytes: usize) {
    let bytes = digest_to_bytes(digest);
    out.extend_from_slice(&bytes[..effective_digest_bytes]);
}

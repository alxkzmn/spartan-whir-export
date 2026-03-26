use alloy_primitives::U256;
use anyhow::{ensure, Context};
use p3_field::BasedVectorSpace;
use spartan_whir::{
    effective_digest_bytes_for_security_bits, engine::F, SecurityConfig, SoundnessAssumption,
    WhirParams,
};
use whir_p3::whir::proof::{
    QueryBatchOpening as RawQueryBatchOpening, SumcheckData as RawSumcheckData,
};

use crate::{
    quartic_fixture::{RawWhirProof4, WhirConfig4, EF4},
    utils::{pack_extension_u256, to_bytes32_digest, to_u256_base, to_u256_usize},
    ExpandedWhirConfig, QueryBatchOpening, RoundConfig, SpartanInstance, SpartanProof,
    SumcheckData, WhirProof, WhirRoundProof, WhirStatement, DIGEST_ELEMS,
};

pub fn proof_to_abi(raw_proof: &RawWhirProof4) -> anyhow::Result<WhirProof> {
    let rounds = raw_proof
        .rounds
        .iter()
        .enumerate()
        .map(|(round_index, round)| {
            let query_batch = round
                .query_batch
                .as_ref()
                .with_context(|| format!("round {round_index} missing query batch"))?;

            Ok(WhirRoundProof {
                commitment: to_bytes32_digest(&round.commitment),
                oodAnswers: round.ood_answers.iter().map(pack_extension_u256).collect(),
                powWitness: to_u256_base(round.pow_witness),
                queryBatch: query_batch_to_abi(query_batch)?,
                sumcheck: sumcheck_to_abi(&round.sumcheck),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let final_poly = raw_proof
        .final_poly
        .as_ref()
        .context("missing final polynomial in WHIR proof")?;

    let final_query_batch_present = raw_proof.final_query_batch.is_some();
    let final_sumcheck_present = raw_proof.final_sumcheck.is_some();

    let final_query_batch = match raw_proof.final_query_batch.as_ref() {
        Some(query_batch) => query_batch_to_abi(query_batch)?,
        None => empty_query_batch(),
    };

    let final_sumcheck = match raw_proof.final_sumcheck.as_ref() {
        Some(sumcheck) => sumcheck_to_abi(sumcheck),
        None => SumcheckData {
            polynomialEvals: vec![],
            powWitnesses: vec![],
        },
    };

    Ok(WhirProof {
        initialCommitment: to_bytes32_digest(&raw_proof.initial_commitment),
        initialOodAnswers: raw_proof
            .initial_ood_answers
            .iter()
            .map(pack_extension_u256)
            .collect(),
        initialSumcheck: sumcheck_to_abi(&raw_proof.initial_sumcheck),
        rounds,
        finalPoly: final_poly
            .as_slice()
            .iter()
            .map(pack_extension_u256)
            .collect(),
        finalPowWitness: to_u256_base(raw_proof.final_pow_witness),
        finalQueryBatchPresent: final_query_batch_present,
        finalQueryBatch: final_query_batch,
        finalSumcheckPresent: final_sumcheck_present,
        finalSumcheck: final_sumcheck,
    })
}

pub fn config_to_abi(
    config: &WhirConfig4,
    security: SecurityConfig,
    whir_params: WhirParams,
    whir_fs_pattern: &[F],
) -> ExpandedWhirConfig {
    ExpandedWhirConfig {
        numVariables: to_u256_usize(config.num_variables),
        securityLevel: to_u256_usize(config.security_level),
        maxPowBits: to_u256_usize(config.max_pow_bits),
        commitmentOodSamples: to_u256_usize(config.commitment_ood_samples),
        startingLogInvRate: to_u256_usize(config.starting_log_inv_rate),
        startingFoldingPowBits: to_u256_usize(config.starting_folding_pow_bits),
        foldingFactor: to_u256_usize(whir_params.folding_factor),
        rsDomainInitialReductionFactor: to_u256_usize(config.rs_domain_initial_reduction_factor),
        finalQueries: to_u256_usize(config.final_queries),
        finalPowBits: to_u256_usize(config.final_pow_bits),
        finalSumcheckRounds: to_u256_usize(config.final_sumcheck_rounds),
        finalFoldingPowBits: to_u256_usize(config.final_folding_pow_bits),
        soundnessAssumption: soundness_tag(security.soundness_assumption),
        merkleSecurityBits: security.merkle_security_bits,
        effectiveDigestBytes: effective_digest_bytes_for_security_bits(
            security.merkle_security_bits as usize,
        ) as u8,
        whirFsPattern: whir_fs_pattern.iter().copied().map(to_u256_base).collect(),
        roundParameters: config
            .round_parameters
            .iter()
            .map(|round| RoundConfig {
                powBits: to_u256_usize(round.pow_bits),
                foldingPowBits: to_u256_usize(round.folding_pow_bits),
                numQueries: to_u256_usize(round.num_queries),
                oodSamples: to_u256_usize(round.ood_samples),
                numVariables: to_u256_usize(round.num_variables),
                foldingFactor: to_u256_usize(round.folding_factor),
                domainSize: to_u256_usize(round.domain_size),
                foldedDomainGen: to_u256_base(round.folded_domain_gen),
            })
            .collect(),
    }
}

pub fn statement_to_abi(points: &[Vec<EF4>], evaluations: &[EF4]) -> WhirStatement {
    WhirStatement {
        points: points
            .iter()
            .map(|point| point.iter().map(pack_extension_u256).collect())
            .collect(),
        evaluations: evaluations.iter().map(pack_extension_u256).collect(),
    }
}

pub fn placeholder_spartan_instance() -> SpartanInstance {
    SpartanInstance {
        publicInputs: vec![],
        witnessCommitment: [0_u8; 32].into(),
    }
}

pub fn placeholder_spartan_proof(pcs_proof: WhirProof) -> SpartanProof {
    SpartanProof {
        outerSumcheckPolys: vec![],
        outerClaims: [U256::ZERO, U256::ZERO, U256::ZERO],
        innerSumcheckPolys: vec![],
        witnessEval: U256::ZERO,
        pcsProof: pcs_proof,
    }
}

fn sumcheck_to_abi<EF>(sumcheck: &RawSumcheckData<F, EF>) -> SumcheckData
where
    EF: BasedVectorSpace<F> + Copy,
{
    let mut polynomial_evals = Vec::with_capacity(sumcheck.polynomial_evaluations.len() * 2);
    for [c0, c2] in &sumcheck.polynomial_evaluations {
        polynomial_evals.push(pack_extension_u256(c0));
        polynomial_evals.push(pack_extension_u256(c2));
    }

    SumcheckData {
        polynomialEvals: polynomial_evals,
        powWitnesses: sumcheck
            .pow_witnesses
            .iter()
            .copied()
            .map(to_u256_base)
            .collect(),
    }
}

fn empty_query_batch() -> QueryBatchOpening {
    QueryBatchOpening {
        kind: 0,
        numQueries: U256::ZERO,
        rowLen: U256::ZERO,
        values: vec![],
        decommitments: vec![],
    }
}

fn query_batch_to_abi<EF>(
    query_batch: &RawQueryBatchOpening<F, EF, u64, DIGEST_ELEMS>,
) -> anyhow::Result<QueryBatchOpening>
where
    EF: BasedVectorSpace<F> + Copy,
{
    let abi = match query_batch {
        RawQueryBatchOpening::Base { values, proof } => {
            let row_len = values.first().map_or(0, Vec::len);
            ensure!(
                values.iter().all(|row| row.len() == row_len),
                "inconsistent base query row length"
            );

            QueryBatchOpening {
                kind: 0,
                numQueries: to_u256_usize(values.len()),
                rowLen: to_u256_usize(row_len),
                values: values
                    .iter()
                    .flat_map(|row| row.iter().copied().map(to_u256_base))
                    .collect(),
                decommitments: proof.decommitments.iter().map(to_bytes32_digest).collect(),
            }
        }
        RawQueryBatchOpening::Extension { values, proof } => {
            let row_len = values.first().map_or(0, Vec::len);
            ensure!(
                values.iter().all(|row| row.len() == row_len),
                "inconsistent extension query row length"
            );

            QueryBatchOpening {
                kind: 1,
                numQueries: to_u256_usize(values.len()),
                rowLen: to_u256_usize(row_len),
                values: values
                    .iter()
                    .flat_map(|row| row.iter().map(pack_extension_u256))
                    .collect(),
                decommitments: proof.decommitments.iter().map(to_bytes32_digest).collect(),
            }
        }
    };

    Ok(abi)
}

fn soundness_tag(soundness: SoundnessAssumption) -> u8 {
    match soundness {
        SoundnessAssumption::UniqueDecoding => 0,
        SoundnessAssumption::JohnsonBound => 1,
        SoundnessAssumption::CapacityBound => 2,
    }
}

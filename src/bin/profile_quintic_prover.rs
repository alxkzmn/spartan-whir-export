use std::time::{Duration, Instant};

use anyhow::Context;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Mmcs;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{dense::RowMajorMatrixView, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use serde::Serialize;
use spartan_whir::{
    engine::{KeccakFieldHash, KeccakNodeCompress, F},
    SumcheckStrategy, WhirParams,
};
use spartan_whir_export::{
    quartic_fixture::{protocol_params_for_fixture_with_folding_factor, GenericWhirProof},
    quintic_fixture::{EF5, QUINTIC_K22_JB100_NUM_VARIABLES, QUINTIC_K22_JB100_SECURITY},
    quintic_schedule_dump::{build_default_quintic_schedule_dump, ScheduleCandidate},
    transcript::TraceChallenger,
    DIGEST_ELEMS,
};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator as WhirFsDomainSeparator,
    poly::{evals::EvaluationsList as WhirEvaluations, multilinear::MultilinearPoint as WhirPoint},
    whir::{constraints::statement::EqStatement, parameters::WhirConfig},
};

#[derive(Debug, Serialize)]
struct ProfileReport {
    schema_version: u32,
    measurement_kind: &'static str,
    build_profile: &'static str,
    label: String,
    folding_variant: &'static str,
    first_round_folding_factor: usize,
    rest_folding_factor: usize,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
    num_variables: usize,
    initial_commit_domain_rows: usize,
    initial_commit_row_width: usize,
    initial_commit_total_values: usize,
    timings: Vec<TimingRow>,
}

#[derive(Debug, Serialize)]
struct TimingRow {
    phase: &'static str,
    seconds: f64,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if cfg!(debug_assertions) {
        anyhow::bail!(
            "quintic prover profiling must be run with `cargo run --release --manifest-path spartan-whir-export/Cargo.toml --bin profile_quintic_prover`"
        );
    }
    let label = args.get(1).map(String::as_str);
    let dump = build_default_quintic_schedule_dump();
    let candidate = select_candidate(&dump.candidates, label)?;
    let report = profile_initial_commit(candidate)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn select_candidate<'a>(
    candidates: &'a [ScheduleCandidate],
    label: Option<&str>,
) -> anyhow::Result<&'a ScheduleCandidate> {
    if let Some(label) = label {
        return candidates
            .iter()
            .find(|candidate| candidate.label == label)
            .with_context(|| format!("unknown candidate label {label}"));
    }

    candidates
        .iter()
        .filter(|candidate| candidate.target_evaluation.target_eligible)
        .min_by_key(|candidate| candidate.structural_score)
        .context("no target-eligible quintic schedule candidates")
}

fn profile_initial_commit(candidate: &ScheduleCandidate) -> anyhow::Result<ProfileReport> {
    let whir_params = WhirParams {
        pow_bits: 30,
        folding_factor: candidate.folding_schedule.first_round,
        starting_log_inv_rate: candidate.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: candidate.rs_domain_initial_reduction_factor,
    };
    let folding_schedule = match candidate.folding_schedule.variant {
        "Constant" => {
            whir_p3::parameters::FoldingFactor::Constant(candidate.folding_schedule.first_round)
        }
        "ConstantFromSecondRound" => whir_p3::parameters::FoldingFactor::ConstantFromSecondRound(
            candidate.folding_schedule.first_round,
            candidate.folding_schedule.rest,
        ),
        variant => anyhow::bail!("unknown folding schedule variant {variant}"),
    };
    let protocol_params = protocol_params_for_fixture_with_folding_factor(
        QUINTIC_K22_JB100_SECURITY,
        whir_params,
        folding_schedule,
    );
    let config = WhirConfig::<EF5, F, KeccakFieldHash, KeccakNodeCompress, TraceChallenger>::new(
        QUINTIC_K22_JB100_NUM_VARIABLES,
        protocol_params.clone(),
    );

    let mut timings = Vec::new();
    let polynomial = timed(&mut timings, "build_polynomial", || {
        (0..(1 << QUINTIC_K22_JB100_NUM_VARIABLES))
            .map(|i| F::from_u32((i + 1) as u32))
            .collect::<Vec<_>>()
    });
    let poly_evals = WhirEvaluations::new(polynomial.clone());

    let mut user_statement = EqStatement::initialize(QUINTIC_K22_JB100_NUM_VARIABLES);
    timed(&mut timings, "build_user_statement", || {
        let point = WhirPoint::expand_from_univariate(
            EF5::from(F::from_u32(3)),
            QUINTIC_K22_JB100_NUM_VARIABLES,
        );
        let evaluation = poly_evals.evaluate_hypercube_base(&point);
        user_statement.add_evaluated_constraint(point, evaluation);
    });

    let mut domain_separator = WhirFsDomainSeparator::<EF5, F>::new(vec![]);
    domain_separator.commit_statement::<_, _, _, DIGEST_ELEMS>(&config);
    domain_separator.add_whir_proof::<_, _, _, DIGEST_ELEMS>(&config);
    let mut prover_challenger = TraceChallenger::new();
    domain_separator.observe_domain_separator(&mut prover_challenger);

    let mut proof =
        GenericWhirProof::<EF5>::from_protocol_parameters(&protocol_params, config.num_variables);
    let mut initial_statement = config.initial_statement(
        WhirEvaluations::new(polynomial.clone()),
        SumcheckStrategy::Svo,
    );
    let dft = Radix2DFTSmallBatch::<F>::default();
    let first_round = config.folding_factor.at_round(0);
    let row_width = 1usize << first_round;
    let domain_rows = 1usize << (config.num_variables + config.starting_log_inv_rate - first_round);

    let padded = timed(&mut timings, "initial_commit_transpose_pad", || {
        let mut mat = RowMajorMatrixView::new(
            polynomial.as_slice(),
            1 << (config.num_variables - first_round),
        )
        .transpose();
        mat.pad_to_height(domain_rows, F::ZERO);
        mat
    });
    let folded_matrix = timed(&mut timings, "initial_commit_dft", || {
        dft.dft_batch(padded).to_row_major_matrix()
    });
    let (root, _prover_data) = timed(&mut timings, "initial_commit_merkle_commit_matrix", || {
        let merkle_tree =
            MerkleTreeMmcs::<F, u64, KeccakFieldHash, KeccakNodeCompress, DIGEST_ELEMS>::new(
                config.merkle_hash.clone(),
                config.merkle_compress.clone(),
            );
        merkle_tree.commit_matrix(folded_matrix)
    });
    proof.initial_commitment = *root.as_ref();
    prover_challenger.observe(root);
    timed(&mut timings, "initial_commit_ood_evaluations", || {
        for _ in 0..config.commitment_ood_samples {
            let point = WhirPoint::expand_from_univariate(
                prover_challenger.sample_algebra_element(),
                config.num_variables,
            );
            let eval = initial_statement.evaluate(&point);
            proof.initial_ood_answers.push(eval);
            prover_challenger.observe_algebra_element(eval);
        }
    });

    Ok(ProfileReport {
        schema_version: 1,
        measurement_kind: "quintic_initial_commit_profile",
        build_profile: "release",
        label: candidate.label.clone(),
        folding_variant: candidate.folding_schedule.variant,
        first_round_folding_factor: candidate.folding_schedule.first_round,
        rest_folding_factor: candidate.folding_schedule.rest,
        starting_log_inv_rate: candidate.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: candidate.rs_domain_initial_reduction_factor,
        num_variables: config.num_variables,
        initial_commit_domain_rows: domain_rows,
        initial_commit_row_width: row_width,
        initial_commit_total_values: domain_rows * row_width,
        timings,
    })
}

fn timed<T>(timings: &mut Vec<TimingRow>, phase: &'static str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    timings.push(TimingRow {
        phase,
        seconds: duration_seconds(start.elapsed()),
    });
    out
}

fn duration_seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

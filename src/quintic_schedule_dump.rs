use p3_field::TwoAdicField;
use serde::Serialize;
use spartan_whir::{
    effective_digest_bytes_for_security_bits,
    engine::{QuinticExtension, F},
    KeccakFieldHash, KeccakNodeCompress, SecurityConfig, SoundnessAssumption, WhirParams,
};
use whir_p3::{
    parameters::{errors::SecurityAssumption as WhirSecurity, FoldingFactor, ProtocolParameters},
    whir::parameters::WhirConfig,
};

use crate::quartic_fixture::protocol_params_for_fixture_with_folding_factor;

pub const DEFAULT_NUM_VARIABLES: usize = 22;
pub const DEFAULT_SECURITY_BITS: u32 = 101;
pub const DEFAULT_MERKLE_SECURITY_BITS: u32 = 80;
pub const DEFAULT_MIN_POW_BITS: u32 = 27;
pub const DEFAULT_POW_BITS: u32 = 30;
pub const DEFAULT_MAX_STARTING_LOG_INV_RATE: usize = 6;
pub const FIELD_BITS: usize = 155;
pub const EXTENSION_DEGREE: usize = 5;
pub const TARGET_SECURITY_BITS: f64 = 100.0;
pub const TARGET_MERKLE_SECURITY_BITS: usize = 80;
pub const TARGET_MAX_DERIVED_POW_BITS: usize = 30;
pub const STRUCTURAL_PREFILTER_CAP: usize = 120;

#[derive(Debug, Clone, Serialize)]
pub struct QuinticScheduleDump {
    pub schema_version: u32,
    pub total_candidates_considered: usize,
    pub num_variables: usize,
    pub extension_degree: usize,
    pub field_bits: usize,
    pub security_level_bits_requested: u32,
    pub merkle_security_bits_requested: u32,
    pub pow_bits_requested: u32,
    pub target_security_bits: f64,
    pub target_merkle_security_bits: usize,
    pub target_max_derived_pow_bits: usize,
    pub soundness_assumption: &'static str,
    pub max_starting_log_inv_rate: usize,
    pub whir_p3_revision: String,
    pub whir_p3_dirty: bool,
    pub selectable_prefilter: StructuralPrefilter,
    pub candidates: Vec<ScheduleCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructuralPrefilter {
    pub formula: &'static str,
    pub keep_within_factor: f64,
    pub cap: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScheduleCandidate {
    pub label: String,
    pub extension_degree: usize,
    pub field_bits: usize,
    pub selectable: bool,
    pub not_selectable_reason: Option<&'static str>,
    pub folding_schedule: FoldingScheduleReport,
    pub requested_pow_bits: u32,
    pub starting_log_inv_rate: usize,
    pub rs_domain_initial_reduction_factor: usize,
    pub valid: bool,
    pub rejection_reason: Option<String>,
    pub target_evaluation: TargetEvaluation,
    pub security_bits_achieved: Option<f64>,
    pub merkle_security_bits_achieved: usize,
    pub max_derived_pow_bits: Option<usize>,
    pub commitment_ood_samples: Option<usize>,
    pub starting_folding_pow_bits: Option<usize>,
    pub final_pow_bits: Option<usize>,
    pub final_sumcheck_rounds: Option<usize>,
    pub final_folding_pow_bits: Option<usize>,
    pub total_query_rows: usize,
    pub total_row_values: usize,
    pub transcript_elements: usize,
    pub structural_score: usize,
    pub pow_bits_schedule: Vec<usize>,
    pub pow_work_units: u64,
    pub inverse_count: usize,
    pub extrapolate_count: usize,
    pub eq_poly_count: usize,
    pub eq_poly_depth_counts: Vec<DepthCount>,
    pub packing_validation_count: usize,
    pub rounds: Vec<RoundDump>,
    pub final_round: Option<RoundDump>,
    pub encoding_counts: EncodingCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct DepthCount {
    pub depth: usize,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetEvaluation {
    pub target_security_bits: f64,
    pub target_merkle_security_bits: usize,
    pub target_max_derived_pow_bits: usize,
    pub passes_security: bool,
    pub passes_merkle_security: bool,
    pub passes_pow: bool,
    pub passes_target_thresholds: bool,
    pub target_eligible: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoldingScheduleReport {
    pub variant: &'static str,
    pub first_round: usize,
    pub rest: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct EncodingCounts {
    pub base_elements: usize,
    pub ext5_elements: usize,
    pub merkle_hashes: usize,
    pub transcript_base_elements: usize,
    pub transcript_ext5_elements: usize,
    pub transcript_hashes: usize,
    pub abi_uint256_slots: usize,
    pub abi_zero_padding_bytes: usize,
    pub native_blob_nonzero_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoundDump {
    pub phase: String,
    pub round_index: Option<usize>,
    pub row_kind: &'static str,
    pub num_variables: usize,
    pub folding_factor: usize,
    pub row_len: usize,
    pub domain_size: usize,
    pub depth: usize,
    pub log_inv_rate: usize,
    pub next_log_inv_rate: Option<usize>,
    pub num_queries_requested: usize,
    pub num_queries_sampled: usize,
    pub pow_bits: usize,
    pub folding_pow_bits: usize,
    pub ood_samples: usize,
    pub merkle_geometry: MerkleGeometry,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MerkleGeometry {
    pub seed: u64,
    pub depth: usize,
    pub query_count: usize,
    pub frontier_init_nodes: usize,
    pub compressions: usize,
    pub decommitments: usize,
    pub in_frontier_merges: usize,
    pub dedup_events: usize,
}

pub fn build_default_quintic_schedule_dump() -> QuinticScheduleDump {
    build_quintic_schedule_dump(
        DEFAULT_NUM_VARIABLES,
        DEFAULT_SECURITY_BITS,
        DEFAULT_MERKLE_SECURITY_BITS,
        DEFAULT_POW_BITS,
        DEFAULT_MAX_STARTING_LOG_INV_RATE,
    )
}

pub fn build_quintic_schedule_dump(
    num_variables: usize,
    security_bits: u32,
    merkle_security_bits: u32,
    pow_bits: u32,
    max_starting_log_inv_rate: usize,
) -> QuinticScheduleDump {
    let security = SecurityConfig {
        security_level_bits: security_bits,
        merkle_security_bits,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    let mut candidates = Vec::new();

    let min_pow_bits = DEFAULT_MIN_POW_BITS.min(pow_bits);
    for requested_pow_bits in min_pow_bits..=pow_bits {
        for folding_factor in 1..=num_variables {
            for starting_log_inv_rate in 1..=max_starting_log_inv_rate {
                for rs_domain_initial_reduction_factor in 1..=folding_factor {
                    candidates.push(candidate_report(
                        num_variables,
                        security,
                        requested_pow_bits,
                        FoldingFactor::Constant(folding_factor),
                        starting_log_inv_rate,
                        rs_domain_initial_reduction_factor,
                        true,
                    ));
                }
            }
        }

        for first_round in 2..=num_variables {
            for rest in 1..first_round {
                for starting_log_inv_rate in 1..=max_starting_log_inv_rate {
                    for rs_domain_initial_reduction_factor in 1..=first_round {
                        candidates.push(candidate_report(
                            num_variables,
                            security,
                            requested_pow_bits,
                            FoldingFactor::ConstantFromSecondRound(first_round, rest),
                            starting_log_inv_rate,
                            rs_domain_initial_reduction_factor,
                            true,
                        ));
                    }
                }
            }
        }
    }

    let total_candidates_considered = candidates.len();
    let candidates = retain_prefiltered_candidates(candidates);

    QuinticScheduleDump {
        schema_version: 1,
        total_candidates_considered,
        num_variables,
        extension_degree: EXTENSION_DEGREE,
        field_bits: FIELD_BITS,
        security_level_bits_requested: security_bits,
        merkle_security_bits_requested: merkle_security_bits,
        pow_bits_requested: pow_bits,
        target_security_bits: TARGET_SECURITY_BITS,
        target_merkle_security_bits: TARGET_MERKLE_SECURITY_BITS,
        target_max_derived_pow_bits: TARGET_MAX_DERIVED_POW_BITS,
        soundness_assumption: "JohnsonBound",
        max_starting_log_inv_rate,
        whir_p3_revision: git_value(&["../whir-p3", "whir-p3"], &["rev-parse", "HEAD"]),
        whir_p3_dirty: !git_value(&["../whir-p3", "whir-p3"], &["status", "--porcelain"]).is_empty(),
        selectable_prefilter: StructuralPrefilter {
            formula: "verifier structural score plus calibrated prover PoW score; verifier structural score = total_query_rows + total_row_values + merkle_decommitments + merkle_compressions + transcript_elements; prover PoW work units = sum(2^pow_bits)",
            keep_within_factor: 2.0,
            cap: STRUCTURAL_PREFILTER_CAP,
        },
        candidates,
    }
}

fn retain_prefiltered_candidates(mut candidates: Vec<ScheduleCandidate>) -> Vec<ScheduleCandidate> {
    let best_selectable_structural = candidates
        .iter()
        .filter(|candidate| {
            candidate.selectable && candidate.target_evaluation.passes_target_thresholds
        })
        .map(|candidate| candidate.structural_score)
        .min()
        .or_else(|| {
            candidates
                .iter()
                .filter(|candidate| {
                    candidate.selectable && candidate.security_bits_achieved.is_some()
                })
                .map(|candidate| candidate.structural_score)
                .min()
        });
    let best_selectable_pow = candidates
        .iter()
        .filter(|candidate| {
            candidate.selectable && candidate.target_evaluation.passes_target_thresholds
        })
        .map(|candidate| candidate.pow_work_units.max(1))
        .min()
        .or_else(|| {
            candidates
                .iter()
                .filter(|candidate| {
                    candidate.selectable && candidate.security_bits_achieved.is_some()
                })
                .map(|candidate| candidate.pow_work_units.max(1))
                .min()
        });
    let fixed_structural_limit = best_selectable_structural.map(|best| best.saturating_mul(2));
    let fixed_pow_limit = best_selectable_pow.map(|best| best.saturating_mul(2));

    let mut fixed: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            candidate.selectable
                && candidate.security_bits_achieved.is_some()
                && (fixed_structural_limit.is_some_and(|limit| candidate.structural_score <= limit)
                    || fixed_pow_limit.is_some_and(|limit| candidate.pow_work_units <= limit))
        })
        .cloned()
        .collect();
    fixed.sort_by(|lhs, rhs| {
        rhs.target_evaluation
            .passes_target_thresholds
            .cmp(&lhs.target_evaluation.passes_target_thresholds)
            .then_with(|| {
                prefilter_score(lhs, best_selectable_structural, best_selectable_pow)
                    .partial_cmp(&prefilter_score(
                        rhs,
                        best_selectable_structural,
                        best_selectable_pow,
                    ))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| lhs.structural_score.cmp(&rhs.structural_score))
            .then_with(|| lhs.pow_work_units.cmp(&rhs.pow_work_units))
    });
    fixed.truncate(STRUCTURAL_PREFILTER_CAP);

    let mut comparison: Vec<_> = candidates
        .drain(..)
        .filter(|candidate| !candidate.selectable && candidate.security_bits_achieved.is_some())
        .collect();
    comparison.sort_by(|lhs, rhs| {
        rhs.target_evaluation
            .passes_target_thresholds
            .cmp(&lhs.target_evaluation.passes_target_thresholds)
            .then_with(|| {
                prefilter_score(lhs, best_selectable_structural, best_selectable_pow)
                    .partial_cmp(&prefilter_score(
                        rhs,
                        best_selectable_structural,
                        best_selectable_pow,
                    ))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| lhs.structural_score.cmp(&rhs.structural_score))
            .then_with(|| lhs.pow_work_units.cmp(&rhs.pow_work_units))
    });
    comparison.truncate(STRUCTURAL_PREFILTER_CAP);

    fixed.extend(comparison);
    fixed
}

fn prefilter_score(
    candidate: &ScheduleCandidate,
    best_structural: Option<usize>,
    best_pow: Option<u64>,
) -> f64 {
    let structural = candidate.structural_score as f64 / best_structural.unwrap_or(1).max(1) as f64;
    let pow = candidate.pow_work_units.max(1) as f64 / best_pow.unwrap_or(1).max(1) as f64;
    structural + pow
}

fn candidate_report(
    num_variables: usize,
    security: SecurityConfig,
    pow_bits: u32,
    folding_schedule: FoldingFactor,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
    selectable: bool,
) -> ScheduleCandidate {
    let schedule = folding_schedule_report(folding_schedule);
    let label = schedule_label(
        &schedule,
        pow_bits,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    );
    let not_selectable_reason =
        (!selectable).then_some("candidate is outside the selectable search policy");

    let invalid = precheck_schedule(
        num_variables,
        folding_schedule,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    );
    if let Some(reason) = invalid {
        return invalid_candidate(
            label,
            selectable,
            not_selectable_reason,
            schedule,
            pow_bits,
            starting_log_inv_rate,
            rs_domain_initial_reduction_factor,
            security,
            reason,
        );
    }

    let whir = WhirParams {
        pow_bits,
        folding_factor: schedule.first_round,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    };
    let protocol_params =
        protocol_params_for_fixture_with_folding_factor(security, whir, folding_schedule);
    let config_result = std::panic::catch_unwind(|| {
        WhirConfig::<
            QuinticExtension,
            F,
            KeccakFieldHash,
            KeccakNodeCompress,
            crate::transcript::TraceChallenger,
        >::new(num_variables, protocol_params.clone())
    });
    let Ok(config) = config_result else {
        return invalid_candidate(
            label,
            selectable,
            not_selectable_reason,
            schedule,
            pow_bits,
            starting_log_inv_rate,
            rs_domain_initial_reduction_factor,
            security,
            "whir-p3 rejected schedule during config derivation".to_owned(),
        );
    };

    let max_derived_pow_bits = max_derived_pow_bits(&config);
    let valid_pow = config.check_pow_bits();
    let mut log_inv_rate = starting_log_inv_rate;
    let mut rounds = Vec::new();
    let mut encoding_counts = EncodingCounts::default();
    let mut total_query_rows = 0;
    let mut total_row_values = 0;
    let mut transcript_elements = 0;
    let mut merkle_decommitments = 0;
    let mut merkle_compressions = 0;

    for (round_index, round) in config.round_parameters.iter().enumerate() {
        let rs_reduction_factor = config.rs_reduction_factor(round_index);
        let next_log_inv_rate = log_inv_rate + round.folding_factor - rs_reduction_factor;
        let row = round_dump(
            &label,
            "round",
            Some(round_index),
            if round_index == 0 { "base" } else { "ext5" },
            round.num_variables,
            round.folding_factor,
            round.domain_size,
            log_inv_rate,
            Some(next_log_inv_rate),
            round.num_queries,
            round.pow_bits,
            round.folding_pow_bits,
            round.ood_samples,
        );
        accumulate_row_counts(&row, &mut encoding_counts);
        total_query_rows += row.merkle_geometry.query_count;
        total_row_values += row.merkle_geometry.query_count * row.row_len;
        transcript_elements += transcript_elements_for_round(&row);
        merkle_decommitments += row.merkle_geometry.decommitments;
        merkle_compressions += row.merkle_geometry.compressions;
        rounds.push(row);
        log_inv_rate = next_log_inv_rate;
    }

    let final_config_result = std::panic::catch_unwind(|| config.final_round_config());
    let Ok(final_config) = final_config_result else {
        return invalid_candidate(
            label,
            selectable,
            not_selectable_reason,
            schedule,
            pow_bits,
            starting_log_inv_rate,
            rs_domain_initial_reduction_factor,
            security,
            "whir-p3 rejected final round during config derivation".to_owned(),
        );
    };
    let final_round = round_dump(
        &label,
        "final",
        None,
        if config.round_parameters.is_empty() {
            "base"
        } else {
            "ext5"
        },
        final_config.num_variables,
        final_config.folding_factor,
        final_config.domain_size,
        log_inv_rate,
        None,
        final_config.num_queries,
        final_config.pow_bits,
        final_config.folding_pow_bits,
        0,
    );
    accumulate_row_counts(&final_round, &mut encoding_counts);
    total_query_rows += final_round.merkle_geometry.query_count;
    total_row_values += final_round.merkle_geometry.query_count * final_round.row_len;
    transcript_elements += transcript_elements_for_round(&final_round);
    merkle_decommitments += final_round.merkle_geometry.decommitments;
    merkle_compressions += final_round.merkle_geometry.compressions;

    let sumcheck_rounds = schedule.first_round
        + rounds
            .iter()
            .map(|round| round.folding_factor)
            .sum::<usize>()
        + config.final_sumcheck_rounds;
    let final_poly_elements = 1usize << config.final_sumcheck_rounds;
    encoding_counts.ext5_elements +=
        2 * sumcheck_rounds + final_poly_elements + config.commitment_ood_samples;
    encoding_counts.transcript_ext5_elements +=
        2 * sumcheck_rounds + final_poly_elements + config.commitment_ood_samples;
    encoding_counts.transcript_hashes += 1 + rounds.len();
    encoding_counts.abi_uint256_slots += encoding_counts.base_elements
        + encoding_counts.ext5_elements
        + encoding_counts.merkle_hashes;
    encoding_counts.abi_zero_padding_bytes += encoding_counts.ext5_elements * 12;
    encoding_counts.native_blob_nonzero_bytes += encoding_counts.base_elements * 4
        + encoding_counts.ext5_elements * 20
        + encoding_counts.merkle_hashes * 32;

    transcript_elements += encoding_counts.transcript_ext5_elements
        + encoding_counts.transcript_base_elements
        + encoding_counts.transcript_hashes;

    let eq_poly_depth_counts = standalone_whir_eq_poly_depth_counts(
        num_variables,
        config.commitment_ood_samples,
        &rounds,
        &final_round,
    );
    let eq_poly_count = eq_poly_depth_counts
        .iter()
        .map(|entry| entry.count)
        .sum::<usize>();

    let structural_score = total_query_rows
        + total_row_values
        + merkle_decommitments
        + merkle_compressions
        + transcript_elements;
    let pow_bits_schedule = pow_bits_schedule(&config);
    let pow_work_units = pow_work_units(&pow_bits_schedule);

    let security_bits_achieved = achieved_security_bits(&protocol_params, &config, log_inv_rate);
    let merkle_security_bits_achieved =
        effective_digest_bytes_for_security_bits(security.merkle_security_bits as usize) * 8;
    let target_evaluation = target_evaluation(
        Some(security_bits_achieved),
        merkle_security_bits_achieved,
        Some(max_derived_pow_bits),
        valid_pow,
        selectable,
    );
    let valid = valid_pow
        && security_bits_achieved >= security.security_level_bits as f64
        && merkle_security_bits_achieved >= security.merkle_security_bits as usize;

    ScheduleCandidate {
        label,
        extension_degree: EXTENSION_DEGREE,
        field_bits: FIELD_BITS,
        selectable,
        not_selectable_reason,
        folding_schedule: schedule,
        requested_pow_bits: pow_bits,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
        valid,
        rejection_reason: (!valid).then(|| {
            if !valid_pow {
                format!(
                    "derived PoW {max_derived_pow_bits} > requested max PoW {}",
                    protocol_params.pow_bits
                )
            } else {
                format!(
                    "achieved security {:.3} below requested {}",
                    security_bits_achieved, security.security_level_bits
                )
            }
        }),
        target_evaluation,
        security_bits_achieved: Some(security_bits_achieved),
        merkle_security_bits_achieved,
        max_derived_pow_bits: Some(max_derived_pow_bits),
        commitment_ood_samples: Some(config.commitment_ood_samples),
        starting_folding_pow_bits: Some(config.starting_folding_pow_bits),
        final_pow_bits: Some(config.final_pow_bits),
        final_sumcheck_rounds: Some(config.final_sumcheck_rounds),
        final_folding_pow_bits: Some(config.final_folding_pow_bits),
        total_query_rows,
        total_row_values,
        transcript_elements,
        structural_score,
        pow_bits_schedule,
        pow_work_units,
        inverse_count: standalone_whir_verifier_inverse_count(),
        extrapolate_count: standalone_whir_extrapolate_count(sumcheck_rounds),
        eq_poly_count,
        eq_poly_depth_counts,
        packing_validation_count: encoding_counts.ext5_elements,
        rounds,
        final_round: Some(final_round),
        encoding_counts,
    }
}

fn invalid_candidate(
    label: String,
    selectable: bool,
    not_selectable_reason: Option<&'static str>,
    folding_schedule: FoldingScheduleReport,
    requested_pow_bits: u32,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
    security: SecurityConfig,
    rejection_reason: String,
) -> ScheduleCandidate {
    ScheduleCandidate {
        label,
        extension_degree: EXTENSION_DEGREE,
        field_bits: FIELD_BITS,
        selectable,
        not_selectable_reason,
        folding_schedule,
        requested_pow_bits,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
        valid: false,
        rejection_reason: Some(rejection_reason),
        target_evaluation: target_evaluation(
            None,
            effective_digest_bytes_for_security_bits(security.merkle_security_bits as usize) * 8,
            None,
            false,
            selectable,
        ),
        security_bits_achieved: None,
        merkle_security_bits_achieved: effective_digest_bytes_for_security_bits(
            security.merkle_security_bits as usize,
        ) * 8,
        max_derived_pow_bits: None,
        commitment_ood_samples: None,
        starting_folding_pow_bits: None,
        final_pow_bits: None,
        final_sumcheck_rounds: None,
        final_folding_pow_bits: None,
        total_query_rows: 0,
        total_row_values: 0,
        transcript_elements: 0,
        structural_score: usize::MAX,
        pow_bits_schedule: Vec::new(),
        pow_work_units: 0,
        inverse_count: standalone_whir_verifier_inverse_count(),
        extrapolate_count: 0,
        eq_poly_count: 0,
        eq_poly_depth_counts: Vec::new(),
        packing_validation_count: 0,
        rounds: Vec::new(),
        final_round: None,
        encoding_counts: EncodingCounts::default(),
    }
}

fn target_evaluation(
    security_bits_achieved: Option<f64>,
    merkle_security_bits_achieved: usize,
    max_derived_pow_bits: Option<usize>,
    valid_requested_pow: bool,
    selectable: bool,
) -> TargetEvaluation {
    let passes_security =
        security_bits_achieved.is_some_and(|security| security >= TARGET_SECURITY_BITS);
    let passes_merkle_security = merkle_security_bits_achieved >= TARGET_MERKLE_SECURITY_BITS;
    let passes_pow = valid_requested_pow
        && max_derived_pow_bits.is_some_and(|pow| pow <= TARGET_MAX_DERIVED_POW_BITS);
    let passes_target_thresholds = passes_security && passes_merkle_security && passes_pow;
    TargetEvaluation {
        target_security_bits: TARGET_SECURITY_BITS,
        target_merkle_security_bits: TARGET_MERKLE_SECURITY_BITS,
        target_max_derived_pow_bits: TARGET_MAX_DERIVED_POW_BITS,
        passes_security,
        passes_merkle_security,
        passes_pow,
        passes_target_thresholds,
        target_eligible: selectable && passes_target_thresholds,
    }
}

fn precheck_schedule(
    num_variables: usize,
    folding_schedule: FoldingFactor,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> Option<String> {
    if let Err(err) = folding_schedule.check_validity(num_variables) {
        return Some(format!("invalid folding schedule: {err}"));
    }
    let first = folding_schedule.at_round(0);
    if rs_domain_initial_reduction_factor > first {
        return Some(format!(
            "rs_domain_initial_reduction_factor {rs_domain_initial_reduction_factor} exceeds first folding factor {first}"
        ));
    }
    if let Some(reason) = overshoot_reason(num_variables, folding_schedule) {
        return Some(reason);
    }
    if let Some(reason) = two_adicity_reason(
        num_variables,
        folding_schedule,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    ) {
        return Some(reason);
    }
    let folded_domain_bits = num_variables + starting_log_inv_rate - first;
    if folded_domain_bits > F::TWO_ADICITY {
        return Some(format!(
            "log_folded_domain_size {folded_domain_bits} exceeds KoalaBear TWO_ADICITY {}",
            F::TWO_ADICITY
        ));
    }
    None
}

fn overshoot_reason(num_variables: usize, folding_schedule: FoldingFactor) -> Option<String> {
    const MAX_SEND: usize = 6;
    match folding_schedule {
        FoldingFactor::Constant(folding_factor) => {
            if num_variables <= MAX_SEND {
                return (folding_factor > num_variables).then(|| {
                    format!("folding factor {folding_factor} exceeds num_variables {num_variables}")
                });
            }
            let num_rounds = (num_variables - MAX_SEND).div_ceil(folding_factor);
            let folded = num_rounds * folding_factor;
            (folded > num_variables).then(|| {
                format!("constant folding overshoots final sumcheck: {folded} > {num_variables}")
            })
        }
        FoldingFactor::ConstantFromSecondRound(first_round, rest) => {
            let remaining = num_variables - first_round;
            if remaining < MAX_SEND {
                return None;
            }
            let num_rounds = (remaining - MAX_SEND).div_ceil(rest);
            let folded = first_round + num_rounds * rest;
            (folded > num_variables).then(|| {
                format!(
                    "second-round folding overshoots final sumcheck: {folded} > {num_variables}"
                )
            })
        }
    }
}

fn two_adicity_reason(
    num_variables: usize,
    folding_schedule: FoldingFactor,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> Option<String> {
    let (round_count, _) = folding_schedule.compute_number_of_rounds(num_variables);
    let mut log_domain_size = num_variables + starting_log_inv_rate;
    for round in 0..round_count {
        let folding_factor = folding_schedule.at_round(round);
        if log_domain_size < folding_factor {
            return Some(format!(
                "round {round} folding factor {folding_factor} exceeds log domain size {log_domain_size}"
            ));
        }
        let folded_bits = log_domain_size - folding_factor;
        if folded_bits > F::TWO_ADICITY {
            return Some(format!(
                "round {round} folded domain bits {folded_bits} exceed KoalaBear TWO_ADICITY {}",
                F::TWO_ADICITY
            ));
        }
        log_domain_size -= if round == 0 {
            rs_domain_initial_reduction_factor
        } else {
            1
        };
    }
    let final_folding_factor = folding_schedule.at_round(round_count);
    if log_domain_size < final_folding_factor {
        return Some(format!(
            "final folding factor {final_folding_factor} exceeds log domain size {log_domain_size}"
        ));
    }
    let final_folded_bits = log_domain_size - final_folding_factor;
    (final_folded_bits > F::TWO_ADICITY).then(|| {
        format!(
            "final folded domain bits {final_folded_bits} exceed KoalaBear TWO_ADICITY {}",
            F::TWO_ADICITY
        )
    })
}

fn round_dump(
    label: &str,
    phase: &str,
    round_index: Option<usize>,
    row_kind: &'static str,
    num_variables: usize,
    folding_factor: usize,
    domain_size: usize,
    log_inv_rate: usize,
    next_log_inv_rate: Option<usize>,
    num_queries: usize,
    pow_bits: usize,
    folding_pow_bits: usize,
    ood_samples: usize,
) -> RoundDump {
    let row_len = 1usize << folding_factor;
    let depth = domain_size.ilog2() as usize - folding_factor;
    let seed = stable_seed(label, phase, round_index);
    let indices = deterministic_query_indices(domain_size >> folding_factor, num_queries, seed);
    let merkle_geometry = merkle_geometry(&indices, depth, seed);
    RoundDump {
        phase: phase.to_owned(),
        round_index,
        row_kind,
        num_variables,
        folding_factor,
        row_len,
        domain_size,
        depth,
        log_inv_rate,
        next_log_inv_rate,
        num_queries_requested: num_queries,
        num_queries_sampled: indices.len(),
        pow_bits,
        folding_pow_bits,
        ood_samples,
        merkle_geometry,
    }
}

fn accumulate_row_counts(row: &RoundDump, encoding_counts: &mut EncodingCounts) {
    let values = row.merkle_geometry.query_count * row.row_len;
    if row.row_kind == "base" {
        encoding_counts.base_elements += values;
        encoding_counts.transcript_base_elements += row.ood_samples;
    } else {
        encoding_counts.ext5_elements += values + row.ood_samples;
        encoding_counts.transcript_ext5_elements += row.ood_samples;
    }
    encoding_counts.merkle_hashes += row.merkle_geometry.decommitments + 1;
}

fn transcript_elements_for_round(row: &RoundDump) -> usize {
    row.ood_samples + row.num_queries_sampled + usize::from(row.pow_bits > 0)
}

fn standalone_whir_verifier_inverse_count() -> usize {
    // The standalone WHIR verifier path folds rows, evaluates constraints, checks sumchecks,
    // and verifies Merkle paths using addition, multiplication, squaring, and base-field powers.
    // Extension inverses are not part of this verifier shape; a future nonzero count should be
    // treated as a hot-path regression risk and measured explicitly.
    0
}

fn standalone_whir_extrapolate_count(sumcheck_rounds: usize) -> usize {
    // One quadratic extrapolation per WHIR sumcheck round.
    sumcheck_rounds
}

fn standalone_whir_eq_poly_depth_counts(
    num_variables: usize,
    commitment_ood_samples: usize,
    rounds: &[RoundDump],
    final_round: &RoundDump,
) -> Vec<DepthCount> {
    let mut counts = std::collections::BTreeMap::<usize, usize>::new();
    if commitment_ood_samples > 0 {
        *counts.entry(num_variables).or_default() += commitment_ood_samples;
    }
    for row in rounds.iter().chain(std::iter::once(final_round)) {
        let count = row.merkle_geometry.query_count + row.ood_samples;
        if count > 0 {
            *counts.entry(row.num_variables).or_default() += count;
        }
    }
    counts
        .into_iter()
        .map(|(depth, count)| DepthCount { depth, count })
        .collect()
}

fn deterministic_query_indices(
    folded_domain_size: usize,
    num_queries: usize,
    seed: u64,
) -> Vec<usize> {
    if folded_domain_size == 0 || num_queries == 0 {
        return Vec::new();
    }
    let mut state = seed | 1;
    let mut indices = Vec::with_capacity(num_queries);
    for _ in 0..num_queries {
        state = xorshift64(state);
        indices.push((state as usize) % folded_domain_size);
    }
    indices.sort_unstable();
    indices.dedup();
    indices
}

fn merkle_geometry(indices: &[usize], depth: usize, seed: u64) -> MerkleGeometry {
    if indices.is_empty() {
        return MerkleGeometry {
            seed,
            depth,
            ..MerkleGeometry::default()
        };
    }
    let mut frontier = indices.to_vec();
    let mut next = Vec::with_capacity(frontier.len());
    let mut geometry = MerkleGeometry {
        seed,
        depth,
        query_count: frontier.len(),
        frontier_init_nodes: frontier.len(),
        ..MerkleGeometry::default()
    };

    for _ in 0..depth {
        next.clear();
        let mut cursor = 0;
        while cursor < frontier.len() {
            let node = frontier[cursor];
            let next_cursor = cursor + 1;
            let has_frontier_sibling =
                node & 1 == 0 && next_cursor < frontier.len() && frontier[next_cursor] == node + 1;
            if has_frontier_sibling {
                geometry.in_frontier_merges += 1;
                cursor = next_cursor + 1;
            } else {
                geometry.decommitments += 1;
                cursor = next_cursor;
            }
            geometry.compressions += 1;
            let parent = node >> 1;
            if next.last().copied() == Some(parent) {
                geometry.dedup_events += 1;
            } else {
                next.push(parent);
            }
        }
        core::mem::swap(&mut frontier, &mut next);
    }
    geometry
}

fn achieved_security_bits(
    protocol_params: &ProtocolParameters<KeccakFieldHash, KeccakNodeCompress>,
    config: &WhirConfig<
        QuinticExtension,
        F,
        KeccakFieldHash,
        KeccakNodeCompress,
        crate::transcript::TraceChallenger,
    >,
    final_log_inv_rate: usize,
) -> f64 {
    let soundness = protocol_params.soundness_type;
    let field_bits = <QuinticExtension as p3_field::Field>::bits();
    let mut achieved = f64::INFINITY;

    achieved = achieved.min(soundness.ood_error(
        config.num_variables,
        config.starting_log_inv_rate,
        field_bits,
        config.commitment_ood_samples,
    ));
    achieved = achieved.min(folding_security(
        soundness,
        field_bits,
        config.num_variables,
        config.starting_log_inv_rate,
        config.starting_folding_pow_bits,
    ));

    let mut log_inv_rate = config.starting_log_inv_rate;
    for (round_index, round) in config.round_parameters.iter().enumerate() {
        let next_log_inv_rate =
            log_inv_rate + round.folding_factor - config.rs_reduction_factor(round_index);
        achieved = achieved.min(
            soundness
                .queries_error(log_inv_rate, round.num_queries)
                .min(WhirConfig::<
                    QuinticExtension,
                    F,
                    KeccakFieldHash,
                    KeccakNodeCompress,
                    crate::transcript::TraceChallenger,
                >::rbr_soundness_queries_combination(
                    soundness,
                    field_bits,
                    round.num_variables,
                    next_log_inv_rate,
                    round.ood_samples,
                    round.num_queries,
                ))
                + round.pow_bits as f64,
        );
        achieved = achieved.min(soundness.ood_error(
            round.num_variables,
            next_log_inv_rate,
            field_bits,
            round.ood_samples,
        ));
        achieved = achieved.min(folding_security(
            soundness,
            field_bits,
            round.num_variables,
            next_log_inv_rate,
            round.folding_pow_bits,
        ));
        log_inv_rate = next_log_inv_rate;
    }

    achieved = achieved.min(
        soundness.queries_error(final_log_inv_rate, config.final_queries)
            + config.final_pow_bits as f64,
    );
    achieved.min((field_bits - 1 + config.final_folding_pow_bits) as f64)
}

fn folding_security(
    soundness: WhirSecurity,
    field_bits: usize,
    num_variables: usize,
    log_inv_rate: usize,
    pow_bits: usize,
) -> f64 {
    let prox_gaps = soundness.prox_gaps_error(num_variables, log_inv_rate, field_bits, 2);
    let sumcheck =
        WhirConfig::<
            QuinticExtension,
            F,
            KeccakFieldHash,
            KeccakNodeCompress,
            crate::transcript::TraceChallenger,
        >::rbr_soundness_fold_sumcheck(soundness, field_bits, num_variables, log_inv_rate);
    prox_gaps.min(sumcheck) + pow_bits as f64
}

fn max_derived_pow_bits(
    config: &WhirConfig<
        QuinticExtension,
        F,
        KeccakFieldHash,
        KeccakNodeCompress,
        crate::transcript::TraceChallenger,
    >,
) -> usize {
    let mut max_pow = config
        .starting_folding_pow_bits
        .max(config.final_pow_bits)
        .max(config.final_folding_pow_bits);
    for round in &config.round_parameters {
        max_pow = max_pow.max(round.pow_bits).max(round.folding_pow_bits);
    }
    max_pow
}

pub fn pow_bits_schedule(
    config: &WhirConfig<
        QuinticExtension,
        F,
        KeccakFieldHash,
        KeccakNodeCompress,
        crate::transcript::TraceChallenger,
    >,
) -> Vec<usize> {
    let mut bits = Vec::new();
    if config.starting_folding_pow_bits > 0 {
        bits.push(config.starting_folding_pow_bits);
    }
    for round in &config.round_parameters {
        if round.pow_bits > 0 {
            bits.push(round.pow_bits);
        }
        if round.folding_pow_bits > 0 {
            bits.push(round.folding_pow_bits);
        }
    }
    if config.final_pow_bits > 0 {
        bits.push(config.final_pow_bits);
    }
    if config.final_folding_pow_bits > 0 {
        bits.push(config.final_folding_pow_bits);
    }
    bits
}

pub fn pow_work_units(bits: &[usize]) -> u64 {
    bits.iter()
        .map(|bits| {
            if *bits >= u64::BITS as usize {
                u64::MAX
            } else {
                1u64 << bits
            }
        })
        .fold(0u64, u64::saturating_add)
}

fn folding_schedule_report(folding_schedule: FoldingFactor) -> FoldingScheduleReport {
    match folding_schedule {
        FoldingFactor::Constant(folding_factor) => FoldingScheduleReport {
            variant: "Constant",
            first_round: folding_factor,
            rest: folding_factor,
        },
        FoldingFactor::ConstantFromSecondRound(first_round, rest) => FoldingScheduleReport {
            variant: "ConstantFromSecondRound",
            first_round,
            rest,
        },
    }
}

fn schedule_label(
    schedule: &FoldingScheduleReport,
    pow_bits: u32,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> String {
    match schedule.variant {
        "Constant" => format!(
            "constant_pow{}_ff{}_lir{}_rsv{}",
            pow_bits,
            schedule.first_round,
            starting_log_inv_rate,
            rs_domain_initial_reduction_factor
        ),
        _ => format!(
            "cfsr_pow{}_ff{}_rest{}_lir{}_rsv{}",
            pow_bits,
            schedule.first_round,
            schedule.rest,
            starting_log_inv_rate,
            rs_domain_initial_reduction_factor
        ),
    }
}

fn stable_seed(label: &str, phase: &str, round_index: Option<usize>) -> u64 {
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for byte in label
        .bytes()
        .chain(phase.bytes())
        .chain(round_index.unwrap_or(usize::MAX).to_le_bytes())
    {
        acc ^= u64::from(byte);
        acc = acc.wrapping_mul(0x1000_0000_01b3);
    }
    acc
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

fn git_value(paths: &[&str], args: &[&str]) -> String {
    paths
        .iter()
        .find_map(|path| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(path)
                .args(args)
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spot_check_candidate() -> ScheduleCandidate {
        candidate_report(
            22,
            SecurityConfig {
                security_level_bits: 100,
                merkle_security_bits: 80,
                soundness_assumption: SoundnessAssumption::JohnsonBound,
            },
            30,
            FoldingFactor::Constant(3),
            5,
            3,
            true,
        )
    }

    #[test]
    fn constant_ff3_lir5_rsv3_spot_check_matches_whir_p3() {
        let candidate = spot_check_candidate();

        assert_eq!(candidate.label, "constant_ff3_lir5_rsv3");
        assert!(candidate.selectable);
        assert_eq!(candidate.rounds.len(), 5);
        assert_eq!(candidate.final_sumcheck_rounds, Some(4));
        assert_eq!(candidate.total_query_rows, 119);
        assert_eq!(candidate.starting_folding_pow_bits, Some(29));
        assert_eq!(candidate.final_pow_bits, Some(29));
        assert!(candidate.security_bits_achieved.unwrap() > 99.0);
        assert_eq!(candidate.max_derived_pow_bits, Some(29));
    }

    #[test]
    fn structural_score_formula_uses_merkle_geometry() {
        let candidate = spot_check_candidate();
        let merkle_decommitments: usize = candidate
            .rounds
            .iter()
            .chain(candidate.final_round.iter())
            .map(|round| round.merkle_geometry.decommitments)
            .sum();
        let merkle_compressions: usize = candidate
            .rounds
            .iter()
            .chain(candidate.final_round.iter())
            .map(|round| round.merkle_geometry.compressions)
            .sum();

        assert_eq!(
            candidate.structural_score,
            candidate.total_query_rows
                + candidate.total_row_values
                + merkle_decommitments
                + merkle_compressions
                + candidate.transcript_elements
        );
    }

    #[test]
    fn guarded_default_dump_marks_100_bit_target_rows() {
        let dump = build_default_quintic_schedule_dump();
        let labels: Vec<_> = dump
            .candidates
            .iter()
            .filter(|candidate| candidate.target_evaluation.target_eligible)
            .map(|candidate| (candidate.label.as_str(), candidate.valid))
            .collect();

        for expected in [
            ("cfsr_ff5_rest4_lir5_rsv4", false),
            ("constant_ff4_lir5_rsv4", false),
            ("cfsr_ff4_rest3_lir5_rsv3", false),
            ("constant_ff4_lir4_rsv3", false),
            ("constant_ff4_lir4_rsv4", false),
            ("constant_ff3_lir5_rsv3", false),
        ] {
            assert!(labels.contains(&expected), "missing {expected:?}");
        }
    }
}

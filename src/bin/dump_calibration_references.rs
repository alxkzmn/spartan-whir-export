use std::process::Command;

use p3_field::{Field, TwoAdicField};
use serde::Serialize;
use spartan_whir::{
    engine::{OcticBinExtension, QuarticBinExtension, F},
    SecurityConfig, SoundnessAssumption, WhirParams,
};
use spartan_whir_export::{
    octic_fixture::{OCTIC_K22_JB100_SECURITY, OCTIC_K22_JB100_WHIR_PARAMS},
    quartic_fixture::{build_checked_whir_config, protocol_params_for_fixture_with_folding_factor},
    quintic_schedule_dump::{DepthCount, EncodingCounts, MerkleGeometry, RoundDump},
    FIXTURE_WHIR_PARAMS, FIXTURE_WHIR_PARAMS_LIR11,
};
use whir_p3::parameters::FoldingFactor;

#[derive(Debug, Serialize)]
struct CalibrationReferenceDump {
    schema_version: u32,
    whir_p3_revision: String,
    whir_p3_dirty: bool,
    references: Vec<ReferenceEntry>,
}

#[derive(Debug, Serialize)]
struct ReferenceEntry {
    reference: &'static str,
    candidate: ReferenceCandidate,
}

#[derive(Debug, Serialize)]
struct ReferenceCandidate {
    label: &'static str,
    extension_degree: usize,
    field_bits: usize,
    folding_schedule: FoldingSchedule,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
    commitment_ood_samples: usize,
    final_sumcheck_rounds: usize,
    total_query_rows: usize,
    total_row_values: usize,
    inverse_count: usize,
    extrapolate_count: usize,
    eq_poly_count: usize,
    eq_poly_depth_counts: Vec<DepthCount>,
    packing_validation_count: usize,
    rounds: Vec<RoundDump>,
    final_round: RoundDump,
    encoding_counts: EncodingCounts,
}

#[derive(Debug, Serialize)]
struct FoldingSchedule {
    variant: &'static str,
    first_round: usize,
    rest: usize,
}

fn main() -> anyhow::Result<()> {
    let dump = CalibrationReferenceDump {
        schema_version: 1,
        whir_p3_revision: git_value(&["../whir-p3", "whir-p3"], &["rev-parse", "HEAD"]),
        whir_p3_dirty: !git_value(&["../whir-p3", "whir-p3"], &["status", "--porcelain"])
            .is_empty(),
        references: vec![
            ReferenceEntry {
                reference: "quartic_lir6_ff5_rsv1",
                candidate: reference_candidate::<QuarticBinExtension>(
                    "quartic_lir6_ff5_rsv1",
                    4,
                    16,
                    SecurityConfig {
                        security_level_bits: 80,
                        merkle_security_bits: 80,
                        soundness_assumption: SoundnessAssumption::CapacityBound,
                    },
                    FIXTURE_WHIR_PARAMS,
                )?,
            },
            ReferenceEntry {
                reference: "quartic_lir11_ff5_rsv3",
                candidate: reference_candidate::<QuarticBinExtension>(
                    "quartic_lir11_ff5_rsv3",
                    4,
                    16,
                    SecurityConfig {
                        security_level_bits: 80,
                        merkle_security_bits: 80,
                        soundness_assumption: SoundnessAssumption::CapacityBound,
                    },
                    FIXTURE_WHIR_PARAMS_LIR11,
                )?,
            },
            ReferenceEntry {
                reference: "octic_k22_jb100_lir6_ff4_rsv1",
                candidate: reference_candidate::<OcticBinExtension>(
                    "octic_k22_jb100_lir6_ff4_rsv1",
                    8,
                    22,
                    OCTIC_K22_JB100_SECURITY,
                    OCTIC_K22_JB100_WHIR_PARAMS,
                )?,
            },
        ],
    };
    println!("{}", serde_json::to_string_pretty(&dump)?);
    Ok(())
}

fn reference_candidate<EF>(
    label: &'static str,
    extension_degree: usize,
    num_variables: usize,
    security: SecurityConfig,
    whir_params: WhirParams,
) -> anyhow::Result<ReferenceCandidate>
where
    EF: p3_field::ExtensionField<F> + TwoAdicField,
{
    let folding_factor = FoldingFactor::Constant(whir_params.folding_factor);
    let protocol_params =
        protocol_params_for_fixture_with_folding_factor(security, whir_params, folding_factor);
    let config = build_checked_whir_config::<EF>(num_variables, &protocol_params)?;
    let mut log_inv_rate = whir_params.starting_log_inv_rate;
    let mut rounds = Vec::new();
    let mut encoding_counts = EncodingCounts::default();
    let mut total_query_rows = 0;
    let mut total_row_values = 0;

    for (round_index, round) in config.round_parameters.iter().enumerate() {
        let rs_reduction_factor = config.rs_reduction_factor(round_index);
        let next_log_inv_rate = log_inv_rate + round.folding_factor - rs_reduction_factor;
        let row = round_dump(
            label,
            "round",
            Some(round_index),
            if round_index == 0 { "base" } else { "ext" },
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
        rounds.push(row);
        log_inv_rate = next_log_inv_rate;
    }

    let final_config = config.final_round_config();
    let final_round = round_dump(
        label,
        "final",
        None,
        if config.round_parameters.is_empty() {
            "base"
        } else {
            "ext"
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

    let sumcheck_rounds = whir_params.folding_factor
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

    let eq_poly_depth_counts = eq_poly_depth_counts(
        num_variables,
        config.commitment_ood_samples,
        &rounds,
        &final_round,
    );
    let eq_poly_count = eq_poly_depth_counts
        .iter()
        .map(|entry| entry.count)
        .sum::<usize>();

    Ok(ReferenceCandidate {
        label,
        extension_degree,
        field_bits: <EF as Field>::bits(),
        folding_schedule: FoldingSchedule {
            variant: "Constant",
            first_round: whir_params.folding_factor,
            rest: whir_params.folding_factor,
        },
        starting_log_inv_rate: whir_params.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: whir_params.rs_domain_initial_reduction_factor,
        commitment_ood_samples: config.commitment_ood_samples,
        final_sumcheck_rounds: config.final_sumcheck_rounds,
        total_query_rows,
        total_row_values,
        inverse_count: 0,
        extrapolate_count: sumcheck_rounds,
        eq_poly_count,
        eq_poly_depth_counts,
        packing_validation_count: encoding_counts.ext5_elements,
        rounds,
        final_round,
        encoding_counts,
    })
}

#[allow(clippy::too_many_arguments)]
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

fn eq_poly_depth_counts(
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
                cursor += 1;
            }
            geometry.compressions += 1;
            next.push(node >> 1);
        }
        next.dedup();
        core::mem::swap(&mut frontier, &mut next);
    }
    geometry
}

fn stable_seed(label: &str, phase: &str, round_index: Option<usize>) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in label
        .as_bytes()
        .iter()
        .chain(phase.as_bytes())
        .copied()
        .chain(round_index.unwrap_or(usize::MAX).to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

fn git_value(dirs: &[&str], args: &[&str]) -> String {
    for dir in dirs {
        if let Ok(output) = Command::new("git").arg("-C").arg(dir).args(args).output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_owned();
            }
        }
    }
    "unknown".to_owned()
}

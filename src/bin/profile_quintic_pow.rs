use std::time::{Duration, Instant};

use anyhow::Context;
use p3_challenger::{CanObserve, GrindingChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::Serialize;
use spartan_whir::engine::F;
use spartan_whir_export::{
    quintic_schedule_dump::{build_default_quintic_schedule_dump, ScheduleCandidate},
    transcript::TraceChallenger,
};

#[derive(Debug, Serialize)]
struct PowProfileReport {
    schema_version: u32,
    measurement_kind: &'static str,
    build_profile: &'static str,
    label: String,
    folding_variant: &'static str,
    first_round_folding_factor: usize,
    rest_folding_factor: usize,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
    max_bits: Option<usize>,
    scheduled_grinds: Vec<ScheduledGrind>,
    skipped_grinds: Vec<ScheduledGrind>,
    timings: Vec<PowTiming>,
    total_seconds: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ScheduledGrind {
    phase: String,
    bits: usize,
}

#[derive(Debug, Serialize)]
struct PowTiming {
    phase: String,
    bits: usize,
    witness: u32,
    seconds: f64,
}

fn main() -> anyhow::Result<()> {
    if cfg!(debug_assertions) {
        anyhow::bail!(
            "quintic PoW profiling must be run with `cargo run --release --manifest-path spartan-whir-export/Cargo.toml --bin profile_quintic_pow`"
        );
    }

    let options = Options::parse(&std::env::args().collect::<Vec<_>>())?;
    let dump = build_default_quintic_schedule_dump();
    let candidate = select_candidate(&dump.candidates, options.label.as_deref())?;
    let report = profile_pow(candidate, options.max_bits)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Debug)]
struct Options {
    label: Option<String>,
    max_bits: Option<usize>,
}

impl Options {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut label = None;
        let mut max_bits = None;
        let mut cursor = 1;
        while cursor < args.len() {
            match args[cursor].as_str() {
                "--max-bits" => {
                    cursor += 1;
                    max_bits = Some(
                        args.get(cursor)
                            .context("missing value for --max-bits")?
                            .parse()?,
                    );
                }
                value if value.starts_with("--") => anyhow::bail!("unknown option {value}"),
                value => {
                    anyhow::ensure!(label.is_none(), "only one candidate label may be provided");
                    label = Some(value.to_owned());
                }
            }
            cursor += 1;
        }
        Ok(Self { label, max_bits })
    }
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

fn profile_pow(
    candidate: &ScheduleCandidate,
    max_bits: Option<usize>,
) -> anyhow::Result<PowProfileReport> {
    let all_scheduled_grinds = scheduled_grinds(candidate);
    let (scheduled_grinds, skipped_grinds): (Vec<_>, Vec<_>) = all_scheduled_grinds
        .into_iter()
        .partition(|grind| max_bits.is_none_or(|max| grind.bits <= max));
    let mut challenger = TraceChallenger::new();
    seed_challenger(&mut challenger, candidate);

    let mut timings = Vec::new();
    let total_start = Instant::now();
    for (index, grind) in scheduled_grinds.iter().enumerate() {
        challenger.observe(F::from_u32((0x5154_0000u32).wrapping_add(index as u32)));
        challenger.observe(F::from_u32(grind.bits as u32));
        let start = Instant::now();
        let witness = challenger.grind(grind.bits);
        timings.push(PowTiming {
            phase: grind.phase.clone(),
            bits: grind.bits,
            witness: witness.as_canonical_u32(),
            seconds: duration_seconds(start.elapsed()),
        });
    }

    Ok(PowProfileReport {
        schema_version: 1,
        measurement_kind: "quintic_pow_profile",
        build_profile: "release",
        label: candidate.label.clone(),
        folding_variant: candidate.folding_schedule.variant,
        first_round_folding_factor: candidate.folding_schedule.first_round,
        rest_folding_factor: candidate.folding_schedule.rest,
        starting_log_inv_rate: candidate.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: candidate.rs_domain_initial_reduction_factor,
        max_bits,
        scheduled_grinds,
        skipped_grinds,
        timings,
        total_seconds: duration_seconds(total_start.elapsed()),
    })
}

fn seed_challenger(challenger: &mut TraceChallenger, candidate: &ScheduleCandidate) {
    challenger.observe(F::from_u32(0x5155_494e));
    challenger.observe(F::from_u32(candidate.folding_schedule.first_round as u32));
    challenger.observe(F::from_u32(candidate.folding_schedule.rest as u32));
    challenger.observe(F::from_u32(candidate.starting_log_inv_rate as u32));
    challenger.observe(F::from_u32(
        candidate.rs_domain_initial_reduction_factor as u32,
    ));
}

fn scheduled_grinds(candidate: &ScheduleCandidate) -> Vec<ScheduledGrind> {
    let mut grinds = Vec::new();
    if let Some(bits) = candidate.starting_folding_pow_bits.filter(|bits| *bits > 0) {
        grinds.push(ScheduledGrind {
            phase: "initial_folding_sumcheck".to_owned(),
            bits,
        });
    }
    for round in &candidate.rounds {
        if round.pow_bits > 0 {
            grinds.push(ScheduledGrind {
                phase: format!("round_{}_pre_query", round.round_index.unwrap_or(0)),
                bits: round.pow_bits,
            });
        }
        if round.folding_pow_bits > 0 {
            grinds.push(ScheduledGrind {
                phase: format!("round_{}_folding_sumcheck", round.round_index.unwrap_or(0)),
                bits: round.folding_pow_bits,
            });
        }
    }
    if let Some(bits) = candidate.final_pow_bits.filter(|bits| *bits > 0) {
        grinds.push(ScheduledGrind {
            phase: "final_pre_query".to_owned(),
            bits,
        });
    }
    if let Some(bits) = candidate.final_folding_pow_bits.filter(|bits| *bits > 0) {
        grinds.push(ScheduledGrind {
            phase: "final_folding_sumcheck".to_owned(),
            bits,
        });
    }
    grinds
}

fn duration_seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

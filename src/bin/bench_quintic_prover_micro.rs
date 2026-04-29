use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use spartan_whir_export::{
    quintic_fixture::build_quintic_k22_jb100_fixture_with_folding_schedule_and_pow_bits,
    quintic_schedule_dump::{
        build_default_quintic_schedule_dump, ScheduleCandidate, STRUCTURAL_PREFILTER_CAP,
    },
};
use whir_p3::parameters::FoldingFactor;

const TARGET_SECURITY_BITS: f64 = 100.0;
const TARGET_MERKLE_SECURITY_BITS: usize = 80;
const MAX_DERIVED_POW_BITS: usize = 30;
const MEASUREMENT_KIND: &str = "actual_whir_commit_prove";

#[derive(Debug, Serialize)]
struct ProverMicroReport {
    schema_version: u32,
    measurement_kind: &'static str,
    build_profile: &'static str,
    compile_rustflags: &'static str,
    target_cpu_native: bool,
    release_required_for_timings: bool,
    num_variables: usize,
    cap_seconds_per_candidate: Option<f64>,
    repetitions_per_candidate: usize,
    max_candidates: usize,
    selected_labels: Vec<String>,
    by_label: Vec<CandidateTiming>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CandidateTiming {
    label: String,
    measurement_kind: String,
    build_profile: String,
    compile_rustflags: String,
    target_cpu_native: bool,
    measured_num_variables: usize,
    seconds: Option<f64>,
    min_seconds: Option<f64>,
    median_seconds: Option<f64>,
    max_seconds: Option<f64>,
    repetitions: usize,
    samples: Vec<RepetitionTiming>,
    timed_out: bool,
    status: String,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepetitionTiming {
    repetition: usize,
    seconds: Option<f64>,
    timed_out: bool,
    status: String,
    error: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--run-one") {
        return run_one_child(&args);
    }

    let options = Options::parse(&args)?;
    if cfg!(debug_assertions) && options.will_measure_candidates() {
        anyhow::bail!(
            "real prover timings must be run with a release build; rerun with `cargo run --release --manifest-path spartan-whir-export/Cargo.toml --bin bench_quintic_prover_micro -- {}` or use --max-candidates 0 for schema checks",
            options.release_rerun_hint()
        );
    }

    let dump = build_default_quintic_schedule_dump();
    let selected_candidates = selected_candidates(&dump.candidates, &options)?;
    let exe = std::env::current_exe()?;
    let by_label = selected_candidates
        .iter()
        .map(|candidate| run_candidate_child(&exe, candidate, options.cap, options.repetitions))
        .collect();

    let report = ProverMicroReport {
        schema_version: 1,
        measurement_kind: MEASUREMENT_KIND,
        build_profile: build_profile(),
        compile_rustflags: compile_rustflags(),
        target_cpu_native: target_cpu_native(),
        release_required_for_timings: true,
        num_variables: dump.num_variables,
        cap_seconds_per_candidate: options.cap.map(|cap| cap.as_secs_f64()),
        repetitions_per_candidate: options.repetitions,
        max_candidates: options.max_candidates,
        selected_labels: options.labels.clone(),
        by_label,
    };

    std::fs::write(options.output, serde_json::to_string_pretty(&report)?)?;
    Ok(())
}

#[derive(Debug)]
struct Options {
    output: PathBuf,
    max_candidates: usize,
    labels: Vec<String>,
    cap: Option<Duration>,
    repetitions: usize,
}

impl Options {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut output = PathBuf::from("quintic_prover_microbench.json");
        let mut max_candidates = 30usize;
        let mut labels = Vec::new();
        let mut cap = Some(Duration::from_secs(120));
        let mut repetitions = 3usize;
        let mut cursor = 1;

        while cursor < args.len() {
            match args[cursor].as_str() {
                "--max-candidates" => {
                    cursor += 1;
                    max_candidates = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --max-candidates"))?
                        .parse()?;
                }
                "--label" => {
                    cursor += 1;
                    labels.push(
                        args.get(cursor)
                            .ok_or_else(|| anyhow::anyhow!("missing value for --label"))?
                            .to_owned(),
                    );
                }
                "--labels" => {
                    cursor += 1;
                    let raw = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --labels"))?;
                    labels.extend(
                        raw.split(',')
                            .map(str::trim)
                            .filter(|label| !label.is_empty())
                            .map(str::to_owned),
                    );
                }
                "--cap-seconds" => {
                    cursor += 1;
                    let seconds = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --cap-seconds"))?
                        .parse::<u64>()?;
                    cap = Some(Duration::from_secs(seconds));
                }
                "--no-cap" => {
                    cap = None;
                }
                "--repetitions" => {
                    cursor += 1;
                    repetitions = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --repetitions"))?
                        .parse()?;
                }
                value if value.starts_with("--") => {
                    anyhow::bail!("unknown option {value}");
                }
                value => {
                    output = PathBuf::from(value);
                }
            }
            cursor += 1;
        }

        Ok(Self {
            output,
            max_candidates,
            labels,
            cap,
            repetitions: repetitions.max(1),
        })
    }

    fn will_measure_candidates(&self) -> bool {
        !self.labels.is_empty() || self.max_candidates > 0
    }

    fn release_rerun_hint(&self) -> String {
        let mut args = Vec::new();
        if self.labels.is_empty() {
            args.push(format!("--max-candidates {}", self.max_candidates));
        } else {
            args.push(format!("--labels {}", self.labels.join(",")));
        }
        args.push(self.output.display().to_string());
        args.join(" ")
    }
}

fn selected_candidates(
    candidates: &[ScheduleCandidate],
    options: &Options,
) -> anyhow::Result<Vec<ScheduleCandidate>> {
    let survivors = structural_survivors(candidates);
    if options.labels.is_empty() {
        return Ok(survivors.into_iter().take(options.max_candidates).collect());
    }

    let by_label = survivors
        .into_iter()
        .map(|candidate| (candidate.label.clone(), candidate))
        .collect::<std::collections::BTreeMap<_, _>>();
    options
        .labels
        .iter()
        .map(|label| {
            by_label
                .get(label)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown or ineligible candidate label: {label}"))
        })
        .collect()
}

fn structural_survivors(candidates: &[ScheduleCandidate]) -> Vec<ScheduleCandidate> {
    candidates
        .iter()
        .filter(|candidate| target_eligible(candidate))
        .cloned()
        .take(STRUCTURAL_PREFILTER_CAP)
        .collect()
}

fn target_eligible(candidate: &ScheduleCandidate) -> bool {
    candidate.selectable
        && candidate
            .security_bits_achieved
            .is_some_and(|security| security >= TARGET_SECURITY_BITS)
        && candidate.merkle_security_bits_achieved >= TARGET_MERKLE_SECURITY_BITS
        && candidate
            .max_derived_pow_bits
            .is_some_and(|pow| pow <= MAX_DERIVED_POW_BITS)
}

fn run_candidate_child(
    exe: &PathBuf,
    candidate: &ScheduleCandidate,
    cap: Option<Duration>,
    repetitions: usize,
) -> CandidateTiming {
    run_candidate_child_with_repetitions(exe, candidate, cap, repetitions)
}

fn run_candidate_child_with_repetitions(
    exe: &PathBuf,
    candidate: &ScheduleCandidate,
    cap: Option<Duration>,
    repetitions: usize,
) -> CandidateTiming {
    let mut samples = Vec::new();
    for repetition in 0..repetitions.max(1) {
        samples.push(run_candidate_child_once(exe, candidate, cap, repetition));
        if samples.last().is_some_and(|sample| sample.timed_out) {
            break;
        }
    }
    aggregate_candidate_timing(candidate, samples)
}

fn run_candidate_child_once(
    exe: &PathBuf,
    candidate: &ScheduleCandidate,
    cap: Option<Duration>,
    repetition: usize,
) -> RepetitionTiming {
    let mut child = match Command::new(exe)
        .arg("--run-one")
        .arg(&candidate.label)
        .arg(candidate.requested_pow_bits.to_string())
        .arg(candidate.folding_schedule.variant)
        .arg(candidate.folding_schedule.first_round.to_string())
        .arg(candidate.folding_schedule.rest.to_string())
        .arg(candidate.starting_log_inv_rate.to_string())
        .arg(candidate.rs_domain_initial_reduction_factor.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return RepetitionTiming {
                repetition,
                seconds: None,
                timed_out: false,
                status: "error".to_owned(),
                error: Some(format!("spawn failed: {err}")),
            }
        }
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) if cap.is_some_and(|cap| start.elapsed() >= cap) => {
                let cap = cap.expect("cap checked above");
                let _ = child.kill();
                let _ = child.wait();
                return RepetitionTiming {
                    repetition,
                    seconds: Some(cap.as_secs_f64()),
                    timed_out: true,
                    status: "timeout".to_owned(),
                    error: Some("candidate exceeded cap_seconds_per_candidate".to_owned()),
                };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(250)),
            Err(err) => {
                let _ = child.kill();
                return RepetitionTiming {
                    repetition,
                    seconds: None,
                    timed_out: false,
                    status: "error".to_owned(),
                    error: Some(format!("wait failed: {err}")),
                };
            }
        }
    }

    match child.wait_with_output() {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<CandidateTiming>(&output.stdout) {
                Ok(timing) => RepetitionTiming {
                    repetition,
                    seconds: timing.seconds,
                    timed_out: timing.timed_out,
                    status: timing.status,
                    error: timing.error,
                },
                Err(err) => RepetitionTiming {
                    repetition,
                    seconds: None,
                    timed_out: false,
                    status: "error".to_owned(),
                    error: Some(format!(
                        "failed to parse child JSON: {err}; stderr={}",
                        String::from_utf8_lossy(&output.stderr)
                    )),
                },
            }
        }
        Ok(output) => RepetitionTiming {
            repetition,
            seconds: None,
            timed_out: false,
            status: "error".to_owned(),
            error: Some(format!(
                "child failed with status {}; stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
        },
        Err(err) => RepetitionTiming {
            repetition,
            seconds: None,
            timed_out: false,
            status: "error".to_owned(),
            error: Some(format!("read output failed: {err}")),
        },
    }
}

fn run_one_child(args: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !cfg!(debug_assertions),
        "--run-one prover timings must be run from a release build"
    );
    anyhow::ensure!(
        args.len() == 9,
        "usage: bench_quintic_prover_micro --run-one <label> <pow_bits> <variant> <first_round_folding_factor> <rest_folding_factor> <lir> <rsv>"
    );
    let label = args[2].clone();
    let pow_bits = args[3].parse::<u32>()?;
    let variant = args[4].as_str();
    let first_round_folding_factor = args[5].parse::<usize>()?;
    let rest_folding_factor = args[6].parse::<usize>()?;
    let starting_log_inv_rate = args[7].parse::<usize>()?;
    let rs_domain_initial_reduction_factor = args[8].parse::<usize>()?;
    let folding_schedule = match variant {
        "Constant" => FoldingFactor::Constant(first_round_folding_factor),
        "ConstantFromSecondRound" => {
            FoldingFactor::ConstantFromSecondRound(first_round_folding_factor, rest_folding_factor)
        }
        _ => anyhow::bail!("unknown folding schedule variant {variant}"),
    };

    let start = Instant::now();
    let result = build_quintic_k22_jb100_fixture_with_folding_schedule_and_pow_bits(
        pow_bits,
        folding_schedule,
        first_round_folding_factor,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    );
    let elapsed = start.elapsed().as_secs_f64();

    let timing = match result {
        Ok(_) => CandidateTiming {
            label,
            measurement_kind: MEASUREMENT_KIND.to_owned(),
            build_profile: build_profile().to_owned(),
            compile_rustflags: compile_rustflags().to_owned(),
            target_cpu_native: target_cpu_native(),
            measured_num_variables: 22,
            seconds: Some(elapsed),
            min_seconds: Some(elapsed),
            median_seconds: Some(elapsed),
            max_seconds: Some(elapsed),
            repetitions: 1,
            samples: vec![RepetitionTiming {
                repetition: 0,
                seconds: Some(elapsed),
                timed_out: false,
                status: "ok".to_owned(),
                error: None,
            }],
            timed_out: false,
            status: "ok".to_owned(),
            error: None,
        },
        Err(err) => CandidateTiming {
            label,
            measurement_kind: MEASUREMENT_KIND.to_owned(),
            build_profile: build_profile().to_owned(),
            compile_rustflags: compile_rustflags().to_owned(),
            target_cpu_native: target_cpu_native(),
            measured_num_variables: 22,
            seconds: Some(elapsed),
            min_seconds: Some(elapsed),
            median_seconds: Some(elapsed),
            max_seconds: Some(elapsed),
            repetitions: 1,
            samples: vec![RepetitionTiming {
                repetition: 0,
                seconds: Some(elapsed),
                timed_out: false,
                status: "error".to_owned(),
                error: Some(err.to_string()),
            }],
            timed_out: false,
            status: "error".to_owned(),
            error: Some(err.to_string()),
        },
    };

    println!("{}", serde_json::to_string(&timing)?);
    Ok(())
}

fn aggregate_candidate_timing(
    candidate: &ScheduleCandidate,
    samples: Vec<RepetitionTiming>,
) -> CandidateTiming {
    let timed_out = samples.iter().any(|sample| sample.timed_out);
    let first_error = samples
        .iter()
        .find(|sample| sample.status == "error" || sample.timed_out)
        .and_then(|sample| sample.error.clone());
    let mut seconds = samples
        .iter()
        .filter(|sample| sample.status == "ok" && !sample.timed_out)
        .filter_map(|sample| sample.seconds)
        .collect::<Vec<_>>();
    seconds.sort_by(|lhs, rhs| lhs.partial_cmp(rhs).unwrap_or(std::cmp::Ordering::Equal));

    let median_seconds = seconds.get(seconds.len() / 2).copied();
    let min_seconds = seconds.first().copied();
    let max_seconds = seconds.last().copied();
    let status = if timed_out {
        "timeout"
    } else if samples.iter().any(|sample| sample.status == "error") {
        "error"
    } else if seconds.is_empty() {
        "error"
    } else {
        "ok"
    };

    CandidateTiming {
        label: candidate.label.clone(),
        measurement_kind: MEASUREMENT_KIND.to_owned(),
        build_profile: build_profile().to_owned(),
        compile_rustflags: compile_rustflags().to_owned(),
        target_cpu_native: target_cpu_native(),
        measured_num_variables: 22,
        seconds: median_seconds,
        min_seconds,
        median_seconds,
        max_seconds,
        repetitions: samples.len(),
        samples,
        timed_out,
        status: status.to_owned(),
        error: first_error,
    }
}

fn compile_rustflags() -> &'static str {
    env!("SPARTAN_WHIR_EXPORT_RUSTFLAGS")
}

fn target_cpu_native() -> bool {
    compile_rustflags()
        .split_whitespace()
        .any(|flag| flag == "target-cpu=native")
        || compile_rustflags().contains("-C target-cpu=native")
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

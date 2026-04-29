use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use p3_challenger::{CanObserve, GrindingChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::Serialize;
use spartan_whir::engine::F;
use spartan_whir_export::transcript::TraceChallenger;

#[derive(Debug, Serialize)]
struct PowCalibrationReport {
    schema_version: u32,
    measurement_kind: &'static str,
    build_profile: &'static str,
    compile_rustflags: &'static str,
    target_cpu_native: bool,
    min_bits: usize,
    max_bits: usize,
    samples_per_bit: usize,
    thread_count: usize,
    seconds_per_pow_unit_median: f64,
    seconds_per_pow_unit_mean: f64,
    by_bits: Vec<PowBitCalibration>,
}

#[derive(Debug, Serialize)]
struct PowBitCalibration {
    bits: usize,
    work_units: u64,
    median_seconds: f64,
    mean_seconds: f64,
    median_seconds_per_pow_unit: f64,
    mean_seconds_per_pow_unit: f64,
    samples: Vec<PowSample>,
}

#[derive(Debug, Serialize)]
struct PowSample {
    sample_index: usize,
    witness: u32,
    seconds: f64,
    seconds_per_pow_unit: f64,
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse(&std::env::args().collect::<Vec<_>>())?;
    if cfg!(debug_assertions) && options.samples_per_bit > 0 {
        anyhow::bail!(
            "PoW calibration must be run with a release build; rerun with `cargo run --release --manifest-path spartan-whir-export/Cargo.toml --bin bench_quintic_pow_calibration -- {}`",
            options.output.display()
        );
    }

    let report = calibrate(&options)?;
    let json = serde_json::to_string_pretty(&report)?;
    if options.output == PathBuf::from("-") {
        println!("{json}");
    } else {
        std::fs::write(options.output, json + "\n")?;
    }
    Ok(())
}

#[derive(Debug)]
struct Options {
    output: PathBuf,
    min_bits: usize,
    max_bits: usize,
    samples_per_bit: usize,
}

impl Options {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut output = PathBuf::from("quintic_pow_calibration.json");
        let mut min_bits = 16usize;
        let mut max_bits = 22usize;
        let mut samples_per_bit = 5usize;
        let mut cursor = 1;
        while cursor < args.len() {
            match args[cursor].as_str() {
                "--min-bits" => {
                    cursor += 1;
                    min_bits = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --min-bits"))?
                        .parse()?;
                }
                "--max-bits" => {
                    cursor += 1;
                    max_bits = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --max-bits"))?
                        .parse()?;
                }
                "--samples-per-bit" => {
                    cursor += 1;
                    samples_per_bit = args
                        .get(cursor)
                        .ok_or_else(|| anyhow::anyhow!("missing value for --samples-per-bit"))?
                        .parse()?;
                }
                value if value.starts_with("--") => anyhow::bail!("unknown option {value}"),
                value => output = PathBuf::from(value),
            }
            cursor += 1;
        }
        anyhow::ensure!(min_bits <= max_bits, "--min-bits must be <= --max-bits");
        anyhow::ensure!(max_bits < u64::BITS as usize, "--max-bits must be < 64");
        Ok(Self {
            output,
            min_bits,
            max_bits,
            samples_per_bit,
        })
    }
}

fn calibrate(options: &Options) -> anyhow::Result<PowCalibrationReport> {
    let mut by_bits = Vec::new();
    let mut unit_samples = Vec::new();
    for bits in options.min_bits..=options.max_bits {
        let work_units = 1u64 << bits;
        let mut samples = Vec::new();
        for sample_index in 0..options.samples_per_bit {
            let mut challenger = seeded_challenger(bits, sample_index);
            let start = Instant::now();
            let witness = challenger.grind(bits);
            let seconds = duration_seconds(start.elapsed());
            let seconds_per_pow_unit = seconds / work_units as f64;
            unit_samples.push(seconds_per_pow_unit);
            samples.push(PowSample {
                sample_index,
                witness: witness.as_canonical_u32(),
                seconds,
                seconds_per_pow_unit,
            });
        }
        let seconds_values = samples
            .iter()
            .map(|sample| sample.seconds)
            .collect::<Vec<_>>();
        let unit_values = samples
            .iter()
            .map(|sample| sample.seconds_per_pow_unit)
            .collect::<Vec<_>>();
        by_bits.push(PowBitCalibration {
            bits,
            work_units,
            median_seconds: median(seconds_values.clone()),
            mean_seconds: mean(&seconds_values),
            median_seconds_per_pow_unit: median(unit_values.clone()),
            mean_seconds_per_pow_unit: mean(&unit_values),
            samples,
        });
    }

    Ok(PowCalibrationReport {
        schema_version: 1,
        measurement_kind: "quintic_pow_grind_calibration",
        build_profile: build_profile(),
        compile_rustflags: compile_rustflags(),
        target_cpu_native: target_cpu_native(),
        min_bits: options.min_bits,
        max_bits: options.max_bits,
        samples_per_bit: options.samples_per_bit,
        thread_count: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
        seconds_per_pow_unit_median: median(unit_samples.clone()),
        seconds_per_pow_unit_mean: mean(&unit_samples),
        by_bits,
    })
}

fn seeded_challenger(bits: usize, sample_index: usize) -> TraceChallenger {
    let mut challenger = TraceChallenger::new();
    challenger.observe(F::from_u32(0x5155_494e));
    challenger.observe(F::from_u32(bits as u32));
    challenger.observe(F::from_u32(sample_index as u32));
    challenger
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|lhs, rhs| lhs.partial_cmp(rhs).unwrap_or(std::cmp::Ordering::Equal));
    values[values.len() / 2]
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn duration_seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
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

use std::{fs, path::PathBuf};

use spartan_whir_export::quintic_schedule_dump::{
    build_quintic_schedule_dump, DEFAULT_MAX_STARTING_LOG_INV_RATE, DEFAULT_MERKLE_SECURITY_BITS,
    DEFAULT_NUM_VARIABLES, DEFAULT_POW_BITS, DEFAULT_SECURITY_BITS,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 1 || args.len() == 2 || args.len() == 7 || args.len() == 8,
        "usage: dump_quintic_schedule_microbench [output.json]\n       dump_quintic_schedule_microbench <num_variables> <security_bits> <merkle_bits> <pow_bits> <max_lir> <output.json>"
    );

    let (num_variables, security_bits, merkle_bits, pow_bits, max_lir, output, prefilter_cap) =
        if args.len() >= 7 {
            (
                args[1].parse::<usize>()?,
                args[2].parse::<u32>()?,
                args[3].parse::<u32>()?,
                args[4].parse::<u32>()?,
                args[5].parse::<usize>()?,
                PathBuf::from(&args[6]),
                if args.len() == 8 {
                    args[7].parse::<usize>()?
                } else {
                    spartan_whir_export::quintic_schedule_dump::STRUCTURAL_PREFILTER_CAP
                },
            )
        } else {
            let output = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("quintic_schedule_microbench_dump.json"));
            (
                DEFAULT_NUM_VARIABLES,
                DEFAULT_SECURITY_BITS,
                DEFAULT_MERKLE_SECURITY_BITS,
                DEFAULT_POW_BITS,
                DEFAULT_MAX_STARTING_LOG_INV_RATE,
                output,
                spartan_whir_export::quintic_schedule_dump::STRUCTURAL_PREFILTER_CAP,
            )
        };

    let dump = build_quintic_schedule_dump(
        num_variables,
        security_bits,
        merkle_bits,
        pow_bits,
        max_lir,
        prefilter_cap,
    );
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_string_pretty(&dump)?)?;
    eprintln!(
        "wrote {} candidates to {}",
        dump.candidates.len(),
        output.display()
    );
    Ok(())
}

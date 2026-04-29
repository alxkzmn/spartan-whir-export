use spartan_whir::{
    effective_digest_bytes_for_security_bits, engine::QuinticExtension, SecurityConfig,
    SoundnessAssumption, WhirParams,
};
use spartan_whir_export::quartic_fixture::{
    build_checked_whir_config, protocol_params_for_fixture_with_folding_factor,
};
use whir_p3::parameters::FoldingFactor;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 7 || args.len() == 8 || args.len() == 9,
        "usage: check_quintic_schedule <num_variables> <security_bits> <merkle_bits> <pow_bits> <folding_factor> <starting_log_inv_rate> [rs_domain_initial_reduction_factor] [second_round_folding_factor]"
    );
    let num_variables = args[1].parse::<usize>()?;
    let security_bits = args[2].parse::<u32>()?;
    let merkle_bits = args[3].parse::<u32>()?;
    let pow_bits = args[4].parse::<u32>()?;
    let folding_factor = args[5].parse::<usize>()?;
    let starting_log_inv_rate = args[6].parse::<usize>()?;
    let rs_domain_initial_reduction_factor = args
        .get(7)
        .map(|arg| arg.parse::<usize>())
        .transpose()?
        .unwrap_or(1);
    let second_round_folding_factor = args.get(8).map(|arg| arg.parse::<usize>()).transpose()?;

    let security = SecurityConfig {
        security_level_bits: security_bits,
        merkle_security_bits: merkle_bits,
        soundness_assumption: SoundnessAssumption::JohnsonBound,
    };
    let whir = WhirParams {
        pow_bits,
        folding_factor,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    };
    let folding = match second_round_folding_factor {
        Some(second_round) => FoldingFactor::ConstantFromSecondRound(folding_factor, second_round),
        None => FoldingFactor::Constant(folding_factor),
    };
    let protocol_params = protocol_params_for_fixture_with_folding_factor(security, whir, folding);
    let config = build_checked_whir_config::<QuinticExtension>(num_variables, &protocol_params)?;
    let final_round = config.final_round_config();

    println!("accepted=true");
    println!("folding_schedule={folding:?}");
    println!("starting_log_inv_rate={starting_log_inv_rate}");
    println!("rs_domain_initial_reduction_factor={rs_domain_initial_reduction_factor}");
    println!(
        "effective_digest_bytes={}",
        effective_digest_bytes_for_security_bits(merkle_bits as usize)
    );
    println!(
        "extension_bits={}",
        <QuinticExtension as p3_field::Field>::bits()
    );
    println!("commitment_ood_samples={}", config.commitment_ood_samples);
    println!(
        "starting_folding_pow_bits={}",
        config.starting_folding_pow_bits
    );
    println!("round_count={}", config.round_parameters.len());
    println!("final_queries={}", config.final_queries);
    println!("final_pow_bits={}", config.final_pow_bits);
    println!("final_sumcheck_rounds={}", config.final_sumcheck_rounds);
    println!("final_folding_pow_bits={}", config.final_folding_pow_bits);
    println!("final_round_num_queries={}", final_round.num_queries);
    println!("final_round_folding_factor={}", final_round.folding_factor);
    println!("final_round_num_variables={}", final_round.num_variables);
    println!("final_round_domain_size={}", final_round.domain_size);
    println!("check_pow_bits={}", config.check_pow_bits());

    Ok(())
}

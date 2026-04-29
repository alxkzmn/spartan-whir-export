use spartan_whir::{engine::QuinticExtension, SecurityConfig, SoundnessAssumption, WhirParams};
use whir_p3::parameters::FoldingFactor;

use crate::quartic_fixture::{build_standalone_fixture_with_folding_factor, StandaloneWhirFixture};

pub type EF5 = QuinticExtension;
pub type QuinticFixture = StandaloneWhirFixture<EF5>;
pub type RawWhirProof5 = crate::quartic_fixture::GenericWhirProof<EF5>;

pub const QUINTIC_K22_JB100_SECURITY: SecurityConfig = SecurityConfig {
    // Derive with a one-bit guard, then filter schedules at 100 achieved bits.
    security_level_bits: 101,
    merkle_security_bits: 80,
    soundness_assumption: SoundnessAssumption::JohnsonBound,
};

pub const QUINTIC_K22_JB100_NUM_VARIABLES: usize = 22;

pub fn quintic_whir_params_with_pow_bits(
    pow_bits: u32,
    folding_factor: usize,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> WhirParams {
    WhirParams {
        pow_bits,
        folding_factor,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    }
}

pub fn build_quintic_k22_jb100_fixture_with_folding_schedule_and_pow_bits(
    pow_bits: u32,
    folding_schedule: FoldingFactor,
    first_round_folding_factor: usize,
    starting_log_inv_rate: usize,
    rs_domain_initial_reduction_factor: usize,
) -> anyhow::Result<QuinticFixture> {
    let whir_params = quintic_whir_params_with_pow_bits(
        pow_bits,
        first_round_folding_factor,
        starting_log_inv_rate,
        rs_domain_initial_reduction_factor,
    );
    build_standalone_fixture_with_folding_factor::<EF5>(
        QUINTIC_K22_JB100_SECURITY,
        whir_params,
        QUINTIC_K22_JB100_NUM_VARIABLES,
        folding_schedule,
    )
}

pub fn build_quintic_k22_jb100_ext5_lir4_ff4_rsv4_fixture() -> anyhow::Result<QuinticFixture> {
    build_quintic_k22_jb100_fixture_with_folding_schedule_and_pow_bits(
        27,
        FoldingFactor::Constant(4),
        4,
        4,
        4,
    )
}

pub fn tamper_first_stir_query_quintic(proof: &RawWhirProof5) -> anyhow::Result<RawWhirProof5> {
    crate::quartic_fixture::tamper_first_stir_query(proof)
}

pub fn tamper_first_initial_ood_answer_quintic(
    proof: &RawWhirProof5,
) -> anyhow::Result<RawWhirProof5> {
    crate::quartic_fixture::tamper_first_initial_ood_answer(proof)
}

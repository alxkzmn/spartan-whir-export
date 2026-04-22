use crate::quartic_fixture::{
    build_standalone_fixture, tamper_first_initial_ood_answer, tamper_first_stir_query,
    GenericWhirProof, StandaloneWhirFixture,
};
use spartan_whir::{engine::OcticBinExtension, SecurityConfig, SoundnessAssumption, WhirParams};

pub type EF8 = OcticBinExtension;
pub type RawWhirProof8 = GenericWhirProof<EF8>;
pub type OcticFixture = StandaloneWhirFixture<EF8>;

pub const OCTIC_K22_JB100_SECURITY: SecurityConfig = SecurityConfig {
    security_level_bits: 100,
    merkle_security_bits: 80,
    soundness_assumption: SoundnessAssumption::JohnsonBound,
};

pub const OCTIC_K22_JB100_WHIR_PARAMS: WhirParams = WhirParams {
    pow_bits: 30,
    folding_factor: 4,
    starting_log_inv_rate: 6,
    rs_domain_initial_reduction_factor: 1,
};

pub fn build_octic_k22_jb100_fixture() -> anyhow::Result<OcticFixture> {
    build_standalone_fixture::<EF8>(OCTIC_K22_JB100_SECURITY, OCTIC_K22_JB100_WHIR_PARAMS, 22)
}

pub fn tamper_first_stir_query_octic(proof: &RawWhirProof8) -> anyhow::Result<RawWhirProof8> {
    tamper_first_stir_query(proof)
}

pub fn tamper_first_initial_ood_answer_octic(
    proof: &RawWhirProof8,
) -> anyhow::Result<RawWhirProof8> {
    tamper_first_initial_ood_answer(proof)
}

use p3_challenger::{CanObserve, FieldChallenger};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, Hash};
use spartan_whir::{
    domain_separator::DomainSeparator,
    engine::{QuarticBinExtension, F},
    generate_satisfiable_fixture, SecurityConfig, SoundnessAssumption, SyntheticR1csConfig,
    WhirParams,
};

use crate::{transcript::TraceChallenger, FIXTURE_WHIR_PARAMS};

pub type EF4 = QuarticBinExtension;

#[derive(Debug)]
pub struct SpartanContextFixture {
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_io: usize,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub public_inputs: Vec<F>,
    pub preimage: Vec<u8>,
    pub digest: [u8; 32],
    pub checkpoint: EF4,
}

pub fn build_spartan_context_fixture() -> anyhow::Result<SpartanContextFixture> {
    build_spartan_context_fixture_with_params(FIXTURE_WHIR_PARAMS)
}

pub fn build_spartan_context_fixture_with_params(
    whir_params: WhirParams,
) -> anyhow::Result<SpartanContextFixture> {
    let security = SecurityConfig {
        security_level_bits: 80,
        merkle_security_bits: 80,
        soundness_assumption: SoundnessAssumption::CapacityBound,
    };
    let fixture = generate_satisfiable_fixture(&SyntheticR1csConfig {
        target_log2_witness_poly: 4,
        num_constraints: 4,
        num_io: 3,
        a_terms_per_constraint: 2,
        b_terms_per_constraint: 2,
        seed: 0x5A17_E2C7_1357_2468,
    })
    .map_err(|err| anyhow::anyhow!("failed to generate Spartan transcript fixture: {err:?}"))?;

    let domain_separator = DomainSeparator::new(&fixture.shape, &security, &whir_params);
    let preimage = domain_separator.to_bytes();
    let digest = Keccak256Hash {}.hash_iter(preimage.clone());

    let digest_hash: Hash<F, u8, 32> = digest.into();
    let mut challenger = TraceChallenger::new();
    challenger.observe(digest_hash);
    challenger.observe_slice(&fixture.public_inputs);
    let checkpoint = challenger.sample_algebra_element::<EF4>();

    let expected_preimage_len = 76;
    anyhow::ensure!(
        preimage.len() == expected_preimage_len,
        "unexpected Spartan domain separator length: expected {expected_preimage_len}, got {}",
        preimage.len()
    );

    Ok(SpartanContextFixture {
        num_cons: fixture.shape.num_cons,
        num_vars: fixture.shape.num_vars,
        num_io: fixture.shape.num_io,
        security,
        whir_params,
        public_inputs: fixture.public_inputs,
        preimage,
        digest,
        checkpoint,
    })
}

pub fn soundness_assumption_byte(soundness: SoundnessAssumption) -> u8 {
    match soundness {
        SoundnessAssumption::UniqueDecoding => 0,
        SoundnessAssumption::JohnsonBound => 1,
        SoundnessAssumption::CapacityBound => 2,
    }
}

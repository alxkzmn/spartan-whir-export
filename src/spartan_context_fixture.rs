use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, Hash};

use crate::{
    octic_fixture::OCTIC_K22_JB100_SECURITY, transcript::TraceChallenger, OcticBinExtension,
    QuarticBinExtension, SecurityConfig, SoundnessAssumption, WhirFoldingSchedule, WhirParams, F,
    FIXTURE_WHIR_PARAMS,
};

pub type EF4 = QuarticBinExtension;
pub type EF8 = OcticBinExtension;

#[derive(Debug)]
pub struct SpartanContextFixture<EF>
where
    EF: BasedVectorSpace<F> + Copy,
{
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_io: usize,
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub public_inputs: Vec<F>,
    pub preimage: Vec<u8>,
    pub digest: [u8; 32],
    pub checkpoint: EF,
}

pub fn build_spartan_context_fixture() -> anyhow::Result<SpartanContextFixture<EF4>> {
    build_spartan_context_fixture_with_security::<EF4>(
        SecurityConfig {
            security_level_bits: 80,
            merkle_security_bits: 80,
            soundness_assumption: SoundnessAssumption::CapacityBound,
        },
        FIXTURE_WHIR_PARAMS,
    )
}

pub fn build_spartan_context_fixture_with_params(
    whir_params: WhirParams,
) -> anyhow::Result<SpartanContextFixture<EF4>> {
    build_spartan_context_fixture_with_security::<EF4>(
        SecurityConfig {
            security_level_bits: 80,
            merkle_security_bits: 80,
            soundness_assumption: SoundnessAssumption::CapacityBound,
        },
        whir_params,
    )
}

pub fn build_spartan_context_fixture_octic_k22_jb100() -> anyhow::Result<SpartanContextFixture<EF8>>
{
    build_spartan_context_fixture_with_security::<EF8>(
        OCTIC_K22_JB100_SECURITY,
        crate::octic_fixture::OCTIC_K22_JB100_WHIR_PARAMS,
    )
}

pub fn build_spartan_context_fixture_with_security<EF>(
    security: SecurityConfig,
    whir_params: WhirParams,
) -> anyhow::Result<SpartanContextFixture<EF>>
where
    EF: BasedVectorSpace<F> + Copy,
{
    const TARGET_LOG2_WITNESS_POLY: usize = 4;
    const NUM_CONSTRAINTS: usize = 4;
    const NUM_IO: usize = 3;
    const SEED: u64 = 0x5A17_E2C7_1357_2468;

    let num_vars = 1usize << TARGET_LOG2_WITNESS_POLY;
    let public_inputs = synthetic_public_inputs(TARGET_LOG2_WITNESS_POLY, NUM_IO, SEED)
        .ok_or_else(|| anyhow::anyhow!("Spartan context fixture dimensions overflow"))?;
    let preimage =
        spartan_context_preimage(NUM_CONSTRAINTS, num_vars, NUM_IO, &security, &whir_params);
    let digest = Keccak256Hash {}.hash_iter(preimage.clone());

    let digest_hash: Hash<F, u8, 32> = digest.into();
    let mut challenger = TraceChallenger::new();
    challenger.observe(digest_hash);
    challenger.observe_slice(&public_inputs);
    let checkpoint = challenger.sample_algebra_element::<EF>();

    let expected_preimage_len = 76;
    anyhow::ensure!(
        preimage.len() == expected_preimage_len,
        "unexpected Spartan domain separator length: expected {expected_preimage_len}, got {}",
        preimage.len()
    );

    Ok(SpartanContextFixture {
        num_cons: NUM_CONSTRAINTS,
        num_vars,
        num_io: NUM_IO,
        security,
        whir_params,
        public_inputs,
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

/// Encodes the `spartan-whir-v0` transcript context consumed by the Solidity parity fixtures.
fn spartan_context_preimage(
    num_cons: usize,
    num_vars: usize,
    num_io: usize,
    security: &SecurityConfig,
    whir_params: &WhirParams,
) -> Vec<u8> {
    let mut out = b"spartan-whir-v0".to_vec();
    out.extend_from_slice(&(num_cons as u64).to_le_bytes());
    out.extend_from_slice(&(num_vars as u64).to_le_bytes());
    out.extend_from_slice(&(num_io as u64).to_le_bytes());
    out.extend_from_slice(&security.security_level_bits.to_le_bytes());
    out.extend_from_slice(&security.merkle_security_bits.to_le_bytes());
    out.push(soundness_assumption_byte(security.soundness_assumption));
    encode_whir_params(whir_params, &mut out);
    out
}

fn synthetic_public_inputs(
    target_log2_witness_poly: usize,
    num_io: usize,
    seed: u64,
) -> Option<Vec<F>> {
    let witness_len = 1usize.checked_shl(target_log2_witness_poly as u32)?;
    let mut rng = XorShift64::new(seed);
    for _ in 0..witness_len {
        let _ = rng.next_field();
    }
    Some((0..num_io).map(|_| rng.next_field()).collect())
}

fn encode_whir_params(params: &WhirParams, out: &mut Vec<u8>) {
    out.extend_from_slice(&params.pow_bits.to_le_bytes());
    out.extend_from_slice(&(params.folding_factor as u64).to_le_bytes());
    out.extend_from_slice(&(params.starting_log_inv_rate as u64).to_le_bytes());
    out.extend_from_slice(&(params.rs_domain_initial_reduction_factor as u64).to_le_bytes());

    let canonical_constant_schedule = match &params.folding_schedule {
        None => true,
        Some(WhirFoldingSchedule::Constant(factor)) => *factor == params.folding_factor,
        Some(_) => false,
    };
    if params.round_log_inv_rates.is_empty() && canonical_constant_schedule {
        return;
    }

    match params.effective_folding_schedule() {
        WhirFoldingSchedule::Constant(factor) => {
            out.push(0);
            out.extend_from_slice(&(factor as u64).to_le_bytes());
        }
        WhirFoldingSchedule::ConstantFromSecondRound { first, rest } => {
            out.push(1);
            out.extend_from_slice(&(first as u64).to_le_bytes());
            out.extend_from_slice(&(rest as u64).to_le_bytes());
        }
        WhirFoldingSchedule::PerRound(factors) => {
            out.push(2);
            out.extend_from_slice(&(factors.len() as u64).to_le_bytes());
            for factor in factors {
                out.extend_from_slice(&(factor as u64).to_le_bytes());
            }
        }
    }
    out.extend_from_slice(&(params.round_log_inv_rates.len() as u64).to_le_bytes());
    for rate in &params.round_log_inv_rates {
        out.extend_from_slice(&(*rate as u64).to_le_bytes());
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_field(&mut self) -> F {
        F::from_u32((self.next_u64() as u32) % F::ORDER_U32)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField32;

    use super::build_spartan_context_fixture;
    use crate::utils::extension_coeffs_u32;

    #[test]
    fn spartan_context_matches_solidity_fixture() {
        let fixture = build_spartan_context_fixture().expect("build Spartan context fixture");

        assert_eq!(fixture.num_cons, 4);
        assert_eq!(fixture.num_vars, 16);
        assert_eq!(fixture.num_io, 3);
        assert_eq!(
            fixture
                .public_inputs
                .iter()
                .map(PrimeField32::as_canonical_u32)
                .collect::<Vec<_>>(),
            [0x1310_e7db, 0x115c_50d3, 0x6198_5d74]
        );
        assert_eq!(
            hex::encode(&fixture.preimage),
            "7370617274616e2d776869722d76300400000000000000100000000000000003000000000000005000000050000000021e000000040000000000000006000000000000000100000000000000"
        );
        assert_eq!(
            hex::encode(fixture.digest),
            "8bd888bc2fbd3b851d27f0e14c01de1c6015f1a840bcfd4022df711363ea6152"
        );
        assert_eq!(
            extension_coeffs_u32(&fixture.checkpoint),
            [0x6c4b_a704, 0x30ae_9763, 0x2249_f386, 0x3868_19a4]
        );
    }
}

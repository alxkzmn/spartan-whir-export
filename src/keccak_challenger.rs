use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, Hash};
use p3_util::log2_ceil_u64;
use tracing::instrument;

const KECCAK_DIGEST_BYTES: usize = 32;

/// Byte challenger with Plonky3 `HashChallenger<u8, Keccak256Hash, 32>` semantics.
#[derive(Clone, Debug, Default)]
pub struct KeccakByteChallenger {
    input_buffer: Vec<u8>,
    output_buffer: [u8; KECCAK_DIGEST_BYTES],
    output_len: usize,
}

impl KeccakByteChallenger {
    pub const fn new(initial_state: Vec<u8>) -> Self {
        Self {
            input_buffer: initial_state,
            output_buffer: [0; KECCAK_DIGEST_BYTES],
            output_len: 0,
        }
    }

    fn flush(&mut self) {
        let output = Keccak256Hash.hash_iter(self.input_buffer.iter().copied());
        self.input_buffer.clear();
        self.input_buffer.extend_from_slice(&output);
        self.output_buffer = output;
        self.output_len = KECCAK_DIGEST_BYTES;
    }

    fn check_witness_u32(&self, bits: usize, witness: u32) -> bool {
        if bits == 0 {
            return true;
        }
        let witness_bytes = witness.to_le_bytes();
        let digest = Keccak256Hash
            .hash_iter_slices([self.input_buffer.as_slice(), witness_bytes.as_slice()]);
        let value = u32::from_le_bytes([digest[31], digest[30], digest[29], digest[28]]) as usize;
        value & ((1 << bits) - 1) == 0
    }
}

impl CanObserve<u8> for KeccakByteChallenger {
    fn observe(&mut self, value: u8) {
        self.output_len = 0;
        self.input_buffer.push(value);
    }

    fn observe_slice(&mut self, values: &[u8]) {
        if !values.is_empty() {
            self.output_len = 0;
            self.input_buffer.extend_from_slice(values);
        }
    }
}

impl<const N: usize> CanObserve<[u8; N]> for KeccakByteChallenger {
    fn observe(&mut self, values: [u8; N]) {
        self.observe_slice(&values);
    }
}

impl CanSample<u8> for KeccakByteChallenger {
    fn sample(&mut self) -> u8 {
        if self.output_len == 0 {
            self.flush();
        }
        self.output_len -= 1;
        self.output_buffer[self.output_len]
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalKeccakChallenger32<F> {
    inner: KeccakByteChallenger,
    _marker: PhantomData<F>,
}

impl<F: PrimeField32> CanonicalKeccakChallenger32<F> {
    pub const fn new(inner: KeccakByteChallenger) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32> CanObserve<F> for CanonicalKeccakChallenger32<F> {
    fn observe(&mut self, value: F) {
        self.inner
            .observe_slice(&value.as_canonical_u32().to_le_bytes());
    }
}

impl<F: PrimeField32, const N: usize> CanObserve<Hash<F, u8, N>>
    for CanonicalKeccakChallenger32<F>
{
    fn observe(&mut self, values: Hash<F, u8, N>) {
        for value in values {
            self.inner.observe(value);
        }
    }
}

impl<F: PrimeField32, const N: usize> CanObserve<Hash<F, u64, N>>
    for CanonicalKeccakChallenger32<F>
{
    fn observe(&mut self, values: Hash<F, u64, N>) {
        for value in values {
            self.inner.observe_slice(&value.to_le_bytes());
        }
    }
}

impl<F, EF> CanSample<EF> for CanonicalKeccakChallenger32<F>
where
    F: PrimeField32,
    EF: BasedVectorSpace<F>,
{
    fn sample(&mut self) -> EF {
        let modulus = F::ORDER_U32;
        let log_size = log2_ceil_u64(F::ORDER_U64);
        let pow_of_two_bound = ((1u64 << log_size) - 1) as u32;
        EF::from_basis_coefficients_fn(|_| loop {
            let value = u32::from_le_bytes(self.inner.sample_array()) & pow_of_two_bound;
            if value < modulus {
                return unsafe { F::from_canonical_unchecked(value) };
            }
        })
    }
}

impl<F: PrimeField32> CanSampleBits<usize> for CanonicalKeccakChallenger32<F> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize);
        assert!((1 << bits) <= F::ORDER_U64 as usize);
        let value = u32::from_le_bytes(self.inner.sample_array()) as usize;
        value & ((1 << bits) - 1)
    }
}

impl<F: PrimeField32> GrindingChallenger for CanonicalKeccakChallenger32<F> {
    type Witness = F;

    #[instrument(name = "grind for proof-of-work witness", skip_all)]
    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert!(bits < usize::BITS as usize);
        assert!((1 << bits) < F::ORDER_U32);
        if bits == 0 {
            return F::ZERO;
        }

        let witness = (0..F::ORDER_U32)
            .into_par_iter()
            .find_any(|&candidate| self.inner.check_witness_u32(bits, candidate))
            .map(|candidate| unsafe { F::from_canonical_unchecked(candidate) })
            .expect("failed to find witness");
        assert!(self.check_witness(bits, witness));
        witness
    }
}

impl<F: PrimeField32> FieldChallenger<F> for CanonicalKeccakChallenger32<F> {}

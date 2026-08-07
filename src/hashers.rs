use p3_field::{PackedValue, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use whir_p3::metrics::{add_leaf_hash_call, add_node_hash_call};

pub const KECCAK_DIGEST_ELEMS: usize = 4;
const KECCAK_DIGEST_BYTES: usize = 32;

#[must_use]
pub const fn effective_digest_bytes_for_security_bits(security_bits: usize) -> usize {
    let bytes = security_bits.saturating_mul(2).div_ceil(8);
    if bytes == 0 {
        1
    } else if bytes > KECCAK_DIGEST_BYTES {
        KECCAK_DIGEST_BYTES
    } else {
        bytes
    }
}

const fn clamp_effective_digest_bytes(effective_digest_bytes: usize) -> usize {
    if effective_digest_bytes == 0 {
        1
    } else if effective_digest_bytes > KECCAK_DIGEST_BYTES {
        KECCAK_DIGEST_BYTES
    } else {
        effective_digest_bytes
    }
}

fn mask_digest_tail(bytes: &mut [u8; KECCAK_DIGEST_BYTES], effective_digest_bytes: usize) {
    bytes[clamp_effective_digest_bytes(effective_digest_bytes)..].fill(0);
}

pub fn digest_to_bytes(digest: &[u64; KECCAK_DIGEST_ELEMS]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, word) in digest.iter().enumerate() {
        out[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn digest_from_bytes(bytes: &[u8; 32]) -> [u64; KECCAK_DIGEST_ELEMS] {
    let mut out = [0_u64; KECCAK_DIGEST_ELEMS];
    for (index, word) in out.iter_mut().enumerate() {
        *word = u64::from_be_bytes(
            bytes[index * 8..(index + 1) * 8]
                .try_into()
                .expect("eight-byte digest word"),
        );
    }
    out
}

#[derive(Clone, Copy, Debug)]
pub struct KeccakFieldLeafHasher {
    effective_digest_bytes: usize,
}

impl KeccakFieldLeafHasher {
    pub const fn new(effective_digest_bytes: usize) -> Self {
        Self {
            effective_digest_bytes,
        }
    }

    pub const fn effective_digest_bytes(&self) -> usize {
        clamp_effective_digest_bytes(self.effective_digest_bytes)
    }
}

impl Default for KeccakFieldLeafHasher {
    fn default() -> Self {
        Self::new(KECCAK_DIGEST_BYTES)
    }
}

impl<P> CryptographicHasher<P, [u64; KECCAK_DIGEST_ELEMS]> for KeccakFieldLeafHasher
where
    P: PackedValue,
    P::Value: PrimeField32,
{
    fn hash_iter<I>(&self, input: I) -> [u64; KECCAK_DIGEST_ELEMS]
    where
        I: IntoIterator<Item = P>,
    {
        let mut preimage = vec![0x00];
        for packed in input {
            for value in packed.as_slice() {
                preimage.extend_from_slice(&value.as_canonical_u32().to_be_bytes());
            }
        }

        add_leaf_hash_call();
        let mut bytes = Keccak256Hash.hash_iter(preimage);
        mask_digest_tail(&mut bytes, self.effective_digest_bytes());
        digest_from_bytes(&bytes)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Keccak256NodeCompress {
    effective_digest_bytes: usize,
}

impl Keccak256NodeCompress {
    pub const fn new(effective_digest_bytes: usize) -> Self {
        Self {
            effective_digest_bytes,
        }
    }

    pub const fn effective_digest_bytes(&self) -> usize {
        clamp_effective_digest_bytes(self.effective_digest_bytes)
    }
}

impl Default for Keccak256NodeCompress {
    fn default() -> Self {
        Self::new(KECCAK_DIGEST_BYTES)
    }
}

impl PseudoCompressionFunction<[u64; KECCAK_DIGEST_ELEMS], 2> for Keccak256NodeCompress {
    fn compress(&self, input: [[u64; KECCAK_DIGEST_ELEMS]; 2]) -> [u64; KECCAK_DIGEST_ELEMS] {
        let left = digest_to_bytes(&input[0]);
        let right = digest_to_bytes(&input[1]);

        add_node_hash_call();
        let mut bytes =
            Keccak256Hash.hash_iter_slices([&[0x01][..], left.as_slice(), right.as_slice()]);
        mask_digest_tail(&mut bytes, self.effective_digest_bytes());
        digest_from_bytes(&bytes)
    }
}

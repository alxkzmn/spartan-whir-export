use anyhow::ensure;
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::PseudoCompressionFunction;
use serde::Serialize;
use spartan_whir::{
    engine::{OcticBinExtension, QuarticBinExtension, F},
    KeccakFieldHash, KeccakNodeCompress,
};
use whir_p3::whir::merkle_multiproof::{
    build_multiproof_from_paths, compute_root_from_multiproof, hash_leaf_base,
};
use whir_p3::{
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    sumcheck::lagrange::extrapolate_012,
};

use crate::{
    utils::{digest_hex, extension_coeffs_u32, pack_extension_u256, u256_hex},
    DIGEST_ELEMS, KOALABEAR_MODULUS,
};

const FIELD_VECTOR_COUNT: usize = 16;

/// One KoalaBear base-field arithmetic test vector: two operands and expected results.
#[derive(Debug, Serialize)]
pub struct BaseFieldVector {
    pub a: u32,
    pub b: u32,
    pub add: u32,
    pub sub: u32,
    pub mul: u32,
    pub inv: u32,
}

/// Extension-field arithmetic test vector with both coefficient-array and packed-U256 forms.
#[derive(Debug, Serialize)]
pub struct ExtensionFieldVector {
    pub a: Vec<u32>,
    pub b: Vec<u32>,
    pub add: Vec<u32>,
    pub sub: Vec<u32>,
    pub mul: Vec<u32>,
    pub inv: Vec<u32>,
    pub packed_a: String,
    pub packed_b: String,
    pub packed_add: String,
    pub packed_sub: String,
    pub packed_mul: String,
    pub packed_inv: String,
}

/// Extension-field helper vector for `extrapolate_012`.
#[derive(Debug, Serialize)]
pub struct ExtensionExtrapolateVector {
    pub packed_e0: String,
    pub packed_e1: String,
    pub packed_e2: String,
    pub packed_r: String,
    pub packed_result: String,
}

/// Extension-field helper vector for equality-polynomial evaluation.
#[derive(Debug, Serialize)]
pub struct ExtensionEqPolyVector {
    pub packed_p: Vec<String>,
    pub packed_q: Vec<String>,
    pub packed_result: String,
}

/// Extension-field helper vector for multilinear hypercube evaluation.
#[derive(Debug, Serialize)]
pub struct ExtensionHypercubeVector {
    pub packed_evals: Vec<String>,
    pub packed_point: Vec<String>,
    pub packed_result: String,
}

/// Top-level JSON structure for field arithmetic test vectors (base, quartic, octic).
#[derive(Debug, Serialize)]
pub struct FieldVectorFile {
    pub base: Vec<BaseFieldVector>,
    pub quartic: Vec<ExtensionFieldVector>,
    pub octic: Vec<ExtensionFieldVector>,
    pub quartic_extrapolate: Vec<ExtensionExtrapolateVector>,
    pub quartic_eq_poly: Vec<ExtensionEqPolyVector>,
    pub quartic_hypercube: Vec<ExtensionHypercubeVector>,
    pub octic_extrapolate: Vec<ExtensionExtrapolateVector>,
    pub octic_eq_poly: Vec<ExtensionEqPolyVector>,
    pub octic_hypercube: Vec<ExtensionHypercubeVector>,
}

/// Leaf-hash test vector: field-element row and the Keccak digest produced by `hash_leaf_base`.
#[derive(Debug, Serialize)]
pub struct MerkleLeafVector {
    pub values: Vec<u32>,
    pub digest: String,
}

/// Internal-node compression test vector: two child digests and the expected parent digest.
#[derive(Debug, Serialize)]
pub struct MerkleNodeCompressionVector {
    pub left: String,
    pub right: String,
    pub parent: String,
}

/// Multiproof test vector: leaf indices, opened rows, sibling decommitments, and expected root.
#[derive(Debug, Serialize)]
pub struct MerkleMultiproofVector {
    pub indices: Vec<usize>,
    pub opened_rows: Vec<Vec<u32>>,
    pub decommitments: Vec<String>,
    pub expected_root: String,
}

/// Top-level JSON structure for Merkle-tree test vectors (leaf hashes, compressions, multiproof).
#[derive(Debug, Serialize)]
pub struct MerkleVectorFile {
    pub effective_digest_bytes: usize,
    pub leaf_hashes: Vec<MerkleLeafVector>,
    pub node_compressions: Vec<MerkleNodeCompressionVector>,
    pub multiproof: MerkleMultiproofVector,
}

/// Deterministic PRNG for reproducible test-vector generation.
#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_base_field(&mut self) -> F {
        let raw = (self.next_u64() as u32) % KOALABEAR_MODULUS;
        F::from_u32(raw)
    }

    fn next_nonzero_base_field(&mut self) -> F {
        let raw = ((self.next_u64() as u32) % (KOALABEAR_MODULUS - 1)) + 1;
        F::from_u32(raw)
    }
}

pub fn generate_field_vectors() -> FieldVectorFile {
    let mut rng = XorShift64::new(0xACE5_1234_5678_9ABC);

    let mut base = Vec::with_capacity(FIELD_VECTOR_COUNT);
    for _ in 0..FIELD_VECTOR_COUNT {
        let a = rng.next_nonzero_base_field();
        let b = rng.next_nonzero_base_field();
        base.push(BaseFieldVector {
            a: a.as_canonical_u32(),
            b: b.as_canonical_u32(),
            add: (a + b).as_canonical_u32(),
            sub: (a - b).as_canonical_u32(),
            mul: (a * b).as_canonical_u32(),
            inv: a.inverse().as_canonical_u32(),
        });
    }

    let quartic = generate_extension_vectors::<QuarticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let octic = generate_extension_vectors::<OcticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let quartic_extrapolate =
        generate_extrapolate_vectors::<QuarticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let quartic_eq_poly =
        generate_eq_poly_vectors::<QuarticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let quartic_hypercube =
        generate_hypercube_vectors::<QuarticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let octic_extrapolate =
        generate_extrapolate_vectors::<OcticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let octic_eq_poly = generate_eq_poly_vectors::<OcticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);
    let octic_hypercube =
        generate_hypercube_vectors::<OcticBinExtension>(&mut rng, FIELD_VECTOR_COUNT);

    FieldVectorFile {
        base,
        quartic,
        octic,
        quartic_extrapolate,
        quartic_eq_poly,
        quartic_hypercube,
        octic_extrapolate,
        octic_eq_poly,
        octic_hypercube,
    }
}

pub fn generate_merkle_vectors(effective_digest_bytes: usize) -> anyhow::Result<MerkleVectorFile> {
    let mut rng = XorShift64::new(0xBEEF_CAFE_1122_3344);
    let height = 8usize;
    let width = 4usize;

    let mut flat_values = Vec::with_capacity(height * width);
    let mut rows = Vec::with_capacity(height);
    for _ in 0..height {
        let row: Vec<F> = (0..width).map(|_| rng.next_base_field()).collect();
        flat_values.extend_from_slice(&row);
        rows.push(row);
    }

    let matrix = RowMajorMatrix::new(flat_values, width);

    let hasher = KeccakFieldHash::new(effective_digest_bytes);
    let compress = KeccakNodeCompress::new(effective_digest_bytes);
    let mmcs = MerkleTreeMmcs::<F, u64, KeccakFieldHash, KeccakNodeCompress, DIGEST_ELEMS>::new(
        hasher, compress,
    );

    let (root, prover_data) = mmcs.commit_matrix(matrix);
    let expected_root = *root.as_ref();

    let leaf_hashes: Vec<[u64; DIGEST_ELEMS]> = rows
        .iter()
        .map(|row| hash_leaf_base::<F, u64, KeccakFieldHash, DIGEST_ELEMS>(&hasher, row))
        .collect();

    let node_compressions = vec![
        MerkleNodeCompressionVector {
            left: digest_hex(&leaf_hashes[0]),
            right: digest_hex(&leaf_hashes[1]),
            parent: digest_hex(&compress.compress([leaf_hashes[0], leaf_hashes[1]])),
        },
        MerkleNodeCompressionVector {
            left: digest_hex(&leaf_hashes[2]),
            right: digest_hex(&leaf_hashes[3]),
            parent: digest_hex(&compress.compress([leaf_hashes[2], leaf_hashes[3]])),
        },
    ];

    let leaf_vectors = rows
        .iter()
        .take(4)
        .zip(leaf_hashes.iter().take(4))
        .map(|(row, digest)| MerkleLeafVector {
            values: row.iter().map(|v| v.as_canonical_u32()).collect(),
            digest: digest_hex(digest),
        })
        .collect::<Vec<_>>();

    let indices = vec![1usize, 3usize, 6usize];
    let mut opened_rows = Vec::new();
    let mut opening_paths = Vec::new();

    for &index in &indices {
        let opening = mmcs.open_batch(index, &prover_data);
        opened_rows.push(opening.opened_values[0].clone());
        opening_paths.push(opening.opening_proof);
    }

    let multiproof = build_multiproof_from_paths::<u64, DIGEST_ELEMS>(&indices, opening_paths)
        .map_err(|err| anyhow::anyhow!("failed to build multiproof: {err:?}"))?;

    let multiproof_leaf_hashes: Vec<[u64; DIGEST_ELEMS]> = opened_rows
        .iter()
        .map(|row| hash_leaf_base::<F, u64, KeccakFieldHash, DIGEST_ELEMS>(&hasher, row))
        .collect();

    let depth = height.ilog2() as usize;
    let recomputed_root = compute_root_from_multiproof::<u64, _, DIGEST_ELEMS>(
        &indices,
        &multiproof_leaf_hashes,
        depth,
        &multiproof.decommitments,
        |pair| compress.compress(pair),
    )
    .map_err(|err| anyhow::anyhow!("failed to recompute multiproof root: {err:?}"))?;

    ensure!(
        recomputed_root == expected_root,
        "recomputed multiproof root does not match expected root"
    );

    let multiproof_vector = MerkleMultiproofVector {
        indices,
        opened_rows: opened_rows
            .into_iter()
            .map(|row| row.into_iter().map(|v| v.as_canonical_u32()).collect())
            .collect(),
        decommitments: multiproof.decommitments.iter().map(digest_hex).collect(),
        expected_root: digest_hex(&expected_root),
    };

    Ok(MerkleVectorFile {
        effective_digest_bytes,
        leaf_hashes: leaf_vectors,
        node_compressions,
        multiproof: multiproof_vector,
    })
}

fn generate_extension_vectors<EF>(rng: &mut XorShift64, count: usize) -> Vec<ExtensionFieldVector>
where
    EF: Field + BasedVectorSpace<F> + Copy,
{
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let a = random_extension::<EF>(rng, true);
        let b = random_extension::<EF>(rng, true);
        let inv = a.inverse();

        out.push(ExtensionFieldVector {
            a: extension_coeffs_u32(&a),
            b: extension_coeffs_u32(&b),
            add: extension_coeffs_u32(&(a + b)),
            sub: extension_coeffs_u32(&(a - b)),
            mul: extension_coeffs_u32(&(a * b)),
            inv: extension_coeffs_u32(&inv),
            packed_a: u256_hex(pack_extension_u256(&a)),
            packed_b: u256_hex(pack_extension_u256(&b)),
            packed_add: u256_hex(pack_extension_u256(&(a + b))),
            packed_sub: u256_hex(pack_extension_u256(&(a - b))),
            packed_mul: u256_hex(pack_extension_u256(&(a * b))),
            packed_inv: u256_hex(pack_extension_u256(&inv)),
        });
    }
    out
}

fn generate_extrapolate_vectors<EF>(
    rng: &mut XorShift64,
    count: usize,
) -> Vec<ExtensionExtrapolateVector>
where
    EF: Field + BasedVectorSpace<F> + Copy,
{
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let e0 = random_extension::<EF>(rng, false);
        let e1 = random_extension::<EF>(rng, false);
        let e2 = random_extension::<EF>(rng, false);
        let r = random_extension::<EF>(rng, false);
        let result = extrapolate_012(e0, e1, e2, r);

        out.push(ExtensionExtrapolateVector {
            packed_e0: u256_hex(pack_extension_u256(&e0)),
            packed_e1: u256_hex(pack_extension_u256(&e1)),
            packed_e2: u256_hex(pack_extension_u256(&e2)),
            packed_r: u256_hex(pack_extension_u256(&r)),
            packed_result: u256_hex(pack_extension_u256(&result)),
        });
    }
    out
}

fn generate_eq_poly_vectors<EF>(rng: &mut XorShift64, count: usize) -> Vec<ExtensionEqPolyVector>
where
    EF: Field + BasedVectorSpace<F> + Copy,
{
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let dimension = (i % 4) + 1;
        let p = random_extension_vec::<EF>(rng, dimension);
        let q = random_extension_vec::<EF>(rng, dimension);
        let result = MultilinearPoint::<EF>::eval_eq(&p, &q);

        out.push(ExtensionEqPolyVector {
            packed_p: p
                .iter()
                .map(|value| u256_hex(pack_extension_u256(value)))
                .collect(),
            packed_q: q
                .iter()
                .map(|value| u256_hex(pack_extension_u256(value)))
                .collect(),
            packed_result: u256_hex(pack_extension_u256(&result)),
        });
    }
    out
}

fn generate_hypercube_vectors<EF>(
    rng: &mut XorShift64,
    count: usize,
) -> Vec<ExtensionHypercubeVector>
where
    EF: Field + BasedVectorSpace<F> + ExtensionField<F> + Copy + Send + Sync,
{
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let num_variables = (i % 4) + 1;
        let evals = random_extension_vec::<EF>(rng, 1 << num_variables);
        let point = random_extension_vec::<EF>(rng, num_variables);
        let result = EvaluationsList::new(evals.clone())
            .evaluate_hypercube_ext::<F>(&MultilinearPoint::new(point.clone()));

        out.push(ExtensionHypercubeVector {
            packed_evals: evals
                .iter()
                .map(|value| u256_hex(pack_extension_u256(value)))
                .collect(),
            packed_point: point
                .iter()
                .map(|value| u256_hex(pack_extension_u256(value)))
                .collect(),
            packed_result: u256_hex(pack_extension_u256(&result)),
        });
    }
    out
}

fn random_extension<EF>(rng: &mut XorShift64, nonzero: bool) -> EF
where
    EF: Field + BasedVectorSpace<F>,
{
    loop {
        let candidate = EF::from_basis_coefficients_fn(|_| rng.next_base_field());
        if !nonzero || !candidate.is_zero() {
            return candidate;
        }
    }
}

fn random_extension_vec<EF>(rng: &mut XorShift64, len: usize) -> Vec<EF>
where
    EF: Field + BasedVectorSpace<F>,
{
    (0..len)
        .map(|_| random_extension::<EF>(rng, false))
        .collect()
}

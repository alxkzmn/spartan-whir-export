use alloy_primitives::Bytes;
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger, HashChallenger,
    SerializingChallenger32,
};
use p3_field::PrimeField32;
use p3_keccak::Keccak256Hash;
use p3_symmetric::Hash;
use serde::Serialize;
use spartan_whir::{engine::F, KeccakChallenger};

use crate::ChallengerTranscriptEvent;

pub const OP_OBSERVE_BYTES: u8 = 0;
pub const OP_SAMPLE_BASE: u8 = 1;
pub const OP_SAMPLE_BITS: u8 = 2;
pub const OP_GRIND: u8 = 3;

/// A single Fiat-Shamir transcript operation in replay-friendly form.
#[derive(Debug, Clone, Serialize)]
pub struct TranscriptEvent {
    pub step: usize,
    pub op: &'static str,
    pub op_code: u8,
    pub observed_bytes_hex: String,
    pub arg0: u64,
    pub arg1: u64,
}

/// Logging wrapper around the real `KeccakChallenger`. Every observe, sample,
/// sample_bits, and grind call is delegated to `inner` and recorded in canonical form.
#[derive(Debug, Clone)]
pub struct TraceChallenger {
    inner: KeccakChallenger,
    events: Vec<TranscriptEvent>,
    observed_base_values: Vec<F>,
}

/// Serializable JSON structure for the full prover/verifier transcript trace and checkpoint comparison.
#[derive(Debug, Serialize)]
pub struct TranscriptTraceFile {
    pub prover_events: Vec<TranscriptEvent>,
    pub verifier_events: Vec<TranscriptEvent>,
    pub checkpoint_prover: Vec<u32>,
    pub checkpoint_verifier: Vec<u32>,
    pub checkpoint_match: bool,
}

impl TraceChallenger {
    pub fn new() -> Self {
        let inner = SerializingChallenger32::new(HashChallenger::<u8, Keccak256Hash, 32>::new(
            vec![],
            Keccak256Hash {},
        ));
        Self {
            inner,
            events: Vec::new(),
            observed_base_values: Vec::new(),
        }
    }

    fn push_event(
        &mut self,
        op: &'static str,
        op_code: u8,
        observed_bytes: Vec<u8>,
        arg0: u64,
        arg1: u64,
    ) {
        self.events.push(TranscriptEvent {
            step: self.events.len(),
            op,
            op_code,
            observed_bytes_hex: hex::encode(observed_bytes),
            arg0,
            arg1,
        });
    }

    pub fn into_events(self) -> Vec<TranscriptEvent> {
        self.events
    }

    pub fn observed_base_values(&self) -> &[F] {
        &self.observed_base_values
    }
}

impl Default for TraceChallenger {
    fn default() -> Self {
        Self::new()
    }
}

impl CanObserve<F> for TraceChallenger {
    fn observe(&mut self, value: F) {
        let observed_bytes = value.to_unique_u32().to_le_bytes();
        self.observed_base_values.push(value);
        self.inner.observe(value);
        self.push_event(
            "observe_bytes",
            OP_OBSERVE_BYTES,
            observed_bytes.to_vec(),
            value.as_canonical_u32().into(),
            0,
        );
    }
}

impl<const N: usize> CanObserve<Hash<F, u8, N>> for TraceChallenger {
    fn observe(&mut self, value: Hash<F, u8, N>) {
        let observed_bytes = value.as_ref().to_vec();
        self.inner.observe(value);
        self.push_event("observe_bytes", OP_OBSERVE_BYTES, observed_bytes, 0, 0);
    }
}

impl<const N: usize> CanObserve<Hash<F, u64, N>> for TraceChallenger {
    fn observe(&mut self, value: Hash<F, u64, N>) {
        let mut observed_bytes = Vec::with_capacity(N * 8);
        for word in value {
            observed_bytes.extend_from_slice(&word.to_le_bytes());
        }
        self.inner.observe(value);
        self.push_event("observe_bytes", OP_OBSERVE_BYTES, observed_bytes, 0, 0);
    }
}

impl CanSample<F> for TraceChallenger {
    fn sample(&mut self) -> F {
        let sampled: F = self.inner.sample();
        self.push_event(
            "sample_base",
            OP_SAMPLE_BASE,
            Vec::new(),
            sampled.as_canonical_u32().into(),
            0,
        );
        sampled
    }
}

impl CanSampleBits<usize> for TraceChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        let sampled = self.inner.sample_bits(bits);
        self.push_event(
            "sample_bits",
            OP_SAMPLE_BITS,
            Vec::new(),
            bits as u64,
            sampled as u64,
        );
        sampled
    }
}

impl GrindingChallenger for TraceChallenger {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        let witness = self.inner.grind(bits);
        self.push_event(
            "grind",
            OP_GRIND,
            Vec::new(),
            bits as u64,
            witness.as_canonical_u32().into(),
        );
        witness
    }
}

impl FieldChallenger<F> for TraceChallenger {}

pub fn events_to_abi(events: Vec<TranscriptEvent>) -> Vec<ChallengerTranscriptEvent> {
    events
        .into_iter()
        .map(|event| ChallengerTranscriptEvent {
            op: event.op_code,
            observedBytes: Bytes::from(hex::decode(event.observed_bytes_hex).expect("valid hex")),
            arg0: alloy_primitives::U256::from(event.arg0 as usize),
            arg1: alloy_primitives::U256::from(event.arg1 as usize),
        })
        .collect()
}

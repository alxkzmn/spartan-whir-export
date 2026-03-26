use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger, HashChallenger,
    SerializingChallenger32,
};
use p3_field::PrimeField32;
use p3_keccak::Keccak256Hash;
use p3_symmetric::Hash;
use serde::Serialize;
use spartan_whir::{engine::F, KeccakChallenger};

/// A single Fiat-Shamir transcript operation (observe/sample/grind) with challenger state snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct TranscriptEvent {
    pub step: usize,
    pub op: &'static str,
    pub value: String,
    pub state_before: String,
    pub state_after: String,
}

/// Logging wrapper around the real `KeccakChallenger`. Every observe, sample,
/// sample_bits, and grind call is delegated to `inner` and a before/after log
/// entry is recorded.
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
        value: String,
        state_before: String,
        state_after: String,
    ) {
        self.events.push(TranscriptEvent {
            step: self.events.len(),
            op,
            value,
            state_before,
            state_after,
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
        let state_before = format!("{:?}", self.inner);
        self.observed_base_values.push(value);
        self.inner.observe(value);
        let state_after = format!("{:?}", self.inner);
        self.push_event(
            "observe",
            format!("base:{}", value.as_canonical_u32()),
            state_before,
            state_after,
        );
    }
}

impl<const N: usize> CanObserve<Hash<F, u8, N>> for TraceChallenger {
    fn observe(&mut self, value: Hash<F, u8, N>) {
        let state_before = format!("{:?}", self.inner);
        let payload = format!("hash_u8:{value:?}");
        self.inner.observe(value);
        let state_after = format!("{:?}", self.inner);
        self.push_event("observe", payload, state_before, state_after);
    }
}

impl<const N: usize> CanObserve<Hash<F, u64, N>> for TraceChallenger {
    fn observe(&mut self, value: Hash<F, u64, N>) {
        let state_before = format!("{:?}", self.inner);
        let payload = format!("hash_u64:{value:?}");
        self.inner.observe(value);
        let state_after = format!("{:?}", self.inner);
        self.push_event("observe", payload, state_before, state_after);
    }
}

impl CanSample<F> for TraceChallenger {
    fn sample(&mut self) -> F {
        let state_before = format!("{:?}", self.inner);
        let sampled: F = self.inner.sample();
        let state_after = format!("{:?}", self.inner);
        self.push_event(
            "sample",
            format!("base:{}", sampled.as_canonical_u32()),
            state_before,
            state_after,
        );
        sampled
    }
}

impl CanSampleBits<usize> for TraceChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        let state_before = format!("{:?}", self.inner);
        let sampled = self.inner.sample_bits(bits);
        let state_after = format!("{:?}", self.inner);
        self.push_event(
            "sample_bits",
            format!("bits:{bits},value:{sampled}"),
            state_before,
            state_after,
        );
        sampled
    }
}

impl GrindingChallenger for TraceChallenger {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        let state_before = format!("{:?}", self.inner);
        let witness = self.inner.grind(bits);
        let state_after = format!("{:?}", self.inner);
        self.push_event(
            "grind",
            format!("bits:{bits},witness:{}", witness.as_canonical_u32()),
            state_before,
            state_after,
        );
        witness
    }
}

impl FieldChallenger<F> for TraceChallenger {}

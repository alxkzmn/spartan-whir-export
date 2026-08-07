use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SoundnessAssumption {
    UniqueDecoding,
    JohnsonBound,
    CapacityBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub security_level_bits: u32,
    pub merkle_security_bits: u32,
    pub soundness_assumption: SoundnessAssumption,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhirFoldingSchedule {
    Constant(usize),
    ConstantFromSecondRound { first: usize, rest: usize },
    PerRound(Vec<usize>),
}

impl WhirFoldingSchedule {
    pub fn first_round(&self) -> usize {
        match self {
            Self::Constant(factor) => *factor,
            Self::ConstantFromSecondRound { first, .. } => *first,
            Self::PerRound(factors) => factors.first().copied().unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhirParams {
    pub pow_bits: u32,
    pub folding_factor: usize,
    pub starting_log_inv_rate: usize,
    pub rs_domain_initial_reduction_factor: usize,
    #[serde(default)]
    pub folding_schedule: Option<WhirFoldingSchedule>,
    #[serde(default)]
    pub round_log_inv_rates: Vec<usize>,
}

impl WhirParams {
    pub fn effective_folding_schedule(&self) -> WhirFoldingSchedule {
        self.folding_schedule
            .clone()
            .unwrap_or(WhirFoldingSchedule::Constant(self.folding_factor))
    }

    pub fn first_folding_factor(&self) -> usize {
        self.effective_folding_schedule().first_round()
    }
}

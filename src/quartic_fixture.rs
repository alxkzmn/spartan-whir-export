use anyhow::{ensure, Context};
use p3_challenger::FieldChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use spartan_whir::{
    effective_digest_bytes_for_security_bits,
    engine::{ExtField, QuarticBinExtension, F},
    KeccakFieldHash, KeccakNodeCompress, SecurityConfig, SoundnessAssumption, SumcheckStrategy,
    WhirParams,
};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator as WhirFsDomainSeparator,
    parameters::{errors::SecurityAssumption as WhirSecurity, FoldingFactor, ProtocolParameters},
    poly::{evals::EvaluationsList as WhirEvaluations, multilinear::MultilinearPoint as WhirPoint},
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        constraints::statement::{initial::InitialStatement, EqStatement},
        parameters::WhirConfig,
        proof::{QueryBatchOpening as RawQueryBatchOpening, WhirProof as RawWhirProof},
        prover::Prover,
        verifier::Verifier,
    },
};

use crate::{
    transcript::TraceChallenger, transcript::TranscriptEvent, DIGEST_ELEMS, FIXTURE_WHIR_PARAMS,
};

pub type GenericWhirProof<EF> = RawWhirProof<F, EF, u64, DIGEST_ELEMS>;
pub type GenericWhirConfig<EF> =
    WhirConfig<EF, F, KeccakFieldHash, KeccakNodeCompress, TraceChallenger>;

#[derive(Debug)]
pub struct StandaloneWhirFixture<EF>
where
    EF: ExtField + BasedVectorSpace<F> + Copy,
{
    pub security: SecurityConfig,
    pub whir_params: WhirParams,
    pub num_variables: usize,
    pub config: GenericWhirConfig<EF>,
    pub proof: GenericWhirProof<EF>,
    pub statement_points: Vec<Vec<EF>>,
    pub statement_evaluations: Vec<EF>,
    pub whir_fs_pattern: Vec<F>,
    pub prover_trace: Vec<TranscriptEvent>,
    pub verifier_trace: Vec<TranscriptEvent>,
    pub checkpoint_prover: EF,
    pub checkpoint_verifier: EF,
}

pub type EF4 = QuarticBinExtension;
pub type RawWhirProof4 = GenericWhirProof<EF4>;
pub type WhirConfig4 = GenericWhirConfig<EF4>;
pub type QuarticFixture = StandaloneWhirFixture<EF4>;

pub fn tamper_first_stir_query<EF>(
    proof: &GenericWhirProof<EF>,
) -> anyhow::Result<GenericWhirProof<EF>>
where
    EF: BasedVectorSpace<F> + Copy + core::ops::AddAssign + From<F>,
{
    let mut tampered = proof.clone();

    if let Some(query_batch) = tampered
        .rounds
        .iter_mut()
        .find_map(|round| round.query_batch.as_mut())
        .or(tampered.final_query_batch.as_mut())
    {
        tamper_query_batch_value(query_batch)?;
        return Ok(tampered);
    }

    Err(anyhow::anyhow!(
        "proof does not contain any STIR query batches"
    ))
}

pub fn tamper_first_initial_ood_answer<EF>(
    proof: &GenericWhirProof<EF>,
) -> anyhow::Result<GenericWhirProof<EF>>
where
    EF: BasedVectorSpace<F> + Copy + core::ops::AddAssign + From<F>,
{
    let mut tampered = proof.clone();
    let first = tampered
        .initial_ood_answers
        .first_mut()
        .context("proof does not contain any initial OOD answers")?;
    *first += EF::from(F::from_u32(1));
    Ok(tampered)
}

pub fn build_quartic_fixture() -> anyhow::Result<QuarticFixture> {
    build_quartic_fixture_with_params(FIXTURE_WHIR_PARAMS)
}

pub fn build_quartic_fixture_with_params(
    whir_params: WhirParams,
) -> anyhow::Result<QuarticFixture> {
    build_standalone_fixture::<EF4>(
        SecurityConfig {
            security_level_bits: 80,
            merkle_security_bits: 80,
            soundness_assumption: SoundnessAssumption::CapacityBound,
        },
        whir_params,
        16,
    )
}

pub fn build_standalone_fixture<EF>(
    security: SecurityConfig,
    whir_params: WhirParams,
    num_variables: usize,
) -> anyhow::Result<StandaloneWhirFixture<EF>>
where
    EF: ExtField + BasedVectorSpace<F> + Copy + From<F>,
{
    build_standalone_fixture_with_folding_factor(
        security,
        whir_params,
        num_variables,
        FoldingFactor::Constant(whir_params.folding_factor),
    )
}

pub fn build_standalone_fixture_with_folding_factor<EF>(
    security: SecurityConfig,
    whir_params: WhirParams,
    num_variables: usize,
    folding_factor: FoldingFactor,
) -> anyhow::Result<StandaloneWhirFixture<EF>>
where
    EF: ExtField + BasedVectorSpace<F> + Copy + From<F>,
{
    let protocol_params =
        protocol_params_for_fixture_with_folding_factor(security, whir_params, folding_factor);
    let config = build_checked_whir_config::<EF>(num_variables, &protocol_params)?;

    let polynomial: Vec<F> = (0..(1 << num_variables))
        .map(|i| F::from_u32((i + 1) as u32))
        .collect();
    let poly_evals = WhirEvaluations::new(polynomial.clone());

    let mut user_statement = EqStatement::initialize(num_variables);
    let mut statement_points = Vec::new();
    let mut statement_evaluations = Vec::new();

    for seed in [3_u32] {
        let point = WhirPoint::expand_from_univariate(EF::from(F::from_u32(seed)), num_variables);
        let evaluation = poly_evals.evaluate_hypercube_base(&point);
        statement_points.push(point.as_slice().to_vec());
        statement_evaluations.push(evaluation);
        user_statement.add_evaluated_constraint(point, evaluation);
    }

    let mut domain_separator = WhirFsDomainSeparator::<EF, F>::new(vec![]);
    domain_separator.commit_statement::<_, _, _, DIGEST_ELEMS>(&config);
    domain_separator.add_whir_proof::<_, _, _, DIGEST_ELEMS>(&config);

    let mut pattern_capture = TraceChallenger::new();
    domain_separator.observe_domain_separator(&mut pattern_capture);
    let whir_fs_pattern = pattern_capture.observed_base_values().to_vec();

    let mut proof =
        GenericWhirProof::<EF>::from_protocol_parameters(&protocol_params, num_variables);

    let mut prover_challenger = TraceChallenger::new();
    domain_separator.observe_domain_separator(&mut prover_challenger);

    let dft = Radix2DFTSmallBatch::<F>::default();
    let mut initial_statement = config.initial_statement(
        WhirEvaluations::new(polynomial.clone()),
        SumcheckStrategy::Svo,
    );

    let committer = CommitmentWriter::new(&config);
    let merkle_tree = committer
        .commit::<_, F, u64, u64, DIGEST_ELEMS>(
            &dft,
            &mut proof,
            &mut prover_challenger,
            &mut initial_statement,
        )
        .map_err(|err| anyhow::anyhow!("commit failed: {err:?}"))?;

    let mut full_statement = user_statement.clone();
    for (point, eval) in initial_statement.normalize().iter() {
        full_statement.add_evaluated_constraint(point.clone(), *eval);
    }

    let final_statement =
        InitialStatement::from_eq_statement(WhirEvaluations::new(polynomial), full_statement);

    let prover = Prover(&config);
    prover
        .prove::<_, F, u64, u64, DIGEST_ELEMS>(
            &dft,
            &mut proof,
            &mut prover_challenger,
            &final_statement,
            merkle_tree,
        )
        .map_err(|err| anyhow::anyhow!("prove failed: {err:?}"))?;

    let checkpoint_prover: EF = prover_challenger.clone().sample_algebra_element();
    let prover_trace = prover_challenger.into_events();

    let mut verifier_challenger = TraceChallenger::new();
    domain_separator.observe_domain_separator(&mut verifier_challenger);

    let reader = CommitmentReader::new(&config);
    let parsed_commitment =
        reader.parse_commitment::<u64, DIGEST_ELEMS>(&proof, &mut verifier_challenger);

    ensure!(
        *parsed_commitment.root.as_ref() == proof.initial_commitment,
        "parsed commitment root mismatch"
    );

    let verifier = Verifier::new(&config);
    verifier
        .verify::<F, u64, u64, DIGEST_ELEMS>(
            &proof,
            &mut verifier_challenger,
            &parsed_commitment,
            user_statement,
        )
        .map_err(|err| anyhow::anyhow!("verify failed: {err:?}"))?;

    let checkpoint_verifier: EF = verifier_challenger.clone().sample_algebra_element();
    let verifier_trace = verifier_challenger.into_events();

    ensure!(
        checkpoint_prover == checkpoint_verifier,
        "transcript checkpoint mismatch"
    );

    Ok(StandaloneWhirFixture {
        security,
        whir_params,
        num_variables,
        config,
        proof,
        statement_points,
        statement_evaluations,
        whir_fs_pattern,
        prover_trace,
        verifier_trace,
        checkpoint_prover,
        checkpoint_verifier,
    })
}

pub fn protocol_params_for_fixture(
    security: SecurityConfig,
    whir_params: WhirParams,
) -> ProtocolParameters<KeccakFieldHash, KeccakNodeCompress> {
    protocol_params_for_fixture_with_folding_factor(
        security,
        whir_params,
        FoldingFactor::Constant(whir_params.folding_factor),
    )
}

pub fn protocol_params_for_fixture_with_folding_factor(
    security: SecurityConfig,
    whir_params: WhirParams,
    folding_factor: FoldingFactor,
) -> ProtocolParameters<KeccakFieldHash, KeccakNodeCompress> {
    ProtocolParameters {
        starting_log_inv_rate: whir_params.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: whir_params.rs_domain_initial_reduction_factor,
        folding_factor,
        soundness_type: map_soundness_assumption(security.soundness_assumption),
        security_level: security.security_level_bits as usize,
        pow_bits: whir_params.pow_bits as usize,
        merkle_hash: KeccakFieldHash::new(effective_digest_bytes_for_security_bits(
            security.merkle_security_bits as usize,
        )),
        merkle_compress: KeccakNodeCompress::new(effective_digest_bytes_for_security_bits(
            security.merkle_security_bits as usize,
        )),
    }
}

pub fn build_checked_whir_config<EF>(
    num_variables: usize,
    protocol_params: &ProtocolParameters<KeccakFieldHash, KeccakNodeCompress>,
) -> anyhow::Result<GenericWhirConfig<EF>>
where
    EF: ExtensionField<F> + TwoAdicField,
{
    let config = GenericWhirConfig::<EF>::new(num_variables, protocol_params.clone());
    if config.check_pow_bits() {
        return Ok(config);
    }

    let mut failures = Vec::new();
    if config.starting_folding_pow_bits > protocol_params.pow_bits {
        failures.push(format!(
            "starting_folding_pow_bits={} > max_pow_bits={}",
            config.starting_folding_pow_bits, protocol_params.pow_bits
        ));
    }
    if config.final_pow_bits > protocol_params.pow_bits {
        failures.push(format!(
            "final_pow_bits={} > max_pow_bits={}",
            config.final_pow_bits, protocol_params.pow_bits
        ));
    }
    if config.final_folding_pow_bits > protocol_params.pow_bits {
        failures.push(format!(
            "final_folding_pow_bits={} > max_pow_bits={}",
            config.final_folding_pow_bits, protocol_params.pow_bits
        ));
    }
    for (round_index, round) in config.round_parameters.iter().enumerate() {
        if round.pow_bits > protocol_params.pow_bits {
            failures.push(format!(
                "round[{round_index}].pow_bits={} > max_pow_bits={}",
                round.pow_bits, protocol_params.pow_bits
            ));
        }
        if round.folding_pow_bits > protocol_params.pow_bits {
            failures.push(format!(
                "round[{round_index}].folding_pow_bits={} > max_pow_bits={}",
                round.folding_pow_bits, protocol_params.pow_bits
            ));
        }
    }

    anyhow::bail!(
        "invalid WHIR schedule for extension_degree={}, num_variables={num_variables}: {}",
        EF::DIMENSION,
        failures.join(", ")
    )
}

fn map_soundness_assumption(soundness: SoundnessAssumption) -> WhirSecurity {
    match soundness {
        SoundnessAssumption::UniqueDecoding => WhirSecurity::UniqueDecoding,
        SoundnessAssumption::JohnsonBound => WhirSecurity::JohnsonBound,
        SoundnessAssumption::CapacityBound => WhirSecurity::CapacityBound,
    }
}

fn tamper_query_batch_value<EF>(
    query_batch: &mut RawQueryBatchOpening<F, EF, u64, DIGEST_ELEMS>,
) -> anyhow::Result<()>
where
    EF: BasedVectorSpace<F> + Copy + core::ops::AddAssign + From<F>,
{
    match query_batch {
        RawQueryBatchOpening::Base { values, .. } => {
            let first = values
                .first_mut()
                .and_then(|row| row.first_mut())
                .context("base STIR query batch is empty")?;
            *first += F::from_u32(1);
        }
        RawQueryBatchOpening::Extension { values, .. } => {
            let first = values
                .first_mut()
                .and_then(|row| row.first_mut())
                .context("extension STIR query batch is empty")?;
            *first += EF::from(F::from_u32(1));
        }
    }

    Ok(())
}

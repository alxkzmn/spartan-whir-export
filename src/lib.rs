pub mod abi_export;
pub mod quartic_fixture;
pub mod spartan_context_fixture;
pub mod transcript;
pub mod utils;
pub mod vectors;

use alloy_sol_types::sol;

pub const DIGEST_ELEMS: usize = 4;

sol! {
    struct MerkleLeafHashFixture {
        uint256[] values;
        bytes32 digest;
    }

    struct MerkleNodeCompressionFixture {
        bytes32 left;
        bytes32 right;
        bytes32 parent;
    }

    struct MerkleMultiproofFixture {
        uint256 depth;
        uint256[] indices;
        uint256[][] openedRows;
        bytes32[] decommitments;
        bytes32 expectedRoot;
    }

    struct MerkleVectorFixture {
        uint256 effectiveDigestBytes;
        MerkleLeafHashFixture[] leafHashes;
        MerkleNodeCompressionFixture[] nodeCompressions;
        MerkleMultiproofFixture multiproof;
    }

    struct ChallengerTranscriptEvent {
        uint8 op;
        bytes observedBytes;
        uint256 arg0;
        uint256 arg1;
    }

    struct ChallengerTranscriptTrace {
        ChallengerTranscriptEvent[] proverEvents;
        ChallengerTranscriptEvent[] verifierEvents;
        uint256[] checkpointProver;
        uint256[] checkpointVerifier;
        bool checkpointMatch;
    }

    struct SpartanTranscriptContextFixture {
        uint256 numCons;
        uint256 numVars;
        uint256 numIo;
        uint32 securityLevelBits;
        uint32 merkleSecurityBits;
        uint8 soundnessAssumption;
        uint32 powBits;
        uint256 foldingFactor;
        uint256 startingLogInvRate;
        uint256 rsDomainInitialReductionFactor;
        uint256[] publicInputs;
        bytes preimage;
        bytes32 digest;
        uint256[] checkpoint;
    }

    struct QueryBatchOpening {
        uint8 kind;
        uint256 numQueries;
        uint256 rowLen;
        uint256[] values;
        bytes32[] decommitments;
    }

    struct SumcheckData {
        uint256[] polynomialEvals;
        uint256[] powWitnesses;
    }

    struct WhirRoundProof {
        bytes32 commitment;
        uint256[] oodAnswers;
        uint256 powWitness;
        QueryBatchOpening queryBatch;
        SumcheckData sumcheck;
    }

    struct WhirProof {
        bytes32 initialCommitment;
        uint256[] initialOodAnswers;
        SumcheckData initialSumcheck;
        WhirRoundProof[] rounds;
        uint256[] finalPoly;
        uint256 finalPowWitness;
        bool finalQueryBatchPresent;
        QueryBatchOpening finalQueryBatch;
        bool finalSumcheckPresent;
        SumcheckData finalSumcheck;
    }

    struct RoundConfig {
        uint256 powBits;
        uint256 foldingPowBits;
        uint256 numQueries;
        uint256 oodSamples;
        uint256 numVariables;
        uint256 foldingFactor;
        uint256 domainSize;
        uint256 foldedDomainGen;
    }

    struct ExpandedWhirConfig {
        uint256 numVariables;
        uint256 securityLevel;
        uint256 maxPowBits;
        uint256 commitmentOodSamples;
        uint256 startingLogInvRate;
        uint256 startingFoldingPowBits;
        uint256 rsDomainInitialReductionFactor;
        uint256 finalSumcheckRounds;
        uint8 soundnessAssumption;
        uint32 merkleSecurityBits;
        uint8 effectiveDigestBytes;
        uint256[] whirFsPattern;
        RoundConfig[] roundParameters;
        RoundConfig finalRoundConfig;
    }

    struct WhirStatement {
        uint256[][] points;
        uint256[] evaluations;
    }

    struct SpartanInstance {
        uint256[] publicInputs;
        bytes32 witnessCommitment;
    }

    struct SpartanProof {
        uint256[] outerSumcheckPolys;
        uint256[3] outerClaims;
        uint256[] innerSumcheckPolys;
        uint256 witnessEval;
        WhirProof pcsProof;
    }
}

pub const KOALABEAR_MODULUS: u32 = 0x7f00_0001;

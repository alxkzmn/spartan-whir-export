use p3_field::{
    extension::{BinomialExtensionField, QuinticTrinomialExtensionField},
    BasedVectorSpace, ExtensionField, TwoAdicField,
};
use p3_koala_bear::KoalaBear;

use crate::{CanonicalKeccakChallenger32, KeccakByteChallenger};

pub type F = KoalaBear;
pub type QuarticBinExtension = BinomialExtensionField<F, 4>;
pub type OcticBinExtension = BinomialExtensionField<F, 8>;
pub type QuinticExtension = QuinticTrinomialExtensionField<F>;
pub type KeccakFieldHash = crate::KeccakFieldLeafHasher;
pub type KeccakNodeCompress = crate::Keccak256NodeCompress;
pub type KeccakChallenger = CanonicalKeccakChallenger32<F>;

pub trait ExtField:
    ExtensionField<F> + BasedVectorSpace<F> + TwoAdicField + Copy + Send + Sync
{
}

impl<EF> ExtField for EF where
    EF: ExtensionField<F> + BasedVectorSpace<F> + TwoAdicField + Copy + Send + Sync
{
}

pub fn keccak_challenger() -> KeccakChallenger {
    KeccakChallenger::new(KeccakByteChallenger::default())
}

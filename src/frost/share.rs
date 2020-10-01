use crate::{SpendAuth, VerificationKey};

/// The threshold analogue of a [`SecretKey`](crate::SecretKey), used for
/// threshold signing.
pub struct SecretShare {
    _config: super::Config,
}

impl<'a> From<&'a SecretShare> for VerificationKey<SpendAuth> {
    fn from(_ss: &'a SecretShare) -> VerificationKey<SpendAuth> {
        unimplemented!();
    }
}

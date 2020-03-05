use crate::{PublicKey, SpendAuth};

/// The threshold analogue of a [`SecretKey`](crate::SecretKey), used for
/// threshold signing.
pub struct SecretShare {
    _config: super::Config,
}

impl<'a> From<&'a SecretShare> for PublicKey<SpendAuth> {
    fn from(_ss: &'a SecretShare) -> PublicKey<SpendAuth> {
        unimplemented!();
    }
}

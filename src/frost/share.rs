use crate::{PublicKey, SpendAuth};

/// A share of a secret key, used for threshold signing.
pub struct SecretShare {
    _config: super::Config,
}

impl<'a> From<&'a SecretShare> for PublicKey<SpendAuth> {
    fn from(_ss: &'a SecretShare) -> PublicKey<SpendAuth> {
        unimplemented!();
    }
}

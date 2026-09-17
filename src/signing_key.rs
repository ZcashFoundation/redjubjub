// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use core::convert::{TryFrom, TryInto};

use crate::{Error, Randomizer, SigType, Signature, SpendAuth, VerificationKey};

use rand_core::{CryptoRng, Rng};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A RedJubJub signing key.
///
/// If the `zeroize` feature is enabled, the secret scalar is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(bound = "T: SigType"))]
pub struct SigningKey<T: SigType>(reddsa::SigningKey<T::RedDSASigType>);

impl<'a, T: SigType> From<&'a SigningKey<T>> for VerificationKey<T> {
    fn from(sk: &'a SigningKey<T>) -> VerificationKey<T> {
        let reddsa_vk = reddsa::VerificationKey::<_>::from(&sk.0);
        VerificationKey(reddsa_vk)
    }
}

#[cfg(feature = "zeroize")]
impl<T: SigType> Zeroize for SigningKey<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// The inner `reddsa::SigningKey` zeroizes itself on drop.
#[cfg(feature = "zeroize")]
impl<T: SigType> ZeroizeOnDrop for SigningKey<T> {}

impl<T: SigType> SigningKey<T> {
    /// Returns the canonical byte encoding of the secret scalar.
    ///
    /// The returned array is secret key material; the caller is responsible for
    /// zeroizing it once it is no longer needed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl<T: SigType> TryFrom<[u8; 32]> for SigningKey<T> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let reddsa_sk = reddsa::SigningKey::<_>::try_from(bytes)?;
        Ok(SigningKey(reddsa_sk))
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SerdeHelper([u8; 32]);

impl<T: SigType> TryFrom<SerdeHelper> for SigningKey<T> {
    type Error = Error;

    fn try_from(helper: SerdeHelper) -> Result<Self, Self::Error> {
        helper.0.try_into()
    }
}

impl<T: SigType> From<SigningKey<T>> for SerdeHelper {
    fn from(sk: SigningKey<T>) -> Self {
        Self(sk.to_bytes())
    }
}

impl SigningKey<SpendAuth> {
    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: &Randomizer) -> SigningKey<SpendAuth> {
        let reddsa_sk = self.0.randomize(randomizer);
        SigningKey(reddsa_sk)
    }
}

impl<T: SigType> SigningKey<T> {
    /// Generate a new signing key.
    pub fn new<R: Rng + CryptoRng>(rng: R) -> SigningKey<T> {
        let reddsa_sk = reddsa::SigningKey::new(rng);
        SigningKey(reddsa_sk)
    }

    /// Create a signature of type `T` on `msg` using this `SigningKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign<R: Rng + CryptoRng>(&self, rng: R, msg: &[u8]) -> Signature<T> {
        let reddsa_sig = self.0.sign(rng, msg);
        Signature(reddsa_sig)
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    use core::convert::TryFrom;

    use zeroize::Zeroize;

    use super::SigningKey;
    use crate::SpendAuth;

    #[test]
    fn zeroize_erases_secret_scalar() {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        let mut key = SigningKey::<SpendAuth>::try_from(bytes).unwrap();
        assert_eq!(key.to_bytes(), bytes);

        key.zeroize();
        assert_eq!(key.to_bytes(), [0; 32]);
    }
}

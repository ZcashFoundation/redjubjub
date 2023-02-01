// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use std::convert::{TryFrom, TryInto};

use crate::{Error, Randomizer, SigType, Signature, SpendAuth, VerificationKey};

use rand_core::{CryptoRng, RngCore};

/// A RedJubJub signing key.
#[derive(Copy, Clone, Debug)]
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

impl<T: SigType> From<SigningKey<T>> for [u8; 32] {
    fn from(sk: SigningKey<T>) -> [u8; 32] {
        sk.0.into()
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
        Self(sk.into())
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
    pub fn new<R: RngCore + CryptoRng>(rng: R) -> SigningKey<T> {
        let reddsa_sk = reddsa::SigningKey::new(rng);
        SigningKey(reddsa_sk)
    }

    /// Create a signature of type `T` on `msg` using this `SigningKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign<R: RngCore + CryptoRng>(&self, rng: R, msg: &[u8]) -> Signature<T> {
        let reddsa_sig = self.0.sign(rng, msg);
        Signature(reddsa_sig)
    }
}

// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use core::{convert::TryFrom, hash::Hash};

use crate::{Error, Randomizer, SigType, Signature, SpendAuth};

/// A refinement type for `[u8; 32]` indicating that the bytes represent
/// an encoding of a RedJubJub verification key.
///
/// This is useful for representing a compressed verification key; the
/// [`VerificationKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone, Hash, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes<T: SigType>(
    pub(crate) reddsa::VerificationKeyBytes<T::RedDSASigType>,
);

impl<T: SigType> From<[u8; 32]> for VerificationKeyBytes<T> {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes<T> {
        VerificationKeyBytes(reddsa::VerificationKeyBytes::from(bytes))
    }
}

impl<T: SigType> From<VerificationKeyBytes<T>> for [u8; 32] {
    fn from(refined: VerificationKeyBytes<T>) -> [u8; 32] {
        refined.0.into()
    }
}

/// A valid RedJubJub verification key.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// [`TryFrom<VerificationKeyBytes<T>>`] checks that the bytes canonically encode
/// a point on the curve. Small-order points, including the identity, are
/// accepted. Sapling separately rejects small-order spend authorization keys.
#[derive(PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(bound = "T: SigType"))]
pub struct VerificationKey<T: SigType>(pub(crate) reddsa::VerificationKey<T::RedDSASigType>);

impl From<jubjub::ExtendedPoint> for VerificationKey<crate::Binding> {
    /// Constructs a binding key from an existing valid Jubjub point.
    ///
    /// Retains the point and computes its canonical encoding without decoding
    /// it again. Identity and other small-order points are accepted.
    /// The point must satisfy Jubjub's curve invariants; release builds trust
    /// coordinates supplied through unchecked constructors.
    fn from(point: jubjub::ExtendedPoint) -> Self {
        Self(reddsa::VerificationKey::from(point))
    }
}

impl From<VerificationKey<SpendAuth>> for jubjub::AffinePoint {
    /// Normalizes the stored spend authorization point without decoding it.
    ///
    /// Small-order points are preserved; protocol-specific restrictions must
    /// still be checked by the caller.
    fn from(key: VerificationKey<SpendAuth>) -> Self {
        Self::from(key.0)
    }
}

impl<T: SigType> From<VerificationKey<T>> for VerificationKeyBytes<T> {
    fn from(pk: VerificationKey<T>) -> VerificationKeyBytes<T> {
        VerificationKeyBytes(pk.0.into())
    }
}

impl<T: SigType> From<VerificationKey<T>> for [u8; 32] {
    fn from(pk: VerificationKey<T>) -> [u8; 32] {
        pk.0.into()
    }
}

impl<T: SigType> TryFrom<VerificationKeyBytes<T>> for VerificationKey<T> {
    type Error = Error;

    fn try_from(bytes: VerificationKeyBytes<T>) -> Result<Self, Self::Error> {
        let reddsa_vk = reddsa::VerificationKey::try_from(bytes.0)?;
        Ok(VerificationKey(reddsa_vk))
    }
}

impl<T: SigType> TryFrom<[u8; 32]> for VerificationKey<T> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        use core::convert::TryInto;
        VerificationKeyBytes::from(bytes).try_into()
    }
}

impl VerificationKey<SpendAuth> {
    /// Randomize this verification key with the given `randomizer`.
    ///
    /// Randomization is only supported for `SpendAuth` keys.
    pub fn randomize(&self, randomizer: &Randomizer) -> VerificationKey<SpendAuth> {
        VerificationKey(self.0.randomize(randomizer))
    }
}

impl<T: SigType> VerificationKey<T> {
    /// Verify a purported `signature` over `msg` made by this verification key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), Error> {
        self.0.verify(msg, &signature.0).map_err(|e| e.into())
    }
}

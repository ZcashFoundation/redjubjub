// -*- mode: rust; -*-
//
// This file is part of reddsa.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

#![doc(html_root_url = "https://docs.rs/reddsa/0.0.0")]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

pub mod batch;
mod constants;
mod error;
pub mod frost;
mod hash;
pub mod sapling;
mod scalar_mul;
mod signature;
mod signing_key;
mod verification_key;

/// An element of the protocol's scalar field used for randomization of public and secret keys.
pub type Randomizer<S> = <S as private::Sealed<S>>::Scalar;

use hash::HStar;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

/// Abstracts over different RedJubJub parameter choices, [`Binding`]
/// and [`SpendAuth`].
///
/// As described [at the end of §5.4.6][concretereddsa] of the Zcash
/// protocol specification, the generator used in RedJubjub is left as
/// an unspecified parameter, chosen differently for each of
/// `BindingSig` and `SpendAuthSig`.
///
/// To handle this, we encode the parameter choice as a genuine type
/// parameter.
///
/// [concretereddsa]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
pub trait SigType: private::Sealed<Self> {}

/// A trait corresponding to `BindingSig` in Zcash protocols.
pub trait Binding: SigType {}

/// A trait corresponding to `SpendAuthSig` in Zcash protocols.
pub trait SpendAuth: SigType {}

pub(crate) mod private {
    use super::*;

    pub trait SealedScalar {
        fn from_bytes_wide(bytes: &[u8; 64]) -> Self;
        fn from_raw(val: [u64; 4]) -> Self;
    }

    impl SealedScalar for jubjub::Scalar {
        fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
            jubjub::Scalar::from_bytes_wide(bytes)
        }
        fn from_raw(val: [u64; 4]) -> Self {
            jubjub::Scalar::from_raw(val)
        }
    }

    pub trait Sealed<T: SigType>:
        Copy + Clone + Default + Eq + PartialEq + std::fmt::Debug
    {
        const H_STAR_PERSONALIZATION: &'static [u8; 16];
        type Scalar: group::ff::PrimeField + SealedScalar;
        type Point: group::cofactor::CofactorCurve<Scalar = Self::Scalar>
            + scalar_mul::VartimeMultiscalarMul<Scalar = Self::Scalar, Point = Self::Point>;

        fn basepoint() -> T::Point;
    }
    impl Sealed<sapling::Binding> for sapling::Binding {
        const H_STAR_PERSONALIZATION: &'static [u8; 16] = b"Zcash_RedJubjubH";
        type Point = jubjub::ExtendedPoint;
        type Scalar = jubjub::Scalar;

        fn basepoint() -> jubjub::ExtendedPoint {
            jubjub::AffinePoint::from_bytes(constants::BINDINGSIG_BASEPOINT_BYTES)
                .unwrap()
                .into()
        }
    }
    impl Sealed<sapling::SpendAuth> for sapling::SpendAuth {
        const H_STAR_PERSONALIZATION: &'static [u8; 16] = b"Zcash_RedJubjubH";
        type Point = jubjub::ExtendedPoint;
        type Scalar = jubjub::Scalar;

        fn basepoint() -> jubjub::ExtendedPoint {
            jubjub::AffinePoint::from_bytes(constants::SPENDAUTHSIG_BASEPOINT_BYTES)
                .unwrap()
                .into()
        }
    }
}

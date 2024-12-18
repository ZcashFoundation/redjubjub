// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod batch;
mod error;
pub(crate) mod signature;
mod signing_key;
mod verification_key;

use reddsa::sapling;

/// An element of the JubJub scalar field used for randomization of public and secret keys.
pub type Randomizer = reddsa::Randomizer<sapling::SpendAuth>;

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
pub trait SigType: private::Sealed {}

/// A type variable corresponding to Zcash's `BindingSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Binding {}
impl SigType for Binding {}

/// A type variable corresponding to Zcash's `SpendAuthSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpendAuth {}
impl SigType for SpendAuth {}

pub(crate) mod private {
    use super::*;
    pub trait Sealed: Copy + Clone + Eq + PartialEq + core::fmt::Debug {
        type RedDSASigType: reddsa::SigType;
    }
    impl Sealed for Binding {
        type RedDSASigType = sapling::Binding;
    }
    impl Sealed for SpendAuth {
        type RedDSASigType = sapling::SpendAuth;
    }
}

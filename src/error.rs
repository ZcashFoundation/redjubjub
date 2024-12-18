// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

#[cfg(feature = "std")]
use thiserror::Error;

/// An error related to RedJubJub signatures.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum Error {
    /// The encoding of a signing key was malformed.
    #[cfg_attr(feature = "std", error("Malformed signing key encoding."))]
    MalformedSigningKey,
    /// The encoding of a verification key was malformed.
    #[cfg_attr(feature = "std", error("Malformed verification key encoding."))]
    MalformedVerificationKey,
    /// Signature verification failed.
    #[cfg_attr(feature = "std", error("Invalid signature."))]
    InvalidSignature,
}

impl From<reddsa::Error> for Error {
    fn from(e: reddsa::Error) -> Self {
        match e {
            reddsa::Error::MalformedSigningKey => Error::MalformedSigningKey,
            reddsa::Error::MalformedVerificationKey => Error::MalformedVerificationKey,
            reddsa::Error::InvalidSignature => Error::InvalidSignature,
        }
    }
}

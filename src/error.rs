// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use thiserror::Error;

/// An error related to RedJubJub signatures.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum SignatureError {
    /// The encoding of a signing key was malformed.
    #[error("Malformed signing key encoding.")]
    MalformedSigningKey,
    /// The encoding of a verification key was malformed.
    #[error("Malformed verification key encoding.")]
    MalformedVerificationKey,
    /// Signature verification failed.
    #[error("Invalid signature.")]
    Invalid,
}

/// An error related to FROST functions.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrostError {
    /// Share verification failed.
    #[error("Share is invalid.")]
    InvalidShare,
    /// The threshold must be greater than 0.
    #[error("Threshold cannot be 0.")]
    ZeroThreshold,
    /// The number of shares must be greater than 0.
    #[error("Number of shares cannot be 0.")]
    ZeroShares,
    /// The threshold must be smaller or equal than the number of shares.
    #[error("Threshold cannot exceed numshares.")]
    ThresholdExceedShares,
    /// Share signature verification.
    #[error("Invalid signature share")]
    InvalidSignatureShare,
    /// The commitment must not be the identity.
    #[error("Commitment equals the identity.")]
    IdentiyCommitment,
    /// The shares provided must not be duplicated.
    #[error("Duplicate shares provided")]
    DuplicateShares,
    /// At least 1 share must be provided.
    #[error("No shares provided")]
    NoShares,
    /// No match in the commitment index.
    #[error("No matching commitment index")]
    NoMatchCommitment,
    /// No match in the binding.
    #[error("No matching binding")]
    NoMatchBinding,
    /// No match in the signing commitment.
    #[error("No matching signing commitment for signer")]
    NoMatchSigningCommitment,
}

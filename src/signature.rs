// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Redjubjub Signatures

use crate::SigType;

/// A RedJubJub signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature<T: SigType>(pub(crate) reddsa::Signature<T::RedDSASigType>);

impl<T: SigType> From<[u8; 64]> for Signature<T> {
    fn from(bytes: [u8; 64]) -> Signature<T> {
        Signature(reddsa::Signature::<_>::from(bytes))
    }
}

impl<T: SigType> From<Signature<T>> for [u8; 64] {
    fn from(sig: Signature<T>) -> [u8; 64] {
        sig.0.into()
    }
}

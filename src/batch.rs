// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Performs batch RedJubjub signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!

use rand_core::{CryptoRng, RngCore};

use crate::*;

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
#[derive(Clone, Debug)]
pub struct Item(reddsa::batch::Item<sapling::SpendAuth, sapling::Binding>);

impl<'msg, M: AsRef<[u8]>>
    From<(
        VerificationKeyBytes<SpendAuth>,
        Signature<SpendAuth>,
        &'msg M,
    )> for Item
{
    fn from(
        (vk_bytes, sig, msg): (
            VerificationKeyBytes<SpendAuth>,
            Signature<SpendAuth>,
            &'msg M,
        ),
    ) -> Self {
        Self(reddsa::batch::Item::from_spendauth(vk_bytes.0, sig.0, msg))
    }
}

impl<'msg, M: AsRef<[u8]>> From<(VerificationKeyBytes<Binding>, Signature<Binding>, &'msg M)>
    for Item
{
    fn from(
        (vk_bytes, sig, msg): (VerificationKeyBytes<Binding>, Signature<Binding>, &'msg M),
    ) -> Self {
        Self(reddsa::batch::Item::from_binding(vk_bytes.0, sig.0, msg))
    }
}

impl Item {
    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing fallback
    /// logic when batch verification fails. In contrast to
    /// [`VerificationKey::verify`](crate::VerificationKey::verify), which requires
    /// borrowing the message data, the `Item` type is unlinked from the lifetime of
    /// the message.
    #[allow(non_snake_case)]
    pub fn verify_single(self) -> Result<(), Error> {
        self.0.verify_single().map_err(|e| e.into())
    }
}

#[derive(Default)]
/// A batch verification context.
pub struct Verifier(reddsa::batch::Verifier<sapling::SpendAuth, sapling::Binding>);

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier {
        Verifier::default()
    }

    /// Queue an Item for verification.
    pub fn queue<I: Into<Item>>(&mut self, item: I) {
        self.0.queue(item.into().0);
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// The batch verification equation is:
    ///
    /// h_G * ( -[sum(z_i * s_i)]P_G + sum(\[z_i\]R_i) + sum([z_i * c_i]VK_i) ) = 0_G
    ///
    /// as given in https://zips.z.cash/protocol/protocol.pdf#reddsabatchvalidate
    /// (the terms are split out so that we can use multiscalar multiplication speedups).
    ///
    /// where for each signature i,
    /// - VK_i is the verification key;
    /// - R_i is the signature's R value;
    /// - s_i is the signature's s value;
    /// - c_i is the hash of the message and other data;
    /// - z_i is a random 128-bit Scalar;
    /// - h_G is the cofactor of the group;
    /// - P_G is the generator of the subgroup;
    ///
    /// Since RedJubjub uses different subgroups for different types
    /// of signatures, SpendAuth's and Binding's, we need to have yet
    /// another point and associated scalar accumulator for all the
    /// signatures of each type in our batch, but we can still
    /// amortize computation nicely in one multiscalar multiplication:
    ///
    /// h_G * ( [-sum(z_i * s_i): i_type == SpendAuth]P_SpendAuth + [-sum(z_i * s_i): i_type == Binding]P_Binding + sum(\[z_i\]R_i) + sum([z_i * c_i]VK_i) ) = 0_G
    ///
    /// As follows elliptic curve scalar multiplication convention,
    /// scalar variables are lowercase and group point variables
    /// are uppercase. This does not exactly match the RedDSA
    /// notation in the [protocol specification §B.1][ps].
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, rng: R) -> Result<(), Error> {
        self.0.verify(rng).map_err(|e| e.into())
    }
}

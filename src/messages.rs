//! The FROST communication messages specified in [RFC-001]
//!
//! [RFC-001]: https://github.com/ZcashFoundation/redjubjub/blob/main/rfcs/0001-messages.md
#![allow(dead_code)]

use jubjub::{AffinePoint, Scalar};

use crate::{verification_key::VerificationKey, SpendAuth};

use std::collections::HashMap;

mod constants;
mod validate;

/// The data required to serialize a frost message.
pub struct Message {
    header: Header,
    payload: Payload,
}

/// The data required to serialize the common header fields for every message.
///
/// Note: the `msg_type` is derived from the `payload` enum variant.
pub struct Header {
    version: MsgVersion,
    sender: ParticipantId,
    receiver: ParticipantId,
}

/// The data required to serialize the payload for a message.
pub enum Payload {
    SharePackage(SharePackage),
    SigningCommitments(SigningCommitments),
    SigningPackage(SigningPackage),
    SignatureShare(SignatureShare),
    AggregateSignature(AggregateSignature),
}

/// The numeric values used to identify each `Payload` variant during serialization.
#[repr(u8)]
#[non_exhaustive]
enum MsgType {
    SharePackage,
    SigningCommitments,
    SigningPackage,
    SignatureShare,
    AggregateSignature,
}

/// The numeric values used to identify the protocol version during serialization.
#[derive(PartialEq)]
pub struct MsgVersion(u8);

/// The numeric values used to identify each participant during serialization.
///
/// In the `frost` module, participant ID `0` should be invalid.
/// But in serialization, we want participants to be indexed from `0..n`,
/// where `n` is the number of participants.
/// This helps us look up their shares and commitments in serialized arrays.
/// So in serialization, we assign the dealer and aggregator the highest IDs,
/// and mark those IDs as invalid for signers.
///
/// "When performing Shamir secret sharing, a polynomial `f(x)` is used to generate
/// each party’s share of the secret. The actual secret is `f(0)` and the party with
/// ID `i` will be given a share with value `f(i)`.
/// Since a DKG may be implemented in the future, we recommend that the ID `0` be declared invalid."
/// https://raw.githubusercontent.com/ZcashFoundation/redjubjub/main/zcash-frost-audit-report-20210323.pdf#d
#[derive(PartialEq, PartialOrd)]
pub enum ParticipantId {
    /// A serialized participant ID for a signer.
    ///
    /// Must be less than or equal to `MAX_SIGNER_PARTICIPANT_ID`.
    Signer(u8),
    /// The fixed participant ID for the dealer.
    Dealer,
    /// The fixed participant ID for the aggregator.
    Aggregator,
}

/// The data required to serialize `frost::SharePackage`.
///
/// The dealer sends this message to each signer for this round.
/// With this, the signer should be able to build a `SharePackage` and use
/// the `sign()` function.
///
/// Note: `frost::SharePackage.public` can be calculated from `secret_share`.
pub struct SharePackage {
    /// This participant's secret key share: `frost::SharePackage.share.value`.
    secret_share: Scalar,
    /// Commitment for the signer as a single jubjub::AffinePoint.
    /// A set of commitments to the coefficients (which themselves are scalars)
    /// for a secret polynomial _f_: `frost::SharePackage.share.commitment`
    share_commitment: Vec<AffinePoint>,
    /// The public signing key that represents the entire group:
    /// `frost::SharePackage.group_public`.
    group_public: VerificationKey<SpendAuth>,
}

/// The data required to serialize `frost::SigningCommitments`.
///
/// Each signer must send this message to the aggregator.
/// A signing commitment from the first round of the signing protocol.
pub struct SigningCommitments {
    /// The hiding point: `frost::SigningCommitments.hiding`
    hiding: AffinePoint,
    /// The binding point: `frost::SigningCommitments.binding`
    binding: AffinePoint,
}

/// The data required to serialize `frost::SigningPackage`.
///
/// The aggregator decides what message is going to be signed and
/// sends it to each signer with all the commitments collected.
pub struct SigningPackage {
    /// The message to be signed: `frost::SigningPackage.message`
    message: Vec<u8>,
    /// The collected commitments for each signer as a hashmap of
    /// unique participant identifiers: `frost::SigningPackage.signing_commitments`
    ///
    /// Signing packages that contain duplicate or missing `ParticipantID`s are invalid.
    signing_commitments: HashMap<ParticipantId, SigningCommitments>,
}

/// The data required to serialize `frost::SignatureShare`.
///
/// Each signer sends their signatures to the aggregator who is going to collect them
/// and generate a final spend signature.
pub struct SignatureShare {
    /// This participant's signature over the message: `frost::SignatureShare.signature`
    signature: Scalar,
}

/// The data required to serialize a successful output from `frost::aggregate()`.
///
/// The final signature is broadcasted by the aggregator to all signers.
pub struct AggregateSignature {
    /// The aggregated group commitment: `Signature<SpendAuth>.r_bytes` returned by `frost::aggregate`
    group_commitment: AffinePoint,
    /// A plain Schnorr signature created by summing all the signature shares:
    /// `Signature<SpendAuth>.s_bytes` returned by `frost::aggregate`
    schnorr_signature: Scalar,
}

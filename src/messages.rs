//! The FROST communication messages specified in [RFC-001]
//!
//! [RFC-001]: https://github.com/ZcashFoundation/redjubjub/blob/main/rfcs/0001-messages.md
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use crate::{verification_key::VerificationKey, SpendAuth};

use std::collections::HashMap;

mod constants;
mod validate;

/// Define our own `Secret` type instead of using `frost::Secret`.
///
/// The serialization design specifies that `Secret` is a `Scalar` that uses:
/// "a 32-byte little-endian canonical representation".
#[derive(Serialize, Deserialize, Debug)]
pub struct Secret([u8; 32]);

/// Define our own `Commitment` type instead of using `frost::Commitment`.
///
/// The serialization design specifies that `Commitment` is a `AffinePoint` that uses:
/// "a 32-byte little-endian canonical representation".
#[derive(Serialize, Deserialize, Debug)]
pub struct Commitment([u8; 32]);

/// Define our own `GroupCommitment` type instead of using `frost::GroupCommitment`.
///
/// The serialization design specifies that `GroupCommitment` is a `AffinePoint` that uses:
/// "a 32-byte little-endian canonical representation".
#[derive(Serialize, Deserialize, Debug)]
pub struct GroupCommitment([u8; 32]);

/// Define our own `SignatureResponse` type instead of using `frost::SignatureResponse`.
///
/// The serialization design specifies that `SignatureResponse` is a `Scalar` that uses:
/// "a 32-byte little-endian canonical representation".
#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureResponse([u8; 32]);


/// The data required to serialize a frost message.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    header: Header,
    payload: Payload,
}

/// The data required to serialize the common header fields for every message.
///
/// Note: the `msg_type` is derived from the `payload` enum variant.
#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    version: MsgVersion,
    sender: ParticipantId,
    receiver: ParticipantId,
}

/// The data required to serialize the payload for a message.
#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Serialize, Deserialize, Debug)]
enum MsgType {
    SharePackage,
    SigningCommitments,
    SigningPackage,
    SignatureShare,
    AggregateSignature,
}

/// The numeric values used to identify the protocol version during serialization.
#[derive(PartialEq, Serialize, Deserialize, Debug)]
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
#[derive(PartialEq, Eq, Hash, PartialOrd, Serialize, Deserialize, Debug)]
pub enum ParticipantId {
    /// A serialized participant ID for a signer.
    ///
    /// Must be less than or equal to `MAX_SIGNER_PARTICIPANT_ID`.
    Signer(u64),
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
#[derive(Serialize, Deserialize, Debug)]
pub struct SharePackage {
    /// The public signing key that represents the entire group:
    /// `frost::SharePackage.group_public`.
    group_public: VerificationKey<SpendAuth>,
    /// This participant's secret key share: `frost::SharePackage.share.value`.
    secret_share: Secret,
    /// The commitments to the coefficients for our secret polynomial _f_,
    /// used to generate participants' key shares. Participants use these to perform
    /// verifiable secret sharing.
    share_commitment: Vec<Commitment>,
}

/// The data required to serialize `frost::SigningCommitments`.
///
/// Each signer must send this message to the aggregator.
/// A signing commitment from the first round of the signing protocol.
#[derive(Serialize, Deserialize, Debug)]
pub struct SigningCommitments {
    /// The hiding point: `frost::SigningCommitments.hiding`
    hiding: Commitment,
    /// The binding point: `frost::SigningCommitments.binding`
    binding: Commitment,
}

/// The data required to serialize `frost::SigningPackage`.
///
/// The aggregator decides what message is going to be signed and
/// sends it to each signer with all the commitments collected.
#[derive(Serialize, Deserialize, Debug)]
pub struct SigningPackage {
    /// The collected commitments for each signer as a hashmap of
    /// unique participant identifiers: `frost::SigningPackage.signing_commitments`
    ///
    /// Signing packages that contain duplicate or missing `ParticipantID`s are invalid.
    signing_commitments: HashMap<ParticipantId, SigningCommitments>,
    /// The message to be signed: `frost::SigningPackage.message`.
    ///
    /// Each signer should perform protocol-specific verification on the message.
    message: Vec<u8>,
}

/// The data required to serialize `frost::SignatureShare`.
///
/// Each signer sends their signatures to the aggregator who is going to collect them
/// and generate a final spend signature.
#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShare {
    /// This participant's signature over the message: `frost::SignatureShare.signature`
    signature: SignatureResponse,
}

/// The data required to serialize a successful output from `frost::aggregate()`.
///
/// The final signature is broadcasted by the aggregator to all signers.
#[derive(Serialize, Deserialize, Debug)]
pub struct AggregateSignature {
    /// The aggregated group commitment: `Signature<SpendAuth>.r_bytes` returned by `frost::aggregate`
    group_commitment: GroupCommitment,
    /// A plain Schnorr signature created by summing all the signature shares:
    /// `Signature<SpendAuth>.s_bytes` returned by `frost::aggregate`
    schnorr_signature: SignatureResponse,
}

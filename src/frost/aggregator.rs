use thiserror::Error;

use super::{signer, SigningParticipants};
use crate::{Signature, SpendAuth};

/// An error arising from the aggregator's part of the signing protocol.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("The selected set of signing participants was invalid.")]
    InvalidSigners,
}

pub struct AwaitingCommitmentShares {
    // ??
}

/// Begin the signing protocol with the given subset of participants.
///
/// This API does not handle sending the message to be signed to those
/// participants; they begin with
/// [`SecretShare::begin_sign`](super::SecretShare::begin_sign).
pub fn begin_sign(participants: SigningParticipants) -> AwaitingCommitmentShares {
    unimplemented!();
}

pub struct CommitmentShareSet {
    // ??
}

pub struct Commitment {
    // ???
}

pub struct ResponseShareSet {
    // ??
}

pub struct AwaitingResponseShares {
    // ???
}

impl AwaitingCommitmentShares {
    pub fn recv(
        self,
        shares: CommitmentShareSet,
    ) -> Result<(AwaitingResponseShares, Commitment), Error> {
        unimplemented!();
    }
}

impl AwaitingResponseShares {
    pub fn recv(self, responses: ResponseShareSet) -> Result<Signature<SpendAuth>, Error> {
        unimplemented!();
    }
}

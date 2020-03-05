use thiserror::Error;

use super::{signer, SigningParticipants};
use crate::{Signature, SpendAuth};

/// An error arising from the aggregator's part of the signing protocol.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("The selected set of signing participants was invalid.")]
    InvalidSigners,
}

/// An intermediate protocol state, awaiting [`signer::CommitmentShare`]s from
/// each [`SecretShare`](super::SecretShare) holder.
pub struct AwaitingCommitmentShares {
    // ??
}

/// Begin the signing protocol with the given subset of participants.
///
/// This API does not handle sending the message to be signed to those
/// participants; they begin with
/// [`SecretShare::begin_sign`](super::SecretShare::begin_sign), which assumes
/// knowledge of the message and the signing participants. This coordination is
/// left to the user of the library, since it is likely to be
/// application-dependent.
pub fn begin_sign(_participants: SigningParticipants) -> AwaitingCommitmentShares {
    unimplemented!();
}

/// A message containing the aggregation of each signer's [`signer::CommitmentShare`].
#[derive(Clone, Debug)]
pub struct Commitment {
    // ???
}

impl AwaitingCommitmentShares {
    /// Continue the signing protocol after receiving each signer's
    /// [`signer::CommitmentShare`].
    ///
    /// This returns the next state, [`AwaitingResponseShares`], and a
    /// [`Commitment`] which should be sent to each signer.
    pub fn recv(
        self,
        _shares: impl Iterator<Item = signer::CommitmentShare>,
    ) -> Result<(AwaitingResponseShares, Commitment), Error> {
        unimplemented!();
    }
}

/// An intermediate protocol state, awaiting [`signer::ResponseShare`]s from each
/// [`SecretShare`](super::SecretShare) holder.
pub struct AwaitingResponseShares {
    // ???
}

impl AwaitingResponseShares {
    /// Finish the signing protocol once [`signer::ResponseShare`]s have been
    /// received from all signers, producing a signature.
    pub fn recv(
        self,
        _responses: impl Iterator<Item = signer::ResponseShare>,
    ) -> Result<Signature<SpendAuth>, Error> {
        unimplemented!();
    }
}

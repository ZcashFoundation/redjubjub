//
// (1.1 generate randomness)
// (1.2 commit to it)
//                     send commitment
// ---------------------------------------->
//                     get all commitments
// <----------------------------------------
// (2.1 gen share for each counterparty)
//                     send shares to each counterparty
// ---------------------------------------->
//                     get shares from each counterparty
// <----------------------------------------
// (2.2 verify shares from each counterparty)
// (2.3 compute secret share)
// (2.4 compute public share, public key)
//
// return (secret share, public share, public key)
//

use thiserror::Error;

use super::{Config, SecretShare};

/// An error arising from the key generation protocol.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("Invalid configuration.")]
    InvalidConfig,
    #[error("Wrong commitment data was received.")]
    WrongCommitments,
    #[error("Wrong share data was received.")]
    WrongShares,
    #[error("Counterparty {0} sent an invalid share.")]
    InvalidShare(usize),
}

/// A message containing a commitment to a share holder's randomness, broadcast in
/// the first round of the protocol.
#[derive(Debug, Clone)]
pub struct Commitment {
    id: usize,
}

/// An intermediate protocol state, awaiting [`keygen::Commitment`](Commitment)s
/// from each counterparty.
pub struct AwaitingCommitments {
    // ???
}

/// A message containing a key generation share, broadcast in the second round of
/// the protocol.
#[derive(Debug, Clone)]
pub struct Share {
    // ??
}

/// An intermediate protocol state, awaiting [`keygen::Share`](Share)s from each
/// counterparty.
pub struct AwaitingShares {
    // ???
}

/// Begin the key generation protocol with the given [`Config`].
///
/// This function is called by each participant (future key share holder). It
/// returns the next state, [`AwaitingCommitments`], and a [`Commitment`] which
/// should be sent to each other participant in the protocol.
///
/// The coordination of who those participants are, and how they agree on the key
/// generation parameters, is left to the user of the library, as it is likely
/// application-dependent.
pub fn begin_keygen(_config: Config) -> (AwaitingCommitments, Commitment) {
    unimplemented!();
}

impl AwaitingCommitments {
    /// Continue the key generation protocol once [`Commitment`]s have been
    /// received from all counterparties.
    ///
    /// This returns the next state, [`AwaitingShares`], and a [`keygen::Share`](Share)
    /// which should be sent to each other participant in the protocol.
    pub fn recv(
        self,
        _commitments: impl Iterator<Item = Commitment>,
    ) -> Result<(AwaitingShares, Share), Error> {
        unimplemented!();
    }
}

impl AwaitingShares {
    /// Finish the key generation protocol once [`keygen::Share`](Share)s have been
    /// received from all counterparties.
    pub fn recv(self, _shares: impl Iterator<Item = Share>) -> Result<SecretShare, Error> {
        unimplemented!();
    }
}

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

/// An error arising from the DKG protocol.
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

#[derive(Debug, Clone)]
pub struct Commitment {
    id: usize,
}

pub struct AwaitingCommitments {
    // ???
}

/// XXX rename this? it's only short-lived
#[derive(Debug, Clone)]
pub struct KeygenShare {
    // ??
}

pub struct AwaitingShares {
    // ???
}

pub fn begin_keygen(_config: Config) -> (AwaitingCommitments, Commitment) {
    unimplemented!();
}

impl AwaitingCommitments {
    pub fn recv(
        self,
        _commitments: impl Iterator<Item = Commitment>,
    ) -> Result<(AwaitingShares, KeygenShare), Error> {
        unimplemented!();
    }
}

impl AwaitingShares {
    pub fn recv(self, _shares: impl Iterator<Item = KeygenShare>) -> Result<SecretShare, Error> {
        unimplemented!();
    }
}

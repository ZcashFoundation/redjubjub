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

pub struct Commitment {
    id: usize,
}

pub struct CommitmentSet {
    // holds 1 per party
}

impl CommitmentSet {
    pub fn collect(
        config: &Config,
        commitments: impl Iterator<Item = Commitment>,
    ) -> Result<Self, Error> {
        unimplemented!();
    }
}

pub struct AwaitingCommitments {
    // ???
}

/// XXX rename this? it's only short-lived
pub struct KeygenShare {
    // ??
}

pub struct KeygenShareSet {
    // ???
}

impl KeygenShareSet {
    pub fn collect(
        config: &Config,
        commitments: impl Iterator<Item = KeygenShare>,
    ) -> Result<Self, Error> {
        unimplemented!();
    }
}

pub struct AwaitingShares {
    // ???
}

pub fn begin_keygen(config: Config) -> (AwaitingCommitments, Commitment) {
    unimplemented!();
}

impl AwaitingCommitments {
    pub fn recv(self, commitments: CommitmentSet) -> (AwaitingShares, KeygenShare) {
        unimplemented!();
    }
}

impl AwaitingShares {
    pub fn recv(self, shares: KeygenShareSet) -> Result<SecretShare, Error> {
        unimplemented!();
    }
}

// [signers]                                    aggregator
//
//                                              start
//                                    choose subset S
//                                     1.1 send (S,m)
// <-------------------------------------------------
// (1.2 generate nonce)
// (1.3 generate commitment)
//             1.4 send nonce commitment
// ------------------------------------------------->
//                   2.1 aggregate commitments into R
//               2.2 send R [m,S already sent]
// <-------------------------------------------------
// (2.3 validate m)
// (2.4 compute challenge)
// (2.5 compute response z_i)
//                     2.6 send z_i
// ------------------------------------------------->
//                                 2.7.a verify z_i's
//                       2.7.b aggregate z_i's into z
//  2.7.c compute signature (R,z) [change from paper]

use thiserror::Error;

use super::{aggregator, SecretShare, SigningParticipants};

/// An error arising from the signers' part of the signing protocol.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("The selected set of signing participants was invalid.")]
    InvalidSigners,
}

impl SecretShare {
    /// Begin the distributed signing protocol with this share.
    ///
    /// The state machine for the signing protocol is encoded into Rust types.
    /// These states hold a mutable borrow of the `SecretShare` so that the
    /// borrow checker enforces at compile time that only one run of the protocol
    /// can be performed at a time, and multiple concurrent runs of the protocol
    /// with the same secret are not possible. This prevents an attack of
    /// Drijvers et al.
    pub fn begin_sign<'ss, M: AsRef<[u8]>>(
        &'ss mut self,
        _msg: M,
        _participants: SigningParticipants,
    ) -> Result<(AwaitingCommitment<'ss>, CommitmentShare), Error> {
        unimplemented!()
    }
}

/// A message containing a single participant's share of the commitment component
/// of a signature, sent to the aggregator in the first round of the signing
/// protocol.
#[derive(Clone, Debug)]
pub struct CommitmentShare {
    // ???
}

/// An intermediate protocol state, awaiting an [`aggregator::Commitment`].
///
/// The `'ss` lifetime is the lifetime of the [`SecretShare`] used for signing.
/// This struct holds a mutable reference to the share to ensure that only one
/// signing operation can be performed at a time, using the borrow checker to
/// prove that the attack of Drijvers et al. is infeasible.
pub struct AwaitingCommitment<'ss> {
    _ss: &'ss mut SecretShare,
}

impl<'ss> AwaitingCommitment<'ss> {
    /// Continue the signing protocol after receiving the
    /// [`aggregator::Commitment`] that combines the commitments from each
    /// participant.
    ///
    /// This returns the participant's [`ResponseShare`], which is sent to the
    /// aggregator, who produces the final [`Signature`](crate::Signature).
    ///
    /// Note that because this function consumes `self`, which holds a `&mut
    /// SecretShare`, it releases the lock on the [`SecretShare`] used in the
    /// signing protocol.
    pub fn recv(self, _commitment: aggregator::Commitment) -> ResponseShare {
        unimplemented!();
    }
}

/// A message containg a single participant's share of the response component of
/// a signature, sent to the aggregator in the second round of the signing
/// protocol.
#[derive(Clone, Debug)]
pub struct ResponseShare {
    // ???
}
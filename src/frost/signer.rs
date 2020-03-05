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
    /// The state machine for the signing protocol is encoded into Rust types. These
    /// states hold a mutable reference to the `SecretShare`. Since only one mutable
    /// reference to the same object can exist at a time, one run of the signing
    /// protocol can be performed at a time.
    ///
    /// This means we can leverage the borrow checker to statically prove that the
    /// attack of [Drijvers et al][drijvers], which relies on parallel runs of the
    /// signing protocol, is infeasible to perform on *any* compilable use of this
    /// library's API. More information on that attack and its implications for FROST
    /// can be found [in this CFRG posting][cfrg] or in the [FROST paper][frost_paper].
    ///
    /// [drijvers]: https://eprint.iacr.org/2018/417.pdf
    /// [cfrg]: https://mailarchive.ietf.org/arch/msg/cfrg/USYUleqIjS-mq93oGPSV-Tu0ndQ/
    /// [frost_paper]: https://crysp.uwaterloo.ca/software/frost/
    pub fn begin_sign<'ss, M: AsRef<[u8]>>(
        &'ss mut self,
        _msg: M,
        _participants: SigningParticipants,
    ) -> Result<(AwaitingCommitment<'ss>, CommitmentShare), Error> {
        // dummy code: ensures that we can hand self to AwaitingCommitment.
        Ok((AwaitingCommitment { _ss: self }, CommitmentShare {}))
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
/// signing operation can be performed at a time.
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

//! Validation rules specified in [RFC-001#rules]
//!
//! [RFC-001#rules]: https://github.com/ZcashFoundation/redjubjub/blob/main/rfcs/0001-messages.md#rules

use super::constants::{
    BASIC_FROST_SERIALIZATION, MAX_PROTOCOL_MESSAGE_LEN, MAX_SIGNER_PARTICIPANT_ID,
};
use super::*;

use thiserror::Error;

pub trait Validate {
    fn validate(&self) -> Result<&Self, MsgErr>;
}

impl Validate for Message {
    fn validate(&self) -> Result<&Self, MsgErr> {
        match self.payload {
            Payload::SharePackage(_) => {
                if self.header.sender != ParticipantId::Dealer {
                    return Err(MsgErr::SenderMustBeDealer);
                }
                if self.header.receiver <= ParticipantId::Signer(MAX_SIGNER_PARTICIPANT_ID) {
                    return Err(MsgErr::ReceiverMustBeSigner);
                }
            }
            Payload::SigningCommitments(_) => {
                if self.header.sender <= ParticipantId::Signer(MAX_SIGNER_PARTICIPANT_ID) {
                    return Err(MsgErr::SenderMustBeSigner);
                }
                if self.header.receiver != ParticipantId::Aggregator {
                    return Err(MsgErr::ReceiverMustBeAggergator);
                }
            }
            Payload::SigningPackage(_) => {
                if self.header.sender != ParticipantId::Aggregator {
                    return Err(MsgErr::SenderMustBeAggregator);
                }
                if self.header.receiver <= ParticipantId::Signer(MAX_SIGNER_PARTICIPANT_ID) {
                    return Err(MsgErr::ReceiverMustBeSigner);
                }
            }
            Payload::SignatureShare(_) => {
                if self.header.sender <= ParticipantId::Signer(MAX_SIGNER_PARTICIPANT_ID) {
                    return Err(MsgErr::SenderMustBeSigner);
                }
                if self.header.receiver != ParticipantId::Aggregator {
                    return Err(MsgErr::ReceiverMustBeAggergator);
                }
            }
            Payload::AggregateSignature(_) => {
                if self.header.sender != ParticipantId::Aggregator {
                    return Err(MsgErr::SenderMustBeAggregator);
                }
                if self.header.receiver <= ParticipantId::Signer(MAX_SIGNER_PARTICIPANT_ID) {
                    return Err(MsgErr::ReceiverMustBeSigner);
                }
            }
        }

        Ok(self)
    }
}

impl Validate for Header {
    fn validate(&self) -> Result<&Self, MsgErr> {
        // Validate the message version.
        // By now we only have 1 valid version so we compare against that.
        if self.version != BASIC_FROST_SERIALIZATION {
            return Err(MsgErr::WrongVersion);
        }

        // Make sure the sender and the receiver are not the same.
        if self.sender == self.receiver {
            return Err(MsgErr::SameSenderAndReceiver);
        }
        Ok(self)
    }
}

impl Validate for Payload {
    fn validate(&self) -> Result<&Self, MsgErr> {
        match self {
            Payload::SharePackage(_) => {}
            Payload::SigningCommitments(_) => {}
            Payload::SigningPackage(signing_package) => {
                if signing_package.message.len() > MAX_PROTOCOL_MESSAGE_LEN {
                    return Err(MsgErr::MsgTooBig);
                }
            }
            Payload::SignatureShare(_) => {}
            Payload::AggregateSignature(_) => {}
        }

        Ok(self)
    }
}

/// The error a message can produce if it fails validation.
#[derive(Error, Debug)]
pub enum MsgErr {
    #[error("wrong version number")]
    WrongVersion,
    #[error("sender and receiver are the same")]
    SameSenderAndReceiver,
    #[error("the sender of this message must be the dealer")]
    SenderMustBeDealer,
    #[error("the receiver of this message must be a signer")]
    ReceiverMustBeSigner,
    #[error("the sender of this message must be a signer")]
    SenderMustBeSigner,
    #[error("the receiver of this message must be the aggregator")]
    ReceiverMustBeAggergator,
    #[error("the sender of this message must be the aggregator")]
    SenderMustBeAggregator,
    #[error("the message is too big")]
    MsgTooBig,
}

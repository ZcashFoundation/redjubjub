//! Definitions of constants.

use super::MsgVersion;

/// The first version of FROST messages
pub const BASIC_FROST_SERIALIZATION: MsgVersion = MsgVersion(0);

/// The fixed participant ID for the dealer.
pub const DEALER_PARTICIPANT_ID: u8 = u8::MAX - 1;

/// The fixed participant ID for the aggregator.
pub const AGGREGATOR_PARTICIPANT_ID: u8 = u8::MAX;

/// The maximum `ParticipantId::Signer` in this serialization format.
///
/// We reserve two participant IDs for the dealer and aggregator.
pub const MAX_SIGNER_PARTICIPANT_ID: u8 = u8::MAX - 2;

/// The maximum number of signers
///
/// `MAX_SIGNER_PARTICIPANT_ID` is 253, but the maximum number of signers is actually 254.
/// (We reserve 2/256 IDs for the dealer and aggregator, leaving 254 valid IDs.)
pub const MAX_SIGNERS: u8 = MAX_SIGNER_PARTICIPANT_ID + 1;

/// The maximum length of a Zcash message, in bytes.
pub const ZCASH_MAX_PROTOCOL_MESSAGE_LEN: usize = 2 * 1024 * 1024;

/// The minimum number of signers of any FROST setup.
pub const MIN_SIGNERS: usize = 2;

/// The minimum number of signers that must sign.
pub const MIN_THRESHOLD: usize = 2;

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

/// The maximum length of a Zcash message, in bytes.
///
/// This value is used to calculate safe preallocation limits for some types
pub const MAX_PROTOCOL_MESSAGE_LEN: usize = 2 * 1024 * 1024;

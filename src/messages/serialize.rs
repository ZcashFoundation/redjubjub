//! Serialization rules specified in [RFC-001#serializationdeserialization]
//!
//! We automatically serialize and deserialize using serde derivations where possible.
//! Sometimes we need to implement ourselves, this file holds that code.
//!
//! [RFC-001#rules]: https://github.com/ZcashFoundation/redjubjub/blob/main/rfcs/0001-messages.md#serializationdeserialization

use serde::ser::{Serialize, Serializer};

use serde::de::{self, Deserialize, Deserializer, Visitor};

use super::constants::{AGGREGATOR_PARTICIPANT_ID, DEALER_PARTICIPANT_ID};
use super::*;

use std::fmt;

impl Serialize for ParticipantId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ParticipantId::Signer(id) => serializer.serialize_u8(id),
            ParticipantId::Dealer => serializer.serialize_u8(DEALER_PARTICIPANT_ID),
            ParticipantId::Aggregator => serializer.serialize_u8(AGGREGATOR_PARTICIPANT_ID),
        }
    }
}

struct ParticipantIdVisitor;

impl<'de> Visitor<'de> for ParticipantIdVisitor {
    type Value = ParticipantId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .write_str(format!("an integer between {} and {}", std::u8::MIN, std::u8::MAX).as_str())
    }

    // We need to use u64 instead of u8 here because the JSON deserialized will call
    // `visit_u64` for any unsigned int:
    // https://serde.rs/impl-deserialize.html#driving-a-visitor
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value == DEALER_PARTICIPANT_ID as u64 {
            return Ok(ParticipantId::Dealer);
        } else if value == AGGREGATOR_PARTICIPANT_ID as u64 {
            return Ok(ParticipantId::Aggregator);
        } else {
            return Ok(ParticipantId::Signer(value as u8));
        }
    }
}

impl<'de> Deserialize<'de> for ParticipantId {
    fn deserialize<D>(deserializer: D) -> Result<ParticipantId, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(ParticipantIdVisitor)
    }
}

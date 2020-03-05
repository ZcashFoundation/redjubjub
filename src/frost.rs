//! An implementation of FROST (Flexible Round-Optimized Schnorr Threshold)
//! signatures.
//!
//! > **WARNING**: The implementation in this submodule is unstable and subject to
//! > revision. It is not covered by the crate's semver guarantees and should not
//! > be deployed without consultation from the FROST authors!
//!
//! This module contains an implementation of both distributed key generation and
//! threshold signing. Each protocol is implemented using session types to have
//! compile-time checks that protocol steps are executed in the correct order.
//!
//! The states and messages for each protocol are contained in this module's
//! submodules. The distributed key generation protocol is run by the share
//! holders. Its entrypoint is [`SecretShare::begin_keygen`]. The signing protocol is
//! coördinated by an untrusted aggregator. This can be one of the share holders,
//! but it is represented seperately because it could be a third party. The
//! entrypoint for the aggregator's part of the signing protocol is
//! [`aggregator::begin_sign`], and the entrypoint for the share holders' part of
//! the signing protocol is [`SecretShare::begin_sign`].
//!
//! This implementation tries to be *unopinionated* about the choice of transport
//! or the programming model (synchronous/asynchronous) used to wait for
//! messages. Instead, each protocol state has a `recv` method that consumes the
//! current state and inbound message(s) from the counterparties, and produces
//! the next state and outbound message(s) to be sent to the counterparties.
//! It is the responsibility of the user of this module to handle
//! how those messages are actually delivered.

mod config;
mod share;

/// States and messages for the untrusted aggregator who coördinates the signing
/// protocol.
pub mod aggregator;
/// States and messages for the distributed key generation protocol.
pub mod keygen;
/// States and messages for the signers who participate in the signing protocol.
pub mod signer;

pub use config::Config;
pub use share::SecretShare;

/// A list of participants for a particular run of the threshold signing protocol.
pub type SigningParticipants = Vec<usize>;

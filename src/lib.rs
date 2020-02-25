#![doc(html_root_url = "https://docs.rs/redjubjub/0.1.1")]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

mod constants;
mod error;
mod hash;
mod public_key;
mod secret_key;
mod signature;

/// An element of the JubJub scalar field used for randomization of public and secret keys.
pub type Randomizer = jubjub::Fr;

/// A better name than Fr.
// XXX-jubjub: upstream this name
type Scalar = jubjub::Fr;

use hash::{Blake2b512, HStar};

#[cfg(feature = "blake2b_simd")]
pub use hash::StdBlake2b512;

pub use error::Error;
pub use public_key::{PublicKey, PublicKeyBytes};
pub use secret_key::SecretKey;
pub use signature::Signature;

/// Abstracts over different RedJubJub parameter choices, [`Binding`]
/// and [`SpendAuth`].
///
/// As described [at the end of §5.4.6][concretereddsa] of the Zcash
/// protocol specification, the generator used in RedJubjub is left as
/// an unspecified parameter, chosen differently for each of
/// `BindingSig` and `SpendAuthSig`.
///
/// To handle this, we encode the parameter choice as a genuine type
/// parameter.
///
/// [concretereddsa]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
pub trait SigType: private::Sealed {}

/// A type variable corresponding to Zcash's `BindingSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Binding {}
impl SigType for Binding {}

/// A type variable corresponding to Zcash's `SpendAuthSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpendAuth {}
impl SigType for SpendAuth {}

pub(crate) mod private {
    use super::*;
    pub trait Sealed: Copy + Clone + Eq + PartialEq + std::fmt::Debug {
        fn basepoint() -> jubjub::ExtendedPoint;
    }
    impl Sealed for Binding {
        fn basepoint() -> jubjub::ExtendedPoint {
            jubjub::AffinePoint::from_bytes(constants::BINDINGSIG_BASEPOINT_BYTES)
                .unwrap()
                .into()
        }
    }
    impl Sealed for SpendAuth {
        fn basepoint() -> jubjub::ExtendedPoint {
            jubjub::AffinePoint::from_bytes(constants::SPENDAUTHSIG_BASEPOINT_BYTES)
                .unwrap()
                .into()
        }
    }
}

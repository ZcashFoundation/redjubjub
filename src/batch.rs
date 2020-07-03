//! Performs batch RedJubjub signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!

use std::convert::TryFrom;

use jubjub::*;
use rand_core::{CryptoRng, RngCore};

use crate::{private::Sealed, scalar_mul::VartimeMultiscalarMul, *};

// Shim to generate a random 128bit value in a [u64; 4], without
// importing `rand`.
fn gen_128_bits<R: RngCore + CryptoRng>(mut rng: R) -> [u64; 4] {
    let mut bytes = [0u64; 4];
    bytes[0] = rng.next_u64();
    bytes[1] = rng.next_u64();
    bytes
}

enum Inner {
    SpendAuth {
        vk_bytes: VerificationKeyBytes<SpendAuth>,
        sig: Signature<SpendAuth>,
        c: Scalar,
    },
    Binding {
        vk_bytes: VerificationKeyBytes<Binding>,
        sig: Signature<Binding>,
        c: Scalar,
    },
}

impl
    From<(
        VerificationKeyBytes<SpendAuth>,
        Signature<SpendAuth>,
        Scalar,
    )> for Inner
{
    fn from(
        tup: (
            VerificationKeyBytes<SpendAuth>,
            Signature<SpendAuth>,
            Scalar,
        ),
    ) -> Self {
        let (vk_bytes, sig, c) = tup;
        Inner::SpendAuth { vk_bytes, sig, c }
    }
}

impl From<(VerificationKeyBytes<Binding>, Signature<Binding>, Scalar)> for Inner {
    fn from(tup: (VerificationKeyBytes<Binding>, Signature<Binding>, Scalar)) -> Self {
        let (vk_bytes, sig, c) = tup;
        Inner::Binding { vk_bytes, sig, c }
    }
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
pub struct Item {
    inner: Inner,
}

impl<'msg, M: AsRef<[u8]>>
    From<(
        VerificationKeyBytes<SpendAuth>,
        Signature<SpendAuth>,
        &'msg M,
    )> for Item
{
    fn from(
        tup: (
            VerificationKeyBytes<SpendAuth>,
            Signature<SpendAuth>,
            &'msg M,
        ),
    ) -> Self {
        let (vk_bytes, sig, msg) = tup;
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::default()
            .update(&sig.r_bytes[..])
            .update(&vk_bytes.bytes[..])
            .update(msg)
            .finalize();
        Self {
            inner: Inner::SpendAuth { vk_bytes, sig, c },
        }
    }
}

impl<'msg, M: AsRef<[u8]>> From<(VerificationKeyBytes<Binding>, Signature<Binding>, &'msg M)>
    for Item
{
    fn from(tup: (VerificationKeyBytes<Binding>, Signature<Binding>, &'msg M)) -> Self {
        let (vk_bytes, sig, msg) = tup;
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::default()
            .update(&sig.r_bytes[..])
            .update(&vk_bytes.bytes[..])
            .update(msg)
            .finalize();
        Self {
            inner: Inner::Binding { vk_bytes, sig, c },
        }
    }
}

// This would ideally be an associated type with `Verifier` but
// generic associated types are unstable:
// https://github.com/rust-lang/rust/issues/44265
type BatchTuple<T: SigType> = (VerificationKeyBytes<T>, Signature<T>, Scalar);

/// A batch verification context.
pub struct Verifier {
    /// Signature data queued for verification.
    signatures: Vec<Item>,
    /// Caching this count avoids a hash traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl Default for Verifier {
    fn default() -> Verifier {
        Verifier {
            signatures: vec![],
            batch_size: usize::default(),
        }
    }
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier {
        Verifier::default()
    }

    /// Queue an Item for verification.
    pub fn queue<I: Into<Item>>(&mut self, item: I) {
        self.signatures.push(item.into());
        self.batch_size += 1;
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// The batch verification equation is:
    ///
    /// h_G * -[sum(z_i * s_i)]P_G + sum([z_i]R_i + [z_i * c_i]VK_i) = 0_G
    ///
    /// which we split out into:
    ///
    /// h_G * -[sum(z_i * s_i)]P_G + sum([z_i]R_i) + sum([z_i * c_i]VK_i) = 0_G
    ///
    /// so that we can use multiscalar multiplication speedups.
    ///
    /// where for each signature i,
    /// - VK_i is the verification key;
    /// - R_i is the signature's R value;
    /// - s_i is the signature's s value;
    /// - c_i is the hash of the message and other data;
    /// - z_i is a random 128-bit Scalar.
    /// - h_G is the cofactor of the group;
    ///
    /// As follows elliptic curve scalar multiplication convention,
    /// scalar variables are lowercase and group point variables
    /// are uppercase. This does not exactly match the RedDSA
    /// notation in the [protocol specification §B.1][ps].
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        let n = self.signatures.len();

        let mut VK_coeffs = Vec::with_capacity(n);
        let mut VKs = Vec::with_capacity(n);
        let mut R_coeffs = Vec::with_capacity(self.batch_size);
        let mut Rs = Vec::with_capacity(self.batch_size);
        let mut P_spendauth_coeff = Scalar::zero();
        let mut P_binding_coeff = Scalar::zero();

        for item in self.signatures.iter() {
            match item.inner {
                Inner::SpendAuth { vk_bytes, sig, c } => {
                    // let tup: BatchTuple<SpendAuth> = (vk_bytes, sig, c);

                    // let (P_coeff, R, R_coeff, VK, VK_coeff) =
                    //     &self.compute_multiscalar_mul_inputs(rng, tup)?;

                    let z = Scalar::from_raw(gen_128_bits(&mut rng));

                    let s = {
                        // XXX-jubjub: should not use CtOption here
                        let maybe_scalar = Scalar::from_bytes(&sig.s_bytes);
                        if maybe_scalar.is_some().into() {
                            maybe_scalar.unwrap()
                        } else {
                            return Err(Error::InvalidSignature);
                        }
                    };

                    let R = {
                        // XXX-jubjub: should not use CtOption here
                        // XXX-jubjub: inconsistent ownership in from_bytes
                        let maybe_point = AffinePoint::from_bytes(sig.r_bytes);
                        if maybe_point.is_some().into() {
                            jubjub::ExtendedPoint::from(maybe_point.unwrap())
                        } else {
                            return Err(Error::InvalidSignature);
                        }
                    };
                    let P_coeff = z * s;
                    let R_coeff = z;
                    let VK = VerificationKey::<SpendAuth>::try_from(vk_bytes.bytes)
                        .unwrap()
                        .point;
                    let VK_coeff = Scalar::zero() + (z * c);

                    P_spendauth_coeff -= P_coeff;
                    Rs.push(R);
                    R_coeffs.push(R_coeff);
                    VKs.push(VK);
                    VK_coeffs.push(VK_coeff);
                }
                Inner::Binding { vk_bytes, sig, c } => {
                    // let tup: BatchTuple<Binding> = (vk_bytes, sig, c);

                    // let (P_coeff, R, R_coeff, VK, VK_coeff) =
                    //     &self.compute_multiscalar_mul_inputs(rng, tup)?;

                    let z = Scalar::from_raw(gen_128_bits(&mut rng));

                    let s = {
                        // XXX-jubjub: should not use CtOption here
                        let maybe_scalar = Scalar::from_bytes(&sig.s_bytes);
                        if maybe_scalar.is_some().into() {
                            maybe_scalar.unwrap()
                        } else {
                            return Err(Error::InvalidSignature);
                        }
                    };

                    let R = {
                        // XXX-jubjub: should not use CtOption here
                        // XXX-jubjub: inconsistent ownership in from_bytes
                        let maybe_point = AffinePoint::from_bytes(sig.r_bytes);
                        if maybe_point.is_some().into() {
                            jubjub::ExtendedPoint::from(maybe_point.unwrap())
                        } else {
                            return Err(Error::InvalidSignature);
                        }
                    };
                    let P_coeff = z * s;
                    let R_coeff = z;
                    let VK = VerificationKey::<SpendAuth>::try_from(vk_bytes.bytes)
                        .unwrap()
                        .point;
                    let VK_coeff = Scalar::zero() + (z * c);

                    P_binding_coeff -= P_coeff;
                    Rs.push(R);
                    R_coeffs.push(R_coeff);
                    VKs.push(VK);
                    VK_coeffs.push(VK_coeff);
                }
            };
        }

        use std::iter::once;

        let scalars = once(&P_spendauth_coeff)
            .chain(once(&P_binding_coeff))
            .chain(VK_coeffs.iter())
            .chain(R_coeffs.iter());

        let basepoints = [SpendAuth::basepoint(), Binding::basepoint()];
        let points = basepoints.iter().chain(VKs.iter()).chain(Rs.iter());

        let check = ExtendedPoint::vartime_multiscalar_mul(scalars, points);

        if check.is_small_order().into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

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

use crate::{
    scalar_mul::VartimeMultiscalarMul, Error, HStar, Scalar, SigType, Signature, VerificationKey,
    VerificationKeyBytes,
};

// Shim to generate a random 128bit value in a [u64; 4], without
// importing `rand`.
fn gen_128_bits<R: RngCore + CryptoRng>(mut rng: R) -> [u64; 4] {
    let mut bytes = [0u64; 4];
    bytes[0] = rng.next_u64();
    bytes[1] = rng.next_u64();
    bytes
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
pub struct Item<T: SigType> {
    vk_bytes: VerificationKeyBytes<T>,
    sig: Signature<T>,
    c: Scalar,
}

impl<'msg, M: AsRef<[u8]>, T: SigType + ?Sized>
    From<(VerificationKeyBytes<T>, Signature<T>, &'msg M)> for Item<T>
{
    fn from(tup: (VerificationKeyBytes<T>, Signature<T>, &'msg M)) -> Self {
        let (vk_bytes, sig, msg) = tup;
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::default()
            .update(&sig.r_bytes[..])
            .update(&vk_bytes.bytes[..])
            .update(msg)
            .finalize();
        Self { vk_bytes, sig, c }
    }
}

/// A batch verification context.
pub struct Verifier<T: SigType> {
    /// Signature data queued for verification.
    signatures: Vec<(VerificationKeyBytes<T>, Scalar, Signature<T>)>,
    /// Caching this count avoids a hash traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl<T: SigType> Default for Verifier<T> {
    fn default() -> Verifier<T> {
        Verifier {
            signatures: vec![],
            batch_size: usize::default(),
        }
    }
}

impl<T: SigType> Verifier<T> {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier<T> {
        Verifier::default()
    }

    /// Queue a (key, signature, message) tuple for verification.
    pub fn queue<I: Into<Item<T>>>(&mut self, item: I) {
        let Item { vk_bytes, sig, c } = item.into();

        self.signatures.push((vk_bytes, c, sig));
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
        let mut P_coeff = Scalar::zero();

        for (vk_bytes, c, sig) in self.signatures.iter() {
            let VK = VerificationKey::<T>::try_from(vk_bytes.bytes)
                .unwrap()
                .point;

            let mut VK_coeff = Scalar::zero();

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

            let s = {
                // XXX-jubjub: should not use CtOption here
                let maybe_scalar = Scalar::from_bytes(&sig.s_bytes);
                if maybe_scalar.is_some().into() {
                    maybe_scalar.unwrap()
                } else {
                    return Err(Error::InvalidSignature);
                }
            };

            let z = Scalar::from_raw(gen_128_bits(&mut rng));

            P_coeff -= z * s;

            Rs.push(R);
            R_coeffs.push(z);

            VK_coeff += z * c;

            VKs.push(VK);
            VK_coeffs.push(VK_coeff);
        }

        use std::iter::once;

        let P = &T::basepoint();

        let check = ExtendedPoint::vartime_multiscalar_mul(
            once(&P_coeff)
                .chain(VK_coeffs.iter())
                .chain(R_coeffs.iter()),
            once(P).chain(VKs.iter()).chain(Rs.iter()),
        );

        if check.is_small_order().into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

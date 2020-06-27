//! Performs batch RedJubjub signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!


use std::{borrow::Borrow, collections::HashMap, convert::TryFrom, fmt::Debug};

use jubjub::*;
use rand_core::{CryptoRng, RngCore};

use crate::{
    Error, HStar, NonAdjacentForm, Scalar, SigType, Signature, VartimeMultiscalarMul,
    VerificationKey, VerificationKeyBytes,
};

// Shim to generate a random 128bit value in a [u64; 4], without
// importing `rand`.
fn gen_128_bits<R: RngCore + CryptoRng>(mut rng: R) -> [u64; 4] {
    let mut bytes = [0u64; 4];
    bytes[0] = rng.next_u64();
    bytes[1] = rng.next_u64();
    bytes
}

impl NonAdjacentForm for Scalar {
    /// Compute a width-\\(w\\) "Non-Adjacent Form" of this scalar.
    ///
    /// Thanks to curve25519-dalek
    fn non_adjacent_form(&self, w: usize) -> [i8; 256] {
        // required by the NAF definition
        debug_assert!(w >= 2);
        // required so that the NAF digits fit in i8
        debug_assert!(w <= 8);

        use byteorder::{ByteOrder, LittleEndian};

        let mut naf = [0i8; 256];

        let mut x_u64 = [0u64; 5];
        LittleEndian::read_u64_into(&self.to_bytes(), &mut x_u64[0..4]);

        let width = 1 << w;
        let window_mask = width - 1;

        let mut pos = 0;
        let mut carry = 0;
        while pos < 256 {
            // Construct a buffer of bits of the scalar, starting at bit `pos`
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let bit_buf: u64;
            if bit_idx < 64 - w {
                // This window's bits are contained in a single u64
                bit_buf = x_u64[u64_idx] >> bit_idx;
            } else {
                // Combine the current u64's bits with the bits from the next u64
                bit_buf = (x_u64[u64_idx] >> bit_idx) | (x_u64[1 + u64_idx] << (64 - bit_idx));
            }

            // Add the carry into the current window
            let window = carry + (bit_buf & window_mask);

            if window & 1 == 0 {
                // If the window value is even, preserve the carry and continue.
                // Why is the carry preserved?
                // If carry == 0 and window & 1 == 0, then the next carry should be 0
                // If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
                pos += 1;
                continue;
            }

            if window < width / 2 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                carry = 1;
                naf[pos] = (window as i8).wrapping_sub(width as i8);
            }

            pos += w;
        }

        naf
    }
}

/// Holds odd multiples 1A, 3A, ..., 15A of a point A.
#[derive(Copy, Clone)]
pub(crate) struct LookupTable5<T>(pub(crate) [T; 8]);

impl<T: Copy> LookupTable5<T> {
    /// Given public, odd \\( x \\) with \\( 0 < x < 2^4 \\), return \\(xA\\).
    pub fn select(&self, x: usize) -> T {
        debug_assert_eq!(x & 1, 1);
        debug_assert!(x < 16);

        self.0[x / 2]
    }
}

impl<T: Debug> Debug for LookupTable5<T> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "LookupTable5({:?})", self.0)
    }
}

impl<'a> From<&'a ExtendedPoint> for LookupTable5<ExtendedNielsPoint> {
    #[allow(non_snake_case)]
    fn from(A: &'a ExtendedPoint) -> Self {
        let mut Ai = [A.to_niels(); 8];
        let A2 = A.double();
        for i in 0..7 {
            Ai[i + 1] = (&A2 + &Ai[i]).to_niels();
        }
        // Now Ai = [A, 3A, 5A, 7A, 9A, 11A, 13A, 15A]
        LookupTable5(Ai)
    }
}

impl VartimeMultiscalarMul for ExtendedPoint {
    type Point = ExtendedPoint;

#[allow(non_snake_case)]
    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<ExtendedPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<ExtendedPoint>>,
    {
        let nafs: Vec<_> = scalars
            .into_iter()
            .map(|c| c.borrow().non_adjacent_form(5))
            .collect();

        let lookup_tables = points
            .into_iter()
            .map(|P_opt| P_opt.map(|P| LookupTable5::<ExtendedNielsPoint>::from(&P)))
            .collect::<Option<Vec<_>>>()?;

        let mut r = ExtendedPoint::identity();

        for i in (0..256).rev() {
            let mut t = r.double();

            for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                if naf[i] > 0 {
                    t = &t + &lookup_table.select(naf[i] as usize);
                } else if naf[i] < 0 {
                    t = &t - &lookup_table.select(-naf[i] as usize);
                }
            }

            r = t;
        }

        Some(r)
    }
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
    signatures: HashMap<VerificationKeyBytes<T>, Vec<(Scalar, Signature<T>)>>,
    /// Caching this count avoids a hash traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl<T: SigType> Default for Verifier<T> {
    fn default() -> Verifier<T> {
        Verifier {
            signatures: HashMap::new(),
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

        self.signatures
            .entry(vk_bytes)
            // The common case is 1 signature per public key.
            // We could also consider using a smallvec here.
            .or_insert_with(|| Vec::with_capacity(1))
            .push((c, sig));
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
        let n = self.signatures.keys().count();

        let mut VK_coeffs = Vec::with_capacity(n);
        let mut VKs = Vec::with_capacity(n);
        let mut R_coeffs = Vec::with_capacity(self.batch_size);
        let mut Rs = Vec::with_capacity(self.batch_size);
        let mut P_coeff = Scalar::zero();

        for (vk_bytes, sigs) in self.signatures.iter() {
            let VK = VerificationKey::<T>::try_from(vk_bytes.bytes)
                .unwrap()
                .point;

            let mut VK_coeff = Scalar::zero();

            for (c, sig) in sigs.iter() {
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
            }

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

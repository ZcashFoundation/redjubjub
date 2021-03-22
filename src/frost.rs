// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2020-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Chelsea H. Komlo <me@chelseakomlo.com>
// - Deirdre Connolly <deirdre@zfnd.org>
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of FROST (Flexible Round-Optimized Schnorr Threshold)
//! signatures.
//!
//! > **WARNING**: This implementation is unstable and subject to
//! > revision. It is not covered by the crate's semver guarantees and should not
//! > be deployed without consultation from the FROST authors!
//!
//! This implementation currently only supports key generation using a central
//! dealer. In the future, we will add support for key generation via a DKG,
//! as specified in the FROST paper.
//! Internally, keygen_with_dealer generates keys using Verifiable Secret
//! Sharing,  where shares are generated using Shamir Secret Sharing.

use std::{collections::HashMap, convert::TryFrom, marker::PhantomData};

use rand_core::{CryptoRng, RngCore};
use zeroize::DefaultIsZeroes;

use crate::private::Sealed;
use crate::{HStar, Scalar, Signature, SpendAuth, VerificationKey};

/// A secret scalar value representing a single signer's secret key.
#[derive(Clone, Copy, Default)]
pub struct Secret(Scalar);

// Zeroizes `Secret` to be the `Default` value on drop (when it goes out of
// scope).  Luckily the derived `Default` includes the `Default` impl of
// jubjub::Fr/Scalar, which is four 0u64's under the hood.
impl DefaultIsZeroes for Secret {}

impl From<Scalar> for Secret {
    fn from(source: Scalar) -> Secret {
        Secret(source)
    }
}

/// A public group element that represents a single signer's public key.
#[derive(Copy, Clone)]
pub struct Public(jubjub::ExtendedPoint);

impl From<jubjub::ExtendedPoint> for Public {
    fn from(source: jubjub::ExtendedPoint) -> Public {
        Public(source)
    }
}

/// A share generated by performing a (t-out-of-n) secret sharing scheme where
/// n is the total number of shares and t is the threshold required to
/// reconstruct the secret; in this case we use Shamir's secret sharing.
#[derive(Clone)]
pub struct Share {
    receiver_index: u32,
    value: Secret,
    commitment: ShareCommitment,
}

/// A Jubjub point that is a commitment to one coefficient of our secret
/// polynomial.
///
/// This is a (public) commitment to one coefficient of a secret polynomial used
/// for performing verifiable secret sharing for a Shamir secret share.
#[derive(Clone)]
struct Commitment(jubjub::ExtendedPoint);

/// Contains the commitments to the coefficients for our secret polynomial _f_,
/// used to generate participants' key shares.
///
/// [`ShareCommitment`] contains a set of commitments to the coefficients (which
/// themselves are scalars) for a secret polynomial f, where f is used to
/// generate each ith participant's key share f(i). Participants use this set of
/// commitments to perform verifiable secret sharing.
///
/// Note that participants MUST be assured that they have the *same*
/// [`ShareCommitment`], either by performing pairwise comparison, or by using
/// some agreed-upon public location for publication, where each participant can
/// ensure that they received the correct (and same) value.
#[derive(Clone)]
pub struct ShareCommitment(Vec<Commitment>);

/// The product of all signers' individual commitments, published as part of the
/// final signature.
pub struct GroupCommitment(jubjub::ExtendedPoint);

/// Secret and public key material generated by a dealer performing
/// [`keygen_with_dealer`].
///
/// To derive a FROST keypair, the receiver of the [`SharePackage`] *must* call
/// .into(), which under the hood also performs validation.
pub struct SharePackage {
    /// Denotes the participant index each share is owned by.
    pub index: u32,
    /// This participant's share.
    pub(crate) share: Share,
    /// This participant's public key.
    pub(crate) public: Public,
    /// The public signing key that represents the entire group.
    pub(crate) group_public: VerificationKey<SpendAuth>,
}

impl TryFrom<SharePackage> for KeyPackage {
    type Error = &'static str;

    /// Tries to verify a share and construct a [`KeyPackage`] from it.
    ///
    /// When participants receive a [`SharePackage`] from the dealer, they
    /// *MUST* verify the integrity of the share before continuing on to
    /// transform it into a signing/verification keypair. Here, we assume that
    /// every participant has the same view of the commitment issued by the
    /// dealer, but implementations *MUST* make sure that all participants have
    /// a consistent view of this commitment in practice.
    fn try_from(sharepackage: SharePackage) -> Result<Self, &'static str> {
        verify_share(&sharepackage.share)?;

        Ok(KeyPackage {
            index: sharepackage.index,
            secret_share: sharepackage.share.value,
            public: sharepackage.public,
            group_public: sharepackage.group_public,
        })
    }
}

/// A FROST keypair, which can be generated either by a trusted dealer or using
/// a DKG.
///
/// When using a central dealer, [`SharePackage`]s are distributed to
/// participants, who then perform verification, before deriving
/// [`KeyPackage`]s, which they store to later use during signing.
pub struct KeyPackage {
    index: u32,
    secret_share: Secret,
    public: Public,
    group_public: VerificationKey<SpendAuth>,
}

/// Public data that contains all the signer's public keys as well as the
/// group public key.
///
/// Used for verification purposes before publishing a signature.
pub struct PublicKeyPackage {
    /// When performing signing, the coordinator must ensure that they have the
    /// correct view of participant's public keys to perform verification before
    /// publishing a signature. signer_pubkeys represents all signers for a
    /// signing operation.
    pub(crate) signer_pubkeys: HashMap<u32, Public>,
    /// group_public represents the joint public key for the entire group.
    pub group_public: VerificationKey<SpendAuth>,
}

/// Allows all participants' keys to be generated using a central, trusted
/// dealer.
///
/// Under the hood, this performs verifiable secret sharing, which itself uses
/// Shamir secret sharing, from which each share becomes a participant's secret
/// key. The output from this function is a set of shares along with one single
/// commitment that participants use to verify the integrity of the share.
pub fn keygen_with_dealer<R: RngCore + CryptoRng>(
    num_signers: u32,
    threshold: u32,
    mut rng: R,
) -> Result<(Vec<SharePackage>, PublicKeyPackage), &'static str> {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    let secret = Secret(Scalar::from_bytes_wide(&bytes));
    let group_public = VerificationKey::from(&secret.0);
    let shares = generate_shares(&secret, num_signers, threshold, rng)?;
    let mut sharepackages: Vec<SharePackage> = Vec::with_capacity(num_signers as usize);
    let mut signer_pubkeys: HashMap<u32, Public> = HashMap::with_capacity(num_signers as usize);

    for share in shares {
        let signer_public = Public(SpendAuth::basepoint() * share.value.0);
        sharepackages.push(SharePackage {
            index: share.receiver_index,
            share: share.clone(),
            public: signer_public,
            group_public,
        });

        signer_pubkeys.insert(share.receiver_index, signer_public);
    }

    Ok((
        sharepackages,
        PublicKeyPackage {
            signer_pubkeys,
            group_public,
        },
    ))
}

/// Verifies that a share is consistent with a commitment.
///
/// This ensures that this participant's share has been generated using the same
/// mechanism as all other signing participants. Note that participants *MUST*
/// ensure that they have the same view as all other participants of the
/// commitment!
fn verify_share(share: &Share) -> Result<(), &'static str> {
    let f_result = SpendAuth::basepoint() * share.value.0;

    let x = Scalar::from(share.receiver_index as u64);

    let (_, result) = share.commitment.0.iter().fold(
        (Scalar::one(), jubjub::ExtendedPoint::identity()),
        |(x_to_the_i, sum_so_far), comm_i| (x_to_the_i * x, sum_so_far + comm_i.0 * x_to_the_i),
    );

    if !(f_result == result) {
        return Err("Share is invalid.");
    }

    Ok(())
}

/// Creates secret shares for a given secret.
///
/// This function accepts a secret from which shares are generated. While in
/// FROST this secret should always be generated randomly, we allow this secret
/// to be specified for this internal function for testability.
///
/// Internally, [`generate_shares`] performs verifiable secret sharing, which
/// generates shares via Shamir Secret Sharing, and then generates public
/// commitments to those shares.
///
/// More specifically, [`generate_shares`]:
/// - Randomly samples of coefficents [a, b, c], this represents a secret
/// polynomial f
/// - For each participant i, their secret share is f(i)
/// - The commitment to the secret polynomial f is [g^a, g^b, g^c]
fn generate_shares<R: RngCore + CryptoRng>(
    secret: &Secret,
    numshares: u32,
    threshold: u32,
    mut rng: R,
) -> Result<Vec<Share>, &'static str> {
    if threshold < 1 {
        return Err("Threshold cannot be 0");
    }

    if numshares < 1 {
        return Err("Number of shares cannot be 0");
    }

    if threshold > numshares {
        return Err("Threshold cannot exceed numshares");
    }

    let numcoeffs = threshold - 1;

    let mut coefficients: Vec<Scalar> = Vec::with_capacity(threshold as usize);

    let mut shares: Vec<Share> = Vec::with_capacity(numshares as usize);

    let mut commitment: ShareCommitment = ShareCommitment(Vec::with_capacity(threshold as usize));

    for _ in 0..numcoeffs {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        coefficients.push(Scalar::from_bytes_wide(&bytes));
    }

    // Verifiable secret sharing, to make sure that participants can ensure their secret is consistent
    // with every other participant's.
    commitment
        .0
        .push(Commitment(SpendAuth::basepoint() * secret.0));

    for c in &coefficients {
        commitment.0.push(Commitment(SpendAuth::basepoint() * c));
    }

    // Evaluate the polynomial with `secret` as the constant term
    // and `coeffs` as the other coefficients at the point x=share_index,
    // using Horner's method.
    for index in 1..numshares + 1 {
        let scalar_index = Scalar::from(index as u64);
        let mut value = Scalar::zero();

        // Polynomial evaluation, for this index
        for i in (0..numcoeffs).rev() {
            value += &coefficients[i as usize];
            value *= scalar_index;
        }
        value += secret.0;

        shares.push(Share {
            receiver_index: index,
            value: Secret(value),
            commitment: commitment.clone(),
        });
    }

    Ok(shares)
}

/// Comprised of hiding and binding nonces.
///
/// Note that [`SigningNonces`] must be used *only once* for a signing
/// operation; re-using nonces will result in leakage of a signer's long-lived
/// signing key.
#[derive(Clone, Copy, Default)]
pub struct SigningNonces {
    hiding: Scalar,
    binding: Scalar,
}

// Zeroizes `SigningNonces` to be the `Default` value on drop (when it goes out
// of scope).  Luckily the derived `Default` includes the `Default` impl of the
// `jubjub::Fr/Scalar`'s, which is four 0u64's under the hood.
impl DefaultIsZeroes for SigningNonces {}

impl SigningNonces {
    /// Generates a new signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub fn new<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        let hiding = Scalar::from_bytes_wide(&bytes);

        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        let binding = Scalar::from_bytes_wide(&bytes);

        Self { hiding, binding }
    }
}

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched if desired by the implementation. Each
/// SigningCommitment can be used for exactly *one* signature.
#[derive(Copy, Clone)]
pub struct SigningCommitments {
    index: u32,
    hiding: jubjub::ExtendedPoint,
    binding: jubjub::ExtendedPoint,
}

impl From<(u32, &SigningNonces)> for SigningCommitments {
    /// For SpendAuth signatures only, not Binding signatures, in RedJubjub/Zcash.
    fn from((index, nonces): (u32, &SigningNonces)) -> Self {
        Self {
            index,
            hiding: SpendAuth::basepoint() * nonces.hiding,
            binding: SpendAuth::basepoint() * nonces.binding,
        }
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub struct SigningPackage {
    /// Message which each participant will sign
    pub message: &'static [u8],
    /// The set of commitments participants published in the first round of the
    /// protocol.
    pub signing_commitments: Vec<SigningCommitments>,
}

/// A participant's signature share, which the coordinator will use to aggregate
/// with all other signer's shares into the joint signature.
#[derive(Clone, Copy, Default)]
pub struct SignatureShare {
    /// Represents the participant index.
    pub(crate) index: u32,
    /// This participant's signature over the message.
    pub(crate) signature: Scalar,
}

// Zeroizes `SignatureShare` to be the `Default` value on drop (when it goes out
// of scope).  Luckily the derived `Default` includes the `Default` impl of
// jubjub::Fr/Scalar, which is four 0u64's under the hood, and u32, which is
// 0u32.
impl DefaultIsZeroes for SignatureShare {}

impl SignatureShare {
    /// Tests if a signature share issued by a participant is valid before
    /// aggregating it into a final joint signature to publish.
    pub fn check_is_valid(
        &self,
        pubkey: &Public,
        lambda_i: Scalar,
        commitment: jubjub::ExtendedPoint,
        challenge: Scalar,
    ) -> Result<(), &'static str> {
        if (SpendAuth::basepoint() * self.signature)
            != (commitment + pubkey.0 * challenge * lambda_i)
        {
            return Err("Invalid signature share");
        }
        Ok(())
    }
}

/// Done once by each participant, to generate _their_ nonces and commitments
/// that are then used during signing.
///
/// When performing signing using two rounds, num_nonces would equal 1, to
/// perform the first round. Batching entails generating more than one
/// nonce/commitment pair at a time.  Nonces should be stored in secret storage
/// for later use, whereas the commitments are published.
pub fn preprocess<R>(
    num_nonces: u32,
    participant_index: u32,
    rng: &mut R,
) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
where
    R: CryptoRng + RngCore,
{
    let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);
    let mut signing_commitments: Vec<SigningCommitments> = Vec::with_capacity(num_nonces as usize);

    for _ in 0..num_nonces {
        let nonces = SigningNonces::new(rng);
        signing_commitments.push(SigningCommitments::from((participant_index, &nonces)));
        signing_nonces.push(nonces);
    }

    (signing_nonces, signing_commitments)
}

/// Generates the binding factor that ensures each signature share is strongly
/// bound to a signing set, specific set of commitments, and a specific message.
fn gen_rho_i(index: u32, signing_package: &SigningPackage) -> Scalar {
    // Hash signature message with HStar before deriving the binding factor.
    //
    // To avoid a collision with other inputs to the hash that generates the
    // binding factor, we should hash our input message first. Our 'standard'
    // hash is HStar, which uses a domain separator already, and is the same one
    // that generates the binding factor.
    let message_hash = HStar::default().update(signing_package.message).finalize();

    let mut hasher = HStar::default();
    hasher
        .update("FROST_rho".as_bytes())
        .update(index.to_be_bytes())
        .update(message_hash.to_bytes());

    for item in signing_package.signing_commitments.iter() {
        hasher.update(item.index.to_be_bytes());
        let hiding_bytes = jubjub::AffinePoint::from(item.hiding).to_bytes();
        hasher.update(hiding_bytes);
        let binding_bytes = jubjub::AffinePoint::from(item.binding).to_bytes();
        hasher.update(binding_bytes);
    }

    hasher.finalize()
}

/// Generates the group commitment which is published as part of the joint
/// Schnorr signature.
fn gen_group_commitment(
    signing_package: &SigningPackage,
    bindings: &HashMap<u32, Scalar>,
) -> Result<GroupCommitment, &'static str> {
    let mut accumulator = jubjub::ExtendedPoint::identity();

    for commitment in signing_package.signing_commitments.iter() {
        let rho_i = bindings
            .get(&commitment.index)
            .ok_or("No matching commitment index")?;
        accumulator += commitment.hiding + (commitment.binding * rho_i)
    }

    Ok(GroupCommitment(accumulator))
}

/// Generates the challenge as is required for Schnorr signatures.
fn gen_challenge(
    signing_package: &SigningPackage,
    group_commitment: &GroupCommitment,
    group_public: &VerificationKey<SpendAuth>,
) -> Scalar {
    let group_commitment_bytes = jubjub::AffinePoint::from(group_commitment.0).to_bytes();

    HStar::default()
        .update(group_commitment_bytes)
        .update(group_public.bytes.bytes)
        .update(signing_package.message)
        .finalize()
}

/// Generates the langrange coefficient for the i'th participant.
fn gen_lagrange_coeff(
    signer_index: u32,
    signing_package: &SigningPackage,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for commitment in signing_package.signing_commitments.iter() {
        if commitment.index == signer_index {
            continue;
        }
        num *= Scalar::from(commitment.index as u64);
        den *= Scalar::from(commitment.index as u64) - Scalar::from(signer_index as u64);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    // TODO: handle this unwrap better like other CtOption's
    let lagrange_coeff = num * den.invert().unwrap();

    Ok(lagrange_coeff)
}

/// Performed once by each participant selected for the signing operation.
///
/// Receives the message to be signed and a set of signing commitments and a set
/// of randomizing commitments to be used in that signing operation, including
/// that for this participant.
///
/// Assumes the participant has already determined which nonce corresponds with
/// the commitment that was assigned by the coordinator in the SigningPackage.
pub fn sign(
    signing_package: &SigningPackage,
    participant_nonces: SigningNonces,
    share_package: &SharePackage,
) -> Result<SignatureShare, &'static str> {
    let mut bindings: HashMap<u32, Scalar> =
        HashMap::with_capacity(signing_package.signing_commitments.len());

    for comm in signing_package.signing_commitments.iter() {
        let rho_i = gen_rho_i(comm.index, &signing_package);
        bindings.insert(comm.index, rho_i);
    }

    let lambda_i = gen_lagrange_coeff(share_package.index, &signing_package)?;

    let group_commitment = gen_group_commitment(&signing_package, &bindings)?;

    let challenge = gen_challenge(
        &signing_package,
        &group_commitment,
        &share_package.group_public,
    );

    let participant_rho_i = bindings
        .get(&share_package.index)
        .ok_or("No matching binding!")?;

    // The Schnorr signature share
    let signature: Scalar = participant_nonces.hiding
        + (participant_nonces.binding * participant_rho_i)
        + (lambda_i * share_package.share.value.0 * challenge);

    Ok(SignatureShare {
        index: share_package.index,
        signature,
    })
}

/// Verifies each participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain SpendAuth
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information).
pub fn aggregate(
    signing_package: &SigningPackage,
    signing_shares: &[SignatureShare],
    pubkeys: &PublicKeyPackage,
) -> Result<Signature<SpendAuth>, &'static str> {
    let mut bindings: HashMap<u32, Scalar> =
        HashMap::with_capacity(signing_package.signing_commitments.len());

    for comm in signing_package.signing_commitments.iter() {
        let rho_i = gen_rho_i(comm.index, &signing_package);
        bindings.insert(comm.index, rho_i);
    }

    let group_commitment = gen_group_commitment(&signing_package, &bindings)?;

    let challenge = gen_challenge(&signing_package, &group_commitment, &pubkeys.group_public);

    for signing_share in signing_shares {
        let signer_pubkey = pubkeys.signer_pubkeys[&signing_share.index];
        let lambda_i = gen_lagrange_coeff(signing_share.index, &signing_package)?;
        let signer_commitment = signing_package
            .signing_commitments
            .iter()
            .find(|comm| comm.index == signing_share.index)
            .ok_or("No matching signing commitment for signer")?;

        let commitment_i =
            signer_commitment.hiding + (signer_commitment.binding * bindings[&signing_share.index]);

        signing_share.check_is_valid(&signer_pubkey, lambda_i, commitment_i, challenge)?;
    }

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    let mut z = Scalar::zero();
    for signature_share in signing_shares {
        z += signature_share.signature;
    }

    Ok(Signature {
        r_bytes: jubjub::AffinePoint::from(group_commitment.0).to_bytes(),
        s_bytes: z.to_bytes(),
        _marker: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn reconstruct_secret(shares: Vec<Share>) -> Result<Scalar, &'static str> {
        let numshares = shares.len();

        if numshares < 1 {
            return Err("No shares provided");
        }

        let mut lagrange_coeffs: Vec<Scalar> = Vec::with_capacity(numshares as usize);

        for i in 0..numshares {
            let mut num = Scalar::one();
            let mut den = Scalar::one();
            for j in 0..numshares {
                if j == i {
                    continue;
                }
                num *= Scalar::from(shares[j].receiver_index as u64);
                den *= Scalar::from(shares[j].receiver_index as u64)
                    - Scalar::from(shares[i].receiver_index as u64);
            }
            if den == Scalar::zero() {
                return Err("Duplicate shares provided");
            }
            lagrange_coeffs.push(num * den.invert().unwrap());
        }

        let mut secret = Scalar::zero();

        for i in 0..numshares {
            secret += lagrange_coeffs[i] * shares[i].value.0;
        }

        Ok(secret)
    }

    /// This is testing that Shamir's secret sharing to compute and arbitrary
    /// value is working.
    #[test]
    fn check_share_generation() {
        let mut rng = thread_rng();

        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        let secret = Secret(Scalar::from_bytes_wide(&bytes));

        let _ = SpendAuth::basepoint() * secret.0;

        let shares = generate_shares(&secret, 5, 3, rng).unwrap();

        for share in shares.iter() {
            assert_eq!(verify_share(&share), Ok(()));
        }

        assert_eq!(reconstruct_secret(shares).unwrap(), secret.0)
    }
}

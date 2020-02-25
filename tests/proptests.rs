use std::convert::TryFrom;

use proptest::prelude::*;
use rand_core::{CryptoRng, RngCore};

use redjubjub::*;

/// A signature test-case, containing signature data and expected validity.
#[derive(Clone, Debug)]
struct SignatureCase<T: SigType> {
    msg: Vec<u8>,
    sig: Signature<T>,
    pk_bytes: PublicKeyBytes<T>,
    is_valid: bool,
}

/// A modification to a test-case.
#[derive(Copy, Clone, Debug)]
enum Tweak {
    /// No-op, used to check that unchanged cases verify.
    None,
    /// Change the message the signature is defined for, invalidating the signature.
    ChangeMessage,
    /// Change the public key the signature is defined for, invalidating the signature.
    ChangePubkey,
    /* XXX implement this -- needs to regenerate a custom signature because the
       nonce commitment is fed into the hash, so it has to have torsion at signing
       time.
    /// Change the case to have a torsion component in the signature's `r` value.
    AddTorsion,
    */
    /* XXX implement this -- needs custom handling of field arithmetic.
    /// Change the signature's `s` scalar to be unreduced (mod L), invalidating the signature.
    UnreducedScalar,
    */
}

impl<T: SigType> SignatureCase<T> {
    fn new<R: RngCore + CryptoRng>(mut rng: R, msg: Vec<u8>) -> Self {
        let sk = SecretKey::new(&mut rng);
        let sig = sk.sign::<StdBlake2b512, _>(&mut rng, &msg);
        let pk_bytes = PublicKey::from(&sk).into();
        Self {
            msg,
            sig,
            pk_bytes,
            is_valid: true,
        }
    }

    // Check that signature verification succeeds or fails, as expected.
    fn check(&self) -> bool {
        // The signature data is stored in (refined) byte types, but do a round trip
        // conversion to raw bytes to exercise those code paths.
        let sig = {
            let bytes: [u8; 64] = self.sig.into();
            Signature::<T>::from(bytes)
        };
        let pk_bytes = {
            let bytes: [u8; 32] = self.pk_bytes.into();
            PublicKeyBytes::<T>::from(bytes)
        };

        // Check that signature validation has the expected result.
        self.is_valid
            == PublicKey::try_from(pk_bytes)
                .and_then(|pk| pk.verify::<StdBlake2b512>(&self.msg, &sig))
                .is_ok()
    }

    fn apply_tweak(&mut self, tweak: &Tweak) {
        match tweak {
            Tweak::None => {}
            Tweak::ChangeMessage => {
                // Changing the message makes the signature invalid.
                self.msg.push(90);
                self.is_valid = false;
            }
            Tweak::ChangePubkey => {
                // Changing the public key makes the signature invalid.
                let mut bytes: [u8; 32] = self.pk_bytes.clone().into();
                let j = (bytes[2] & 31) as usize;
                bytes[2] ^= 0x23;
                bytes[2] |= 0x99;
                bytes[j] ^= bytes[2];
                self.pk_bytes = bytes.into();
                self.is_valid = false;
            }
        }
    }
}

fn tweak_strategy() -> impl Strategy<Value = Tweak> {
    prop_oneof![
        10 => Just(Tweak::None),
        1 => Just(Tweak::ChangeMessage),
        1 => Just(Tweak::ChangePubkey),
    ]
}

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

proptest! {

    #[test]
    fn tweak_signature(
        tweaks in prop::collection::vec(tweak_strategy(), (0,5)),
        rng_seed in any::<u64>(),
    ) {
        // Use a deterministic RNG so that test failures can be reproduced.
        // Seeding with 64 bits of entropy is INSECURE and this code should
        // not be copied outside of this test!
        let mut rng = ChaChaRng::seed_from_u64(rng_seed);

        // Create a test case for each signature type.
        let msg = b"test message for proptests";
        let mut binding = SignatureCase::<Binding>::new(&mut rng, msg.to_vec());
        let mut spendauth = SignatureCase::<SpendAuth>::new(&mut rng, msg.to_vec());

        // Apply tweaks to each case.
        for t in &tweaks {
            binding.apply_tweak(t);
            spendauth.apply_tweak(t);
        }

        assert!(binding.check());
        assert!(spendauth.check());
    }

    #[test]
    fn randomization_commutes_with_pubkey_homomorphism(rng_seed in any::<u64>()) {
        // Use a deterministic RNG so that test failures can be reproduced.
        // Seeding with 64 bits of entropy is INSECURE and this code should
        // not be copied outside of this test!
        let mut rng = ChaChaRng::seed_from_u64(rng_seed);

        let r = {
            // XXX-jubjub: better API for this
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes[..]);
            Randomizer::from_bytes_wide(&bytes)
        };

        let sk = SecretKey::<SpendAuth>::new(&mut rng);
        let pk = PublicKey::from(&sk);

        let sk_r = sk.randomize(&r);
        let pk_r = pk.randomize(&r);

        let pk_r_via_sk_rand: [u8; 32] = PublicKeyBytes::from(PublicKey::from(&sk_r)).into();
        let pk_r_via_pk_rand: [u8; 32] = PublicKeyBytes::from(pk_r).into();

        assert_eq!(pk_r_via_pk_rand, pk_r_via_sk_rand);
    }
}

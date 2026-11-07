use rand::rng;

use redjubjub::*;

#[test]
fn spendauth_batch_verify() {
    let mut rng = rng();
    let mut batch = batch::Verifier::new();
    for _ in 0..32 {
        let sk = SigningKey::<SpendAuth>::new(&mut rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&mut rng, &msg[..]);
        batch.queue((vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn binding_batch_verify() {
    let mut rng = rng();
    let mut batch = batch::Verifier::new();
    for _ in 0..32 {
        let sk = SigningKey::<Binding>::new(&mut rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&mut rng, &msg[..]);
        batch.queue((vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn alternating_batch_verify() {
    let mut rng = rng();
    let mut batch = batch::Verifier::new();
    for i in 0..32 {
        let item: batch::Item = match i % 2 {
            0 => {
                let sk = SigningKey::<SpendAuth>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                (vk.into(), sig, msg).into()
            }
            1 => {
                let sk = SigningKey::<Binding>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                (vk.into(), sig, msg).into()
            }
            _ => unreachable!(),
        };
        batch.queue(item);
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn bad_batch_verify() {
    let mut rng = rng();
    let bad_index = 4; // must be even
    let mut batch = batch::Verifier::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let item: batch::Item = match i % 2 {
            0 => {
                let sk = SigningKey::<SpendAuth>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = if i != bad_index {
                    sk.sign(&mut rng, &msg[..])
                } else {
                    sk.sign(&mut rng, b"bad")
                };
                (vk.into(), sig, msg).into()
            }
            1 => {
                let sk = SigningKey::<Binding>::new(&mut rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                (vk.into(), sig, msg).into()
            }
            _ => unreachable!(),
        };
        items.push(item.clone());
        batch.queue(item);
    }
    assert!(batch.verify(rng).is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}

#[test]
fn retained_keys_match_byte_keys_and_single_fallback() {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    let mut rng = ChaChaRng::from_seed([23; 32]);
    let msg = b"retained RedJubjub key";
    let mut byte_batch = batch::Verifier::new();
    let mut retained_batch = batch::Verifier::new();
    for _ in 0..16 {
        let spend_sk = SigningKey::<SpendAuth>::new(&mut rng);
        let binding_sk = SigningKey::<Binding>::new(&mut rng);
        let spend_vk = VerificationKey::from(&spend_sk);
        let binding_vk = VerificationKey::from(&binding_sk);
        let spend_sig = spend_sk.sign(&mut rng, msg);
        let binding_sig = binding_sk.sign(&mut rng, msg);
        for (encoded, retained) in [
            (
                batch::Item::from((VerificationKeyBytes::from(spend_vk), spend_sig, msg)),
                batch::Item::from_spendauth_key(spend_vk, spend_sig, msg),
            ),
            (
                batch::Item::from((VerificationKeyBytes::from(binding_vk), binding_sig, msg)),
                batch::Item::from_binding_key(binding_vk, binding_sig, msg),
            ),
        ] {
            assert_eq!(encoded.clone().verify_single(), Ok(()));
            assert_eq!(retained.clone().verify_single(), Ok(()));
            byte_batch.queue(encoded);
            retained_batch.queue(retained);
        }
        let bytes: [u8; 32] = binding_vk.into();
        let point = jubjub::AffinePoint::from_bytes(bytes)
            .unwrap()
            .to_extended();
        assert_eq!(VerificationKey::<Binding>::from(point), binding_vk);
        let spend_bytes: [u8; 32] = spend_vk.into();
        assert_eq!(
            jubjub::AffinePoint::from(spend_vk),
            jubjub::AffinePoint::from_bytes(spend_bytes).unwrap()
        );
        for range in [0..32, 32..64] {
            let mut malformed: [u8; 64] = spend_sig.into();
            malformed[range].fill(0xff);
            let item = batch::Item::from_spendauth_key(spend_vk, Signature::from(malformed), msg);
            assert_eq!(item.clone().verify_single(), Err(Error::InvalidSignature));
            let mut batch = batch::Verifier::new();
            batch.queue(item.clone());
            batch.queue(item);
            assert_eq!(batch.verify(&mut rng), Err(Error::InvalidSignature));
        }
    }
    assert_eq!(byte_batch.verify(ChaChaRng::from_seed([42; 32])), Ok(()));
    assert_eq!(
        retained_batch.verify(ChaChaRng::from_seed([42; 32])),
        Ok(())
    );
}

#[test]
fn point_conversions_preserve_torsion_and_small_order_keys() {
    let small_order = jubjub::AffinePoint::from_bytes([0; 32]).unwrap();
    let mut rng = rng();
    let spend_key = VerificationKey::from(&SigningKey::<SpendAuth>::new(&mut rng));
    let subgroup = jubjub::AffinePoint::from(spend_key).to_extended();
    for point in [
        jubjub::AffinePoint::identity().to_extended(),
        small_order.to_extended(),
        subgroup + small_order.to_extended(),
    ] {
        let bytes = jubjub::AffinePoint::from(point).to_bytes();
        assert_eq!(
            VerificationKey::<Binding>::from(point),
            VerificationKey::<Binding>::try_from(bytes).unwrap()
        );
        let spend = VerificationKey::<SpendAuth>::try_from(bytes).unwrap();
        assert_eq!(jubjub::AffinePoint::from(spend).to_extended(), point);
    }
    // RedJubjub accepts small-order SpendAuth keys; Sapling rejects them later.
    let bytes = small_order.to_bytes();
    let spend = VerificationKey::<SpendAuth>::try_from(bytes).unwrap();
    let binding = VerificationKey::<Binding>::from(small_order.to_extended());
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&bytes);
    let mut batch = batch::Verifier::new();
    batch.queue(batch::Item::from_spendauth_key(
        spend,
        Signature::from(signature),
        b"small order",
    ));
    batch.queue(batch::Item::from_binding_key(
        binding,
        Signature::from(signature),
        b"small order",
    ));
    assert_eq!(batch.verify(rng), Ok(()));
}

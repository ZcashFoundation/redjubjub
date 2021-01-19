use rand::thread_rng;
use std::collections::HashMap;

use redjubjub::frost::{self, *};

#[test]
fn check_sign_with_dealer() {
    let mut rng = thread_rng();
    let numsigners = 5;
    let threshold = 3;
    let (shares, pubkeys) = frost::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    let mut nonces: HashMap<u32, Vec<frost::SigningNonces>> =
        HashMap::with_capacity(threshold as usize);
    let mut commitments: Vec<frost::SigningCommitments> = Vec::with_capacity(threshold as usize);

    for participant_index in 1..(threshold + 1) {
        let (nonce, commitment) = preprocess(1, participant_index, &mut rng);
        nonces.insert(participant_index, nonce);
        commitments.push(commitment[0]);
    }

    let mut signature_shares: Vec<frost::SignatureShare> = Vec::with_capacity(threshold as usize);
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage {
        message,
        signing_commitments: commitments,
    };

    for (participant_index, nonce) in nonces {
        let share_package = shares
            .iter()
            .find(|share| participant_index == share.index)
            .unwrap();
        let nonce_to_use = &nonce[0];
        let signature_share = frost::sign(&signing_package, &nonce_to_use, share_package).unwrap();
        signature_shares.push(signature_share);
    }

    let group_signature_res = frost::aggregate(&signing_package, &signature_shares, &pubkeys);
    assert!(group_signature_res.is_ok());
    let group_signature = group_signature_res.unwrap();

    assert!(pubkeys
        .group_public
        .verify(&message, &group_signature)
        .is_ok());
}

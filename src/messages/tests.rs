use rand::thread_rng;

use super::*;

use crate::messages::validate::{MsgErr, Validate};

use crate::{frost, verification_key};

use serde_json;
use std::convert::TryFrom;

#[test]
fn validate_version() {
    // A version number that we expect to be always invalid
    const INVALID_VERSION: u8 = u8::MAX;

    let setup = basic_setup();

    let header = Header {
        version: MsgVersion(INVALID_VERSION),
        sender: setup.dealer,
        receiver: setup.signer1,
    };

    let validate = Validate::validate(&header);
    assert_eq!(validate, Err(MsgErr::WrongVersion));

    let validate = Validate::validate(&Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: setup.dealer,
        receiver: setup.signer1,
    })
    .err();

    assert_eq!(validate, None);
}

#[test]
fn validate_sender_receiver() {
    let setup = basic_setup();

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: setup.signer1,
        receiver: setup.signer1,
    };

    let validate = Validate::validate(&header);
    assert_eq!(validate, Err(MsgErr::SameSenderAndReceiver));
}

#[test]
fn validate_sharepackage() {
    let setup = basic_setup();
    let (shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let header = create_valid_header(setup.signer1, setup.signer2);

    let group_public = VerificationKey::from(
        verification_key::VerificationKey::try_from(shares[0].group_public.bytes).unwrap(),
    );
    let secret_share = Secret(shares[0].share.value.0.to_bytes());
    let mut share_commitment1: BTreeMap<ParticipantId, Commitment> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| (setup.signer1, Commitment::from(c.clone())))
        .collect();
    // this is ugly, merge this with the iteration above
    let share_commitment2: BTreeMap<ParticipantId, Commitment> = shares[1]
        .share
        .commitment
        .0
        .iter()
        .map(|c| (setup.signer2, Commitment::from(c.clone())))
        .collect();

    share_commitment1.extend(&share_commitment2);

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share: secret_share,
        share_commitment: share_commitment1.clone(),
    });
    let validate_payload = Validate::validate(&payload);
    let valid_payload = validate_payload.expect("a valid payload").clone();

    let message = Message {
        header,
        payload: valid_payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeDealer));

    // change the header
    let header = create_valid_header(setup.dealer, setup.aggregator);

    let message = Message {
        header,
        payload: valid_payload,
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    //
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share: secret_share,
        share_commitment: share_commitment2.clone(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(
        validate_payload,
        Err(MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS))
    );

    for i in 2..constants::MAX_SIGNERS as u64 + 2 {
        share_commitment1.insert(
            ParticipantId::Signer(i),
            share_commitment1.clone()[&setup.signer1],
        );
    }
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment: share_commitment1,
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::TooManyCommitments));
}

#[test]
fn serialize_sharepackage() {
    let setup = basic_setup();

    let (shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let header = create_valid_header(setup.dealer, setup.signer1);

    let group_public = VerificationKey::from(
        verification_key::VerificationKey::try_from(shares[0].group_public.bytes).unwrap(),
    );
    let secret_share = Secret(shares[0].share.value.0.to_bytes());
    let share_commitment: BTreeMap<ParticipantId, Commitment> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| (setup.signer1, Commitment::from(c.clone())))
        .collect();

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment: share_commitment.clone(),
    });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_bytes: Message = bincode::deserialize(&serialized_bytes).unwrap();
    assert_eq!(message, deserialized_bytes);

    let serialized_json = serde_json::to_string(&message).unwrap();
    let deserialized_json: Message = serde_json::from_str(serialized_json.as_str()).unwrap();
    assert_eq!(message, deserialized_json);

    // make sure the header fields are in the right order
    let header_serialized_bytes = bincode::serialize(&header).unwrap();
    serialize_header(header_serialized_bytes, setup.dealer, setup.signer1);

    // make sure the payload fields are in the right order
    let payload_serialized_bytes = bincode::serialize(&payload).unwrap();
    let deserialized_group_public: VerificationKey =
        bincode::deserialize(&payload_serialized_bytes[4..36]).unwrap();
    let deserialized_secret_share: Secret =
        bincode::deserialize(&payload_serialized_bytes[36..68]).unwrap();
    let deserialized_share_commitment: BTreeMap<ParticipantId, Commitment> =
        bincode::deserialize(&payload_serialized_bytes[68..payload_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_group_public, group_public);
    assert_eq!(deserialized_secret_share, secret_share);
    assert_eq!(deserialized_share_commitment, share_commitment);

    // make sure the message fields are in the right order
    let message_serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_header: Header =
        bincode::deserialize(&message_serialized_bytes[0..17]).unwrap();
    let deserialized_payload: Payload =
        bincode::deserialize(&message_serialized_bytes[17..message_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_header, header);
    assert_eq!(deserialized_payload, payload);
}

#[test]
fn validate_signingcommitments() {
    let mut setup = basic_setup();

    let (_nonce, commitment) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);

    let header = create_valid_header(setup.aggregator, setup.signer2);

    let payload = Payload::SigningCommitments(SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment[0].binding).to_bytes()),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeSigner));

    // change the header
    let header = create_valid_header(setup.signer1, setup.signer2);

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeAggergator));

    // change the header to valid
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signingcommitments() {
    let mut setup = basic_setup();

    let (_nonce, commitment) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let hiding = Commitment(jubjub::AffinePoint::from(commitment[0].hiding).to_bytes());
    let binding = Commitment(jubjub::AffinePoint::from(commitment[0].binding).to_bytes());

    let payload = Payload::SigningCommitments(SigningCommitments { hiding, binding });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_bytes: Message = bincode::deserialize(&serialized_bytes).unwrap();
    assert_eq!(message, deserialized_bytes);

    let serialized_json = serde_json::to_string(&message).unwrap();
    let deserialized_json: Message = serde_json::from_str(serialized_json.as_str()).unwrap();
    assert_eq!(message, deserialized_json);

    // make sure the header fields are in the right order
    let header_serialized_bytes = bincode::serialize(&header).unwrap();
    serialize_header(header_serialized_bytes, setup.aggregator, setup.signer1);

    // make sure the payload fields are in the right order
    let payload_serialized_bytes = bincode::serialize(&payload).unwrap();
    let deserialized_hiding: Commitment =
        bincode::deserialize(&payload_serialized_bytes[4..36]).unwrap();
    let deserialized_binding: Commitment =
        bincode::deserialize(&payload_serialized_bytes[36..68]).unwrap();
    assert_eq!(deserialized_hiding, hiding);
    assert_eq!(deserialized_binding, binding);

    // make sure the message fields are in the right order
    let message_serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_header: Header =
        bincode::deserialize(&message_serialized_bytes[0..17]).unwrap();
    let deserialized_payload: Payload =
        bincode::deserialize(&message_serialized_bytes[17..message_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_header, header);
    assert_eq!(deserialized_payload, payload);
}

#[test]
fn validate_signingpackage() {
    let mut setup = basic_setup();

    let (_nonce, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);

    let header = create_valid_header(setup.signer1, setup.signer2);

    let signing_commitment1 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment1[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment1[0].binding).to_bytes()),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment2[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment2[0].binding).to_bytes()),
    };

    let mut signing_commitments = BTreeMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(setup.signer1, signing_commitment1.clone());

    // try with only 1 commitment
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(
        validate_payload,
        Err(MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS))
    );

    // add too many commitments
    let mut big_signing_commitments = BTreeMap::<ParticipantId, SigningCommitments>::new();
    for i in 0..constants::MAX_SIGNERS as u64 + 1 {
        big_signing_commitments.insert(ParticipantId::Signer(i), signing_commitment1.clone());
    }
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: big_signing_commitments,
        message: "hola".as_bytes().to_vec(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::TooManyCommitments));

    // add the other valid commitment
    signing_commitments.insert(setup.signer2, signing_commitment2);

    let big_message = [0u8; constants::ZCASH_MAX_PROTOCOL_MESSAGE_LEN + 1].to_vec();
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments,
        message: big_message,
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::MsgTooBig));

    let message = Message {
        header,
        payload: payload.clone(),
    };
    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeAggregator));

    // change header
    let header = create_valid_header(setup.aggregator, setup.dealer);

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let validate_message = Validate::validate(&Message { header, payload }).err();
    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signingpackage() {
    let mut setup = basic_setup();

    let (_nonce, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let signing_commitment1 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment1[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment1[0].binding).to_bytes()),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment2[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment2[0].binding).to_bytes()),
    };

    let mut signing_commitments = BTreeMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(setup.signer1, signing_commitment1.clone());
    signing_commitments.insert(setup.signer2, signing_commitment2.clone());

    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_bytes: Message = bincode::deserialize(&serialized_bytes).unwrap();
    assert_eq!(message, deserialized_bytes);

    let serialized_json = serde_json::to_string(&message).unwrap();
    let deserialized_json: Message = serde_json::from_str(serialized_json.as_str()).unwrap();
    assert_eq!(message, deserialized_json);

    // make sure the header fields are in the right order
    let header_serialized_bytes = bincode::serialize(&header).unwrap();
    serialize_header(header_serialized_bytes, setup.aggregator, setup.signer1);

    // make sure the payload fields are in the right order
    let payload_serialized_bytes = bincode::serialize(&payload).unwrap();

    let map_len_serialized: u32 = bincode::deserialize(&payload_serialized_bytes[0..12]).unwrap();
    assert_eq!(map_len_serialized, 2);

    // TODO: deserializing the entire HashMap brings problems
    let deserialized_participant_id_1: ParticipantId =
        bincode::deserialize(&payload_serialized_bytes[12..20]).unwrap();
    let deserialized_signing_commitment_1: SigningCommitments =
        bincode::deserialize(&payload_serialized_bytes[20..20 + 64]).unwrap();
    let deserialized_participant_id_2: ParticipantId =
        bincode::deserialize(&payload_serialized_bytes[20 + 64..20 + 64 + 8]).unwrap();
    let deserialized_signing_commitment_2: SigningCommitments =
        bincode::deserialize(&payload_serialized_bytes[20 + 64 + 8..20 + 128 + 8]).unwrap();
    let deserialized_message: Vec<u8> = bincode::deserialize(
        &payload_serialized_bytes
            [payload_serialized_bytes.len() - 12..payload_serialized_bytes.len()],
    )
    .unwrap();

    assert_eq!(deserialized_participant_id_1, setup.signer1);
    assert_eq!(deserialized_signing_commitment_1, signing_commitment1);
    assert_eq!(deserialized_participant_id_2, setup.signer2);
    assert_eq!(deserialized_signing_commitment_2, signing_commitment2);
    assert_eq!(deserialized_message, "hola".as_bytes().to_vec());

    // make sure the message fields are in the right order
    let message_serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_header: Header =
        bincode::deserialize(&message_serialized_bytes[0..17]).unwrap();
    let deserialized_payload: Payload =
        bincode::deserialize(&message_serialized_bytes[17..message_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_header, header);
    assert_eq!(deserialized_payload, payload);
}

#[test]
fn validate_signatureshare() {
    let mut setup = basic_setup();

    // signers and aggergator should have this data from `SharePackage`
    let (shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    // create a signing package, this is done in the aggregator side.
    // the signrs should have this data from `SigningPackage`
    let (nonce1, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce2, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);

    let signing_commitment1 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment1[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment1[0].binding).to_bytes()),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment2[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment2[0].binding).to_bytes()),
    };

    let mut signing_commitments = BTreeMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(setup.signer1, signing_commitment1.clone());
    signing_commitments.insert(setup.signer2, signing_commitment2.clone());

    let signing_package = frost::SigningPackage::from(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    // here we get started with the `SignatureShare` message.
    let signature_share = frost::sign(&signing_package, nonce1[0], &shares[0]).unwrap();

    // this header is invalid
    let header = create_valid_header(setup.aggregator, setup.signer1);

    let payload = Payload::SignatureShare(SignatureShare {
        signature: SignatureResponse(signature_share.signature.0.to_bytes()),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeSigner));

    // change the header, still invalid.
    let header = create_valid_header(setup.signer1, setup.signer2);

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeAggergator));

    // change the header to valid
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signatureshare() {
    let mut setup = basic_setup();

    // signers and aggergator should have this data from `SharePackage`
    let (shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    // create a signing package, this is done in the aggregator side.
    // the signers should have this data from `SigningPackage`
    let (nonce1, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce2, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);

    let signing_commitment1 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment1[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment1[0].binding).to_bytes()),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment2[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment2[0].binding).to_bytes()),
    };

    let mut signing_commitments = BTreeMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(setup.signer1, signing_commitment1.clone());
    signing_commitments.insert(setup.signer2, signing_commitment2.clone());

    let signing_package = frost::SigningPackage::from(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    // here we get started with the `SignatureShare` message.
    let signature_share = frost::sign(&signing_package, nonce1[0], &shares[0]).unwrap();

    // valid header
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let payload = Payload::SignatureShare(SignatureShare {
        signature: SignatureResponse(signature_share.signature.0.to_bytes()),
    });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_bytes: Message = bincode::deserialize(&serialized_bytes).unwrap();
    assert_eq!(message, deserialized_bytes);

    let serialized_json = serde_json::to_string(&message).unwrap();
    let deserialized_json: Message = serde_json::from_str(serialized_json.as_str()).unwrap();
    assert_eq!(message, deserialized_json);

    let header_serialized_bytes = bincode::serialize(&header).unwrap();
    serialize_header(header_serialized_bytes, setup.signer1, setup.aggregator);

    // make sure the message fields are in the right order
    let message_serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_header: Header =
        bincode::deserialize(&message_serialized_bytes[0..17]).unwrap();
    let deserialized_payload: Payload =
        bincode::deserialize(&message_serialized_bytes[17..message_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_header, header);
    assert_eq!(deserialized_payload, payload);
}

#[test]
fn validate_aggregatesignature() {
    let mut setup = basic_setup();

    // aggregator creates the shares and pubkeys for this round
    let (shares, pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let mut nonces: std::collections::HashMap<u64, Vec<frost::SigningNonces>> =
        std::collections::HashMap::with_capacity(setup.threshold as usize);
    let mut commitments: Vec<frost::SigningCommitments> =
        Vec::with_capacity(setup.threshold as usize);

    // aggregator generates nonces and signing commitments for each participant.
    for participant_index in 1..(setup.threshold + 1) {
        let (nonce, commitment) = frost::preprocess(1, participant_index as u64, &mut setup.rng);
        nonces.insert(participant_index as u64, nonce);
        commitments.push(commitment[0]);
    }

    // aggregator generates a signing package
    let mut signature_shares: Vec<frost::SignatureShare> =
        Vec::with_capacity(setup.threshold as usize);
    let message = "message to sign".as_bytes().to_vec();
    let signing_package = frost::SigningPackage {
        message: message.clone(),
        signing_commitments: commitments,
    };

    // each participant generates their signature share
    for (participant_index, nonce) in nonces {
        let share_package = shares
            .iter()
            .find(|share| participant_index == share.index)
            .unwrap();
        let nonce_to_use = nonce[0];
        let signature_share = frost::sign(&signing_package, nonce_to_use, share_package).unwrap();
        signature_shares.push(signature_share);
    }

    // aggregator generate the final signature
    let group_signature_res =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();

    // this header is invalid
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let payload = Payload::AggregateSignature(AggregateSignature {
        group_commitment: GroupCommitment::from(group_signature_res),
        schnorr_signature: SignatureResponse::from(group_signature_res),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeAggregator));

    // change the header, still invalid.
    let header = create_valid_header(setup.aggregator, setup.dealer);

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    // change the header to valid
    let header = create_valid_header(setup.aggregator, setup.signer1);

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_aggregatesignature() {
    let mut setup = basic_setup();

    // aggregator creates the shares and pubkeys for this round
    let (shares, pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let mut nonces: std::collections::HashMap<u64, Vec<frost::SigningNonces>> =
        std::collections::HashMap::with_capacity(setup.threshold as usize);
    let mut commitments: Vec<frost::SigningCommitments> =
        Vec::with_capacity(setup.threshold as usize);

    // aggregator generates nonces and signing commitments for each participant.
    for participant_index in 1..(setup.threshold + 1) {
        let (nonce, commitment) = frost::preprocess(1, participant_index as u64, &mut setup.rng);
        nonces.insert(participant_index as u64, nonce);
        commitments.push(commitment[0]);
    }

    // aggregator generates a signing package
    let mut signature_shares: Vec<frost::SignatureShare> =
        Vec::with_capacity(setup.threshold as usize);
    let message = "message to sign".as_bytes().to_vec();
    let signing_package = frost::SigningPackage {
        message: message.clone(),
        signing_commitments: commitments,
    };

    // each participant generates their signature share
    for (participant_index, nonce) in nonces {
        let share_package = shares
            .iter()
            .find(|share| participant_index == share.index)
            .unwrap();
        let nonce_to_use = nonce[0];
        let signature_share = frost::sign(&signing_package, nonce_to_use, share_package).unwrap();
        signature_shares.push(signature_share);
    }

    // aggregator generate the final signature
    let group_signature_res =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let payload = Payload::AggregateSignature(AggregateSignature {
        group_commitment: GroupCommitment::from(group_signature_res),
        schnorr_signature: SignatureResponse::from(group_signature_res),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_bytes: Message = bincode::deserialize(&serialized_bytes).unwrap();
    assert_eq!(message, deserialized_bytes);

    let serialized_json = serde_json::to_string(&message).unwrap();
    let deserialized_json: Message = serde_json::from_str(serialized_json.as_str()).unwrap();
    assert_eq!(message, deserialized_json);

    let header_serialized_bytes = bincode::serialize(&header).unwrap();
    serialize_header(header_serialized_bytes, setup.aggregator, setup.signer1);

    // make sure the message fields are in the right order
    let message_serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_header: Header =
        bincode::deserialize(&message_serialized_bytes[0..17]).unwrap();
    let deserialized_payload: Payload =
        bincode::deserialize(&message_serialized_bytes[17..message_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_header, header);
    assert_eq!(deserialized_payload, payload);
}

// utility functions

fn create_valid_header(sender: ParticipantId, receiver: ParticipantId) -> Header {
    Validate::validate(&Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: sender,
        receiver: receiver,
    })
    .expect("always a valid header")
    .clone()
}

fn serialize_header(
    header_serialized_bytes: Vec<u8>,
    sender: ParticipantId,
    receiver: ParticipantId,
) {
    let deserialized_version: MsgVersion =
        bincode::deserialize(&header_serialized_bytes[0..1]).unwrap();
    let deserialized_sender: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[1..9]).unwrap();
    let deserialized_receiver: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[9..17]).unwrap();
    assert_eq!(deserialized_version, constants::BASIC_FROST_SERIALIZATION);
    assert_eq!(deserialized_sender, sender);
    assert_eq!(deserialized_receiver, receiver);
}

struct Setup {
    rng: rand::rngs::ThreadRng,
    num_signers: u8,
    threshold: u8,
    dealer: ParticipantId,
    aggregator: ParticipantId,
    signer1: ParticipantId,
    signer2: ParticipantId,
}

fn basic_setup() -> Setup {
    Setup {
        rng: thread_rng(),
        num_signers: 3,
        threshold: 2,
        dealer: ParticipantId::Dealer,
        aggregator: ParticipantId::Aggregator,
        signer1: ParticipantId::Signer(1),
        signer2: ParticipantId::Signer(2),
    }
}

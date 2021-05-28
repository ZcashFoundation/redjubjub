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

    let signer1 = ParticipantId::Signer(0);
    let dealer = ParticipantId::Dealer;

    let header = Header {
        version: MsgVersion(INVALID_VERSION),
        sender: dealer.clone(),
        receiver: signer1.clone(),
    };

    let validate = Validate::validate(&header);
    assert_eq!(validate, Err(MsgErr::WrongVersion));

    let validate = Validate::validate(&Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: dealer,
        receiver: signer1,
    })
    .err();

    assert_eq!(validate, None);
}

#[test]
fn validate_sender_receiver() {
    let signer1 = ParticipantId::Signer(0);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: signer1,
    };

    let validate = Validate::validate(&header);
    assert_eq!(validate, Err(MsgErr::SameSenderAndReceiver));
}

#[test]
fn validate_sharepackage() {
    let mut rng = thread_rng();
    let numsigners = 3;
    let threshold = 2;
    let (shares, _pubkeys) = frost::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    let signer1 = ParticipantId::Signer(0);
    let signer2 = ParticipantId::Signer(1);
    let dealer = ParticipantId::Dealer;
    let aggregator = ParticipantId::Aggregator;

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: signer2.clone(),
    };
    let validate_header = Validate::validate(&header);
    let valid_header = validate_header.expect("a valid header").clone();

    let group_public = VerificationKey::from(
        verification_key::VerificationKey::try_from(shares[0].group_public.bytes).unwrap(),
    );
    let secret_share = Secret(shares[0].share.value.0.to_bytes());
    let mut share_commitment: Vec<Commitment> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| Commitment::from(c.clone()))
        .collect();

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share: secret_share.clone(),
        share_commitment: share_commitment.clone(),
    });
    let validate_payload = Validate::validate(&payload);
    let valid_payload = validate_payload.expect("a valid payload").clone();

    let message = Message {
        header: valid_header,
        payload: valid_payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeDealer));

    // change the header
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: dealer.clone(),
        receiver: aggregator.clone(),
    };
    let validate_header = Validate::validate(&header);
    let valid_header = validate_header.expect("a valid header").clone();

    let message = Message {
        header: valid_header,
        payload: valid_payload,
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    //
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share: secret_share.clone(),
        share_commitment: share_commitment.clone()[0..1].to_vec(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(
        validate_payload,
        Err(MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS))
    );

    share_commitment.resize(
        usize::try_from(constants::MAX_SIGNERS as u64 + 1).unwrap(),
        share_commitment.clone()[0],
    );
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment,
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::TooManyCommitments));
}

#[test]
fn serialize_sharepackage() {
    let mut rng = thread_rng();
    let numsigners = 3;
    let threshold = 2;
    let (shares, _pubkeys) = frost::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    let signer1 = ParticipantId::Signer(0);
    let dealer = ParticipantId::Dealer;

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: dealer.clone(),
        receiver: signer1.clone(),
    };

    let group_public = VerificationKey::from(
        verification_key::VerificationKey::try_from(shares[0].group_public.bytes).unwrap(),
    );
    let secret_share = Secret(shares[0].share.value.0.to_bytes());
    let share_commitment: Vec<Commitment> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| Commitment::from(c.clone()))
        .collect();

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment: share_commitment.clone(),
    });

    let message = Message {
        header: header.clone(),
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
    let deserialized_version: MsgVersion =
        bincode::deserialize(&header_serialized_bytes[0..1]).unwrap();
    let deserialized_sender: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[1..9]).unwrap();
    let deserialized_receiver: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[9..17]).unwrap();
    assert_eq!(deserialized_version, constants::BASIC_FROST_SERIALIZATION);
    assert_eq!(deserialized_sender, dealer.clone());
    assert_eq!(deserialized_receiver, signer1.clone());

    // make sure the payload fields are in the right order
    let payload_serialized_bytes = bincode::serialize(&payload).unwrap();
    let deserialized_group_public: VerificationKey =
        bincode::deserialize(&payload_serialized_bytes[4..36]).unwrap();
    let deserialized_secret_share: Secret =
        bincode::deserialize(&payload_serialized_bytes[36..68]).unwrap();
    let deserialized_share_commitment: Vec<Commitment> =
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
    let mut rng = thread_rng();
    let signer1 = ParticipantId::Signer(0);
    let signer2 = ParticipantId::Signer(1);
    let signer1_id = 0u64;
    let aggregator = ParticipantId::Aggregator;

    let (_nonce, commitment) = frost::preprocess(1, signer1_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer2.clone(),
    };

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
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: signer2.clone(),
    };

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeAggergator));

    // change the header to valid
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: aggregator.clone(),
    };

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signingcommitments() {
    let mut rng = thread_rng();

    let signer1 = ParticipantId::Signer(0);
    let signer1_id = 0u64;
    let aggregator = ParticipantId::Aggregator;

    let (_nonce, commitment) = frost::preprocess(1, signer1_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer1.clone(),
    };

    let hiding = Commitment(jubjub::AffinePoint::from(commitment[0].hiding).to_bytes());
    let binding = Commitment(jubjub::AffinePoint::from(commitment[0].binding).to_bytes());

    let payload = Payload::SigningCommitments(SigningCommitments { hiding, binding });

    let message = Message {
        header: header.clone(),
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
    let deserialized_version: MsgVersion =
        bincode::deserialize(&header_serialized_bytes[0..1]).unwrap();
    let deserialized_sender: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[1..9]).unwrap();
    let deserialized_receiver: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[9..17]).unwrap();
    assert_eq!(deserialized_version, constants::BASIC_FROST_SERIALIZATION);
    assert_eq!(deserialized_sender, aggregator.clone());
    assert_eq!(deserialized_receiver, signer1.clone());

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
    let mut rng = thread_rng();
    let signer1 = ParticipantId::Signer(0);
    let signer2 = ParticipantId::Signer(1);
    let signer1_id = 0u64;
    let signer2_id = 1u64;
    let aggregator = ParticipantId::Aggregator;
    let dealer = ParticipantId::Dealer;

    let (_nonce, commitment1) = frost::preprocess(1, signer1_id, &mut rng);
    let (_nonce, commitment2) = frost::preprocess(1, signer2_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: signer2.clone(),
    };

    let signing_commitment1 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment1[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment1[0].binding).to_bytes()),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment2[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment2[0].binding).to_bytes()),
    };

    let mut signing_commitments = HashMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(signer1.clone(), signing_commitment1.clone());

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
    let mut big_signing_commitments = HashMap::<ParticipantId, SigningCommitments>::new();
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
    signing_commitments.insert(signer2.clone(), signing_commitment2);

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
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: dealer.clone(),
    };

    let message = Message {
        header: header.clone(),
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer1.clone(),
    };

    let validate_message = Validate::validate(&Message { header, payload }).err();
    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signingpackage() {
    let mut rng = thread_rng();
    let signer1 = ParticipantId::Signer(0);
    let signer2 = ParticipantId::Signer(1);
    let signer1_id = 0u64;
    let signer2_id = 1u64;
    let aggregator = ParticipantId::Aggregator;

    let (_nonce, commitment1) = frost::preprocess(1, signer1_id, &mut rng);
    let (_nonce, commitment2) = frost::preprocess(1, signer2_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer1.clone(),
    };

    let signing_commitment1 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment1[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment1[0].binding).to_bytes()),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment2[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment2[0].binding).to_bytes()),
    };

    let mut signing_commitments = HashMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(signer1.clone(), signing_commitment1.clone());
    signing_commitments.insert(signer2.clone(), signing_commitment2.clone());

    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    let message = Message {
        header: header.clone(),
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
    let deserialized_version: MsgVersion =
        bincode::deserialize(&header_serialized_bytes[0..1]).unwrap();
    let deserialized_sender: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[1..9]).unwrap();
    let deserialized_receiver: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[9..17]).unwrap();
    assert_eq!(deserialized_version, constants::BASIC_FROST_SERIALIZATION);
    assert_eq!(deserialized_sender, aggregator.clone());
    assert_eq!(deserialized_receiver, signer1.clone());

    // make sure the payload fields are in the right order
    let _payload_serialized_bytes = bincode::serialize(&payload).unwrap();
    //let _map_len_serialized: u64 = bincode::deserialize(&payload_serialized_bytes[0..8]).unwrap();

    /*
    // TODO: deserializing the entire HashMap brings problems

    let _deserialized_participant_id_1: ParticipantId =
        bincode::deserialize(&payload_serialized_bytes[0..8]).unwrap();
    let _deserialized_signing_commitment_1: SigningCommitments =
        bincode::deserialize(&payload_serialized_bytes[8..8 + 64]).unwrap();
    let _deserialized_participant_id_2: ParticipantId =
        bincode::deserialize(&payload_serialized_bytes[8 + 64..8 + 64 + 8]).unwrap();
    let _deserialized_signing_commitment_2: SigningCommitments =
        bincode::deserialize(&payload_serialized_bytes[8 + 64 + 8..8 + 128 + 8]).unwrap();
    let deserialized_message: Vec<u8> = bincode::deserialize(
        &payload_serialized_bytes[8 + 128 + 8..payload_serialized_bytes.len()],
    )
    .unwrap();


    // TODO: We can't gauarantee the order of the entiries in the hashmap so don't test them by now.
    assert_eq!(deserialized_message, "hola".as_bytes().to_vec());
    */

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

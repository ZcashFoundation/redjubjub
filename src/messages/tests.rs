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

    let validate = Validate::validate(&Header {
        version: MsgVersion(INVALID_VERSION),
        sender: dealer.clone(),
        receiver: signer1.clone(),
    })
    .err()
    .expect("an error");

    assert_eq!(validate, MsgErr::WrongVersion);

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

    let validate = Validate::validate(&Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: signer1,
    })
    .err()
    .expect("an error");

    assert_eq!(validate, MsgErr::SameSenderAndReceiver);
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
    let secret_share = Scalar::from(shares[0].share.value.0);
    let mut share_commitment: Vec<AffinePoint> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| AffinePoint::from(c.clone()))
        .collect();

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment: share_commitment.clone(),
    });
    let validate_payload = Validate::validate(&payload);
    let valid_payload = validate_payload.expect("a valid payload").clone();

    let validate_message = Validate::validate(&Message {
        header: valid_header,
        payload: valid_payload.clone(),
    })
    .err()
    .expect("an error");
    assert_eq!(validate_message, MsgErr::SenderMustBeDealer);

    // change the header
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: dealer.clone(),
        receiver: aggregator.clone(),
    };
    let validate_header = Validate::validate(&header);
    let valid_header = validate_header.expect("a valid header").clone();

    let validate_message = Validate::validate(&Message {
        header: valid_header,
        payload: valid_payload,
    })
    .err()
    .expect("an error");
    assert_eq!(validate_message, MsgErr::ReceiverMustBeSigner);

    //
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment: share_commitment[0..1].to_vec(),
    });
    let validate_payload = Validate::validate(&payload).err().expect("an error");
    assert_eq!(
        validate_payload,
        MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS)
    );

    share_commitment.resize((constants::MAX_SIGNERS + 1).into(), share_commitment[0]);
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment,
    });
    let validate_payload = Validate::validate(&payload).err().expect("an error");
    assert_eq!(validate_payload, MsgErr::TooManyCommitments);
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
    let secret_share = Scalar::from(shares[0].share.value.0);
    let share_commitment: Vec<AffinePoint> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| AffinePoint::from(c.clone()))
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

    let serialized = serde_json::to_string(&message).unwrap();
    let deserialized: Message = serde_json::from_str(serialized.as_str()).unwrap();
    assert_eq!(message, deserialized);
}

#[test]
fn validate_signingcommitments() {
    let mut rng = thread_rng();
    let signer1 = ParticipantId::Signer(0);
    let signer2 = ParticipantId::Signer(1);
    let signer1_id = 0u8;
    let aggregator = ParticipantId::Aggregator;

    let (_nonce, commitment) = frost::preprocess(1, signer1_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer2.clone(),
    };

    let payload = Payload::SigningCommitments(SigningCommitments {
        hiding: AffinePoint::from(commitment[0].hiding),
        binding: AffinePoint::from(commitment[0].binding),
    });

    let validate_message = Validate::validate(&Message {
        header,
        payload: payload.clone(),
    })
    .err()
    .expect("an error");
    assert_eq!(validate_message, MsgErr::SenderMustBeSigner);

    // change the header
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: signer1.clone(),
        receiver: signer2.clone(),
    };

    let validate_message = Validate::validate(&Message {
        header,
        payload: payload.clone(),
    })
    .err()
    .expect("an error");
    assert_eq!(validate_message, MsgErr::ReceiverMustBeAggergator);

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
    let signer1_id = 0u8;
    let aggregator = ParticipantId::Aggregator;

    let (_nonce, commitment) = frost::preprocess(1, signer1_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer1.clone(),
    };

    let payload = Payload::SigningCommitments(SigningCommitments {
        hiding: AffinePoint::from(commitment[0].hiding),
        binding: AffinePoint::from(commitment[0].binding),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let serialized = serde_json::to_string(&message).unwrap();
    let deserialized: Message = serde_json::from_str(serialized.as_str()).unwrap();
    assert_eq!(message, deserialized);
}

#[test]
fn validate_signingpackage() {
    let mut rng = thread_rng();
    let signer1 = ParticipantId::Signer(0);
    let signer2 = ParticipantId::Signer(1);
    let signer1_id = 0u8;
    let signer2_id = 1u8;
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
        hiding: AffinePoint::from(commitment1[0].hiding),
        binding: AffinePoint::from(commitment1[0].binding),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: AffinePoint::from(commitment2[0].hiding),
        binding: AffinePoint::from(commitment2[0].binding),
    };

    let mut signing_commitments = HashMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(signer1.clone(), signing_commitment1.clone());

    // try with only 1 commitment
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });
    let validate_payload = Validate::validate(&payload).err().expect("an error");
    assert_eq!(
        validate_payload,
        MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS)
    );

    // add too many commitments
    let mut big_signing_commitments = HashMap::<ParticipantId, SigningCommitments>::new();
    for i in 0..constants::MAX_SIGNERS + 1 {
        big_signing_commitments.insert(ParticipantId::Signer(i), signing_commitment1.clone());
    }
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: big_signing_commitments,
        message: "hola".as_bytes().to_vec(),
    });
    let validate_payload = Validate::validate(&payload).err().expect("an error");
    assert_eq!(validate_payload, MsgErr::TooManyCommitments);

    // add the other valid commitment
    signing_commitments.insert(signer2.clone(), signing_commitment2);

    let big_message = [0u8; constants::ZCASH_MAX_PROTOCOL_MESSAGE_LEN + 1].to_vec();
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments,
        message: big_message,
    });
    let validate_payload = Validate::validate(&payload).err().expect("an error");
    assert_eq!(validate_payload, MsgErr::MsgTooBig);

    let validate_message = Validate::validate(&Message {
        header,
        payload: payload.clone(),
    })
    .err()
    .expect("an error");
    assert_eq!(validate_message, MsgErr::SenderMustBeAggregator);

    // change header
    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: dealer.clone(),
    };
    let validate_message = Validate::validate(&Message {
        header: header.clone(),
        payload: payload.clone(),
    })
    .err()
    .expect("an error");
    assert_eq!(validate_message, MsgErr::ReceiverMustBeSigner);

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
    let signer1_id = 0u8;
    let signer2_id = 1u8;
    let aggregator = ParticipantId::Aggregator;

    let (_nonce, commitment1) = frost::preprocess(1, signer1_id, &mut rng);
    let (_nonce, commitment2) = frost::preprocess(1, signer2_id, &mut rng);

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: aggregator.clone(),
        receiver: signer1.clone(),
    };

    let signing_commitment1 = SigningCommitments {
        hiding: AffinePoint::from(commitment1[0].hiding),
        binding: AffinePoint::from(commitment1[0].binding),
    };
    let signing_commitment2 = SigningCommitments {
        hiding: AffinePoint::from(commitment2[0].hiding),
        binding: AffinePoint::from(commitment2[0].binding),
    };

    let mut signing_commitments = HashMap::<ParticipantId, SigningCommitments>::new();
    signing_commitments.insert(signer1.clone(), signing_commitment1.clone());
    signing_commitments.insert(signer2.clone(), signing_commitment2.clone());

    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let serialized = serde_json::to_string(&message).unwrap();
    let deserialized: Message = serde_json::from_str(serialized.as_str()).unwrap();
    assert_eq!(message, deserialized);
}

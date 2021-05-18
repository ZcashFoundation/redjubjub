use rand::thread_rng;

use super::*;

use crate::messages::validate::{MsgErr, Validate};

use crate::frost;

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

    let secret_share = Scalar::from(shares[0].share.value.0);
    let mut share_commitment: Vec<AffinePoint> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| AffinePoint::from(c.clone()))
        .collect();
    let group_public = VerificationKey::try_from(shares[0].group_public.bytes).unwrap();

    let payload = Payload::SharePackage(SharePackage {
        secret_share,
        share_commitment: share_commitment.clone(),
        group_public,
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
        secret_share,
        share_commitment: share_commitment[0..1].to_vec(),
        group_public,
    });
    let validate_payload = Validate::validate(&payload).err().expect("an error");
    assert_eq!(
        validate_payload,
        MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS)
    );

    share_commitment.resize((constants::MAX_SIGNERS + 1).into(), share_commitment[0]);
    let payload = Payload::SharePackage(SharePackage {
        secret_share,
        share_commitment,
        group_public,
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

    let secret_share = Scalar::from(shares[0].share.value.0);
    let share_commitment: Vec<AffinePoint> = shares[0]
        .share
        .commitment
        .0
        .iter()
        .map(|c| AffinePoint::from(c.clone()))
        .collect();
    let group_public = VerificationKey::try_from(shares[0].group_public.bytes).unwrap();

    let payload = Payload::SharePackage(SharePackage {
        secret_share,
        share_commitment: share_commitment.clone(),
        group_public,
    });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let serialized = serde_json::to_string(&message).unwrap();
    let deserialized: Message = serde_json::from_str(serialized.as_str()).unwrap();
    assert_eq!(message, deserialized);
}

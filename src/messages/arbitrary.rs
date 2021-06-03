use proptest::{
    arbitrary::{any, Arbitrary},
    array,
    prelude::*,
};

use super::*;

impl Arbitrary for Message {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Header>(), any::<Payload>())
            .prop_map(|(header, payload)| Message { header, payload })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for Header {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<MsgVersion>(),
            any::<ParticipantId>(),
            any::<ParticipantId>(),
        )
            .prop_filter(
                "Sender and receiver participant IDs can not be the same",
                |(_, sender, receiver)| sender != receiver,
            )
            .prop_map(|(version, sender, receiver)| Header {
                version: version,
                sender: sender,
                receiver: receiver,
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for Payload {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (any::<SharePackage>()).prop_map(Payload::SharePackage),
            (any::<SigningCommitments>()).prop_map(Payload::SigningCommitments),
            (any::<SigningPackage>()).prop_map(Payload::SigningPackage),
            (any::<SignatureShare>()).prop_map(Payload::SignatureShare),
            (any::<AggregateSignature>()).prop_map(Payload::AggregateSignature),
        ]
        .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for SharePackage {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<VerificationKey>(),
            any::<Secret>(),
            any::<BTreeMap<ParticipantId, Commitment>>(),
        )
            .prop_map(
                |(group_public, secret_share, share_commitment)| SharePackage {
                    group_public,
                    secret_share,
                    share_commitment,
                },
            )
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for SigningCommitments {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Commitment>(), any::<Commitment>())
            .prop_map(|(hiding, binding)| SigningCommitments { hiding, binding })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for SigningPackage {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<BTreeMap<ParticipantId, SigningCommitments>>(),
            any::<Vec<u8>>(),
        )
            .prop_map(|(signing_commitments, message)| SigningPackage {
                signing_commitments,
                message,
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for SignatureShare {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<SignatureResponse>())
            .prop_map(|signature| SignatureShare { signature })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for AggregateSignature {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<GroupCommitment>(), any::<SignatureResponse>())
            .prop_map(|(group_commitment, schnorr_signature)| AggregateSignature {
                group_commitment,
                schnorr_signature,
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for MsgVersion {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        Just(constants::BASIC_FROST_SERIALIZATION).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for ParticipantId {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (u64::MIN..=constants::MAX_SIGNER_PARTICIPANT_ID).prop_map(ParticipantId::Signer),
            Just(ParticipantId::Dealer),
            Just(ParticipantId::Aggregator),
        ]
        .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for VerificationKey {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_map(VerificationKey)
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for Secret {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>()).prop_map(Secret).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for Commitment {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>()).prop_map(Commitment).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for SignatureResponse {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_map(SignatureResponse)
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for GroupCommitment {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        array::uniform32(any::<u8>())
            .prop_map(GroupCommitment)
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

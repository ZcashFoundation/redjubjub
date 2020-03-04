use futures::prelude::*;
use redjubjub::{frost::*, PublicKey, PublicKeyBytes, Signature, SpendAuth};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

type SignResult = Result<Signature<SpendAuth>, aggregator::Error>;
type SignRequest = (&'static [u8], oneshot::Sender<SignResult>);

async fn run_aggregator(
    // this could be a good reason to split out the share_id from config
    _num_shares: usize,
    threshold: usize,
    mut request_rx: mpsc::Receiver<SignRequest>,
    message_tx: watch::Sender<Option<(&'static [u8], SigningParticipants)>>,
    mut commitment_share_rx: mpsc::Receiver<signer::CommitmentShare>,
    commitment_tx: watch::Sender<Option<aggregator::Commitment>>,
    mut response_share_rx: mpsc::Receiver<signer::ResponseShare>,
) {
    while let Some((msg, response)) = request_rx.next().await {
        let participants = (0..threshold).collect::<Vec<usize>>();
        let state = aggregator::begin_sign(participants.clone());

        // XXX check whether we need to send the participants list.
        message_tx
            .broadcast(Some((msg, participants)))
            .expect("message broadcast should succeed");

        let (state, commitment) = state
            .recv(
                (&mut commitment_share_rx)
                    .take(threshold)
                    .collect::<Vec<_>>()
                    .await
                    .into_iter(),
            )
            .expect("must have received all required commitments");

        commitment_tx
            .broadcast(Some(commitment))
            .expect("commitment broadcast should succeed");

        let sig_result = state.recv(
            (&mut response_share_rx)
                .take(threshold)
                .collect::<Vec<_>>()
                .await
                .into_iter(),
        );

        let _ = response.send(sig_result);
    }
}

async fn run_party(
    config: Config,
    mut start_rx: watch::Receiver<()>,
    keygen_commitments_tx: broadcast::Sender<keygen::Commitment>,
    keygen_shares_tx: broadcast::Sender<keygen::Share>,
    mut pubkey_tx: mpsc::Sender<PublicKey<SpendAuth>>,
    mut signing_message_rx: watch::Receiver<Option<(&'static [u8], SigningParticipants)>>,
    mut signing_commitment_share_tx: mpsc::Sender<signer::CommitmentShare>,
    mut signing_commitment_rx: watch::Receiver<Option<aggregator::Commitment>>,
    mut signing_response_share_tx: mpsc::Sender<signer::ResponseShare>,
) {
    let keygen_commitments_rx = keygen_commitments_tx.subscribe();
    let keygen_shares_rx = keygen_shares_tx.subscribe();

    // We need to ensure that no task starts broadcasting until all
    // parties' tasks' broadcast receivers have been constructed.
    let _ = start_rx.recv().await;

    let (state, keygen_commitment) = keygen::begin_keygen(config.clone());

    keygen_commitments_tx
        .send(keygen_commitment)
        .expect("must be able to broadcast commitments");

    let (state, keygen_share) = state
        .recv(
            keygen_commitments_rx
                .take(config.num_shares)
                .try_collect::<Vec<_>>()
                .await
                .expect("receiving broadcasts should not fail")
                .into_iter(),
        )
        .expect("must have received all required commitments");

    keygen_shares_tx
        .send(keygen_share)
        .expect("must be able to broadcast keygen share");

    let mut share = state
        .recv(
            keygen_shares_rx
                .take(config.num_shares)
                .try_collect::<Vec<_>>()
                .await
                .expect("receiving broadcasts should not fail")
                .into_iter(),
        )
        .expect("key generation should succeed");

    pubkey_tx
        .send((&share).into())
        .await
        .expect("must be able to report public key");

    // Now receive messages from the aggregator and do the signing protocol.
    while let Some(Some((msg, participants))) = signing_message_rx.next().await {
        // Check whether we are participating in signing
        if !participants.contains(&config.share_id) {
            continue;
        }

        // here is where we could check the message contents.
        // instead, blindly sign whatever we get! yolo

        // XXX do we need to pass in participants here?
        let (state, commitment_share) = share
            .begin_sign(msg, participants)
            .expect("XXX try to remember why this is fallible??");

        signing_commitment_share_tx
            .send(commitment_share)
            .await
            .expect("sending commitment share should succeed");

        let response_share = state.recv(
            signing_commitment_rx
                .next()
                .await
                .expect("broadcast channel should not close")
                .expect("should not have dummy value to work around tokio defaults"),
        );

        signing_response_share_tx
            .send(response_share)
            .await
            .expect("sending response share should succeed");
    }
}

#[tokio::test]
async fn keygen_and_sign() {
    let (start_tx, mut start_rx) = watch::channel(());
    let _ = start_rx.recv().await;

    let num_shares = 10;
    let threshold = 7;

    // Here we have a lot of channels because we create one channel
    // for each message type, instead of doing serialization.
    let (keygen_commitments_tx, _) = broadcast::channel(num_shares);
    let (keygen_shares_tx, _) = broadcast::channel(num_shares);

    let (pubkey_tx, pubkey_rx) = mpsc::channel(num_shares);

    // Somewhat unintuitive tokio behavior: `watch` channels
    // have a default value, so we set the default to None
    // and then pull it out, so that recv calls to (any clones of)
    // the channel wait for the *next* value.
    let (signing_message_tx, mut signing_message_rx) = watch::channel(None);
    let _ = signing_message_rx.recv().await;
    let (signing_commitment_share_tx, signing_commitment_share_rx) = mpsc::channel(num_shares);

    let (signing_commitment_tx, mut signing_commitment_rx) = watch::channel(None);
    let _ = signing_commitment_rx.recv().await;
    let (signing_response_share_tx, signing_response_share_rx) = mpsc::channel(num_shares);

    // We need to hold on to the JoinHandle from each party's task to propagate
    // panics.
    let mut task_handles = Vec::new();

    // construct an aggregator that communicates with the party tasks

    let (mut request_tx, request_rx) = mpsc::channel(1);

    task_handles.push(tokio::spawn(run_aggregator(
        num_shares,
        threshold,
        request_rx,
        signing_message_tx,
        signing_commitment_share_rx,
        signing_commitment_tx,
        signing_response_share_rx,
    )));

    for share_id in 0..num_shares {
        let handle = tokio::spawn(run_party(
            Config {
                num_shares,
                threshold,
                share_id,
            },
            start_rx.clone(),
            keygen_commitments_tx.clone(),
            keygen_shares_tx.clone(),
            pubkey_tx.clone(),
            signing_message_rx.clone(),
            signing_commitment_share_tx.clone(),
            signing_commitment_rx.clone(),
            signing_response_share_tx.clone(),
        ));

        task_handles.push(handle);
    }

    // Signal all tasks to start running the protocol.
    start_tx
        .broadcast(())
        .expect("send broadcast should succeed");

    let all_pubkeys = pubkey_rx.take(num_shares).collect::<Vec<_>>().await;
    let pubkey = all_pubkeys[0];

    // Since we're testing, let's enforce consistency
    // in pubkey generation
    for pk in &all_pubkeys {
        assert_eq!(PublicKeyBytes::from(*pk), PublicKeyBytes::from(pubkey));
    }

    // request signing...

    for msg in &[b"AAA", b"BBB", b"CCC"] {
        let (tx, rx) = oneshot::channel();
        request_tx
            .send((msg.as_ref(), tx))
            .await
            .expect("sending sign request should succeed");

        match rx.await {
            Ok(Ok(sig)) => {
                assert!(pubkey.verify(msg.as_ref(), &sig).is_ok());
            }
            Ok(Err(e)) => panic!("got error {}", e),
            Err(e) => panic!("got error {}", e),
        }
    }

    // We only have one sender handle, so dropping it drops all sender handles
    // and closes the channel. This *should* cause all tasks to shut down
    // cleanly.
    drop(request_tx);

    // Check that all tasks shut down without errors.
    for handle in task_handles.into_iter() {
        assert!(handle.await.is_ok());
    }
}

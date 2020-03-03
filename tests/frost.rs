use futures::prelude::*;
use redjubjub::{frost::*, Signature, SpendAuth};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

type SignResult = Result<Signature<SpendAuth>, aggregator::Error>;
type SignRequest = (&'static [u8], oneshot::Sender<SignResult>);

async fn run_aggregator(
    // this could be a good reason to split out the share_id from config
    _num_parties: usize,
    _threshold: usize,
    _request_rx: mpsc::Receiver<SignRequest>,
    _message_tx: watch::Sender<Option<(&'static [u8], SigningParticipants)>>,
    _commitment_share_rx: mpsc::Receiver<signer::CommitmentShare>,
    _commitment_tx: watch::Sender<Option<aggregator::Commitment>>,
    _response_share_rx: mpsc::Receiver<signer::ResponseShare>,
) {
    unimplemented!();
}

async fn run_party(
    config: Config,
    mut start_rx: watch::Receiver<()>,
    keygen_commitments_tx: broadcast::Sender<keygen::Commitment>,
    keygen_shares_tx: broadcast::Sender<keygen::Share>,
    _signing_message_rx: watch::Receiver<Option<(&'static [u8], SigningParticipants)>>,
    _signing_commitment_share_tx: mpsc::Sender<signer::CommitmentShare>,
    _signing_commitment_rx: watch::Receiver<Option<aggregator::Commitment>>,
    _signing_response_share_tx: mpsc::Sender<signer::ResponseShare>,
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

    let _share = state
        .recv(
            keygen_shares_rx
                .take(config.num_shares)
                .try_collect::<Vec<_>>()
                .await
                .expect("receiving broadcasts should not fail")
                .into_iter(),
        )
        .expect("key generation should succeed");

    // Now receive messages from the aggregator and do the signing protocol.
    unimplemented!();
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

    // request signing...

    // check signatures...

    // check no panics...

    for handle in task_handles.into_iter() {
        assert!(handle.await.is_ok());
    }
}

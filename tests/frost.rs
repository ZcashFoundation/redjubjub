use redjubjub::frost::*;

#[tokio::test]
async fn keygen_and_sign() {
    use futures::prelude::*;
    use tokio::sync::{broadcast, watch};

    let (start_tx, mut start_rx) = watch::channel(());
    let _ = start_rx.recv().await;

    let num_shares = 10;
    let threshold = 7;

    let (commitments_tx, _) = broadcast::channel(num_shares);
    let (keygen_shares_tx, _) = broadcast::channel(num_shares);

    // We need to hold on to the JoinHandle from each party's task to propagate
    // panics.
    let mut task_handles = Vec::new();

    // construct an aggregator that communicates with the party tasks

    for share_id in 0..num_shares {
        // Create local copies of channel handles to move into the task.
        // Here we have a lot of channels because we create one channel
        // for each message type, instead of doing serialization.
        let mut start_rx = start_rx.clone();
        let commitments_tx = commitments_tx.clone();
        let commitments_rx = commitments_tx.subscribe();
        let keygen_shares_tx = keygen_shares_tx.clone();
        let keygen_shares_rx = keygen_shares_tx.subscribe();
        let handle = tokio::spawn(async move {
            // We need to ensure that no task starts broadcasting until all
            // tasks' broadcast receivers have been constructed.
            let _ = start_rx.recv().await;

            let config = Config {
                num_shares,
                threshold,
                share_id,
            };

            let (state, commitment) = keygen::begin_keygen(config.clone());

            commitments_tx
                .send(commitment)
                .expect("must be able to broadcast commitments");

            let (state, keygen_share) = state
                .recv(
                    commitments_rx
                        .take(num_shares)
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
                        .take(num_shares)
                        .try_collect::<Vec<_>>()
                        .await
                        .expect("receiving broadcasts should not fail")
                        .into_iter(),
                )
                .expect("key generation should succeed");

            // Now receive messages from the aggregator and do the signing protocol.
            unimplemented!();
        });

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

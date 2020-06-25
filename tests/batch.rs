use rand::thread_rng;

use redjubjub::*;

#[test]
fn batch_verify() {
    let rng = thread_rng();
    let mut batch = batch::Verifier::<SpendAuth>::new();
    for _ in 0..32 {
        let sk = SigningKey::<SpendAuth>::new(rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(rng, &msg[..]);
        batch.queue((vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

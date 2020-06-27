use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rand::thread_rng;
use redjubjub::*;
use std::convert::TryFrom;

fn sigs_with_distinct_pubkeys() -> impl Iterator<Item = (VerificationKeyBytes, Signature)> {
    std::iter::repeat_with(|| {
        let sk = SigningKey::<SpendAuth>::new(thread_rng());
        let vk_bytes: VerificationKeyBytes = VerificationKey::from(&sk).into();
        let sig = sk.sign(thread_rng(), b"");
        (vk_bytes, sig)
    })
}

fn sigs_with_same_pubkey() -> impl Iterator<Item = (VerificationKeyBytes, Signature)> {
    let sk = SigningKey::<SpendAuth>::new(thread_rng());
    let vk_bytes: VerificationKeyBytes = VerificationKey::from(&sk).into();
    std::iter::repeat_with(move || {
        let sig = sk.sign(thread_rng(), b"");
        (vk_bytes, sig)
    })
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Verification");
    for n in [8usize, 16, 24, 32, 40, 48, 56, 64].iter() {
        group.throughput(Throughput::Elements(*n as u64));
        let sigs = sigs_with_distinct_pubkeys().take(*n).collect::<Vec<_>>();
        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    for (vk_bytes, sig) in sigs.iter() {
                        let _ =
                            VerificationKey::try_from(*vk_bytes).and_then(|vk| vk.verify(sig, b""));
                    }
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Signatures with Distinct Pubkeys", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::<SpendAuth>::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify(thread_rng())
                })
            },
        );
        let sigs = sigs_with_same_pubkey().take(*n).collect::<Vec<_>>();
        group.bench_with_input(
            BenchmarkId::new("Signatures with the Same Pubkey", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::<SpendAuth>::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify(thread_rng())
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_batch_verify);
criterion_main!(benches);
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use encrypted_message::{
    EncryptedMessage,
    strategy::{Deterministic, Randomized},
    config::{Config, Secret},
};
use rand::distributions::{Alphanumeric, DistString};

#[derive(Debug, Default)]
pub struct ConfigDeterministic;
impl Config for ConfigDeterministic {
    type Strategy = Deterministic;

    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
    }
}

#[derive(Debug, Default)]
pub struct ConfigRandomized;
impl Config for ConfigRandomized {
    type Strategy = Randomized;

    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
    }
}

fn encrypted_message(c: &mut Criterion) {
    // 32-byte payload.
    let payload = black_box(Alphanumeric.sample_string(&mut rand::thread_rng(), 32));

    c.bench_function("Encrypt 32-byte payload (Deterministic)", |b| b.iter(|| {
        EncryptedMessage::<_, ConfigDeterministic>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Encrypt 32-byte payload (Randomized)", |b| b.iter(|| {
        EncryptedMessage::<_, ConfigRandomized>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Decrypt 32-byte payload", |b| {
        let encrypted = EncryptedMessage::<_, ConfigRandomized>::encrypt(payload.clone()).unwrap();
        b.iter(|| encrypted.decrypt().unwrap())
    });
}

criterion_group!(benches, encrypted_message);
criterion_main!(benches);

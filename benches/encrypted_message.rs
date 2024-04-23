use criterion::{Criterion, black_box, criterion_group, criterion_main};
use encrypted_message::{
    EncryptedMessage,
    strategy::{Deterministic, Randomized},
    key_config::Secret,
};
use rand::distributions::{Alphanumeric, DistString};

#[derive(Debug, Default)]
pub struct KeyConfig;
impl encrypted_message::KeyConfig for KeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
    }
}

fn encrypted_message(c: &mut Criterion) {
    // 32-byte payload.
    let payload = black_box(Alphanumeric.sample_string(&mut rand::thread_rng(), 32));

    c.bench_function("Encrypt 32-byte payload (Deterministic)", |b| b.iter(|| {
        EncryptedMessage::<_, Deterministic, KeyConfig>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Encrypt 32-byte payload (Randomized)", |b| b.iter(|| {
        EncryptedMessage::<_, Randomized, KeyConfig>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Decrypt 32-byte payload", |b| {
        let encrypted = EncryptedMessage::<_, Deterministic, KeyConfig>::encrypt(payload.clone()).unwrap();
        b.iter(|| encrypted.decrypt().unwrap())
    });
}

criterion_group!(benches, encrypted_message);
criterion_main!(benches);

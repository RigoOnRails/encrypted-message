mod key_config;
use key_config::{DerivationEnabledKeyConfig, DerivationDisabledKeyConfig};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use encrypted_message::{EncryptedMessage, encryption_type::{Deterministic, Randomized}};
use rand::distributions::{Alphanumeric, DistString};

fn key_derivation_enabled(c: &mut Criterion) {
    // 32-byte payload.
    let payload = black_box(Alphanumeric.sample_string(&mut rand::thread_rng(), 32));

    c.bench_function("Encrypt Deterministic (32-byte payload; Key derivation enabled with 2^16 iterations)", |b| b.iter(|| {
        EncryptedMessage::<_, Deterministic, DerivationEnabledKeyConfig>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Encrypt Randomized (32-byte payload; Key derivation enabled with 2^16 iterations)", |b| b.iter(|| {
        EncryptedMessage::<_, Randomized, DerivationEnabledKeyConfig>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Decrypt (32-byte payload; Key derivation enabled with 2^16 iterations)", |b| {
        let encrypted = EncryptedMessage::<_, Deterministic, DerivationEnabledKeyConfig>::encrypt(payload.clone()).unwrap();
        b.iter(|| encrypted.decrypt().unwrap())
    });
}

fn key_derivation_disabled(c: &mut Criterion) {
    // 32-byte payload.
    let payload = black_box(Alphanumeric.sample_string(&mut rand::thread_rng(), 32));

    c.bench_function("Encrypt Deterministic (32-byte payload; Key derivation disabled)", |b| b.iter(|| {
        EncryptedMessage::<_, Deterministic, DerivationDisabledKeyConfig>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Encrypt Randomized (32-byte payload; Key derivation disabled)", |b| b.iter(|| {
        EncryptedMessage::<_, Randomized, DerivationDisabledKeyConfig>::encrypt(payload.clone()).unwrap()
    }));

    c.bench_function("Decrypt (32-byte payload; Key derivation disabled)", |b| {
        let encrypted = EncryptedMessage::<_, Deterministic, DerivationDisabledKeyConfig>::encrypt(payload.clone()).unwrap();
        b.iter(|| encrypted.decrypt().unwrap())
    });
}

criterion_group!(benches, key_derivation_enabled, key_derivation_disabled);
criterion_main!(benches);

use secrecy::SecretVec;

pub fn deterministic_keys() -> Vec<SecretVec<u8>> {
    let keys: Vec<_> = std::env::var("ENCRYPTION_DETERMINISTIC_KEYS")
        .expect("ENCRYPTION_DETERMINISTIC_KEYS must be set.")
        .split(',')
        .map(|key| key.to_owned().into_bytes().into())
        .collect();

    assert!(!keys.is_empty(), "ENCRYPTION_DETERMINISTIC_KEYS must not be empty.");

    keys
}

pub fn randomized_keys() -> Vec<SecretVec<u8>> {
    let keys: Vec<_> = std::env::var("ENCRYPTION_RANDOMIZED_KEYS")
        .expect("ENCRYPTION_RANDOMIZED_KEYS must be set.")
        .split(',')
        .map(|key| key.to_owned().into_bytes().into())
        .collect();

    assert!(!keys.is_empty(), "ENCRYPTION_RANDOMIZED_KEYS must not be empty.");

    keys
}

pub fn key_derivation_salt() -> SecretVec<u8> {
    std::env::var("ENCRYPTION_KEY_DERIVATION_SALT")
        .expect("ENCRYPTION_KEY_DERIVATION_SALT must be set.")
        .into_bytes()
        .into()
}

pub fn key_derivation_iterations() -> u32 {
    std::env::var("ENCRYPTION_KEY_DERIVATION_ITERATIONS").map(|iterations| {
        iterations.parse().expect("ENCRYPTION_KEY_DERIVATION_ITERATIONS must be an integer.")
    }).unwrap_or(2_u32.pow(16))
}

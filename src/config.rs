use secrecy::SecretVec;

pub fn deterministic_key() -> SecretVec<u8> {
    std::env::var("ENCRYPTION_DETERMINISTIC_KEY")
        .expect("ENCRYPTION_DETERMINISTIC_KEY must be set.")
        .into_bytes()
        .into()
}

pub fn randomized_key() -> SecretVec<u8> {
    std::env::var("ENCRYPTION_RANDOMIZED_KEY")
        .expect("ENCRYPTION_RANDOMIZED_KEY must be set.")
        .into_bytes()
        .into()
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

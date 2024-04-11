use once_cell::sync::Lazy;

pub struct Config {
    pub primary_key: Vec<u8>,
    pub deterministic_key: Vec<u8>,
    pub key_derivation_salt: Vec<u8>,
    pub key_derivation_iterations: u32,
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| Config {
    primary_key: {
        std::env::var("ENCRYPTION_PRIMARY_KEY")
            .expect("ENCRYPTION_PRIMARY_KEY must be set.")
            .into_bytes()
    },
    deterministic_key: {
        std::env::var("ENCRYPTION_DETERMINISTIC_KEY")
            .expect("ENCRYPTION_DETERMINISTIC_KEY must be set.")
            .into_bytes()
    },
    key_derivation_salt: {
        std::env::var("ENCRYPTION_KEY_DERIVATION_SALT")
            .expect("ENCRYPTION_KEY_DERIVATION_SALT must be set.")
            .into_bytes()
    },
    key_derivation_iterations: {
        std::env::var("ENCRYPTION_KEY_DERIVATION_ITERATIONS").map(|iterations| {
            iterations.parse().expect("ENCRYPTION_KEY_DERIVATION_ITERATIONS must be an integer.")
        }).unwrap_or(2_u32.pow(16))
    },
});

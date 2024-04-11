use once_cell::sync::Lazy;

struct Config {
    primary_key: String,
    deterministic_key: String,
    key_derivation_salt: String,
    key_derivation_iterations: u32,
}

static CONFIG: Lazy<Config> = Lazy::new(|| Config {
    primary_key: {
        std::env::var("ENCRYPTION_PRIMARY_KEY")
            .expect("ENCRYPTION_PRIMARY_KEY must be set.")
    },
    deterministic_key: {
        std::env::var("ENCRYPTION_DETERMINISTIC_KEY")
            .expect("ENCRYPTION_DETERMINISTIC_KEY must be set.")
    },
    key_derivation_salt: {
        std::env::var("ENCRYPTION_KEY_DERIVATION_SALT")
            .expect("ENCRYPTION_KEY_DERIVATION_SALT must be set.")
    },
    key_derivation_iterations: {
        std::env::var("ENCRYPTION_KEY_DERIVATION_ITERATIONS").map(|iterations| {
            iterations.parse().expect("ENCRYPTION_KEY_DERIVATION_ITERATIONS must be an integer.")
        }).unwrap_or(2_u32.pow(16))
    },
});

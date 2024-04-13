use secrecy::Secret;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

/// Derives a new 256-bit key from a raw key using the
/// key derivation salt & iterations provided.
pub fn derive_from(key: &[u8], salt: &[u8], iterations: u32) -> Secret<[u8; 32]> {
    pbkdf2_hmac_array::<Sha256, 32>(key, salt, iterations).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::ExposeSecret as _;

    use crate::{Config, testing::DeterministicConfig, utilities::base64};

    #[test]
    fn test_derive_from() {
        let salt = DeterministicConfig::key_derivation_salt();
        let iterations = DeterministicConfig::KEY_DERIVATION_ITERATIONS;

        assert_eq!(
            *derive_from(b"Be1Px0bQu6SzkQubyuBusMJRC7GXO0vn", salt.expose_secret(), iterations).expose_secret(),
            *base64::decode("AKVUqJ2fBI9P53gHpWv+ywd3p8x/PRGB2qsR6G3bNpM=").unwrap(),
        );
    }
}

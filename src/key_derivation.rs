use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

use crate::config::CONFIG;

/// Derives a new 256-bit key from an existing key using the key derivation salt.
fn derive_from(key: &[u8]) -> [u8; 32] {
    let salt = CONFIG.key_derivation_salt.as_bytes();
    let iterations = CONFIG.key_derivation_iterations;

    pbkdf2_hmac_array::<Sha256, 32>(key, salt, iterations)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utilities::{base64, testing};

    #[test]
    fn test_derive_from() {
        testing::setup();

        assert_eq!(
            derive_from(b"Be1Px0bQu6SzkQubyuBusMJRC7GXO0vn"),
            *base64::decode("AKVUqJ2fBI9P53gHpWv+ywd3p8x/PRGB2qsR6G3bNpM=").unwrap(),
        );
    }
}

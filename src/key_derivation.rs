use secrecy::{Secret, SecretVec, ExposeSecret as _};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

/// Derives a new 256-bit key from an existing key using the key derivation salt.
pub fn derive_from(key: &[u8]) -> Secret<[u8; 32]> {
    let salt: SecretVec<u8> = {
        std::env::var("ENCRYPTED_MESSAGE_KEY_DERIVATION_SALT")
            .expect("ENCRYPTED_MESSAGE_KEY_DERIVATION_SALT must be set.")
            .into_bytes()
            .into()
    };

    let iterations = {
        std::env::var("ENCRYPTED_MESSAGE_KEY_DERIVATION_ITERATIONS").map(|iterations| {
            iterations.parse().expect("ENCRYPTED_MESSAGE_KEY_DERIVATION_ITERATIONS must be an integer.")
        }).unwrap_or(2_u32.pow(16))
    };

    pbkdf2_hmac_array::<Sha256, 32>(key, salt.expose_secret(), iterations).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{testing, utilities::base64};

    #[test]
    fn test_derive_from() {
        testing::setup();

        assert_eq!(
            *derive_from(b"Be1Px0bQu6SzkQubyuBusMJRC7GXO0vn").expose_secret(),
            *base64::decode("AKVUqJ2fBI9P53gHpWv+ywd3p8x/PRGB2qsR6G3bNpM=").unwrap(),
        );
    }
}

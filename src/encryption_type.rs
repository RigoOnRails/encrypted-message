use std::fmt::Debug;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng as _;

mod private {
    pub trait Sealed {}

    impl Sealed for super::Deterministic {}
    impl Sealed for super::Randomized {}
}

pub trait EncryptionType: private::Sealed + Debug {
    /// Generates a 96-bit nonce to encrypt a payload.
    fn generate_nonce_for(payload: &[u8], key: &[u8]) -> [u8; 12];
}

/// This encryption type is guaranteed to always produce the same nonce for a payload,
/// which will generate the same encrypted message every time.
///
/// This is useful for data you'd like to be able to query, as you can simply encrypt
/// the payload you're querying for & search for the same encrypted message.
#[derive(Debug, PartialEq, Eq)]
pub struct Deterministic;
impl EncryptionType for Deterministic {
    /// Generates a deterministic 96-bit nonce for the payload.
    fn generate_nonce_for(payload: &[u8], key: &[u8]) -> [u8; 12] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(payload);

        mac.finalize().into_bytes()[0..12].try_into().unwrap()
    }
}

/// This encryption type is guaranteed to always produce a random nonce, regardless of the payload,
/// which will generate a different encrypted message every time.
///
/// This encryption type improves security by making crypto-analysis of encrypted messages harder,
/// but makes querying them impossible.
#[derive(Debug, PartialEq, Eq)]
pub struct Randomized;
impl EncryptionType for Randomized {
    /// Generates a random 96-bit nonce for the payload.
    fn generate_nonce_for(_payload: &[u8], _key: &[u8]) -> [u8; 12] {
        let mut buffer = [0; 12];
        rand::thread_rng().fill(&mut buffer);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::ExposeSecret as _;

    use crate::{KeyConfig, utilities::base64, testing};

    mod deterministic {
        use super::*;

        #[test]
        fn nonce_is_deterministic() {
            let key = testing::DeterministicKeyConfig::key();
            let nonce = Deterministic::generate_nonce_for("rigo is cool".as_bytes(), key.expose_secret());

            // Test that the nonce is 12 bytes long.
            assert_eq!(nonce.len(), 12);

            // Test that the nonce is deterministic.
            assert_eq!(nonce, *base64::decode("3gCtDpVQCVyV6Pyg").unwrap());
        }
    }

    mod randomized {
        use super::*;

        #[test]
        fn nonce_is_randomized() {
            let payload = "much secret much secure".as_bytes();
            let key = testing::RandomizedKeyConfig::key();
            let first_nonce = Randomized::generate_nonce_for(payload, key.expose_secret());
            let second_nonce = Randomized::generate_nonce_for(payload, key.expose_secret());

            // Test that the nonces are 12 bytes long.
            assert_eq!(first_nonce.len(), 12);
            assert_eq!(second_nonce.len(), 12);

            // Test that the nonces never match, even when generated for the same payload.
            assert_ne!(first_nonce, second_nonce);
        }
    }
}

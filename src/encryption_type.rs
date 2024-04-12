use std::fmt::Debug;

use secrecy::{SecretVec, Secret, ExposeSecret as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng as _;

use crate::{key_derivation, config};

mod private {
    pub trait Sealed {}

    impl Sealed for super::Deterministic {}
    impl Sealed for super::Randomized {}
}

pub trait EncryptionType: private::Sealed + Debug {
    /// Returns the raw keys for the encryption type.
    fn raw_keys() -> Vec<SecretVec<u8>>;

    /// Generates a 96-bit nonce to encrypt a payload.
    fn generate_nonce_for(payload: &[u8]) -> [u8; 12];

    /// Returns the primary key, derived, for the encryption type.
    fn key() -> Secret<[u8; 32]> {
        key_derivation::derive_from(Self::raw_keys().remove(0).expose_secret())
    }
}

#[derive(Debug)]
pub struct Deterministic;
impl EncryptionType for Deterministic {
    fn raw_keys() -> Vec<SecretVec<u8>> {
        config::deterministic_keys()
    }

    fn generate_nonce_for(payload: &[u8]) -> [u8; 12] {
        let mut mac = Hmac::<Sha256>::new_from_slice(Self::key().expose_secret()).unwrap();
        mac.update(payload);

        mac.finalize().into_bytes()[0..12].try_into().unwrap()
    }
}

#[derive(Debug)]
pub struct Randomized;
impl EncryptionType for Randomized {
    fn raw_keys() -> Vec<SecretVec<u8>> {
        config::randomized_keys()
    }

    fn generate_nonce_for(_payload: &[u8]) -> [u8; 12] {
        let mut buffer = [0; 12];
        rand::thread_rng().fill(&mut buffer);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{testing, utilities::base64};

    mod deterministic {
        use super::*;

        #[test]
        fn nonce_is_deterministic() {
            testing::setup();

            let nonce = Deterministic::generate_nonce_for("rigo is cool".as_bytes());

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
            testing::setup();

            let payload = "much secret much secure".as_bytes();
            let first_nonce = Randomized::generate_nonce_for(payload);
            let second_nonce = Randomized::generate_nonce_for(payload);

            // Test that the nonces are 12 bytes long.
            assert_eq!(first_nonce.len(), 12);
            assert_eq!(second_nonce.len(), 12);

            // Test that the nonces never match, even when generated for the same payload.
            assert_ne!(first_nonce, second_nonce);
        }
    }
}

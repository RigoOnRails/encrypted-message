use std::fmt::Debug;

use secrecy::{SecretVec, Secret, ExposeSecret as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng as _;

use crate::key_derivation;

mod private {
    pub trait Sealed {}

    impl Sealed for super::Deterministic {}
    impl Sealed for super::Randomized {}
}

pub trait EncryptionType: private::Sealed + Debug + PartialEq + Eq {
    /// The environment variable that contains the keys for the encryption type.
    const KEYS_ENV_VAR: &'static str;

    /// Generates a 96-bit nonce to encrypt a payload.
    fn generate_nonce_for(payload: &[u8]) -> [u8; 12];

    /// Returns the raw keys for the encryption type.
    fn raw_keys() -> Vec<SecretVec<u8>> {
        let keys: Vec<_> = std::env::var(Self::KEYS_ENV_VAR)
            .unwrap_or_else(|_| panic!("{} must be set.", Self::KEYS_ENV_VAR))
            .split(',')
            .map(|key| key.to_owned().into_bytes().into())
            .collect();

        assert!(!keys.is_empty(), "{} must have a key present.", Self::KEYS_ENV_VAR);
        keys
    }

    /// Returns the primary key, derived, for the encryption type.
    fn key() -> Secret<[u8; 32]> {
        key_derivation::derive_from(Self::raw_keys().remove(0).expose_secret())
    }
}

/// This encryption type is guaranteed to always produce the same nonce for a payload,
/// which will generate the same encrypted message every time.
///
/// This is useful for data you'd like to be able to query, as you can simply encrypt
/// the payload you're querying for & search for the same encrypted message.
#[derive(Debug, PartialEq, Eq)]
pub struct Deterministic;
impl EncryptionType for Deterministic {
    const KEYS_ENV_VAR: &'static str = "ENCRYPTED_MESSAGE_DETERMINISTIC_KEYS";

    /// Generates a deterministic 96-bit nonce for the payload.
    fn generate_nonce_for(payload: &[u8]) -> [u8; 12] {
        let mut mac = Hmac::<Sha256>::new_from_slice(Self::key().expose_secret()).unwrap();
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
    const KEYS_ENV_VAR: &'static str = "ENCRYPTED_MESSAGE_RANDOMIZED_KEYS";

    /// Generates a random 96-bit nonce for the payload.
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
        fn returns_correct_raw_keys() {
            testing::setup();

            let keys = Deterministic::raw_keys()
                .into_iter()
                .map(|k| String::from_utf8(k.expose_secret().clone()).unwrap())
                .collect::<Vec<_>>();

            assert_eq!(keys, vec!["uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW", "tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt"]);
        }

        #[test]
        fn returns_correct_derived_key() {
            testing::setup();

            assert_eq!(
                *Deterministic::key().expose_secret(),
                *base64::decode("Zhw8+76eCgBrUQPFlbz1ajnWZII+6uF/6h0a3d3IU2s=").unwrap(),
            );
        }

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
        fn returns_correct_raw_keys() {
            testing::setup();

            let keys = Randomized::raw_keys()
                .into_iter()
                .map(|k| String::from_utf8(k.expose_secret().clone()).unwrap())
                .collect::<Vec<_>>();

            assert_eq!(keys, vec!["VDIVbMzI30DL0YBgxS4i360Ox22mixRA", "JHedIoHEwoJuyvqwTMacEGJ6Scsh6ltK"]);
        }

        #[test]
        fn returns_correct_derived_key() {
            testing::setup();

            assert_eq!(
                *Randomized::key().expose_secret(),
                *base64::decode("UzHAn57j9PblBH6uBQRh+4E0dOnhZvam5erBQEFY1TU=").unwrap(),
            );
        }

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

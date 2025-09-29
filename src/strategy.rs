//! All the encryption strategies that can be used with [`EncryptedMessage`](crate::EncryptedMessage).

use std::fmt::Debug;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ConfigError;

mod private {
    pub trait Sealed {}

    impl Sealed for super::Deterministic {}
    impl Sealed for super::Randomized {}
}

pub trait Strategy: private::Sealed + Debug {
    /// Generates a 192-bit nonce to encrypt a payload.
    fn generate_nonce(payload: &[u8], key: &[u8; 32]) -> Result<[u8; 24], ConfigError>;
}

/// This encryption strategy is guaranteed to always produce the same nonce for a payload,
/// which will generate the same encrypted message every time.
///
/// This is useful for data you'd like to be able to query, as you can simply encrypt
/// the payload you're querying for & search for the same encrypted message.
#[derive(Debug, PartialEq, Eq)]
pub struct Deterministic;
impl Strategy for Deterministic {
    /// Generates a deterministic 192-bit nonce for the payload.
    fn generate_nonce(payload: &[u8], key: &[u8; 32]) -> Result<[u8; 24], ConfigError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ConfigError::InvalidKeyLength)?;
        mac.update(payload);

        let digest = mac.finalize().into_bytes();
        let nonce = digest[0..24].try_into().unwrap_or_else(|_| {
            unreachable!("HMAC-SHA256 digests are 32 bytes long.")
        });

        Ok(nonce)
    }
}

/// This encryption strategy will produce a random nonce, regardless of the payload,
/// which will generate a different encrypted message every time.
///
/// This encryption strategy improves security by making crypto-analysis of encrypted messages harder,
/// but makes querying them without decrypting all data impossible.
#[derive(Debug, PartialEq, Eq)]
pub struct Randomized;
impl Strategy for Randomized {
    /// Generates a random 192-bit nonce for the payload.
    fn generate_nonce(_payload: &[u8], _key: &[u8; 32]) -> Result<[u8; 24], ConfigError> {
        Ok(rand::random())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::ExposeSecret;

    use crate::{
        config::Config,
        testing::{TestConfigDeterministic, TestConfigRandomized},
        utilities::base64,
    };

    mod deterministic {
        use super::*;

        #[test]
        fn nonce_is_deterministic() {
            let key = TestConfigDeterministic.primary_key().unwrap();
            let nonce = Deterministic::generate_nonce("rigo is cool".as_bytes(), key.expose_secret()).unwrap();

            // Test that the nonce is 24 bytes long.
            assert_eq!(nonce.len(), 24);

            // Test that the nonce is deterministic.
            assert_eq!(nonce, *base64::decode("Ts2jGkMEW9NFsQZXO+2BA60uExH5xfEe").unwrap());
        }
    }

    mod randomized {
        use super::*;

        #[test]
        fn nonce_is_randomized() {
            let payload = "much secret much secure".as_bytes();
            let key = TestConfigRandomized.primary_key().unwrap();
            let first_nonce = Randomized::generate_nonce(payload, key.expose_secret()).unwrap();
            let second_nonce = Randomized::generate_nonce(payload, key.expose_secret()).unwrap();

            // Test that the nonces are 24 bytes long.
            assert_eq!(first_nonce.len(), 24);
            assert_eq!(second_nonce.len(), 24);

            // Test that the nonces never match, even when generated for the same payload.
            assert_ne!(first_nonce, second_nonce);
        }
    }
}

//! ## Configuration
//!
//! First, you'll need to create a configuration type by implementing the [`Config`] trait.
//! If your configuration type implements the [`Default`] trait, you can use the shorthand methods
//! of the [`EncryptedMessage`] struct.
//!
//! The first key provided is considered the primary key, & is always used to encrypt new payloads.
//! The following keys are used in the order provided when the primary key can't decrypt a payload. This allows you to rotate keys.
//!
//! ```
//! use encrypted_message::{
//!     config::{Config, Secret, ExposeSecret},
//!     strategy::Randomized,
//! };
//!
//! #[derive(Debug, Default)]
//! struct EncryptionConfig;
//! impl Config for EncryptionConfig {
//!     type Strategy = Randomized;
//!
//!     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//!         Secret::new(std::env::var("ENCRYPTION_KEYS").unwrap())
//!             .expose_secret()
//!             .split(", ")
//!             .map(|hex_key| {
//!                 let mut key = [0; 32];
//!                 hex::decode_to_slice(hex_key, &mut key).unwrap();
//!
//!                 key.into()
//!             })
//!             .collect()
//!     }
//! }
//! ```
//!
//! You can generate secure 32-byte keys using the `openssl` command-line tool:
//! ```sh
//! openssl rand -hex 32
//! ```
//!
//! ## Encryption strategies
//!
//! Two encryption strategies are provided, [`Deterministic`](crate::strategy::Deterministic) & [`Randomized`](crate::strategy::Randomized).
//!
//! - [`Deterministic`](crate::strategy::Deterministic) encryption will always produce the same encrypted message for the same payload, allowing you to query encrypted data.
//! - [`Randomized`](crate::strategy::Randomized) encryption will always produce a different encrypted message for the same payload. More secure than [`Deterministic`](crate::strategy::Deterministic), but impossible to query without decrypting all data.
//!
//! It's recommended to use different keys for each encryption strategy.
//!
//! ## Defining encrypted fields
//!
//! You can now define your encrypted fields using the [`EncryptedMessage`] struct.
//! The first type parameter is the payload type, & the second is the configuration type.
//!
//! ```
//! # use encrypted_message::{config::{Config, Secret}, strategy::Randomized};
//! #
//! # #[derive(Debug, Default)]
//! # struct EncryptionConfig;
//! # impl Config for EncryptionConfig {
//! #     type Strategy = Randomized;
//! #
//! #     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//! #         vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
//! #     }
//! # }
//! #
//! use encrypted_message::EncryptedMessage;
//!
//! struct User {
//!     diary: EncryptedMessage<String, EncryptionConfig>,
//! }
//! ```
//!
//! ## Encrypting & decrypting payloads
//!
//! If your [`Config`] implements the [`Default`] trait (like above), you can use the shorthand methods:
//! ```
//! # use encrypted_message::{
//! #     EncryptedMessage,
//! #     config::{Config, Secret},
//! #     strategy::Randomized,
//! # };
//! #
//! # #[derive(Debug, Default)]
//! # struct EncryptionConfig;
//! # impl Config for EncryptionConfig {
//! #     type Strategy = Randomized;
//! #
//! #     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//! #         vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
//! #     }
//! # }
//! #
//! # struct User {
//! #     diary: EncryptedMessage<String, EncryptionConfig>,
//! # }
//! #
//! // Encrypt a user's diary.
//! let user = User {
//!     diary: EncryptedMessage::encrypt("Very personal stuff".to_string()).unwrap(),
//! };
//!
//! // Decrypt the user's diary.
//! let decrypted: String = user.diary.decrypt().unwrap();
//! ```
//!
//! If your [`Config`] depends on external data:
//! ```
//! use encrypted_message::{
//!     EncryptedMessage,
//!     config::{Config, Secret, ExposeSecret},
//!     strategy::Randomized,
//! };
//! use pbkdf2::pbkdf2_hmac_array;
//! use sha2::Sha256;
//!
//! #[derive(Debug)]
//! struct UserEncryptionConfig {
//!     user_password: Secret<String>,
//!     salt: Secret<String>,
//! }
//!
//! impl Config for UserEncryptionConfig {
//!     type Strategy = Randomized;
//!
//!     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//!         let raw_key = self.user_password.expose_secret().as_bytes();
//!         let salt = self.salt.expose_secret().as_bytes();
//!         vec![pbkdf2_hmac_array::<Sha256, 32>(raw_key, salt, 2_u32.pow(16)).into()]
//!     }
//! }
//!
//! struct User {
//!     diary: EncryptedMessage<String, UserEncryptionConfig>,
//! }
//!
//! // Define the user's encryption configuration.
//! let config = UserEncryptionConfig {
//!     user_password: "human-password-that-should-be-derived".to_string().into(),
//!     salt: "unique-salt".to_string().into(),
//! };
//!
//! // Encrypt a user's diary.
//! let user = User {
//!     diary: EncryptedMessage::encrypt_with_config("Very personal stuff".to_string(), &config).unwrap(),
//! };
//!
//! // Decrypt the user's diary.
//! let decrypted: String = user.diary.decrypt_with_config(&config).unwrap();
//! ```
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod config;
pub mod error;
pub mod strategy;

mod integrations;
mod utilities;

#[cfg(test)]
mod testing;

pub use crate::error::{ConfigError, EncryptionError, DecryptionError};

use std::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, AeadInPlace};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::strategy::Strategy;
use crate::config::Config;
use crate::utilities::base64;

/// Used to safely handle & transport encrypted data within your application.
/// It contains an encrypted payload, along with a nonce & tag that are
/// used in the encryption & decryption processes.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Json))]
#[cfg_attr(all(feature = "diesel", feature = "diesel-postgres"), diesel(sql_type = diesel::sql_types::Jsonb))]
pub struct EncryptedMessage<P: Debug + DeserializeOwned + Serialize, C: Config> {
    /// The base64-encoded & encrypted payload.
    #[serde(rename = "p")]
    payload: String,

    /// The headers stored with the encrypted payload.
    #[serde(rename = "h")]
    headers: EncryptedMessageHeaders,

    /// The payload type.
    #[serde(skip)]
    payload_type: PhantomData<P>,

    /// The configuration for the encrypted message.
    #[serde(skip)]
    config: PhantomData<C>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EncryptedMessageHeaders {
    /// The base64-encoded nonce used to encrypt the payload.
    #[serde(rename = "iv")]
    nonce: String,

    /// The base64-encoded auth tag used to verify the encrypted payload.
    #[serde(rename = "at")]
    tag: String,
}

impl<P: Debug + DeserializeOwned + Serialize, C: Config> EncryptedMessage<P, C> {
    /// Creates an [`EncryptedMessage`] from a payload, using the XChaCha20Poly1305 encryption cipher.
    ///
    /// # Errors
    ///
    /// - Returns an [`EncryptionError::Serialization`] error if the payload cannot be serialized into a JSON string.
    ///   See [`serde_json::to_vec`] for more information.
    pub fn encrypt_with_config(payload: P, config: &C) -> Result<Self, EncryptionError> {
        let payload = serde_json::to_vec(&payload)?;

        let key = config.primary_key()?;
        let nonce = C::Strategy::generate_nonce(&payload, key.expose_secret())?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|_| ConfigError::InvalidKeyLength)?;

        let mut buffer = payload;
        let tag = cipher.encrypt_in_place_detached(&nonce.into(), b"", &mut buffer).map_err(|_| EncryptionError::Encryption)?;

        Ok(EncryptedMessage {
            payload: base64::encode(buffer),
            headers: EncryptedMessageHeaders {
                nonce: base64::encode(nonce),
                tag: base64::encode(tag),
            },
            payload_type: PhantomData,
            config: PhantomData,
        })
    }

    /// Decrypts the payload of the [`EncryptedMessage`], trying all available keys in order until it finds one that works.
    ///
    /// # Errors
    ///
    /// - Returns a [`DecryptionError::Base64Decoding`] error if the base64-decoding of the payload, nonce, or tag fails.
    /// - Returns a [`DecryptionError::Decryption`] error if the payload cannot be decrypted with any of the available keys.
    /// - Returns a [`DecryptionError::Deserialization`] error if the payload cannot be deserialized into the expected type.
    ///   See [`serde_json::from_slice`] for more information.
    pub fn decrypt_with_config(&self, config: &C) -> Result<P, DecryptionError> {
        let nonce = base64::decode(&self.headers.nonce)?;
        let tag = base64::decode(&self.headers.tag)?;

        for key in config.keys() {
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|_| ConfigError::InvalidKeyLength)?;

            let mut buffer = Zeroizing::new(base64::decode(&self.payload)?);
            if cipher.decrypt_in_place_detached(nonce.as_slice().into(), b"", &mut buffer, tag.as_slice().into()).is_err() {
                continue;
            };

            return Ok(serde_json::from_slice(&buffer)?);
        }

        Err(DecryptionError::Decryption)
    }
}

impl<P: Debug + DeserializeOwned + Serialize, C: Config + Default> EncryptedMessage<P, C> {
    /// This method is a shorthand for [`EncryptedMessage::encrypt_with_config`],
    /// passing `&C::default()` as the configuration.
    pub fn encrypt(payload: P) -> Result<Self, EncryptionError> {
        Self::encrypt_with_config(payload, &C::default())
    }

    /// This method is a shorthand for [`EncryptedMessage::decrypt_with_config`],
    /// passing `&C::default()` as the configuration.
    pub fn decrypt(&self) -> Result<P, DecryptionError> {
        self.decrypt_with_config(&C::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    use crate::testing::{TestConfigDeterministic, TestConfigRandomized};

    mod encrypt {
        use super::*;

        #[test]
        fn deterministic() {
            assert_eq!(
                EncryptedMessage::<String, TestConfigDeterministic>::encrypt("rigo does pretty codes".to_string()).unwrap(),
                EncryptedMessage {
                    payload: "48lwH3W0sEJjjC3z4S8qyNVpdf6jN0sF".to_string(),
                    headers: EncryptedMessageHeaders {
                        nonce: "1WOXnWc3iX5iA3wdqMmcSeGEE365QXK0".to_string(),
                        tag: "uXQhmffPV/1D7qG8stw6vA==".to_string(),
                    },
                    payload_type: PhantomData,
                    config: PhantomData,
                },
            );
        }

        #[test]
        fn randomized() {
            let payload = "much secret much secure".to_string();

            // Test that the encrypted messages never match, even when they contain the same payload.
            assert_ne!(
                EncryptedMessage::<String, TestConfigRandomized>::encrypt(payload.clone()).unwrap(),
                EncryptedMessage::<String, TestConfigRandomized>::encrypt(payload).unwrap(),
            );
        }

        #[test]
        fn test_serialization_error() {
            // A map with non-string keys can't be serialized into JSON.
            let map = std::collections::HashMap::<[u8; 2], String>::from([([1, 2], "Hi".to_string())]);
            assert!(matches!(EncryptedMessage::<_, TestConfigDeterministic>::encrypt(map).unwrap_err(), EncryptionError::Serialization(_)));
        }
    }

    mod decrypt {
        use super::*;

        #[test]
        fn decrypts_correctly() {
            let payload = "hi :D".to_string();
            let message = EncryptedMessage::<String, TestConfigDeterministic>::encrypt(payload.clone()).unwrap();
            assert_eq!(message.decrypt().unwrap(), payload);
        }

        #[test]
        fn test_base64_decoding_error() {
            fn generate() -> EncryptedMessage<String, TestConfigDeterministic> {
                EncryptedMessage::encrypt("hi :)".to_string()).unwrap()
            }

            // Test invalid payload.
            let mut message = generate();
            message.payload = "invalid".to_string();
            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Base64Decoding(_)));

            // Test invalid nonce.
            let mut message = generate();
            message.headers.nonce = "invalid".to_string();
            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Base64Decoding(_)));

            // Test invalid tag.
            let mut message = generate();
            message.headers.tag = "invalid".to_string();
            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Base64Decoding(_)));
        }

        #[test]
        fn test_decryption_error() {
            // Created using a random disposed key not used in other tests.
            let message = EncryptedMessage {
                payload: "c+cOk5DA9y/4LulYA+WCAxFjI8WGbTVK".to_string(),
                headers: EncryptedMessageHeaders {
                    nonce: "dBI9t1Y8mUBea+b0nyWXlTeoCdrNPLkg".to_string(),
                    tag: "6NLYKDiHNRkpwoQusf9BaA==".to_string(),
                },
                payload_type: PhantomData::<String>,
                config: PhantomData::<TestConfigDeterministic>,
            };

            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Decryption));
        }

        #[test]
        fn test_deserialization_error() {
            let message = EncryptedMessage::<String, TestConfigDeterministic>::encrypt("hi :)".to_string()).unwrap();

            // Change the payload type to an integer, even though the initial payload was serialized as a string.
            let message = EncryptedMessage {
                payload: message.payload,
                headers: message.headers,
                payload_type: PhantomData::<u8>,
                config: message.config,
            };

            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Deserialization(_)));
        }
    }

    #[test]
    fn allows_rotating_keys() {
        // Created using TestConfig's second key.
        let message = EncryptedMessage {
            payload: "LC4u257NQw==".to_string(),
            headers: EncryptedMessageHeaders {
                nonce: "nv6rH50Sn2Po320KT57fg1a3Lyu/IGeG".to_string(),
                tag: "/jK8Y7fOyA+S7/dTxRR3SQ==".to_string(),
            },
            payload_type: PhantomData::<String>,
            config: PhantomData::<TestConfigDeterministic>,
        };

        // Ensure that if encrypting the same value, it'll be different since it'll use the new primary key.
        // Note that we're using the `Deterministic` encryption strategy, so the encrypted message would be the
        // same if the key was the same.
        let expected_payload = "hi :)".to_string();
        assert_ne!(
            EncryptedMessage::<String, TestConfigDeterministic>::encrypt(expected_payload.clone()).unwrap(),
            message,
        );

        // Ensure that it can be decrypted even though the key is not primary anymore.
        assert_eq!(message.decrypt().unwrap(), expected_payload);
    }

    #[test]
    fn handles_empty_payload() {
        let message = EncryptedMessage::<String, TestConfigDeterministic>::encrypt("".to_string()).unwrap();
        assert_eq!(message.decrypt().unwrap(), "");
    }

    #[test]
    fn handles_json_types() {
        // Nullable values
        let encrypted = EncryptedMessage::<Option<String>, TestConfigRandomized>::encrypt(None).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), None);

        let encrypted = EncryptedMessage::<Option<String>, TestConfigRandomized>::encrypt(Some("rigo is cool".to_string())).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), Some("rigo is cool".to_string()));

        // Boolean values
        let encrypted = EncryptedMessage::<bool, TestConfigRandomized>::encrypt(true).unwrap();
        assert_eq!(encrypted.decrypt().unwrap() as u8, 1);

        // Integer values
        let encrypted = EncryptedMessage::<u8, TestConfigRandomized>::encrypt(255).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), 255);

        // Float values
        let encrypted = EncryptedMessage::<f64, TestConfigRandomized>::encrypt(0.12345).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), 0.12345);

        // String values
        let encrypted = EncryptedMessage::<String, TestConfigRandomized>::encrypt("rigo is cool".to_string()).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), "rigo is cool");

        // Array values
        let encrypted = EncryptedMessage::<Vec<u8>, TestConfigRandomized>::encrypt(vec![1, 2, 3]).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), vec![1, 2, 3]);

        // Object values
        let encrypted = EncryptedMessage::<serde_json::Value, TestConfigRandomized>::encrypt(json!({ "a": 1, "b": "hello", "c": false })).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), json!({ "a": 1, "b": "hello", "c": false }));
    }

    #[test]
    fn to_and_from_json() {
        let message = EncryptedMessage {
            payload: "48lwH3W0sEJjjC3z4S8qyNVpdf6jN0sF".to_string(),
            headers: EncryptedMessageHeaders {
                nonce: "1WOXnWc3iX5iA3wdqMmcSeGEE365QXK0".to_string(),
                tag: "uXQhmffPV/1D7qG8stw6vA==".to_string(),
            },
            payload_type: PhantomData::<String>,
            config: PhantomData::<TestConfigRandomized>,
        };

        // To JSON.
        let message_json = serde_json::to_value(&message).unwrap();
        assert_eq!(
            message_json,
            json!({
                "p": "48lwH3W0sEJjjC3z4S8qyNVpdf6jN0sF",
                "h": {
                    "iv": "1WOXnWc3iX5iA3wdqMmcSeGEE365QXK0",
                    "at": "uXQhmffPV/1D7qG8stw6vA==",
                },
            }),
        );

        // From JSON.
        assert_eq!(
            serde_json::from_value::<EncryptedMessage::<_, _>>(message_json).unwrap(),
            message,
        );
    }
}

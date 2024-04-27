//! Safely encrypt & store serializable data using AES-256-GCM.
//!
//! # Key configuration
//!
//! First, you need to create a key configuration that implements the [`KeyConfig`] trait.
//! If your key configuration implements the [`Default`] trait, you can use the shorthand methods
//! of the [`EncryptedMessage`] struct.
//!
//! The first key provided is considered the primary key, & is always used to encrypt new payloads.
//! The following keys are used in the order provided when the primary key can't decrypt a payload. This allows you to rotate keys.
//!
//! Two key decoders are provided, [`HexKeyDecoder`](crate::utilities::key_decoder::HexKeyDecoder)
//! & [`Base64KeyDecoder`](crate::utilities::key_decoder::Base64KeyDecoder),
//! to help you store your key(s) as strings.
//!
//! ```
//! use encrypted_message::{
//!     key_config::Secret,
//!     utilities::key_decoder::{KeyDecoder as _, HexKeyDecoder},
//! };
//!
//! #[derive(Debug, Default)]
//! struct KeyConfig;
//! impl encrypted_message::KeyConfig for KeyConfig {
//!     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//!         // Load the keys from an environment variable, & wrap them in a `Secret`.
//!         let keys = std::env::var("ENCRYPTION_KEYS").unwrap()
//!             .split(", ")
//!             .map(|key| Secret::new(key.to_string()))
//!             .collect();
//!
//!         HexKeyDecoder::decode_keys(keys)
//!     }
//! }
//! ```
//!
//! You can generate secure 32-byte keys using the `openssl` command-line tool. Remember to use
//! [`HexKeyDecoder`](crate::utilities::key_decoder::HexKeyDecoder) to decode the key.
//! ```sh
//! openssl rand -hex 32
//! ```
//!
//! # Encryption strategies
//!
//! Two encryption strategies are provided, [`Deterministic`](crate::strategy::Deterministic) & [`Randomized`](crate::strategy::Randomized).
//!
//! - [`Deterministic`](crate::strategy::Deterministic) encryption will always produce the same encrypted message for the same payload, allowing you to query encrypted data.
//! - [`Randomized`](crate::strategy::Randomized) encryption will always produce a different encrypted message for the same payload. More secure than [`Deterministic`](crate::strategy::Deterministic), but impossible to query without decrypting all data.
//!
//! It's recommended to use different keys for each encryption strategy.
//!
//! # Defining encrypted fields
//!
//! You can now define your encrypted fields using the [`EncryptedMessage`] struct.
//! The first type parameter is the payload type, the second is the encryption strategy, & the third is the key configuration type.
//!
//! ```
//! # use encrypted_message::{
//! #     key_config::Secret,
//! #     utilities::key_decoder::{KeyDecoder as _, HexKeyDecoder},
//! # };
//! #
//! # #[derive(Debug, Default)]
//! # struct KeyConfig;
//! # impl encrypted_message::KeyConfig for KeyConfig {
//! #     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//! #         HexKeyDecoder::decode_keys(vec![String::from("75754f7866705767526749456f33644972646f30686e484a484631686e747657").into()])
//! #     }
//! # }
//! #
//! use encrypted_message::{EncryptedMessage, strategy::Randomized};
//!
//! struct User {
//!     diary: EncryptedMessage<String, Randomized, KeyConfig>,
//! }
//! ```
//!
//! # Encrypting & decrypting payloads
//!
//! If your [`KeyConfig`] implements the [`Default`] trait (like above), you can use the shorthand methods:
//! ```
//! # use encrypted_message::{
//! #     EncryptedMessage,
//! #     key_config::Secret,
//! #     strategy::Randomized,
//! #     utilities::key_decoder::{KeyDecoder as _, HexKeyDecoder},
//! # };
//! #
//! # #[derive(Debug, Default)]
//! # struct KeyConfig;
//! # impl encrypted_message::KeyConfig for KeyConfig {
//! #     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//! #         HexKeyDecoder::decode_keys(vec![String::from("75754f7866705767526749456f33644972646f30686e484a484631686e747657").into()])
//! #     }
//! # }
//! #
//! # struct User {
//! #     diary: EncryptedMessage<String, Randomized, KeyConfig>,
//! # }
//! #
//! // Encrypt a user's diary.
//! let mut user = User {
//!     diary: EncryptedMessage::encrypt("Very personal stuff".to_string()).unwrap(),
//! };
//!
//! // Decrypt the user's diary.
//! let decrypted: String = user.diary.decrypt().unwrap();
//!
//! // Update the user's diary using the same encryption strategy & key config.
//! user.diary = user.diary.with_new_payload("More personal stuff".to_string()).unwrap();
//! ```
//!
//! If your [`KeyConfig`] depends on external data:
//! ```
//! use encrypted_message::{
//!     EncryptedMessage,
//!     key_config::Secret,
//!     strategy::Randomized,
//!     utilities::key_generation::derive_key_from,
//! };
//! use secrecy::{ExposeSecret as _, SecretString};
//!
//! #[derive(Debug)]
//! struct UserKeyConfig {
//!     user_password: SecretString,
//!     salt: SecretString,
//! }
//!
//! impl encrypted_message::KeyConfig for UserKeyConfig {
//!     fn keys(&self) -> Vec<Secret<[u8; 32]>> {
//!         let raw_key = self.user_password.expose_secret().as_bytes();
//!         let salt = self.salt.expose_secret().as_bytes();
//!         vec![derive_key_from(&raw_key, &salt, 2_u32.pow(16))]
//!     }
//! }
//!
//! struct User {
//!     diary: EncryptedMessage<String, Randomized, UserKeyConfig>,
//! }
//!
//! // Define the user's key configuration.
//! let key_config = UserKeyConfig {
//!     user_password: "human-password-that-should-be-derived".to_string().into(),
//!     salt: "unique-salt".to_string().into(),
//! };
//!
//! // Encrypt a user's diary.
//! let mut user = User {
//!     diary: EncryptedMessage::encrypt_with_key_config("Very personal stuff".to_string(), &key_config).unwrap(),
//! };
//!
//! // Decrypt the user's diary.
//! let decrypted: String = user.diary.decrypt_with_key_config(&key_config).unwrap();
//!
//! // Update the user's diary using the same encryption strategy & key config.
//! user.diary = user.diary.with_new_payload_and_key_config("More personal stuff".to_string(), &key_config).unwrap();
//! ```
//!
//! # Integration with Diesel
//!
//! [`EncryptedMessage`] implements [`FromSql`](diesel::deserialize::FromSql) & [`ToSql`](diesel::serialize::ToSql),
//! allowing you to use `EncryptedMessage` as a field type in your models.
//!
//! - **MySQL**: Enable the `diesel` & `diesel-mysql` features. Supports the [`Json`](diesel::sql_types::Json) type.
//! - **PostgreSQL**: Enable the `diesel` & `diesel-postgres` features. Supports the [`Json`](diesel::sql_types::Json) & [`Jsonb`](diesel::sql_types::Jsonb) types.

pub mod strategy;
use strategy::Strategy;

pub mod error;
pub use error::{EncryptionError, DecryptionError};

mod integrations;

pub mod key_config;
use key_config::KeyConfig;

mod utilities;
use utilities::base64;

#[cfg(test)]
mod testing;

use std::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use aes_gcm::{KeyInit as _, Aes256Gcm, AeadInPlace as _};
use secrecy::ExposeSecret as _;

/// Used to safely handle & transport encrypted data within your application.
/// It contains an encrypted payload, along with a nonce & tag that are
/// used in the encryption & decryption processes.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Json))]
#[cfg_attr(all(feature = "diesel", feature = "diesel-postgres"), diesel(sql_type = diesel::sql_types::Jsonb))]
pub struct EncryptedMessage<P: Debug + DeserializeOwned + Serialize, S: Strategy, K: KeyConfig> {
    /// The base64-encoded & encrypted payload.
    #[serde(rename = "p")]
    payload: String,

    /// The headers stored with the encrypted payload.
    #[serde(rename = "h")]
    headers: EncryptedMessageHeaders,

    /// The payload type.
    #[serde(skip)]
    payload_type: PhantomData<P>,

    /// The encryption strategy used to encrypt the payload.
    #[serde(skip)]
    strategy: PhantomData<S>,

    // The key configuration used to encrypt/decrypt the payload.
    #[serde(skip)]
    key_config: PhantomData<K>,
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

impl<P: Debug + DeserializeOwned + Serialize, S: Strategy, K: KeyConfig> EncryptedMessage<P, S, K> {
    /// Creates an [`EncryptedMessage`] from a payload, using the AES-256-GCM encryption cipher.
    ///
    /// # Errors
    ///
    /// - Returns an [`EncryptionError::Serialization`] error if the payload cannot be serialized into a JSON string.
    ///   See [`serde_json::to_vec`] for more information.
    pub fn encrypt_with_key_config(payload: P, key_config: &K) -> Result<Self, EncryptionError> {
        let payload = serde_json::to_vec(&payload)?;

        let key = key_config.primary_key();
        let nonce = S::generate_nonce_for(&payload, key.expose_secret());
        let cipher = Aes256Gcm::new_from_slice(key.expose_secret()).unwrap();

        let mut buffer = payload;
        let tag = cipher.encrypt_in_place_detached(&nonce.into(), b"", &mut buffer).unwrap();

        Ok(EncryptedMessage {
            payload: base64::encode(buffer),
            headers: EncryptedMessageHeaders {
                nonce: base64::encode(nonce),
                tag: base64::encode(tag),
            },
            payload_type: PhantomData,
            strategy: PhantomData,
            key_config: PhantomData,
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
    pub fn decrypt_with_key_config(&self, key_config: &K) -> Result<P, DecryptionError> {
        let payload = base64::decode(&self.payload)?;
        let nonce = base64::decode(&self.headers.nonce)?;
        let tag = base64::decode(&self.headers.tag)?;

        for key in key_config.keys() {
            let cipher = Aes256Gcm::new_from_slice(key.expose_secret()).unwrap();

            let mut buffer = payload.clone();
            if cipher.decrypt_in_place_detached(nonce.as_slice().into(), b"", &mut buffer, tag.as_slice().into()).is_err() {
                continue;
            };

            return Ok(serde_json::from_slice(&buffer)?);
        }

        Err(DecryptionError::Decryption)
    }
}

impl<P: Debug + DeserializeOwned + Serialize, S: Strategy, K: KeyConfig + Default> EncryptedMessage<P, S, K> {
    /// This method is a shorthand for [`EncryptedMessage::encrypt_with_key_config`],
    /// passing `&K::default()` as the key configuration.
    pub fn encrypt(payload: P) -> Result<Self, EncryptionError> {
        Self::encrypt_with_key_config(payload, &K::default())
    }

    /// This method is a shorthand for [`EncryptedMessage::decrypt_with_key_config`],
    /// passing `&K::default()` as the key configuration.
    pub fn decrypt(&self) -> Result<P, DecryptionError> {
        self.decrypt_with_key_config(&K::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    use crate::{
        strategy::{Deterministic, Randomized},
        testing::TestKeyConfig,
    };

    mod encrypt {
        use super::*;

        #[test]
        fn deterministic() {
            assert_eq!(
                EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt("rigo does pretty codes".to_string()).unwrap(),
                EncryptedMessage {
                    payload: "K6FbTsR8lNt9osq7vfvpDl4gPOxaQUhH".to_string(),
                    headers: EncryptedMessageHeaders {
                        nonce: "1WOXnWc3iX5iA3wd".to_string(),
                        tag: "fdnw5HvNImSdBm0nTFiRFw==".to_string(),
                    },
                    payload_type: PhantomData,
                    strategy: PhantomData,
                    key_config: PhantomData,
                },
            );
        }

        #[test]
        fn randomized() {
            let payload = "much secret much secure".to_string();

            // Test that the encrypted messages never match, even when they contain the same payload.
            assert_ne!(
                EncryptedMessage::<String, Randomized, TestKeyConfig>::encrypt(payload.clone()).unwrap(),
                EncryptedMessage::<String, Randomized, TestKeyConfig>::encrypt(payload).unwrap(),
            );
        }

        #[test]
        fn test_serialization_error() {
            // A map with non-string keys can't be serialized into JSON.
            let map = std::collections::HashMap::<[u8; 2], String>::from([([1, 2], "Hi".to_string())]);
            assert!(matches!(EncryptedMessage::<_, Deterministic, TestKeyConfig>::encrypt(map).unwrap_err(), EncryptionError::Serialization(_)));
        }
    }

    mod decrypt {
        use super::*;

        #[test]
        fn decrypts_correctly() {
            let payload = "hi :D".to_string();
            let message = EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt(payload.clone()).unwrap();
            assert_eq!(message.decrypt().unwrap(), payload);
        }

        #[test]
        fn test_base64_decoding_error() {
            fn generate() -> EncryptedMessage<String, Deterministic, TestKeyConfig> {
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
                payload: "2go7QdfuErm53fOI2jiNnHcPunwGWHpM".to_string(),
                headers: EncryptedMessageHeaders {
                    nonce: "Exz8Fa9hKHEWvvmZ".to_string(),
                    tag: "r/AdKM4Dp0YAr/7dzAqujw==".to_string(),
                },
                payload_type: PhantomData::<String>,
                strategy: PhantomData::<Deterministic>,
                key_config: PhantomData::<TestKeyConfig>,
            };

            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Decryption));
        }

        #[test]
        fn test_deserialization_error() {
            let message = EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt("hi :)".to_string()).unwrap();

            // Change the payload type to an integer, even though the initial payload was serialized as a string.
            let message = EncryptedMessage {
                payload: message.payload,
                headers: message.headers,
                payload_type: PhantomData::<u8>,
                strategy: message.strategy,
                key_config: message.key_config,
            };

            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Deserialization(_)));
        }
    }

    #[test]
    fn allows_rotating_keys() {
        // Created using TestConfig's second key.
        let message = EncryptedMessage {
            payload: "DT6PJ1ROSA==".to_string(),
            headers: EncryptedMessageHeaders {
                nonce: "nv6rH50Sn2Po320K".to_string(),
                tag: "ZtAoub/4fB30QetW+O7oaA==".to_string(),
            },
            payload_type: PhantomData::<String>,
            strategy: PhantomData::<Deterministic>,
            key_config: PhantomData::<TestKeyConfig>,
        };

        // Ensure that if encrypting the same value, it'll be different since it'll use the new primary key.
        // Note that we're using the `Deterministic` encryption strategy, so the encrypted message would be the
        // same if the key was the same.
        let expected_payload = "hi :)".to_string();
        assert_ne!(
            EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt(expected_payload.clone()).unwrap(),
            message,
        );

        // Ensure that it can be decrypted even though the key is not primary anymore.
        assert_eq!(message.decrypt().unwrap(), expected_payload);
    }

    #[test]
    fn handles_empty_payload() {
        let message = EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt("".to_string()).unwrap();
        assert_eq!(message.decrypt().unwrap(), "");
    }

    #[test]
    fn handles_json_types() {
        // Nullable values
        let encrypted = EncryptedMessage::<Option<String>, Randomized, TestKeyConfig>::encrypt(None).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), None);

        let encrypted = EncryptedMessage::<Option<String>, Randomized, TestKeyConfig>::encrypt(Some("rigo is cool".to_string())).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), Some("rigo is cool".to_string()));

        // Boolean values
        let encrypted = EncryptedMessage::<bool, Randomized, TestKeyConfig>::encrypt(true).unwrap();
        assert_eq!(encrypted.decrypt().unwrap() as u8, 1);

        // Integer values
        let encrypted = EncryptedMessage::<u8, Randomized, TestKeyConfig>::encrypt(255).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), 255);

        // Float values
        let encrypted = EncryptedMessage::<f64, Randomized, TestKeyConfig>::encrypt(0.12345).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), 0.12345);

        // String values
        let encrypted = EncryptedMessage::<String, Randomized, TestKeyConfig>::encrypt("rigo is cool".to_string()).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), "rigo is cool");

        // Array values
        let encrypted = EncryptedMessage::<Vec<u8>, Randomized, TestKeyConfig>::encrypt(vec![1, 2, 3]).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), vec![1, 2, 3]);

        // Object values
        let encrypted = EncryptedMessage::<serde_json::Value, Randomized, TestKeyConfig>::encrypt(json!({ "a": 1, "b": "hello", "c": false })).unwrap();
        assert_eq!(encrypted.decrypt().unwrap(), json!({ "a": 1, "b": "hello", "c": false }));
    }

    #[test]
    fn to_and_from_json() {
        let message = EncryptedMessage {
            payload: "SBwByX5cxBSMgPlixDEf0pYEa6W41TIA".to_string(),
            headers: EncryptedMessageHeaders {
                nonce: "xg172uWMpjJqmWro".to_string(),
                tag: "S88wdO9tf/381mZQ88kMNw==".to_string(),
            },
            payload_type: PhantomData::<String>,
            strategy: PhantomData::<Deterministic>,
            key_config: PhantomData::<TestKeyConfig>,
        };

        // To JSON.
        let message_json = serde_json::to_value(&message).unwrap();
        assert_eq!(
            message_json,
            json!({
                "p": "SBwByX5cxBSMgPlixDEf0pYEa6W41TIA",
                "h": {
                    "iv": "xg172uWMpjJqmWro",
                    "at": "S88wdO9tf/381mZQ88kMNw==",
                },
            }),
        );

        // From JSON.
        assert_eq!(
            serde_json::from_value::<EncryptedMessage::<_, _, _>>(message_json).unwrap(),
            message,
        );
    }
}

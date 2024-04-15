pub mod key_config;
pub use key_config::KeyConfig;

pub mod encryption_type;
use encryption_type::EncryptionType;

pub mod error;
pub use error::{EncryptionError, DecryptionError};

mod integrations;
mod key_generation;

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
pub struct EncryptedMessage<P: Debug + DeserializeOwned + Serialize, E: EncryptionType, K: KeyConfig> {
    /// The base64-encoded & encrypted payload.
    #[serde(rename = "p")]
    payload: String,

    /// The headers stored with the encrypted payload.
    #[serde(rename = "h")]
    headers: EncryptedMessageHeaders,

    /// The payload type.
    #[serde(skip)]
    payload_type: PhantomData<P>,

    /// The encryption type used to encrypt the payload.
    #[serde(skip)]
    encryption_type: PhantomData<E>,

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

impl<P: Debug + DeserializeOwned + Serialize, E: EncryptionType, K: KeyConfig> EncryptedMessage<P, E, K> {
    /// Creates an [`EncryptedMessage`] from a payload, using the AES-256-GCM encryption cipher.
    ///
    /// # Errors
    ///
    /// - Returns an [`EncryptionError::Serialization`] error if the payload cannot be serialized into a JSON string.
    ///   See [`serde_json::to_value`] for more information.
    pub fn encrypt_with_key_config(payload: P, key_config: K) -> Result<Self, EncryptionError> {
        // Serialize the payload into a JSON string, then convert it into a byte array.
        let payload = serde_json::to_value(payload)?.to_string().into_bytes();

        let key = key_config.key();
        let nonce = E::generate_nonce_for(&payload, key.expose_secret());
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
            encryption_type: PhantomData,
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
    pub fn decrypt_with_key_config(&self, key_config: K) -> Result<P, DecryptionError> {
        let payload = base64::decode(&self.payload)?;
        let nonce = base64::decode(&self.headers.nonce)?;
        let tag = base64::decode(&self.headers.tag)?;

        for raw_key in key_config.raw_keys() {
            let salt = key_config.key_derivation_salt();
            let iterations = K::KEY_DERIVATION_ITERATIONS;
            let key = key_generation::derive_from(raw_key.expose_secret(), salt.expose_secret(), iterations);
            let cipher = Aes256Gcm::new_from_slice(key.expose_secret()).unwrap();

            let mut buffer = payload.clone();
            if cipher.decrypt_in_place_detached(nonce.as_slice().into(), b"", &mut buffer, tag.as_slice().into()).is_err() {
                continue;
            };

            return Ok(serde_json::from_slice(&buffer)?);
        }

        Err(DecryptionError::Decryption)
    }

    /// Consumes the [`EncryptedMessage`] & returns a new one with
    /// the same encryption type, but with a new encrypted payload.
    ///
    /// See [`Self::encrypt_with_key_config`] for more information.
    pub fn with_new_payload_and_key_config(self, payload: P, key_config: K) -> Result<Self, EncryptionError> {
        Self::encrypt_with_key_config(payload, key_config)
    }
}

impl<P: Debug + DeserializeOwned + Serialize, E: EncryptionType, K: KeyConfig + Default> EncryptedMessage<P, E, K> {
    /// This method is a shorthand for [`Self::encrypt_with_key_config`],
    /// passing `K::default()` as the key configuration.
    pub fn encrypt(payload: P) -> Result<Self, EncryptionError> {
        Self::encrypt_with_key_config(payload, K::default())
    }

    /// This method is a shorthand for [`Self::decrypt_with_key_config`],
    /// passing `K::default()` as the key configuration.
    pub fn decrypt(&self) -> Result<P, DecryptionError> {
        self.decrypt_with_key_config(K::default())
    }

    /// This method is a shorthand for [`Self::with_new_payload_and_key_config`],
    /// passing `K::default()` as the key configuration.
    pub fn with_new_payload(self, payload: P) -> Result<Self, EncryptionError> {
        self.with_new_payload_and_key_config(payload, K::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    use crate::{
        encryption_type::{Deterministic, Randomized},
        testing::TestKeyConfig,
    };

    mod encrypt {
        use super::*;

        #[test]
        fn deterministic() {
            assert_eq!(
                EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt("rigo does pretty codes".to_string()).unwrap(),
                EncryptedMessage {
                    payload: "SBwByX5cxBSMgPlixDEf0pYEa6W41TIA".to_string(),
                    headers: EncryptedMessageHeaders {
                        nonce: "xg172uWMpjJqmWro".to_string(),
                        tag: "S88wdO9tf/381mZQ88kMNw==".to_string(),
                    },
                    payload_type: PhantomData,
                    encryption_type: PhantomData,
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
        fn deterministic() {
            let payload = "hi :D".to_string();
            let message = EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt(payload.clone()).unwrap();
            assert_eq!(message.decrypt().unwrap(), payload);
        }

        #[test]
        fn randomized() {
            let payload = "hi :D".to_string();
            let message = EncryptedMessage::<String, Randomized, TestKeyConfig>::encrypt(payload.clone()).unwrap();
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
                encryption_type: PhantomData::<Deterministic>,
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
                encryption_type: message.encryption_type,
                key_config: message.key_config,
            };

            assert!(matches!(message.decrypt().unwrap_err(), DecryptionError::Deserialization(_)));
        }
    }

    #[test]
    fn test_with_new_payload() {
        let message = EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt("bonjour".to_string()).unwrap();
        let encrypted_payload = message.payload.clone();

        let new_message = message.with_new_payload("hola".to_string()).unwrap();
        let new_encrypted_payload = new_message.payload;

        assert_eq!(new_message.payload_type, PhantomData::<String>);
        assert_eq!(new_message.encryption_type, PhantomData::<Deterministic>);
        assert_ne!(encrypted_payload, new_encrypted_payload);
    }

    #[test]
    fn allows_rotating_keys() {
        // Created using `Deterministic`'s second key.
        let message = EncryptedMessage {
            payload: "D6lZNGd5Jw==".to_string(),
            headers: EncryptedMessageHeaders {
                nonce: "QMDFOQuKaUD9o9AP".to_string(),
                tag: "gn1Wgm1bgbgl9wjAv1PFYA==".to_string(),
            },
            payload_type: PhantomData::<String>,
            encryption_type: PhantomData::<Deterministic>,
            key_config: PhantomData::<TestKeyConfig>,
        };

        // Ensure that it can be decrypted even though the key is not primary anymore.
        let expected_payload = "hi :)".to_string();
        assert_eq!(message.decrypt().unwrap(), expected_payload);

        // Ensure that if encrypting the same value, it'll be different since it'll use the new primary key.
        // Note that we're using the `Deterministic` encryption type, so the encrypted message would be the
        // same if the key was the same.
        assert_ne!(
            EncryptedMessage::<String, Deterministic, TestKeyConfig>::encrypt(expected_payload).unwrap(),
            message,
        )
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
            encryption_type: PhantomData::<Deterministic>,
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

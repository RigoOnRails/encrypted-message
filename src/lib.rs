pub mod encryption_type;
use encryption_type::EncryptionType;

mod integrations;
mod key_derivation;

mod utilities;
use utilities::base64;

#[cfg(test)]
mod testing;

use std::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};
use aes_gcm::{KeyInit as _, Aes256Gcm, AeadInPlace as _};
use secrecy::ExposeSecret as _;

/// An encrypted message.
///
/// Used to safely handle & transport encrypted data within your application.
/// It contains the encrypted payload of the message, along with a nonce & tag
/// that are used in the encryption & decryption processes.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Json))]
#[cfg_attr(all(feature = "diesel", feature = "diesel-postgres"), diesel(sql_type = diesel::sql_types::Jsonb))]
pub struct EncryptedMessage<P: Serialize + Debug, E: EncryptionType> {
    /// The base64-encoded & encrypted payload.
    p: String,

    /// The headers stored with the encrypted payload.
    h: EncryptedMessageHeaders,

    /// The payload type.
    _payload_type: PhantomData<P>,

    /// The encryption type used to encrypt the payload.
    _encryption_type: PhantomData<E>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EncryptedMessageHeaders {
    /// The base64-encoded nonce used to encrypt the payload.
    iv: String,

    /// The base64-encoded auth tag used to verify the encrypted payload.
    at: String,
}

impl<P: Serialize + Debug, E: EncryptionType> EncryptedMessage<P, E> {
    /// Creates an [`EncryptedMessage`] from a payload, using the AES-256-GCM encryption cipher.
    ///
    /// Fails if the payload cannot be serialized into a JSON string.
    /// See [`serde_json::to_value`] for more information.
    pub fn encrypt(payload: P) -> Result<Self, serde_json::Error> {
        // Serialize the payload into a JSON string, then convert it into a byte array.
        let payload = serde_json::to_value(payload)?.to_string().into_bytes();

        let nonce = E::generate_nonce_for(&payload);
        let cipher = Aes256Gcm::new_from_slice(E::key().expose_secret()).unwrap();

        let mut buffer = payload;
        let tag = cipher.encrypt_in_place_detached(&nonce.into(), b"", &mut buffer).unwrap();

        Ok(EncryptedMessage {
            p: base64::encode(buffer),
            h: EncryptedMessageHeaders {
                iv: base64::encode(nonce),
                at: base64::encode(tag),
            },
            _payload_type: PhantomData,
            _encryption_type: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing;

    mod deterministic {
        use super::*;

        use crate::encryption_type::Deterministic;

        #[test]
        fn test_encrypt() {
            testing::setup();

            assert_eq!(
                EncryptedMessage::<&str, Deterministic>::encrypt("rigo does pretty codes").unwrap(),
                EncryptedMessage {
                    p: "SBwByX5cxBSMgPlixDEf0pYEa6W41TIA".to_string(),
                    h: EncryptedMessageHeaders {
                        iv: "xg172uWMpjJqmWro".to_string(),
                        at: "S88wdO9tf/381mZQ88kMNw==".to_string(),
                    },
                    _payload_type: PhantomData,
                    _encryption_type: PhantomData,
                },
            );
        }
    }

    mod randomized {
        use super::*;

        use crate::encryption_type::Randomized;

        #[test]
        fn test_encrypt() {
            testing::setup();

            let payload = "much secret much secure";

            // Test that the encrypted messages never match, even when they contain the same payload.
            assert_ne!(
                EncryptedMessage::<&str, Randomized>::encrypt(payload).unwrap(),
                EncryptedMessage::<&str, Randomized>::encrypt(payload).unwrap(),
            );
        }
    }
}

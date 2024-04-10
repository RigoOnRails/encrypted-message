use serde::{Deserialize, Serialize};

/// The JSON format of an encrypted column.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EncryptedMessage {
    /// The base64-encoded & encrypted payload.
    p: String,

    /// The headers stored with the encrypted payload.
    h: EncryptedMessageHeaders,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EncryptedMessageHeaders {
    /// The base64-encoded nonce used to encrypt the payload.
    iv: String,

    /// The base64-encoded auth tag used to verify the encrypted payload.
    at: String,
}

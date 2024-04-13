use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("The payload could not be serialized.")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error(transparent)]
    Base64Decoding(#[from] base64::DecodeError),

    #[error("The payload could not be decrypted with any of the available keys.")]
    Decryption,

    #[error("The payload could not be deserialized.")]
    Deserialization(#[from] serde_json::Error),
}

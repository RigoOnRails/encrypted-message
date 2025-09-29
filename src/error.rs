//! Error types for the encryption & decryption operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("The provided key length is invalid. It must be 32 bytes.")]
    InvalidKeyLength,

    #[error("No keys were provided in the configuration.")]
    NoKeysProvided,
}

/// Returned from [`EncryptedMessage`](crate::EncryptedMessage) encryption methods when an error occurs.
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// This error occurs when there's an issue with the provided configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// This error occurs when a payload could not be encrypted.
    #[error("The payload could not be encrypted.")]
    Encryption,

    /// This error occurs when a payload could not be serialized into JSON.
    #[error("The payload could not be serialized into JSON.")]
    Serialization(#[from] serde_json::Error),
}

/// Returned from [`EncryptedMessage`](crate::EncryptedMessage) decryption methods when an error occurs.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// This error occurs when a field in [`EncryptedMessage`](crate::EncryptedMessage) could not be base64-decoded.
    #[error(transparent)]
    Base64Decoding(#[from] base64::DecodeError),

    /// This error occurs when there's an issue with the provided configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// This error occurs when a payload could not be decrypted with any of the available keys.
    #[error("The payload could not be decrypted with any of the available keys.")]
    Decryption,

    /// This error occurs when a payload could not be deserialized into the expected type.
    #[error("The payload could not be deserialized into the expected type.")]
    Deserialization(#[from] serde_json::Error),
}

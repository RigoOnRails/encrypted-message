use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("The payload could not be serialized.")]
    Serialization(#[from] serde_json::Error),
}

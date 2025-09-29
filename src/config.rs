//! Contains the [`Config`] trait used to define the configuration for an [`EncryptedMessage`](crate::EncryptedMessage).

use std::fmt::Debug;

pub use secrecy::{Secret, ExposeSecret};

use crate::error::ConfigError;

/// A trait to define the configuration for an [`EncryptedMessage`](crate::EncryptedMessage).
/// This allows you to effectively define different keys for different kinds of data if needed.
pub trait Config: Debug {
    /// The strategy to use for encryption. See the [`strategy`](crate::strategy) module for more information.
    type Strategy: crate::strategy::Strategy;

    /// Returns a list of keys to use for encryption.
    ///
    /// The first key is considered the primary key, & is always used for encryption.
    /// The next keys are used in the order provided when the primary key can't decrypt
    /// an [`EncryptedMessage`](crate::EncryptedMessage). This allows for key rotation.
    fn keys(&self) -> Vec<Secret<[u8; 32]>>;

    /// Returns the primary key, which is the first key in [`Config::keys`].
    fn primary_key(&self) -> Result<Secret<[u8; 32]>, ConfigError> {
        self.keys().into_iter().next().ok_or(ConfigError::NoKeysProvided)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::TestConfigRandomized as TestConfig;

    #[test]
    fn primary_key_returns_first_key() {
        let config = TestConfig;
        assert_eq!(config.primary_key().unwrap().expose_secret(), config.keys()[0].expose_secret());
    }
}

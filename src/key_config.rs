use std::fmt::Debug;

pub use secrecy::Secret;

/// A trait to define the configuration for the encryption/decryption process
/// of an [`EncryptedMessage`](crate::EncryptedMessage).
///
/// This trait allows you to effectively define different keys for different
/// kinds of data.
///
/// It's recommended to use different implementations for [`Deterministic`](crate::encryption_type::Deterministic)
/// & [`Randomized`](crate::encryption_type::Randomized) with different keys.
pub trait KeyConfig: Debug {
    /// Returns a list of keys to use for encryption.
    ///
    /// The first key is considered the primary key, & is always used for encryption.
    /// The next keys are used in the order provided when the primary key can't decrypt
    /// an [`EncryptedMessage`](crate::EncryptedMessage). This allows for key rotation.
    fn keys(&self) -> Vec<Secret<[u8; 32]>>;

    /// Returns the primary key, which is the first key in [`KeyConfig::keys`].
    fn primary_key(&self) -> Secret<[u8; 32]> {
        let mut keys = self.keys();
        assert!(!keys.is_empty(), "Must provide at least one key.");

        keys.remove(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::ExposeSecret as _;

    use crate::testing::TestKeyConfig;

    #[test]
    fn primary_key_returns_first_key() {
        let config = TestKeyConfig;
        assert_eq!(config.primary_key().expose_secret(), config.keys()[0].expose_secret());
    }
}

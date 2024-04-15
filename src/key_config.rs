use std::fmt::Debug;

pub use secrecy;
use secrecy::{SecretVec, Secret, ExposeSecret as _};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

/// A trait to define the configuration for the encryption/decryption process
/// of an [`EncryptedMessage`](crate::EncryptedMessage).
///
/// This trait allows you to effectively define different keys for different
/// kinds of data.
///
/// We recommend one implementation for [`Deterministic`](crate::encryption_type::Deterministic)
/// & one for [`Randomized`](crate::encryption_type::Randomized) with different keys but
/// the same salt & iterations.
pub trait KeyConfig: Debug {
    /// The number of iterations to use when deriving keys.
    ///
    /// You can disable key derivation by setting this to `None`.
    /// Please be sure of what you're doing if you decide to do this.
    /// You should provide a secure 32-byte key with exceptional entropy.
    const KEY_DERIVATION_ITERATIONS: Option<u32> = Some(2_u32.pow(16));

    /// Returns a list of raw keys to use for encryption.
    ///
    /// The first key is considered the primary key, & is always used for encryption.
    /// The next keys are used in the order provided when the primary key can't decrypt
    /// an [`EncryptedMessage`](crate::EncryptedMessage). This allows for key rotation.
    fn raw_keys(&self) -> Vec<SecretVec<u8>>;

    /// Returns the salt to use when deriving keys.
    fn key_derivation_salt(&self) -> SecretVec<u8>;

    /// Returns the primary key, derived unless key derivation is disabled.
    /// See [`KeyConfig::KEY_DERIVATION_ITERATIONS`] for more information.
    fn key(&self) -> Secret<[u8; 32]> {
        let keys = self.raw_keys();
        assert!(!keys.is_empty(), "Must provide at least one key.");

        self.derive_key(keys[0].expose_secret())
    }

    /// Derives a new 256-bit key from a raw key using the
    /// key derivation salt & iterations configured.
    ///
    /// If key derivation is disabled, the raw key is returned as-is.
    /// See [`KeyConfig::KEY_DERIVATION_ITERATIONS`] for more information.
    fn derive_key(&self, key: &[u8]) -> Secret<[u8; 32]> {
        let Some(iterations) = Self::KEY_DERIVATION_ITERATIONS else {
            let key: [u8; 32] = key.try_into().expect("Key must be 32 bytes long.");
            return key.into();
        };

        pbkdf2_hmac_array::<Sha256, 32>(key, self.key_derivation_salt().expose_secret(), iterations).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::TestKeyConfig;

    #[test]
    fn derives_key_by_default() {
        let config = TestKeyConfig;
        assert_ne!(config.raw_keys()[0].expose_secret(), config.key().expose_secret());
    }

    #[test]
    fn allows_disabling_key_derivation() {
        #[derive(Debug)]
        struct NoDerivationConfig;

        impl KeyConfig for NoDerivationConfig {
            const KEY_DERIVATION_ITERATIONS: Option<u32> = None;

            fn raw_keys(&self) -> Vec<SecretVec<u8>> {
                TestKeyConfig.raw_keys()
            }

            fn key_derivation_salt(&self) -> SecretVec<u8> {
                TestKeyConfig.key_derivation_salt()
            }
        }

        let config = NoDerivationConfig;
        assert_eq!(config.raw_keys()[0].expose_secret(), config.key().expose_secret());
    }
}

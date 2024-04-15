use std::fmt::Debug;

pub use secrecy;
use secrecy::{SecretVec, Secret, ExposeSecret as _};

use crate::key_generation;

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
    const KEY_DERIVATION_ITERATIONS: u32 = 2_u32.pow(16);

    /// Returns a list of raw keys to use for encryption.
    ///
    /// The first key is considered the primary key, & is always used for encryption.
    /// The next keys are used in the order provided when the primary key can't decrypt
    /// an [`EncryptedMessage`](crate::EncryptedMessage). This allows for key rotation.
    fn raw_keys(&self) -> Vec<SecretVec<u8>>;

    /// Returns the salt to use when deriving keys.
    fn key_derivation_salt(&self) -> SecretVec<u8>;

    /// Returns the primary key, derived.
    fn key(&self) -> Secret<[u8; 32]> {
        let keys = self.raw_keys();
        assert!(!keys.is_empty(), "Must provide at least one key.");

        key_generation::derive_from(
            keys[0].expose_secret(),
            self.key_derivation_salt().expose_secret(),
            Self::KEY_DERIVATION_ITERATIONS,
        )
    }
}

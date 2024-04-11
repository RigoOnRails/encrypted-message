use crate::{key_derivation, config::CONFIG};

mod private {
    pub trait Sealed {}

    impl Sealed for super::Deterministic {}
    impl Sealed for super::Randomized {}
}

pub trait EncryptionType: private::Sealed {
    /// Returns the appropriate key for the encryption type.
    fn key() -> [u8; 32];
}

#[derive(Debug)]
pub struct Deterministic;
impl EncryptionType for Deterministic {
    fn key() -> [u8; 32] {
        key_derivation::derive_from(&CONFIG.deterministic_key)
    }
}

#[derive(Debug)]
pub struct Randomized;
impl EncryptionType for Randomized {
    fn key() -> [u8; 32] {
        key_derivation::derive_from(&CONFIG.primary_key)
    }
}

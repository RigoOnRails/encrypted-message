use crate::key_config::{KeyConfig, secrecy::SecretVec};

#[derive(Debug, PartialEq, Eq)]
pub struct DeterministicKeyConfig;
impl KeyConfig for DeterministicKeyConfig {
    fn raw_keys() -> Vec<SecretVec<u8>> {
        vec![
            b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW".to_vec().into(),
            b"tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt".to_vec().into(),
        ]
    }

    fn key_derivation_salt() -> SecretVec<u8> {
        b"8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI".to_vec().into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RandomizedKeyConfig;
impl KeyConfig for RandomizedKeyConfig {
    fn raw_keys() -> Vec<SecretVec<u8>> {
        vec![
            b"VDIVbMzI30DL0YBgxS4i360Ox22mixRA".to_vec().into(),
            b"JHedIoHEwoJuyvqwTMacEGJ6Scsh6ltK".to_vec().into(),
        ]
    }

    fn key_derivation_salt() -> SecretVec<u8> {
        b"8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI".to_vec().into()
    }
}

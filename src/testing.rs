use crate::key_config::{KeyConfig, secrecy::SecretVec};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestKeyConfig;
impl KeyConfig for TestKeyConfig {
    fn raw_keys(&self) -> Vec<SecretVec<u8>> {
        vec![
            b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW".to_vec().into(),
            b"tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt".to_vec().into(),
        ]
    }

    fn key_derivation_salt(&self) -> SecretVec<u8> {
        b"8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI".to_vec().into()
    }
}

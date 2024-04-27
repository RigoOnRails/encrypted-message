use crate::key_config::{KeyConfig, Secret};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestKeyConfig;
impl KeyConfig for TestKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![
            (*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into(),
            (*b"tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt").into(),
        ]
    }
}

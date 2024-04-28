use crate::config::{Config, Secret};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestConfig;
impl Config for TestConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![
            (*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into(),
            (*b"tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt").into(),
        ]
    }
}

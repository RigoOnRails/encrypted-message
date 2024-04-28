use crate::{config::{Config, Secret}, strategy::{Deterministic, Randomized}};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestConfigDeterministic;
impl Config for TestConfigDeterministic {
    type Strategy = Deterministic;

    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![
            (*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into(),
            (*b"tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt").into(),
        ]
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestConfigRandomized;
impl Config for TestConfigRandomized {
    type Strategy = Randomized;

    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![
            (*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into(),
            (*b"tiwQCWKCsW1d6qzZfp7HYvnRqZPYYhMt").into(),
        ]
    }
}

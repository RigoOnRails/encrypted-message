use crate::{
    key_config::{KeyConfig, Secret},
    utilities::key_decoder::{KeyDecoder as _, HexKeyDecoder},
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestKeyConfig;
impl KeyConfig for TestKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        HexKeyDecoder::decode_keys(vec![
            String::from("75754f7866705767526749456f33644972646f30686e484a484631686e747657").into(),
            String::from("7469775143574b437357316436717a5a6670374859766e52715a505959684d74").into(),
        ])
    }
}

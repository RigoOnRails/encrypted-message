#[derive(Debug, Default)]
pub struct DerivationEnabledKeyConfig;
impl encrypted_message::KeyConfig for DerivationEnabledKeyConfig {
    fn raw_keys(&self) -> Vec<secrecy::SecretVec<u8>> {
        vec![b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW".to_vec().into()]
    }

    fn key_derivation_salt(&self) -> secrecy::SecretVec<u8> {
        b"8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI".to_vec().into()
    }
}

#[derive(Debug, Default)]
pub struct DerivationDisabledKeyConfig;
impl encrypted_message::KeyConfig for DerivationDisabledKeyConfig {
    const KEY_DERIVATION_ITERATIONS: Option<u32> = None;

    fn raw_keys(&self) -> Vec<secrecy::SecretVec<u8>> {
        DerivationEnabledKeyConfig.raw_keys()
    }

    fn key_derivation_salt(&self) -> secrecy::SecretVec<u8> {
        DerivationEnabledKeyConfig.key_derivation_salt()
    }
}

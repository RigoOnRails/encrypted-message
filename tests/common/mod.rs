#[derive(Debug)]
struct Config;
impl encrypted_message::Config for Config {
    fn raw_keys() -> Vec<secrecy::SecretVec<u8>> {
        vec![b"Fl1cANaYYRKWjmZPMDG2a3lhMnulSBqx".to_vec().into()]
    }

    fn key_derivation_salt() -> secrecy::SecretVec<u8> {
        b"ucTe1weWDJC0zz8Pl4pDMR4ydgnuUsZZ".to_vec().into()
    }
}
//! This example demonstrates how to use `encrypted-message`
//! to encrypt & decrypt a payload.

use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    key_config::{KeyConfig, Secret, ExposeSecret as _},
};

/// NOTE: Never hardcode your keys like this, obviously.
#[derive(Debug, Default)]
struct AppKeyConfig;
impl KeyConfig for AppKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let encoded_keys = [Secret::new("75754f7866705767526749456f33644972646f30686e484a484631686e747657".to_string())];
        encoded_keys.iter()
            .map(|hex_key| {
                let mut key = [0; 32];
                hex::decode_to_slice(hex_key.expose_secret(), &mut key).unwrap();

                key.into()
            })
            .collect()
    }
}

fn main() {
    // Encrypt a user's diary.
    let diary: EncryptedMessage::<String, Randomized, AppKeyConfig> = {
        EncryptedMessage::encrypt("Very personal stuff".to_string()).unwrap()
    };
    println!("Encrypted diary: {diary:#?}");

    // Decrypt the user's diary.
    let decrypted = diary.decrypt().unwrap();
    println!("Decrypted diary: {decrypted}");
}

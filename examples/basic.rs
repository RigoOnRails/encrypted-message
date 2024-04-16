//! This example demonstrates how to use `encrypted-message`
//! to encrypt & decrypt a payload.

use encrypted_message::{EncryptedMessage, encryption_type::Randomized, key_config::Secret};

/// NOTE: Never hardcode your keys like this, obviously.
#[derive(Debug, Default)]
struct KeyConfig;
impl encrypted_message::KeyConfig for KeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![(*b"Fl1cANaYYRKWjmZPMDG2a3lhMnulSBqx").into()]
    }
}

fn main() {
    // Encrypt a payload.
    let encrypted: EncryptedMessage<String, Randomized, KeyConfig> = {
        EncryptedMessage::encrypt("Hi".to_string()).unwrap()
    };
    println!("Encrypted: {:#?}", encrypted);

    // Decrypt the payload.
    let decrypted = encrypted.decrypt().unwrap();
    println!("Decrypted: {decrypted}");

    // Create a new encrypted message with the same encryption type & key config.
    let encrypted = encrypted.with_new_payload("Bonjour".to_string()).unwrap();
    println!("Encrypted with new payload: {:#?}", encrypted);
}

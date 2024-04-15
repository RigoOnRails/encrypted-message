//! This example demonstrates how to use `encrypted-message`
//! to encrypt & decrypt a payload.

use encrypted_message::{EncryptedMessage, encryption_type::Randomized};

// NOTE: Never hardcode your keys like this, obviously.
#[derive(Debug, Default)]
struct KeyConfig;
impl encrypted_message::KeyConfig for KeyConfig {
    fn raw_keys(&self) -> Vec<secrecy::SecretVec<u8>> {
        vec![b"Fl1cANaYYRKWjmZPMDG2a3lhMnulSBqx".to_vec().into()]
    }

    fn key_derivation_salt(&self) -> secrecy::SecretVec<u8> {
        b"ucTe1weWDJC0zz8Pl4pDMR4ydgnuUsZZ".to_vec().into()
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

//! This example demonstrates how to use a key configuration
//! that depends on external data.

use encrypted_message::{EncryptedMessage, encryption_type::Randomized};

#[derive(Debug, Default, Clone)]
struct KeyConfig {
    user_id: Option<String>,
}

impl encrypted_message::KeyConfig for KeyConfig {
    fn raw_keys(&self) -> Vec<secrecy::SecretVec<u8>> {
        vec![format!("{}-key", self.user_id.as_ref().unwrap()).into_bytes().into()]
    }

    fn key_derivation_salt(&self) -> secrecy::SecretVec<u8> {
        format!("{}-key-derivation-salt", self.user_id.as_ref().unwrap()).into_bytes().into()
    }
}

fn main() {
    let key_config = KeyConfig {
        user_id: Some("rigo".to_string()),
    };

    // Encrypt a payload.
    let encrypted: EncryptedMessage<String, Randomized, KeyConfig> = {
        EncryptedMessage::encrypt_with_key_config("Hi".to_string(), key_config.clone()).unwrap()
    };
    println!("Encrypted: {:#?}", encrypted);

    // Decrypt the payload.
    let decrypted = encrypted.decrypt_with_key_config(key_config.clone()).unwrap();
    println!("Decrypted: {decrypted}");

    // Create a new encrypted message with the same encryption type.
    let encrypted = encrypted.with_new_payload_and_key_config("Bonjour".to_string(), key_config).unwrap();
    println!("Encrypted with new payload: {:#?}", encrypted);
}

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

struct User {
    diary: EncryptedMessage<String, Randomized, KeyConfig>,
}

fn main() {
    // Encrypt a user's diary.
    let mut user = User {
        diary: EncryptedMessage::encrypt("Very personal stuff".to_string()).unwrap(),
    };
    println!("Encrypted diary: {:#?}", user.diary);

    // Decrypt the user's diary.
    let decrypted = user.diary.decrypt().unwrap();
    println!("Decrypted: {decrypted}");

    // Update the user's diary using the same encryption type & key config.
    user.diary = user.diary.with_new_payload("More personal stuff".to_string()).unwrap();
    println!("New encrypted diary: {:#?}", user.diary);
}

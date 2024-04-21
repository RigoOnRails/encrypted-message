//! This example demonstrates how to use `encrypted-message`
//! to encrypt & decrypt a payload.

use encrypted_message::{
    EncryptedMessage,
    encryption_type::Randomized,
    key_config::Secret,
    utilities::key_decoder::HexKeyDecoder,
};

/// NOTE: Never hardcode your keys like this, obviously.
#[derive(Debug, Default)]
struct KeyConfig;
impl encrypted_message::KeyConfig for KeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        HexKeyDecoder::decode_keys(vec![String::from("75754f7866705767526749456f33644972646f30686e484a484631686e747657").into()])
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

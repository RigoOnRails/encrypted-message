//! This example demonstrates how to use a key configuration
//! that depends on external data.

use encrypted_message::{
    EncryptedMessage,
    encryption_type::Randomized,
    key_config::Secret,
    utilities::key_generation::derive_key_from,
};
use secrecy::{ExposeSecret as _, SecretString};

/// NOTE: When depending on human-provided keys/passwords, ensure you derive them
/// using [`derive_key_from`]. Using a human-provided key directly is not secure as they're likely to be weak.
///
/// You should also use the `secrecy` crate in cases like these, to ensure safe key handling.
#[derive(Debug, Clone)]
struct UserKeyConfig {
    user_key: SecretString,
}

impl encrypted_message::KeyConfig for UserKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let salt = hex::decode("384e645a6872315263646f61567948594472504f57755a7538576c426c547749").unwrap();
        vec![derive_key_from(self.user_key.expose_secret().as_bytes(), &salt, 2_u32.pow(16))]
    }
}

struct User {
    diary: EncryptedMessage<String, Randomized, UserKeyConfig>,
}

fn main() {
    let key_config = UserKeyConfig {
        user_key: "rigos-weak-key-because-hes-a-human".to_string().into(),
    };

    // Encrypt a user's diary.
    let mut user = User {
        diary: EncryptedMessage::encrypt_with_key_config("Very personal stuff".to_string(), key_config.clone()).unwrap(),
    };
    println!("Encrypted diary: {:#?}", user.diary);

    // Decrypt the user's diary.
    let decrypted = user.diary.decrypt_with_key_config(key_config.clone()).unwrap();
    println!("Decrypted: {decrypted}");

    // Update the user's diary using the same encryption type & key config.
    user.diary = user.diary.with_new_payload_and_key_config("More personal stuff".to_string(), key_config).unwrap();
    println!("New encrypted diary: {:#?}", user.diary);
}

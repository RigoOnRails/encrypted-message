//! This example demonstrates how to use a key configuration
//! that depends on external data.

use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    key_config::Secret,
    utilities::key_generation::derive_key_from,
};
use secrecy::{ExposeSecret as _, SecretString};

/// NOTE: When depending on human-provided keys/passwords, ensure you derive them
/// using [`derive_key_from`]. Using a human-provided key directly is not secure as they're likely to be weak.
///
/// You should also use the `secrecy` crate in cases like these, to ensure safe key handling.
#[derive(Debug)]
struct UserKeyConfig {
    user_password: SecretString,
    salt: SecretString,
}

impl encrypted_message::KeyConfig for UserKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let raw_key = self.user_password.expose_secret().as_bytes();
        let salt = self.salt.expose_secret().as_bytes();
        vec![derive_key_from(raw_key, salt, 2_u32.pow(16))]
    }
}

struct User {
    diary: EncryptedMessage<String, Randomized, UserKeyConfig>,
}

fn main() {
    let key_config = UserKeyConfig {
        user_password: "human-password-that-should-be-derived".to_string().into(),
        salt: "unique-salt".to_string().into(),
    };

    // Encrypt a user's diary.
    let mut user = User {
        diary: EncryptedMessage::encrypt_with_key_config("Very personal stuff".to_string(), &key_config).unwrap(),
    };
    println!("Encrypted diary: {:#?}", user.diary);

    // Decrypt the user's diary.
    let decrypted = user.diary.decrypt_with_key_config(&key_config).unwrap();
    println!("Decrypted diary: {decrypted}");
}

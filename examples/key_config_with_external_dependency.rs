//! This example demonstrates how to use a key configuration
//! that depends on external data.

use encrypted_message::{
    EncryptedMessage,
    encryption_type::Randomized,
    key_config::Secret,
    key_generator,
};

/// NOTE: When depending on human-provided keys/passwords, ensure you derive them
/// using [`encrypted_message::key_generator::derive_key_from`].
///
/// Using a human-provided key directly is not secure as they're likely to be weak.
#[derive(Debug, Clone)]
struct UserKeyConfig {
    user_key: String,
}

impl encrypted_message::KeyConfig for UserKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let salt = b"8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI";
        vec![key_generator::derive_key_from(self.user_key.as_bytes(), salt, 2_u32.pow(16))]
    }
}

fn main() {
    let key_config = UserKeyConfig {
        user_key: "rigos-weak-key-because-hes-a-human".to_string(),
    };

    // Encrypt a payload.
    let encrypted: EncryptedMessage<String, Randomized, UserKeyConfig> = {
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

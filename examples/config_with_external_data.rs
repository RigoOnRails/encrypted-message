//! This example demonstrates how to use a configuration that depends on external data.

use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    config::{Config, Secret, ExposeSecret as _},
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

/// NOTE: When depending on human-provided keys/passwords, ensure you derive them
/// using a key derivation function (KDF). Using a human-provided key directly is not secure as they're likely to be weak.
///
/// You should also use the `secrecy` crate in cases like these, to ensure safe key handling.
#[derive(Debug)]
struct UserEncryptionConfig {
    user_password: Secret<String>,
    salt: Secret<String>,
}

impl Config for UserEncryptionConfig {
    type Strategy = Randomized;

    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let raw_key = self.user_password.expose_secret().as_bytes();
        let salt = self.salt.expose_secret().as_bytes();
        let derived_key = pbkdf2_hmac_array::<Sha256, 32>(raw_key, salt, 2_u32.pow(16)).into();

        vec![derived_key]
    }
}

fn main() {
    let config = UserEncryptionConfig {
        user_password: "human-password-that-should-be-derived".to_string().into(),
        salt: "unique-salt".to_string().into(),
    };

    // Encrypt a user's diary.
    let diary: EncryptedMessage::<String, UserEncryptionConfig> = {
        EncryptedMessage::encrypt_with_config("Very personal stuff".to_string(), &config).unwrap()
    };
    println!("Encrypted diary: {diary:#?}");

    // Decrypt the user's diary.
    let decrypted = diary.decrypt_with_config(&config).unwrap();
    println!("Decrypted diary: {decrypted}");
}

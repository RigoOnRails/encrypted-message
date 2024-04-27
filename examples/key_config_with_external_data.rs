//! This example demonstrates how to use a key configuration
//! that depends on external data.

use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    key_config::{KeyConfig, Secret},
};
use pbkdf2::pbkdf2_hmac_array;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::Sha256;

/// NOTE: When depending on human-provided keys/passwords, ensure you derive them
/// using [`derive_key_from`]. Using a human-provided key directly is not secure as they're likely to be weak.
///
/// You should also use the `secrecy` crate in cases like these, to ensure safe key handling.
#[derive(Debug)]
struct UserKeyConfig {
    user_password: SecretString,
    salt: SecretString,
}

impl KeyConfig for UserKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let raw_key = self.user_password.expose_secret().as_bytes();
        let salt = self.salt.expose_secret().as_bytes();
        let derived_key = pbkdf2_hmac_array::<Sha256, 32>(raw_key, salt, 2_u32.pow(16)).into();

        vec![derived_key]
    }
}

fn main() {
    let key_config = UserKeyConfig {
        user_password: "human-password-that-should-be-derived".to_string().into(),
        salt: "unique-salt".to_string().into(),
    };

    // Encrypt a user's diary.
    let diary: EncryptedMessage::<String, Randomized, UserKeyConfig> = {
        EncryptedMessage::encrypt_with_key_config("Very personal stuff".to_string(), &key_config).unwrap()
    };
    println!("Encrypted diary: {diary:#?}");

    // Decrypt the user's diary.
    let decrypted = diary.decrypt_with_key_config(&key_config).unwrap();
    println!("Decrypted diary: {decrypted}");
}

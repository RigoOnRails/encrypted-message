use encrypted_message::{
    EncryptedMessage,
    encryption_type::Randomized,
    key_config::Secret,
    utilities::key_generation::derive_key_from,
};
use secrecy::{ExposeSecret as _, SecretString};

#[derive(Debug)]
struct UserKeyConfig {
    user_password: SecretString,
    salt: SecretString,
}

impl encrypted_message::KeyConfig for UserKeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        let raw_key = self.user_password.expose_secret().as_bytes();
        let salt = self.salt.expose_secret().as_bytes();
        vec![derive_key_from(&raw_key, &salt, 2_u32.pow(16))]
    }
}

#[test]
fn key_config_with_external_data() {
    let key_config = UserKeyConfig {
        user_password: "human-password-that-should-be-derived".to_string().into(),
        salt: "unique-salt".to_string().into(),
    };

    // Encrypt a payload.
    let encrypted: EncryptedMessage<String, Randomized, UserKeyConfig> = {
        EncryptedMessage::encrypt_with_key_config("Hi".to_string(), &key_config).unwrap()
    };

    // Decrypt the payload.
    let decrypted = encrypted.decrypt_with_key_config(&key_config).unwrap();
    assert_eq!(decrypted, "Hi");

    // Create a new encrypted message with the same encryption type.
    let encrypted = encrypted.with_new_payload_and_key_config("Bonjour".to_string(), &key_config).unwrap();

    // Decrypt the new payload.
    let decrypted = encrypted.decrypt_with_key_config(&key_config).unwrap();
    assert_eq!(decrypted, "Bonjour");
}

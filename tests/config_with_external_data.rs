use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    config::{Config, Secret, ExposeSecret as _},
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

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

#[test]
fn config_with_external_data() {
    let config = UserEncryptionConfig {
        user_password: "human-password-that-should-be-derived".to_string().into(),
        salt: "unique-salt".to_string().into(),
    };

    // Encrypt a payload.
    let encrypted: EncryptedMessage<String, UserEncryptionConfig> = {
        EncryptedMessage::encrypt_with_config("Hi".to_string(), &config).unwrap()
    };

    // Decrypt the payload.
    let decrypted = encrypted.decrypt_with_config(&config).unwrap();
    assert_eq!(decrypted, "Hi");
}

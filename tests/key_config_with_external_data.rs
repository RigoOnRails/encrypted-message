use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    key_config::{KeyConfig, Secret},
};
use pbkdf2::pbkdf2_hmac_array;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::Sha256;

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
}

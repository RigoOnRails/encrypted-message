use encrypted_message::{EncryptedMessage, encryption_type::Randomized};

#[derive(Debug, Clone)]
struct KeyConfig {
    user_id: String,
}

impl encrypted_message::KeyConfig for KeyConfig {
    fn raw_keys(&self) -> Vec<secrecy::SecretVec<u8>> {
        vec![format!("{}-key", self.user_id).into_bytes().into()]
    }

    fn key_derivation_salt(&self) -> secrecy::SecretVec<u8> {
        format!("{}-key-derivation-salt", self.user_id).into_bytes().into()
    }
}

#[test]
fn key_config_with_external_dependency() {
    let key_config = KeyConfig {
        user_id: "rigo".to_string(),
    };

    // Encrypt a payload.
    let encrypted: EncryptedMessage<String, Randomized, KeyConfig> = {
        EncryptedMessage::encrypt_with_key_config("Hi".to_string(), key_config.clone()).unwrap()
    };

    // Decrypt the payload.
    encrypted.decrypt_with_key_config(key_config.clone()).unwrap();

    // Create a new encrypted message with the same encryption type.
    encrypted.with_new_payload_and_key_config("Bonjour".to_string(), key_config).unwrap();
}

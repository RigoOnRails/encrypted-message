use secrecy::Secret;

use super::base64;

trait KeyDecoder {
    fn decode_keys(keys: &[&str]) -> Vec<Secret<[u8; 32]>>;
}

/// Base64 key decoder.
pub struct Base64KeyDecoder;
impl Base64KeyDecoder {
    /// Decodes a list of base64-encoded keys.
    ///
    /// Panics if any of the keys are not valid base64, or if a decoded key is not 32 bytes long.
    pub fn decode_keys(keys: &[&str]) -> Vec<Secret<[u8; 32]>> {
        keys.iter()
            .map(|base64_key| {
                let key: [u8; 32] = base64::decode(base64_key).unwrap().try_into().unwrap();
                key.into()
            })
            .collect()
    }
}

/// Hex key decoder.
pub struct HexKeyDecoder;
impl HexKeyDecoder {
    /// Decodes a list of hex-encoded keys.
    ///
    /// Panics if any of the keys are not valid hex, or if a decoded key is not 32 bytes long.
    pub fn decode_keys(keys: &[&str]) -> Vec<Secret<[u8; 32]>> {
        keys.iter()
            .map(|hex_key| {
                let mut key = [0; 32];
                hex::decode_to_slice(hex_key, &mut key).unwrap();

                key.into()
            })
            .collect()
    }
}

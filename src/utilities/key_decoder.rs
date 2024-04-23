//! Key decoders for various formats.

use secrecy::{SecretString, Secret, ExposeSecret as _};

use super::base64;

trait KeyDecoder {
    fn decode_keys(keys: Vec<SecretString>) -> Vec<Secret<[u8; 32]>>;
}

/// Base64 key decoder.
pub struct Base64KeyDecoder;
impl Base64KeyDecoder {
    /// Decodes a list of base64-encoded keys.
    ///
    /// Panics if any of the keys are not valid base64, or if a decoded key is not 32 bytes long.
    pub fn decode_keys(keys: Vec<SecretString>) -> Vec<Secret<[u8; 32]>> {
        keys.iter()
            .map(|base64_key| {
                let key: [u8; 32] = base64::decode(base64_key.expose_secret()).unwrap().try_into().unwrap();
                key.into()
            })
            .collect()
    }
}

/// Hexadecimal key decoder.
pub struct HexKeyDecoder;
impl HexKeyDecoder {
    /// Decodes a list of hexadecimal-encoded keys.
    ///
    /// Panics if any of the keys are not valid hexadecimal, or if a decoded key is not 32 bytes long.
    pub fn decode_keys(keys: Vec<SecretString>) -> Vec<Secret<[u8; 32]>> {
        keys.iter()
            .map(|hex_key| {
                let mut key = [0; 32];
                hex::decode_to_slice(hex_key.expose_secret(), &mut key).unwrap();

                key.into()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decoder() {
        let decoded = Base64KeyDecoder::decode_keys(vec![SecretString::new("OE5kWmhyMVJjZG9hVnlIWURyUE9XdVp1OFdsQmxUd0k=".to_string())])
            .into_iter()
            .map(|key| String::from_utf8(key.expose_secret().to_vec()).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(decoded, vec!["8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI"]);
    }

    #[test]
    fn hex_decoder() {
        let decoded = HexKeyDecoder::decode_keys(vec![SecretString::new("384e645a6872315263646f61567948594472504f57755a7538576c426c547749".to_string())])
            .into_iter()
            .map(|key| String::from_utf8(key.expose_secret().to_vec()).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(decoded, vec!["8NdZhr1RcdoaVyHYDrPOWuZu8WlBlTwI"]);
    }
}

use secrecy::Secret;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

/// Derives a new 256-bit key from a raw key using the salt & iterations provided.
///
/// You should use this function to derive keys from human-provided keys,
/// as they're likely to be weak.
pub fn derive_key_from(key: &[u8], salt: &[u8], iterations: u32) -> Secret<[u8; 32]> {
    pbkdf2_hmac_array::<Sha256, 32>(key, salt, iterations).into()
}

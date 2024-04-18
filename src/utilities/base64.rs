use base64::{engine::general_purpose, DecodeError, Engine as _};

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    general_purpose::STANDARD.decode(input)
}

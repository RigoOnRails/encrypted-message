pub trait EncryptionType {
}

#[derive(Debug)]
pub struct Deterministic;
impl EncryptionType for Deterministic {
}

#[derive(Debug)]
pub struct Randomized;
impl EncryptionType for Randomized {
}

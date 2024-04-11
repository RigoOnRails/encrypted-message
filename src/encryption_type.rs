pub trait EncryptionType {
}

pub struct Deterministic;
impl EncryptionType for Deterministic {
}

pub struct Randomized;
impl EncryptionType for Randomized {
}

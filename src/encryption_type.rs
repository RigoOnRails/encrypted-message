mod private {
    pub trait Sealed {}

    impl Sealed for super::Deterministic {}
    impl Sealed for super::Randomized {}
}

pub trait EncryptionType: private::Sealed {
}

#[derive(Debug)]
pub struct Deterministic;
impl EncryptionType for Deterministic {
}

#[derive(Debug)]
pub struct Randomized;
impl EncryptionType for Randomized {
}

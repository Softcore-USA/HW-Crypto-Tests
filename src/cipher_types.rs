#[derive(clap::ValueEnum, Copy, Clone, Debug)]
pub enum CipherTypes {
    AES,
    DES
}

impl CipherTypes {
    pub fn cipher_length(&self) -> usize {
        match self {
            CipherTypes::AES => 16,
            CipherTypes::DES => 8,
        }
    }
}

impl std::fmt::Display for CipherTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CipherTypes::AES => write!(f, "AES"),
            CipherTypes::DES => write!(f, "DES"),
        }
    }
}
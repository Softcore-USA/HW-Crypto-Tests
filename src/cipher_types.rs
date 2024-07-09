use std::fmt::write;

#[derive(clap::ValueEnum, Copy, Clone, Debug)]
pub enum CipherTypes {
    HWAES,
    HWDES,
    SWAES,
    SWDES
}

impl CipherTypes {
    pub fn cipher_length(&self) -> usize {
        match self {
            CipherTypes::HWAES => 16,
            CipherTypes::HWDES => 8,
            CipherTypes::SWAES => 16,
            CipherTypes::SWDES => 8
        }
    }
}

impl std::fmt::Display for CipherTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CipherTypes::HWAES => write!(f, "HW_AES"),
            CipherTypes::HWDES => write!(f, "HW_DES"),
            CipherTypes::SWAES => write!(f, "SW_AES"),
            CipherTypes::SWDES => write!(f, "SW_DES")
        }
    }
}
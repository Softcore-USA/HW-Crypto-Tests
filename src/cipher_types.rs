const AES_KEY_DEFAULT: [u8; 16] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const DES_KEY_DEFAULT: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
const AES_PLAINTEXT_DEFAULT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DES_PLAINTEXT_DEFAULT: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];


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

    pub fn default_key(&self) -> Vec<u8> {
        match self {
            CipherTypes::HWAES => AES_KEY_DEFAULT.to_vec(),
            CipherTypes::HWDES => DES_KEY_DEFAULT.to_vec(),
            CipherTypes::SWAES => AES_KEY_DEFAULT.to_vec(),
            CipherTypes::SWDES => DES_KEY_DEFAULT.to_vec()
        }
    }

    pub fn default_plaintext(&self) -> Vec<u8> {
        match self {
            CipherTypes::HWAES => AES_PLAINTEXT_DEFAULT.to_vec(),
            CipherTypes::HWDES => DES_PLAINTEXT_DEFAULT.to_vec(),
            CipherTypes::SWAES => AES_PLAINTEXT_DEFAULT.to_vec(),
            CipherTypes::SWDES => DES_PLAINTEXT_DEFAULT.to_vec()
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
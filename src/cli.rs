use std::path::PathBuf;
use std::time::Duration;
use aes::cipher::{Block, BlockCipherEncrypt, Key};
use clap::Parser;
use des::cipher::KeyInit;
use log::{error, info};
use rand::Rng;
use regex::Regex;
use crate::cipher_types::CipherTypes;
use crate::config_handler::Config;

const CMD_DES_KEYCHANGE: u8 = 0xD7;
const CMD_AES128_KEYCHANGE: u8 = 0xE7;
const CMD_SWDES_ENC: u8 = 0x44;
const CMD_SWAES128_ENC: u8 = 0xAE;
const CMD_HWDES_ENC: u8 = 0xBE;
const CMD_HWAES128_ENC: u8 = 0xCA;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long="config-path")]
    config_path: Option<String>,
    #[arg(short, long)]
    runs: Option<u32>,
    #[arg(long)]
    key_hex: Option<String>,
    #[arg(long)]
    plaintext_hex: Option<String>,
    #[arg(short, long)]
    key: Option<String>,
    #[arg(short, long)]
    plaintext: Option<String>,
    #[arg(short, long, default_value = "hwaes")]
    cipher: CipherTypes,
    #[arg(short, long, default_value = "0")]
    delay: Option<u32>,
    #[arg(long)]
    key_send_flag: bool,
    #[arg(long)]
    use_random_keys: bool
}


impl Cli {
    pub fn get_config(&self) -> Config{
        let error_path= "./config.ini".to_string();
        Config::new(&PathBuf::from(self.config_path.as_ref().unwrap_or_else(|| {
            error!("Failed to load config at {:?}", self.config_path);
            &error_path
        })))
    }

    pub fn get_commands(&self) -> (u8, u8) {
        match self.cipher {
            CipherTypes::HWAES => {(CMD_AES128_KEYCHANGE, CMD_HWAES128_ENC)}
            CipherTypes::HWDES => {(CMD_DES_KEYCHANGE, CMD_HWDES_ENC)}
            CipherTypes::SWAES => {(CMD_AES128_KEYCHANGE, CMD_SWAES128_ENC)}
            CipherTypes::SWDES => {(CMD_DES_KEYCHANGE, CMD_SWDES_ENC)}
        }
    }
    
    pub fn generate_encrypted_block(&self, key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>{
        match self.cipher {
            CipherTypes::HWAES => {
                let aes = aes::Aes128::new(Key::<aes::Aes128>::from_slice(&key));
                let mut block= *Block::<aes::Aes128>::from_slice(plaintext.as_slice());
                aes.encrypt_block(&mut block);
                block.to_vec()
            }
            CipherTypes::HWDES => {
                // Perform software DES
                let des = des::Des::new(Key::<des::Des>::from_slice(&key));
                let mut block= *Block::<des::Des>::from_slice(plaintext.as_slice());
                des.encrypt_block(&mut block);
                block.to_vec()
            }
            CipherTypes::SWAES => {
                let aes = aes::Aes128::new(Key::<aes::Aes128>::from_slice(&key));
                let mut block= *Block::<aes::Aes128>::from_slice(plaintext.as_slice());
                aes.encrypt_block(&mut block);
                block.to_vec()
            }
            CipherTypes::SWDES => {
                let des = des::Des::new(Key::<des::Des>::from_slice(&key));
                let mut block= *Block::<des::Des>::from_slice(plaintext.as_slice());
                des.encrypt_block(&mut block);
                block.to_vec()
            }
        }
    }

    pub(crate) fn cipher_length(&self) -> usize {
        self.cipher.cipher_length()
    }

    pub(crate) fn get_plaintext(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        if let Some(plaintext) = self.plaintext.as_deref() {
            let val = validate_text(plaintext, self.cipher).expect("Invalid plaintext");
            info!("Using Plaintext: {}", plaintext);

            val
        } else if let Some(plaintext) = self.plaintext_hex.as_deref() {
            validate_hex(plaintext, self.cipher).expect("Invalid Hex");
            info!("Using Plaintext: {:02x?}", hex::decode(plaintext).expect("Failed to decode Hex from cli input"));

            hex::decode(plaintext).expect("Failed to decode Hex from cli input")
        } else if self.use_random_keys {
            (0..self.cipher.cipher_length()).map(|_| rng.gen()).collect()
        } else {
            vec![]
        }
    }

    /// Get current key if set and validate it for the set cipher, or generates a new one if `self.use_random_keys` is set.
    pub(crate) fn get_key(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        if let Some(key) = self.key.as_deref() {
            let val = validate_text(key, self.cipher).expect("Invalid plaintext");
            info!("Using Key: {}", key);

            val
        } else if let Some(key) = self.key_hex.as_deref() {
            validate_hex(key, self.cipher).expect("Invalid Hex");
            info!("Using Key: {:02x?}", hex::decode(key).expect("Failed to decode Hex from cli input"));

            hex::decode(key).expect("Failed to decode Hex from cli input")
        } else if self.use_random_keys {
            (0..self.cipher.cipher_length()).map(|_| rng.gen()).collect()
        } else {
            vec![]
        }
    }

    pub fn get_delay(&self) -> Duration {
        let d = self.delay.unwrap_or_else(|| 0);

        match self.cipher {
            CipherTypes::HWAES => {Duration::from_millis(3 + d as u64)}
            CipherTypes::HWDES => {Duration::from_millis(2 + d as u64)}
            CipherTypes::SWAES => {Duration::from_millis(20 + d as u64)}
            CipherTypes::SWDES => {Duration::from_millis(20 + d as u64)}
        }
    }

    pub fn is_finished(&self, total_runs: u32) -> bool{
        if let Some(count) = self.runs {
            if total_runs + 1 > count {
                return true;
            }
        } else {
            if self.key_hex.is_some() && self.plaintext_hex.is_some() {
                return true;
            }
        }

        false
    }
    pub fn get_send_key_flag(&self) -> bool { self.key_send_flag }
}

fn validate_text(plaintext: &str, cipher_types: CipherTypes) -> Result<Vec<u8>, String> {
    let expected_length = cipher_types.cipher_length();

    if plaintext.len() != expected_length {
        return Err(format!("Plaintext must be exactly {} characters long", expected_length));
    }

    // Convert the valid hexadecimal plaintext to a Vec<u8>
    let plaintext_bytes = Vec::from(plaintext.as_bytes());
    Ok(plaintext_bytes)
}

fn validate_hex(hex: &str, cipher_types: CipherTypes) -> Result<(), String> {
    let expected_length = cipher_types.cipher_length() * 2;

    let hex_regex = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
    if !hex_regex.is_match(&hex) || hex.len() != expected_length {
        return Err(format!(
            "Hex key must be exactly {} characters long and contain valid hexadecimal characters",
            expected_length
        ));
    }

    Ok(())
}
use std::path::PathBuf;
use std::time::Duration;
use aes::cipher::{Block, BlockCipherEncrypt, Key};
use clap::Parser;
use des::cipher::KeyInit;
use log::{error, info, warn};
use rand::Rng;
use regex::Regex;
use crate::cipher_types::CipherTypes;
use crate::config_handler::Config;
use crate::utils;

const CMD_DES_KEYCHANGE: u8 = 0xD7;
const CMD_AES128_KEYCHANGE: u8 = 0xE7;
const CMD_SWDES_ENC: u8 = 0x44;
const CMD_SWAES128_ENC: u8 = 0xAE;
const CMD_HWDES_ENC: u8 = 0xBE;
const CMD_HWAES128_ENC: u8 = 0xCA;


#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long)]
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
    pub key_send_flag: bool,
    #[arg(long)]
    pub use_random_keys: bool,
    #[arg(long)]
    pub use_random_plaintext: bool,
    #[arg(skip)]
    config: Option<Config>,
}


impl Cli {
    pub fn init_config(&mut self){
        if self.config_path.is_some() {
            let error_path = "./config.ini".to_string();
            self.config = Some(Config::new());
        } else {
            self.config = None;
        }
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

    pub fn cipher_length(&self) -> usize {
        self.cipher.cipher_length()
    }

    pub fn get_plaintext(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        if let Some(config) = &self.config {
            config.get_cipher_plaintext(self.cipher)
        } else if let Some(plaintext) = self.plaintext.as_deref() {
            let val = utils::validate_text(plaintext, self.cipher).expect("Invalid plaintext");
            info!("Using Plaintext: {}", plaintext);

            val
        } else if let Some(plaintext) = self.plaintext_hex.as_deref() {
            utils::validate_hex(plaintext, self.cipher).expect("Invalid Hex");
            info!("Using Plaintext: {}", plaintext);

            hex::decode(plaintext).expect("Failed to decode Hex from cli input")
        } else if self.use_random_plaintext {
            (0..self.cipher.cipher_length()).map(|_| rng.gen()).collect()
        } else {
            self.cipher.default_plaintext()
        }
    }

    /// Get current key if set and validate it for the set cipher, or generates a new one if `self.use_random_keys` is set.
    pub fn get_key(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        if let Some(config) = &self.config {
            config.get_cipher_key(self.cipher)
        } else if let Some(key) = self.key.as_deref() {
            let val = utils::validate_text(key, self.cipher).expect("Invalid plaintext");
            info!("Using Key: {}", key);

            val
        } else if let Some(key) = self.key_hex.as_deref() {
            utils::validate_hex(key, self.cipher).expect("Invalid Hex");
            info!("Using Key: {:02x?}", hex::decode(key).expect("Failed to decode Hex from cli input"));

            hex::decode(key).expect("Failed to decode Hex from cli input")
        } else if self.use_random_keys {
            (0..self.cipher.cipher_length()).map(|_| rng.gen()).collect()
        } else {
            self.cipher.default_key()
        }
    }

    pub fn get_delay(&self) -> Duration {
        let d = self.delay.unwrap_or(0);

        match self.cipher {
            CipherTypes::HWAES => {Duration::from_millis(3 + d as u64)}
            CipherTypes::HWDES => {Duration::from_millis(3 + d as u64)}
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
}
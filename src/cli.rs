use aes::cipher::{Block, BlockCipherEncrypt, Key};
use clap::Parser;
use des::cipher::KeyInit;
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
    pub config: Config,
}


impl Cli {

    pub fn init_config(&mut self){
        if let Some(path) = self.config_path.clone() {
            self.config = Config::new(&path)
        } else {
            let pt = if let Some(plaintext) = self.plaintext.as_deref() {
                utils::validate_text(plaintext, self.cipher).expect("Invalid plaintext")
            } else if let Some(plaintext) = self.plaintext_hex.as_deref() {
                utils::validate_hex(plaintext, self.cipher).expect("Invalid Hex");
                hex::decode(plaintext).expect("Failed to decode Hex from cli input")
            } else {
                self.cipher.default_plaintext()
            };

            let k = if let Some(key) = self.key.as_deref() {
                utils::validate_text(key, self.cipher).expect("Invalid plaintext")
            } else if let Some(key) = self.key_hex.as_deref() {
                utils::validate_hex(key, self.cipher).expect("Invalid Hex");
                hex::decode(key).expect("Failed to decode Hex from cli input")
            } else {
                self.cipher.default_key()
            };


            self.config = Config {
                key: k,
                plaintext: pt,
                runs: self.runs,
                delay: self.delay,
                algorithm: self.cipher,
                random_keys: Some(self.use_random_keys),
                random_plaintext: Some(self.use_random_plaintext)
            }
        }
    }

    pub fn get_commands(&self) -> (u8, u8) {
        match self.config.algorithm {
            CipherTypes::HWAES => {(CMD_AES128_KEYCHANGE, CMD_HWAES128_ENC)}
            CipherTypes::HWDES => {(CMD_DES_KEYCHANGE, CMD_HWDES_ENC)}
            CipherTypes::SWAES => {(CMD_AES128_KEYCHANGE, CMD_SWAES128_ENC)}
            CipherTypes::SWDES => {(CMD_DES_KEYCHANGE, CMD_SWDES_ENC)}
        }
    }
    
    pub fn generate_encrypted_block(&self, key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>{
        match self.config.algorithm {
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
        match !(self.key_send_flag || self.use_random_keys) {
            true => 0,
            false => self.config.algorithm.cipher_length()
        }
    }


    pub fn is_finished(&self, total_runs: u32) -> bool{
        if let Some(count) = self.config.runs {
            if total_runs + 1 > count {
                return true;
            }
        }

        false
    }
}
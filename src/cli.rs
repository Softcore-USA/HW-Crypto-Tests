use std::time::Duration;
use aes::cipher::{Block, BlockCipherEncrypt, Key};
use clap::Parser;
use des::cipher::KeyInit;
use log::info;
use rand::Rng;
use regex::Regex;
use crate::cipher_types::CipherTypes;

const CMD_DES_KEYCHANGE: u8 = 0xD7;
const CMD_AES128_KEYCHANGE: u8 = 0xE7;
const CMD_HWDES_ENC: u8 = 0xBE;
const CMD_HWAES128_ENC: u8 = 0xCA;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
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
    #[arg(short, long, default_value = "aes")]
    cipher: CipherTypes,
}


impl Cli {
    pub fn get_commands(&self) -> (u8, u8) {
        match self.cipher {
            CipherTypes::AES => {(CMD_AES128_KEYCHANGE, CMD_HWAES128_ENC)}
            CipherTypes::DES => {(CMD_DES_KEYCHANGE, CMD_HWDES_ENC)}
        }
    }
    
    pub fn generate_encrypted_block(&self, key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>{
        match self.cipher {
            CipherTypes::AES => {
                let aes = aes::Aes128::new(Key::<aes::Aes128>::from_slice(&key));
                let mut block= *Block::<aes::Aes128>::from_slice(plaintext.as_slice());
                aes.encrypt_block(&mut block);
                block.to_vec()
            }
            CipherTypes::DES => {
                // Perform software DES
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
        } else {
            (0..self.cipher.cipher_length()).map(|_| rng.gen()).collect()
        }
    }

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

        } else {
            (0..self.cipher.cipher_length()).map(|_| rng.gen()).collect()
        }
    }

    pub fn get_delay(&self) -> Duration {
        match self.cipher {
            CipherTypes::AES => {Duration::from_millis(3)}
            CipherTypes::DES => {Duration::from_millis(2)}
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
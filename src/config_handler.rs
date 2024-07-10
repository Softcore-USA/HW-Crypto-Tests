use std::{fs, io};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::io::Write;
use std::ops::Index;
use aes::Aes128;
use aes::cipher::{Block, Key};
use clap::Parser;
use des::Des;
use serde::{Serialize, Deserialize, Serializer};
use serde::de::Unexpected::Str;
use std::string::String;
use serde_bytes::Bytes;
use log;
use serde::Deserializer;
use serde_bytes::ByteBuf;
use crate::cipher_types::CipherTypes;

const AES_KEY_DEFAULT: [u8; 16] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const DES_KEY_DEFAULT: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
const AES_PLAINTEXT_DEFAULT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DES_PLAINTEXT_DEFAULT: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const RUNS_DEFAULT: Option<u32> = None;





/// Config type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    aes_key: Vec<u8>,
    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    des_key: Vec<u8>,
    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    aes_plaintext: Vec<u8>,
    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    des_plaintext: Vec<u8>,
    runs: Option<u32>,
}

fn serialize_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_string = hex::encode(bytes);
    serializer.serialize_str(&hex_string.to_ascii_uppercase())
}

fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = Deserialize::deserialize(deserializer)?;
    hex::decode(&hex_string).map_err(serde::de::Error::custom)
}


impl Config {

    pub fn new() -> Self {
        let path = "config.toml";
        if Path::new(path).exists() {
            log::info!("Found config. Loading...");
            let toml_str = fs::read_to_string(path).expect("Failed to read config file");
            toml::from_str(&toml_str).expect("Failed to parse config file")
        } else {
            log::warn!("Generating new config...");
            let config = Config::default();
            let mut toml_str = toml::to_string(&config).expect("Failed to serialize config");
            toml_str = format!("# Default Values\n{}", toml_str);
            let mut file = std::fs::File::create(path).expect("Failed to create config file");
            file.write_all(toml_str.as_bytes())
                .expect("Failed to write config file");
            config
        }
    }

    pub fn get_cipher_plaintext(&self, cipher_type: CipherTypes) -> Vec<u8>{
        match cipher_type {
            CipherTypes::HWAES | CipherTypes::SWAES => self.aes_plaintext.clone(),
            CipherTypes::HWDES | CipherTypes::SWDES => self.des_plaintext.clone(),
        }
    }

    pub fn get_cipher_key(&self, cipher_type: CipherTypes) -> Vec<u8>{
        match cipher_type {
            CipherTypes::HWAES | CipherTypes::SWAES => self.aes_key.clone(),
            CipherTypes::HWDES | CipherTypes::SWDES => self.des_key.clone(),
        }
    }
}

impl Default for Config{
    fn default() -> Self {
        Config{
            aes_key: AES_KEY_DEFAULT.to_vec(),
            des_key: DES_KEY_DEFAULT.to_vec(),
            aes_plaintext: AES_PLAINTEXT_DEFAULT.to_vec(),
            des_plaintext: DES_PLAINTEXT_DEFAULT.to_vec(),
            runs: RUNS_DEFAULT
        }
    }
}





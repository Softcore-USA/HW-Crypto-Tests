use std::fs;
use std::path::Path;
use std::io::Write;
use serde::{Serialize, Deserialize, Serializer};
use std::string::String;
use std::time::Duration;
use rand::Rng;
use serde::Deserializer;
use crate::cipher_types::CipherTypes;

const AES_KEY_DEFAULT: [u8; 16] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const DES_KEY_DEFAULT: [u8; 8] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
const AES_PLAINTEXT_DEFAULT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DES_PLAINTEXT_DEFAULT: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const RUNS_DEFAULT: Option<u32> = None;
const DELAY_DEFAULT: Option<u32> = None;
const ALGORITHM_DEFAULT: CipherTypes = CipherTypes::HWDES;



/// Config type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    pub(crate) key: Vec<u8>,

    #[serde(
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    pub(crate) plaintext: Vec<u8>,

    pub runs: Option<u32>,
    pub delay: Option<u32>,
    pub algorithm: CipherTypes,
    pub random_keys: Option<bool>,
    pub random_plaintext: Option<bool>
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

    pub fn new(path: &String) -> Self {
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

    pub fn get_delay(&self) -> Duration {
        let d = self.delay.unwrap();
        match self.algorithm {
            CipherTypes::HWAES => {Duration::from_millis(5 + d as u64)}
            CipherTypes::HWDES => {Duration::from_millis(3 + d as u64)}
            CipherTypes::SWAES => {Duration::from_millis(20 + d as u64)}
            CipherTypes::SWDES => {Duration::from_millis(20 + d as u64)}
        }
    }
    pub fn get_plaintext(&mut self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        if let Some(urk) = self.random_plaintext {
            if urk {
                self.plaintext = (0..self.algorithm.cipher_length()).map(|_| rng.gen()).collect()
            }
        }

        self.plaintext.clone()
    }

    /// Get current key if set and validate it for the set cipher, or generates a new one if `self.use_random_keys` is set.
    pub fn get_key(&mut self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        if let Some(urk) = self.random_keys {
            if urk {
                self.key = (0..self.algorithm.cipher_length()).map(|_| rng.gen()).collect()
            }
        }

        self.key.clone()
    }
}

impl Default for Config{
    fn default() -> Self {
        Config{
            // aes_key: AES_KEY_DEFAULT.to_vec(),
            // des_key: DES_KEY_DEFAULT.to_vec(),
            // aes_plaintext: AES_PLAINTEXT_DEFAULT.to_vec(),
            // des_plaintext: DES_PLAINTEXT_DEFAULT.to_vec(),
            key: DES_KEY_DEFAULT.to_vec(),
            plaintext: DES_PLAINTEXT_DEFAULT.to_vec(),
            runs: RUNS_DEFAULT,
            delay: DELAY_DEFAULT,
            algorithm: ALGORITHM_DEFAULT,
            random_keys: None,
            random_plaintext: None,
        }
    }
}





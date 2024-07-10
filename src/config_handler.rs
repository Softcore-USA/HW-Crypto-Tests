
use ini;
use std::{fs, io};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::ops::Index;
use clap::Parser;

const DEFAULT_CONFIG: &str = r#"# Config for default values when using the tool
[Default Values]
aes_key = 0xCAFEBABEDEADBEEF0001020304050607
des_key = 0xCAFEBABEDEADBEEF
aes_plaintext = 0x00000000000000000000000000000000
des_plaintext = 0x0000000000000000
"#;

/// Config type
#[derive(Clone, Debug)]
pub struct Config {
    pub config_path: PathBuf,
    data: HashMap<String, HashMap<String, Option<String>>>
}

impl Config {
    pub fn new(config_path: &PathBuf) -> Config {
        match Self::validate_path(config_path) {
            Ok(_) => {
                log::info!("Loaded config file: {:?}", config_path.to_str());
                Config {
                    config_path: PathBuf::from(config_path),
                    data: ini::ini!(config_path.to_str().expect("Could not convert Path to &str."))
                }
            },
            Err(e) => {
                log::error!("Error validating path: {:?}, ERROR: {}", config_path.to_str(), e);
                panic!();
            }
        }
    }

    /// Unsafe read given a section header and key value
    pub fn read_item(&self, section_key: String, key: String) -> String {
        self.data[&section_key].unwrap()[&key].unwrap().clone().unwrap()
    }

    /// Unsafe read given a section header and key value
    pub fn read_section(&self, section_key: String) -> HashMap<String, Option<String>> {
        self.data[&section_key].clone()
    }

    /// Safe read given a section header and key value
    pub fn try_read_item(&self, section_key: String, key: String) -> Option<String> {
        self.data[&section_key][&key].clone()
    }

    /// Safe read of a section returned as a HashMap
    pub fn try_read_section(&self, section_key: String) -> Result<HashMap<String, Option<String>>, String> {
        Ok(self.data[&section_key].clone())
    }

    /// Validates a given path, creates a .ini at that path if it doesn't exist
    fn validate_path(config_path: &PathBuf) -> io::Result<()> {
         match Path::new(config_path.as_path()).try_exists()? {
             true => Ok(()),
             false => {
                 log::warn!("No config file found at path: {:?}, Generating default config...", config_path.to_str());
                 fs::write(config_path, DEFAULT_CONFIG)?;
                 Ok(())
             }
         }
    }
}



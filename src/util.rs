use rand::Rng;
use regex::Regex;
use crate::{CipherTypes, Cli};



pub fn get_plaintext(cli: &Cli) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    if let Some(plaintext) = cli.plaintext.as_deref() {
        let val = validate_text(plaintext, cli.cipher).expect("Invalid plaintext");
        println!("Using Plaintext: {}", plaintext);
        val
    } else if let Some(plaintext) = cli.plaintext_hex.as_deref() {
        validate_hex(plaintext, cli.cipher).expect("Invalid Hex");
        println!("Using Plaintext: {:02x?}", hex::decode(plaintext).expect("Failed to decode Hex from cli input"));
        hex::decode(plaintext).expect("Failed to decode Hex from cli input")
    } else {
        (0..cli.cipher.cipher_length()).map(|_| rng.gen()).collect()
    }
}

pub fn get_key(cli: &Cli) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    if let Some(key) = cli.key.as_deref() {
        let val = validate_text(key, cli.cipher).expect("Invalid plaintext");
        println!("Using Key: {}", key);
        val
    } else if let Some(key) = cli.key_hex.as_deref() {
        validate_hex(key, cli.cipher).expect("Invalid Hex");
        println!("Using Key: {:02x?}", hex::decode(key).expect("Failed to decode Hex from cli input"));
        hex::decode(key).expect("Failed to decode Hex from cli input")

    } else {
        (0..cli.cipher.cipher_length()).map(|_| rng.gen()).collect()
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
use regex::Regex;
use crate::cipher_types::CipherTypes;

pub fn validate_text(plaintext: &str, cipher_types: CipherTypes) -> Result<Vec<u8>, String> {
    let expected_length = cipher_types.cipher_length();

    if plaintext.len() != expected_length {
        return Err(format!("Plaintext must be exactly {} characters long", expected_length));
    }

    // Convert the valid hexadecimal plaintext to a Vec<u8>
    let plaintext_bytes = Vec::from(plaintext.as_bytes());
    Ok(plaintext_bytes)
}

pub fn validate_hex(hex: &str, cipher_types: CipherTypes) -> Result<(), String> {
    let expected_length = cipher_types.cipher_length() * 2;

    let hex_regex = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
    if !hex_regex.is_match(hex) || hex.len() != expected_length {
        return Err(format!(
            "Hex key must be exactly {} characters long and contain valid hexadecimal characters",
            expected_length
        ));
    }

    Ok(())
}
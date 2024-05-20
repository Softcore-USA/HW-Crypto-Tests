mod util;

use std::io::{Write};
use std::thread::sleep;
use std::time::Duration;
use clap::Parser;
use des::cipher::{Block, BlockEncrypt, Key, KeyInit};
use crate::util::{get_key, get_plaintext};

#[derive(clap::ValueEnum, Copy, Clone, Debug)]
enum CipherTypes {
    AES,
    DES
}

impl CipherTypes {
    pub fn cipher_length(&self) -> usize {
        match self {
            CipherTypes::AES => 16,
            CipherTypes::DES => 8,
        }
    }
}

impl std::fmt::Display for CipherTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CipherTypes::AES => write!(f, "AES"),
            CipherTypes::DES => write!(f, "DES"),
        }
    }
}
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
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

const CMD_DES_KEYCHANGE: u8 = 0xD7;
const CMD_AES128_KEYCHANGE: u8 = 0xE7;
const CMD_HWDES_ENC: u8 = 0xBE;
const CMD_HWAES128_ENC: u8 = 0xCA;

impl Cli {
    pub fn get_commands(&self) -> (u8, u8) {
        match self.cipher {
            CipherTypes::AES => {(CMD_AES128_KEYCHANGE, CMD_HWAES128_ENC)}
            CipherTypes::DES => {(CMD_DES_KEYCHANGE, CMD_HWDES_ENC)}
        }
    }

    pub fn get_delay(&self) -> Duration {
        match self.cipher {
            CipherTypes::AES => {Duration::from_millis(3)}
            CipherTypes::DES => {Duration::from_millis(2)}
        }
    }
}


fn main() {
    let cli = Cli::parse();

    let mut port_name = String::new();
    let baud_rate = 115200;

    match serialport::available_ports() {
        Ok(ports) => {
            println!("Available ports:");
            for port in ports {
                println!("Port: {}", port.port_name);
                match port.port_type {
                    serialport::SerialPortType::UsbPort(info) => {
                        println!("Type: USB");
                        println!(" - VID: {}", info.vid);
                        println!(" - PID: {}", info.pid);
                        println!(" - Serial Number: {:?}", info.serial_number);

                        if info.pid == 8 && info.vid == 1204 {
                            println!("Found receiver...");
                            port_name = port.port_name.clone();
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if port_name.is_empty() {
                eprintln!("Could not find ground station");
                return;
            }
        }
        Err(e) => {
            eprintln!("Error listing ports: {}", e);
        }
    }

    let mut port = serialport::new(port_name, baud_rate)
        .timeout(std::time::Duration::from_millis(2))
        .open()
        .expect("Failed to open port...");
    let mut serial_buf = [0u8; 32];


    let mut matches = 0;
    let mut total = 0;

    let (key_change, hw_enc) = cli.get_commands();


    loop {
        let key = get_key(&cli);
        let plaintext= get_plaintext(&cli);

        let block = match cli.cipher {
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
        };



        // Write key to design, send an CMD_DES_KEYCHANGE command first
        port.write(&[key_change]).unwrap();
        port.write(key.as_slice()).unwrap();

        // Write plaintext to design, send an CMD_HWDES_ENC command first
        port.write(&[hw_enc]).unwrap();
        port.write(plaintext.as_slice()).unwrap();

        // Need to let the writes propagate through serial to the design
        sleep(cli.get_delay());

        // Read from serial into the buffer
        match port.read(&mut serial_buf[..]) {
            Ok(t) => {
                let len = cli.cipher.cipher_length();
                let hw_buf = &serial_buf[len..t];
                total += 1;

                // Check if they're equal
                if block.eq(hw_buf) {
                    matches += 1;

                    println!("{:02x?} : Tests passed {}/{}", block, matches, total);
                } else {
                    println!("{:02x?} {:02x?} : Test Failed", block, hw_buf);
                    sleep(Duration::from_secs(2));
                }
            }
            Err(e) => {
                println!("{}", e)
            }
        }

        if let Some(count) = cli.runs {
            if total + 1 > count {
                return;
            }
        } else {
            if cli.key_hex.is_some() && cli.plaintext_hex.is_some() {
                return;
            }
        }
    }

}






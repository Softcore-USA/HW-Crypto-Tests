mod cli;
mod cipher_types;
mod config_handler;

use std::thread::sleep;
use std::time::Duration;
use clap::Parser;
use log::{error, info, warn};
use simple_logger::SimpleLogger;
use crate::cli::Cli;


fn main() {
    SimpleLogger::new().init().unwrap();
    let cli = Cli::parse();
    let config = cli.get_config();

    let mut port_name = String::new();
    let baud_rate = 115200;

    match serialport::available_ports() {
        Ok(ports) => {
            info!("Available ports:");
            for port in ports {
                info!("Port: {}", port.port_name);
                match port.port_type {
                    serialport::SerialPortType::UsbPort(info) => {
                        info!("Type: USB");
                        info!(" - VID: {}", info.vid);
                        info!(" - PID: {}", info.pid);
                        info!(" - Serial Number: {:?}", info.serial_number);

                        if (info.pid == 8 && info.vid == 1204) || (info.pid == 24577 && info.vid == 1027) {
                            info!("Found test device...");
                            port_name = port.port_name.clone();
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if port_name.is_empty() {
                error!("Could not find test device (Check connections/power)");
                return;
            }
        }
        Err(e) => {
            error!("Error listing ports: {}", e);
        }
    }

    let mut port = serialport::new(port_name, baud_rate)
        .timeout(std::time::Duration::from_millis(2))
        .open()
        .expect("Failed to open port...");
    let mut serial_buf = [0u8; 32];


    let mut matches = 0;
    let mut total = 0;

    let (kc_cmd, enc_cmd) = cli.get_commands();


    loop {
        let key = cli.get_key();

        if cli.get_send_key_flag() == true {
            // Write key to design, send an CMD_DES_KEYCHANGE command first
            port.write(&[kc_cmd]).unwrap();
            port.write(key.as_slice()).unwrap();
        }

        let plaintext= cli.get_plaintext();

        // Write plaintext to design, send an CMD_HWDES_ENC command first
        port.write(&[enc_cmd]).unwrap();
        port.write(plaintext.as_slice()).unwrap();

        // Need to let the writes propagate through serial to the design
        sleep(cli.get_delay());

        // Read from serial into the buffer
        match port.read(&mut serial_buf[..]) {
            Ok(t) => {
                let len = cli.cipher_length();
                let hw_buf = &serial_buf[len..t];
                total += 1;

                let block = cli.generate_encrypted_block(key, plaintext);

                // Check if they're equal
                if block.eq(hw_buf) {
                    matches += 1;

                    info!("{:02x?} : Tests passed {}/{}", block, matches, total);
                } else {
                    warn!("{:02x?} {:02x?} : Test Failed", block, hw_buf);
                    sleep(Duration::from_secs(2));
                }
            }
            Err(e) => {
                error!("{}", e)
            }
        }

        if cli.is_finished(total) {
            return;
        }
    }

}






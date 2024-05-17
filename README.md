# HW-Crypto-Tests

## Description
This project is a CLI tool we used to test our AES-128 and DES designs. 

The tool will:
- Automatically detect a virtual COM port with a valid serial connection.
- Randomly generate cryptographic Keys and Data based on the designated algorithm.
- Run through the designated software encryption.
- Send that data over serial to a board running one of the two hardware encryption designs.
- Once it gets information back over serial, it compares the software encryption output to the information it received over serial and report if they match or not.

Options:  
  -r, --runs <RUNS> 
      --key-hex <KEY_HEX> 
      --plaintext-hex <PLAINTEXT_HEX>
  -k, --key <KEY> 
  -p, --plaintext <PLAINTEXT> 
  -c, --cipher <CIPHER>                [default: aes] [possible values: aes, des]  
  -h, --help                           Print help  
  -V, --version                        Print version  

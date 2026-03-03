// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use clap::Parser;
use dialoguer::Password;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use ::aloecrypt::KeyPEM;
use ::aloecrypt::aloecrypt;
use ::aloecrypt::cli;
use ::aloecrypt::keyfile;
use ::aloecrypt::keypair;
use aloecrypt::AloecryptPackage;
use cli::{Cli, Commands, KeyCommands};
use keyfile::{Keyfile, key_pack, key_unpack};
use keypair::Keypair; // Disambiguate the trait from the struct

/// Safely prompts the user for a password, masking input.
fn prompt_password(prompt: &str, confirm: bool) -> String {
    eprintln!("(input is hidden)");
    if confirm {
        Password::new()
            .with_prompt(prompt)
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()
            .expect("Failed to read password from TTY")
    } else {
        Password::new()
            .with_prompt(prompt)
            .interact()
            .expect("Failed to read password from TTY")
    }
}

/// Reads from a file path if provided, otherwise reads from stdin (useful for pipes)
fn read_input(path: Option<&PathBuf>) -> Result<String, std::io::Error> {
    match path {
        Some(p) => fs::read_to_string(p),
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Helper to parse a 16-byte array from a string, truncating or padding with zeros
fn parse_16_bytes(input: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    let bytes = input.as_bytes();
    let len = bytes.len().min(16);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

fn bail(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Key { command } => match command {
            KeyCommands::New { out, password } => {
                let pw = password
                    .clone()
                    .unwrap_or_else(|| prompt_password("Enter new password", true));

                let kp = Keypair::new();
                let kf = match key_pack(&kp, pw.as_bytes()) {
                    Ok(kf) => kf,
                    Err(e) => bail(&format!("Failed to pack new keypair: {}", e)),
                };
                let pem = kf.pem();

                if let Some(out_path) = out {
                    if let Err(e) = fs::write(out_path, &pem) {
                        bail(&format!("Failed to write keyfile to {:?}: {}", out_path, e));
                    }
                    eprintln!("Keyfile saved to {:?}", out_path);
                } else {
                    print!("{}", pem);
                }
            }

            KeyCommands::Info { keyfile, password } => {
                let pem_str = match read_input(keyfile.as_ref()) {
                    Ok(s) => s,
                    Err(e) => bail(&format!("Failed to read keyfile: {}", e)),
                };
                let kf = match Keyfile::loads(&pem_str) {
                    Ok(kf) => kf,
                    Err(e) => bail(&format!("Invalid keyfile format: {}", e)),
                };

                let pw = password
                    .clone()
                    .unwrap_or_else(|| prompt_password("Enter password to unlock", false));

                let kp = match key_unpack(&kf, pw.as_bytes()) {
                    Ok(kp) => kp,
                    Err(_) => bail("Failed to unlock keyfile. Wrong password?"),
                };

                println!("--- Keyfile Info ---");
                println!("CID:        {}", hex::encode(kp.cid));
                println!("Public Key: {}", hex::encode(kp.public_key));
            }

            KeyCommands::Pubkey { keyfile } => {
                let pem_str = match read_input(keyfile.as_ref()) {
                    Ok(s) => s,
                    Err(e) => bail(&format!("Failed to read keyfile: {}", e)),
                };
                let kf = match Keyfile::loads(&pem_str) {
                    Ok(kf) => kf,
                    Err(e) => bail(&format!("Invalid keyfile format: {}", e)),
                };
                // Public key is unencrypted in the keyfile — no password needed
                print!("{}", hex::encode(kf.public_key));
            }

            KeyCommands::Setpw {
                keyfile,
                out,
                password,
                new_password,
            } => {
                let pem_str = match read_input(keyfile.as_ref()) {
                    Ok(s) => s,
                    Err(e) => bail(&format!("Failed to read keyfile: {}", e)),
                };
                let kf = match Keyfile::loads(&pem_str) {
                    Ok(kf) => kf,
                    Err(e) => bail(&format!("Invalid keyfile format: {}", e)),
                };

                let current_pw = password
                    .clone()
                    .unwrap_or_else(|| prompt_password("Enter current password", false));

                let kp = match key_unpack(&kf, current_pw.as_bytes()) {
                    Ok(kp) => kp,
                    Err(_) => bail("Failed to unlock keyfile. Wrong password?"),
                };

                let next_pw = new_password
                    .clone()
                    .unwrap_or_else(|| prompt_password("Enter NEW password", true));

                let new_kf = match key_pack(&kp, next_pw.as_bytes()) {
                    Ok(kf) => kf,
                    Err(e) => bail(&format!("Failed to repack keyfile: {}", e)),
                };
                let new_pem = new_kf.pem();

                if let Some(out_path) = out {
                    if let Err(e) = fs::write(out_path, &new_pem) {
                        bail(&format!(
                            "Failed to write new keyfile to {:?}: {}",
                            out_path, e
                        ));
                    }
                    eprintln!("Updated keyfile saved to {:?}", out_path);
                } else {
                    print!("{}", new_pem);
                }
            }
        },

        Commands::Pack(args) => {
            let pem_str = match fs::read_to_string(&args.keyfile) {
                Ok(s) => s,
                Err(e) => bail(&format!("Failed to read keyfile {:?}: {}", args.keyfile, e)),
            };
            let kf = match Keyfile::loads(&pem_str) {
                Ok(kf) => kf,
                Err(e) => bail(&format!("Invalid keyfile format: {}", e)),
            };

            let pw = args
                .password
                .clone()
                .unwrap_or_else(|| prompt_password("Enter password to unlock your key", false));
            let my_kp = match key_unpack(&kf, pw.as_bytes()) {
                Ok(kp) => kp,
                Err(_) => bail("Failed to unlock keyfile. Wrong password?"),
            };

            let peer_bytes = match hex::decode(&args.peer_pubkey) {
                Ok(b) => b,
                Err(_) => bail("Invalid peer public key: not valid hex"),
            };
            if peer_bytes.len() != 32 {
                bail(&format!(
                    "Invalid peer public key: expected 32 bytes, got {}",
                    peer_bytes.len()
                ));
            }
            let mut peer_pubkey = [0u8; 32];
            peer_pubkey.copy_from_slice(&peer_bytes);

            let app_id_16 = parse_16_bytes(&args.app_id);

            let nonce_16 = match &args.nonce {
                Some(n) => parse_16_bytes(n),
                None => {
                    let mut n = [0u8; 16];
                    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut n);
                    n
                }
            };

            let input_data = match fs::read(&args.input_file) {
                Ok(d) => d,
                Err(e) => bail(&format!(
                    "Failed to read input file {:?}: {}",
                    args.input_file, e
                )),
            };
            let byte_buf = serde_bytes::ByteBuf::from(input_data);

            let package = match AloecryptPackage::pack(
                &byte_buf,
                &my_kp,
                &peer_pubkey,
                &app_id_16,
                &nonce_16,
            ) {
                Ok(p) => p,
                Err(e) => bail(&format!("Failed to pack data: {}", e)),
            };

            let out_bytes = match package.to_bytes() {
                Ok(b) => b,
                Err(e) => bail(&format!("Failed to serialize package: {}", e)),
            };
            if let Err(e) = fs::write(&args.out, out_bytes) {
                bail(&format!(
                    "Failed to write output package {:?}: {}",
                    args.out, e
                ));
            }
            eprintln!("Successfully packed and encrypted to {:?}", args.out);
        }

        Commands::Unpack(args) => {
            let pem_str = match fs::read_to_string(&args.keyfile) {
                Ok(s) => s,
                Err(e) => bail(&format!("Failed to read keyfile {:?}: {}", args.keyfile, e)),
            };
            let kf = match Keyfile::loads(&pem_str) {
                Ok(kf) => kf,
                Err(e) => bail(&format!("Invalid keyfile format: {}", e)),
            };

            let pw = args
                .password
                .clone()
                .unwrap_or_else(|| prompt_password("Enter password to unlock your key", false));
            let my_kp = match key_unpack(&kf, pw.as_bytes()) {
                Ok(kp) => kp,
                Err(_) => bail("Failed to unlock keyfile. Wrong password?"),
            };

            let pkg_bytes = match fs::read(&args.input_package) {
                Ok(b) => b,
                Err(e) => bail(&format!(
                    "Failed to read input package {:?}: {}",
                    args.input_package, e
                )),
            };
            let package = match AloecryptPackage::from_bytes(&pkg_bytes) {
                Ok(p) => p,
                Err(e) => bail(&format!("Invalid package format: {}", e)),
            };

            // 1. Verify the signature is cryptographically valid
            if !package.verify_hdr() {
                eprintln!(
                    "CRITICAL: Package header signature verification failed. The payload has been tampered with."
                );
                std::process::exit(1);
            }

            // 2. Identity Assertion: Check who actually signed it
            let actual_signer_hex = hex::encode(package.hdr.signer_key);

            if let Some(expected_hex) = &args.expected_pubkey {
                if expected_hex.trim().to_lowercase() != actual_signer_hex {
                    eprintln!(
                        "CRITICAL: Sender identity mismatch! Potential Man-in-the-Middle attack."
                    );
                    eprintln!("Expected: {}", expected_hex);
                    eprintln!("Actual:   {}", actual_signer_hex);
                    std::process::exit(1);
                }
            } else {
                eprintln!("Verified. Signed by: {}", actual_signer_hex);
            }

            // 3. Unpack the payload
            let unpacked_data: serde_bytes::ByteBuf = match package.unpack(&my_kp) {
                Ok(d) => d,
                Err(e) => bail(&format!("Failed to decrypt and unpack payload: {}", e)),
            };

            match &args.out {
                Some(out_path) => {
                    if let Err(e) = fs::write(out_path, unpacked_data.as_slice()) {
                        bail(&format!(
                            "Failed to write extracted file {:?}: {}",
                            out_path, e
                        ));
                    }
                    eprintln!("Successfully unpacked to {:?}", out_path);
                }
                None => {
                    if let Err(e) = io::stdout().write_all(unpacked_data.as_slice()) {
                        bail(&format!("Failed to write to stdout: {}", e));
                    }
                }
            }
        }
    }
}

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
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aloecrypt",
    about = "aloecrypt - encrypt, sign, and package data using Ed25519 identity keys.\n\n\
             Use 'key new' to generate a password-protected keyfile, then 'pack' and 'unpack'\n\
             to send encrypted packages to other keyholders.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate, inspect, and manage keyfiles
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Decrypt and verify an .alo package using your keyfile
    Unpack(UnpackArgs),
    /// Encrypt and sign a file into an .alo package for a specific recipient
    Pack(PackArgs),
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new password-protected keyfile
    New {
        /// Write keyfile to this path (prints to stdout if omitted)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Password to protect the key (will prompt interactively if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Unlock a keyfile and display its CID and public key
    Info {
        /// Path to keyfile (reads from stdin if omitted, e.g. via pipe)
        #[arg(short = 'k', long)]
        keyfile: Option<PathBuf>,

        /// Password to unlock (will prompt interactively if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Print the hex-encoded public key (no password required, for use in scripts)
    Pubkey {
        /// Path to keyfile (reads from stdin if omitted)
        #[arg(short = 'k', long)]
        keyfile: Option<PathBuf>,
    },

    /// Re-encrypt a keyfile with a new password
    Setpw {
        /// Path to keyfile (reads from stdin if omitted)
        #[arg(short = 'k', long)]
        keyfile: Option<PathBuf>,

        /// Write updated keyfile to this path (prints to stdout if omitted)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Current password (will prompt interactively if omitted)
        #[arg(short, long)]
        password: Option<String>,

        /// New password (will prompt interactively if omitted)
        #[arg(short = 'n', long)]
        new_password: Option<String>,
    },
}

#[derive(Args)]
pub struct UnpackArgs {
    /// Path to the .alo package to decrypt
    pub input_package: PathBuf,

    /// Expected sender public key (hex). Rejects the package if the signer doesn't match
    pub expected_pubkey: Option<String>,

    /// Your keyfile (recipient identity)
    #[arg(short = 'k', long)]
    pub keyfile: PathBuf,

    /// Write decrypted output to this path (prints to stdout if omitted)
    #[arg(short, long)]
    pub out: Option<PathBuf>,

    /// Output format for the payload
    #[arg(long, default_value = "json")]
    pub fmt: OutputFormat,

    /// Password to unlock your keyfile (will prompt interactively if omitted)
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(Args)]
pub struct PackArgs {
    /// File to encrypt and package
    pub input_file: PathBuf,

    /// Recipient's public key (64-char hex string, see 'key pubkey')
    pub peer_pubkey: String,

    /// Application ID tag (up to 16 bytes, padded/truncated to exactly 16)
    pub app_id: String,

    /// Your keyfile (sender identity)
    #[arg(short = 'k', long)]
    pub keyfile: PathBuf,

    /// Output path for the .alo package
    #[arg(short, long)]
    pub out: PathBuf,

    /// Password to unlock your keyfile (will prompt interactively if omitted)
    #[arg(short, long)]
    pub password: Option<String>,

    /// 16-byte nonce (auto-generated if omitted; truncated/padded to 16 bytes)
    #[arg(long)]
    pub nonce: Option<String>,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Json,
    Yaml,
    Msgpack,
}

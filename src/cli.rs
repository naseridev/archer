use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "archer")]
#[command(about = "Encrypt files disguised as ISO images", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(
        name = "enc",
        about = "Encrypt file as fake Arch ISO",
        long_about = None
    )]
    Enc {
        #[arg(value_name = "FILE", help = "File to encrypt")]
        input: PathBuf,

        #[arg(
            short = 'o',
            long = "output",
            value_name = "FILE",
            help = "Output path (default: archlinux-YYYY.MM.DD-x86_64.iso)"
        )]
        output: Option<PathBuf>,

        #[arg(
            short = 's',
            long = "size",
            value_name = "MB",
            help = "Minimum output size in MB (pads with ISO sectors)"
        )]
        min_size_mb: Option<u64>,
    },

    #[command(
        name = "dec",
        about = "Decrypt archer-encrypted file",
        long_about = None
    )]
    Dec {
        #[arg(value_name = "FILE", help = "Encrypted file")]
        input: PathBuf,

        #[arg(
            short = 'o',
            long = "output",
            value_name = "FILE",
            help = "Where to write decrypted output"
        )]
        output: PathBuf,
    },
}

pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    fn new(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.data) }
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.fill(0);
    }
}

pub fn get_password(confirm: bool) -> Result<SecureString, crate::error::ArcherError> {
    if let Ok(password) = std::env::var("ARCHER_KEY") {
        return Ok(SecureString::new(password));
    }

    let password =
        rpassword::prompt_password("Password: ").map_err(crate::error::ArcherError::Io)?;

    if confirm {
        let confirm_password = rpassword::prompt_password("Confirm password: ")
            .map_err(crate::error::ArcherError::Io)?;

        if password != confirm_password {
            return Err(crate::error::ArcherError::PasswordMismatch);
        }
    }

    Ok(SecureString::new(password))
}

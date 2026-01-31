use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArcherError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("File already exists: {0}")]
    FileExists(String),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Password mismatch")]
    PasswordMismatch,
}

pub type Result<T> = std::result::Result<T, ArcherError>;

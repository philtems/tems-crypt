use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption error: {0}")]
    Crypto(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Key error: {0}")]
    Key(String),

    #[error("Hash error: {0}")]
    Hash(String),

    #[error("Invalid magic number")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Integrity check failed")]
    IntegrityCheckFailed,

    #[error("Walkdir error: {0}")]
    Walkdir(#[from] walkdir::Error),

    #[error("Strip prefix error")]
    StripPrefix,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::env::VarError> for Error {
    fn from(err: std::env::VarError) -> Self {
        Error::InvalidParams(format!("Environment variable error: {}", err))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::InvalidFormat(format!("UTF-8 error: {}", err))
    }
}


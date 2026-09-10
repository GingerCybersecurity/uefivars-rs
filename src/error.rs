use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid {format} input: {message}")]
    InvalidInput {
        format: &'static str,
        message: String,
    },

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}

impl Error {
    #[allow(dead_code)] // used by format modules added in later phases
    pub(crate) fn invalid(format: &'static str, message: impl Into<String>) -> Self {
        Error::InvalidInput {
            format,
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

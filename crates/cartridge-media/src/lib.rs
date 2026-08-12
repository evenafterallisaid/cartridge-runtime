mod audio;
mod graphics;
mod input;

pub use audio::*;
pub use graphics::*;
pub use input::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("invalid media document: {0}")]
    Invalid(String),
    #[error("media limit exceeded: {0}")]
    Limit(String),
    #[error("media asset error: {0}")]
    Asset(String),
    #[error("media encoding failed: {0}")]
    Encoding(String),
}

pub type Result<T> = std::result::Result<T, MediaError>;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("authentication failed")]
    AuthFailed,

    #[error("session closed")]
    SessionClosed,

    #[error("stream closed")]
    StreamClosed,

    #[error("invalid segment: {0}")]
    InvalidSegment(String),

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("max sessions exceeded")]
    MaxSessionsExceeded,

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("segment too large: {0} bytes")]
    SegmentTooLarge(usize),
}

pub type Result<T> = std::result::Result<T, Error>;

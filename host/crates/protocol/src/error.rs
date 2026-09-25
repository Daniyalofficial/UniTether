//! ULP error types.

/// Fatal protocol violation: the session MUST be torn down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub kind: ErrorKind,
    pub detail: String,
}

impl ProtocolError {
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self { kind, detail: detail.into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    BadMagic,
    BadVersion,
    BadLength,
    Incomplete,
    BadChannel,
    WrongDirection,
    BadMessage,
    BadPayload,
    Auth,
    CipherNegotiation,
    Timeout,
    Io,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protocol error [{:?}]: {}", self.kind, self.detail)
    }
}

impl std::error::Error for ProtocolError {}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::new(ErrorKind::Io, e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

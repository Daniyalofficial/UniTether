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
    // v1.1 structured codes (docs/02 §15.4)
    Limit,
    IdentityRequired,
    Throttled,
    Revoked,
    ResumeInvalid,
    UpgradeRequired,
}

/// Stable wire error codes (ULP v1.1, append-only).
pub mod codes {
    pub const AUTH: u16 = 0x0001;
    pub const CIPHER: u16 = 0x0002;
    pub const VERSION: u16 = 0x0003;
    pub const FORMAT: u16 = 0x0004;
    pub const LIMIT: u16 = 0x0005;
    pub const TIMEOUT: u16 = 0x0006;
    pub const IDENTITY_REQUIRED: u16 = 0x0007;
    pub const THROTTLED: u16 = 0x0008;
    pub const REVOKED: u16 = 0x0009;
    pub const RESUME_INVALID: u16 = 0x000A;
    pub const UPGRADE_REQUIRED: u16 = 0x000B;
}

impl ErrorKind {
    /// Stable wire code (docs/02 §15.4).
    pub const fn code(self) -> u16 {
        match self {
            ErrorKind::BadMagic => codes::FORMAT,
            ErrorKind::BadVersion => codes::VERSION,
            ErrorKind::BadLength => codes::FORMAT,
            ErrorKind::Incomplete => codes::FORMAT,
            ErrorKind::BadChannel => codes::FORMAT,
            ErrorKind::WrongDirection => codes::FORMAT,
            ErrorKind::BadMessage => codes::FORMAT,
            ErrorKind::BadPayload => codes::FORMAT,
            ErrorKind::Auth => codes::AUTH,
            ErrorKind::CipherNegotiation => codes::CIPHER,
            ErrorKind::Timeout => codes::TIMEOUT,
            ErrorKind::Io => codes::TIMEOUT,
            ErrorKind::Limit => codes::LIMIT,
            ErrorKind::IdentityRequired => codes::IDENTITY_REQUIRED,
            ErrorKind::Throttled => codes::THROTTLED,
            ErrorKind::Revoked => codes::REVOKED,
            ErrorKind::ResumeInvalid => codes::RESUME_INVALID,
            ErrorKind::UpgradeRequired => codes::UPGRADE_REQUIRED,
        }
    }

    /// Safe to retry the operation.
    pub const fn retryable(self) -> bool {
        matches!(self, ErrorKind::Incomplete | ErrorKind::Timeout | ErrorKind::Io)
    }
}

impl ProtocolError {
    pub fn code(&self) -> u16 {
        self.kind.code()
    }
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

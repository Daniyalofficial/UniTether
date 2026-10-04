//! Resource limits (Phase 8): every network-controlled value bounded.
//! Mirrors `tests/protocol/limits.py` (conformance); the session layer
//! must enforce these — rejection, not clamping, is the policy.

/// Fixed protocol limits.
pub struct Limits;

impl Limits {
    pub const MAX_FRAME_BYTES: usize = 0x0010_0000; // 1 MiB (v1)
    pub const MAX_EXTENDED_FRAME_BYTES: usize = 0x0010_0000;
    pub const MAX_CONTROL_QUEUE: usize = 128;
    pub const MAX_PENDING_FRAMES: usize = 4096;
    pub const MAX_NAME_LEN: usize = 64;
    pub const MAX_PLATFORM_LEN: usize = 16;
    pub const MAX_ERROR_MSG_LEN: usize = 120;
    pub const MAX_RECONNECT_ATTEMPTS: u32 = 20;
    pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB
    pub const MAX_CONCURRENT_FILES: usize = 16;
    pub const MAX_FILE_CHUNK: usize = 256 * 1024;
    pub const MAX_PROXY_CONNECTIONS: usize = 64;
    pub const MAX_SESSION_BUFFER_BYTES: usize = 8 * 1024 * 1024;
    pub const MAX_HANDSHAKE_TIMEOUT_S: u64 = 15;
    pub const MAX_TRANSPORT_RESELECTS: u32 = 5;

    /// Reserved frame flags: never set by a conformant sender
    /// (compression/fragmentation unimplemented; docs/18 T9).
    pub const RESERVED_FLAGS: u8 = 0x05; // F_COMPRESSED | F_FRAG
}

/// Validate an inbound frame length (post-header parse).
pub fn validate_frame_len(len: usize) -> Result<(), crate::error::ProtocolError> {
    if len > Limits::MAX_FRAME_BYTES {
        return Err(crate::error::ProtocolError::new(
            crate::error::ErrorKind::Limit,
            format!("frame too large: {len} > {}", Limits::MAX_FRAME_BYTES),
        ));
    }
    Ok(())
}

/// Validate inbound frame flags: reserved flags are rejected.
pub fn validate_flags(flags: u8) -> Result<(), crate::error::ProtocolError> {
    if flags & Limits::RESERVED_FLAGS != 0 {
        return Err(crate::error::ProtocolError::new(
            crate::error::ErrorKind::Limit,
            format!("reserved frame flag {flags:#04x}"),
        ));
    }
    Ok(())
}

/// Validate a declared file size.
pub fn validate_file_size(total: u64) -> Result<(), crate::error::ProtocolError> {
    if total > Limits::MAX_FILE_SIZE {
        return Err(crate::error::ProtocolError::new(
            crate::error::ErrorKind::Limit,
            format!("file too large: {total}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;

    #[test]
    fn frame_len_bounds() {
        assert!(validate_frame_len(0).is_ok());
        assert!(validate_frame_len(Limits::MAX_FRAME_BYTES).is_ok());
        let e = validate_frame_len(Limits::MAX_FRAME_BYTES + 1).unwrap_err();
        assert_eq!(e.kind.code(), codes::LIMIT);
        assert!(!e.kind.retryable());
    }

    #[test]
    fn reserved_flags_rejected() {
        assert!(validate_flags(0).is_ok());
        assert!(validate_flags(0b10101000).is_ok()); // PRIORITY|0x20|0x80: no reserved bits
        for bad in [0x01, 0x04, 0x05] {
            let e = validate_flags(bad).unwrap_err();
            assert_eq!(e.kind.code(), codes::LIMIT);
        }
    }

    #[test]
    fn file_size_bound() {
        assert!(validate_file_size(Limits::MAX_FILE_SIZE).is_ok());
        let e = validate_file_size(Limits::MAX_FILE_SIZE + 1).unwrap_err();
        assert_eq!(e.kind.code(), codes::LIMIT);
    }

    #[test]
    fn error_code_map() {
        assert_eq!(crate::error::ErrorKind::Auth.code(), codes::AUTH);
        assert_eq!(crate::error::ErrorKind::BadVersion.code(), codes::VERSION);
        assert_eq!(crate::error::ErrorKind::CipherNegotiation.code(), codes::CIPHER);
        assert_eq!(crate::error::ErrorKind::Timeout.code(), codes::TIMEOUT);
        assert!(crate::error::ErrorKind::Timeout.retryable());
        assert!(!crate::error::ErrorKind::Auth.retryable());
        assert_eq!(crate::error::ErrorKind::Throttled.code(), codes::THROTTLED);
        assert_eq!(crate::error::ErrorKind::Revoked.code(), codes::REVOKED);
        assert_eq!(crate::error::ErrorKind::ResumeInvalid.code(), codes::RESUME_INVALID);
        assert_eq!(crate::error::ErrorKind::UpgradeRequired.code(), codes::UPGRADE_REQUIRED);
        assert_eq!(crate::error::ErrorKind::IdentityRequired.code(), codes::IDENTITY_REQUIRED);
    }
}

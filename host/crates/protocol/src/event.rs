//! Structured events (Phase 32) — JSON-line envelope, dependency-free.
//!
//! Privacy rule (docs/23): no content, ever. `validate` mechanically
//! enforces the envelope shape + string cap; denied field names are
//! rejected. Emitters in the transport/CLI layer call `emit_json`.

use std::collections::HashMap;

pub const SCHEMA_V: u8 = 1;

const SEVERITIES: [&str; 5] = ["debug", "info", "warn", "error", "fatal"];
const MAX_STRING_LEN: usize = 128;
const MAX_CTX_ENTRIES: usize = 24;

const DENYLIST: [&str; 16] = [
    "sms", "sms_body", "sms_text", "clipboard", "clipboard_text",
    "file_data", "file_name", "screen", "screen_frame", "frame_data",
    "camera", "camera_frame", "audio", "audio_bytes", "secret", "token",
];

#[derive(Debug)]
pub struct EventSchemaError(pub String);

impl std::fmt::Display for EventSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "event schema: {}", self.0)
    }
}
impl std::error::Error for EventSchemaError {}

/// Validate an event map before emission.
pub fn validate(evt: &HashMap<String, String>) -> Result<(), EventSchemaError> {
    for req in ["v", "ts", "sev", "ev"] {
        if !evt.contains_key(req) {
            return Err(EventSchemaError(format!("missing field {req}")));
        }
    }
    if evt.get("v").map(|s| s.as_str()) != Some("1") {
        return Err(EventSchemaError("unsupported schema version".into()));
    }
    let sev = evt.get("sev").map(|s| s.as_str()).unwrap_or("");
    if !SEVERITIES.contains(&sev) {
        return Err(EventSchemaError(format!("bad severity {sev:?}")));
    }
    if evt["ts"].parse::<f64>().is_err() {
        return Err(EventSchemaError("ts must be numeric".into()));
    }
    if evt["ev"].len() > 64 {
        return Err(EventSchemaError("ev too long".into()));
    }
    for (k, v) in evt {
        if DENYLIST.contains(&k.as_str()) {
            return Err(EventSchemaError(format!("denied field {k:?}")));
        }
        if v.len() > MAX_STRING_LEN {
            return Err(EventSchemaError(format!(
                "string {k:?} exceeds {MAX_STRING_LEN} chars (content leakage?)"
            )));
        }
        if k == "ctx" && v.split(',').count() > MAX_CTX_ENTRIES {
            return Err(EventSchemaError("ctx too large".into()));
        }
    }
    Ok(())
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Serialize an event to a single JSON line (stable key order).
pub fn emit_json(
    evt: &HashMap<String, String>,
) -> Result<String, EventSchemaError> {
    validate(evt)?;
    let mut parts: Vec<String> = Vec::with_capacity(evt.len());
    for (k, v) in evt {
        parts.push(format!("\"{}\":\"{}\"", esc(k), esc(v)));
    }
    parts.sort(); // deterministic order
    Ok(format!("{{{}}}", parts.join(",")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("v".into(), "1".into());
        m.insert("ts".into(), "1714000000.1".into());
        m.insert("sev".into(), "info".into());
        m.insert("ev".into(), "session.state".into());
        m
    }

    #[test]
    fn valid_event_serializes() {
        let mut m = base();
        m.insert("state".into(), "CONNECTED".into());
        let line = emit_json(&m).unwrap();
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert!(line.contains("\"ev\":\"session.state\""));
        assert!(line.contains("\"state\":\"CONNECTED\""));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn denied_fields_rejected() {
        for f in DENYLIST {
            let mut m = base();
            m.insert(f.into(), "x".into());
            assert!(emit_json(&m).is_err(), "{f} accepted");
        }
    }

    #[test]
    fn shape_rules() {
        let mut m = base();
        m.remove("sev");
        assert!(emit_json(&m).is_err(), "missing sev");
        m = base();
        m.insert("sev".into(), "loud".into());
        assert!(emit_json(&m).is_err(), "bad severity");
        m = base();
        m.insert("v".into(), "2".into());
        assert!(emit_json(&m).is_err(), "bad version");
        m = base();
        m.insert("note".into(), "y".repeat(MAX_STRING_LEN + 1));
        assert!(emit_json(&m).is_err(), "string cap");
    }

    #[test]
    fn escaping() {
        let mut m = base();
        m.insert("msg".into(), "a\"b\\c\n".into());
        let line = emit_json(&m).unwrap();
        assert!(line.contains(r#"a\"b\\c\n"#));
    }
}

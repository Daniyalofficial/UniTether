//! ULP v1 channel payload codecs (docs/02-PROTOCOL.md section 5).

use crate::error::{ProtocolError, Result};

fn need(body: &[u8], n: usize, what: &str) -> Result<()> {
    if body.len() < n {
        return Err(ProtocolError::new(
            crate::error::ErrorKind::BadPayload,
            format!("{what}: short body")));
    }
    Ok(())
}

// ------------------------------------------------------------ VIDEO
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub kind: u8,        // 0 key, 1 delta, 2 eoi
    pub codec: u8,       // 0 h264, 1 hevc, 2 av1, 3 mjpeg (camera)
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub pts_ms: u32,
    pub seq: u32,
    pub nal: Vec<u8>,
}

pub const VIDEO_KIND_KEY: u8 = 0;
pub const VIDEO_KIND_DELTA: u8 = 1;
pub const VIDEO_KIND_EOI: u8 = 2;
pub const VIDEO_H264: u8 = 0;
pub const VIDEO_HEVC: u8 = 1;
pub const VIDEO_AV1: u8 = 2;
pub const VIDEO_MJPEG: u8 = 3;

impl VideoFrame {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(15 + self.nal.len());
        b.push(self.kind);
        b.push(self.codec);
        b.extend_from_slice(&self.width.to_be_bytes());
        b.extend_from_slice(&self.height.to_be_bytes());
        b.push(self.fps);
        b.extend_from_slice(&self.pts_ms.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.nal);
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        need(body, 15, "video")?;
        Ok(Self {
            kind: body[0],
            codec: body[1],
            width: u16::from_be_bytes([body[2], body[3]]),
            height: u16::from_be_bytes([body[4], body[5]]),
            fps: body[6],
            pts_ms: u32::from_be_bytes(body[7..11].try_into().unwrap()),
            seq: u32::from_be_bytes(body[11..15].try_into().unwrap()),
            nal: body[15..].to_vec(),
        })
    }
}

// ------------------------------------------------------------ AUDIO
#[derive(Debug, Clone)]
pub struct AudioFrame {
    pub codec: u8,   // 0 opus, 1 aac, 2 pcm16le
    pub rate: u16,
    pub ch: u8,
    pub seq: u32,
    pub pts_ms: u32,
    pub data: Vec<u8>,
}

pub const AUDIO_OPUS: u8 = 0;
pub const AUDIO_AAC: u8 = 1;
pub const AUDIO_PCM16: u8 = 2;

impl AudioFrame {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(12 + self.data.len());
        b.push(self.codec);
        b.extend_from_slice(&self.rate.to_be_bytes());
        b.push(self.ch);
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.pts_ms.to_be_bytes());
        b.extend_from_slice(&self.data);
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        need(body, 12, "audio")?;
        Ok(Self {
            codec: body[0],
            rate: u16::from_be_bytes([body[1], body[2]]),
            ch: body[3],
            seq: u32::from_be_bytes(body[4..8].try_into().unwrap()),
            pts_ms: u32::from_be_bytes(body[8..12].try_into().unwrap()),
            data: body[12..].to_vec(),
        })
    }
}

// ------------------------------------------------------------ INPUT
#[derive(Debug, Clone)]
pub struct InputEvent {
    pub ty: u8,      // 0 touch, 1 key, 2 mouse, 3 text
    pub action: u8,  // 0 down, 1 up, 2 move
    pub x: u16,      // normalized 0..=1000
    pub y: u16,
    pub key: u16,
    pub text: String,
}

pub const INPUT_TOUCH: u8 = 0;
pub const INPUT_KEY: u8 = 1;
pub const INPUT_MOUSE: u8 = 2;
pub const INPUT_TEXT: u8 = 3;

impl InputEvent {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(10 + self.text.len());
        b.push(self.ty);
        b.push(self.action);
        b.extend_from_slice(&self.x.to_be_bytes());
        b.extend_from_slice(&self.y.to_be_bytes());
        b.extend_from_slice(&self.key.to_be_bytes());
        b.extend_from_slice(&(self.text.len() as u16).to_be_bytes());
        b.extend_from_slice(self.text.as_bytes());
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        need(body, 10, "input")?;
        let tl = u16::from_be_bytes([body[8], body[9]]) as usize;
        need(body, 10 + tl, "input text")?;
        Ok(Self {
            ty: body[0],
            action: body[1],
            x: u16::from_be_bytes([body[2], body[3]]),
            y: u16::from_be_bytes([body[4], body[5]]),
            key: u16::from_be_bytes([body[6], body[7]]),
            text: String::from_utf8_lossy(&body[10..10 + tl]).into_owned(),
        })
    }
}

// ------------------------------------------------------------ FILE
#[derive(Debug, Clone)]
pub enum FileOp {
    Meta { direction: u8, file_id: u32, total_size: u64, name: String },
    Data { direction: u8, file_id: u32, seq: u32, offset: u64, chunk: Vec<u8> },
    Ack { direction: u8, file_id: u32, seq_ack: u32 },
    Cancel { direction: u8, file_id: u32 },
    Done { direction: u8, file_id: u32 },
}

impl FileOp {
    pub fn body(&self) -> Vec<u8> {
        let (op, direction, file_id) = match self {
            FileOp::Meta { direction, file_id, .. } => (0x00, direction, file_id),
            FileOp::Data { direction, file_id, .. } => (0x01, direction, file_id),
            FileOp::Ack { direction, file_id, .. } => (0x02, direction, file_id),
            FileOp::Cancel { direction, file_id } => (0x03, direction, file_id),
            FileOp::Done { direction, file_id } => (0x04, direction, file_id),
        };
        let mut b = vec![op, *direction];
        b.extend_from_slice(&file_id.to_be_bytes());
        match self {
            FileOp::Meta { total_size, name, .. } => {
                b.extend_from_slice(&total_size.to_be_bytes());
                b.extend_from_slice(&(name.len() as u16).to_be_bytes());
                b.extend_from_slice(name.as_bytes());
            }
            FileOp::Data { seq, offset, chunk, .. } => {
                b.extend_from_slice(&seq.to_be_bytes());
                b.extend_from_slice(&offset.to_be_bytes());
                b.extend_from_slice(chunk);
            }
            FileOp::Ack { seq_ack, .. } => b.extend_from_slice(&seq_ack.to_be_bytes()),
            _ => {}
        }
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        need(body, 6, "file")?;
        let (op, direction) = (body[0], body[1]);
        let file_id = u32::from_be_bytes(body[2..6].try_into().unwrap());
        match op {
            0x00 => {
                need(body, 16, "file meta")?;
                let total = u64::from_be_bytes(body[6..14].try_into().unwrap());
                let nl = u16::from_be_bytes([body[14], body[15]]) as usize;
                need(body, 16 + nl, "file meta name")?;
                Ok(FileOp::Meta {
                    direction, file_id, total_size: total,
                    name: String::from_utf8_lossy(&body[16..16 + nl]).into_owned(),
                })
            }
            0x01 => {
                need(body, 18, "file data")?;
                Ok(FileOp::Data {
                    direction, file_id,
                    seq: u32::from_be_bytes(body[6..10].try_into().unwrap()),
                    offset: u64::from_be_bytes(body[10..18].try_into().unwrap()),
                    chunk: body[18..].to_vec(),
                })
            }
            0x02 => {
                need(body, 10, "file ack")?;
                Ok(FileOp::Ack {
                    direction, file_id,
                    seq_ack: u32::from_be_bytes(body[6..10].try_into().unwrap()),
                })
            }
            0x03 => Ok(FileOp::Cancel { direction, file_id }),
            0x04 => Ok(FileOp::Done { direction, file_id }),
            other => Err(ProtocolError::new(
                crate::error::ErrorKind::BadPayload,
                format!("file: unknown op {other:#x}"))),
        }
    }
}

// ------------------------------------------------------------ CLIPBOARD
#[derive(Debug, Clone)]
pub struct ClipboardUpdate {
    pub direction: u8, // 0 device->host, 1 host->device
    pub kind: u8,      // 0 text, 1 html, 2 image
    pub data: Vec<u8>,
}

impl ClipboardUpdate {
    pub fn body(&self) -> Vec<u8> {
        let mut b = vec![self.direction, self.kind];
        b.extend_from_slice(&self.data);
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        need(body, 2, "clipboard")?;
        Ok(Self {
            direction: body[0],
            kind: body[1],
            data: body[2..].to_vec(),
        })
    }
}

// ------------------------------------------------------------ NOTIFICATION
#[derive(Debug, Clone)]
pub struct Notification {
    pub id: u32,
    pub ts_ms: u64,
    pub action: u8, // 0 post, 1 clear
    pub app: String,
    pub title: String,
    pub body: String,
}

impl Notification {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.id.to_be_bytes());
        b.extend_from_slice(&self.ts_ms.to_be_bytes());
        b.push(self.action);
        for s in [&self.app, &self.title, &self.body] {
            b.extend_from_slice(&(s.len() as u16).to_be_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        b
    }

    pub fn parse(body: &[u8]) -> Result<Self> {
        need(body, 13, "notification")?;
        let mut off = 13;
        let mut fields = std::array::from_fn(|_| String::new());
        for f in fields.iter_mut() {
            need(body, off + 2, "notification str")?;
            let l = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
            off += 2;
            need(body, off + l, "notification str data")?;
            *f = String::from_utf8_lossy(&body[off..off + l]).into_owned();
            off += l;
        }
        Ok(Self {
            id: u32::from_be_bytes(body[0..4].try_into().unwrap()),
            ts_ms: u64::from_be_bytes(body[4..12].try_into().unwrap()),
            action: body[12],
            app: fields[0].clone(),
            title: fields[1].clone(),
            body: fields[2].clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_roundtrip() {
        let v = VideoFrame {
            kind: 0, codec: 0, width: 1920, height: 1080, fps: 60,
            pts_ms: 33, seq: 7, nal: vec![0; 100],
        };
        let p = VideoFrame::parse(&v.body()).unwrap();
        assert_eq!(p.width, 1920);
        assert_eq!(p.seq, 7);
        assert_eq!(p.nal.len(), 100);
    }

    #[test]
    fn audio_roundtrip() {
        let a = AudioFrame { codec: 0, rate: 48000, ch: 1, seq: 5, pts_ms: 100, data: vec![9u8; 50] };
        let p = AudioFrame::parse(&a.body()).unwrap();
        assert_eq!(p.rate, 48000);
        assert_eq!(p.data.len(), 50);
    }

    #[test]
    fn input_text_roundtrip() {
        let i = InputEvent { ty: 3, action: 0, x: 0, y: 0, key: 0, text: "héllo".into() };
        let p = InputEvent::parse(&i.body()).unwrap();
        assert_eq!(p.text, "héllo");
    }

    #[test]
    fn file_roundtrip() {
        let f = FileOp::Meta { direction: 0, file_id: 42, total_size: 999, name: "a.txt".into() };
        let p = FileOp::parse(&f.body()).unwrap();
        match p {
            FileOp::Meta { file_id, total_size, name, .. } => {
                assert_eq!(file_id, 42);
                assert_eq!(total_size, 999);
                assert_eq!(name, "a.txt");
            }
            _ => panic!(),
        }
        let d = FileOp::Data { direction: 0, file_id: 1, seq: 2, offset: 3, chunk: vec![4, 5] };
        match FileOp::parse(&d.body()).unwrap() {
            FileOp::Data { offset, chunk, .. } => {
                assert_eq!(offset, 3);
                assert_eq!(chunk, vec![4, 5]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn notification_roundtrip() {
        let n = Notification { id: 7, ts_ms: 123, action: 0, app: "com.x".into(), title: "T".into(), body: "B".into() };
        let p = Notification::parse(&n.body()).unwrap();
        assert_eq!(p.app, "com.x");
        assert_eq!(p.title, "T");
        assert_eq!(p.body, "B");
    }
}

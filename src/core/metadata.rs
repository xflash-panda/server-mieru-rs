use std::time::{SystemTime, UNIX_EPOCH};

pub const METADATA_LEN: usize = 32;

/// Protocol type byte values used in mieru metadata headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolType {
    CloseConnRequest = 0,
    CloseConnResponse = 1,
    OpenSessionRequest = 2,
    OpenSessionResponse = 3,
    CloseSessionRequest = 4,
    CloseSessionResponse = 5,
    DataClientToServer = 6,
    DataServerToClient = 7,
    AckClientToServer = 8,
    AckServerToClient = 9,
}

impl ProtocolType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::CloseConnRequest),
            1 => Some(Self::CloseConnResponse),
            2 => Some(Self::OpenSessionRequest),
            3 => Some(Self::OpenSessionResponse),
            4 => Some(Self::CloseSessionRequest),
            5 => Some(Self::CloseSessionResponse),
            6 => Some(Self::DataClientToServer),
            7 => Some(Self::DataServerToClient),
            8 => Some(Self::AckClientToServer),
            9 => Some(Self::AckServerToClient),
            _ => None,
        }
    }

    /// Returns true for connection/session control types (0–5).
    pub fn is_session_type(self) -> bool {
        (self as u8) <= 5
    }

    /// Returns true for data and ack types (6–9).
    pub fn is_data_type(self) -> bool {
        (self as u8) >= 6
    }
}

/// Metadata for session control messages (protocol types 0–5).
///
/// Wire layout (32 bytes):
/// ```text
/// Byte  0     : protocol_type
/// Byte  1     : reserved (0)
/// Bytes 2–5   : timestamp (u32 big-endian, unix minutes)
/// Bytes 6–9   : session_id (u32 big-endian)
/// Bytes 10–13 : sequence (u32 big-endian)
/// Byte  14    : status_code (0=OK, 1=QuotaExhausted)
/// Bytes 15–16 : payload_length (u16 big-endian, max 1024)
/// Byte  17    : suffix_padding_length (u8)
/// Bytes 18–31 : reserved (zeros)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    pub protocol_type: ProtocolType,
    pub timestamp: u32,
    pub session_id: u32,
    pub sequence: u32,
    pub status_code: u8,
    pub payload_length: u16,
    pub suffix_padding_length: u8,
}

impl SessionMetadata {
    pub fn encode(&self) -> [u8; METADATA_LEN] {
        let mut buf = [0u8; METADATA_LEN];
        buf[0] = self.protocol_type as u8;
        // byte 1: reserved, already 0
        buf[2..6].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        buf[10..14].copy_from_slice(&self.sequence.to_be_bytes());
        buf[14] = self.status_code;
        buf[15..17].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[17] = self.suffix_padding_length;
        // bytes 18–31: reserved, already 0
        buf
    }

    pub fn decode(buf: &[u8; METADATA_LEN]) -> Option<Self> {
        let pt = ProtocolType::from_u8(buf[0])?;
        if !pt.is_session_type() {
            return None;
        }
        let timestamp = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let session_id = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let sequence = u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]);
        let status_code = buf[14];
        let payload_length = u16::from_be_bytes([buf[15], buf[16]]);
        let suffix_padding_length = buf[17];
        Some(Self {
            protocol_type: pt,
            timestamp,
            session_id,
            sequence,
            status_code,
            payload_length,
            suffix_padding_length,
        })
    }
}

/// Metadata for data and ack messages (protocol types 6–9).
///
/// Wire layout (32 bytes):
/// ```text
/// Byte  0     : protocol_type
/// Byte  1     : reserved (0)
/// Bytes 2–5   : timestamp (u32 big-endian)
/// Bytes 6–9   : session_id (u32 big-endian)
/// Bytes 10–13 : sequence (u32 big-endian)
/// Bytes 14–17 : unack_seq (u32 big-endian)
/// Bytes 18–19 : window_size (u16 big-endian)
/// Byte  20    : fragment_number (u8)
/// Byte  21    : prefix_padding_length (u8)
/// Bytes 22–23 : payload_length (u16 big-endian)
/// Byte  24    : suffix_padding_length (u8)
/// Bytes 25–31 : reserved (zeros)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMetadata {
    pub protocol_type: ProtocolType,
    pub timestamp: u32,
    pub session_id: u32,
    pub sequence: u32,
    pub unack_seq: u32,
    pub window_size: u16,
    pub fragment_number: u8,
    pub prefix_padding_length: u8,
    pub payload_length: u16,
    pub suffix_padding_length: u8,
}

impl DataMetadata {
    pub fn encode(&self) -> [u8; METADATA_LEN] {
        let mut buf = [0u8; METADATA_LEN];
        buf[0] = self.protocol_type as u8;
        // byte 1: reserved, already 0
        buf[2..6].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        buf[10..14].copy_from_slice(&self.sequence.to_be_bytes());
        buf[14..18].copy_from_slice(&self.unack_seq.to_be_bytes());
        buf[18..20].copy_from_slice(&self.window_size.to_be_bytes());
        buf[20] = self.fragment_number;
        buf[21] = self.prefix_padding_length;
        buf[22..24].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[24] = self.suffix_padding_length;
        // bytes 25–31: reserved, already 0
        buf
    }

    pub fn decode(buf: &[u8; METADATA_LEN]) -> Option<Self> {
        let pt = ProtocolType::from_u8(buf[0])?;
        if !pt.is_data_type() {
            return None;
        }
        let timestamp = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let session_id = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let sequence = u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]);
        let unack_seq = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let window_size = u16::from_be_bytes([buf[18], buf[19]]);
        let fragment_number = buf[20];
        let prefix_padding_length = buf[21];
        let payload_length = u16::from_be_bytes([buf[22], buf[23]]);
        let suffix_padding_length = buf[24];
        Some(Self {
            protocol_type: pt,
            timestamp,
            session_id,
            sequence,
            unack_seq,
            window_size,
            fragment_number,
            prefix_padding_length,
            payload_length,
            suffix_padding_length,
        })
    }
}

/// Unified metadata enum covering both session and data variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Metadata {
    Session(SessionMetadata),
    Data(DataMetadata),
}

impl Metadata {
    /// Decode a 32-byte buffer into the appropriate metadata variant.
    pub fn decode(buf: &[u8; METADATA_LEN]) -> Option<Self> {
        let pt = ProtocolType::from_u8(buf[0])?;
        if pt.is_session_type() {
            SessionMetadata::decode(buf).map(Metadata::Session)
        } else {
            DataMetadata::decode(buf).map(Metadata::Data)
        }
    }

    /// Encode the metadata into a 32-byte buffer.
    pub fn encode(&self) -> [u8; METADATA_LEN] {
        match self {
            Metadata::Session(s) => s.encode(),
            Metadata::Data(d) => d.encode(),
        }
    }

    /// Return the session ID from either variant.
    pub fn session_id(&self) -> u32 {
        match self {
            Metadata::Session(s) => s.session_id,
            Metadata::Data(d) => d.session_id,
        }
    }

    /// Return the protocol type from either variant.
    pub fn protocol_type(&self) -> ProtocolType {
        match self {
            Metadata::Session(s) => s.protocol_type,
            Metadata::Data(d) => d.protocol_type,
        }
    }
}

/// Returns the current unix time expressed in whole minutes.
pub fn current_timestamp_minutes() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (secs / 60) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProtocolType ────────────────────────────────────────────────────────

    #[test]
    fn test_protocol_type_from_u8_all_valid() {
        for v in 0u8..=9 {
            let pt = ProtocolType::from_u8(v).unwrap_or_else(|| panic!("expected Some for {v}"));
            assert_eq!(pt as u8, v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn test_protocol_type_from_u8_invalid() {
        assert!(ProtocolType::from_u8(10).is_none());
        assert!(ProtocolType::from_u8(255).is_none());
    }

    #[test]
    fn test_protocol_type_is_session_type() {
        for v in 0u8..=5 {
            let pt = ProtocolType::from_u8(v).unwrap();
            assert!(pt.is_session_type(), "{v} should be session type");
        }
        for v in 6u8..=9 {
            let pt = ProtocolType::from_u8(v).unwrap();
            assert!(!pt.is_session_type(), "{v} should NOT be session type");
        }
    }

    #[test]
    fn test_protocol_type_is_data_type() {
        for v in 6u8..=9 {
            let pt = ProtocolType::from_u8(v).unwrap();
            assert!(pt.is_data_type(), "{v} should be data type");
        }
        for v in 0u8..=5 {
            let pt = ProtocolType::from_u8(v).unwrap();
            assert!(!pt.is_data_type(), "{v} should NOT be data type");
        }
    }

    // ── SessionMetadata ─────────────────────────────────────────────────────

    fn sample_session() -> SessionMetadata {
        SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: 28_000_000,
            session_id: 0xDEAD_BEEF,
            sequence: 42,
            status_code: 0,
            payload_length: 512,
            suffix_padding_length: 7,
        }
    }

    #[test]
    fn test_session_metadata_encode_decode_roundtrip() {
        let original = sample_session();
        let buf = original.encode();
        let decoded = SessionMetadata::decode(&buf).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_session_metadata_all_fields() {
        let m = SessionMetadata {
            protocol_type: ProtocolType::CloseSessionResponse,
            timestamp: 12_345_678,
            session_id: 0xCAFE_BABE,
            sequence: 0xFFFF_FFFE,
            status_code: 1,
            payload_length: 1024,
            suffix_padding_length: 255,
        };
        let buf = m.encode();
        let d = SessionMetadata::decode(&buf).expect("decode failed");
        assert_eq!(d.protocol_type, ProtocolType::CloseSessionResponse);
        assert_eq!(d.timestamp, 12_345_678);
        assert_eq!(d.session_id, 0xCAFE_BABE);
        assert_eq!(d.sequence, 0xFFFF_FFFE);
        assert_eq!(d.status_code, 1);
        assert_eq!(d.payload_length, 1024);
        assert_eq!(d.suffix_padding_length, 255);
    }

    #[test]
    fn test_session_metadata_decode_rejects_data_type() {
        let mut buf = sample_session().encode();
        buf[0] = ProtocolType::DataClientToServer as u8;
        assert!(SessionMetadata::decode(&buf).is_none());
    }

    #[test]
    fn test_session_metadata_reserved_bytes_zero() {
        let buf = sample_session().encode();
        for i in 18..32 {
            assert_eq!(buf[i], 0, "byte {i} should be zero (reserved)");
        }
    }

    #[test]
    fn test_session_metadata_big_endian() {
        let m = SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: 0x0102_0304,
            session_id: 0x0506_0708,
            sequence: 0x090A_0B0C,
            status_code: 0,
            payload_length: 0x0D0E,
            suffix_padding_length: 0x0F,
        };
        let buf = m.encode();
        // byte 0: protocol type
        assert_eq!(buf[0], 2);
        // byte 1: reserved
        assert_eq!(buf[1], 0);
        // timestamp big-endian
        assert_eq!(&buf[2..6], &[0x01, 0x02, 0x03, 0x04]);
        // session_id big-endian
        assert_eq!(&buf[6..10], &[0x05, 0x06, 0x07, 0x08]);
        // sequence big-endian
        assert_eq!(&buf[10..14], &[0x09, 0x0A, 0x0B, 0x0C]);
        // status_code
        assert_eq!(buf[14], 0);
        // payload_length big-endian
        assert_eq!(&buf[15..17], &[0x0D, 0x0E]);
        // suffix_padding_length
        assert_eq!(buf[17], 0x0F);
    }

    // ── DataMetadata ─────────────────────────────────────────────────────────

    fn sample_data() -> DataMetadata {
        DataMetadata {
            protocol_type: ProtocolType::DataClientToServer,
            timestamp: 28_000_000,
            session_id: 0xDEAD_BEEF,
            sequence: 100,
            unack_seq: 99,
            window_size: 256,
            fragment_number: 3,
            prefix_padding_length: 16,
            payload_length: 1400,
            suffix_padding_length: 8,
        }
    }

    #[test]
    fn test_data_metadata_encode_decode_roundtrip() {
        let original = sample_data();
        let buf = original.encode();
        let decoded = DataMetadata::decode(&buf).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_data_metadata_all_fields() {
        let m = DataMetadata {
            protocol_type: ProtocolType::AckServerToClient,
            timestamp: 99_999_999,
            session_id: 0xAAAA_BBBB,
            sequence: 0x1234_5678,
            unack_seq: 0x8765_4321,
            window_size: 0xBEEF,
            fragment_number: 0,
            prefix_padding_length: 32,
            payload_length: 65535,
            suffix_padding_length: 128,
        };
        let buf = m.encode();
        let d = DataMetadata::decode(&buf).expect("decode failed");
        assert_eq!(d.protocol_type, ProtocolType::AckServerToClient);
        assert_eq!(d.timestamp, 99_999_999);
        assert_eq!(d.session_id, 0xAAAA_BBBB);
        assert_eq!(d.sequence, 0x1234_5678);
        assert_eq!(d.unack_seq, 0x8765_4321);
        assert_eq!(d.window_size, 0xBEEF);
        assert_eq!(d.fragment_number, 0);
        assert_eq!(d.prefix_padding_length, 32);
        assert_eq!(d.payload_length, 65535);
        assert_eq!(d.suffix_padding_length, 128);
    }

    #[test]
    fn test_data_metadata_decode_rejects_session_type() {
        let mut buf = sample_data().encode();
        buf[0] = ProtocolType::OpenSessionRequest as u8;
        assert!(DataMetadata::decode(&buf).is_none());
    }

    #[test]
    fn test_data_metadata_reserved_bytes_zero() {
        let buf = sample_data().encode();
        for i in 25..32 {
            assert_eq!(buf[i], 0, "byte {i} should be zero (reserved)");
        }
    }

    #[test]
    fn test_data_metadata_big_endian() {
        let m = DataMetadata {
            protocol_type: ProtocolType::DataServerToClient,
            timestamp: 0x0102_0304,
            session_id: 0x0506_0708,
            sequence: 0x090A_0B0C,
            unack_seq: 0x0D0E_0F10,
            window_size: 0x1112,
            fragment_number: 0x13,
            prefix_padding_length: 0x14,
            payload_length: 0x1516,
            suffix_padding_length: 0x17,
        };
        let buf = m.encode();
        // byte 0: protocol type (DataServerToClient = 7)
        assert_eq!(buf[0], 7);
        // byte 1: reserved
        assert_eq!(buf[1], 0);
        // timestamp big-endian
        assert_eq!(&buf[2..6], &[0x01, 0x02, 0x03, 0x04]);
        // session_id big-endian
        assert_eq!(&buf[6..10], &[0x05, 0x06, 0x07, 0x08]);
        // sequence big-endian
        assert_eq!(&buf[10..14], &[0x09, 0x0A, 0x0B, 0x0C]);
        // unack_seq big-endian
        assert_eq!(&buf[14..18], &[0x0D, 0x0E, 0x0F, 0x10]);
        // window_size big-endian
        assert_eq!(&buf[18..20], &[0x11, 0x12]);
        // fragment_number
        assert_eq!(buf[20], 0x13);
        // prefix_padding_length
        assert_eq!(buf[21], 0x14);
        // payload_length big-endian
        assert_eq!(&buf[22..24], &[0x15, 0x16]);
        // suffix_padding_length
        assert_eq!(buf[24], 0x17);
    }

    // ── Metadata enum ────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_decode_dispatches_session() {
        let buf = sample_session().encode();
        match Metadata::decode(&buf).expect("decode failed") {
            Metadata::Session(_) => {}
            Metadata::Data(_) => panic!("expected Session variant"),
        }
    }

    #[test]
    fn test_metadata_decode_dispatches_data() {
        let buf = sample_data().encode();
        match Metadata::decode(&buf).expect("decode failed") {
            Metadata::Data(_) => {}
            Metadata::Session(_) => panic!("expected Data variant"),
        }
    }

    #[test]
    fn test_metadata_session_id_accessor() {
        let s = sample_session();
        let expected_id = s.session_id;
        let buf = s.encode();
        let m = Metadata::decode(&buf).unwrap();
        assert_eq!(m.session_id(), expected_id);

        let d = sample_data();
        let expected_id = d.session_id;
        let buf = d.encode();
        let m = Metadata::decode(&buf).unwrap();
        assert_eq!(m.session_id(), expected_id);
    }

    #[test]
    fn test_metadata_protocol_type_accessor() {
        let buf = sample_session().encode();
        let m = Metadata::decode(&buf).unwrap();
        assert_eq!(m.protocol_type(), ProtocolType::OpenSessionRequest);

        let buf = sample_data().encode();
        let m = Metadata::decode(&buf).unwrap();
        assert_eq!(m.protocol_type(), ProtocolType::DataClientToServer);
    }

    // ── Timestamp ────────────────────────────────────────────────────────────

    #[test]
    fn test_current_timestamp_minutes_reasonable() {
        let ts = current_timestamp_minutes();
        assert!(ts > 0, "timestamp should be > 0");
        // Approximate: 2024-01-01 00:00 UTC is ~28_200_480 minutes since epoch.
        // We expect something in a reasonable ballpark (> 28 million minutes).
        assert!(ts > 28_000_000, "timestamp {ts} seems too small");
        // Should be less than ~35 million (well past 2100).
        assert!(ts < 35_000_000, "timestamp {ts} seems too large");
    }
}

//! Padding generation for traffic obfuscation.
//!
//! Matches Go mieru's ASCII padding strategy: random-length padding bytes
//! filled with printable ASCII characters (0x21..=0x7E).

use rand::Rng;

use super::segment::{MAX_PDU, STREAM_OVERHEAD};

/// Maximum padding size given the MTU, current payload size, and existing
/// padding already committed.
///
/// Mirrors Go's `MaxPaddingSize(mtu, transport, payloadLen, existingPadding)`.
pub fn max_padding_size(payload_len: usize, existing_padding: usize) -> usize {
    // Max total wire size per segment (excluding nonce which is only first segment).
    let max_wire = MAX_PDU;
    let overhead = STREAM_OVERHEAD + payload_len + existing_padding;
    if overhead >= max_wire {
        return 0;
    }
    // Padding length is u8, so cap at 255.
    (max_wire - overhead).min(255)
}

/// Generate random ASCII padding of a random length up to `max_len`.
///
/// Returns an empty vec if `max_len` is 0.
pub fn generate_padding(max_len: usize) -> Vec<u8> {
    if max_len == 0 {
        return vec![];
    }
    let mut rng = rand::rng();
    let len = rng.random_range(1..=max_len);
    let mut buf = vec![0u8; len];
    for b in &mut buf {
        // Printable ASCII: 0x21 ('!') to 0x7E ('~'), 94 characters.
        *b = rng.random_range(0x21u8..=0x7E);
    }
    buf
}

/// Compute padding for a session control segment (types 0-5).
/// Returns suffix padding only (session metadata has no prefix padding field).
pub fn session_padding(payload_len: usize) -> Vec<u8> {
    let max = max_padding_size(payload_len, 0);
    generate_padding(max)
}

/// Compute padding for a data segment (types 6-9).
/// Returns (prefix_padding, suffix_padding).
pub fn data_padding(payload_len: usize) -> (Vec<u8>, Vec<u8>) {
    let prefix = generate_padding(max_padding_size(payload_len, 0));
    let suffix = generate_padding(max_padding_size(payload_len, prefix.len()));
    (prefix, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_padding_size_small_payload() {
        let max = max_padding_size(100, 0);
        assert!(max > 0, "small payload should allow padding");
        assert!(max <= 255, "padding capped at u8 max");
    }

    #[test]
    fn test_max_padding_size_full_payload() {
        // A payload that fills the entire PDU should leave no room.
        let max = max_padding_size(MAX_PDU, 0);
        assert_eq!(max, 0, "full PDU should leave no room for padding");
    }

    #[test]
    fn test_generate_padding_non_empty() {
        let pad = generate_padding(100);
        assert!(!pad.is_empty(), "padding should not be empty when max > 0");
        assert!(pad.len() <= 100);
    }

    #[test]
    fn test_generate_padding_ascii_range() {
        let pad = generate_padding(255);
        for &b in &pad {
            assert!(
                (0x21..=0x7E).contains(&b),
                "byte {b:#x} outside printable ASCII range"
            );
        }
    }

    #[test]
    fn test_generate_padding_zero_max() {
        let pad = generate_padding(0);
        assert!(pad.is_empty());
    }

    #[test]
    fn test_session_padding_returns_nonzero() {
        let pad = session_padding(0);
        assert!(!pad.is_empty(), "session padding should be non-empty");
    }

    #[test]
    fn test_data_padding_returns_nonzero() {
        let (prefix, suffix) = data_padding(100);
        assert!(
            !prefix.is_empty() || !suffix.is_empty(),
            "at least one data padding should be non-empty"
        );
    }
}

use super::crypto::{KEY_LEN, NONCE_SIZE, TAG_SIZE, decrypt, encrypt, increment_nonce};
use super::metadata::{METADATA_LEN, Metadata};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum TCP payload size (32 KB).
pub const MAX_PDU: usize = 32 * 1024;

/// Per-segment overhead for TCP stream segments (metadata block + two auth tags).
/// Layout (without nonce): [encrypted_meta(METADATA_LEN) + tag(TAG_SIZE)] + [encrypted_payload + tag(TAG_SIZE)]
pub const STREAM_OVERHEAD: usize = METADATA_LEN + TAG_SIZE * 2;

/// Per-segment overhead for UDP packet segments (nonce + metadata block + two auth tags).
pub const PACKET_OVERHEAD: usize = NONCE_SIZE + METADATA_LEN + TAG_SIZE * 2;

// ---------------------------------------------------------------------------
// Helper: extract padding lengths from decoded metadata
// ---------------------------------------------------------------------------

fn padding_lengths(meta: &Metadata) -> (usize, usize) {
    match meta {
        Metadata::Session(s) => (0, s.suffix_padding_length as usize),
        Metadata::Data(d) => (
            d.prefix_padding_length as usize,
            d.suffix_padding_length as usize,
        ),
    }
}

fn payload_length(meta: &Metadata) -> usize {
    match meta {
        Metadata::Session(s) => s.payload_length as usize,
        Metadata::Data(d) => d.payload_length as usize,
    }
}

// ---------------------------------------------------------------------------
// TCP Stream encode/decode
// ---------------------------------------------------------------------------

/// Encode one TCP stream segment.
///
/// Nonce handling mirrors Go's implicit-nonce stateful cipher:
/// - Encrypt metadata with `*nonce`; then increment `*nonce`.
/// - Encrypt payload  with `*nonce`; then increment `*nonce`.
///
/// Wire format (when `include_nonce == false`):
///   [encrypted_meta + tag(16)] [prefix_padding] [encrypted_payload + tag(16)] [suffix_padding]
///
/// Wire format (when `include_nonce == true`, i.e. first segment):
///   [original_nonce(24)] [encrypted_meta + tag(16)] [prefix_padding] [encrypted_payload + tag(16)] [suffix_padding]
///
/// `include_nonce`: prepend the nonce value that was current **before** any increments.
pub fn encode_stream_segment(
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
    metadata: &Metadata,
    payload: &[u8],
    prefix_padding: &[u8],
    suffix_padding: &[u8],
    include_nonce: bool,
) -> Vec<u8> {
    // Save the original nonce for optional prepending.
    let original_nonce = *nonce;

    // 1. Encrypt metadata with current nonce, then advance.
    let meta_plain = metadata.encode();
    let enc_meta = encrypt(key, nonce, &meta_plain);
    increment_nonce(nonce);

    // 2. Encrypt payload with new nonce, then advance.
    let enc_payload = encrypt(key, nonce, payload);
    increment_nonce(nonce);

    // 3. Assemble output.
    let mut out = Vec::with_capacity(
        if include_nonce { NONCE_SIZE } else { 0 }
            + enc_meta.len()
            + prefix_padding.len()
            + enc_payload.len()
            + suffix_padding.len(),
    );

    if include_nonce {
        out.extend_from_slice(&original_nonce);
    }
    out.extend_from_slice(&enc_meta);
    out.extend_from_slice(prefix_padding);
    out.extend_from_slice(&enc_payload);
    out.extend_from_slice(suffix_padding);
    out
}

/// Decode one TCP stream segment (without leading nonce).
///
/// Nonce handling:
/// - Decrypt metadata with `*nonce`; then increment `*nonce`.
/// - Decrypt payload  with `*nonce`; then increment `*nonce`.
///
/// Returns `None` on authentication failure or malformed data.
pub fn decode_stream_segment(
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
    data: &[u8],
) -> Option<(Metadata, Vec<u8>)> {
    // Need at least the encrypted metadata block.
    if data.len() < METADATA_LEN + TAG_SIZE {
        return None;
    }

    // 1. Decrypt metadata.
    let enc_meta = &data[..METADATA_LEN + TAG_SIZE];
    let meta_plain = decrypt(key, nonce, enc_meta)?;
    if meta_plain.len() != METADATA_LEN {
        return None;
    }
    let meta_arr: [u8; METADATA_LEN] = meta_plain.try_into().ok()?;
    let meta = Metadata::decode(&meta_arr)?;
    increment_nonce(nonce);

    // 2. Validate timestamp (±1 minute tolerance, matching Go behavior).
    if !meta.is_timestamp_valid() {
        return None;
    }

    // 3. Determine padding and payload sizes from decrypted metadata.
    let (prefix_len, suffix_len) = padding_lengths(&meta);
    let pay_len = payload_length(&meta);

    // Remaining bytes after the metadata block.
    let rest = &data[METADATA_LEN + TAG_SIZE..];

    // Layout of rest: [prefix_padding][encrypted_payload + tag][suffix_padding]
    let expected_rest = prefix_len + pay_len + TAG_SIZE + suffix_len;
    if rest.len() < expected_rest {
        return None;
    }

    // 4. Skip prefix padding.
    let after_prefix = &rest[prefix_len..];

    // 5. Decrypt payload.
    let enc_payload = &after_prefix[..pay_len + TAG_SIZE];
    let payload = decrypt(key, nonce, enc_payload)?;
    increment_nonce(nonce);

    Some((meta, payload))
}

/// Decode the **first** TCP stream segment, which carries an explicit nonce prefix.
///
/// Extracts the 24-byte nonce, calls `decode_stream_segment`, and returns
/// `(nonce_after_two_increments, metadata, payload)`.
pub fn decode_first_stream_segment(
    key: &[u8; KEY_LEN],
    data: &[u8],
) -> Option<([u8; NONCE_SIZE], Metadata, Vec<u8>)> {
    if data.len() < NONCE_SIZE {
        return None;
    }
    let mut nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE].try_into().ok()?;
    let rest = &data[NONCE_SIZE..];
    let (meta, payload) = decode_stream_segment(key, &mut nonce, rest)?;
    // `nonce` has been incremented twice by decode_stream_segment.
    Some((nonce, meta, payload))
}

// ---------------------------------------------------------------------------
// UDP Packet encode/decode
// ---------------------------------------------------------------------------

/// Encode one UDP packet segment.
///
/// Nonce handling mirrors Go's stateless cipher:
/// - Encrypt metadata; the output is `[nonce(24)][ciphertext+tag(16)]`.
/// - Encrypt payload with THE SAME nonce (no increment).
///
/// Wire format:
///   [nonce(24)] [encrypted_meta + tag(16)] [prefix_padding] [encrypted_payload + tag(16)] [suffix_padding]
///
/// Unlike stream segments, the nonce is chosen externally and is NOT mutated.
pub fn encode_packet_segment(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    metadata: &Metadata,
    payload: &[u8],
    prefix_padding: &[u8],
    suffix_padding: &[u8],
) -> Vec<u8> {
    // 1. Encrypt metadata (produces ciphertext without nonce prefix, same nonce).
    let meta_plain = metadata.encode();
    let enc_meta = encrypt(key, nonce, &meta_plain);

    // 2. Encrypt payload with the SAME nonce (stateless — no increment).
    let enc_payload = encrypt(key, nonce, payload);

    // 3. Assemble: [nonce][enc_meta][prefix_pad][enc_payload][suffix_pad]
    let mut out = Vec::with_capacity(
        NONCE_SIZE
            + enc_meta.len()
            + prefix_padding.len()
            + enc_payload.len()
            + suffix_padding.len(),
    );
    out.extend_from_slice(nonce);
    out.extend_from_slice(&enc_meta);
    out.extend_from_slice(prefix_padding);
    out.extend_from_slice(&enc_payload);
    out.extend_from_slice(suffix_padding);
    out
}

/// Decode one UDP packet segment.
///
/// Extracts the nonce from the first 24 bytes, decrypts metadata, then
/// decrypts payload with THE SAME nonce (stateless, no increment).
///
/// Returns `(nonce, metadata, payload)`, or `None` on failure.
pub fn decode_packet_segment(
    key: &[u8; KEY_LEN],
    data: &[u8],
) -> Option<([u8; NONCE_SIZE], Metadata, Vec<u8>)> {
    if data.len() < NONCE_SIZE + METADATA_LEN + TAG_SIZE {
        return None;
    }

    // 1. Extract nonce.
    let nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE].try_into().ok()?;

    // 2. Decrypt metadata.
    let enc_meta = &data[NONCE_SIZE..NONCE_SIZE + METADATA_LEN + TAG_SIZE];
    let meta_plain = decrypt(key, &nonce, enc_meta)?;
    if meta_plain.len() != METADATA_LEN {
        return None;
    }
    let meta_arr: [u8; METADATA_LEN] = meta_plain.try_into().ok()?;
    let meta = Metadata::decode(&meta_arr)?;

    // 3. Validate timestamp (±1 minute tolerance, matching Go behavior).
    if !meta.is_timestamp_valid() {
        return None;
    }

    // 4. Determine padding and payload sizes.
    let (prefix_len, suffix_len) = padding_lengths(&meta);
    let pay_len = payload_length(&meta);

    // Remaining after [nonce][enc_meta].
    let rest = &data[NONCE_SIZE + METADATA_LEN + TAG_SIZE..];
    let expected_rest = prefix_len + pay_len + TAG_SIZE + suffix_len;
    if rest.len() < expected_rest {
        return None;
    }

    // 5. Skip prefix padding.
    let after_prefix = &rest[prefix_len..];

    // 6. Decrypt payload with THE SAME nonce (stateless).
    let enc_payload = &after_prefix[..pay_len + TAG_SIZE];
    let payload = decrypt(key, &nonce, enc_payload)?;

    Some((nonce, meta, payload))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{derive_key, hashed_password, time_salt};
    use crate::core::metadata::{DataMetadata, ProtocolType, SessionMetadata, current_timestamp_minutes};

    fn test_key() -> [u8; KEY_LEN] {
        let pw = hashed_password("testuser", "testpass");
        let salt = time_salt(9999);
        derive_key(&pw, &salt)
    }

    fn test_nonce() -> [u8; NONCE_SIZE] {
        let mut n = [0u8; NONCE_SIZE];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    fn sample_data_meta(prefix: u8, suffix: u8, payload_len: u16) -> Metadata {
        Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataClientToServer,
            timestamp: current_timestamp_minutes(),
            session_id: 0xDEAD_BEEF,
            sequence: 1,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: prefix,
            payload_length: payload_len,
            suffix_padding_length: suffix,
        })
    }

    fn sample_session_meta(suffix: u8, payload_len: u16) -> Metadata {
        Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: current_timestamp_minutes(),
            session_id: 0xCAFE_BABE,
            sequence: 0,
            status_code: 0,
            payload_length: payload_len,
            suffix_padding_length: suffix,
        })
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stream_overhead_value() {
        assert_eq!(STREAM_OVERHEAD, METADATA_LEN + 2 * TAG_SIZE);
        assert_eq!(STREAM_OVERHEAD, 32 + 16 + 16);
        assert_eq!(STREAM_OVERHEAD, 64);
    }

    #[test]
    fn test_packet_overhead_value() {
        assert_eq!(PACKET_OVERHEAD, NONCE_SIZE + METADATA_LEN + 2 * TAG_SIZE);
        assert_eq!(PACKET_OVERHEAD, 24 + 32 + 16 + 16);
        assert_eq!(PACKET_OVERHEAD, 88);
    }

    // -----------------------------------------------------------------------
    // Encoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_stream_segment_without_nonce() {
        let key = test_key();
        let mut nonce = test_nonce();
        let payload = b"hello stream";
        let meta = sample_data_meta(0, 0, payload.len() as u16);

        let encoded = encode_stream_segment(&key, &mut nonce, &meta, payload, &[], &[], false);

        // No nonce prefix: first bytes are encrypted metadata.
        // Length: (METADATA_LEN + TAG_SIZE) + 0 + (payload.len() + TAG_SIZE) + 0
        assert_eq!(
            encoded.len(),
            METADATA_LEN + TAG_SIZE + payload.len() + TAG_SIZE
        );
        // Should NOT start with the original nonce bytes.
        let original_nonce = test_nonce();
        assert_ne!(&encoded[..NONCE_SIZE], &original_nonce[..]);
    }

    #[test]
    fn test_encode_stream_segment_with_nonce() {
        let key = test_key();
        let mut nonce = test_nonce();
        let original_nonce = test_nonce();
        let payload = b"hello first segment";
        let meta = sample_data_meta(0, 0, payload.len() as u16);

        let encoded = encode_stream_segment(&key, &mut nonce, &meta, payload, &[], &[], true);

        // First 24 bytes must be the original nonce.
        assert_eq!(
            encoded.len(),
            NONCE_SIZE + METADATA_LEN + TAG_SIZE + payload.len() + TAG_SIZE
        );
        assert_eq!(&encoded[..NONCE_SIZE], &original_nonce[..]);
    }

    #[test]
    fn test_encode_stream_nonce_advances() {
        let key = test_key();
        let mut nonce = test_nonce();
        let original_nonce = test_nonce();
        let payload = b"data";
        let meta = sample_data_meta(0, 0, payload.len() as u16);

        encode_stream_segment(&key, &mut nonce, &meta, payload, &[], &[], false);

        // Nonce should have been incremented exactly twice.
        let mut expected = original_nonce;
        increment_nonce(&mut expected);
        increment_nonce(&mut expected);
        assert_eq!(nonce, expected);
    }

    // -----------------------------------------------------------------------
    // Decode tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_stream_segment_roundtrip() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let payload = b"roundtrip payload";
        let meta = sample_data_meta(0, 0, payload.len() as u16);

        let encoded = encode_stream_segment(&key, &mut enc_nonce, &meta, payload, &[], &[], false);
        let (decoded_meta, decoded_payload) =
            decode_stream_segment(&key, &mut dec_nonce, &encoded).expect("decode failed");

        assert_eq!(decoded_payload, payload);
        // Verify metadata fields match.
        match (&meta, &decoded_meta) {
            (Metadata::Data(orig), Metadata::Data(dec)) => {
                assert_eq!(orig.session_id, dec.session_id);
                assert_eq!(orig.sequence, dec.sequence);
                assert_eq!(orig.payload_length, dec.payload_length);
            }
            _ => panic!("metadata variant mismatch"),
        }
    }

    #[test]
    fn test_decode_stream_segment_with_padding() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let payload = b"padded payload data";
        let prefix_pad = vec![0xAAu8; 16];
        let suffix_pad = vec![0xBBu8; 8];
        let meta = sample_data_meta(
            prefix_pad.len() as u8,
            suffix_pad.len() as u8,
            payload.len() as u16,
        );

        let encoded = encode_stream_segment(
            &key,
            &mut enc_nonce,
            &meta,
            payload,
            &prefix_pad,
            &suffix_pad,
            false,
        );

        // Total length: enc_meta + prefix_pad + enc_payload + suffix_pad
        let expected_len = METADATA_LEN
            + TAG_SIZE
            + prefix_pad.len()
            + payload.len()
            + TAG_SIZE
            + suffix_pad.len();
        assert_eq!(encoded.len(), expected_len);

        let (decoded_meta, decoded_payload) =
            decode_stream_segment(&key, &mut dec_nonce, &encoded).expect("decode failed");

        assert_eq!(decoded_payload, payload);
        match decoded_meta {
            Metadata::Data(d) => {
                assert_eq!(d.prefix_padding_length, prefix_pad.len() as u8);
                assert_eq!(d.suffix_padding_length, suffix_pad.len() as u8);
            }
            _ => panic!("expected Data metadata"),
        }
    }

    #[test]
    fn test_decode_first_stream_segment_roundtrip() {
        let key = test_key();
        let mut enc_nonce = test_nonce();

        let payload = b"first segment payload";
        let meta = sample_session_meta(0, payload.len() as u16);

        let encoded = encode_stream_segment(&key, &mut enc_nonce, &meta, payload, &[], &[], true);

        let (nonce_after, decoded_meta, decoded_payload) =
            decode_first_stream_segment(&key, &encoded).expect("decode failed");

        assert_eq!(decoded_payload, payload);
        match decoded_meta {
            Metadata::Session(s) => {
                assert_eq!(s.session_id, 0xCAFE_BABE);
                assert_eq!(s.payload_length, payload.len() as u16);
            }
            _ => panic!("expected Session metadata"),
        }

        // nonce_after should equal enc_nonce (both incremented twice from the same start).
        assert_eq!(nonce_after, enc_nonce);
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_stream_segment_wrong_key() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let payload = b"secret";
        let meta = sample_data_meta(0, 0, payload.len() as u16);
        let encoded = encode_stream_segment(&key, &mut enc_nonce, &meta, payload, &[], &[], false);

        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        let result = decode_stream_segment(&wrong_key, &mut dec_nonce, &encoded);
        assert!(result.is_none(), "wrong key must not decrypt");
    }

    #[test]
    fn test_decode_stream_segment_too_short() {
        let key = test_key();
        let mut nonce = test_nonce();

        // Anything shorter than METADATA_LEN + TAG_SIZE must fail.
        let short = vec![0u8; METADATA_LEN + TAG_SIZE - 1];
        assert!(decode_stream_segment(&key, &mut nonce, &short).is_none());

        // Empty input.
        assert!(decode_stream_segment(&key, &mut nonce, &[]).is_none());
    }

    #[test]
    fn test_decode_stream_segment_corrupted() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let payload = b"some data";
        let meta = sample_data_meta(0, 0, payload.len() as u16);
        let mut encoded =
            encode_stream_segment(&key, &mut enc_nonce, &meta, payload, &[], &[], false);

        // Flip a bit in the encrypted metadata region.
        encoded[0] ^= 0x01;
        assert!(decode_stream_segment(&key, &mut dec_nonce, &encoded).is_none());
    }

    // -----------------------------------------------------------------------
    // Packet (UDP) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_decode_packet_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();

        let payload = b"udp packet payload";
        let meta = sample_data_meta(0, 0, payload.len() as u16);

        let encoded = encode_packet_segment(&key, &nonce, &meta, payload, &[], &[]);
        let (dec_nonce, decoded_meta, decoded_payload) =
            decode_packet_segment(&key, &encoded).expect("decode failed");

        assert_eq!(dec_nonce, nonce);
        assert_eq!(decoded_payload, payload);
        match (&meta, &decoded_meta) {
            (Metadata::Data(orig), Metadata::Data(dec)) => {
                assert_eq!(orig.session_id, dec.session_id);
                assert_eq!(orig.payload_length, dec.payload_length);
            }
            _ => panic!("metadata variant mismatch"),
        }
    }

    #[test]
    fn test_packet_segment_includes_nonce() {
        let key = test_key();
        let nonce = test_nonce();

        let payload = b"udp data";
        let meta = sample_data_meta(0, 0, payload.len() as u16);
        let encoded = encode_packet_segment(&key, &nonce, &meta, payload, &[], &[]);

        // First 24 bytes must be the nonce.
        assert_eq!(
            encoded.len(),
            NONCE_SIZE + METADATA_LEN + TAG_SIZE + payload.len() + TAG_SIZE
        );
        assert_eq!(&encoded[..NONCE_SIZE], &nonce[..]);
    }

    #[test]
    fn test_encode_decode_packet_with_padding() {
        let key = test_key();
        let nonce = test_nonce();

        let payload = b"padded udp payload";
        let prefix_pad = vec![0xCCu8; 12];
        let suffix_pad = vec![0xDDu8; 4];
        let meta = sample_data_meta(
            prefix_pad.len() as u8,
            suffix_pad.len() as u8,
            payload.len() as u16,
        );

        let encoded = encode_packet_segment(&key, &nonce, &meta, payload, &prefix_pad, &suffix_pad);

        let (_, _, decoded_payload) = decode_packet_segment(&key, &encoded).expect("decode failed");
        assert_eq!(decoded_payload, payload);
    }

    // -----------------------------------------------------------------------
    // Multi-segment sequential test
    // -----------------------------------------------------------------------

    #[test]
    fn test_stream_multiple_segments_sequential() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let payloads: [&[u8]; 3] = [b"segment one data", b"segment two longer data", b"seg3"];

        // Encode all 3 segments sequentially (shared nonce state).
        let mut encoded_segments: Vec<Vec<u8>> = Vec::new();
        for (i, &p) in payloads.iter().enumerate() {
            let meta = sample_data_meta(0, 0, p.len() as u16);
            let include_nonce = i == 0;
            let seg =
                encode_stream_segment(&key, &mut enc_nonce, &meta, p, &[], &[], include_nonce);
            encoded_segments.push(seg);
        }

        // Decode segment 0 (has nonce prefix) via decode_first_stream_segment.
        let (mut dec_nonce, _, decoded_payload_0) =
            decode_first_stream_segment(&key, &encoded_segments[0]).expect("decode seg 0 failed");
        assert_eq!(decoded_payload_0, payloads[0]);

        // Decode segments 1 and 2 with the shared nonce state.
        for i in 1..3 {
            let (decoded_meta, decoded_payload) =
                decode_stream_segment(&key, &mut dec_nonce, &encoded_segments[i])
                    .unwrap_or_else(|| panic!("decode seg {i} failed"));
            assert_eq!(decoded_payload, payloads[i]);
            match decoded_meta {
                Metadata::Data(d) => assert_eq!(d.payload_length, payloads[i].len() as u16),
                _ => panic!("expected Data metadata for segment {i}"),
            }
        }

        // Encoder and decoder nonce states must be in sync after all segments.
        assert_eq!(dec_nonce, enc_nonce);
    }
}

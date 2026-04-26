//! UDP underlay: stateless per-packet authentication and encoding.
//!
//! Each UDP packet is self-contained with its own nonce. Unlike TCP, there is
//! no implicit nonce state -- the same nonce is used for both metadata and
//! payload within a single packet.

use crate::business::UserId;
use crate::core::crypto::{KEY_LEN, NONCE_SIZE, TAG_SIZE};
use crate::core::metadata::{METADATA_LEN, Metadata};
use crate::core::segment::{decode_packet_segment, encode_packet_segment};
use crate::core::underlay::registry::UserRegistry;

/// Result of authenticating a UDP packet: (user_id, key, nonce, metadata, payload).
type AuthResult = (UserId, [u8; KEY_LEN], [u8; NONCE_SIZE], Metadata, Vec<u8>);

/// Authenticate and decode a single UDP packet.
///
/// Returns `(user_id, key, nonce, metadata, payload)` on success.
pub fn authenticate_packet(data: &[u8], registry: &UserRegistry) -> Option<AuthResult> {
    // Minimum size: nonce + encrypted_metadata + tag.
    if data.len() < NONCE_SIZE + METADATA_LEN + TAG_SIZE {
        return None;
    }

    // Extract nonce and encrypted metadata for authentication.
    let nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE].try_into().ok()?;
    let encrypted_meta = &data[NONCE_SIZE..NONCE_SIZE + METADATA_LEN + TAG_SIZE];

    let (user_id, key) = registry.authenticate(&nonce, encrypted_meta)?;

    // Now decode the full packet with the known key.
    let (_, metadata, payload) = decode_packet_segment(&key, data)?;

    Some((user_id, key, nonce, metadata, payload))
}

/// Encode a response UDP packet.
///
/// Generates a fresh random nonce and encodes the segment in stateless mode.
pub fn encode_response_packet(key: &[u8; KEY_LEN], metadata: &Metadata, payload: &[u8]) -> Vec<u8> {
    let nonce = generate_random_nonce();
    encode_packet_segment(key, &nonce, metadata, payload, &[], &[])
}

/// Encode a response UDP packet with padding.
pub fn encode_response_packet_with_padding(
    key: &[u8; KEY_LEN],
    metadata: &Metadata,
    payload: &[u8],
    prefix_padding: &[u8],
    suffix_padding: &[u8],
) -> Vec<u8> {
    let nonce = generate_random_nonce();
    encode_packet_segment(
        key,
        &nonce,
        metadata,
        payload,
        prefix_padding,
        suffix_padding,
    )
}

/// Encode a response UDP packet with a specific nonce (useful for testing).
pub fn encode_response_packet_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    metadata: &Metadata,
    payload: &[u8],
) -> Vec<u8> {
    encode_packet_segment(key, nonce, metadata, payload, &[], &[])
}

fn generate_random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business::mieru_hashed_password;
    use crate::core::crypto::{derive_key, embed_user_hint, time_slots_now};
    use crate::core::metadata::{DataMetadata, Metadata, ProtocolType, SessionMetadata};
    use crate::core::underlay::registry::UserRegistry;

    fn make_test_registry() -> (UserRegistry, String, i64) {
        let uuid = "udp-test-uuid-5678".to_string();
        let user_id: i64 = 77;
        let registry = UserRegistry::from_list(vec![(user_id, uuid.clone())]);
        (registry, uuid, user_id)
    }

    fn derive_test_key(uuid: &str) -> [u8; KEY_LEN] {
        let hashed_pw = mieru_hashed_password(uuid);
        let slots = time_slots_now();
        let salt = crate::core::crypto::time_salt(slots[1]);
        derive_key(&hashed_pw, &salt)
    }

    fn make_client_packet(uuid: &str, payload: &[u8]) -> (Vec<u8>, [u8; KEY_LEN]) {
        let key = derive_test_key(uuid);
        let mut nonce = [0u8; NONCE_SIZE];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut nonce);
        embed_user_hint(&mut nonce, uuid);

        let meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataClientToServer,
            timestamp: crate::core::metadata::current_timestamp_minutes(),
            session_id: 0xBEEF_CAFE,
            sequence: 1,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: 0,
            payload_length: payload.len() as u16,
            suffix_padding_length: 0,
        });

        let packet = encode_packet_segment(&key, &nonce, &meta, payload, &[], &[]);
        (packet, key)
    }

    #[test]
    fn test_udp_encode_decode_packet_roundtrip() {
        let key = derive_test_key("roundtrip-uuid");
        let mut nonce = [0u8; NONCE_SIZE];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut nonce);

        let payload = b"udp roundtrip data";
        let meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataClientToServer,
            timestamp: crate::core::metadata::current_timestamp_minutes(),
            session_id: 0xAAAA_BBBB,
            sequence: 5,
            unack_seq: 4,
            window_size: 128,
            fragment_number: 0,
            prefix_padding_length: 0,
            payload_length: payload.len() as u16,
            suffix_padding_length: 0,
        });

        let encoded = encode_packet_segment(&key, &nonce, &meta, payload, &[], &[]);
        let (dec_nonce, dec_meta, dec_payload) =
            decode_packet_segment(&key, &encoded).expect("decode failed");

        assert_eq!(dec_nonce, nonce);
        assert_eq!(dec_payload, payload);
        assert_eq!(dec_meta.session_id(), 0xAAAA_BBBB);
    }

    #[test]
    fn test_udp_authenticate_packet_valid() {
        let (registry, uuid, expected_user_id) = make_test_registry();
        let payload = b"authenticated udp data";
        let (packet, expected_key) = make_client_packet(&uuid, payload);

        let result = authenticate_packet(&packet, &registry);
        assert!(result.is_some(), "auth should succeed");

        let (user_id, key, _nonce, metadata, dec_payload) = result.unwrap();
        assert_eq!(user_id, expected_user_id);
        assert_eq!(key, expected_key);
        assert_eq!(dec_payload, payload);
        assert_eq!(metadata.protocol_type(), ProtocolType::DataClientToServer);
    }

    #[test]
    fn test_udp_authenticate_packet_invalid() {
        let (registry, _uuid, _) = make_test_registry();

        // Create a packet for a user NOT in the registry.
        let payload = b"unknown user data";
        let (packet, _) = make_client_packet("unknown-uuid-9999", payload);

        let result = authenticate_packet(&packet, &registry);
        assert!(result.is_none(), "unknown user should fail auth");
    }

    #[test]
    fn test_udp_authenticate_packet_too_short() {
        let registry = UserRegistry::from_list(vec![]);
        let short_data = vec![0u8; 10];
        assert!(authenticate_packet(&short_data, &registry).is_none());
    }

    #[test]
    fn test_udp_encode_response_packet_with_padding() {
        let key = derive_test_key("padding-uuid");
        let payload = b"padded response";
        let prefix_pad = vec![0xAAu8; 10];
        let suffix_pad = vec![0xBBu8; 5];
        let meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataServerToClient,
            timestamp: crate::core::metadata::current_timestamp_minutes(),
            session_id: 0xABCD_EF01,
            sequence: 1,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: prefix_pad.len() as u8,
            payload_length: payload.len() as u16,
            suffix_padding_length: suffix_pad.len() as u8,
        });

        let encoded =
            encode_response_packet_with_padding(&key, &meta, payload, &prefix_pad, &suffix_pad);

        // Should be decodable
        let (_, dec_meta, dec_payload) =
            decode_packet_segment(&key, &encoded).expect("padded response decode failed");
        assert_eq!(dec_payload, payload);
        assert_eq!(dec_meta.session_id(), 0xABCD_EF01);
    }

    #[test]
    fn test_udp_encode_response_packet() {
        let key = derive_test_key("response-uuid");
        let payload = b"response data";
        let meta = Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionResponse,
            timestamp: crate::core::metadata::current_timestamp_minutes(),
            session_id: 0x1234_5678,
            sequence: 0,
            status_code: 0,
            payload_length: payload.len() as u16,
            suffix_padding_length: 0,
        });

        let encoded = encode_response_packet(&key, &meta, payload);

        // Should be decodable.
        let (_, dec_meta, dec_payload) =
            decode_packet_segment(&key, &encoded).expect("response decode failed");
        assert_eq!(dec_payload, payload);
        assert_eq!(dec_meta.protocol_type(), ProtocolType::OpenSessionResponse);
    }
}

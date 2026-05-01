//! TCP underlay: handles a single TCP connection after authentication.
//!
//! Wire format for a TCP stream:
//! - First segment: `[nonce(24)][encrypted_meta+tag][prefix_pad][encrypted_payload+tag][suffix_pad]`
//! - Subsequent:    `[encrypted_meta+tag][prefix_pad][encrypted_payload+tag][suffix_pad]`
//!
//! The nonce is incremented twice per segment (once for metadata, once for payload).
//! The server's send nonce is independent of the receive nonce.

use crate::business::UserId;
use crate::core::crypto::{KEY_LEN, NONCE_SIZE, TAG_SIZE, increment_nonce};
use crate::core::metadata::{METADATA_LEN, Metadata};
use crate::core::segment::{
    decode_first_stream_segment, decode_stream_segment, encode_stream_segment,
};
use crate::core::underlay::registry::{AuthCache, UserRegistry};
use crate::error::{Error, Result};

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// A TCP underlay represents an authenticated TCP connection with stateful
/// nonce-based encryption for both directions.
pub struct TcpUnderlay {
    pub user_id: UserId,
    key: [u8; KEY_LEN],
    recv_nonce: [u8; NONCE_SIZE],
    send_nonce: [u8; NONCE_SIZE],
    /// Whether the first response segment has been sent (includes nonce prefix).
    first_send: bool,
}

/// Read half of a TCP underlay — owns the receive nonce.
pub struct TcpUnderlayReader {
    key: [u8; KEY_LEN],
    recv_nonce: [u8; NONCE_SIZE],
}

/// Write half of a TCP underlay — owns the send nonce.
pub struct TcpUnderlayWriter {
    key: [u8; KEY_LEN],
    send_nonce: [u8; NONCE_SIZE],
    first_send: bool,
}

impl TcpUnderlay {
    /// Authenticate an incoming TCP connection by reading the first segment.
    ///
    /// Uses two-phase auth when `auth_cache` and `auth_semaphore` are provided:
    /// 1. **Fast path** (no semaphore): tries IP-affinity + hot-user cache inline.
    /// 2. **Slow path** (with semaphore): acquires a concurrency permit, then
    ///    does the full AEAD scan on a blocking thread.
    ///
    /// This ensures cached users (99%+ of traffic) never contend for semaphore
    /// permits, while attackers (always cache-miss) are rate-limited.
    pub async fn authenticate(
        stream: &mut TcpStream,
        registry: &Arc<UserRegistry>,
        auth_cache: Option<&Arc<AuthCache>>,
        auth_semaphore: Option<&Arc<Semaphore>>,
    ) -> Result<(Self, Metadata, Vec<u8>)> {
        // The first segment starts with [nonce(24)][encrypted_meta(32)+tag(16)].
        // We must read at least the nonce + encrypted metadata to attempt auth.
        // The minimum first read is NONCE_SIZE + METADATA_LEN + TAG_SIZE = 72 bytes.
        let header_len = NONCE_SIZE + METADATA_LEN + TAG_SIZE;
        let mut header = vec![0u8; header_len];
        stream.read_exact(&mut header).await?;

        let nonce: [u8; NONCE_SIZE] = header[..NONCE_SIZE]
            .try_into()
            .expect("slice is NONCE_SIZE");
        let encrypted_meta = header[NONCE_SIZE..].to_vec();
        let peer_ip = stream.peer_addr().ok().map(|a| a.ip());

        // Phase 1: try cache fast path (IP affinity + hot users).
        // At most ~100 AEAD decrypts — fast enough to run inline without
        // spawn_blocking or semaphore.
        let fast_result = if let Some(cache) = auth_cache {
            registry.try_fast_auth(&nonce, &encrypted_meta, cache, peer_ip)
        } else {
            None
        };

        let (user_id, key, encrypted_meta) = if let Some((uid, key)) = fast_result {
            (uid, key, encrypted_meta)
        } else {
            // Phase 2: full AEAD scan — try_acquire to drop excess on
            // saturation. Mirrors the UDP fix in udp_relay.rs: under attack,
            // unbounded `acquire().await` would pile up tokio tasks each
            // holding a TcpStream + Arc clones, exhausting RAM. Legitimate
            // bursts at this scale stay well under the per-permit ~6ms scan
            // time, so try_acquire failures are confined to true overload.
            let _permit = if let Some(sem) = auth_semaphore {
                Some(sem.try_acquire().map_err(|_| Error::AuthFailed)?)
            } else {
                None
            };

            let registry = Arc::clone(registry);
            let cache = auth_cache.cloned();
            tokio::task::spawn_blocking(move || {
                if let Some(ref cache) = cache {
                    registry
                        .authenticate_cached(&nonce, &encrypted_meta, cache, peer_ip)
                        .map(|(uid, k)| (uid, k, encrypted_meta))
                } else {
                    registry
                        .authenticate(&nonce, &encrypted_meta)
                        .map(|(uid, k)| (uid, k, encrypted_meta))
                }
            })
            .await
            .map_err(|_| Error::AuthFailed)?
            .ok_or(Error::AuthFailed)?
        };

        // Decrypt the metadata to find out how much more to read.
        let meta_plain = crate::core::crypto::decrypt(&key, &nonce, &encrypted_meta)
            .ok_or(Error::DecryptionFailed)?;
        let meta_arr: [u8; METADATA_LEN] = meta_plain
            .try_into()
            .map_err(|_| Error::InvalidSegment("metadata length mismatch".into()))?;
        let metadata =
            Metadata::decode(&meta_arr).ok_or(Error::InvalidSegment("invalid metadata".into()))?;

        // Advance the nonce past the metadata decryption.
        let mut recv_nonce = nonce;
        increment_nonce(&mut recv_nonce);

        // Determine remaining bytes to read: prefix_padding + [encrypted_payload + tag] + suffix_padding.
        // When payload is empty, there is no encrypted payload block.
        let (prefix_len, suffix_len) = padding_lengths(&metadata);
        let pay_len = payload_length(&metadata);

        let payload_block_len = if pay_len > 0 { pay_len + TAG_SIZE } else { 0 };
        let remaining_len = prefix_len + payload_block_len + suffix_len;
        let mut remaining = vec![0u8; remaining_len];
        if remaining_len > 0 {
            stream.read_exact(&mut remaining).await?;
        }

        // Decrypt payload (only if non-empty; nonce only advances when payload exists).
        let payload = if pay_len > 0 {
            let after_prefix = &remaining[prefix_len..];
            let encrypted_payload = &after_prefix[..pay_len + TAG_SIZE];
            let p = crate::core::crypto::decrypt(&key, &recv_nonce, encrypted_payload)
                .ok_or(Error::DecryptionFailed)?;
            increment_nonce(&mut recv_nonce);
            p
        } else {
            vec![]
        };

        // Generate a fresh random nonce for the send direction.
        let send_nonce = generate_random_nonce();

        Ok((
            Self {
                user_id,
                key,
                recv_nonce,
                send_nonce,
                first_send: true,
            },
            metadata,
            payload,
        ))
    }

    /// Split into independent reader and writer halves.
    ///
    /// This enables running read and write loops as independent concurrent
    /// tasks, preventing deadlock when `dispatch().await` blocks the read
    /// path from draining the outbound channel.
    pub fn split(self) -> (TcpUnderlayReader, TcpUnderlayWriter) {
        (
            TcpUnderlayReader {
                key: self.key,
                recv_nonce: self.recv_nonce,
            },
            TcpUnderlayWriter {
                key: self.key,
                send_nonce: self.send_nonce,
                first_send: self.first_send,
            },
        )
    }

    /// Get the encryption key (for testing or session management).
    pub fn key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// TcpUnderlayReader
// ---------------------------------------------------------------------------

impl TcpUnderlayReader {
    /// Read one segment from the stream.
    pub async fn read_segment<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
    ) -> Result<(Metadata, Vec<u8>)> {
        let meta_len = METADATA_LEN + TAG_SIZE;
        let mut enc_meta = vec![0u8; meta_len];
        stream.read_exact(&mut enc_meta).await?;

        let meta_plain = crate::core::crypto::decrypt(&self.key, &self.recv_nonce, &enc_meta)
            .ok_or(Error::DecryptionFailed)?;
        let meta_arr: [u8; METADATA_LEN] = meta_plain
            .try_into()
            .map_err(|_| Error::InvalidSegment("metadata length mismatch".into()))?;
        let metadata =
            Metadata::decode(&meta_arr).ok_or(Error::InvalidSegment("invalid metadata".into()))?;
        increment_nonce(&mut self.recv_nonce);

        let (prefix_len, suffix_len) = padding_lengths(&metadata);
        let pay_len = payload_length(&metadata);

        let payload_block_len = if pay_len > 0 { pay_len + TAG_SIZE } else { 0 };
        let remaining_len = prefix_len + payload_block_len + suffix_len;
        let mut remaining = vec![0u8; remaining_len];
        if remaining_len > 0 {
            stream.read_exact(&mut remaining).await?;
        }

        let payload = if pay_len > 0 {
            let after_prefix = &remaining[prefix_len..];
            let encrypted_payload = &after_prefix[..pay_len + TAG_SIZE];
            let p = crate::core::crypto::decrypt(&self.key, &self.recv_nonce, encrypted_payload)
                .ok_or(Error::DecryptionFailed)?;
            increment_nonce(&mut self.recv_nonce);
            p
        } else {
            vec![]
        };

        Ok((metadata, payload))
    }
}

// ---------------------------------------------------------------------------
// TcpUnderlayWriter
// ---------------------------------------------------------------------------

impl TcpUnderlayWriter {
    /// Write one segment to the stream.
    ///
    /// The first call includes the nonce prefix; subsequent calls do not.
    pub async fn write_segment<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        metadata: &Metadata,
        payload: &[u8],
        prefix_padding: &[u8],
        suffix_padding: &[u8],
    ) -> Result<()> {
        let include_nonce = self.first_send;
        let encoded = encode_stream_segment(
            &self.key,
            &mut self.send_nonce,
            metadata,
            payload,
            prefix_padding,
            suffix_padding,
            include_nonce,
        );
        stream.write_all(&encoded).await?;
        self.first_send = false;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
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

fn generate_random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

// ---------------------------------------------------------------------------
// Synchronous helpers for unit testing (no async, no TcpStream)
// ---------------------------------------------------------------------------

/// Encode a segment using shared nonce state (for testing).
pub fn encode_test_segment(
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
    metadata: &Metadata,
    payload: &[u8],
    include_nonce: bool,
) -> Vec<u8> {
    encode_stream_segment(key, nonce, metadata, payload, &[], &[], include_nonce)
}

/// Decode a segment using shared nonce state (for testing).
pub fn decode_test_segment(
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
    data: &[u8],
) -> Option<(Metadata, Vec<u8>)> {
    decode_stream_segment(key, nonce, data)
}

/// Decode the first segment (with nonce prefix) for testing.
pub fn decode_test_first_segment(
    key: &[u8; KEY_LEN],
    data: &[u8],
) -> Option<([u8; NONCE_SIZE], Metadata, Vec<u8>)> {
    decode_first_stream_segment(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business::mieru_hashed_password;
    use crate::core::crypto::{derive_key, embed_user_hint, increment_nonce, time_slots_now};
    use crate::core::metadata::{
        DataMetadata, Metadata, ProtocolType, SessionMetadata, current_timestamp_minutes,
    };

    fn test_key() -> [u8; KEY_LEN] {
        let pw = crate::core::crypto::hashed_password("testuser", "testpass");
        let salt = crate::core::crypto::time_salt(9999);
        derive_key(&pw, &salt)
    }

    fn test_nonce() -> [u8; NONCE_SIZE] {
        let mut n = [0u8; NONCE_SIZE];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    fn sample_data_meta(payload_len: u16) -> Metadata {
        Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataClientToServer,
            timestamp: current_timestamp_minutes(),
            session_id: 0xDEAD_BEEF,
            sequence: 1,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: 0,
            payload_length: payload_len,
            suffix_padding_length: 0,
        })
    }

    fn sample_session_meta(payload_len: u16) -> Metadata {
        Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: current_timestamp_minutes(),
            session_id: 0xCAFE_BABE,
            sequence: 0,
            status_code: 0,
            payload_length: payload_len,
            suffix_padding_length: 0,
        })
    }

    #[test]
    fn test_tcp_encode_decode_segment_roundtrip() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let payload = b"hello tcp underlay";
        let meta = sample_data_meta(payload.len() as u16);

        let encoded = encode_test_segment(&key, &mut enc_nonce, &meta, payload, false);
        let (decoded_meta, decoded_payload) =
            decode_test_segment(&key, &mut dec_nonce, &encoded).expect("decode failed");

        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_meta.session_id(), meta.session_id());
    }

    #[test]
    fn test_tcp_nonce_advances_after_segment() {
        let key = test_key();
        let original = test_nonce();
        let mut enc_nonce = test_nonce();

        let payload = b"data";
        let meta = sample_data_meta(payload.len() as u16);

        encode_test_segment(&key, &mut enc_nonce, &meta, payload, false);

        // Nonce should have been incremented exactly twice (meta + payload).
        let mut expected = original;
        increment_nonce(&mut expected);
        increment_nonce(&mut expected);
        assert_eq!(enc_nonce, expected);
    }

    #[test]
    fn test_tcp_multiple_segments_nonce_sync() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let payloads: [&[u8]; 3] = [b"segment one", b"segment two longer", b"seg3"];

        for (i, &p) in payloads.iter().enumerate() {
            let meta = sample_data_meta(p.len() as u16);
            let include_nonce = i == 0;
            let encoded = encode_test_segment(&key, &mut enc_nonce, &meta, p, include_nonce);

            if i == 0 {
                let (nonce_after, _decoded_meta, decoded_payload) =
                    decode_test_first_segment(&key, &encoded).expect("decode first failed");
                dec_nonce = nonce_after;
                assert_eq!(decoded_payload, p);
            } else {
                let (_decoded_meta, decoded_payload) =
                    decode_test_segment(&key, &mut dec_nonce, &encoded)
                        .expect("decode subsequent failed");
                assert_eq!(decoded_payload, p);
            }
        }

        // Encoder and decoder nonce must be synchronized.
        assert_eq!(enc_nonce, dec_nonce);
    }

    // -----------------------------------------------------------------------
    // Empty payload nonce tests — verifies the bug fix
    // -----------------------------------------------------------------------

    #[test]
    fn test_tcp_empty_payload_nonce_advances_once() {
        let key = test_key();
        let original = test_nonce();
        let mut nonce = test_nonce();

        // Encode a session segment with empty payload (like OpenSessionResponse)
        let meta = Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionResponse,
            timestamp: current_timestamp_minutes(),
            session_id: 42,
            sequence: 0,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        });
        encode_test_segment(&key, &mut nonce, &meta, &[], false);

        let mut expected = original;
        increment_nonce(&mut expected); // only once for metadata
        assert_eq!(
            nonce, expected,
            "empty payload segment should advance nonce only once"
        );
    }

    #[test]
    fn test_tcp_empty_payload_decode_roundtrip() {
        let key = test_key();
        let mut enc_nonce = test_nonce();
        let mut dec_nonce = test_nonce();

        let meta = Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionResponse,
            timestamp: current_timestamp_minutes(),
            session_id: 42,
            sequence: 0,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        });
        let encoded = encode_test_segment(&key, &mut enc_nonce, &meta, &[], false);
        let (decoded_meta, decoded_payload) =
            decode_test_segment(&key, &mut dec_nonce, &encoded).expect("decode failed");

        assert!(decoded_payload.is_empty());
        assert_eq!(
            decoded_meta.protocol_type(),
            ProtocolType::OpenSessionResponse
        );
        assert_eq!(
            enc_nonce, dec_nonce,
            "nonce desync after empty payload roundtrip"
        );
    }

    #[test]
    fn test_tcp_simulated_session_handshake_flow() {
        // Simulates the exact flow that caused the nonce desync bug:
        //
        // Client→Server: OpenSessionRequest with SOCKS5 payload (nonce +2)
        // Server→Client: OpenSessionResponse empty (nonce +1, NOT +2!)
        // Server→Client: DataServerToClient with SOCKS5 response (nonce +2)
        // Client→Server: DataClientToServer with HTTP data (nonce +2)
        // Server→Client: DataServerToClient with HTTP response (nonce +2)

        let key = test_key();

        // --- Client send direction ---
        let mut client_send_nonce = test_nonce();

        // Client sends OpenSessionRequest with SOCKS5 request payload
        let socks5_request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]; // CONNECT 127.0.0.1:80
        let open_meta = Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: current_timestamp_minutes(),
            session_id: 1,
            sequence: 0,
            status_code: 0,
            payload_length: socks5_request.len() as u16,
            suffix_padding_length: 0,
        });
        let first_seg = encode_test_segment(
            &key,
            &mut client_send_nonce,
            &open_meta,
            &socks5_request,
            true,
        );

        // Server decodes first segment
        let (server_recv_nonce, decoded_meta, decoded_payload) =
            decode_test_first_segment(&key, &first_seg).expect("server decode first failed");
        assert_eq!(decoded_payload, socks5_request);
        assert_eq!(
            decoded_meta.protocol_type(),
            ProtocolType::OpenSessionRequest
        );
        assert_eq!(
            server_recv_nonce, client_send_nonce,
            "nonce sync after first segment"
        );

        // --- Server send direction ---
        let mut server_send_nonce = [0xAA; NONCE_SIZE];

        // Server sends OpenSessionResponse (EMPTY payload — the bug trigger)
        let open_resp = Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionResponse,
            timestamp: current_timestamp_minutes(),
            session_id: 1,
            sequence: 0,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        });
        let resp_seg = encode_test_segment(&key, &mut server_send_nonce, &open_resp, &[], true);

        // Client decodes first server segment
        let (client_recv_nonce, decoded_resp, decoded_resp_payload) =
            decode_test_first_segment(&key, &resp_seg).expect("client decode resp failed");
        assert!(decoded_resp_payload.is_empty());
        assert_eq!(
            decoded_resp.protocol_type(),
            ProtocolType::OpenSessionResponse
        );
        assert_eq!(
            server_send_nonce, client_recv_nonce,
            "CRITICAL: nonce desync after empty OpenSessionResponse!"
        );

        // Server sends DataServerToClient with SOCKS5 response
        let socks5_response = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let data_meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataServerToClient,
            timestamp: current_timestamp_minutes(),
            session_id: 1,
            sequence: 1,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: 0,
            payload_length: socks5_response.len() as u16,
            suffix_padding_length: 0,
        });
        let mut client_recv_nonce = client_recv_nonce;
        let data_seg = encode_test_segment(
            &key,
            &mut server_send_nonce,
            &data_meta,
            &socks5_response,
            false,
        );

        // Client decodes SOCKS5 response
        let (_, decoded_socks_resp) = decode_test_segment(&key, &mut client_recv_nonce, &data_seg)
            .expect("SOCKS5 response decode failed — nonce desync!");
        assert_eq!(decoded_socks_resp, socks5_response);
        assert_eq!(
            server_send_nonce, client_recv_nonce,
            "nonce sync after SOCKS5 response"
        );

        // Server sends HTTP response data
        let http_data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let http_meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataServerToClient,
            timestamp: current_timestamp_minutes(),
            session_id: 1,
            sequence: 2,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: 0,
            payload_length: http_data.len() as u16,
            suffix_padding_length: 0,
        });
        let http_seg =
            encode_test_segment(&key, &mut server_send_nonce, &http_meta, http_data, false);

        let (_, decoded_http) = decode_test_segment(&key, &mut client_recv_nonce, &http_seg)
            .expect("HTTP data decode failed — nonce desync propagated!");
        assert_eq!(decoded_http, http_data);
        assert_eq!(
            server_send_nonce, client_recv_nonce,
            "nonce sync after HTTP data"
        );
    }

    #[test]
    fn test_tcp_rejects_stale_timestamp() {
        // A segment with a stale timestamp (e.g., 0 = unix epoch) should be
        // rejected during decode_first_stream_segment when validation is on.
        let uuid = "stale-ts-uuid";
        let user_id: UserId = 100;
        let registry =
            super::super::registry::UserRegistry::from_list(vec![(user_id, uuid.to_string())]);

        let hashed_pw = mieru_hashed_password(uuid);
        let slots = time_slots_now();
        let salt = crate::core::crypto::time_salt(slots[1]);
        let client_key = derive_key(&hashed_pw, &salt);

        let mut client_nonce = generate_random_nonce();
        embed_user_hint(&mut client_nonce, uuid);

        // Create a segment with timestamp = 0 (stale).
        let stale_meta = Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: 0, // stale!
            session_id: 0xDEAD_0001,
            sequence: 0,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        });
        let first_segment =
            encode_test_segment(&client_key, &mut client_nonce, &stale_meta, &[], true);

        // Registry should authenticate (key is correct), but the metadata
        // timestamp validation should reject this segment.
        let nonce_bytes: [u8; NONCE_SIZE] = first_segment[..NONCE_SIZE].try_into().unwrap();
        let enc_meta_bytes = &first_segment[NONCE_SIZE..NONCE_SIZE + METADATA_LEN + TAG_SIZE];
        let auth_result = registry.authenticate(&nonce_bytes, enc_meta_bytes);
        assert!(
            auth_result.is_some(),
            "auth should still succeed (key is valid)"
        );

        // But full decode+validate should reject it.
        let result = decode_test_first_segment(&client_key, &first_segment);
        assert!(
            result.is_none(),
            "segment with stale timestamp should be rejected"
        );
    }

    #[test]
    fn test_full_tcp_flow() {
        // Simulate: create user registry -> encode first segment as client ->
        // authenticate -> exchange data segments -> verify payloads match.
        let uuid = "flow-test-uuid-12345";
        let user_id: UserId = 99;

        // Build registry.
        let registry =
            super::super::registry::UserRegistry::from_list(vec![(user_id, uuid.to_string())]);

        // Client creates first segment.
        let hashed_pw = mieru_hashed_password(uuid);
        let slots = time_slots_now();
        let salt = crate::core::crypto::time_salt(slots[1]);
        let client_key = derive_key(&hashed_pw, &salt);

        let mut client_nonce = generate_random_nonce();
        embed_user_hint(&mut client_nonce, uuid);

        let first_payload = b"open session payload";
        let first_meta = sample_session_meta(first_payload.len() as u16);
        let first_segment = encode_test_segment(
            &client_key,
            &mut client_nonce,
            &first_meta,
            first_payload,
            true, // include nonce
        );

        // Server authenticates.
        let (server_recv_nonce, decoded_meta, decoded_payload) =
            decode_test_first_segment(&client_key, &first_segment)
                .expect("first segment decode failed");

        // Verify the registry authentication works with the raw nonce + encrypted meta.
        let nonce_bytes: [u8; NONCE_SIZE] = first_segment[..NONCE_SIZE].try_into().unwrap();
        let enc_meta_bytes = &first_segment[NONCE_SIZE..NONCE_SIZE + METADATA_LEN + TAG_SIZE];
        let auth_result = registry.authenticate(&nonce_bytes, enc_meta_bytes);
        assert!(auth_result.is_some(), "registry auth should succeed");
        let (auth_user_id, auth_key) = auth_result.unwrap();
        assert_eq!(auth_user_id, user_id);
        assert_eq!(auth_key, client_key);

        assert_eq!(decoded_payload, first_payload);
        assert_eq!(
            decoded_meta.protocol_type(),
            ProtocolType::OpenSessionRequest
        );

        // Client sends 2 more data segments.
        let mut dec_nonce = server_recv_nonce;
        for seq in 1..=2u32 {
            let payload = format!("data segment {}", seq);
            let meta = sample_data_meta(payload.len() as u16);
            let encoded = encode_test_segment(
                &client_key,
                &mut client_nonce,
                &meta,
                payload.as_bytes(),
                false,
            );
            let (_, decoded_payload) = decode_test_segment(&client_key, &mut dec_nonce, &encoded)
                .expect("data segment decode failed");
            assert_eq!(decoded_payload, payload.as_bytes());
        }

        // Nonce states must be synchronized.
        assert_eq!(client_nonce, dec_nonce);
    }

    // -----------------------------------------------------------------------
    // Regression: TCP auth must drop on saturated semaphore, not queue.
    //
    // History: an earlier `sem.acquire().await` allowed cache-miss attackers
    // to pile up tokio tasks each holding a TcpStream + Arc clones, exhausting
    // RAM on small VMs (1G / 2C, 2000 users). UDP was fixed first; this test
    // pins the TCP path to the same drop-on-full semantics.
    // -----------------------------------------------------------------------

    /// `TcpUnderlay::authenticate` must return `Err` immediately when the
    /// auth semaphore is exhausted, instead of parking on the await queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticate_drops_when_semaphore_exhausted() {
        use crate::core::underlay::registry::{AuthCache, UserRegistry};
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::Semaphore;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry = Arc::new(UserRegistry::from_list(vec![(1, "real-user".into())]));
        let cache = Arc::new(AuthCache::new());
        let sem = Arc::new(Semaphore::new(1));
        let _hold = sem.clone().try_acquire_owned().unwrap();

        let server = {
            let registry = Arc::clone(&registry);
            let cache = Arc::clone(&cache);
            let sem = Arc::clone(&sem);
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                TcpUnderlay::authenticate(&mut stream, &registry, Some(&cache), Some(&sem)).await
            })
        };

        let mut s = TcpStream::connect(server_addr).await.unwrap();
        let header = [0xA5u8; NONCE_SIZE + METADATA_LEN + TAG_SIZE];
        s.write_all(&header).await.unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("authenticate must not park on the semaphore queue");
        let inner = outcome.expect("server task panicked");
        assert!(
            inner.is_err(),
            "exhausted auth semaphore must reject the connection"
        );
    }

    /// Pinned semantics for the auth-semaphore: every excess attempt drops
    /// instead of queueing. Matches the pattern used by both TCP (after the
    /// fix) and UDP (`udp_relay.rs:182`).
    #[tokio::test]
    async fn auth_semaphore_try_acquire_drops_excess() {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let sem = Arc::new(Semaphore::new(1));
        let _hold = sem.clone().try_acquire_owned().unwrap();

        let n = 1000;
        let mut accepted = 0usize;
        let mut dropped = 0usize;
        for _ in 0..n {
            match sem.try_acquire() {
                Ok(_p) => accepted += 1,
                Err(_) => dropped += 1,
            }
        }

        assert_eq!(accepted, 0);
        assert_eq!(dropped, n, "every excess attempt must drop, no queueing");
    }

}

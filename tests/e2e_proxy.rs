//! End-to-end integration test for the mieru proxy protocol.
//!
//! Requires a running mieru server on 127.0.0.1:15999 with user UUID
//! available in the database. Run with:
//!
//!   cargo test --test e2e_proxy -- --ignored --nocapture

use std::time::Duration;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Protocol constants (duplicated from lib to keep test self-contained)
// ---------------------------------------------------------------------------

const KEY_LEN: usize = 32;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const METADATA_LEN: usize = 32;
const KEY_ITER: u32 = 64;
const KEY_REFRESH_INTERVAL: u64 = 120;

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn hashed_password(uuid: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(uuid.as_bytes()); // password = uuid
    h.update([0x00u8]);
    h.update(uuid.as_bytes()); // username = uuid
    h.finalize().into()
}

fn time_salt(unix_seconds: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(unix_seconds.to_be_bytes());
    h.finalize().into()
}

fn derive_key(hashed_pw: &[u8; 32], salt: &[u8; 32]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::<Hmac<Sha256>>(hashed_pw, salt, KEY_ITER, &mut key).expect("PBKDF2 should not fail");
    key
}

fn current_time_slot() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let half = KEY_REFRESH_INTERVAL / 2;
    ((now + half) / KEY_REFRESH_INTERVAL) * KEY_REFRESH_INTERVAL
}

fn current_timestamp_minutes() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (secs / 60) as u32
}

fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    cipher.encrypt(xnonce, plaintext).expect("encrypt failed")
}

fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    cipher.decrypt(xnonce, ciphertext).ok()
}

fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for i in 0..NONCE_SIZE {
        let j = NONCE_SIZE - 1 - i;
        nonce[j] = nonce[j].wrapping_add(1);
        if nonce[j] != 0 {
            break;
        }
    }
}

fn compute_user_hint(username: &str, nonce: &[u8]) -> [u8; 4] {
    let prefix_len = nonce.len().min(16);
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(&nonce[..prefix_len]);
    let digest = h.finalize();
    digest[..4].try_into().unwrap()
}

fn embed_user_hint(nonce: &mut [u8; NONCE_SIZE], username: &str) {
    let hint = compute_user_hint(username, nonce);
    nonce[20..24].copy_from_slice(&hint);
}

// ---------------------------------------------------------------------------
// Segment encoding (client side)
// ---------------------------------------------------------------------------

fn encode_open_session(
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
    session_id: u32,
    socks_addr: &[u8],
) -> Vec<u8> {
    let original_nonce = *nonce;

    // SessionMetadata: OpenSessionRequest (type=2)
    let mut meta = [0u8; METADATA_LEN];
    meta[0] = 2; // OpenSessionRequest
    meta[2..6].copy_from_slice(&current_timestamp_minutes().to_be_bytes());
    meta[6..10].copy_from_slice(&session_id.to_be_bytes());
    // sequence = 0
    // status_code = 0
    let payload_len = socks_addr.len() as u16;
    meta[15..17].copy_from_slice(&payload_len.to_be_bytes());
    // suffix_padding_length = 0

    let enc_meta = encrypt(key, nonce, &meta);
    increment_nonce(nonce);

    let enc_payload = encrypt(key, nonce, socks_addr);
    increment_nonce(nonce);

    let mut out = Vec::with_capacity(NONCE_SIZE + enc_meta.len() + enc_payload.len());
    out.extend_from_slice(&original_nonce); // first segment includes nonce
    out.extend_from_slice(&enc_meta);
    out.extend_from_slice(&enc_payload);
    out
}

fn encode_data_segment(
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
    session_id: u32,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    // DataMetadata: DataClientToServer (type=6)
    let mut meta = [0u8; METADATA_LEN];
    meta[0] = 6; // DataClientToServer
    meta[2..6].copy_from_slice(&current_timestamp_minutes().to_be_bytes());
    meta[6..10].copy_from_slice(&session_id.to_be_bytes());
    meta[10..14].copy_from_slice(&sequence.to_be_bytes());
    // unack_seq = 0, window_size = 256
    meta[18..20].copy_from_slice(&256u16.to_be_bytes());
    // prefix_padding = 0
    let payload_len = payload.len() as u16;
    meta[22..24].copy_from_slice(&payload_len.to_be_bytes());
    // suffix_padding = 0

    let enc_meta = encrypt(key, nonce, &meta);
    increment_nonce(nonce);

    let enc_payload = encrypt(key, nonce, payload);
    increment_nonce(nonce);

    let mut out = Vec::with_capacity(enc_meta.len() + enc_payload.len());
    out.extend_from_slice(&enc_meta);
    out.extend_from_slice(&enc_payload);
    out
}

// ---------------------------------------------------------------------------
// Segment decoding (reading server responses)
// ---------------------------------------------------------------------------

/// Read and decode the first server segment (has nonce prefix).
/// Returns (server_nonce_after, protocol_type, session_id, payload).
async fn read_first_server_segment(
    stream: &mut TcpStream,
    key: &[u8; KEY_LEN],
) -> (
    [u8; NONCE_SIZE],
    u8,  // protocol_type
    u32, // session_id
    Vec<u8>,
) {
    // Read nonce + encrypted metadata
    let mut header = vec![0u8; NONCE_SIZE + METADATA_LEN + TAG_SIZE];
    stream
        .read_exact(&mut header)
        .await
        .expect("read server first header");

    let mut server_nonce: [u8; NONCE_SIZE] = header[..NONCE_SIZE].try_into().unwrap();
    let enc_meta = &header[NONCE_SIZE..];

    let meta_plain = decrypt(key, &server_nonce, enc_meta).expect("decrypt server metadata");
    increment_nonce(&mut server_nonce);

    let protocol_type = meta_plain[0];
    let session_id =
        u32::from_be_bytes([meta_plain[6], meta_plain[7], meta_plain[8], meta_plain[9]]);

    // Determine payload and padding sizes based on protocol type
    let (prefix_len, payload_len, suffix_len) = if protocol_type <= 5 {
        // Session metadata
        let payload_len = u16::from_be_bytes([meta_plain[15], meta_plain[16]]) as usize;
        let suffix_len = meta_plain[17] as usize;
        (0usize, payload_len, suffix_len)
    } else {
        // Data metadata
        let prefix_len = meta_plain[21] as usize;
        let payload_len = u16::from_be_bytes([meta_plain[22], meta_plain[23]]) as usize;
        let suffix_len = meta_plain[24] as usize;
        (prefix_len, payload_len, suffix_len)
    };

    // Go mieru: when payload is empty, NO encrypted payload block is written (no tag).
    // Nonce only advances for payload when payload is non-empty.
    let payload_block_len = if payload_len > 0 {
        payload_len + TAG_SIZE
    } else {
        0
    };
    let remaining_len = prefix_len + payload_block_len + suffix_len;
    let mut remaining = vec![0u8; remaining_len];
    if remaining_len > 0 {
        stream
            .read_exact(&mut remaining)
            .await
            .expect("read server first remaining");
    }

    let payload = if payload_len > 0 {
        let enc_payload = &remaining[prefix_len..prefix_len + payload_len + TAG_SIZE];
        let p = decrypt(key, &server_nonce, enc_payload).expect("decrypt server payload");
        increment_nonce(&mut server_nonce);
        p
    } else {
        vec![]
    };

    (server_nonce, protocol_type, session_id, payload)
}

/// Read and decode a subsequent server segment (no nonce prefix).
/// Returns (protocol_type, session_id, payload).
async fn read_server_segment(
    stream: &mut TcpStream,
    key: &[u8; KEY_LEN],
    nonce: &mut [u8; NONCE_SIZE],
) -> (u8, u32, Vec<u8>) {
    let mut enc_meta_buf = vec![0u8; METADATA_LEN + TAG_SIZE];
    stream
        .read_exact(&mut enc_meta_buf)
        .await
        .expect("read server segment meta");

    let meta_plain = decrypt(key, nonce, &enc_meta_buf).expect("decrypt server segment metadata");
    increment_nonce(nonce);

    let protocol_type = meta_plain[0];
    let session_id =
        u32::from_be_bytes([meta_plain[6], meta_plain[7], meta_plain[8], meta_plain[9]]);

    let (prefix_len, payload_len, suffix_len) = if protocol_type <= 5 {
        let payload_len = u16::from_be_bytes([meta_plain[15], meta_plain[16]]) as usize;
        let suffix_len = meta_plain[17] as usize;
        (0usize, payload_len, suffix_len)
    } else {
        let prefix_len = meta_plain[21] as usize;
        let payload_len = u16::from_be_bytes([meta_plain[22], meta_plain[23]]) as usize;
        let suffix_len = meta_plain[24] as usize;
        (prefix_len, payload_len, suffix_len)
    };

    // Go mieru: when payload is empty, NO encrypted payload block is written.
    let payload_block_len = if payload_len > 0 {
        payload_len + TAG_SIZE
    } else {
        0
    };
    let remaining_len = prefix_len + payload_block_len + suffix_len;
    let mut remaining = vec![0u8; remaining_len];
    if remaining_len > 0 {
        stream
            .read_exact(&mut remaining)
            .await
            .expect("read server segment remaining");
    }

    let payload = if payload_len > 0 {
        let enc_payload = &remaining[prefix_len..prefix_len + payload_len + TAG_SIZE];
        let p = decrypt(key, nonce, enc_payload).expect("decrypt server segment payload");
        increment_nonce(nonce);
        p
    } else {
        vec![]
    };

    (protocol_type, session_id, payload)
}

// ---------------------------------------------------------------------------
// SOCKS5 address encoding
// ---------------------------------------------------------------------------

/// Encode a full SOCKS5 CONNECT request: [version=0x05, command=0x01, reserved=0x00, addr...]
/// This matches what real Go mieru clients send via `Request.WriteToSocks5()`.
fn encode_socks5_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.push(0x05); // SOCKS5 version
    buf.push(0x01); // CONNECT command
    buf.push(0x00); // reserved
    buf.push(0x01); // IPv4
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

fn encode_socks5_connect_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 1 + domain.len() + 2);
    buf.push(0x05); // SOCKS5 version
    buf.push(0x01); // CONNECT command
    buf.push(0x00); // reserved
    buf.push(0x03); // domain
    buf.push(domain.len() as u8);
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

// ---------------------------------------------------------------------------
// Echo server
// ---------------------------------------------------------------------------

async fn start_echo_server() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

async fn run_echo_server(listener: TcpListener) {
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Get the test user UUID from environment or use a default.
fn test_uuid() -> String {
    std::env::var("MIERU_TEST_UUID")
        .unwrap_or_else(|_| "12361d7a-840a-4499-947e-76823e102f00".to_string())
}

fn mieru_server_addr() -> String {
    std::env::var("MIERU_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:15999".to_string())
}

#[tokio::test]
#[ignore] // requires running mieru server
async fn test_e2e_tcp_proxy_echo() {
    // 1. Start echo server
    let (echo_listener, echo_port) = start_echo_server().await;
    println!("Echo server listening on port {echo_port}");
    tokio::spawn(run_echo_server(echo_listener));

    // 2. Derive mieru key
    let uuid = test_uuid();
    let hashed_pw = hashed_password(&uuid);
    let slot = current_time_slot();
    let salt = time_salt(slot);
    let key = derive_key(&hashed_pw, &salt);

    // 3. Generate client nonce with user hint
    let mut client_nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut client_nonce);
    embed_user_hint(&mut client_nonce, &uuid);

    // 4. Connect to mieru server
    let server_addr = mieru_server_addr();
    println!("Connecting to mieru server at {server_addr}");
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&server_addr))
        .await
        .expect("connect timeout")
        .expect("connect failed");
    println!("Connected!");

    // 5. Send OpenSessionRequest with SOCKS5 address pointing to echo server
    let session_id: u32 = 0x0000_0001;
    let socks_addr = encode_socks5_connect_ipv4([127, 0, 0, 1], echo_port);
    let first_segment = encode_open_session(&key, &mut client_nonce, session_id, &socks_addr);
    stream
        .write_all(&first_segment)
        .await
        .expect("write first segment");
    println!("Sent OpenSessionRequest (session_id={session_id}, target=127.0.0.1:{echo_port})");

    // 6. Read server's first response (OpenSessionResponse)
    let (mut server_nonce, proto_type, resp_session_id, _payload) = tokio::time::timeout(
        Duration::from_secs(5),
        read_first_server_segment(&mut stream, &key),
    )
    .await
    .expect("read first response timeout");
    println!("Got server response: proto_type={proto_type}, session_id={resp_session_id}");
    assert_eq!(proto_type, 3, "expected OpenSessionResponse (type=3)");
    assert_eq!(resp_session_id, session_id, "session ID mismatch");
    println!("Session opened successfully!");

    // 6b. Read SOCKS5 response from server (DataServerToClient with 10-byte SOCKS5 reply)
    // Real Go mieru clients block here until they receive the SOCKS5 response.
    let (socks_proto_type, _socks_sid, socks_payload) = tokio::time::timeout(
        Duration::from_secs(5),
        read_server_segment(&mut stream, &key, &mut server_nonce),
    )
    .await
    .expect("read SOCKS5 response timeout");
    assert_eq!(
        socks_proto_type, 7,
        "expected DataServerToClient for SOCKS5 response"
    );
    assert!(socks_payload.len() >= 4, "SOCKS5 response too short");
    assert_eq!(socks_payload[0], 0x05, "SOCKS5 version");
    assert_eq!(socks_payload[1], 0x00, "SOCKS5 success reply");
    println!("Got SOCKS5 response: {:02x?}", &socks_payload);

    // 7. Send test data through the proxy
    let test_data = b"Hello from mieru e2e test!";
    let data_segment = encode_data_segment(&key, &mut client_nonce, session_id, 1, test_data);
    stream
        .write_all(&data_segment)
        .await
        .expect("write data segment");
    println!("Sent data: {:?}", String::from_utf8_lossy(test_data));

    // 8. Read echoed data back from server
    let (proto_type, resp_session_id, echoed_payload) = tokio::time::timeout(
        Duration::from_secs(5),
        read_server_segment(&mut stream, &key, &mut server_nonce),
    )
    .await
    .expect("read echo response timeout");
    println!(
        "Got echo response: proto_type={proto_type}, session_id={resp_session_id}, payload={:?}",
        String::from_utf8_lossy(&echoed_payload)
    );
    assert_eq!(proto_type, 7, "expected DataServerToClient (type=7)");
    assert_eq!(resp_session_id, session_id);
    assert_eq!(echoed_payload, test_data, "echoed data mismatch!");

    println!("E2E proxy test PASSED! Data was successfully proxied through mieru.");

    // 9. Send another round to verify continued operation
    let test_data2 = b"Second round of data through the mieru proxy!";
    let data_segment2 = encode_data_segment(&key, &mut client_nonce, session_id, 2, test_data2);
    stream
        .write_all(&data_segment2)
        .await
        .expect("write data segment 2");

    let (proto_type2, _, echoed2) = tokio::time::timeout(
        Duration::from_secs(5),
        read_server_segment(&mut stream, &key, &mut server_nonce),
    )
    .await
    .expect("read echo response 2 timeout");
    assert_eq!(proto_type2, 7);
    assert_eq!(echoed2, test_data2, "second round echo mismatch!");
    println!("Second round PASSED!");
}

#[tokio::test]
#[ignore]
async fn test_e2e_tcp_proxy_http() {
    // Test proxying an actual HTTP request through mieru

    let uuid = test_uuid();
    let hashed_pw = hashed_password(&uuid);
    let slot = current_time_slot();
    let salt = time_salt(slot);
    let key = derive_key(&hashed_pw, &salt);

    let mut client_nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut client_nonce);
    embed_user_hint(&mut client_nonce, &uuid);

    let server_addr = mieru_server_addr();
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&server_addr))
        .await
        .expect("connect timeout")
        .expect("connect failed");

    // Target: httpbin.org:80 (or use a known reachable host)
    let session_id: u32 = 0x0000_0002;
    let socks_addr = encode_socks5_connect_domain("httpbin.org", 80);
    let http_request = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";

    // Combine socks addr + HTTP request as the first session payload
    let open_payload = socks_addr.clone();
    // The socks address is in the OpenSession payload, but the actual HTTP data
    // comes as a separate Data segment (based on how handle_session works).
    let first_segment = encode_open_session(&key, &mut client_nonce, session_id, &open_payload);
    stream
        .write_all(&first_segment)
        .await
        .expect("write first segment");
    println!("Sent OpenSessionRequest to httpbin.org:80");

    // Read OpenSessionResponse
    let (mut server_nonce, proto_type, _, _) = tokio::time::timeout(
        Duration::from_secs(5),
        read_first_server_segment(&mut stream, &key),
    )
    .await
    .expect("timeout");
    assert_eq!(proto_type, 3, "expected OpenSessionResponse");
    println!("Session opened to httpbin.org:80");

    // Read SOCKS5 response (DataServerToClient)
    let (_socks_pt, _socks_sid, socks_resp) = tokio::time::timeout(
        Duration::from_secs(5),
        read_server_segment(&mut stream, &key, &mut server_nonce),
    )
    .await
    .expect("SOCKS5 response timeout");
    assert_eq!(socks_resp[0], 0x05, "SOCKS5 version");
    assert_eq!(socks_resp[1], 0x00, "SOCKS5 success reply");
    println!("Got SOCKS5 response");

    // Send HTTP request as data segment
    let data_segment = encode_data_segment(&key, &mut client_nonce, session_id, 1, http_request);
    stream
        .write_all(&data_segment)
        .await
        .expect("write HTTP request");
    println!("Sent HTTP GET /get");

    // Read HTTP response (may come in multiple segments)
    let mut full_response = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(
            deadline,
            read_server_segment(&mut stream, &key, &mut server_nonce),
        )
        .await
        {
            Ok((proto_type, _, payload)) => {
                if proto_type == 7 {
                    // DataServerToClient
                    full_response.extend_from_slice(&payload);
                    let response_str = String::from_utf8_lossy(&full_response);
                    if response_str.contains("\r\n\r\n")
                        && (response_str.contains("\"url\"")
                            || response_str.contains("Connection: close"))
                    {
                        // Got enough of the HTTP response
                        break;
                    }
                } else if proto_type == 5 {
                    // CloseSessionResponse
                    println!("Session closed by server");
                    break;
                }
            }
            Err(_) => {
                println!("Timeout waiting for HTTP response segments");
                break;
            }
        }
    }

    let response_str = String::from_utf8_lossy(&full_response);
    println!(
        "HTTP response ({} bytes):\n{}",
        full_response.len(),
        &response_str[..response_str.len().min(500)]
    );
    assert!(
        response_str.contains("HTTP/1.1 200"),
        "expected HTTP 200 OK response"
    );
    println!("HTTP proxy test PASSED!");
}

// ---------------------------------------------------------------------------
// UDP packet encode/decode helpers
// ---------------------------------------------------------------------------

fn encode_udp_open_session(
    key: &[u8; KEY_LEN],
    username: &str,
    session_id: u32,
    socks_addr: &[u8],
) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    embed_user_hint(&mut nonce, username);

    // SessionMetadata: OpenSessionRequest (type=2)
    let mut meta = [0u8; METADATA_LEN];
    meta[0] = 2; // OpenSessionRequest
    meta[2..6].copy_from_slice(&current_timestamp_minutes().to_be_bytes());
    meta[6..10].copy_from_slice(&session_id.to_be_bytes());
    let payload_len = socks_addr.len() as u16;
    meta[15..17].copy_from_slice(&payload_len.to_be_bytes());

    // UDP: same nonce for metadata and payload (stateless)
    let enc_meta = encrypt(key, &nonce, &meta);
    let enc_payload = encrypt(key, &nonce, socks_addr);

    let mut out = Vec::new();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&enc_meta);
    out.extend_from_slice(&enc_payload);
    out
}

fn encode_udp_data_segment(
    key: &[u8; KEY_LEN],
    username: &str,
    session_id: u32,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    embed_user_hint(&mut nonce, username);

    // DataMetadata: DataClientToServer (type=6)
    let mut meta = [0u8; METADATA_LEN];
    meta[0] = 6; // DataClientToServer
    meta[2..6].copy_from_slice(&current_timestamp_minutes().to_be_bytes());
    meta[6..10].copy_from_slice(&session_id.to_be_bytes());
    meta[10..14].copy_from_slice(&sequence.to_be_bytes());
    meta[18..20].copy_from_slice(&256u16.to_be_bytes()); // window_size
    let payload_len = payload.len() as u16;
    meta[22..24].copy_from_slice(&payload_len.to_be_bytes());

    // UDP: same nonce for metadata and payload (stateless)
    let enc_meta = encrypt(key, &nonce, &meta);
    let enc_payload = encrypt(key, &nonce, payload);

    let mut out = Vec::new();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&enc_meta);
    out.extend_from_slice(&enc_payload);
    out
}

fn encode_udp_close_session(key: &[u8; KEY_LEN], username: &str, session_id: u32) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    embed_user_hint(&mut nonce, username);

    // SessionMetadata: CloseSessionRequest (type=4)
    let mut meta = [0u8; METADATA_LEN];
    meta[0] = 4;
    meta[2..6].copy_from_slice(&current_timestamp_minutes().to_be_bytes());
    meta[6..10].copy_from_slice(&session_id.to_be_bytes());

    // Go mieru: empty payload → no encrypted payload block at all
    let enc_meta = encrypt(key, &nonce, &meta);

    let mut out = Vec::new();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&enc_meta);
    out
}

/// Decode a UDP response packet from the server.
/// Returns (protocol_type, session_id, sequence, payload).
fn decode_udp_response(key: &[u8; KEY_LEN], data: &[u8]) -> Option<(u8, u32, u32, Vec<u8>)> {
    if data.len() < NONCE_SIZE + METADATA_LEN + TAG_SIZE {
        return None;
    }

    let nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE].try_into().ok()?;
    let enc_meta = &data[NONCE_SIZE..NONCE_SIZE + METADATA_LEN + TAG_SIZE];
    let meta_plain = decrypt(key, &nonce, enc_meta)?;

    let protocol_type = meta_plain[0];
    let session_id =
        u32::from_be_bytes([meta_plain[6], meta_plain[7], meta_plain[8], meta_plain[9]]);
    let sequence = u32::from_be_bytes([
        meta_plain[10],
        meta_plain[11],
        meta_plain[12],
        meta_plain[13],
    ]);

    let (prefix_len, payload_len, suffix_len) = if protocol_type <= 5 {
        let payload_len = u16::from_be_bytes([meta_plain[15], meta_plain[16]]) as usize;
        let suffix_len = meta_plain[17] as usize;
        (0usize, payload_len, suffix_len)
    } else {
        let prefix_len = meta_plain[21] as usize;
        let payload_len = u16::from_be_bytes([meta_plain[22], meta_plain[23]]) as usize;
        let suffix_len = meta_plain[24] as usize;
        (prefix_len, payload_len, suffix_len)
    };

    let rest = &data[NONCE_SIZE + METADATA_LEN + TAG_SIZE..];
    // Go mieru: when payload is empty, no encrypted payload block exists
    let payload_block_len = if payload_len > 0 {
        payload_len + TAG_SIZE
    } else {
        0
    };
    let expected = prefix_len + payload_block_len + suffix_len;
    if rest.len() < expected {
        return None;
    }

    let payload = if payload_len > 0 {
        let enc_payload = &rest[prefix_len..prefix_len + payload_len + TAG_SIZE];
        decrypt(key, &nonce, enc_payload)?
    } else {
        vec![]
    };

    Some((protocol_type, session_id, sequence, payload))
}

// ---------------------------------------------------------------------------
// UDP Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires running mieru server with UDP transport
async fn test_e2e_udp_proxy_echo() {
    use tokio::net::UdpSocket;

    // 1. Start echo server (TCP - the proxy connects to target via TCP)
    let (echo_listener, echo_port) = start_echo_server().await;
    println!("[UDP] Echo server listening on port {echo_port}");
    tokio::spawn(run_echo_server(echo_listener));

    // 2. Derive mieru key
    let uuid = test_uuid();
    let hashed_pw = hashed_password(&uuid);
    let slot = current_time_slot();
    let salt = time_salt(slot);
    let key = derive_key(&hashed_pw, &salt);

    // 3. Bind a local UDP socket
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
    let server_addr = mieru_server_addr();
    client_socket
        .connect(&server_addr)
        .await
        .expect("connect UDP");
    println!("[UDP] Client bound, targeting mieru server at {server_addr}");

    // 4. Send OpenSessionRequest with SOCKS5 address
    let session_id: u32 = 0x0000_0010;
    let socks_addr = encode_socks5_connect_ipv4([127, 0, 0, 1], echo_port);
    let open_packet = encode_udp_open_session(&key, &uuid, session_id, &socks_addr);
    client_socket
        .send(&open_packet)
        .await
        .expect("send open session");
    println!(
        "[UDP] Sent OpenSessionRequest (session_id={session_id:#x}, target=127.0.0.1:{echo_port})"
    );

    // 5. Read OpenSessionResponse
    let mut recv_buf = vec![0u8; 2048];
    let (len, proto_type, resp_sid) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let len = client_socket.recv(&mut recv_buf).await.expect("recv UDP");
            if let Some((proto_type, sid, _, _)) = decode_udp_response(&key, &recv_buf[..len]) {
                return (len, proto_type, sid);
            }
            println!("[UDP] Got undecodable packet ({len} bytes), retrying...");
        }
    })
    .await
    .expect("timeout waiting for OpenSessionResponse");
    println!("[UDP] Got response: proto_type={proto_type}, session_id={resp_sid:#x} ({len} bytes)");
    assert_eq!(proto_type, 3, "expected OpenSessionResponse (type=3)");
    assert_eq!(resp_sid, session_id);
    println!("[UDP] Session opened!");

    // 6. Send data through the proxy
    let test_data = b"Hello from UDP mieru e2e test!";
    let data_packet = encode_udp_data_segment(&key, &uuid, session_id, 0, test_data);
    client_socket.send(&data_packet).await.expect("send data");
    println!("[UDP] Sent data: {:?}", String::from_utf8_lossy(test_data));

    // 7. Read echoed data (may get ACKs or other control packets first)
    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let len = client_socket.recv(&mut recv_buf).await.expect("recv UDP");
            if let Some((proto_type, sid, _seq, payload)) =
                decode_udp_response(&key, &recv_buf[..len])
            {
                if proto_type == 7 && sid == session_id && !payload.is_empty() {
                    return payload;
                }
                println!("[UDP] Got packet: proto_type={proto_type}, session_id={sid:#x}, payload_len={}", payload.len());
            }
        }
    })
    .await
    .expect("timeout waiting for echo data");

    println!("[UDP] Got echo: {:?}", String::from_utf8_lossy(&echoed));
    assert_eq!(echoed, test_data, "echoed data mismatch!");
    println!("[UDP] E2E UDP proxy echo test PASSED!");

    // 8. Second round
    let test_data2 = b"Second UDP round!";
    let data_packet2 = encode_udp_data_segment(&key, &uuid, session_id, 1, test_data2);
    client_socket
        .send(&data_packet2)
        .await
        .expect("send data 2");

    let echoed2 = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let len = client_socket.recv(&mut recv_buf).await.expect("recv UDP");
            if let Some((proto_type, sid, _seq, payload)) =
                decode_udp_response(&key, &recv_buf[..len])
                && proto_type == 7
                && sid == session_id
                && !payload.is_empty()
            {
                return payload;
            }
        }
    })
    .await
    .expect("timeout waiting for echo data 2");

    assert_eq!(echoed2, test_data2, "second round echo mismatch!");
    println!("[UDP] Second round PASSED!");
}

/// Comprehensive UDP stress test: multiple sessions, varying payload sizes,
/// concurrent data, and repeated rounds to catch intermittent issues.
#[tokio::test]
#[ignore]
async fn test_e2e_udp_proxy_stress() {
    use tokio::net::UdpSocket;

    let (echo_listener, echo_port) = start_echo_server().await;
    println!("[UDP-STRESS] Echo server on port {echo_port}");
    tokio::spawn(run_echo_server(echo_listener));

    let uuid = test_uuid();
    let hashed_pw = hashed_password(&uuid);
    let slot = current_time_slot();
    let salt = time_salt(slot);
    let key = derive_key(&hashed_pw, &salt);

    let server_addr = mieru_server_addr();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client_socket.connect(&server_addr).await.expect("connect");

    let total_sessions = 5u32;
    let rounds_per_session = 20u32;
    let mut passed = 0u32;
    let mut failed = 0u32;

    for s in 0..total_sessions {
        let session_id = 0x1000 + s;

        // Open session
        let socks_addr = encode_socks5_connect_ipv4([127, 0, 0, 1], echo_port);
        let open_pkt = encode_udp_open_session(&key, &uuid, session_id, &socks_addr);
        client_socket.send(&open_pkt).await.unwrap();

        // Wait for OpenSessionResponse
        let mut recv_buf = vec![0u8; 4096];
        let opened = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let len = client_socket.recv(&mut recv_buf).await.unwrap();
                if let Some((pt, sid, _, _)) = decode_udp_response(&key, &recv_buf[..len])
                    && pt == 3
                    && sid == session_id
                {
                    return true;
                }
            }
        })
        .await;

        if opened.is_err() {
            println!("[UDP-STRESS] Session {session_id:#x} open TIMEOUT");
            failed += 1;
            continue;
        }
        println!("[UDP-STRESS] Session {session_id:#x} opened");

        // Send multiple rounds with varying payload sizes
        for r in 0..rounds_per_session {
            // Vary payload: small, medium, large
            let payload_size = match r % 4 {
                0 => 16,   // tiny
                1 => 128,  // small
                2 => 512,  // medium
                3 => 1200, // near MTU
                _ => unreachable!(),
            };
            let test_data: Vec<u8> = (0..payload_size)
                .map(|i| {
                    (session_id as u8)
                        .wrapping_mul(7)
                        .wrapping_add(r as u8)
                        .wrapping_add(i as u8)
                })
                .collect();

            let pkt = encode_udp_data_segment(&key, &uuid, session_id, r, &test_data);
            client_socket.send(&pkt).await.unwrap();

            // Collect response, skip ACKs
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let len = client_socket.recv(&mut recv_buf).await.unwrap();
                    if let Some((pt, sid, _seq, payload)) =
                        decode_udp_response(&key, &recv_buf[..len])
                        && pt == 7
                        && sid == session_id
                        && !payload.is_empty()
                    {
                        return payload;
                    }
                }
            })
            .await;

            match result {
                Ok(echoed) => {
                    if echoed == test_data {
                        passed += 1;
                    } else {
                        println!(
                            "[UDP-STRESS] Session {session_id:#x} round {r}: DATA MISMATCH (sent {} bytes, got {} bytes)",
                            test_data.len(),
                            echoed.len()
                        );
                        failed += 1;
                    }
                }
                Err(_) => {
                    println!(
                        "[UDP-STRESS] Session {session_id:#x} round {r}: TIMEOUT ({payload_size} bytes)"
                    );
                    failed += 1;
                    // Don't break — keep testing remaining rounds
                }
            }
        }

        // Close session
        let close_pkt = encode_udp_close_session(&key, &uuid, session_id);
        client_socket.send(&close_pkt).await.unwrap();
        // Small delay between sessions
        tokio::time::sleep(Duration::from_millis(50)).await;

        println!(
            "[UDP-STRESS] Session {session_id:#x} done. Running total: {passed} passed, {failed} failed"
        );
    }

    let total = passed + failed;
    println!("\n[UDP-STRESS] === RESULTS ===");
    println!(
        "[UDP-STRESS] {passed}/{total} passed, {failed} failed ({} sessions x {} rounds)",
        total_sessions, rounds_per_session
    );

    // Allow a small failure rate for UDP (packet loss)
    let success_rate = passed as f64 / total as f64;
    println!("[UDP-STRESS] Success rate: {:.1}%", success_rate * 100.0);
    assert!(
        success_rate >= 0.90,
        "success rate {:.1}% is below 90% threshold",
        success_rate * 100.0
    );
    if failed == 0 {
        println!("[UDP-STRESS] PERFECT — all rounds passed!");
    }
}

/// Heavy TCP stress test: multiple concurrent sessions, large payloads,
/// many rounds, measures throughput.
#[tokio::test]
#[ignore]
async fn test_e2e_tcp_proxy_stress() {
    let (echo_listener, echo_port) = start_echo_server().await;
    println!("[TCP-STRESS] Echo server on port {echo_port}");
    tokio::spawn(run_echo_server(echo_listener));

    let uuid = test_uuid();
    let hashed_pw = hashed_password(&uuid);
    let slot = current_time_slot();
    let salt = time_salt(slot);
    let key = derive_key(&hashed_pw, &salt);
    let server_addr = mieru_server_addr();

    let total_connections = 10u32;
    let rounds_per_conn = 200u32;
    let payload_sizes: &[usize] = &[8, 64, 256, 1024, 4096, 8192, 16384, 32000];

    let start_time = std::time::Instant::now();
    let mut total_passed = 0u64;
    let mut total_failed = 0u64;
    let mut total_bytes = 0u64;

    for c in 0..total_connections {
        let mut client_nonce = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut client_nonce);
        embed_user_hint(&mut client_nonce, &uuid);

        let mut stream =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&server_addr))
                .await
                .expect("connect timeout")
                .expect("connect failed");

        let session_id: u32 = 0xAA00_0000 + c;
        let socks_addr = encode_socks5_connect_ipv4([127, 0, 0, 1], echo_port);
        let first_seg = encode_open_session(&key, &mut client_nonce, session_id, &socks_addr);
        stream.write_all(&first_seg).await.unwrap();

        let (mut server_nonce, pt, sid, _) = tokio::time::timeout(
            Duration::from_secs(5),
            read_first_server_segment(&mut stream, &key),
        )
        .await
        .expect("open timeout");
        assert_eq!(pt, 3);
        assert_eq!(sid, session_id);

        // Read SOCKS5 response before sending data
        let (socks_pt, _, socks_payload) = tokio::time::timeout(
            Duration::from_secs(5),
            read_server_segment(&mut stream, &key, &mut server_nonce),
        )
        .await
        .expect("SOCKS5 response timeout in stress test");
        assert_eq!(socks_pt, 7);
        assert_eq!(socks_payload[1], 0x00, "SOCKS5 success");

        let mut conn_passed = 0u32;
        let mut conn_failed = 0u32;
        let mut conn_bytes = 0u64;

        for r in 0..rounds_per_conn {
            let payload_size = payload_sizes[r as usize % payload_sizes.len()];
            let test_data: Vec<u8> = (0..payload_size)
                .map(|i| {
                    (c as u8)
                        .wrapping_mul(31)
                        .wrapping_add(r as u8)
                        .wrapping_mul(13)
                        .wrapping_add(i as u8)
                })
                .collect();

            let seg = encode_data_segment(&key, &mut client_nonce, session_id, r + 1, &test_data);
            stream.write_all(&seg).await.unwrap();

            let result = tokio::time::timeout(Duration::from_secs(10), async {
                let mut collected = Vec::new();
                loop {
                    let (pt, _sid, chunk) =
                        read_server_segment(&mut stream, &key, &mut server_nonce).await;
                    if pt == 7 {
                        collected.extend_from_slice(&chunk);
                        if collected.len() >= test_data.len() {
                            return collected;
                        }
                    }
                }
            })
            .await;

            match result {
                Ok(echoed) => {
                    if echoed[..test_data.len()] == test_data[..] {
                        conn_passed += 1;
                        conn_bytes += (payload_size * 2) as u64; // upload + download
                    } else {
                        println!(
                            "[TCP-STRESS] conn={c} round={r}: MISMATCH (sent {}, got {})",
                            test_data.len(),
                            echoed.len()
                        );
                        conn_failed += 1;
                    }
                }
                Err(_) => {
                    println!("[TCP-STRESS] conn={c} round={r}: TIMEOUT ({payload_size} bytes)");
                    conn_failed += 1;
                    break;
                }
            }
        }

        total_passed += conn_passed as u64;
        total_failed += conn_failed as u64;
        total_bytes += conn_bytes;

        let elapsed = start_time.elapsed().as_secs_f64();
        println!(
            "[TCP-STRESS] conn {}/{total_connections}: {conn_passed}/{} passed | cumulative: {total_passed} ok, {total_failed} fail, {:.1} MB, {:.1}s",
            c + 1,
            conn_passed + conn_failed,
            total_bytes as f64 / 1_048_576.0,
            elapsed,
        );
    }

    let elapsed = start_time.elapsed();
    let total = total_passed + total_failed;
    let throughput_mb = total_bytes as f64 / 1_048_576.0 / elapsed.as_secs_f64();

    println!("\n[TCP-STRESS] ========== RESULTS ==========");
    println!("[TCP-STRESS] {total_passed}/{total} passed, {total_failed} failed");
    println!(
        "[TCP-STRESS] {total_connections} connections x {rounds_per_conn} rounds = {total} total"
    );
    println!("[TCP-STRESS] Payload sizes: {:?}", payload_sizes);
    println!(
        "[TCP-STRESS] Total data: {:.2} MB in {:.2}s ({:.2} MB/s)",
        total_bytes as f64 / 1_048_576.0,
        elapsed.as_secs_f64(),
        throughput_mb,
    );
    assert_eq!(total_failed, 0, "TCP is reliable — no failures allowed");
    println!("[TCP-STRESS] PERFECT — all {total} rounds passed!");
}

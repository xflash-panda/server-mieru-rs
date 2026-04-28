//! Session multiplexing over an underlay connection.
//!
//! Multiple logical sessions share a single TCP or UDP underlay. The
//! `SessionManager` dispatches incoming segments to the correct session
//! and collects outbound segments from all sessions for writing back to
//! the underlay.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};

use crate::core::metadata::{
    DataMetadata, Metadata, ProtocolType, SessionMetadata, current_timestamp_minutes,
};
use crate::core::padding;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A segment ready to be written to the underlay.
#[derive(Debug)]
pub struct OutboundSegment {
    pub metadata: Metadata,
    pub payload: Vec<u8>,
    pub prefix_padding: Vec<u8>,
    pub suffix_padding: Vec<u8>,
}

/// Handle to an active session held by the manager.
struct SessionEntry {
    data_tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
}

/// Manages multiplexed sessions over an underlay.
pub struct SessionManager {
    sessions: HashMap<u32, SessionEntry>,
    outbound_tx: mpsc::Sender<OutboundSegment>,
}

/// A stream representing one side of a session, used by the proxy handler.
///
/// Implements `AsyncRead` + `AsyncWrite` for compatibility with
/// `tokio::io::copy_bidirectional`.
pub struct SessionStream {
    session_id: u32,
    data_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<OutboundSegment>,
    poll_sender: PollSender<OutboundSegment>,
    next_seq: u32,
    cancel: CancellationToken,
    /// Buffered data from partial reads.
    read_buf: Vec<u8>,
    read_offset: usize,
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

impl SessionManager {
    /// Create a new session manager and the outbound segment receiver.
    ///
    /// The caller should drive the receiver to write segments back to the
    /// underlay connection.
    pub fn new() -> (Self, mpsc::Receiver<OutboundSegment>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(2048);
        (
            Self {
                sessions: HashMap::new(),
                outbound_tx,
            },
            outbound_rx,
        )
    }

    /// Dispatch an incoming segment to the appropriate session.
    ///
    /// - `OpenSessionRequest`: creates a new session and returns its `SessionStream`.
    /// - `CloseSessionRequest` / `CloseSessionResponse`: removes the session.
    /// - `DataClientToServer`: forwards payload to the session's data channel.
    /// - `AckClientToServer`: currently a no-op for TCP (flow control simplified).
    ///
    /// Returns `Some(SessionStream)` only for `OpenSessionRequest`.
    ///
    /// This method is async because it uses blocking sends to guarantee no data
    /// is lost — matching Go mieru's behavior where the underlay loop blocks
    /// when session buffers are full, providing natural backpressure.
    pub async fn dispatch(
        &mut self,
        metadata: &Metadata,
        payload: Vec<u8>,
    ) -> Option<SessionStream> {
        let session_id = metadata.session_id();
        let protocol = metadata.protocol_type();

        match protocol {
            ProtocolType::OpenSessionRequest => {
                if session_id == 0 {
                    tracing::warn!("rejecting reserved session ID 0");
                    return None;
                }
                if self.sessions.contains_key(&session_id) {
                    tracing::warn!(session_id, "duplicate open session request");
                    return None;
                }

                let (data_tx, data_rx) = mpsc::channel(4096);
                let cancel = CancellationToken::new();

                self.sessions.insert(
                    session_id,
                    SessionEntry {
                        data_tx: data_tx.clone(),
                        cancel: cancel.clone(),
                    },
                );

                // Send the open-session payload (if any) to the data channel.
                // Blocking send guarantees initial payload is never lost.
                if !payload.is_empty()
                    && let Err(e) = data_tx.send(payload).await
                {
                    tracing::warn!(session_id, "failed to deliver initial payload: {}", e);
                }

                // Send OpenSessionResponse back to the client.
                // Blocking send guarantees control messages are never dropped.
                let suffix_pad = padding::session_padding(0);
                let response_meta = Metadata::Session(SessionMetadata {
                    protocol_type: ProtocolType::OpenSessionResponse,
                    timestamp: current_timestamp_minutes(),
                    session_id,
                    sequence: 0,
                    status_code: 0,
                    payload_length: 0,
                    suffix_padding_length: suffix_pad.len() as u8,
                });
                if let Err(e) = self
                    .outbound_tx
                    .send(OutboundSegment {
                        metadata: response_meta,
                        payload: vec![],
                        suffix_padding: suffix_pad,
                        prefix_padding: vec![],
                    })
                    .await
                {
                    tracing::warn!(
                        session_id,
                        "outbound channel closed, OpenSessionResponse not sent: {}",
                        e
                    );
                }

                let outbound_tx = self.outbound_tx.clone();
                let poll_sender = PollSender::new(outbound_tx.clone());
                Some(SessionStream {
                    session_id,
                    data_rx,
                    outbound_tx,
                    poll_sender,
                    next_seq: 1,
                    cancel,
                    read_buf: Vec::new(),
                    read_offset: 0,
                })
            }
            ProtocolType::CloseSessionRequest | ProtocolType::CloseSessionResponse => {
                self.close_session(session_id).await;
                None
            }
            ProtocolType::DataClientToServer => {
                if let Some(entry) = self.sessions.get(&session_id)
                    && !payload.is_empty()
                    && let Err(e) = entry.data_tx.send(payload).await
                {
                    tracing::debug!(session_id, "session closed, data not delivered: {}", e);
                }
                None
            }
            ProtocolType::AckClientToServer => {
                // TCP: no-op for simplified flow control.
                None
            }
            _ => {
                tracing::debug!(?protocol, "ignoring unexpected protocol type in dispatch");
                None
            }
        }
    }

    /// Close a specific session by ID.
    pub async fn close_session(&mut self, session_id: u32) {
        if let Some(entry) = self.sessions.remove(&session_id) {
            entry.cancel.cancel();
            // Send close response. Blocking send guarantees delivery.
            let suffix_pad = padding::session_padding(0);
            let close_meta = Metadata::Session(SessionMetadata {
                protocol_type: ProtocolType::CloseSessionResponse,
                timestamp: current_timestamp_minutes(),
                session_id,
                sequence: 0,
                status_code: 0,
                payload_length: 0,
                suffix_padding_length: suffix_pad.len() as u8,
            });
            if let Err(e) = self
                .outbound_tx
                .send(OutboundSegment {
                    metadata: close_meta,
                    payload: vec![],
                    suffix_padding: suffix_pad,
                    prefix_padding: vec![],
                })
                .await
            {
                tracing::warn!(
                    session_id,
                    "outbound channel closed, CloseSessionResponse not sent: {}",
                    e
                );
            }
        }
    }

    /// Close all sessions.
    pub async fn close_all(&mut self) {
        let ids: Vec<u32> = self.sessions.keys().copied().collect();
        for id in ids {
            self.close_session(id).await;
        }
    }

    /// Non-blocking data dispatch for UDP.
    ///
    /// Uses `try_send` for data payloads to avoid blocking the UDP event loop
    /// (which would deadlock since outbound writes share the same loop).
    /// Control messages (open/close) still use blocking sends via `dispatch()`.
    /// With 4096-element channel buffers, drops are extremely rare.
    pub fn try_dispatch_data(&self, session_id: u32, payload: Vec<u8>) {
        if let Some(entry) = self.sessions.get(&session_id)
            && !payload.is_empty()
            && let Err(e) = entry.data_tx.try_send(payload)
        {
            tracing::warn!(session_id, "UDP session data dropped (channel full): {}", e);
        }
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// ---------------------------------------------------------------------------
// SessionStream
// ---------------------------------------------------------------------------

impl SessionStream {
    /// Receive data from the client (blocking async).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.data_rx.recv().await
    }

    /// Send data back to the client via the outbound channel.
    ///
    /// Panics if `payload.len() > u16::MAX` (protocol limit).
    pub async fn send(
        &mut self,
        payload: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<OutboundSegment>> {
        debug_assert!(
            payload.len() <= u16::MAX as usize,
            "payload {} exceeds protocol max {}",
            payload.len(),
            u16::MAX
        );

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let payload_len = payload.len().min(u16::MAX as usize);
        let (prefix_pad, suffix_pad) = padding::data_padding(payload_len);
        let meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataServerToClient,
            timestamp: current_timestamp_minutes(),
            session_id: self.session_id,
            sequence: seq,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: prefix_pad.len() as u8,
            payload_length: payload_len as u16,
            suffix_padding_length: suffix_pad.len() as u8,
        });

        self.outbound_tx
            .send(OutboundSegment {
                metadata: meta,
                payload,
                prefix_padding: prefix_pad,
                suffix_padding: suffix_pad,
            })
            .await
    }

    /// Session ID.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Check if the session has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Get a clone of the cancellation token.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

// ---------------------------------------------------------------------------
// AsyncRead / AsyncWrite for SessionStream
// ---------------------------------------------------------------------------

impl tokio::io::AsyncRead for SessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain any buffered data first.
        if self.read_offset < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_offset += n;
            if self.read_offset >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Try to receive new data.
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data;
                    self.read_offset = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed = EOF.
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for SessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Reserve capacity first — properly registers waker for backpressure.
        match self.poll_sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "outbound channel closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        // Cap at u16::MAX so payload_length metadata field is not truncated.
        let effective_len = buf.len().min(u16::MAX as usize);
        let payload = buf[..effective_len].to_vec();
        let payload_len = payload.len();

        let (prefix_pad, suffix_pad) = padding::data_padding(payload_len);
        let meta = Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataServerToClient,
            timestamp: current_timestamp_minutes(),
            session_id: self.session_id,
            sequence: seq,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: prefix_pad.len() as u8,
            payload_length: payload_len as u16,
            suffix_padding_length: suffix_pad.len() as u8,
        });

        let segment = OutboundSegment {
            metadata: meta,
            payload,
            prefix_padding: prefix_pad,
            suffix_padding: suffix_pad,
        };

        match self.poll_sender.send_item(segment) {
            Ok(()) => Poll::Ready(Ok(payload_len)),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outbound channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.cancel.cancel();
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::metadata::{DataMetadata, ProtocolType, SessionMetadata};

    fn open_session_meta(session_id: u32) -> Metadata {
        Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: 28_000_000,
            session_id,
            sequence: 0,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        })
    }

    fn data_meta(session_id: u32, payload_len: u16) -> Metadata {
        Metadata::Data(DataMetadata {
            protocol_type: ProtocolType::DataClientToServer,
            timestamp: 28_000_000,
            session_id,
            sequence: 1,
            unack_seq: 0,
            window_size: 256,
            fragment_number: 0,
            prefix_padding_length: 0,
            payload_length: payload_len,
            suffix_padding_length: 0,
        })
    }

    fn close_session_meta(session_id: u32) -> Metadata {
        Metadata::Session(SessionMetadata {
            protocol_type: ProtocolType::CloseSessionRequest,
            timestamp: 28_000_000,
            session_id,
            sequence: 1,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        })
    }

    #[tokio::test]
    async fn test_session_manager_open_session() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        let meta = open_session_meta(1);
        let stream = mgr.dispatch(&meta, vec![]).await;
        assert!(stream.is_some(), "open session should return a stream");
        assert_eq!(mgr.session_count(), 1);

        // Should have sent an OpenSessionResponse.
        let seg = outbound_rx.try_recv().expect("expected outbound response");
        assert_eq!(
            seg.metadata.protocol_type(),
            ProtocolType::OpenSessionResponse
        );
        assert_eq!(seg.metadata.session_id(), 1);
    }

    #[tokio::test]
    async fn test_session_manager_dispatch_data() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        // Open session.
        let meta = open_session_meta(42);
        let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
        let _ = outbound_rx.try_recv(); // consume open response

        // Dispatch data to the session.
        let payload = b"hello session data".to_vec();
        let data = data_meta(42, payload.len() as u16);
        let result = mgr.dispatch(&data, payload.clone()).await;
        assert!(result.is_none(), "data dispatch should not return stream");

        // The stream should receive the data.
        let received = stream.recv().await;
        assert!(received.is_some());
        assert_eq!(received.unwrap(), payload);
    }

    #[tokio::test]
    async fn test_session_manager_close_session() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        // Open session.
        let meta = open_session_meta(10);
        let stream = mgr.dispatch(&meta, vec![]).await;
        assert!(stream.is_some());
        let _ = outbound_rx.try_recv(); // consume open response
        assert_eq!(mgr.session_count(), 1);

        // Close session.
        let close = close_session_meta(10);
        mgr.dispatch(&close, vec![]).await;
        assert_eq!(mgr.session_count(), 0);

        // Should have sent a CloseSessionResponse.
        let seg = outbound_rx.try_recv().expect("expected close response");
        assert_eq!(
            seg.metadata.protocol_type(),
            ProtocolType::CloseSessionResponse
        );
    }

    #[tokio::test]
    async fn test_session_manager_close_all() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        // Open 3 sessions.
        for id in 1..=3u32 {
            let meta = open_session_meta(id);
            let _ = mgr.dispatch(&meta, vec![]).await;
            let _ = outbound_rx.try_recv();
        }
        assert_eq!(mgr.session_count(), 3);

        // Close all.
        mgr.close_all().await;
        assert_eq!(mgr.session_count(), 0);
    }

    #[tokio::test]
    async fn test_outbound_data_segments_have_padding() {
        // Go always sends padding on data segments: prefix + suffix.
        // Server outbound DataServerToClient segments should have non-zero
        // padding lengths to match Go's behavior for traffic obfuscation.
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        let meta = open_session_meta(88);
        let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
        let _ = outbound_rx.try_recv(); // consume open response

        let payload = b"test payload for padding check".to_vec();
        stream
            .send(payload.clone())
            .await
            .expect("send should succeed");

        let seg = outbound_rx.try_recv().expect("expected data segment");
        match &seg.metadata {
            Metadata::Data(d) => {
                // At least one of prefix or suffix padding should be non-zero.
                assert!(
                    d.prefix_padding_length > 0 || d.suffix_padding_length > 0,
                    "server should send padding on data segments (prefix={}, suffix={})",
                    d.prefix_padding_length,
                    d.suffix_padding_length
                );
            }
            _ => panic!("expected Data metadata"),
        }
    }

    #[tokio::test]
    async fn test_outbound_session_segments_have_padding() {
        // Go always sends suffix padding on session control segments.
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        let meta = open_session_meta(89);
        let _stream = mgr.dispatch(&meta, vec![]).await;

        let seg = outbound_rx.try_recv().expect("expected open response");
        match &seg.metadata {
            Metadata::Session(s) => {
                assert!(
                    s.suffix_padding_length > 0,
                    "server should send suffix padding on session segments (suffix={})",
                    s.suffix_padding_length
                );
            }
            _ => panic!("expected Session metadata"),
        }
    }

    #[tokio::test]
    async fn test_session_stream_send() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        let meta = open_session_meta(55);
        let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
        let _ = outbound_rx.try_recv(); // consume open response

        // Send data from session back to client.
        let payload = b"response from server".to_vec();
        stream
            .send(payload.clone())
            .await
            .expect("send should succeed");

        let seg = outbound_rx.try_recv().expect("expected data segment");
        assert_eq!(
            seg.metadata.protocol_type(),
            ProtocolType::DataServerToClient
        );
        assert_eq!(seg.metadata.session_id(), 55);
        assert_eq!(seg.payload, payload);
    }

    #[tokio::test]
    async fn test_session_open_with_payload() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        let meta = open_session_meta(7);
        let initial_payload = b"piggybacked data".to_vec();
        let mut stream = mgr.dispatch(&meta, initial_payload.clone()).await.unwrap();
        let _ = outbound_rx.try_recv(); // consume open response

        // The initial payload should be available via recv.
        let received = stream.recv().await;
        assert!(received.is_some());
        assert_eq!(received.unwrap(), initial_payload);
    }

    #[tokio::test]
    async fn test_session_manager_reject_duplicate() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        let meta = open_session_meta(1);
        let first = mgr.dispatch(&meta, vec![]).await;
        assert!(first.is_some());
        let _ = outbound_rx.try_recv();

        // Duplicate open should be rejected.
        let meta2 = open_session_meta(1);
        let second = mgr.dispatch(&meta2, vec![]).await;
        assert!(second.is_none(), "duplicate session should be rejected");
        assert_eq!(mgr.session_count(), 1);
    }

    #[tokio::test]
    async fn test_session_manager_reject_zero_id() {
        let (mut mgr, _outbound_rx) = SessionManager::new();

        let meta = open_session_meta(0);
        let result = mgr.dispatch(&meta, vec![]).await;
        assert!(result.is_none(), "session ID 0 should be rejected");
        assert_eq!(mgr.session_count(), 0);
    }

    // ---- Stream interruption / data loss tests (RED) ----

    /// Verify that data is NOT lost when the session's data channel
    /// is under backpressure (slow consumer).
    ///
    /// With async dispatch, the sender blocks until the channel has space,
    /// so a concurrent consumer must drain to allow the producer to proceed.
    #[tokio::test]
    async fn test_dispatch_data_not_lost_under_backpressure() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        // Open a session — channel capacity is 4096.
        let meta = open_session_meta(99);
        let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
        let _ = outbound_rx.try_recv(); // consume open response

        let total_messages = 5000u32; // > 4096 channel capacity

        // Spawn a concurrent consumer that slowly drains the data channel.
        let consumer = tokio::spawn(async move {
            let mut received = 0u32;
            while let Some(_data) = stream.recv().await {
                received += 1;
                if received >= total_messages {
                    break;
                }
            }
            received
        });

        // Producer: dispatch all messages (will block when channel is full,
        // resume when consumer drains).
        for i in 0..total_messages {
            let payload = format!("msg-{i}").into_bytes();
            let data = data_meta(99, payload.len() as u16);
            mgr.dispatch(&data, payload).await;
        }

        // Close the session to signal EOF to the consumer.
        mgr.close_session(99).await;

        let received = consumer.await.unwrap();
        assert_eq!(
            received,
            total_messages,
            "expected {total_messages} messages but only received {received} — \
             {} messages were lost",
            total_messages - received
        );
    }

    /// Verify that OpenSessionResponse control messages are never
    /// dropped when the outbound channel is saturated with data segments.
    ///
    /// With async dispatch, the send blocks until the channel has space.
    /// A concurrent drainer ensures it eventually makes room.
    #[tokio::test]
    async fn test_control_messages_not_dropped_under_data_pressure() {
        let (mut mgr, mut outbound_rx) = SessionManager::new();

        // Open some sessions and fill the outbound channel (capacity 2048)
        // with data segments via the streams' outbound_tx.
        let mut streams = Vec::new();
        for id in 1..=20u32 {
            let meta = open_session_meta(id);
            if let Some(s) = mgr.dispatch(&meta, vec![]).await {
                streams.push(s);
            }
        }
        // Drain the open responses
        while outbound_rx.try_recv().is_ok() {}

        // Fill the outbound channel with data segments
        let mut filled = 0;
        'outer: for s in &streams {
            for _ in 0..200 {
                let seg = OutboundSegment {
                    metadata: Metadata::Data(DataMetadata {
                        protocol_type: ProtocolType::DataServerToClient,
                        timestamp: crate::core::metadata::current_timestamp_minutes(),
                        session_id: s.session_id(),
                        sequence: 0,
                        unack_seq: 0,
                        window_size: 256,
                        fragment_number: 0,
                        prefix_padding_length: 0,
                        payload_length: 100,
                        suffix_padding_length: 0,
                    }),
                    payload: vec![0xAA; 100],
                    prefix_padding: vec![],
                    suffix_padding: vec![],
                };
                if s.outbound_tx.try_send(seg).is_err() {
                    break 'outer;
                }
                filled += 1;
            }
        }
        assert!(
            filled > 1000,
            "should have filled most of the outbound channel, filled {filled}"
        );

        // Spawn a drainer so the blocking send can eventually complete.
        let drainer = tokio::spawn(async move {
            let mut found = false;
            while let Some(seg) = outbound_rx.recv().await {
                if seg.metadata.session_id() == 999
                    && seg.metadata.protocol_type() == ProtocolType::OpenSessionResponse
                {
                    found = true;
                    break;
                }
            }
            found
        });

        // Now open a NEW session — its OpenSessionResponse MUST be delivered.
        let new_meta = open_session_meta(999);
        let _new_stream = mgr.dispatch(&new_meta, vec![]).await;

        let found = drainer.await.unwrap();
        assert!(
            found,
            "OpenSessionResponse for session 999 was DROPPED — \
             control messages must never be lost even when outbound channel is full"
        );
    }

    // ---- Bug verification tests ----

    #[tokio::test]
    async fn test_open_session_responses_not_dropped() {
        // Opening more sessions than the outbound channel capacity must not
        // silently drop OpenSessionResponse control messages.
        let (mut mgr, mut outbound_rx) = SessionManager::new();
        let n = 300u32;
        for id in 1..=n {
            let meta = open_session_meta(id);
            let _ = mgr.dispatch(&meta, vec![]).await;
        }
        let mut count = 0;
        while outbound_rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(
            count, n as usize,
            "all OpenSessionResponses must be delivered"
        );
    }

    #[tokio::test]
    async fn test_poll_write_large_payload_metadata_consistency() {
        // Writing more than u16::MAX bytes through poll_write must not
        // produce metadata with a truncated payload_length.
        use tokio::io::AsyncWriteExt;

        let (mut mgr, mut outbound_rx) = SessionManager::new();
        let meta = open_session_meta(1);
        let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
        let _ = outbound_rx.try_recv(); // consume open response

        let large_buf = vec![0xAB; 70_000]; // > u16::MAX (65535)
        let written = stream.write(&large_buf).await.unwrap();

        let seg = outbound_rx.try_recv().expect("expected data segment");
        if let Metadata::Data(d) = &seg.metadata {
            assert_eq!(
                d.payload_length as usize,
                seg.payload.len(),
                "metadata payload_length ({}) must match actual payload len ({})",
                d.payload_length,
                seg.payload.len()
            );
            assert_eq!(
                written,
                seg.payload.len(),
                "written bytes must match payload"
            );
        } else {
            panic!("expected Data metadata");
        }
    }
}

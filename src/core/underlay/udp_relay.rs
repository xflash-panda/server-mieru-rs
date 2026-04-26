//! UDP relay event loop with reliable transport (recv/send buffers,
//! RTT estimation, CUBIC congestion control).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::acl::{self, OutboundType};
use crate::business::{self, StatsCollector, UserId};
use crate::connection::{ConnectionGuard, ConnectionManager};
use crate::core::crypto::KEY_LEN;
use crate::core::metadata::{DataMetadata, Metadata, ProtocolType, current_timestamp_minutes};
use crate::core::padding;
use crate::core::session::{OutboundSegment, SessionManager, SessionStream};
use crate::core::underlay::congestion::CubicCongestion;
use crate::core::underlay::recv_buf::RecvBuf;
use crate::core::underlay::registry::UserRegistry;
use crate::core::underlay::rtt::RttEstimator;
use crate::core::underlay::send_buf::SendBuf;
use crate::core::underlay::udp::{authenticate_packet, encode_response_packet_with_padding};
use crate::outbound;

const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
const OUTPUT_INTERVAL: Duration = Duration::from_millis(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECV_BUF_CAPACITY: usize = 1024;
const UDP_BUF_SIZE: usize = 1500;

// ---------------------------------------------------------------------------
// PeerSession
// ---------------------------------------------------------------------------

struct PeerSession {
    addr: SocketAddr,
    key: [u8; KEY_LEN],
    user_id: UserId,
    last_rx: Instant,
    recv_buf: RecvBuf,
    send_buf: SendBuf,
    rtt: RttEstimator,
    congestion: CubicCongestion,
    ack_needed: bool,
    /// Held for the session's lifetime; dropped on cleanup → removes from ConnectionManager.
    _conn_guard: Option<ConnectionGuard>,
}

// ---------------------------------------------------------------------------
// UdpRelay
// ---------------------------------------------------------------------------

pub struct UdpRelay {
    socket: Arc<UdpSocket>,
    sessions: HashMap<u32, PeerSession>,
    session_manager: SessionManager,
    outbound_rx: mpsc::Receiver<OutboundSegment>,
}

impl UdpRelay {
    /// Create a new UDP relay bound to the given socket.
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        let (session_manager, outbound_rx) = SessionManager::new();
        Self {
            socket,
            sessions: HashMap::new(),
            session_manager,
            outbound_rx,
        }
    }

    /// Main event loop. Runs until cancelled.
    pub async fn run(
        mut self,
        registry: Arc<UserRegistry>,
        stats: Arc<dyn StatsCollector>,
        router: Arc<dyn acl::OutboundRouter>,
        conn_mgr: ConnectionManager,
        cancel: CancellationToken,
        relay_idle_timeout: Duration,
    ) {
        let mut buf = vec![0u8; UDP_BUF_SIZE];
        let mut output_tick = tokio::time::interval(OUTPUT_INTERVAL);
        let mut cleanup_tick = tokio::time::interval(CLEANUP_INTERVAL);
        output_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            self.handle_incoming(
                                &buf[..len],
                                peer_addr,
                                &registry,
                                &stats,
                                &router,
                                &conn_mgr,
                                relay_idle_timeout,
                            ).await;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "UDP recv_from error");
                        }
                    }
                }
                Some(seg) = self.outbound_rx.recv() => {
                    self.handle_outbound(seg, &*stats).await;
                }
                _ = output_tick.tick() => {
                    self.process_retransmissions().await;
                    self.send_acks().await;
                }
                _ = cleanup_tick.tick() => {
                    self.cleanup_idle_sessions();
                }
                _ = cancel.cancelled() => {
                    break;
                }
            }
        }

        self.session_manager.close_all();
    }

    async fn handle_incoming(
        &mut self,
        packet: &[u8],
        peer_addr: SocketAddr,
        registry: &UserRegistry,
        stats: &Arc<dyn StatsCollector>,
        router: &Arc<dyn acl::OutboundRouter>,
        conn_mgr: &ConnectionManager,
        relay_idle_timeout: Duration,
    ) {
        let (user_id, key, _nonce, metadata, payload) = match authenticate_packet(packet, registry)
        {
            Some(r) => r,
            None => return,
        };

        let session_id = metadata.session_id();
        let protocol = metadata.protocol_type();

        // Record upload bytes.
        let upload_bytes = payload.len() as u64;
        if upload_bytes > 0 {
            stats.record_upload(user_id, upload_bytes);
        }

        // Update or create PeerSession.
        let peer = self
            .sessions
            .entry(session_id)
            .or_insert_with(|| PeerSession {
                addr: peer_addr,
                key,
                user_id,
                last_rx: Instant::now(),
                recv_buf: RecvBuf::new(RECV_BUF_CAPACITY),
                send_buf: SendBuf::new(),
                rtt: RttEstimator::new(),
                congestion: CubicCongestion::new(),
                ack_needed: false,
                _conn_guard: None,
            });
        peer.last_rx = Instant::now();
        peer.addr = peer_addr;

        // Handle ACK from client (unack_seq in DataMetadata).
        if let Metadata::Data(ref dm) = metadata
            && dm.unack_seq > 0
        {
            let now = Instant::now();
            if let Some(rtt_sample) = peer.send_buf.ack(dm.unack_seq, now) {
                peer.rtt.update(rtt_sample);
                peer.congestion.on_ack(now);
            }
        }

        match protocol {
            ProtocolType::DataClientToServer => {
                if let Metadata::Data(ref dm) = metadata {
                    if peer.recv_buf.insert(dm.sequence, payload.clone()) {
                        peer.ack_needed = true;
                    }
                    let ready = peer.recv_buf.drain_ready();
                    for data in ready {
                        self.session_manager.dispatch(&metadata, data);
                    }
                }
            }
            ProtocolType::OpenSessionRequest => {
                let guard = conn_mgr.register(user_id);
                peer._conn_guard = Some(guard);
                stats.record_request(user_id);
                if let Some(stream) = self.session_manager.dispatch(&metadata, payload) {
                    tracing::debug!(
                        session_id = stream.session_id(),
                        user_id,
                        "New UDP session opened"
                    );
                    let router = Arc::clone(router);
                    let stats = Arc::clone(stats);
                    tokio::spawn(async move {
                        handle_session(stream, &*router, user_id, &*stats, relay_idle_timeout).await;
                    });
                }
            }
            ProtocolType::CloseSessionRequest | ProtocolType::CloseSessionResponse => {
                self.session_manager.dispatch(&metadata, payload);
                self.sessions.remove(&session_id);
            }
            ProtocolType::AckClientToServer => {
                // ACK already handled above via unack_seq.
            }
            _ => {
                tracing::debug!(?protocol, "Ignoring unexpected protocol type in UDP relay");
            }
        }
    }

    async fn handle_outbound(&mut self, seg: OutboundSegment, stats: &dyn StatsCollector) {
        let session_id = seg.metadata.session_id();
        let protocol = seg.metadata.protocol_type();

        match protocol {
            ProtocolType::DataServerToClient => {
                if let Some(peer) = self.sessions.get_mut(&session_id) {
                    let download_bytes = seg.payload.len() as u64;
                    if download_bytes > 0 {
                        stats.record_download(peer.user_id, download_bytes);
                    }

                    let now = Instant::now();
                    let inflight = peer.send_buf.inflight();
                    let seq = peer.send_buf.enqueue(seg.payload.clone(), now);

                    // Only send immediately if congestion window allows.
                    // Otherwise the data stays in send_buf and will be sent
                    // by process_retransmissions once the window opens.
                    if peer.congestion.can_send(inflight) {
                        let unack = peer.recv_buf.next_expected_seq();
                        let meta = Metadata::Data(DataMetadata {
                            protocol_type: ProtocolType::DataServerToClient,
                            timestamp: current_timestamp_minutes(),
                            session_id,
                            sequence: seq,
                            unack_seq: unack,
                            window_size: peer.congestion.window() as u16,
                            fragment_number: 0,
                            prefix_padding_length: seg.prefix_padding.len() as u8,
                            payload_length: seg.payload.len() as u16,
                            suffix_padding_length: seg.suffix_padding.len() as u8,
                        });

                        let packet = encode_response_packet_with_padding(
                            &peer.key,
                            &meta,
                            &seg.payload,
                            &seg.prefix_padding,
                            &seg.suffix_padding,
                        );

                        if let Err(e) = self.socket.send_to(&packet, peer.addr).await {
                            tracing::warn!(error = %e, session_id, "Failed to send UDP data");
                        }

                        peer.ack_needed = false; // piggybacked ACK
                    }
                }
            }
            _ => {
                // Session control: encode and send directly.
                if let Some(peer) = self.sessions.get(&session_id) {
                    let packet = encode_response_packet_with_padding(
                        &peer.key,
                        &seg.metadata,
                        &seg.payload,
                        &seg.prefix_padding,
                        &seg.suffix_padding,
                    );
                    if let Err(e) = self.socket.send_to(&packet, peer.addr).await {
                        tracing::warn!(error = %e, session_id, "Failed to send UDP control");
                    }
                }
            }
        }
    }

    async fn process_retransmissions(&mut self) {
        let socket = self.socket.clone();
        for (&session_id, peer) in self.sessions.iter_mut() {
            let rto = peer.rtt.rto();
            let now = Instant::now();
            let due = peer.send_buf.retransmit_due(rto, now);
            let has_retransmits = !due.is_empty();
            for seq in due {
                if let Some(payload) = peer.send_buf.get(seq) {
                    let payload = payload.to_vec();
                    let unack = peer.recv_buf.next_expected_seq();
                    let (prefix_pad, suffix_pad) = padding::data_padding(payload.len());
                    let meta = Metadata::Data(DataMetadata {
                        protocol_type: ProtocolType::DataServerToClient,
                        timestamp: current_timestamp_minutes(),
                        session_id,
                        sequence: seq,
                        unack_seq: unack,
                        window_size: peer.congestion.window() as u16,
                        fragment_number: 0,
                        prefix_padding_length: prefix_pad.len() as u8,
                        payload_length: payload.len() as u16,
                        suffix_padding_length: suffix_pad.len() as u8,
                    });

                    let packet = encode_response_packet_with_padding(
                        &peer.key,
                        &meta,
                        &payload,
                        &prefix_pad,
                        &suffix_pad,
                    );

                    if let Err(e) = socket.send_to(&packet, peer.addr).await {
                        tracing::warn!(error = %e, session_id, seq, "Failed to retransmit");
                    }

                    peer.send_buf.mark_retransmitted(seq, now);
                }
            }
            if has_retransmits {
                peer.rtt.on_timeout();
                peer.congestion.on_loss();
            }
        }
    }

    async fn send_acks(&mut self) {
        let socket = self.socket.clone();
        for (&session_id, peer) in self.sessions.iter_mut() {
            if !peer.ack_needed {
                continue;
            }
            let unack = peer.recv_buf.next_expected_seq();
            let suffix_pad = padding::session_padding(0);
            let meta = Metadata::Data(DataMetadata {
                protocol_type: ProtocolType::AckServerToClient,
                timestamp: current_timestamp_minutes(),
                session_id,
                sequence: 0,
                unack_seq: unack,
                window_size: peer.congestion.window() as u16,
                fragment_number: 0,
                prefix_padding_length: 0,
                payload_length: 0,
                suffix_padding_length: suffix_pad.len() as u8,
            });

            let packet =
                encode_response_packet_with_padding(&peer.key, &meta, &[], &[], &suffix_pad);

            if let Err(e) = socket.send_to(&packet, peer.addr).await {
                tracing::warn!(error = %e, session_id, "Failed to send ACK");
            }

            peer.ack_needed = false;
        }
    }

    fn cleanup_idle_sessions(&mut self) {
        let now = Instant::now();
        let stale: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, peer)| now.duration_since(peer.last_rx) > IDLE_SESSION_TIMEOUT)
            .map(|(&id, _)| id)
            .collect();

        for id in stale {
            tracing::debug!(session_id = id, "Removing idle UDP session");
            self.sessions.remove(&id);
            self.session_manager.close_session(id);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared handle_session function
// ---------------------------------------------------------------------------

/// Handle a proxied session: read the SOCKS5 target address from the first
/// data chunk, route via ACL, and relay traffic bidirectionally.
///
/// Shared between TCP and UDP underlay handlers.
pub async fn handle_session(
    mut session: SessionStream,
    router: &dyn acl::OutboundRouter,
    user_id: business::UserId,
    _stats: &dyn StatsCollector,
    relay_idle_timeout: Duration,
) {
    use tokio::io::AsyncWriteExt;

    let first_data = match session.recv().await {
        Some(data) => data,
        None => return,
    };

    let (target, consumed) = match outbound::parse_socks_address(&first_data) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "Failed to parse target address");
            return;
        }
    };

    tracing::debug!(target = %target, user_id, "Session opened");

    let route = router.route(&target).await;
    match route {
        OutboundType::Direct { resolved } => {
            match outbound::connect_target(&target, resolved, CONNECT_TIMEOUT).await {
                Ok(mut remote) => {
                    let remaining = &first_data[consumed..];
                    if !remaining.is_empty()
                        && let Err(e) = remote.write_all(remaining).await
                    {
                        tracing::debug!(error = %e, "Failed to send initial data");
                        return;
                    }
                    crate::relay::relay_with_idle_timeout(
                        session,
                        remote,
                        relay_idle_timeout,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::debug!(target = %target, error = %e, "Failed to connect");
                }
            }
        }
        OutboundType::Reject => {
            tracing::debug!(target = %target, "Connection rejected by ACL");
        }
        _ => {
            tracing::debug!(target = %target, "Proxy outbound");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(addr: SocketAddr) -> PeerSession {
        PeerSession {
            addr,
            key: [0u8; KEY_LEN],
            user_id: 1,
            last_rx: Instant::now(),
            recv_buf: RecvBuf::new(RECV_BUF_CAPACITY),
            send_buf: SendBuf::new(),
            rtt: RttEstimator::new(),
            congestion: CubicCongestion::new(),
            ack_needed: false,
            _conn_guard: None,
        }
    }

    #[tokio::test]
    async fn test_idle_session_cleanup() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(socket);
        let mut relay = UdpRelay::new(socket);

        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut stale = make_peer(addr);
        stale.last_rx = Instant::now() - Duration::from_secs(120);
        relay.sessions.insert(100, stale);

        let fresh = make_peer(addr);
        relay.sessions.insert(200, fresh);

        relay.cleanup_idle_sessions();

        assert!(!relay.sessions.contains_key(&100));
        assert!(relay.sessions.contains_key(&200));
    }

    #[test]
    fn test_peer_session_default_state() {
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let peer = make_peer(addr);
        assert_eq!(peer.recv_buf.buffered_count(), 0);
        assert_eq!(peer.send_buf.inflight(), 0);
        assert_eq!(peer.rtt.rto(), Duration::from_secs(1));
        assert_eq!(peer.congestion.window(), 10);
        assert!(!peer.ack_needed);
    }
}

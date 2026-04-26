use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

// ── TCP ──────────────────────────────────────────────────────────────────────

/// Bind a TCP listener on the given port with IPv4+IPv6 dual-stack support.
///
/// Creates an IPv6 socket with `IPV6_V6ONLY` disabled so it accepts both
/// IPv4 (mapped) and IPv6 connections. Falls back to IPv4-only (`0.0.0.0`)
/// if the dual-stack bind fails.
pub fn bind_tcp_dual_stack(port: u16) -> Result<TcpListener> {
    match try_bind_tcp_dual_stack(port) {
        Ok(listener) => Ok(listener),
        Err(e) => {
            tracing::warn!(error = %e, "TCP dual-stack bind failed, falling back to IPv4-only");
            bind_tcp_socket(Domain::IPV4, ([0, 0, 0, 0], port).into())
        }
    }
}

fn try_bind_tcp_dual_stack(port: u16) -> Result<TcpListener> {
    let socket = new_tcp_socket(Domain::IPV6)?;
    socket.set_only_v6(false)?;

    let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 0u16], port).into();
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn bind_tcp_socket(domain: Domain, addr: SocketAddr) -> Result<TcpListener> {
    let socket = new_tcp_socket(domain)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn new_tcp_socket(domain: Domain) -> Result<Socket> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Enable TCP keepalive on a connection.
/// TCP_KEEPIDLE=30s (when to start probes), TCP_KEEPINTVL=10s (probe interval).
/// Without this, dead connections (peer crashed/disconnected) hang until the
/// relay idle timeout fires. With keepalive, detection takes ~120s (30 + 10*9).
pub fn set_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_keepalive(true);
    let _ = sock.set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(30))
            .with_interval(std::time::Duration::from_secs(10)),
    );
}

// ── UDP ──────────────────────────────────────────────────────────────────────

/// Bind a UDP socket on the given port with IPv4+IPv6 dual-stack support.
///
/// Creates an IPv6 socket with `IPV6_V6ONLY` disabled so it receives both
/// IPv4 (mapped) and IPv6 datagrams. Falls back to IPv4-only (`0.0.0.0`)
/// if the dual-stack bind fails.
pub fn bind_udp_dual_stack(port: u16) -> Result<UdpSocket> {
    match try_bind_udp_dual_stack(port) {
        Ok(socket) => Ok(socket),
        Err(e) => {
            tracing::warn!(error = %e, "UDP dual-stack bind failed, falling back to IPv4-only");
            bind_udp_socket(Domain::IPV4, ([0, 0, 0, 0], port).into())
        }
    }
}

fn try_bind_udp_dual_stack(port: u16) -> Result<UdpSocket> {
    let socket = new_udp_socket(Domain::IPV6)?;
    socket.set_only_v6(false)?;

    let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 0u16], port).into();
    socket.bind(&SockAddr::from(addr))?;

    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_socket)?)
}

fn bind_udp_socket(domain: Domain, addr: SocketAddr) -> Result<UdpSocket> {
    let socket = new_udp_socket(domain)?;
    socket.bind(&SockAddr::from(addr))?;

    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_socket)?)
}

fn new_udp_socket(domain: Domain) -> Result<Socket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    Ok(socket)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_tcp_dual_stack_accepts_ipv4() {
        let listener = bind_tcp_dual_stack(0).expect("bind failed");
        let port = listener.local_addr().unwrap().port();

        let connect = TcpStream::connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        let accept = listener.accept();

        let (connect_result, accept_result) = tokio::join!(connect, accept);
        let mut client = connect_result.expect("IPv4 connect failed");
        let (_, peer_addr) = accept_result.expect("IPv4 accept failed");

        match peer_addr {
            SocketAddr::V4(v4) => assert!(v4.ip().is_loopback()),
            SocketAddr::V6(v6) => {
                let ip = v6.ip();
                assert!(
                    ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
                    "unexpected peer addr: {peer_addr}"
                );
            }
        }
        client.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_tcp_dual_stack_accepts_ipv6() {
        let listener = bind_tcp_dual_stack(0).expect("bind failed");
        let port = listener.local_addr().unwrap().port();

        let connect = TcpStream::connect(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port));
        let accept = listener.accept();

        let (connect_result, accept_result) = tokio::join!(connect, accept);
        let mut client = connect_result.expect("IPv6 connect failed");
        let (_, peer_addr) = accept_result.expect("IPv6 accept failed");

        assert!(
            peer_addr.ip().is_loopback(),
            "expected loopback, got: {peer_addr}"
        );
        client.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_tcp_dual_stack_local_addr_is_ipv6() {
        let listener = bind_tcp_dual_stack(0).expect("bind failed");
        let local_addr = listener.local_addr().unwrap();
        assert!(
            local_addr.is_ipv6(),
            "expected IPv6 local addr for dual-stack, got: {local_addr}"
        );
    }

    #[tokio::test]
    async fn test_udp_dual_stack_send_recv() {
        let server = bind_udp_dual_stack(0).expect("UDP bind failed");
        let server_port = server.local_addr().unwrap().port();

        // Client connects from IPv4 loopback
        let client_std = std::net::UdpSocket::bind("0.0.0.0:0").expect("client bind failed");
        client_std.set_nonblocking(true).unwrap();
        let client = UdpSocket::from_std(client_std).unwrap();

        let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), server_port);
        let msg = b"hello mieru";

        client.send_to(msg, server_addr).await.expect("send failed");

        let mut buf = vec![0u8; 64];
        let (len, _src) = server.recv_from(&mut buf).await.expect("recv failed");

        assert_eq!(&buf[..len], msg);
    }

    #[tokio::test]
    async fn test_tcp_keepalive_enabled() {
        let listener = bind_tcp_dual_stack(0).expect("bind failed");
        let port = listener.local_addr().unwrap().port();

        let connect = TcpStream::connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        let accept = listener.accept();
        let (_, accept_result) = tokio::join!(connect, accept);
        let (accepted, _) = accept_result.expect("accept failed");

        set_tcp_keepalive(&accepted);

        let sock = socket2::SockRef::from(&accepted);
        assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE should be enabled");
    }

    #[tokio::test]
    async fn test_tcp_keepalive_interval() {
        let listener = bind_tcp_dual_stack(0).expect("bind failed");
        let port = listener.local_addr().unwrap().port();

        let connect = TcpStream::connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        let accept = listener.accept();
        let (_, accept_result) = tokio::join!(connect, accept);
        let (accepted, _) = accept_result.expect("accept failed");

        set_tcp_keepalive(&accepted);

        let sock = socket2::SockRef::from(&accepted);
        let interval = sock
            .tcp_keepalive_interval()
            .expect("keepalive_interval should be readable");
        assert!(
            interval <= std::time::Duration::from_secs(30),
            "TCP keepalive interval should be <= 30s, got {:?}",
            interval
        );
    }
}

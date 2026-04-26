use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::acl::Address;
use crate::error::{Error, Result};

/// SOCKS5 command types.
pub const SOCKS5_CONNECT: u8 = 0x01;
pub const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;

/// Build a SOCKS5 response: `[version=0x05, reply, reserved=0x00, addr_type=0x01, 0.0.0.0:0]`.
///
/// Uses a minimal IPv4 0.0.0.0:0 bind address (the client ignores it for CONNECT).
pub fn socks5_response(reply: u8) -> [u8; 10] {
    [
        0x05, reply, 0x00, // version, reply, reserved
        0x01, 0, 0, 0, 0, // IPv4 0.0.0.0
        0, 0, // port 0
    ]
}

/// Parse a full SOCKS5 request from the given byte slice.
///
/// Format: `[version=0x05, command, reserved=0x00, addr_type, addr..., port]`
/// Returns `(command, Address, bytes_consumed)` on success.
pub fn parse_socks5_request(data: &[u8]) -> Result<(u8, Address, usize)> {
    if data.len() < 4 {
        return Err(Error::InvalidSegment("socks5 request too short".into()));
    }
    if data[0] != 0x05 {
        return Err(Error::InvalidSegment(format!(
            "invalid socks5 version: 0x{:02x}",
            data[0]
        )));
    }
    let command = data[1];
    // data[2] is reserved
    let (addr, addr_consumed) = parse_socks_address(&data[3..])?;
    Ok((command, addr, 3 + addr_consumed))
}

/// Parse a SOCKS5-style address from the given byte slice.
/// Returns `(Address, bytes_consumed)` on success.
pub fn parse_socks_address(data: &[u8]) -> Result<(Address, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidSegment("address type byte missing".into()));
    }
    match data[0] {
        0x01 => {
            // IPv4: type(1) + ip(4) + port(2) = 7 bytes
            if data.len() < 7 {
                return Err(Error::InvalidSegment("truncated IPv4 address".into()));
            }
            let ip: [u8; 4] = data[1..5].try_into().unwrap();
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((Address::IPv4(ip, port), 7))
        }
        0x03 => {
            // Domain: type(1) + len(1) + name(N) + port(2)
            if data.len() < 2 {
                return Err(Error::InvalidSegment("truncated domain length".into()));
            }
            let name_len = data[1] as usize;
            let total = 1 + 1 + name_len + 2;
            if data.len() < total {
                return Err(Error::InvalidSegment("truncated domain address".into()));
            }
            let domain = std::str::from_utf8(&data[2..2 + name_len])
                .map_err(|_| Error::InvalidSegment("domain is not valid UTF-8".into()))?
                .to_string();
            let port = u16::from_be_bytes([data[2 + name_len], data[2 + name_len + 1]]);
            Ok((Address::Domain(domain, port), total))
        }
        0x04 => {
            // IPv6: type(1) + ip(16) + port(2) = 19 bytes
            if data.len() < 19 {
                return Err(Error::InvalidSegment("truncated IPv6 address".into()));
            }
            let ip: [u8; 16] = data[1..17].try_into().unwrap();
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((Address::IPv6(ip, port), 19))
        }
        t => Err(Error::InvalidSegment(format!(
            "unknown address type: 0x{:02x}",
            t
        ))),
    }
}

/// Connect to `target`, optionally using pre-resolved addresses.
/// If `resolved` is provided and non-empty, those addresses are tried first.
/// Otherwise, connects directly from the `Address` variant.
/// Sets TCP_NODELAY on the resulting stream.
/// The entire attempt is wrapped in `timeout`.
pub async fn connect_target(
    target: &Address,
    resolved: Option<Arc<[SocketAddr]>>,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    tokio::time::timeout(timeout, connect_target_inner(target, resolved))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
}

async fn connect_target_inner(
    target: &Address,
    resolved: Option<Arc<[SocketAddr]>>,
) -> std::io::Result<TcpStream> {
    // Use pre-resolved addresses when available to avoid a redundant DNS lookup.
    if let Some(ref addrs) = resolved
        && !addrs.is_empty()
    {
        let port = target.port();
        let mut last_err = None;
        for addr in addrs.iter() {
            let mut addr = *addr;
            addr.set_port(port);
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    crate::net::set_tcp_keepalive(&stream);
                    return Ok(stream);
                }
                Err(e) => last_err = Some(e),
            }
        }
        return Err(last_err.unwrap_or_else(|| std::io::Error::other("no resolved addresses")));
    }

    // Connect directly from the address variant.
    let stream = match target {
        Address::IPv4(ip, port) => {
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(*ip), *port));
            TcpStream::connect(addr).await?
        }
        Address::IPv6(ip, port) => {
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(*ip), *port, 0, 0));
            TcpStream::connect(addr).await?
        }
        Address::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await?,
    };
    let _ = stream.set_nodelay(true);
    crate::net::set_tcp_keepalive(&stream);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks_addr_ipv4() {
        let data = &[0x01, 127, 0, 0, 1, 0x00, 0x50];
        let (addr, consumed) = parse_socks_address(data).unwrap();
        assert!(matches!(addr, Address::IPv4([127, 0, 0, 1], 80)));
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_socks_addr_ipv6() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&[0x01, 0xBB]); // port 443
        let (addr, consumed) = parse_socks_address(&data).unwrap();
        assert!(matches!(addr, Address::IPv6(_, 443)));
        assert_eq!(consumed, 19);
    }

    #[test]
    fn test_parse_socks_addr_domain() {
        let mut data = vec![0x03];
        data.push(11); // length of "example.com"
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 0x50]); // port 80
        let (addr, consumed) = parse_socks_address(&data).unwrap();
        if let Address::Domain(domain, port) = addr {
            assert_eq!(domain, "example.com");
            assert_eq!(port, 80);
        } else {
            panic!("expected Domain address");
        }
        assert_eq!(consumed, 15);
    }

    #[test]
    fn test_parse_socks_addr_invalid_type() {
        let data = &[0xFF, 0, 0, 0, 0, 0, 0];
        let result = parse_socks_address(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_socks_addr_truncated_ipv4() {
        // Only 5 bytes instead of 7
        let data = &[0x01, 127, 0, 0, 1];
        let result = parse_socks_address(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_socks_addr_truncated_ipv6() {
        // Only 10 bytes instead of 19
        let mut data = vec![0x04];
        data.extend_from_slice(&[0u8; 9]);
        let result = parse_socks_address(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_socks_addr_truncated_domain() {
        // Claims domain length 20 but only provides 5 bytes of name
        let mut data = vec![0x03, 20u8];
        data.extend_from_slice(b"short");
        let result = parse_socks_address(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_socks_addr_empty() {
        let result = parse_socks_address(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_socks5_request_connect_ipv4() {
        // version=5, command=CONNECT(1), reserved=0, then IPv4 addr
        let data = &[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        let (cmd, addr, consumed) = parse_socks5_request(data).unwrap();
        assert_eq!(cmd, SOCKS5_CONNECT);
        assert!(matches!(addr, Address::IPv4([127, 0, 0, 1], 80)));
        assert_eq!(consumed, 10); // 3 header + 7 addr
    }

    #[test]
    fn test_parse_socks5_request_connect_domain() {
        // version=5, command=CONNECT(1), reserved=0, then FQDN
        let mut data = vec![0x05, 0x01, 0x00, 0x03, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x01, 0xBB]); // port 443
        let (cmd, addr, consumed) = parse_socks5_request(&data).unwrap();
        assert_eq!(cmd, SOCKS5_CONNECT);
        if let Address::Domain(domain, port) = addr {
            assert_eq!(domain, "example.com");
            assert_eq!(port, 443);
        } else {
            panic!("expected Domain address");
        }
        assert_eq!(consumed, 3 + 15);
    }

    #[test]
    fn test_parse_socks5_request_invalid_version() {
        let data = &[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        assert!(parse_socks5_request(data).is_err());
    }

    #[test]
    fn test_parse_socks5_request_too_short() {
        assert!(parse_socks5_request(&[0x05, 0x01]).is_err());
    }

    #[test]
    fn test_parse_socks5_request_udp_associate() {
        // version=5, command=UDP_ASSOCIATE(3), reserved=0, then IPv4
        let data = &[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00];
        let (cmd, addr, consumed) = parse_socks5_request(data).unwrap();
        assert_eq!(cmd, SOCKS5_UDP_ASSOCIATE);
        assert!(matches!(addr, Address::IPv4([0, 0, 0, 0], 0)));
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_socks5_response_matches_go_format() {
        // Go mieru Response.WriteToSocks5() writes:
        // [version=5, reply, reserved=0, addr_type=1, 0.0.0.0:0]
        let resp = socks5_response(0x00);
        assert_eq!(resp, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        // Error reply
        let resp_err = socks5_response(0x05); // connection refused
        assert_eq!(resp_err, [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_parse_socks5_request_and_response_roundtrip() {
        // Simulate what a Go mieru client sends and what our server parses
        // Client sends: CONNECT to example.com:443
        let mut request = vec![0x05, 0x01, 0x00]; // version, CONNECT, reserved
        request.push(0x03); // domain
        request.push(11); // "example.com".len()
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());

        let (cmd, addr, consumed) = parse_socks5_request(&request).unwrap();
        assert_eq!(cmd, SOCKS5_CONNECT);
        assert_eq!(consumed, request.len());
        if let Address::Domain(domain, port) = addr {
            assert_eq!(domain, "example.com");
            assert_eq!(port, 443);
        } else {
            panic!("expected Domain address");
        }

        // Server responds with success
        let response = socks5_response(0x00);
        assert_eq!(response[0], 0x05); // version
        assert_eq!(response[1], 0x00); // success
    }

    #[test]
    fn test_socks5_response_success() {
        let resp = socks5_response(0x00);
        assert_eq!(resp[0], 0x05); // version
        assert_eq!(resp[1], 0x00); // success
        assert_eq!(resp[2], 0x00); // reserved
        assert_eq!(resp[3], 0x01); // IPv4
        assert_eq!(resp.len(), 10);
    }
}

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::acl::Address;
use crate::error::{Error, Result};

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
}

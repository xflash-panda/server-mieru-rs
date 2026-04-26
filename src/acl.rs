//! ACL (Access Control List) Engine integration
//!
//! Provides rule-based traffic routing with support for:
//! - Direct connections
//! - SOCKS5 proxy
//! - HTTP/HTTPS proxy
//! - Reject (block) connections
//!
//! Configuration format (YAML):
//! ```yaml
//! outbounds:
//!   - name: warp
//!     type: socks5
//!     socks5:
//!       addr: 127.0.0.1:40000
//!   - name: http-proxy
//!     type: http
//!     http:
//!       addr: 127.0.0.1:8080
//! acl:
//!   inline:
//!     - reject(all, udp/443)
//!     - warp(suffix:google.com)
//!     - direct(all)
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Re-export types from acl-engine-rs
pub use acl_engine_rs::{
    HostInfo, Protocol,
    geo::{AutoGeoLoader, GeoIpFormat, GeoSiteFormat, NilGeoLoader},
    outbound::{
        Addr, AsyncOutbound, AsyncTcpConn, AsyncUdpConn, Direct, DirectMode, DirectOptions, Http,
        Reject, Socks5,
    },
};

use crate::logger::log;

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Address {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) | Address::IPv6(_, port) | Address::Domain(_, port) => *port,
        }
    }

    pub fn host_string(&self) -> String {
        self.host_str().into_owned()
    }

    /// Returns the host as a borrowed string when possible (Domain case),
    /// avoiding allocation. For IP addresses, returns the formatted string
    /// via Cow::Owned.
    pub fn host_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Address::IPv4(ip, _) => {
                std::borrow::Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
            }
            Address::IPv6(ip, _) => {
                std::borrow::Cow::Owned(std::net::Ipv6Addr::from(*ip).to_string())
            }
            Address::Domain(host, _) => std::borrow::Cow::Borrowed(host.as_str()),
        }
    }

    pub fn to_socket_string(&self) -> String {
        match self {
            Address::IPv4(ip, port) => {
                format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
            }
            Address::IPv6(ip, port) => {
                let segments: Vec<String> = ip
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                format!("[{}]:{}", segments.join(":"), port)
            }
            Address::Domain(host, port) => format!("{}:{}", host, port),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_socket_string())
    }
}

// ---------------------------------------------------------------------------
// OutboundType
// ---------------------------------------------------------------------------

pub enum OutboundType {
    /// Direct connection, optionally carrying pre-resolved socket addresses
    /// from DNS lookup in the router (avoids duplicate resolution in connect).
    Direct {
        resolved: Option<Arc<[SocketAddr]>>,
    },
    Reject,
    /// Proxy connection via ACL engine outbound handler (Socks5, Http, etc.)
    Proxy(Arc<dyn acl_engine_rs::outbound::AsyncOutbound>),
}

impl fmt::Debug for OutboundType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutboundType::Direct { .. } => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),
            OutboundType::Proxy(_) => write!(f, "Proxy"),
        }
    }
}

// ---------------------------------------------------------------------------
// OutboundRouter trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait OutboundRouter: Send + Sync {
    async fn route(&self, addr: &Address) -> OutboundType;
    async fn route_udp(&self, addr: &Address) -> OutboundType;
}

// ---------------------------------------------------------------------------
// DirectRouter
// ---------------------------------------------------------------------------

pub struct DirectRouter;

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, _addr: &Address) -> OutboundType {
        OutboundType::Direct { resolved: None }
    }

    async fn route_udp(&self, _addr: &Address) -> OutboundType {
        OutboundType::Direct { resolved: None }
    }
}

// ---------------------------------------------------------------------------
// ACL configuration types
// ---------------------------------------------------------------------------

/// ACL configuration loaded from YAML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// List of outbound configurations
    #[serde(default)]
    pub outbounds: Vec<OutboundEntry>,

    /// ACL rules configuration
    #[serde(default)]
    pub acl: AclRules,
}

/// ACL rules section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclRules {
    /// Inline rules (list of rule strings)
    #[serde(default)]
    pub inline: Vec<String>,
}

/// Outbound entry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEntry {
    /// Outbound name (used in rules)
    pub name: String,

    /// Outbound type: "direct", "socks5", "http", "reject"
    #[serde(rename = "type")]
    pub outbound_type: String,

    /// SOCKS5 configuration (when type = "socks5")
    #[serde(default)]
    pub socks5: Option<Socks5Config>,

    /// HTTP proxy configuration (when type = "http")
    #[serde(default)]
    pub http: Option<HttpConfig>,

    /// Direct configuration (when type = "direct")
    #[serde(default)]
    pub direct: Option<DirectConfig>,
}

/// SOCKS5 outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// SOCKS5 server address (host:port)
    pub addr: String,

    /// Optional username for authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Whether to allow UDP through this proxy (default: true)
    #[serde(default = "default_allow_udp")]
    pub allow_udp: bool,
}

fn default_allow_udp() -> bool {
    true
}

/// HTTP proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// HTTP proxy server address (host:port or full URL)
    pub addr: String,

    /// Optional username for basic authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for basic authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Use HTTPS for proxy connection
    #[serde(default)]
    pub https: bool,
}

/// Direct outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConfig {
    /// IP mode: "auto", "4", "6", "prefer4", "prefer6"
    #[serde(default = "default_ip_mode")]
    pub mode: String,

    /// Bind outgoing connections to a specific local IPv4 address
    #[serde(rename = "bindIPv4", default)]
    pub bind_ipv4: Option<String>,

    /// Bind outgoing connections to a specific local IPv6 address
    #[serde(rename = "bindIPv6", default)]
    pub bind_ipv6: Option<String>,

    /// Bind outgoing connections to a specific network device (Linux only, SO_BINDTODEVICE)
    /// Mutually exclusive with bindIPv4/bindIPv6
    #[serde(rename = "bindDevice", default)]
    pub bind_device: Option<String>,

    /// Enable TCP Fast Open for outgoing connections (Linux/macOS)
    #[serde(rename = "fastOpen", default)]
    pub fast_open: bool,

    /// Enable TCP_NODELAY (disable Nagle's algorithm). Default: true.
    #[serde(rename = "tcpNoDelay", default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,

    /// TCP keepalive interval in seconds. 0 = disable. Default: 60.
    #[serde(rename = "tcpKeepAlive", default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
}

fn default_ip_mode() -> String {
    "auto".to_string()
}

fn default_tcp_nodelay() -> bool {
    true
}

fn default_tcp_keepalive_secs() -> u64 {
    60
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            mode: default_ip_mode(),
            bind_ipv4: None,
            bind_ipv6: None,
            bind_device: None,
            fast_open: false,
            tcp_nodelay: default_tcp_nodelay(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// OutboundHandler
// ---------------------------------------------------------------------------

/// Outbound handler wrapper
#[derive(Clone)]
pub enum OutboundHandler {
    /// Direct connection
    Direct(Arc<Direct>),
    /// SOCKS5 proxy
    Socks5 { inner: Arc<Socks5>, allow_udp: bool },
    /// HTTP proxy
    Http(Arc<Http>),
    /// Reject connection
    Reject(Arc<Reject>),
}

impl std::fmt::Debug for OutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundHandler::Direct(_) => write!(f, "Direct"),
            OutboundHandler::Socks5 { allow_udp, .. } => write!(f, "Socks5(udp={})", allow_udp),
            OutboundHandler::Http(_) => write!(f, "Http"),
            OutboundHandler::Reject(_) => write!(f, "Reject"),
        }
    }
}

impl OutboundHandler {
    /// Create OutboundHandler from configuration entry
    pub fn from_entry(entry: &OutboundEntry) -> Result<Self> {
        match entry.outbound_type.as_str() {
            "direct" => {
                let config = entry.direct.as_ref();
                let mode = config.map(|d| d.mode.as_str()).unwrap_or("auto");

                let direct_mode = match mode {
                    "auto" => DirectMode::Auto,
                    "4" | "only4" => DirectMode::Only4,
                    "6" | "only6" => DirectMode::Only6,
                    "prefer4" | "46" => DirectMode::Prefer46,
                    "prefer6" | "64" => DirectMode::Prefer64,
                    _ => {
                        return Err(anyhow!(
                            "Invalid direct mode '{}' for outbound '{}', \
                             valid values: auto, 4, only4, 6, only6, prefer4, 46, prefer6, 64",
                            mode,
                            entry.name
                        ));
                    }
                };

                let bind_ip4 = config
                    .and_then(|d| d.bind_ipv4.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv4Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv4 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_ip6 = config
                    .and_then(|d| d.bind_ipv6.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv6Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv6 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_device = config.and_then(|d| d.bind_device.clone());
                let fast_open = config.is_some_and(|d| d.fast_open);
                let tcp_nodelay = config
                    .map(|d| d.tcp_nodelay)
                    .unwrap_or_else(default_tcp_nodelay);
                let tcp_keepalive_secs = config
                    .map(|d| d.tcp_keepalive_secs)
                    .unwrap_or_else(default_tcp_keepalive_secs);
                let tcp_keepalive = if tcp_keepalive_secs > 0 {
                    Some(std::time::Duration::from_secs(tcp_keepalive_secs))
                } else {
                    None
                };

                // Validate bind IPs at startup by trying to bind a test socket
                if let Some(ip) = bind_ip4 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv4 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
                    })?;
                }
                if let Some(ip) = bind_ip6 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv6 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
                    })?;
                }

                // Validate bindDevice at startup
                #[cfg(target_os = "linux")]
                if let Some(ref device) = bind_device {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    socket.bind_device(Some(device.as_bytes())).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindDevice '{}' failed: {}",
                            entry.name,
                            device,
                            e
                        )
                    })?;
                }
                #[cfg(not(target_os = "linux"))]
                if let Some(ref device) = bind_device {
                    return Err(anyhow!(
                        "FATAL: outbound '{}' bindDevice '{}' is only supported on Linux",
                        entry.name,
                        device
                    ));
                }

                let opts = DirectOptions {
                    mode: direct_mode,
                    bind_ip4,
                    bind_ip6,
                    bind_device,
                    fast_open,
                    timeout: None,
                    tcp_nodelay,
                    tcp_keepalive,
                };
                let direct = Direct::with_options(opts)
                    .map_err(|e| anyhow!("Invalid direct outbound '{}': {}", entry.name, e))?;

                // Log the direct outbound configuration
                let mut parts = vec![format!("mode={}", mode)];
                if let Some(ip) = bind_ip4 {
                    parts.push(format!("bindIPv4={}", ip));
                }
                if let Some(ip) = bind_ip6 {
                    parts.push(format!("bindIPv6={}", ip));
                }
                if let Some(ref dev) = config.and_then(|d| d.bind_device.as_ref()) {
                    parts.push(format!("bindDevice={}", dev));
                }
                if fast_open {
                    parts.push("fastOpen=true".to_string());
                }
                if !tcp_nodelay {
                    parts.push("tcpNoDelay=false".to_string());
                }
                if let Some(ka) = tcp_keepalive {
                    if ka.as_secs() != 60 {
                        parts.push(format!("tcpKeepAlive={}s", ka.as_secs()));
                    }
                } else {
                    parts.push("tcpKeepAlive=off".to_string());
                }
                log::info!(
                    outbound = %entry.name,
                    "Direct outbound configured: {}",
                    parts.join(", ")
                );

                Ok(OutboundHandler::Direct(Arc::new(direct)))
            }
            "socks5" => {
                let config = entry.socks5.as_ref().ok_or_else(|| {
                    anyhow!("socks5 config required for outbound '{}'", entry.name)
                })?;

                let socks5 = if let (Some(username), Some(password)) =
                    (&config.username, &config.password)
                {
                    Socks5::with_auth(&config.addr, username, password)
                        .map_err(|e| anyhow!("Invalid socks5 outbound '{}': {}", entry.name, e))?
                } else {
                    Socks5::new(&config.addr)
                };

                Ok(OutboundHandler::Socks5 {
                    inner: Arc::new(socks5),
                    allow_udp: config.allow_udp,
                })
            }
            "http" => {
                let config = entry
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow!("http config required for outbound '{}'", entry.name))?;

                let mut http = if config.https {
                    Http::try_new(&config.addr, true)
                        .map_err(|e| anyhow!("Invalid http outbound '{}': {}", entry.name, e))?
                } else {
                    Http::new(&config.addr)
                };

                if let (Some(username), Some(password)) = (&config.username, &config.password) {
                    http = http.with_auth(username, password);
                }

                Ok(OutboundHandler::Http(Arc::new(http)))
            }
            "reject" => Ok(OutboundHandler::Reject(Arc::new(Reject::new()))),
            unknown => Err(anyhow!(
                "Unknown outbound type '{}' for outbound '{}'",
                unknown,
                entry.name
            )),
        }
    }

    /// Check if this handler rejects connections
    #[allow(dead_code)]
    pub fn is_reject(&self) -> bool {
        matches!(self, OutboundHandler::Reject(_))
    }

    /// Check if this handler routes through a proxy (SOCKS5 or HTTP)
    #[allow(dead_code)]
    pub fn is_proxy(&self) -> bool {
        matches!(
            self,
            OutboundHandler::Socks5 { .. } | OutboundHandler::Http(_)
        )
    }

    /// Check if this handler allows UDP
    #[allow(dead_code)]
    pub fn allows_udp(&self) -> bool {
        match self {
            OutboundHandler::Direct(_) => true,
            OutboundHandler::Socks5 { allow_udp, .. } => *allow_udp,
            OutboundHandler::Http(_) => false,
            OutboundHandler::Reject(_) => false,
        }
    }
}

#[async_trait]
impl AsyncOutbound for OutboundHandler {
    async fn dial_tcp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncTcpConn>> {
        match self {
            OutboundHandler::Direct(d) => d.dial_tcp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Http(h) => h.dial_tcp(addr).await,
            OutboundHandler::Reject(r) => r.dial_tcp(addr).await,
        }
    }

    async fn dial_udp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncUdpConn>> {
        match self {
            OutboundHandler::Direct(d) => d.dial_udp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_udp(addr).await,
            OutboundHandler::Http(h) => h.dial_udp(addr).await,
            OutboundHandler::Reject(r) => r.dial_udp(addr).await,
        }
    }
}

// ---------------------------------------------------------------------------
// AclEngine
// ---------------------------------------------------------------------------

/// ACL Engine for rule-based traffic routing
pub struct AclEngine {
    /// Compiled rule set
    compiled: acl_engine_rs::CompiledRuleSet<Arc<OutboundHandler>>,
    /// Keep outbounds map for reference
    #[allow(dead_code)]
    outbounds: HashMap<String, Arc<OutboundHandler>>,
}

impl AclEngine {
    /// Create a new ACL engine from configuration
    ///
    /// # Arguments
    /// * `config` - ACL configuration
    /// * `data_dir` - Optional data directory for geo data files
    /// * `refresh_geodata` - If true, force refresh geo data files on startup
    pub async fn new(
        config: AclConfig,
        data_dir: Option<&Path>,
        refresh_geodata: bool,
    ) -> Result<Self> {
        // Step 1: Parse outbounds into handler map
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();

        for entry in &config.outbounds {
            let handler = OutboundHandler::from_entry(entry)?;
            log::info!(
                outbound = %entry.name,
                outbound_type = %entry.outbound_type,
                "Loaded outbound"
            );
            outbounds.insert(entry.name.clone(), Arc::new(handler));
        }

        // Step 2: Ensure default outbounds exist
        outbounds
            .entry("reject".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))));
        outbounds
            .entry("direct".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Direct(Arc::new(Direct::new()))));

        // Step 3: Get rules or use default
        let rules = if config.acl.inline.is_empty() {
            vec!["direct(all)".to_string()]
        } else {
            config.acl.inline.clone()
        };

        // Step 4: Parse rules text
        let rules_text = rules.join("\n");
        let text_rules = acl_engine_rs::parse_rules(&rules_text)
            .map_err(|e| anyhow!("Failed to parse ACL rules: {}", e))?;

        // Step 5: Create geo loader
        let mut geo_loader = if let Some(dir) = data_dir {
            AutoGeoLoader::new()
                .with_data_dir(dir)
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        } else {
            AutoGeoLoader::new()
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        };

        // Force refresh geodata if requested
        if refresh_geodata {
            geo_loader = geo_loader.with_update_interval(Duration::ZERO);
            log::info!("Geo data refresh requested, will download latest files");
        }

        // Step 6: Compile rules
        let compiled = acl_engine_rs::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(4096).unwrap(),
            &geo_loader,
        )
        .map_err(|e| anyhow!("Failed to compile ACL rules: {}", e))?;

        log::info!(
            outbounds = outbounds.len(),
            rules = compiled.rule_count(),
            "ACL engine initialized"
        );

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    /// Create a default ACL engine (direct all traffic)
    #[allow(dead_code)]
    pub fn new_default() -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();
        outbounds.insert(
            "direct".to_string(),
            Arc::new(OutboundHandler::Direct(Arc::new(Direct::new()))),
        );
        outbounds.insert(
            "reject".to_string(),
            Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))),
        );

        let text_rules = acl_engine_rs::parse_rules("direct(all)")
            .map_err(|e| anyhow!("Failed to parse default rules: {}", e))?;

        let compiled = acl_engine_rs::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(1024).unwrap(),
            &NilGeoLoader,
        )
        .map_err(|e| anyhow!("Failed to compile default rules: {}", e))?;

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    /// Match a host against ACL rules and return the appropriate outbound handler
    pub fn match_host(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
    ) -> Option<Arc<OutboundHandler>> {
        let host_info = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            HostInfo::from_ip(ip)
        } else {
            HostInfo::from_name(host)
        };

        match self.compiled.match_host(&host_info, protocol, port) {
            Some(result) => Some(result.outbound.clone()),
            None => self.outbounds.get("direct").cloned(),
        }
    }

    /// Get the number of compiled rules
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.compiled.rule_count()
    }
}

// ---------------------------------------------------------------------------
// load_acl_config
// ---------------------------------------------------------------------------

/// Load ACL configuration from YAML file
pub async fn load_acl_config(path: &Path) -> Result<AclConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow!("Failed to read ACL config file '{}': {}", path.display(), e))?;

    let config: AclConfig = serde_yaml::from_str(&content).map_err(|e| {
        anyhow!(
            "Failed to parse ACL config file '{}': {}",
            path.display(),
            e
        )
    })?;

    Ok(config)
}

// ---------------------------------------------------------------------------
// Private IP helpers
// ---------------------------------------------------------------------------

fn is_private_ipv4(ip: &[u8; 4]) -> bool {
    matches!(
        ip,
        [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [127, ..] | [0, 0, 0, 0] | [169, 254, ..]
    )
}

fn is_private_ipv6(ip: &[u8; 16]) -> bool {
    // ::1 (loopback)
    if ip == &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        return true;
    }
    // :: (unspecified)
    if ip == &[0u8; 16] {
        return true;
    }
    // fc00::/7 (ULA)
    if ip[0] & 0xfe == 0xfc {
        return true;
    }
    // fe80::/10 (link-local)
    if ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80 {
        return true;
    }
    // ::ffff:0:0/96 (IPv4-mapped) - check embedded IPv4
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        return is_private_ipv4(&[ip[12], ip[13], ip[14], ip[15]]);
    }
    false
}

// ---------------------------------------------------------------------------
// AclRouter
// ---------------------------------------------------------------------------

/// Default DNS cache TTL: 120 seconds.
const DNS_CACHE_TTL: Duration = Duration::from_secs(120);

/// Negative cache TTL: 15 seconds (short, avoids hammering DNS on failures).
const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(15);

/// Maximum number of entries in the DNS cache.
const DNS_CACHE_MAX_ENTRIES: u64 = 4096;

/// Per-entry expiry policy: negative cache entries (empty addrs) get a shorter TTL.
struct DnsExpiry;

impl moka::Expiry<String, Arc<[std::net::SocketAddr]>> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Arc<[std::net::SocketAddr]>,
        _current_time: std::time::Instant,
    ) -> Option<Duration> {
        if value.is_empty() {
            Some(DNS_NEGATIVE_CACHE_TTL)
        } else {
            Some(DNS_CACHE_TTL)
        }
    }
}

/// ACL Router adapter implementing OutboundRouter
///
/// Wraps the ACL engine and implements the OutboundRouter trait
/// for integration with the proxy layer.
pub struct AclRouter {
    engine: AclEngine,
    /// Block connections to private/loopback IP addresses (SSRF protection)
    block_private_ip: bool,
    /// DNS resolution cache with built-in LRU eviction, per-entry TTL, and singleflight.
    dns_cache: moka::future::Cache<String, Arc<[std::net::SocketAddr]>>,
}

impl AclRouter {
    /// Create a new ACL router with custom private IP blocking setting
    pub fn with_block_private_ip(engine: AclEngine, block_private_ip: bool) -> Self {
        let dns_cache = moka::future::Cache::builder()
            .max_capacity(DNS_CACHE_MAX_ENTRIES)
            .expire_after(DnsExpiry)
            .build();
        Self {
            engine,
            block_private_ip,
            dns_cache,
        }
    }

    /// Resolve a domain, using the cache if available and not expired.
    /// Features:
    /// - Positive cache with DNS_CACHE_TTL
    /// - Negative cache with DNS_NEGATIVE_CACHE_TTL (avoids hammering DNS on failures)
    /// - Singleflight: concurrent lookups for the same domain coalesce into one query (via get_with)
    /// - Bounded capacity with LRU eviction (max DNS_CACHE_MAX_ENTRIES)
    async fn resolve_domain(&self, host: &str) -> Option<Arc<[std::net::SocketAddr]>> {
        // Fast path: cache hit avoids host.to_string() allocation.
        if let Some(addrs) = self.dns_cache.get(host).await {
            return if addrs.is_empty() { None } else { Some(addrs) };
        }

        // Cache miss: resolve and cache (get_with provides singleflight).
        let addrs = self
            .dns_cache
            .get_with(host.to_string(), async {
                tokio::net::lookup_host((host, 0u16))
                    .await
                    .ok()
                    .map(|iter| iter.collect())
                    .unwrap_or_else(|| Arc::from([]))
            })
            .await;

        if addrs.is_empty() { None } else { Some(addrs) }
    }

    /// Shared routing logic parameterized by protocol.
    ///
    /// ACL matching runs **before** DNS resolution so that proxied domains
    /// (SOCKS5/HTTP) never trigger a server-side DNS lookup. This avoids
    /// unnecessary latency and prevents false rejections when the server
    /// cannot resolve the domain but a downstream proxy can.
    async fn route_with_protocol(&self, addr: &Address, protocol: Protocol) -> OutboundType {
        // Fast-reject private IP literals (no DNS needed).
        match addr {
            Address::IPv4(ip, _) if self.block_private_ip && is_private_ipv4(ip) => {
                log::debug!(target = %addr, "Blocked private IPv4 address");
                return OutboundType::Reject;
            }
            Address::IPv6(ip, _) if self.block_private_ip && is_private_ipv6(ip) => {
                log::debug!(target = %addr, "Blocked private IPv6 address");
                return OutboundType::Reject;
            }
            _ => {}
        }

        // ACL match first — no DNS involved, pure string matching.
        let host = addr.host_str();
        let port = addr.port();
        let acl_result = self.engine.match_host(&host, port, protocol);

        // Proxy / Reject: return immediately, no DNS needed on our side.
        if let Some(handler) = acl_result {
            if handler.is_proxy() {
                return OutboundType::Proxy(handler);
            }
            if handler.is_reject() {
                return OutboundType::Reject;
            }
        }

        // Direct route — resolve DNS for domain addresses so connect_target()
        // can reuse the result and we can enforce private-IP blocking.
        let mut resolved_addrs: Option<Arc<[std::net::SocketAddr]>> = None;

        if let Address::Domain(domain, _) = addr {
            if let Some(addrs) = self.resolve_domain(domain).await {
                if self.block_private_ip {
                    for resolved in addrs.iter() {
                        match resolved.ip() {
                            std::net::IpAddr::V4(ip) => {
                                let octets = ip.octets();
                                if is_private_ipv4(&octets) {
                                    log::debug!(target = %addr, resolved = %ip, "Blocked domain resolving to private IPv4");
                                    return OutboundType::Reject;
                                }
                            }
                            std::net::IpAddr::V6(ip) => {
                                let octets = ip.octets();
                                if is_private_ipv6(&octets) {
                                    log::debug!(target = %addr, resolved = %ip, "Blocked domain resolving to private IPv6");
                                    return OutboundType::Reject;
                                }
                            }
                        }
                    }
                }
                resolved_addrs = Some(addrs);
            } else if self.block_private_ip {
                log::debug!(target = %addr, "Blocked domain with unresolvable DNS (fail-closed)");
                return OutboundType::Reject;
            }
        }

        OutboundType::Direct {
            resolved: resolved_addrs,
        }
    }
}

#[async_trait]
impl OutboundRouter for AclRouter {
    async fn route(&self, addr: &Address) -> OutboundType {
        self.route_with_protocol(addr, Protocol::TCP).await
    }

    async fn route_udp(&self, addr: &Address) -> OutboundType {
        self.route_with_protocol(addr, Protocol::UDP).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_display_ipv4() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(addr.to_string(), "192.168.1.1:8080");
    }

    #[test]
    fn test_address_display_ipv6() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(
            addr.to_string(),
            "[0000:0000:0000:0000:0000:0000:0000:0001]:443"
        );
    }

    #[test]
    fn test_address_display_domain() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.to_string(), "example.com:80");
    }

    #[test]
    fn test_address_host_string() {
        let ipv4 = Address::IPv4([10, 0, 0, 1], 22);
        assert_eq!(ipv4.host_string(), "10.0.0.1");

        let domain = Address::Domain("foo.bar".to_string(), 443);
        assert_eq!(domain.host_string(), "foo.bar");

        let ipv6 = Address::IPv6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            80,
        );
        // host_string for IPv6 uses Ipv6Addr::from(*ip).to_string()
        let expected = std::net::Ipv6Addr::from([
            0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])
        .to_string();
        assert_eq!(ipv6.host_string(), expected);
    }

    #[test]
    fn test_address_port() {
        assert_eq!(Address::IPv4([1, 2, 3, 4], 1234).port(), 1234);
        assert_eq!(Address::IPv6([0u8; 16], 443).port(), 443);
        assert_eq!(Address::Domain("x.com".to_string(), 8080).port(), 8080);
    }

    #[tokio::test]
    async fn test_direct_router_routes_direct() {
        let router = DirectRouter;

        let tcp_addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&tcp_addr).await;
        assert!(matches!(result, OutboundType::Direct { resolved: None }));

        let udp_addr = Address::IPv4([8, 8, 8, 8], 53);
        let result = router.route_udp(&udp_addr).await;
        assert!(matches!(result, OutboundType::Direct { resolved: None }));
    }
}

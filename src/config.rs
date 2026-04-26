use anyhow::{Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

use crate::business::IpVersion;

fn parse_ip_version(s: &str) -> Result<IpVersion, String> {
    match s.to_lowercase().as_str() {
        "v4" | "ipv4" | "4" => Ok(IpVersion::V4),
        "v6" | "ipv6" | "6" => Ok(IpVersion::V6),
        "auto" | "dual" => Ok(IpVersion::Auto),
        other => Err(format!(
            "Invalid IP version '{}'. Use 'v4', 'v6', or 'auto'",
            other
        )),
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    if let Ok(d) = humantime::parse_duration(s) {
        return Ok(d);
    }
    s.parse::<u64>().map(Duration::from_secs).map_err(|_| {
        format!(
            "Invalid duration '{}'. Use formats like '60s', '2m', '1h' or plain seconds",
            s
        )
    })
}

const DEFAULT_DATA_DIR: &str = "/var/lib/mieru-agent-node";

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "Mieru Server Agent with gRPC Panel Integration"
)]
#[command(rename_all = "snake_case")]
pub struct CliArgs {
    #[arg(long, env = "X_PANDA_MIERU_SERVER_HOST", default_value = "127.0.0.1")]
    pub server_host: String,

    #[arg(long, env = "X_PANDA_MIERU_PORT", default_value_t = 8082)]
    pub port: u16,

    #[arg(long, env = "X_PANDA_MIERU_NODE")]
    pub node: u32,

    #[arg(long, env = "X_PANDA_MIERU_SERVER_NAME")]
    pub server_name: Option<String>,

    #[arg(long, env = "X_PANDA_MIERU_CA_FILE")]
    pub ca_file: Option<String>,

    #[arg(long, env = "X_PANDA_MIERU_FETCH_USERS_INTERVAL", default_value = "60s", value_parser = parse_duration)]
    pub fetch_users_interval: Duration,

    #[arg(long, env = "X_PANDA_MIERU_REPORT_TRAFFICS_INTERVAL", default_value = "80s", value_parser = parse_duration)]
    pub report_traffics_interval: Duration,

    #[arg(long, env = "X_PANDA_MIERU_HEARTBEAT_INTERVAL", default_value = "180s", value_parser = parse_duration)]
    pub heartbeat_interval: Duration,

    #[arg(long, env = "X_PANDA_MIERU_API_TIMEOUT", default_value = "15s", value_parser = parse_duration)]
    pub api_timeout: Duration,

    #[arg(long, env = "X_PANDA_MIERU_LOG_MODE", default_value = "error")]
    pub log_mode: String,

    #[arg(long, env = "X_PANDA_MIERU_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,

    #[arg(long, env = "X_PANDA_MIERU_ACL_CONF_FILE")]
    pub acl_conf_file: Option<PathBuf>,

    #[arg(long, env = "X_PANDA_MIERU_BLOCK_PRIVATE_IP", default_value_t = true, action = clap::ArgAction::Set)]
    pub block_private_ip: bool,

    #[arg(long, env = "X_PANDA_MIERU_REFRESH_GEODATA", default_value_t = false, action = clap::ArgAction::Set)]
    pub refresh_geodata: bool,

    /// Maximum number of concurrent connections.
    #[arg(
        long,
        env = "X_PANDA_MIERU_MAX_CONNECTIONS",
        default_value_t = 10000,
        help_heading = "Performance"
    )]
    pub max_connections: usize,

    /// Maximum time a relay may be idle (no bytes in either direction) before
    /// being terminated. Prevents connections from hanging indefinitely.
    #[arg(
        long,
        env = "X_PANDA_MIERU_RELAY_IDLE_TIMEOUT",
        default_value = "100s",
        value_parser = parse_duration,
        help_heading = "Performance"
    )]
    pub relay_idle_timeout: Duration,

    /// IP version preference for panel API connections (auto, v4, v6).
    #[arg(
        long,
        env = "X_PANDA_MIERU_PANEL_IP_VERSION",
        default_value = "v4",
        value_parser = parse_ip_version,
        help_heading = "Network"
    )]
    pub panel_ip_version: IpVersion,
}

impl CliArgs {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    pub fn validate(&self) -> Result<()> {
        if self.server_host.is_empty() {
            return Err(anyhow!("Server host is required"));
        }
        if self.node == 0 {
            return Err(anyhow!("Node ID must be a positive integer"));
        }
        if self.fetch_users_interval.is_zero() {
            return Err(anyhow!("fetch_users_interval must be greater than 0"));
        }
        if self.report_traffics_interval.is_zero() {
            return Err(anyhow!("report_traffics_interval must be greater than 0"));
        }
        if self.heartbeat_interval.is_zero() {
            return Err(anyhow!("heartbeat_interval must be greater than 0"));
        }
        if let Some(ref path) = self.acl_conf_file {
            if !path.exists() {
                return Err(anyhow!("ACL config file not found: {}", path.display()));
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
                return Err(anyhow!(
                    "Invalid ACL config file format: expected .yaml or .yml"
                ));
            }
        }
        Ok(())
    }
}

/// Mieru node configuration from panel JSON
#[derive(Debug, Clone, Deserialize)]
pub struct MieruConfig {
    pub server_port: u16,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub port_range: Option<String>,
    #[serde(default)]
    pub multiplexing: Option<String>,
    #[serde(default)]
    pub traffic_pattern: Option<String>,
}

/// Resolved listen configuration derived from MieruConfig
#[derive(Debug, Clone)]
pub struct ListenConfig {
    pub ports: Vec<u16>,
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
}

pub fn parse_listen_config(mieru_config: &MieruConfig) -> ListenConfig {
    let mut ports: Vec<u16> = vec![mieru_config.server_port];

    // Parse port_range "start-end", add all ports in range (dedup with server_port)
    if let Some(ref range_str) = mieru_config.port_range {
        let parts: Vec<&str> = range_str.splitn(2, '-').collect();
        if parts.len() == 2
            && let (Ok(start), Ok(end)) = (
                parts[0].trim().parse::<u16>(),
                parts[1].trim().parse::<u16>(),
            )
        {
            for p in start..=end {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
        }
    }

    // Parse transport: "TCP" → tcp only, "UDP" → udp only, default TCP
    let (tcp_enabled, udp_enabled) = match mieru_config
        .transport
        .as_deref()
        .unwrap_or("TCP")
        .to_uppercase()
        .as_str()
    {
        "UDP" => (false, true),
        _ => (true, false),
    };

    ListenConfig {
        ports,
        tcp_enabled,
        udp_enabled,
    }
}

pub fn parse_mieru_config(node_config: panel_core::NodeConfigEnum) -> Result<MieruConfig> {
    match node_config {
        panel_core::NodeConfigEnum::Mieru(json) => {
            serde_json::from_str(&json).map_err(|e| anyhow!("Failed to parse MieruConfig: {}", e))
        }
        other => Err(anyhow!(
            "Expected Mieru config, got {:?}",
            std::mem::discriminant(&other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cli_args() -> CliArgs {
        CliArgs {
            server_host: "127.0.0.1".to_string(),
            port: 8082,
            node: 1,
            server_name: None,
            ca_file: None,
            fetch_users_interval: Duration::from_secs(60),
            report_traffics_interval: Duration::from_secs(80),
            heartbeat_interval: Duration::from_secs(180),
            api_timeout: Duration::from_secs(15),
            log_mode: "error".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            acl_conf_file: None,
            block_private_ip: true,
            refresh_geodata: false,
            max_connections: 10000,
            relay_idle_timeout: Duration::from_secs(100),
            panel_ip_version: IpVersion::V4,
        }
    }

    #[test]
    fn test_cli_args_validate_success() {
        let cli = create_test_cli_args();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_empty_server_host() {
        let mut cli = create_test_cli_args();
        cli.server_host = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_invalid_node() {
        let mut cli = create_test_cli_args();
        cli.node = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_zero_interval() {
        let mut cli = create_test_cli_args();
        cli.fetch_users_interval = Duration::ZERO;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_parse_duration_humantime() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_plain_seconds() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("120").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_mieru_config() {
        let json = r#"{"server_port": 8080}"#;
        let config = parse_mieru_config(panel_core::NodeConfigEnum::Mieru(json.to_string()));
        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.server_port, 8080);
        assert!(cfg.transport.is_none());
        assert!(cfg.port_range.is_none());
    }

    #[test]
    fn test_parse_mieru_config_wrong_type() {
        let json = r#"{"server_port": 8080}"#;
        let config = parse_mieru_config(panel_core::NodeConfigEnum::Trojan(json.to_string()));
        assert!(config.is_err());
    }

    #[test]
    fn test_parse_listen_config_single_port() {
        let mieru_config = MieruConfig {
            server_port: 9000,
            transport: None,
            port_range: None,
            multiplexing: None,
            traffic_pattern: None,
        };
        let listen = parse_listen_config(&mieru_config);
        assert_eq!(listen.ports, vec![9000]);
        assert!(listen.tcp_enabled);
        assert!(!listen.udp_enabled);
    }

    #[test]
    fn test_parse_listen_config_port_range() {
        let mieru_config = MieruConfig {
            server_port: 9000,
            transport: Some("UDP".to_string()),
            port_range: Some("9001-9003".to_string()),
            multiplexing: None,
            traffic_pattern: None,
        };
        let listen = parse_listen_config(&mieru_config);
        assert!(listen.ports.contains(&9000));
        assert!(listen.ports.contains(&9001));
        assert!(listen.ports.contains(&9002));
        assert!(listen.ports.contains(&9003));
        assert_eq!(listen.ports.len(), 4);
        assert!(!listen.tcp_enabled);
        assert!(listen.udp_enabled);
    }

    #[test]
    fn test_parse_listen_config_dedup_server_port() {
        let mieru_config = MieruConfig {
            server_port: 9001,
            transport: None,
            port_range: Some("9001-9003".to_string()),
            multiplexing: None,
            traffic_pattern: None,
        };
        let listen = parse_listen_config(&mieru_config);
        // server_port 9001 is already in range, should not be duplicated
        let count_9001 = listen.ports.iter().filter(|&&p| p == 9001).count();
        assert_eq!(count_9001, 1);
        assert_eq!(listen.ports.len(), 3); // 9001, 9002, 9003
    }

    #[test]
    fn test_parse_ip_version_valid() {
        let cases = [
            ("v4", IpVersion::V4),
            ("V4", IpVersion::V4),
            ("ipv4", IpVersion::V4),
            ("4", IpVersion::V4),
            ("v6", IpVersion::V6),
            ("ipv6", IpVersion::V6),
            ("6", IpVersion::V6),
            ("auto", IpVersion::Auto),
            ("dual", IpVersion::Auto),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                parse_ip_version(input).unwrap(),
                *expected,
                "failed for input: {input}"
            );
        }
    }
}

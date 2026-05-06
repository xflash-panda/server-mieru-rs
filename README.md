# server-mieru

Rust implementation of the [mieru](https://github.com/enfein/mieru) proxy protocol server. Communicates with the panel via HTTP REST API.

## Features

- **Mieru protocol** — XChaCha20-Poly1305 encryption with time-based PBKDF2 key derivation
- **TCP & UDP** — Full support for both transport modes with session multiplexing
- **Panel integration** — Connects to panel via HTTP for config, user sync, traffic reporting, and heartbeat
- **ACL routing** — Rule-based outbound routing with geo-data support and private IP blocking
- **Hot reload** — Automatic user list sync with connection kick on user removal/change
- **Graceful shutdown** — Connection draining, panel unregister, and signal handling (SIGINT/SIGTERM)

## Usage

```bash
server-mieru \
  --api https://panel.example.com/api \
  --token your-api-token \
  --node 1 \
  --log_mode info
```

### CLI Arguments

| Argument | Env | Default | Description |
|----------|-----|---------|-------------|
| `--api` | `X_PANDA_MIERU_API` | *required* | Panel API URL |
| `--token` | `X_PANDA_MIERU_TOKEN` | *required* | Panel API token |
| `--node` | `X_PANDA_MIERU_NODE` | *required* | Node ID |
| `--log_mode` | `X_PANDA_MIERU_LOG_MODE` | `error` | Log level |
| `--data_dir` | `X_PANDA_MIERU_DATA_DIR` | `/var/lib/mieru-node` | Data directory |
| `--acl_conf_file` | `X_PANDA_MIERU_ACL_CONF_FILE` | — | ACL config file (.yaml) |
| `--block_private_ip` | `X_PANDA_MIERU_BLOCK_PRIVATE_IP` | `true` | Block private IP destinations |
| `--max_connections` | `X_PANDA_MIERU_MAX_CONNECTIONS` | `auto` | Max concurrent connections. `auto` derives a cap from `min(cpu_throughput, ram_budget, fd_limit)`; pass a positive integer to override. |
| `--relay_idle_timeout` | `X_PANDA_MIERU_RELAY_IDLE_TIMEOUT` | `100s` | Relay idle timeout |
| `--api_timeout` | `X_PANDA_MIERU_API_TIMEOUT` | `30s` | Panel API timeout |
| `--fetch_users_interval` | `X_PANDA_MIERU_FETCH_USERS_INTERVAL` | `60s` | User sync interval |
| `--report_traffics_interval` | `X_PANDA_MIERU_REPORT_TRAFFICS_INTERVAL` | `80s` | Traffic report interval |
| `--heartbeat_interval` | `X_PANDA_MIERU_HEARTBEAT_INTERVAL` | `180s` | Heartbeat interval |
| `--panel_ip_version` | `X_PANDA_MIERU_PANEL_IP_VERSION` | `v4` | Panel connection IP version |

## Build

```bash
cargo build --release
```

Release binary is at `target/release/server-mieru`.

## Architecture

```
src/
  main.rs          — Entry point, panel lifecycle, TCP/UDP listeners
  lib.rs           — Crate root, module re-exports
  business/        — Panel type bridging (HTTP API manager)
  config.rs        — CLI argument parsing, panel config deserialization
  connection.rs    — Connection manager with per-user kick
  acl.rs           — ACL routing engine
  outbound.rs      — SOCKS5 address parsing, target connection
  relay.rs         — Bidirectional relay with idle timeout
  core/
    crypto.rs      — Key derivation, encryption, nonce management
    metadata.rs    — Session/Data metadata encoding (32 bytes each)
    segment.rs     — TCP segment / UDP packet encode/decode
    session.rs     — Session multiplexing, AsyncRead/AsyncWrite streams
    padding.rs     — Random padding generation
    underlay/
      tcp.rs       — Stateful TCP underlay with implicit nonce
      udp.rs       — Stateless UDP packet authentication
      udp_relay.rs — UDP relay event loop with congestion control
      registry.rs  — User authentication registry (time-slot PBKDF2)
```

## License

Private.

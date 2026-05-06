//! Automatic computation of `max_connections` from system resources.
//!
//! Constants are derived from this server's specific implementation:
//!   - XChaCha20-Poly1305 software AEAD (no AES-NI hardware accel)
//!   - 32 KB max segment payload (`core::segment::MAX_PDU`)
//!   - Outbound channel 2048 slots (`core::session::SessionManager::new`)
//!   - Session data channel 4096 slots
//!   - copy_bidirectional relay 32+32 KB (`relay::RELAY_BUF_SIZE`)
//!   - Per-connection spawn count: ~3 tokio tasks (handler + writer + session)

use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxConnections {
    Auto,
    Fixed(usize),
}

impl FromStr for MaxConnections {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let n = s.parse::<usize>().map_err(|_| {
            format!("Invalid max_connections '{s}'. Use 'auto' or a positive integer")
        })?;
        if n == 0 {
            return Err(format!(
                "Invalid max_connections '{s}'. Must be 'auto' or a positive integer (>= 1)"
            ));
        }
        Ok(Self::Fixed(n))
    }
}

/// Sustained throughput per CPU core (Mbps).
///
/// XChaCha20-Poly1305 is a software-only cipher (no AES-NI accel). With AVX2
/// SIMD it sustains ~1.5–2 Gbps/core, but with mieru's framing/padding/AEAD
/// overhead and the per-connection write_task hop, realistic end-to-end
/// throughput is closer to **1.2 Gbps/core** on typical x86_64 VPS CPUs.
///
/// TODO(arch): tuned for x86_64 + AVX2. ARM64 with NEON is in the same
/// ballpark; ARM cores without crypto-extensions can be 2–3× slower.
const PER_CORE_MBPS: u64 = 1200;

/// Average per-user bandwidth assumption (Kbps).
///
/// Mixed proxy traffic (mobile + desktop, web + occasional video) averages
/// 100~500 Kbps per active user. 200 Kbps is a middle-of-the-road default.
const PER_USER_KBPS: u64 = 200;

/// Per-connection user-space + kernel memory cost (KB).
///
/// Steady-state breakdown (active session, code-traceable):
///
/// - TcpUnderlay AEAD state (XChaCha20 ciphers + nonce tracking): ~10 KB
/// - `mpsc<OutboundSegment>(2048)` queue header + ring: ~4 KB headers
///   (slot data is dynamic; transient backpressure can spike higher)
/// - `mpsc<Vec<u8>>(4096)` per-session: ~4 KB headers
/// - copy_bidirectional 32+32 KB relay buffers when active: 64 KB
/// - 3 tokio task stacks/futures: ~3 KB
/// - Outbound TcpStream + kernel TCP buffers (in+out): ~60 KB steady
/// - Misc Arcs / connection guard / registry / state: ~5 KB
///
/// Total ≈ 150 KB / connection (active steady state).
///
/// Note: the outbound channel can in principle buffer up to
/// 2048 × 32 KB = 64 MB **per connection** under sustained backpressure,
/// but in practice the writer blocks long before this materializes, so it
/// isn't factored into steady-state sizing.
const PER_SESSION_KB: u64 = 150;

/// Fraction of total RAM (in percent) reserved as the connection-state budget.
/// The remaining 50% covers kernel TCP buffers, panel client, geosite, logs.
const MEM_BUDGET_PCT: u64 = 50;

/// File descriptors reserved for non-connection use (logs, panel HTTP, DNS).
/// On boxes with a small `RLIMIT_NOFILE` this is capped to a quarter of the
/// limit so a low rlimit doesn't drive `fd_cap` to zero.
const FD_RESERVE_DEFAULT: u64 = 1024;

/// Average file descriptors consumed per connection (1 inbound + 1 outbound).
const FD_PER_SESSION: u64 = 2;

/// Pure function that computes `max_connections` from system resources.
///
/// Formula:
/// ```text
/// auto = min(
///     cpus * PER_CORE_MBPS * 1000 / PER_USER_KBPS,           // CPU throughput
///     total_mem_kb * MEM_BUDGET_PCT / 100 / PER_SESSION_KB,  // memory
///     (nofile_soft - reserve) / FD_PER_SESSION,              // file descriptors
/// )
/// ```
/// where `reserve = min(FD_RESERVE_DEFAULT, nofile_soft / 4)`.
///
/// The minimum result is 1 — any caller passing a degenerate input still
/// receives a value safe to feed into `Semaphore::new`.
pub fn compute_auto(cpus: usize, total_mem_kb: u64, nofile_soft: u64) -> AutoBreakdown {
    let cpus = cpus.max(1) as u64;

    let cpu_cap = cpus.saturating_mul(PER_CORE_MBPS).saturating_mul(1000) / PER_USER_KBPS;

    let mem_cap = total_mem_kb.saturating_mul(MEM_BUDGET_PCT) / 100 / PER_SESSION_KB;

    let fd_reserve = FD_RESERVE_DEFAULT.min(nofile_soft / 4);
    let fd_cap = nofile_soft.saturating_sub(fd_reserve) / FD_PER_SESSION;

    let raw = cpu_cap.min(mem_cap).min(fd_cap);
    let value = (raw.max(1)) as usize;

    let limiting = if cpu_cap <= mem_cap && cpu_cap <= fd_cap {
        Limit::Cpu
    } else if mem_cap <= fd_cap {
        Limit::Memory
    } else {
        Limit::FileDescriptors
    };

    AutoBreakdown {
        value,
        cpu_cap,
        mem_cap,
        fd_cap,
        limiting,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Cpu,
    Memory,
    FileDescriptors,
}

impl Limit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Limit::Cpu => "cpu",
            Limit::Memory => "memory",
            Limit::FileDescriptors => "fd",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AutoBreakdown {
    pub value: usize,
    pub cpu_cap: u64,
    pub mem_cap: u64,
    pub fd_cap: u64,
    pub limiting: Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    Auto,
    Fixed,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedMaxConnections {
    pub value: usize,
    pub mode: ResolveMode,
    /// Always populated. For `Fixed`, this is the auto-derived reference cap
    /// against which the user-supplied value can be compared for diagnostics.
    pub breakdown: AutoBreakdown,
    pub cpus: usize,
    pub total_mem_kb: u64,
    pub nofile_soft: u64,
}

/// Resolve a `MaxConnections` spec to a concrete value, querying the host
/// in both modes so the caller can log/compare against the auto-derived cap.
/// Always succeeds; falls back to safe defaults when host queries fail.
pub fn resolve(spec: MaxConnections) -> ResolvedMaxConnections {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // 4 GB fallback when total memory can't be queried (non-Linux dev hosts).
    // Production target is Linux where the real value is always available.
    let total_mem_kb = total_memory_kb().unwrap_or(4 * 1024 * 1024);
    let nofile_soft = nofile_soft_limit().unwrap_or(65_536);

    let breakdown = compute_auto(cpus, total_mem_kb, nofile_soft);

    let (value, mode) = match spec {
        MaxConnections::Fixed(n) => (n, ResolveMode::Fixed),
        MaxConnections::Auto => (breakdown.value, ResolveMode::Auto),
    };

    ResolvedMaxConnections {
        value,
        mode,
        breakdown,
        cpus,
        total_mem_kb,
        nofile_soft,
    }
}

#[cfg(target_os = "linux")]
fn total_memory_kb() -> Option<u64> {
    // SAFETY: sysconf is async-signal-safe and side-effect-free.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages > 0 && page_size > 0 {
        Some((pages as u64).saturating_mul(page_size as u64) / 1024)
    } else {
        None
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn total_memory_kb() -> Option<u64> {
    // macOS/BSD don't expose _SC_PHYS_PAGES.  Production target is Linux,
    // so a None here just means dev builds use the safe fallback.
    None
}

#[cfg(not(unix))]
fn total_memory_kb() -> Option<u64> {
    None
}

#[cfg(unix)]
fn nofile_soft_limit() -> Option<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills the rlimit struct; no aliasing concerns.
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if ret == 0 { Some(rl.rlim_cur) } else { None }
}

#[cfg(not(unix))]
fn nofile_soft_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb_to_kb(mb: u64) -> u64 {
        mb * 1024
    }

    fn gb_to_kb(gb: u64) -> u64 {
        gb * 1024 * 1024
    }

    #[test]
    fn parses_auto_case_insensitive() {
        assert_eq!(
            "auto".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
        assert_eq!(
            "AUTO".parse::<MaxConnections>().unwrap(),
            MaxConnections::Auto
        );
    }

    #[test]
    fn parses_fixed_integer() {
        assert_eq!(
            "5000".parse::<MaxConnections>().unwrap(),
            MaxConnections::Fixed(5000)
        );
    }

    #[test]
    fn zero_is_rejected() {
        assert!("0".parse::<MaxConnections>().is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!("xyz".parse::<MaxConnections>().is_err());
        assert!("-1".parse::<MaxConnections>().is_err());
    }

    #[test]
    fn one_cpu_two_gb_typical() {
        // CPU = 1 * 1200 * 1000 / 200 = 6000
        // mem = 2*1024*1024 * 50 / 100 / 150 ≈ 6990
        // fd  = (65536 - 1024) / 2 = 32256
        // min = 6000, CPU-bound (mieru's lighter per-conn footprint vs anytls
        //                        means CPU often binds first on small VPS)
        let bd = compute_auto(1, gb_to_kb(2), 65_536);
        assert_eq!(bd.limiting, Limit::Cpu);
        assert_eq!(bd.value, 6000);
    }

    #[test]
    fn two_cpu_four_gb_typical() {
        // CPU = 2 * 1200 * 1000 / 200 = 12000
        // mem ≈ 13981
        // fd  = 32256
        // min = 12000, CPU-bound
        let bd = compute_auto(2, gb_to_kb(4), 65_536);
        assert_eq!(bd.limiting, Limit::Cpu);
        assert_eq!(bd.value, 12_000);
    }

    #[test]
    fn four_cpu_four_gb_is_memory_bound() {
        // CPU = 24000, mem ≈ 13981, fd = 32256 → memory binds
        let bd = compute_auto(4, gb_to_kb(4), 65_536);
        assert_eq!(bd.limiting, Limit::Memory);
        assert!(bd.value >= 13_500 && bd.value <= 14_500, "got {}", bd.value);
    }

    #[test]
    fn many_cores_small_ram_is_memory_bound() {
        let bd = compute_auto(16, gb_to_kb(2), 65_536);
        assert_eq!(bd.limiting, Limit::Memory);
        assert!(bd.value <= 7_100);
    }

    #[test]
    fn small_rlimit_uses_adaptive_reserve() {
        // nofile=512: reserve = min(1024, 128) = 128
        // fd_cap = (512 - 128) / 2 = 192
        let bd = compute_auto(8, gb_to_kb(16), 512);
        assert_eq!(bd.limiting, Limit::FileDescriptors);
        assert_eq!(bd.fd_cap, 192);
        assert_eq!(bd.value, 192);
    }

    #[test]
    fn tight_fd_limit_binds() {
        // nofile=4096: reserve = min(1024, 1024) = 1024
        // fd_cap = (4096 - 1024) / 2 = 1536
        let bd = compute_auto(8, gb_to_kb(16), 4096);
        assert_eq!(bd.limiting, Limit::FileDescriptors);
        assert_eq!(bd.value, 1536);
    }

    #[test]
    fn tiny_box_reports_actual_value_not_floor() {
        // 32 MB → mem_cap ≈ 109; report it honestly.
        let bd = compute_auto(1, mb_to_kb(32), 65_536);
        assert_eq!(bd.limiting, Limit::Memory);
        assert_eq!(bd.value, bd.mem_cap as usize);
        assert!(bd.value < 200, "got {}", bd.value);
    }

    #[test]
    fn degenerate_zero_inputs_floor_to_one() {
        let bd = compute_auto(1, 0, 0);
        assert_eq!(bd.value, 1);
    }

    #[test]
    fn zero_cpus_treated_as_one() {
        let bd0 = compute_auto(0, gb_to_kb(2), 65_536);
        let bd1 = compute_auto(1, gb_to_kb(2), 65_536);
        assert_eq!(bd0.cpu_cap, bd1.cpu_cap);
    }

    #[test]
    fn resolve_auto_smokes() {
        let r = resolve(MaxConnections::Auto);
        assert_eq!(r.mode, ResolveMode::Auto);
        assert!(r.value >= 1);
        assert!(r.cpus >= 1);
        let bd = r.breakdown;
        assert_eq!(r.value, bd.value);
        assert!(bd.value as u64 <= bd.cpu_cap);
        assert!(bd.value as u64 <= bd.mem_cap);
        assert!(bd.value as u64 <= bd.fd_cap);
    }

    #[test]
    fn resolve_fixed_passes_value_through() {
        let r = resolve(MaxConnections::Fixed(1234));
        assert_eq!(r.value, 1234);
        assert_eq!(r.mode, ResolveMode::Fixed);
        // Breakdown is still populated for diagnostics / over-cap warnings.
        assert!(r.breakdown.value >= 1);
    }
}

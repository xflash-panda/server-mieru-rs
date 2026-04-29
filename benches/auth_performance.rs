//! Benchmarks for user authentication performance.
//!
//! Measures:
//! - AEAD-only scan (current implementation) at various user counts
//! - Time-slot prioritization: current slot (N AEAD) vs naive 3N scan
//! - Common case (current time slot hit) vs clock-skew case (adjacent slot)

use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use server_mieru_rs::business::mieru_hashed_password;
use server_mieru_rs::core::crypto::{
    KEY_LEN, NONCE_SIZE, decrypt, derive_key, encrypt, time_salt, time_slots_now,
};
use server_mieru_rs::core::metadata::{
    METADATA_LEN, ProtocolType, SessionMetadata, current_timestamp_minutes,
};
use server_mieru_rs::core::underlay::registry::{AuthCache, UserRegistry};

use server_mieru_rs::business::UserId;

/// Build an encrypted first segment for the given uuid using the specified time-slot index.
fn make_segment(uuid: &str, slot_idx: usize) -> ([u8; NONCE_SIZE], Vec<u8>, [u8; KEY_LEN]) {
    let mut nonce = [0u8; NONCE_SIZE];
    // Deterministic pseudo-random nonce
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(99);
    }

    let hashed_pw = mieru_hashed_password(uuid);
    let slots = time_slots_now();
    let salt = time_salt(slots[slot_idx]);
    let key = derive_key(&hashed_pw, &salt);

    let meta = SessionMetadata {
        protocol_type: ProtocolType::OpenSessionRequest,
        timestamp: current_timestamp_minutes(),
        session_id: 0xBEEF_CAFE,
        sequence: 0,
        status_code: 0,
        payload_length: 0,
        suffix_padding_length: 0,
    };
    let meta_bytes = meta.encode();
    let encrypted = encrypt(&key, &nonce, &meta_bytes);

    (nonce, encrypted, key)
}

/// Build a registry with N users named "user-uuid-XXXX".
fn build_registry(n: usize) -> UserRegistry {
    let users: Vec<(UserId, String)> = (1..=n)
        .map(|i| (i as UserId, format!("user-uuid-{i:05}")))
        .collect();
    UserRegistry::from_list(users)
}

/// Bench: authenticate at various user counts (target = last user, current time slot).
/// This is the common case — measures N AEAD decrypts.
fn bench_auth_current_slot(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_current_slot");

    for &n in &[100, 500, 2000] {
        let registry = build_registry(n);
        let target_uuid = format!("user-uuid-{n:05}");
        let (nonce, encrypted_meta, _) = make_segment(&target_uuid, 1); // current slot

        group.bench_with_input(BenchmarkId::new("users", n), &n, |b, _| {
            b.iter(|| {
                let result = registry.authenticate(&nonce, &encrypted_meta);
                assert!(result.is_some());
            });
        });
    }

    group.finish();
}

/// Bench: authenticate with adjacent time slot (clock-skew scenario).
/// This is the worst case — N AEAD (phase 1 miss) + up to 2N AEAD (phase 2).
fn bench_auth_adjacent_slot(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_adjacent_slot");

    for &n in &[100, 500, 2000] {
        let registry = build_registry(n);
        let target_uuid = format!("user-uuid-{n:05}");
        let (nonce, encrypted_meta, _) = make_segment(&target_uuid, 0); // previous slot

        group.bench_with_input(BenchmarkId::new("users", n), &n, |b, _| {
            b.iter(|| {
                let result = registry.authenticate(&nonce, &encrypted_meta);
                assert!(result.is_some());
            });
        });
    }

    group.finish();
}

/// Bench: time-slot prioritized scan vs naive 3N brute-force scan.
/// Shows the benefit of trying current slot for ALL users first.
fn bench_timeslot_prioritization(c: &mut Criterion) {
    let n = 2000;
    let registry = build_registry(n);
    let target_uuid = format!("user-uuid-{n:05}");
    let (nonce, encrypted_meta, _) = make_segment(&target_uuid, 1); // current slot

    let mut group = c.benchmark_group("timeslot_prioritization_2000users");

    // Optimized: time-slot prioritized (current implementation)
    group.bench_function("optimized_N_then_2N", |b| {
        b.iter(|| {
            let result = registry.authenticate(&nonce, &encrypted_meta);
            assert!(result.is_some());
        });
    });

    // Baseline: naive 3N scan (all 3 keys per user before moving to next)
    group.bench_function("naive_3N_per_user", |b| {
        b.iter(|| {
            let mut found = false;
            'outer: for group in registry.iter_groups() {
                for key in group.keys() {
                    if let Some(p) = decrypt(key, &nonce, &encrypted_meta) {
                        if p.len() == METADATA_LEN {
                            found = true;
                            break 'outer;
                        }
                    }
                }
            }
            assert!(found);
        });
    });

    group.finish();
}

/// Bench: first-user (best case) vs last-user (worst case) to show scaling.
fn bench_auth_position(c: &mut Criterion) {
    let n = 2000;
    let registry = build_registry(n);

    let mut group = c.benchmark_group("auth_position_2000users");

    // First user — 1 AEAD decrypt
    let (nonce_first, enc_first, _) = make_segment("user-uuid-00001", 1);
    group.bench_function("first_user", |b| {
        b.iter(|| {
            let result = registry.authenticate(&nonce_first, &enc_first);
            assert!(result.is_some());
        });
    });

    // Last user — N AEAD decrypts
    let (nonce_last, enc_last, _) = make_segment(&format!("user-uuid-{n:05}"), 1);
    group.bench_function("last_user", |b| {
        b.iter(|| {
            let result = registry.authenticate(&nonce_last, &enc_last);
            assert!(result.is_some());
        });
    });

    group.finish();
}

/// Bench: failed authentication (no matching user) — full scan of all keys.
fn bench_auth_failure(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_failure");

    for &n in &[100, 500, 2000] {
        let registry = build_registry(n);
        let (nonce, encrypted_meta, _) = make_segment("nonexistent-user", 1);

        group.bench_with_input(BenchmarkId::new("users", n), &n, |b, _| {
            b.iter(|| {
                let result = registry.authenticate(&nonce, &encrypted_meta);
                assert!(result.is_none());
            });
        });
    }

    group.finish();
}

/// Bench: AuthCache IP affinity hit vs full scan.
/// Shows O(1) vs O(N) speedup for returning clients.
fn bench_auth_cached_ip_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_cached_ip_hit");

    for &n in &[100, 500, 2000] {
        let registry = build_registry(n);
        let target_uuid = format!("user-uuid-{n:05}");
        let (nonce, encrypted_meta, _) = make_segment(&target_uuid, 1);
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // Uncached: full AEAD scan
        group.bench_with_input(BenchmarkId::new("uncached", n), &n, |b, _| {
            b.iter(|| {
                let result = registry.authenticate(&nonce, &encrypted_meta);
                assert!(result.is_some());
            });
        });

        // Cached: IP affinity hit (O(1) — single user, 3 time slots max)
        let cache = Arc::new(AuthCache::new());
        // Prime the cache
        let _ = registry.authenticate_cached(&nonce, &encrypted_meta, &cache, Some(ip));

        group.bench_with_input(BenchmarkId::new("ip_cached", n), &n, |b, _| {
            b.iter(|| {
                let result =
                    registry.authenticate_cached(&nonce, &encrypted_meta, &cache, Some(ip));
                assert!(result.is_some());
            });
        });
    }

    group.finish();
}

/// Bench: AuthCache hot user hit (new IP, but user in hot list).
fn bench_auth_cached_hot_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_cached_hot_user");

    for &n in &[100, 500, 2000] {
        let registry = build_registry(n);
        let target_uuid = format!("user-uuid-{n:05}");
        let (nonce, encrypted_meta, _) = make_segment(&target_uuid, 1);

        let cache = Arc::new(AuthCache::new());
        // Prime the cache from a different IP
        let old_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let _ = registry.authenticate_cached(&nonce, &encrypted_meta, &cache, Some(old_ip));

        // New IP — no IP hint, but hot list should help
        let new_ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();

        group.bench_with_input(BenchmarkId::new("users", n), &n, |b, _| {
            b.iter(|| {
                let result =
                    registry.authenticate_cached(&nonce, &encrypted_meta, &cache, Some(new_ip));
                assert!(result.is_some());
            });
        });
    }

    group.finish();
}

/// Bench: AuthCache miss (unknown user) — full scan + cache overhead.
fn bench_auth_cached_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_cached_miss");

    for &n in &[100, 500, 2000] {
        let registry = build_registry(n);
        let (nonce, encrypted_meta, _) = make_segment("nonexistent-user", 1);
        let cache = Arc::new(AuthCache::new());
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        group.bench_with_input(BenchmarkId::new("users", n), &n, |b, _| {
            b.iter(|| {
                let result =
                    registry.authenticate_cached(&nonce, &encrypted_meta, &cache, Some(ip));
                assert!(result.is_none());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_auth_current_slot,
    bench_auth_adjacent_slot,
    bench_timeslot_prioritization,
    bench_auth_position,
    bench_auth_failure,
    bench_auth_cached_ip_hit,
    bench_auth_cached_hot_user,
    bench_auth_cached_miss,
);
criterion_main!(benches);

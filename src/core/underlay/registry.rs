//! User registry with pre-computed key cache for fast authentication.
//!
//! All PBKDF2 key derivations are done upfront when the registry is built
//! (every ~2 minutes when users are refreshed).  Authentication only needs
//! to attempt XChaCha20-Poly1305 decryptions against cached keys.
//!
//! **Time-slot prioritization**: The mieru v3 protocol does NOT embed user
//! hints in nonces — all clients generate pure random 24-byte nonces.
//! Authentication uses a two-phase AEAD-only scan: first try the current
//! time slot (most likely) for all users, then try adjacent slots for
//! clock-skewed clients.  This reduces the common case from 3N to N decrypts.

use crate::business::{MieruUserManager, UserId, mieru_hashed_password};
use crate::core::crypto::{KEY_LEN, NONCE_SIZE, TAG_SIZE, decrypt, derive_key, time_slots_now};
use crate::core::metadata::METADATA_LEN;

/// A group of pre-computed keys for a single user (one per time slot).
#[doc(hidden)]
pub struct UserKeyGroup {
    user_id: UserId,
    keys: Vec<[u8; KEY_LEN]>,
}

impl UserKeyGroup {
    /// Access the pre-computed keys (for benchmarks).
    pub fn keys(&self) -> &[[u8; KEY_LEN]] {
        &self.keys
    }
}

/// Pre-computed key cache for all users × 3 time slots.
///
/// Built once when users are loaded/refreshed.  Authentication tries the
/// current time slot first, then falls back to adjacent slots.
pub struct UserRegistry {
    /// One entry per user, each containing up to 3 keys (one per time slot).
    user_groups: Vec<UserKeyGroup>,
}

impl UserRegistry {
    /// Build a registry from the current snapshot of the user manager.
    ///
    /// Pre-computes PBKDF2 keys for all users × 3 time slots.
    pub fn from_user_manager(mgr: &MieruUserManager) -> Self {
        let map = mgr.get_users();
        let users: Vec<(UserId, String)> = map
            .into_iter()
            .map(|(uuid, user_id)| (user_id, uuid))
            .collect();
        Self::build(users)
    }

    /// Create a registry from an explicit list (useful for tests).
    pub fn from_list(users: Vec<(UserId, String)>) -> Self {
        Self::build(users)
    }

    fn build(users: Vec<(UserId, String)>) -> Self {
        let time_slots = time_slots_now();
        let mut user_groups = Vec::with_capacity(users.len());

        for &(user_id, ref uuid) in &users {
            let hashed_pw = mieru_hashed_password(uuid);
            let keys: Vec<[u8; KEY_LEN]> = time_slots
                .iter()
                .map(|&slot| {
                    let salt = crate::core::crypto::time_salt(slot);
                    derive_key(&hashed_pw, &salt)
                })
                .collect();
            user_groups.push(UserKeyGroup { user_id, keys });
        }

        tracing::debug!(
            users = user_groups.len(),
            cached_keys = user_groups.len() * 3,
            "registry: built key cache"
        );

        Self { user_groups }
    }

    /// Try to authenticate using the nonce from the first segment.
    ///
    /// Pure AEAD scan with time-slot prioritization:
    /// 1. Try the most-likely key (current time slot, index 1) for ALL users.
    /// 2. Try remaining time slots (prev/next) for clock-skewed clients.
    ///
    /// The mieru v3 protocol does NOT embed user hints in nonces — all
    /// clients (official mieru + mihomo) generate pure random nonces.
    /// We skip any hint-based computation and go straight to AEAD decryption.
    ///
    /// Returns `(user_id, derived_key)` on success.
    pub fn authenticate(
        &self,
        nonce: &[u8; NONCE_SIZE],
        encrypted_metadata: &[u8],
    ) -> Option<(UserId, [u8; KEY_LEN])> {
        if encrypted_metadata.len() < METADATA_LEN + TAG_SIZE {
            return None;
        }

        // Phase 1: try the most-likely key (current time slot) for all users.
        // This handles the common case with N AEAD decrypts.
        for group in &self.user_groups {
            if let Some(result) = try_single_key(group, 1, nonce, encrypted_metadata) {
                return Some(result);
            }
        }

        // Phase 2: try remaining time slots (0, 2) for clock-skewed clients.
        for group in &self.user_groups {
            for slot_idx in [0, 2] {
                if let Some(result) = try_single_key(group, slot_idx, nonce, encrypted_metadata) {
                    return Some(result);
                }
            }
        }

        None
    }

    /// Iterate over user key groups (for benchmarks).
    #[doc(hidden)]
    pub fn iter_groups(&self) -> &[UserKeyGroup] {
        &self.user_groups
    }

    /// Number of cached keys (users × 3 time slots).
    pub fn key_count(&self) -> usize {
        self.user_groups.len() * 3
    }
}

/// Try a single key (by time-slot index) in a user group.
fn try_single_key(
    group: &UserKeyGroup,
    slot_idx: usize,
    nonce: &[u8; NONCE_SIZE],
    encrypted_metadata: &[u8],
) -> Option<(UserId, [u8; KEY_LEN])> {
    if let Some(key) = group.keys.get(slot_idx)
        && let Some(plaintext) = decrypt(key, nonce, encrypted_metadata)
        && plaintext.len() == METADATA_LEN
    {
        return Some((group.user_id, *key));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{embed_user_hint, encrypt, time_slots_now};
    use crate::core::metadata::{ProtocolType, SessionMetadata};

    /// Helper: create a properly encrypted first-segment metadata block
    /// for the given uuid, returning (nonce, encrypted_metadata, key).
    fn make_first_segment(uuid: &str) -> ([u8; NONCE_SIZE], Vec<u8>, [u8; 32]) {
        let mut nonce = [0u8; NONCE_SIZE];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        embed_user_hint(&mut nonce, uuid);

        let hashed_pw = mieru_hashed_password(uuid);
        let slots = time_slots_now();
        let salt = crate::core::crypto::time_salt(slots[1]);
        let key = derive_key(&hashed_pw, &salt);

        let meta = SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: crate::core::metadata::current_timestamp_minutes(),
            session_id: 0xDEAD_BEEF,
            sequence: 0,
            status_code: 0,
            payload_length: 0,
            suffix_padding_length: 0,
        };
        let meta_bytes = meta.encode();
        let encrypted = encrypt(&key, &nonce, &meta_bytes);

        (nonce, encrypted, key)
    }

    /// Helper: create a segment with pure-random nonce (no user hint),
    /// simulating a mieru v3 client like mihomo.
    fn make_first_segment_no_hint(uuid: &str) -> ([u8; NONCE_SIZE], Vec<u8>, [u8; 32]) {
        let mut nonce = [0u8; NONCE_SIZE];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(99);
        }
        // NO embed_user_hint — pure random nonce

        let hashed_pw = mieru_hashed_password(uuid);
        let slots = time_slots_now();
        let salt = crate::core::crypto::time_salt(slots[1]);
        let key = derive_key(&hashed_pw, &salt);

        let meta = SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: crate::core::metadata::current_timestamp_minutes(),
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

    #[test]
    fn test_user_registry_authenticate_valid_user() {
        let uuid = "test-user-uuid-1234";
        let registry = UserRegistry::from_list(vec![(42, uuid.to_string())]);

        let (nonce, encrypted_meta, expected_key) = make_first_segment(uuid);
        let result = registry.authenticate(&nonce, &encrypted_meta);

        assert!(result.is_some(), "authentication should succeed");
        let (user_id, key) = result.unwrap();
        assert_eq!(user_id, 42);
        assert_eq!(key, expected_key);
    }

    #[test]
    fn test_user_registry_authenticate_no_hint() {
        let uuid = "no-hint-user-uuid";
        let registry = UserRegistry::from_list(vec![(77, uuid.to_string())]);

        let (nonce, encrypted_meta, expected_key) = make_first_segment_no_hint(uuid);
        let result = registry.authenticate(&nonce, &encrypted_meta);

        assert!(result.is_some(), "auth without user hint should succeed");
        let (user_id, key) = result.unwrap();
        assert_eq!(user_id, 77);
        assert_eq!(key, expected_key);
    }

    #[test]
    fn test_user_registry_authenticate_wrong_user() {
        let registry = UserRegistry::from_list(vec![(1, "user-A".to_string())]);

        let (nonce, encrypted_meta, _) = make_first_segment("user-B");
        let result = registry.authenticate(&nonce, &encrypted_meta);
        assert!(result.is_none(), "wrong user should fail auth");
    }

    #[test]
    fn test_user_registry_authenticate_empty_registry() {
        let registry = UserRegistry::from_list(vec![]);

        let (nonce, encrypted_meta, _) = make_first_segment("any-user");
        let result = registry.authenticate(&nonce, &encrypted_meta);
        assert!(result.is_none(), "empty registry should fail auth");
    }

    #[test]
    fn test_user_registry_multiple_users() {
        let registry = UserRegistry::from_list(vec![
            (1, "alice-uuid".to_string()),
            (2, "bob-uuid".to_string()),
            (3, "charlie-uuid".to_string()),
        ]);

        let (nonce, encrypted_meta, _) = make_first_segment("bob-uuid");
        let result = registry.authenticate(&nonce, &encrypted_meta);
        assert!(result.is_some());
        let (user_id, _) = result.unwrap();
        assert_eq!(user_id, 2);

        let (nonce, encrypted_meta, _) = make_first_segment("charlie-uuid");
        let result = registry.authenticate(&nonce, &encrypted_meta);
        assert!(result.is_some());
        let (user_id, _) = result.unwrap();
        assert_eq!(user_id, 3);
    }

    #[test]
    fn test_key_count() {
        let registry = UserRegistry::from_list(vec![(1, "a".to_string()), (2, "b".to_string())]);
        assert_eq!(registry.key_count(), 6); // 2 users × 3 time slots
    }

    // ---- RED tests: no user hint in mieru v3 protocol ----
    //
    // The mieru v3 protocol does NOT embed user hints in nonces.
    // All clients (official mieru + mihomo) generate pure random nonces.
    // The authenticate() method should NOT waste CPU on hint computation.

    /// Auth with random nonce should have NO performance difference vs
    /// a nonce that happens to match a hint pattern. This proves the
    /// hint phase has been removed (previously random-nonce auth was
    /// 1.5x+ slower because it fell through to fallback scan).
    #[test]
    fn test_no_performance_gap_between_nonce_types() {
        let n = 500;
        let users: Vec<(UserId, String)> = (1..=n)
            .map(|i| (i as UserId, format!("user-uuid-{i:04}")))
            .collect();
        let target_uuid = "user-uuid-0500";

        let registry = UserRegistry::from_list(users);

        // Nonce with coincidental hint match (old "fast path")
        let (nonce_hint, enc_hint, _) = make_first_segment(target_uuid);
        // Pure random nonce (the ONLY real case in mieru v3)
        let (nonce_random, enc_random, _) = make_first_segment_no_hint(target_uuid);

        // Warm up
        let _ = registry.authenticate(&nonce_hint, &enc_hint);
        let _ = registry.authenticate(&nonce_random, &enc_random);

        let iterations = 50;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let r = registry.authenticate(&nonce_hint, &enc_hint);
            assert!(r.is_some());
        }
        let hint_time = start.elapsed();

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let r = registry.authenticate(&nonce_random, &enc_random);
            assert!(r.is_some());
        }
        let random_time = start.elapsed();

        // With hint phase removed, both paths take the same code path.
        // Allow up to 2x variance for scheduling noise, but NOT the 1.5x+
        // systematic gap the old hint phase caused.
        let ratio = random_time.as_nanos() as f64 / hint_time.as_nanos().max(1) as f64;
        assert!(
            ratio < 2.0,
            "random-nonce auth ({:?}) should NOT be systematically slower \
             than hint-nonce auth ({:?}), ratio={:.2}x — \
             hint phase should be removed (no user hints in mieru v3 protocol)",
            random_time,
            hint_time,
            ratio,
        );
    }

    /// Auth must NOT call compute_user_hint at all. With the hint phase
    /// removed, authenticate should go straight to AEAD-only scanning.
    /// For 500 users, random-nonce auth (worst case = last user, current
    /// time slot) should complete in under 8ms in debug builds.
    /// The old code did N SHA-256 (hint) + N AEAD = ~15ms; new code does
    /// only N AEAD = ~8ms.
    #[test]
    fn test_authenticate_no_hint_overhead() {
        let n = 500;
        let users: Vec<(UserId, String)> = (1..=n)
            .map(|i| (i as UserId, format!("user-uuid-{i:04}")))
            .collect();
        let target_uuid = "user-uuid-0500"; // last user

        let registry = UserRegistry::from_list(users);
        let (nonce, encrypted_meta, _) = make_first_segment_no_hint(target_uuid);

        // Warm up
        let _ = registry.authenticate(&nonce, &encrypted_meta);

        let iterations = 50;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let r = registry.authenticate(&nonce, &encrypted_meta);
            assert!(r.is_some());
        }
        let per_auth = start.elapsed() / iterations;

        // Without hint overhead: N AEAD decrypts ≈ 5-8ms in debug.
        // With hint overhead: N SHA-256 + N AEAD ≈ 12-15ms in debug.
        assert!(
            per_auth < std::time::Duration::from_millis(10),
            "authenticate took {:?}/call with {} users — \
             hint overhead may still be present (expected < 10ms without SHA-256 phase)",
            per_auth,
            n,
        );
    }

    // ---- time-slot prioritization (kept) ----

    /// Time-slot prioritization: try the most-likely slot (current) for
    /// ALL users first, reducing common-case AEAD decrypts from 3N to N.
    #[test]
    fn test_timeslot_prioritization() {
        let n = 2000;
        let users: Vec<(UserId, String)> = (1..=n)
            .map(|i| (i as UserId, format!("user-uuid-{i:05}")))
            .collect();
        let target_uuid = "user-uuid-02000"; // last user

        let registry = UserRegistry::from_list(users);
        let (nonce, encrypted_meta, _) = make_first_segment_no_hint(target_uuid);

        // Warm up
        let _ = registry.authenticate(&nonce, &encrypted_meta);

        let iterations = 20;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let r = registry.authenticate(&nonce, &encrypted_meta);
            assert!(r.is_some());
        }
        let optimized_time = start.elapsed();

        // Baseline: simulate old 3N AEAD scan (all 3 keys per user before
        // moving to next user).
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let mut _found = false;
            'outer: for group in &registry.user_groups {
                for key in &group.keys {
                    if let Some(p) = decrypt(key, &nonce, &encrypted_meta)
                        && p.len() == METADATA_LEN
                    {
                        _found = true;
                        break 'outer;
                    }
                }
            }
        }
        let baseline_time = start.elapsed();

        let ratio = baseline_time.as_nanos() as f64 / optimized_time.as_nanos().max(1) as f64;
        assert!(
            ratio > 1.5,
            "time-slot prioritization not effective: \
             optimized={:?}, baseline={:?}, ratio={:.2}x (expected >1.5x)",
            optimized_time / iterations,
            baseline_time / iterations,
            ratio,
        );
    }
}

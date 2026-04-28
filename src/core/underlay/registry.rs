//! User registry with pre-computed key cache for fast authentication.
//!
//! All PBKDF2 key derivations are done upfront when the registry is built
//! (every ~2 minutes when users are refreshed).  Authentication only needs
//! to attempt XChaCha20-Poly1305 decryptions against cached keys.
//!
//! **User hint optimization**: Official mieru clients embed a 4-byte hint in
//! `nonce[20..24]` derived from `SHA-256(username || nonce[0..16])`.  During
//! authentication we first check this hint against each user (a cheap SHA-256)
//! and only attempt AEAD decryption for the matching user.  This reduces the
//! common-case cost from O(3N) AEAD decrypts to O(N) SHA-256 + O(3) decrypts.
//! A full fallback scan handles clients without hints (e.g. mihomo).

use crate::business::{MieruUserManager, UserId, mieru_hashed_password};
use crate::core::crypto::{
    KEY_LEN, NONCE_SIZE, TAG_SIZE, compute_user_hint, decrypt, derive_key, extract_user_hint,
    time_slots_now,
};
use crate::core::metadata::METADATA_LEN;

/// A group of pre-computed keys for a single user (one per time slot).
struct UserKeyGroup {
    user_id: UserId,
    uuid: String,
    keys: Vec<[u8; KEY_LEN]>,
}

/// Pre-computed key cache for all users × 3 time slots.
///
/// Built once when users are loaded/refreshed.  Authentication uses a
/// two-phase approach: hint-based fast path, then full fallback scan.
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
            user_groups.push(UserKeyGroup {
                user_id,
                uuid: uuid.clone(),
                keys,
            });
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
    /// Two-phase approach:
    /// 1. **Hint fast path**: extract the 4-byte user hint from the nonce,
    ///    compute the expected hint for each user (cheap SHA-256), and only
    ///    attempt AEAD decryption for the user whose hint matches.
    /// 2. **Fallback scan**: if no hint match is found (e.g. mihomo clients
    ///    that don't embed hints), fall back to trying all keys.
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

        let extracted_hint = extract_user_hint(nonce);

        // Phase 1: hint-based fast path — try only the user whose hint matches.
        let mut hint_matched_idx = None;
        for (i, group) in self.user_groups.iter().enumerate() {
            if compute_user_hint(&group.uuid, nonce) == extracted_hint {
                hint_matched_idx = Some(i);
                if let Some(result) = try_group_keys(group, nonce, encrypted_metadata) {
                    return Some(result);
                }
                break; // At most one user matches the 4-byte hint in practice.
            }
        }

        // Phase 2: fallback for clients without embedded hints (e.g. mihomo).
        // Time-slot prioritization: try the most-likely key (current time slot,
        // index 1) for ALL users first, then try adjacent slots.  This reduces
        // the common case from 3N to N AEAD decrypts.
        for (i, group) in self.user_groups.iter().enumerate() {
            if Some(i) == hint_matched_idx {
                continue;
            }
            if let Some(result) = try_single_key(group, 1, nonce, encrypted_metadata) {
                return Some(result);
            }
        }

        // Phase 3: try remaining time slots (0, 2) for clock-skewed clients.
        for (i, group) in self.user_groups.iter().enumerate() {
            if Some(i) == hint_matched_idx {
                continue;
            }
            for slot_idx in [0, 2] {
                if let Some(result) = try_single_key(group, slot_idx, nonce, encrypted_metadata) {
                    return Some(result);
                }
            }
        }

        None
    }

    /// Number of cached keys (users × 3 time slots).
    pub fn key_count(&self) -> usize {
        self.user_groups.len() * 3
    }
}

/// Try all keys in a user group against the encrypted metadata.
fn try_group_keys(
    group: &UserKeyGroup,
    nonce: &[u8; NONCE_SIZE],
    encrypted_metadata: &[u8],
) -> Option<(UserId, [u8; KEY_LEN])> {
    for key in &group.keys {
        if let Some(plaintext) = decrypt(key, nonce, encrypted_metadata)
            && plaintext.len() == METADATA_LEN
        {
            return Some((group.user_id, *key));
        }
    }
    None
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

    // ---- RED tests: verify user-hint optimization exists ----

    /// With 500 users, hint-bearing auth should be significantly faster than
    /// brute-force (hint narrows to ~1 user → 3 AEAD decrypts vs 1500).
    /// In debug builds SHA-256 per user adds overhead, so we use 5ms threshold
    /// (still proves optimization — brute-force takes ~15ms+).
    #[test]
    fn test_authenticate_with_hint_is_fast_many_users() {
        let n = 500;
        let users: Vec<(UserId, String)> = (1..=n)
            .map(|i| (i as UserId, format!("user-uuid-{i:04}")))
            .collect();
        let target_uuid = "user-uuid-0500"; // last user in the list

        let registry = UserRegistry::from_list(users);
        let (nonce, encrypted_meta, _) = make_first_segment(target_uuid);

        // Warm up
        let _ = registry.authenticate(&nonce, &encrypted_meta);

        let start = std::time::Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let result = registry.authenticate(&nonce, &encrypted_meta);
            assert!(result.is_some());
        }
        let elapsed = start.elapsed();
        let per_auth = elapsed / iterations;

        // With hint optimization: N SHA-256 + 3 AEAD → ~2ms in debug
        // Without optimization: 3N AEAD decrypts → ~15ms+ in debug
        assert!(
            per_auth < std::time::Duration::from_millis(5),
            "authenticate took {:?}/call with {} users — \
             user hint optimization is missing (expected < 5ms, brute-force takes ~15ms+)",
            per_auth,
            n,
        );
    }

    /// Compare hint-bearing vs no-hint auth to prove optimization exists.
    /// Hint-bearing auth should be at least 2x faster than no-hint auth
    /// (which must do a full fallback scan for mihomo compatibility).
    #[test]
    fn test_hint_auth_faster_than_no_hint_auth() {
        let n = 500;
        let users: Vec<(UserId, String)> = (1..=n)
            .map(|i| (i as UserId, format!("user-uuid-{i:04}")))
            .collect();
        let target_uuid = "user-uuid-0500";

        let registry = UserRegistry::from_list(users);

        // With hint (official client)
        let (nonce_hint, enc_hint, _) = make_first_segment(target_uuid);
        // Without hint (mihomo-style)
        let (nonce_nohint, enc_nohint, _) = make_first_segment_no_hint(target_uuid);

        // Warm up
        let _ = registry.authenticate(&nonce_hint, &enc_hint);
        let _ = registry.authenticate(&nonce_nohint, &enc_nohint);

        let iterations = 50;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let r = registry.authenticate(&nonce_hint, &enc_hint);
            assert!(r.is_some());
        }
        let hint_time = start.elapsed();

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let r = registry.authenticate(&nonce_nohint, &enc_nohint);
            assert!(r.is_some());
        }
        let nohint_time = start.elapsed();

        // No-hint must scan all users (fallback path) → significantly slower.
        // Require at least 1.5x ratio to avoid flakiness from scheduling noise.
        let ratio = nohint_time.as_nanos() as f64 / hint_time.as_nanos().max(1) as f64;
        assert!(
            ratio > 1.5,
            "no-hint auth ({:?}) should be >1.5x slower than hint auth ({:?}), \
             ratio={:.2}x — hint optimization not working",
            nohint_time,
            hint_time,
            ratio,
        );
    }

    // ---- RED test: verify time-slot prioritization for mihomo ----

    /// Mihomo (no-hint) auth should benefit from time-slot prioritization:
    /// try the most-likely slot (current) for ALL users first, reducing
    /// common-case AEAD decrypts from 3N to N.
    ///
    /// We measure both the optimized path and a baseline 3-key-per-user scan
    /// to prove the optimization gives at least 1.5x speedup.
    #[test]
    fn test_mihomo_auth_timeslot_prioritization() {
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
        // moving to next user).  Uses the same precomputed keys.
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let mut _found = false;
            'outer: for group in &registry.user_groups {
                for key in &group.keys {
                    if let Some(p) = decrypt(key, &nonce, &encrypted_meta) {
                        if p.len() == METADATA_LEN {
                            _found = true;
                            break 'outer;
                        }
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

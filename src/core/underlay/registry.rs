//! User registry with pre-computed key cache for fast authentication.
//!
//! All PBKDF2 key derivations are done upfront when the registry is built
//! (every ~2 minutes when users are refreshed).  Authentication only needs
//! to attempt XChaCha20-Poly1305 decryptions against cached keys.

use crate::business::{MieruUserManager, UserId, mieru_hashed_password};
use crate::core::crypto::{
    KEY_LEN, NONCE_SIZE, TAG_SIZE, decrypt, derive_key, time_slots_now,
};
use crate::core::metadata::METADATA_LEN;

/// A pre-computed (user_id, derived_key) pair ready for decryption attempts.
struct CachedKey {
    user_id: UserId,
    key: [u8; KEY_LEN],
}

/// Pre-computed key cache for all users × 3 time slots.
///
/// Built once when users are loaded/refreshed.  Authentication is a simple
/// linear scan of decrypt attempts — no PBKDF2 on the hot path.
pub struct UserRegistry {
    /// Flattened list: for N users, contains up to 3N entries
    /// (one per user per time slot).
    cached_keys: Vec<CachedKey>,
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
        let mut cached_keys = Vec::with_capacity(users.len() * 3);

        for &(user_id, ref uuid) in &users {
            let hashed_pw = mieru_hashed_password(uuid);
            for &slot in &time_slots {
                let salt = crate::core::crypto::time_salt(slot);
                let key = derive_key(&hashed_pw, &salt);
                cached_keys.push(CachedKey { user_id, key });
            }
        }

        tracing::debug!(
            users = users.len(),
            cached_keys = cached_keys.len(),
            "registry: built key cache"
        );

        Self { cached_keys }
    }

    /// Try to authenticate using the nonce from the first segment.
    ///
    /// Iterates all pre-computed keys and attempts decryption.
    /// Returns `(user_id, derived_key)` on success.
    pub fn authenticate(
        &self,
        nonce: &[u8; NONCE_SIZE],
        encrypted_metadata: &[u8],
    ) -> Option<(UserId, [u8; KEY_LEN])> {
        if encrypted_metadata.len() < METADATA_LEN + TAG_SIZE {
            return None;
        }

        for ck in &self.cached_keys {
            if let Some(plaintext) = decrypt(&ck.key, nonce, encrypted_metadata)
                && plaintext.len() == METADATA_LEN
            {
                return Some((ck.user_id, ck.key));
            }
        }

        None
    }

    /// Number of cached keys (users × 3 time slots).
    pub fn key_count(&self) -> usize {
        self.cached_keys.len()
    }
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
        let registry = UserRegistry::from_list(vec![
            (1, "a".to_string()),
            (2, "b".to_string()),
        ]);
        assert_eq!(registry.key_count(), 6); // 2 users × 3 time slots
    }
}

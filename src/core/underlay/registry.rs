//! User registry for fast authentication via nonce-embedded user hints.
//!
//! When a client sends its first segment, the nonce carries a 4-byte user hint
//! at bytes [20..24].  The server iterates registered users, computes each
//! user's expected hint, and tries to decrypt metadata only for matching
//! users (across 3 time-slot key derivations).

use crate::business::{MieruUserManager, UserId, mieru_hashed_password};
use crate::core::crypto::{
    NONCE_SIZE, TAG_SIZE, compute_user_hint, decrypt, derive_key, extract_user_hint, time_slots_now,
};
use crate::core::metadata::METADATA_LEN;

/// Pre-loaded list of (user_id, uuid) pairs for authentication attempts.
pub struct UserRegistry {
    users: Vec<(UserId, String)>,
}

impl UserRegistry {
    /// Build a registry from the current snapshot of the user manager.
    pub fn from_user_manager(mgr: &MieruUserManager) -> Self {
        let map = mgr.get_users();
        let users: Vec<(UserId, String)> = map
            .into_iter()
            .map(|(uuid, user_id)| (user_id, uuid))
            .collect();
        Self { users }
    }

    /// Create a registry from an explicit list (useful for tests).
    pub fn from_list(users: Vec<(UserId, String)>) -> Self {
        Self { users }
    }

    /// Try to authenticate using the nonce from the first segment.
    ///
    /// `nonce` is the 24-byte nonce extracted from the first segment.
    /// `encrypted_metadata` is the ciphertext+tag for the metadata block
    /// (exactly `METADATA_LEN + TAG_SIZE` bytes).
    ///
    /// Returns `(user_id, derived_key)` on success.
    pub fn authenticate(
        &self,
        nonce: &[u8; NONCE_SIZE],
        encrypted_metadata: &[u8],
    ) -> Option<(UserId, [u8; 32])> {
        if encrypted_metadata.len() < METADATA_LEN + TAG_SIZE {
            return None;
        }

        let hint = extract_user_hint(nonce);
        let time_slots = time_slots_now();

        for &(user_id, ref uuid) in &self.users {
            // Check if this user's hint matches the nonce.
            let candidate_hint = compute_user_hint(uuid, nonce);
            if candidate_hint != hint {
                continue;
            }

            // Hint matches -- try all 3 time slots.
            let hashed_pw = mieru_hashed_password(uuid);
            for &slot in &time_slots {
                let salt = crate::core::crypto::time_salt(slot);
                let key = derive_key(&hashed_pw, &salt);

                if let Some(plaintext) = decrypt(&key, nonce, encrypted_metadata)
                    && plaintext.len() == METADATA_LEN
                {
                    return Some((user_id, key));
                }
            }
        }

        None
    }

    /// Number of registered users.
    pub fn user_count(&self) -> usize {
        self.users.len()
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
        // Generate a nonce with embedded user hint.
        let mut nonce = [0u8; NONCE_SIZE];
        // Fill with pseudo-random bytes.
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        embed_user_hint(&mut nonce, uuid);

        // Derive key using the current time slot.
        let hashed_pw = mieru_hashed_password(uuid);
        let slots = time_slots_now();
        let salt = crate::core::crypto::time_salt(slots[1]); // current slot
        let key = derive_key(&hashed_pw, &salt);

        // Encrypt a valid metadata block.
        let meta = SessionMetadata {
            protocol_type: ProtocolType::OpenSessionRequest,
            timestamp: 28_000_000,
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
    fn test_user_registry_authenticate_wrong_user() {
        // Registry has user A, but the segment was encrypted for user B.
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

        // Authenticate as bob.
        let (nonce, encrypted_meta, _) = make_first_segment("bob-uuid");
        let result = registry.authenticate(&nonce, &encrypted_meta);
        assert!(result.is_some());
        let (user_id, _) = result.unwrap();
        assert_eq!(user_id, 2);

        // Authenticate as charlie.
        let (nonce, encrypted_meta, _) = make_first_segment("charlie-uuid");
        let result = registry.authenticate(&nonce, &encrypted_meta);
        assert!(result.is_some());
        let (user_id, _) = result.unwrap();
        assert_eq!(user_id, 3);
    }
}

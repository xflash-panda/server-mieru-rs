use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PBKDF2 iteration count (mieru v3 protocol value, was 4096 in v2).
pub const KEY_ITER: u32 = 64;

/// Key length in bytes (256-bit key).
pub const KEY_LEN: usize = 32;

/// Key refresh interval in seconds (2 minutes).
pub const KEY_REFRESH_INTERVAL: u64 = 120;

/// XChaCha20-Poly1305 nonce size in bytes.
pub const NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Compute SHA-256(password || 0x00 || username).
///
/// Matches mieru Go `HashPassword(rawPassword, uniqueValue)` where
/// `uniqueValue` is the username bytes.
pub fn hashed_password(username: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update([0x00u8]);
    h.update(username.as_bytes());
    h.finalize().into()
}

/// Compute SHA-256(unix_minutes_as_big_endian_u64).
///
/// Matches mieru Go `saltFromTime` which encodes the unix timestamp as 8
/// big-endian bytes and hashes them.
pub fn time_salt(unix_minutes: u64) -> [u8; 32] {
    let bytes = unix_minutes.to_be_bytes();
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Derive a 32-byte key from a hashed password and a salt using PBKDF2-SHA256.
pub fn derive_key(hashed_pw: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::<Hmac<Sha256>>(hashed_pw, salt, KEY_ITER, &mut key)
        .expect("PBKDF2 should not fail with valid parameters");
    key
}

/// Return [prev_slot, current_slot, next_slot] as unix-second timestamps
/// rounded to 2-minute boundaries.
///
/// Mirrors mieru Go `saltFromTime` which uses `time.Round(2*time.Minute)`.
/// Go's `time.Round` is a symmetric (away-from-zero) rounding on the elapsed
/// time since the zero time, equivalent to rounding the unix timestamp to the
/// nearest multiple of `KEY_REFRESH_INTERVAL` with ties going to the higher
/// value.
pub fn time_slots_now() -> [u64; 3] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();

    // Round to nearest 2-minute boundary (ties round up, matching Go behavior).
    let interval = KEY_REFRESH_INTERVAL;
    let half = interval / 2;
    let current = ((now + half) / interval) * interval;

    [current - interval, current, current + interval]
}

// ---------------------------------------------------------------------------
// User hint (nonce embedding)
// ---------------------------------------------------------------------------

/// Compute the 4-byte user hint: first 4 bytes of
/// SHA-256(username || nonce[0..min(16, nonce.len())]).
pub fn compute_user_hint(username: &str, nonce: &[u8]) -> [u8; 4] {
    let prefix_len = nonce.len().min(16);
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(&nonce[..prefix_len]);
    let digest = h.finalize();
    digest[..4].try_into().expect("digest is at least 4 bytes")
}

/// Embed a 4-byte user hint into nonce[20..24].
///
/// The hint is computed from nonce[0..16] BEFORE any modification so it is
/// always stable.
pub fn embed_user_hint(nonce: &mut [u8; NONCE_SIZE], username: &str) {
    // Compute hint using the unmodified nonce bytes first.
    let hint = compute_user_hint(username, nonce);
    nonce[20..24].copy_from_slice(&hint);
}

/// Extract the 4-byte user hint from nonce[20..24].
pub fn extract_user_hint(nonce: &[u8; NONCE_SIZE]) -> [u8; 4] {
    nonce[20..24].try_into().expect("slice is exactly 4 bytes")
}

// ---------------------------------------------------------------------------
// Encryption / Decryption
// ---------------------------------------------------------------------------

/// XChaCha20-Poly1305 encrypt. Returns ciphertext || 16-byte tag.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(xnonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption should not fail")
}

/// XChaCha20-Poly1305 decrypt. Returns `None` on authentication failure.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    cipher.decrypt(xnonce, ciphertext).ok()
}

// ---------------------------------------------------------------------------
// Nonce increment
// ---------------------------------------------------------------------------

/// Increment the nonce treated as a big-endian integer by 1.
///
/// Matches mieru Go `increaseNonce` which iterates from index 0, accessing
/// `j = len-1-i`, i.e. it increments from the last (least significant) byte
/// and carries toward the first (most significant) byte.
pub fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for i in 0..NONCE_SIZE {
        let j = NONCE_SIZE - 1 - i;
        nonce[j] = nonce[j].wrapping_add(1);
        if nonce[j] != 0 {
            break;
        }
        // If nonce[j] wrapped to 0, carry into the next more-significant byte.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Key derivation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hashed_password_deterministic() {
        let a = hashed_password("user", "pass");
        let b = hashed_password("user", "pass");
        assert_eq!(a, b);
    }

    #[test]
    fn test_hashed_password_different_inputs() {
        let a = hashed_password("user1", "pass");
        let b = hashed_password("user2", "pass");
        let c = hashed_password("user1", "different");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn test_hashed_password_known_value() {
        // SHA-256("pass" || 0x00 || "user")
        let expected = {
            let mut h = Sha256::new();
            h.update(b"pass");
            h.update([0x00u8]);
            h.update(b"user");
            let d = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&d);
            arr
        };
        assert_eq!(hashed_password("user", "pass"), expected);
    }

    #[test]
    fn test_time_salt_deterministic() {
        let a = time_salt(12345);
        let b = time_salt(12345);
        assert_eq!(a, b);
    }

    #[test]
    fn test_time_salt_different_values() {
        let a = time_salt(0);
        let b = time_salt(1);
        let c = time_salt(12345);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let pw = hashed_password("user", "pass");
        let salt = time_salt(100);
        let k1 = derive_key(&pw, &salt);
        let k2 = derive_key(&pw, &salt);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_salt_different_key() {
        let pw = hashed_password("user", "pass");
        let salt1 = time_salt(100);
        let salt2 = time_salt(101);
        let k1 = derive_key(&pw, &salt1);
        let k2 = derive_key(&pw, &salt2);
        assert_ne!(k1, k2);
    }

    // -----------------------------------------------------------------------
    // Time slot tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_time_slots_returns_three_slots() {
        let slots = time_slots_now();
        assert_eq!(slots.len(), 3);
    }

    #[test]
    fn test_time_slots_spacing() {
        let slots = time_slots_now();
        assert_eq!(slots[1] - slots[0], KEY_REFRESH_INTERVAL);
        assert_eq!(slots[2] - slots[1], KEY_REFRESH_INTERVAL);
    }

    #[test]
    fn test_time_slots_multiples_of_interval() {
        let slots = time_slots_now();
        for slot in slots {
            assert_eq!(
                slot % KEY_REFRESH_INTERVAL,
                0,
                "slot {slot} is not a multiple of {KEY_REFRESH_INTERVAL}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // User hint tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_user_hint_deterministic() {
        let nonce = [0xabu8; NONCE_SIZE];
        let h1 = compute_user_hint("alice", &nonce);
        let h2 = compute_user_hint("alice", &nonce);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_user_hint_different_users() {
        let nonce = [0x01u8; NONCE_SIZE];
        let h1 = compute_user_hint("alice", &nonce);
        let h2 = compute_user_hint("bob", &nonce);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_embed_extract_roundtrip() {
        let mut nonce = [0u8; NONCE_SIZE];
        // Fill nonce[0..16] with distinct values so the hint is non-trivial.
        for (i, b) in nonce[..16].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }

        let expected_hint = compute_user_hint("alice", &nonce);
        embed_user_hint(&mut nonce, "alice");
        let extracted = extract_user_hint(&nonce);
        assert_eq!(extracted, expected_hint);
    }

    #[test]
    fn test_embed_doesnt_affect_first_16_bytes() {
        let mut nonce = [0u8; NONCE_SIZE];
        for (i, b) in nonce[..16].iter_mut().enumerate() {
            *b = i as u8;
        }
        let before: [u8; 16] = nonce[..16].try_into().unwrap();
        embed_user_hint(&mut nonce, "testuser");
        let after: [u8; 16] = nonce[..16].try_into().unwrap();
        assert_eq!(
            before, after,
            "embed_user_hint must not modify nonce[0..16]"
        );
    }

    // -----------------------------------------------------------------------
    // Encryption tests
    // -----------------------------------------------------------------------

    fn test_key() -> [u8; KEY_LEN] {
        let pw = hashed_password("testuser", "testpass");
        let salt = time_salt(9999);
        derive_key(&pw, &salt)
    }

    fn test_nonce() -> [u8; NONCE_SIZE] {
        let mut n = [0u8; NONCE_SIZE];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"hello, mieru!";

        let ciphertext = encrypt(&key, &nonce, plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let key = test_key();
        let plaintext = b"same plaintext";

        let nonce1 = test_nonce();
        let mut nonce2 = test_nonce();
        increment_nonce(&mut nonce2);

        let ct1 = encrypt(&key, &nonce1, plaintext);
        let ct2 = encrypt(&key, &nonce2, plaintext);
        assert_ne!(
            ct1, ct2,
            "different nonces must produce different ciphertext"
        );

        // Also verify both decrypt correctly.
        assert_eq!(decrypt(&key, &nonce1, &ct1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &nonce2, &ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let ciphertext = encrypt(&key, &nonce, b"secret");

        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        assert!(
            decrypt(&wrong_key, &nonce, &ciphertext).is_none(),
            "wrong key must not decrypt"
        );
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let ciphertext = encrypt(&key, &nonce, b"secret");

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0xff;
        assert!(
            decrypt(&key, &wrong_nonce, &ciphertext).is_none(),
            "wrong nonce must not decrypt"
        );
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let mut ciphertext = encrypt(&key, &nonce, b"secret");

        // Flip a bit in the ciphertext body (not the tag).
        ciphertext[0] ^= 0x01;
        assert!(
            decrypt(&key, &nonce, &ciphertext).is_none(),
            "corrupted ciphertext must not decrypt"
        );
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = test_key();
        let nonce = test_nonce();
        let ciphertext = encrypt(&key, &nonce, b"");

        // Empty plaintext still produces a TAG_SIZE-byte ciphertext (just the tag).
        assert_eq!(ciphertext.len(), TAG_SIZE);
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("empty decrypt should succeed");
        assert!(decrypted.is_empty());
    }

    // -----------------------------------------------------------------------
    // Nonce increment tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_increment_nonce_basic() {
        let mut nonce = [0u8; NONCE_SIZE];
        increment_nonce(&mut nonce);
        // Last byte becomes 1; all others remain 0.
        assert_eq!(nonce[NONCE_SIZE - 1], 1);
        assert!(nonce[..NONCE_SIZE - 1].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_increment_nonce_carry() {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[NONCE_SIZE - 1] = 0xff;
        increment_nonce(&mut nonce);
        // Last byte wraps to 0 and carry propagates to second-to-last byte.
        assert_eq!(nonce[NONCE_SIZE - 1], 0x00);
        assert_eq!(nonce[NONCE_SIZE - 2], 0x01);
    }

    #[test]
    fn test_increment_nonce_wrap() {
        let mut nonce = [0xffu8; NONCE_SIZE];
        increment_nonce(&mut nonce);
        // All-0xFF wraps entirely to all-0x00.
        assert_eq!(nonce, [0u8; NONCE_SIZE]);
    }
}

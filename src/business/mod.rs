use sha2::{Digest, Sha256};
use std::sync::Arc;

// Re-export panel types
pub use panel_core::{
    BackgroundTasks, StatsCollector as PanelStatsCollector, TaskConfig, UserManager,
};
pub use panel_http::{HttpApiManager as ApiManager, HttpPanelConfig as PanelConfig, IpVersion};

pub type UserId = i64;

/// Mieru uses the raw UUID string as user key
pub type MieruUserManager = UserManager<String>;

/// Identity key — mieru needs raw UUID for PBKDF2
pub fn uuid_key(uuid: &str) -> String {
    uuid.to_string()
}

/// Compute mieru hashedPassword = SHA-256(password + 0x00 + username)
/// where username = password = uuid
pub fn mieru_hashed_password(uuid: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes()); // password
    hasher.update([0x00]);
    hasher.update(uuid.as_bytes()); // username
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Trait for recording traffic stats
pub trait StatsCollector: Send + Sync {
    fn record_upload(&self, user_id: UserId, bytes: u64);
    fn record_download(&self, user_id: UserId, bytes: u64);
    fn record_request(&self, user_id: UserId);
}

/// Bridge panel StatsCollector to our trait
pub struct MieruStatsCollector(pub Arc<PanelStatsCollector>);

impl StatsCollector for MieruStatsCollector {
    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.0.record_upload(user_id, bytes);
    }
    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.0.record_download(user_id, bytes);
    }
    fn record_request(&self, user_id: UserId) {
        self.0.record_request(user_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::{StatsCollector as PanelStatsCollectorType, User};

    fn make_user(id: i64, uuid: &str) -> User {
        User {
            id,
            uuid: uuid.to_string(),
        }
    }

    // ---- mieru_hashed_password tests ----

    #[test]
    fn test_mieru_hashed_password_deterministic() {
        let h1 = mieru_hashed_password("test-uuid");
        let h2 = mieru_hashed_password("test-uuid");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_mieru_hashed_password_different_inputs() {
        let h1 = mieru_hashed_password("uuid-1");
        let h2 = mieru_hashed_password("uuid-2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_mieru_hashed_password_length() {
        let h = mieru_hashed_password("any-uuid");
        assert_eq!(h.len(), 32);
    }

    // ---- UserManager authenticate tests ----

    #[test]
    fn test_user_manager_authenticate() {
        let um: MieruUserManager = UserManager::new(uuid_key);
        let users = vec![make_user(1, "uuid-aaa"), make_user(2, "uuid-bbb")];
        um.init(&users);

        assert_eq!(um.authenticate(&"uuid-aaa".to_string()), Some(1));
        assert_eq!(um.authenticate(&"uuid-bbb".to_string()), Some(2));
    }

    #[test]
    fn test_user_manager_authenticate_invalid() {
        let um: MieruUserManager = UserManager::new(uuid_key);
        let users = vec![make_user(1, "uuid-aaa")];
        um.init(&users);

        assert_eq!(um.authenticate(&"nonexistent".to_string()), None);
    }

    #[test]
    fn test_user_manager_authenticate_empty() {
        let um: MieruUserManager = UserManager::new(uuid_key);
        assert_eq!(um.authenticate(&"anything".to_string()), None);
    }

    #[test]
    fn test_user_manager_hot_reload() {
        let um: MieruUserManager = UserManager::new(uuid_key);
        let initial = vec![make_user(1, "uuid-old"), make_user(2, "uuid-keep")];
        um.init(&initial);

        assert_eq!(um.authenticate(&"uuid-old".to_string()), Some(1));
        assert_eq!(um.authenticate(&"uuid-keep".to_string()), Some(2));

        // Hot reload: remove user 1, add user 3
        let updated = vec![make_user(2, "uuid-keep"), make_user(3, "uuid-new")];
        let diff = um.update(&updated);

        assert_eq!(diff.removed, 1);
        assert_eq!(diff.added, 1);

        // Old user gone, kept user still works, new user works
        assert_eq!(um.authenticate(&"uuid-old".to_string()), None);
        assert_eq!(um.authenticate(&"uuid-keep".to_string()), Some(2));
        assert_eq!(um.authenticate(&"uuid-new".to_string()), Some(3));
    }

    // ---- StatsCollector bridge tests ----

    #[test]
    fn test_stats_bridge() {
        let panel_collector = Arc::new(PanelStatsCollectorType::new());
        let bridge = MieruStatsCollector(Arc::clone(&panel_collector));

        bridge.record_upload(1, 500);
        bridge.record_download(1, 1000);
        bridge.record_request(1);

        let snap = panel_collector.get_stats(1).unwrap();
        assert_eq!(snap.upload_bytes, 500);
        assert_eq!(snap.download_bytes, 1000);
        assert_eq!(snap.request_count, 1);
    }

    #[test]
    fn test_stats_bridge_reset() {
        let panel_collector = Arc::new(PanelStatsCollectorType::new());
        let bridge = MieruStatsCollector(Arc::clone(&panel_collector));

        bridge.record_upload(2, 300);
        bridge.record_download(2, 600);
        bridge.record_request(2);

        // Verify recorded
        let snap = panel_collector.get_stats(2).unwrap();
        assert_eq!(snap.upload_bytes, 300);
        assert_eq!(snap.download_bytes, 600);

        // Reset and verify cleared
        let snapshots = panel_collector.reset_all();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].upload_bytes, 300);
        assert_eq!(snapshots[0].download_bytes, 600);
        assert_eq!(snapshots[0].request_count, 1);

        // After reset, stats should be gone
        assert!(panel_collector.get_stats(2).is_none());
    }
}

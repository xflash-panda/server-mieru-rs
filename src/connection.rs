//! Connection manager: tracks active connections per user, supports kick and drain.

use std::sync::Arc;

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

use crate::business::UserId;

/// Tracks active connections and supports per-user kick and graceful drain.
#[derive(Clone)]
pub struct ConnectionManager {
    /// Maps connection_id → (user_id, cancel_token)
    connections: Arc<DashMap<u64, (UserId, CancellationToken)>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

/// Handle returned when registering a connection. Removes itself on drop.
pub struct ConnectionGuard {
    id: u64,
    connections: Arc<DashMap<u64, (UserId, CancellationToken)>>,
    pub cancel: CancellationToken,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        // Fire the cancel token so dependent tasks (read loop, write task,
        // session relays) observe shutdown when the guard drops. Without this,
        // tasks that select on `cancel.cancelled()` hang until other signals
        // (e.g. broken pipe) fire, leaving sockets in CLOSE-WAIT.
        self.cancel.cancel();
        self.connections.remove(&self.id);
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new connection. Returns a guard that auto-removes on drop.
    pub fn register(&self, user_id: UserId) -> ConnectionGuard {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancel = CancellationToken::new();
        self.connections.insert(id, (user_id, cancel.clone()));
        ConnectionGuard {
            id,
            connections: Arc::clone(&self.connections),
            cancel,
        }
    }

    /// Kick all connections for a specific user. Returns number kicked.
    pub fn kick_user(&self, user_id: UserId) -> usize {
        let mut kicked = 0;
        for entry in self.connections.iter() {
            let (uid, token) = entry.value();
            if *uid == user_id {
                token.cancel();
                kicked += 1;
            }
        }
        kicked
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Cancel all connections and wait up to `timeout` for them to drain.
    pub async fn shutdown_drain(&self, timeout: std::time::Duration) {
        for entry in self.connections.iter() {
            entry.value().1.cancel();
        }
        let start = std::time::Instant::now();
        while !self.connections.is_empty() && start.elapsed() < timeout {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_register_and_drop() {
        let mgr = ConnectionManager::new();
        assert_eq!(mgr.connection_count(), 0);

        let guard = mgr.register(1);
        assert_eq!(mgr.connection_count(), 1);

        drop(guard);
        assert_eq!(mgr.connection_count(), 0);
    }

    #[test]
    fn test_connection_manager_kick_user() {
        let mgr = ConnectionManager::new();
        let g1 = mgr.register(10);
        let g2 = mgr.register(10);
        let g3 = mgr.register(20);

        let kicked = mgr.kick_user(10);
        assert_eq!(kicked, 2);
        assert!(g1.cancel.is_cancelled());
        assert!(g2.cancel.is_cancelled());
        assert!(!g3.cancel.is_cancelled());

        drop(g1);
        drop(g2);
        drop(g3);
    }

    #[test]
    fn test_connection_manager_kick_nonexistent() {
        let mgr = ConnectionManager::new();
        let _g = mgr.register(1);
        assert_eq!(mgr.kick_user(999), 0);
    }

    #[tokio::test]
    async fn test_guard_drop_fires_cancel_token() {
        // Reproduces the CLOSE-WAIT leak: handle_tcp_connection's write_task
        // observes guard.cancel.cancelled() to break its loop. If Drop doesn't
        // fire the cancel, write_task hangs (waiting on outbound_rx.recv()),
        // holding write_half, leaving the inbound TCP socket in CLOSE-WAIT.
        let mgr = ConnectionManager::new();
        let guard = mgr.register(1);
        let cancel = guard.cancel.clone();

        let task = tokio::spawn(async move {
            cancel.cancelled().await;
        });

        drop(guard);

        tokio::time::timeout(std::time::Duration::from_millis(100), task)
            .await
            .expect("dependent task should complete within 100ms after guard drop")
            .expect("dependent task should not panic");
    }

    #[tokio::test]
    async fn test_write_task_pattern_unblocks_on_guard_drop() {
        // Reproduces the EXACT write_task structure from main.rs: a select!
        // loop that picks between outbound_rx.recv() and guard.cancel.cancelled().
        // The outbound_tx is intentionally kept alive (mimicking sessions still
        // holding clones), so outbound_rx.recv() will never return None on its
        // own. The ONLY way the task can exit is via guard cancel.
        //
        // This proves that fix #1 (cancel on guard drop) makes the awkward
        // `tokio::time::timeout(2s, write_task)` pattern in main.rs:466
        // correct in practice — fix B is not required for the CLOSE-WAIT bug.
        let mgr = ConnectionManager::new();
        let guard = mgr.register(1);
        let guard_cancel = guard.cancel.clone();

        let (_outbound_tx_kept_alive, mut outbound_rx) = tokio::sync::mpsc::channel::<()>(8);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = outbound_rx.recv() => {
                        if msg.is_none() { break; }
                    }
                    _ = guard_cancel.cancelled() => break,
                }
            }
        });

        drop(guard);

        tokio::time::timeout(std::time::Duration::from_millis(100), task)
            .await
            .expect("write_task pattern should exit within 100ms after guard drop")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_connection_manager_shutdown_drain() {
        let mgr = ConnectionManager::new();
        let g1 = mgr.register(1);
        let g2 = mgr.register(2);
        assert_eq!(mgr.connection_count(), 2);

        // Spawn tasks that drop guards when cancelled
        let cancel1 = g1.cancel.clone();
        let cancel2 = g2.cancel.clone();
        tokio::spawn(async move {
            cancel1.cancelled().await;
            drop(g1);
        });
        tokio::spawn(async move {
            cancel2.cancelled().await;
            drop(g2);
        });

        mgr.shutdown_drain(std::time::Duration::from_secs(2)).await;
        assert_eq!(mgr.connection_count(), 0);
    }
}

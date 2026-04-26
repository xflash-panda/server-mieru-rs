use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Buffer size for each direction of `copy_bidirectional` relay.
const RELAY_BUF_SIZE: usize = 8 * 1024;

/// Wrapper that counts bytes written through an `AsyncWrite`, used by the
/// idle watchdog to detect stalled connections.
pub(crate) struct CountedWrite<W> {
    inner: W,
    bytes_written: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountedWrite<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            this.bytes_written.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<W: AsyncRead + Unpin> AsyncRead for CountedWrite<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

/// Relay data bidirectionally between `a` and `b` with an idle timeout.
///
/// If no bytes flow in either direction for `idle_timeout`, the relay is
/// terminated. The check polls every `idle_timeout / 10` (minimum 1 s).
pub async fn relay_with_idle_timeout<A, B>(a: A, b: B, idle_timeout: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let upload_bytes = Arc::new(AtomicU64::new(0));
    let download_bytes = Arc::new(AtomicU64::new(0));

    let mut counted_a = CountedWrite {
        inner: a,
        bytes_written: download_bytes.clone(),
    };
    let mut counted_b = CountedWrite {
        inner: b,
        bytes_written: upload_bytes.clone(),
    };

    let idle_watchdog = async {
        let check_interval = std::cmp::max(idle_timeout / 10, Duration::from_secs(1));
        let mut prev_up = upload_bytes.load(Ordering::Relaxed);
        let mut prev_down = download_bytes.load(Ordering::Relaxed);
        let mut idle_since = tokio::time::Instant::now();

        loop {
            tokio::time::sleep(check_interval).await;
            let cur_up = upload_bytes.load(Ordering::Relaxed);
            let cur_down = download_bytes.load(Ordering::Relaxed);
            if cur_up != prev_up || cur_down != prev_down {
                prev_up = cur_up;
                prev_down = cur_down;
                idle_since = tokio::time::Instant::now();
            } else if idle_since.elapsed() >= idle_timeout {
                tracing::debug!("relay idle for {:?}, terminating", idle_timeout);
                return;
            }
        }
    };

    let relay = tokio::io::copy_bidirectional_with_sizes(
        &mut counted_a,
        &mut counted_b,
        RELAY_BUF_SIZE,
        RELAY_BUF_SIZE,
    );

    tokio::select! {
        _ = relay => {}
        _ = idle_watchdog => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_counted_write_tracks_bytes() {
        let (mut client, server) = duplex(1024);
        let counter = Arc::new(AtomicU64::new(0));
        let mut counted = CountedWrite {
            inner: server,
            bytes_written: counter.clone(),
        };

        // Write some bytes through the counted wrapper
        counted.write_all(b"hello").await.unwrap();
        counted.flush().await.unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 5);

        counted.write_all(b"world!").await.unwrap();
        counted.flush().await.unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 11);

        // Verify the data actually passes through
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"helloworld!");
    }

    #[tokio::test]
    async fn test_relay_idle_timeout_terminates() {
        // Two duplex pairs: client ↔ relay_a, relay_b ↔ server
        let (_client, relay_a) = duplex(1024);
        let (relay_b, _server) = duplex(1024);

        // Use a very short idle timeout so the test completes quickly
        let start = tokio::time::Instant::now();
        relay_with_idle_timeout(relay_a, relay_b, Duration::from_millis(100)).await;
        let elapsed = start.elapsed();

        // Should have terminated due to idle timeout, not hang forever.
        // Allow some slack for timer granularity.
        assert!(
            elapsed < Duration::from_secs(5),
            "relay should have terminated due to idle timeout, took {:?}",
            elapsed
        );
        assert!(
            elapsed >= Duration::from_millis(90),
            "relay terminated too early ({:?}), idle watchdog may not have fired",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_relay_data_flows_bidirectionally() {
        let (mut client, relay_a) = duplex(1024);
        let (relay_b, mut server) = duplex(1024);

        let relay_handle = tokio::spawn(async move {
            relay_with_idle_timeout(relay_a, relay_b, Duration::from_secs(5)).await;
        });

        // client → server
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // server → client
        server.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // Close both ends to terminate the relay cleanly
        drop(client);
        drop(server);
        relay_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_active_traffic_prevents_idle_timeout() {
        let (mut client, relay_a) = duplex(1024);
        let (relay_b, mut server) = duplex(1024);

        // 200ms idle timeout
        let idle_timeout = Duration::from_millis(200);
        let relay_handle = tokio::spawn(async move {
            relay_with_idle_timeout(relay_a, relay_b, idle_timeout).await;
        });

        // Send data every 100ms for 500ms — should NOT trigger the 200ms idle timeout
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            client.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            server.read_exact(&mut buf).await.unwrap();
        }

        // Now stop sending — relay should terminate after ~200ms idle
        let idle_start = tokio::time::Instant::now();
        drop(client);
        drop(server);
        relay_handle.await.unwrap();
        let idle_elapsed = idle_start.elapsed();

        // Should not have taken unreasonably long
        assert!(
            idle_elapsed < Duration::from_secs(5),
            "relay did not terminate in time: {:?}",
            idle_elapsed
        );
    }
}

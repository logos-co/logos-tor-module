//! What Tor carried for the apps since the module started, who follows it, and what it
//! costs this computer.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A module that has not asked for Tor's status this long is no longer following it.
pub const FOLLOW_WINDOW_MS: u64 = 90_000;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Byte and stream counts over every SOCKS client.
#[derive(Debug, Default)]
pub struct Usage {
    sent: AtomicU64,
    received: AtomicU64,
    opened: AtomicU64,
    open: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// From the apps into Tor.
    pub sent: u64,
    /// From Tor back to the apps.
    pub received: u64,
    /// Streams Tor opened, and those still open.
    pub opened: u64,
    pub open: u64,
}

impl Usage {
    pub fn counts(&self) -> Counts {
        Counts {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            opened: self.opened.load(Ordering::Relaxed),
            open: self.open.load(Ordering::Relaxed),
        }
    }

    /// Counts a stream as open until the guard drops.
    pub fn open_stream(self: &Arc<Self>) -> OpenStream {
        self.opened.fetch_add(1, Ordering::Relaxed);
        self.open.fetch_add(1, Ordering::Relaxed);
        OpenStream(self.clone())
    }
}

pub struct OpenStream(Arc<Usage>);

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The app's end of a stream, counting what passes through it.
pub struct Counted<S> {
    inner: S,
    usage: Arc<Usage>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, usage: Arc<Usage>) -> Self {
        Self { inner, usage }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            self.usage.sent.fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            self.usage.received.fetch_add(n as u64, Ordering::Relaxed);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Modules that asked for Tor's status lately, by name: the apps following it.
#[derive(Default)]
pub struct Followers(Mutex<HashMap<String, u64>>);

impl Followers {
    pub fn saw(&self, module: &str, at: u64) {
        self.0.lock().unwrap().insert(module.to_string(), at);
    }

    /// `(module, last asked)` for those seen within the window, by name.
    pub fn recent(&self, now: u64) -> Vec<(String, u64)> {
        let mut seen = self.0.lock().unwrap();
        seen.retain(|_, at| now.saturating_sub(*at) <= FOLLOW_WINDOW_MS);
        let mut out: Vec<_> = seen.iter().map(|(m, at)| (m.clone(), *at)).collect();
        out.sort();
        out
    }
}

/// Bytes in the files under `dir`; links are not followed.
pub fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    entries
        .flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// This process's resident memory. A module runs in a process of its own, so this is Tor's.
pub fn memory() -> Option<u64> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let pid = sysinfo::get_current_pid().ok()?;
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), false, ProcessRefreshKind::nothing().with_memory());
    sys.process(pid).map(|p| p.memory())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_both_ways_and_open_streams() {
        let usage = Arc::new(Usage::default());
        let (app, mut far) = tokio::io::duplex(64);
        let mut app = Counted::new(app, usage.clone());
        let open = usage.open_stream();
        far.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        app.read_exact(&mut got).await.unwrap();
        app.write_all(b"hi").await.unwrap();
        assert_eq!(usage.counts(), Counts { sent: 5, received: 2, opened: 1, open: 1 });
        drop(open);
        assert_eq!(usage.counts().open, 0);
        assert_eq!(usage.counts().opened, 1);
    }

    #[test]
    fn followers_age_out() {
        let f = Followers::default();
        f.saw("zcash_node_module", 1_000);
        f.saw("bitcoin_wallet_backend", 50_000);
        assert_eq!(f.recent(60_000).len(), 2);
        assert_eq!(f.recent(1_000 + FOLLOW_WINDOW_MS + 1), vec![("bitcoin_wallet_backend".to_string(), 50_000)]);
        f.saw("zcash_node_module", 100_000);
        assert_eq!(f.recent(100_000).len(), 2);
    }

    #[test]
    fn sizes_a_tree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cache/sub")).unwrap();
        std::fs::write(dir.path().join("state.json"), [0u8; 10]).unwrap();
        std::fs::write(dir.path().join("cache/sub/db"), [0u8; 32]).unwrap();
        assert_eq!(dir_size(dir.path()), 42);
        assert_eq!(dir_size(&dir.path().join("absent")), 0);
    }

    #[test]
    fn reads_this_process_memory() {
        assert!(memory().unwrap_or(0) > 0);
    }
}

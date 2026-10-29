//! What Tor carried since the module started, for which module, and what it costs this
//! computer.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A module that has not asked anything of Tor this long is no longer following it.
pub const FOLLOW_WINDOW_MS: u64 = 90_000;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Bytes into Tor and out of it.
#[derive(Debug, Default)]
pub struct Meter {
    sent: AtomicU64,
    received: AtomicU64,
}

impl Meter {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

/// One module's requests over IPC.
#[derive(Debug, Default)]
pub struct AppMeter {
    pub meter: Arc<Meter>,
    requests: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCounts {
    pub module: String,
    pub sent: u64,
    pub received: u64,
    pub requests: u64,
}

/// Every module's traffic over IPC, the SOCKS port's, and the Tor streams behind both.
#[derive(Debug, Default)]
pub struct Usage {
    /// Programs on the SOCKS port, which have no name Tor could know.
    socks: Arc<Meter>,
    opened: AtomicU64,
    open: AtomicU64,
    apps: Mutex<HashMap<String, Arc<AppMeter>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// From the apps and programs into Tor.
    pub sent: u64,
    /// From Tor back to them.
    pub received: u64,
    /// Tor streams opened, and those still open.
    pub opened: u64,
    pub open: u64,
}

impl Usage {
    pub fn counts(&self) -> Counts {
        let (mut sent, mut received) = (self.socks.sent(), self.socks.received());
        for a in self.apps.lock().unwrap().values() {
            sent += a.meter.sent();
            received += a.meter.received();
        }
        Counts { sent, received, opened: self.opened.load(Ordering::Relaxed), open: self.open.load(Ordering::Relaxed) }
    }

    pub fn socks(&self) -> &Arc<Meter> {
        &self.socks
    }

    /// `module`'s meter, counting one more request.
    pub fn request_by(&self, module: &str) -> Arc<AppMeter> {
        let app = self.apps.lock().unwrap().entry(module.to_string()).or_default().clone();
        app.requests.fetch_add(1, Ordering::Relaxed);
        app
    }

    /// By module name.
    pub fn apps(&self) -> Vec<AppCounts> {
        let mut out: Vec<AppCounts> = self
            .apps
            .lock()
            .unwrap()
            .iter()
            .map(|(m, a)| AppCounts {
                module: m.clone(),
                sent: a.meter.sent(),
                received: a.meter.received(),
                requests: a.requests.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by(|a, b| a.module.cmp(&b.module));
        out
    }

    /// Counts a Tor stream as open until the guard drops.
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

/// Which way the bytes a stream reads go: on the app's end of a SOCKS stream they go into
/// Tor; on Tor's end of a request they come out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reads {
    Sent,
    Received,
}

/// A stream counting what passes through it into a meter.
pub struct Counted<S> {
    inner: S,
    meter: Arc<Meter>,
    reads: Reads,
}

impl<S> Counted<S> {
    pub fn new(inner: S, meter: Arc<Meter>, reads: Reads) -> Self {
        Self { inner, meter, reads }
    }

    fn count(&self, read: bool, n: usize) {
        let into_tor = read == (self.reads == Reads::Sent);
        let way = if into_tor { &self.meter.sent } else { &self.meter.received };
        way.fetch_add(n as u64, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            self.count(true, buf.filled().len() - before);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            self.count(false, n);
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

/// Modules that asked Tor for anything lately, by name: the apps following it.
#[derive(Default)]
pub struct Followers(Mutex<HashMap<String, u64>>);

impl Followers {
    pub fn saw(&self, module: &str, at: u64) {
        self.0.lock().unwrap().insert(module.to_string(), at);
    }

    /// `(module, last asked)` for every module seen, by name.
    pub fn all(&self) -> Vec<(String, u64)> {
        let mut out: Vec<_> = self.0.lock().unwrap().iter().map(|(m, at)| (m.clone(), *at)).collect();
        out.sort();
        out
    }

    /// Those seen within the window.
    pub fn recent(&self, now: u64) -> Vec<(String, u64)> {
        self.all().into_iter().filter(|(_, at)| now.saturating_sub(*at) <= FOLLOW_WINDOW_MS).collect()
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
    async fn counts_each_end_its_own_way() {
        let usage = Arc::new(Usage::default());
        // The app's end of a SOCKS stream: what it reads goes into Tor.
        let (app, mut far) = tokio::io::duplex(64);
        let mut app = Counted::new(app, usage.socks().clone(), Reads::Sent);
        let open = usage.open_stream();
        far.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        app.read_exact(&mut got).await.unwrap();
        app.write_all(b"hi").await.unwrap();
        assert_eq!(usage.counts(), Counts { sent: 5, received: 2, opened: 1, open: 1 });
        drop(open);
        assert_eq!(usage.counts().open, 0);

        // Tor's end of a module's request: what it reads came out of Tor.
        let zcash = usage.request_by("zcash_node_module");
        let (tor, mut far) = tokio::io::duplex(64);
        let mut tor = Counted::new(tor, zcash.meter.clone(), Reads::Received);
        tor.write_all(b"GET").await.unwrap();
        far.write_all(b"200 OK").await.unwrap();
        let mut got = [0u8; 6];
        tor.read_exact(&mut got).await.unwrap();
        usage.request_by("zcash_node_module");
        assert_eq!(
            usage.apps(),
            [AppCounts { module: "zcash_node_module".into(), sent: 3, received: 6, requests: 2 }]
        );
        assert_eq!((usage.counts().sent, usage.counts().received), (8, 8));
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

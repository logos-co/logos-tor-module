//! The running module: a tokio runtime that drives Arti, the SOCKS port, and the status.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;

use crate::socks;
use crate::status::{from_progress, Progress, Sink, State, Status, Tracker};
use crate::tor::{Client, Tor};

/// A join that failed is tried again after this long.
const RETRY: Duration = Duration::from_secs(60);

pub struct Service {
    runtime: Option<Runtime>,
    tracker: Tracker,
    stop: watch::Sender<bool>,
}

impl Service {
    /// Opens the SOCKS port and starts joining Tor, with Arti's files under `dir`. When Tor
    /// cannot start, the status says why and no port opens.
    pub fn start(dir: &Path, sink: Sink) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("tor_module")
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        let tracker = Tracker::new(sink);
        let (stop, stopped) = watch::channel(false);
        let tor = {
            let _in = runtime.enter();
            Tor::create(dir)
        };
        match tor {
            Err(e) => tracker.update(|s| (s.state, s.detail) = (State::Failed, e)),
            Ok(tor) => {
                let listener = runtime
                    .block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
                    .map_err(|e| format!("socks port: {e}"))?;
                let addr = listener.local_addr().map_err(|e| format!("socks port: {e}"))?;
                tracker.update(|s| s.socks = Some(format!("socks5h://{addr}")));
                runtime.spawn(join(tor.client().clone(), tracker.clone()));
                runtime.spawn(socks::serve(listener, Arc::new(tor), stopped));
            }
        }
        Ok(Self { runtime: Some(runtime), tracker, stop })
    }

    pub fn status(&self) -> Status {
        self.tracker.get()
    }

    /// Closes the port and stops Arti, waiting at most `grace`.
    pub fn stop(mut self, grace: Duration) {
        let _ = self.stop.send(true);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(grace);
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Joins Tor and follows Arti's progress.
async fn join(client: Client, tracker: Tracker) {
    let joined = Arc::new(AtomicBool::new(false));
    let mut events = client.bootstrap_events();
    let (follower, seen) = (tracker.clone(), joined.clone());
    tokio::spawn(async move {
        while let Some(s) = events.next().await {
            let (blocked, detail) = (s.blocked().map(|b| b.to_string()), s.to_string());
            let progress = Progress { fraction: s.as_frac(), ready: s.ready_for_traffic(), blocked: blocked.as_deref(), detail: &detail };
            let (state, pct, detail) = from_progress(&progress, seen.load(Ordering::Relaxed));
            follower.update(|st| (st.state, st.progress, st.detail) = (state, pct, detail));
        }
    });
    loop {
        match client.bootstrap().await {
            Ok(()) => {
                joined.store(true, Ordering::Relaxed);
                tracker.update(|s| {
                    if s.state != State::Blocked {
                        (s.state, s.progress) = (State::Ready, 100);
                    }
                });
                return;
            }
            Err(e) => {
                tracker.update(|s| (s.state, s.detail) = (State::Failed, e.to_string()));
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

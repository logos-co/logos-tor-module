//! The running module: the SOCKS port, and Arti in a tokio runtime behind it. The port
//! outlives each run of Arti, so reconnecting and forgetting Tor's data keep it. Arti joins
//! the Tor network only once something asks for it: an app's status() call, a connection,
//! or the user.

use std::future::Future;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tor_socksproto::SocksStatus;

use crate::socks::{self, Dial, Dialed, Target};
use crate::status::{from_progress, Progress, Sink, State, Status, Tracker};
use crate::tor::{Client, Tor};
use crate::usage::{now_ms, Counts, Usage};

/// A join that failed is tried again after this long.
const RETRY: Duration = Duration::from_secs(60);

/// What a reconnect gives the old run to stop: blocking work past it is left to finish.
const RESTART_GRACE: Duration = Duration::from_millis(500);

/// What answers behind the SOCKS port: Arti in the module, a fake in tests.
pub trait Engine: Send + Sync + 'static {
    /// Opens Tor with its files under `dir`, without joining. Runs inside the run's runtime.
    fn launch(&self, dir: &Path, tracker: &Tracker) -> Result<Arc<dyn Backend>, String>;
}

/// Tor behind the port.
pub trait Backend: Dial {
    /// Starts joining the Tor network unless it has. Runs inside the run's runtime.
    fn wake(&self);
}

pub struct Arti;

impl Engine for Arti {
    fn launch(&self, dir: &Path, tracker: &Tracker) -> Result<Arc<dyn Backend>, String> {
        Ok(Arc::new(ArtiBackend { tor: Tor::create(dir)?, tracker: tracker.clone(), woken: AtomicBool::new(false) }))
    }
}

struct ArtiBackend {
    tor: Tor,
    tracker: Tracker,
    woken: AtomicBool,
}

impl Backend for ArtiBackend {
    fn wake(&self) {
        if !self.woken.swap(true, Ordering::SeqCst) {
            if self.tracker.get().state == State::Idle {
                self.tracker.relaunch("starting");
            }
            tokio::spawn(join(self.tor.client().clone(), self.tracker.clone()));
        }
    }
}

impl Dial for ArtiBackend {
    fn dial(&self, target: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        self.wake();
        self.tor.dial(target)
    }
}

/// Answers every client with why Tor is not running.
struct Down(String);

impl Backend for Down {
    fn wake(&self) {}
}

impl Dial for Down {
    fn dial(&self, _: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        Box::pin(async move { Err((SocksStatus::GENERAL_FAILURE, self.0.clone())) })
    }
}

struct Run {
    runtime: Runtime,
    stop: watch::Sender<bool>,
    backend: Arc<dyn Backend>,
}

impl Run {
    fn wake(&self) {
        let _in = self.runtime.enter();
        self.backend.wake();
    }
}

impl Run {
    fn stop(self, grace: Duration) {
        let _ = self.stop.send(true);
        self.runtime.shutdown_timeout(grace);
    }
}

pub struct Service {
    dir: PathBuf,
    engine: Arc<dyn Engine>,
    tracker: Tracker,
    usage: Arc<Usage>,
    /// Bound once, each run serving a handle to it; stop() closes it.
    listener: Mutex<Option<std::net::TcpListener>>,
    run: Mutex<Option<Run>>,
    stopped: AtomicBool,
    started_at: u64,
}

impl Service {
    /// Opens the SOCKS port, with Arti's files under `dir`; Tor joins once something asks.
    /// When Tor cannot start, the status says why and the port answers each client with a
    /// failure.
    pub fn start(dir: &Path, sink: Sink) -> Result<Self, String> {
        Self::start_with(dir, sink, Arc::new(Arti))
    }

    pub fn start_with(dir: &Path, sink: Sink, engine: Arc<dyn Engine>) -> Result<Self, String> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| format!("socks port: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| format!("socks port: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("socks port: {e}"))?;
        let tracker = Tracker::new(sink);
        tracker.update(|s| s.socks = Some(format!("socks5h://{addr}")));
        let service = Self {
            dir: dir.to_path_buf(),
            engine,
            tracker,
            usage: Arc::default(),
            listener: Mutex::new(Some(listener)),
            run: Mutex::new(None),
            stopped: AtomicBool::new(false),
            started_at: now_ms(),
        };
        let run = service.launch()?;
        *service.run.lock().unwrap() = Some(run);
        Ok(service)
    }

    fn launch(&self) -> Result<Run, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("tor_module")
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        let (stop, stopped) = watch::channel(false);
        let backend = {
            let _in = runtime.enter();
            let listener = match self.listener.lock().unwrap().as_ref() {
                Some(l) => l.try_clone().and_then(TcpListener::from_std).map_err(|e| format!("socks port: {e}"))?,
                None => return Err("stopped".into()),
            };
            let backend = self.engine.launch(&self.dir, &self.tracker).unwrap_or_else(|e| {
                self.tracker.update(|s| (s.state, s.detail) = (State::Failed, e.clone()));
                Arc::new(Down(e))
            });
            runtime.spawn(socks::serve(listener, backend.clone(), stopped, self.usage.clone()));
            backend
        };
        Ok(Run { runtime, stop, backend })
    }

    /// Starts joining Tor unless it has: an app asked for it. A reconnect in progress
    /// joins anyway, so this does not wait for it.
    pub fn demand(&self) {
        if let Ok(run) = self.run.try_lock() {
            if let Some(run) = run.as_ref() {
                run.wake();
            }
        }
    }

    pub fn status(&self) -> Status {
        self.tracker.get()
    }

    pub fn usage(&self) -> Counts {
        self.usage.counts()
    }

    /// Unix milliseconds when the module started Tor the first time.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Arti's files: `state/` (the entry guards it picked) and `cache/` (the directory).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Stops Arti and starts it again on the same port, joining at once; streams open now
    /// end. With `forget`, Arti's state and cache go in between, so it picks new entry guards
    /// and downloads the directory again. Returns once the new run is joining; an error from
    /// deleting the files is returned after Tor started again.
    pub fn reconnect(&self, forget: bool) -> Result<(), String> {
        let mut run = self.run.lock().unwrap();
        if self.stopped.load(Ordering::SeqCst) {
            return Err("stopped".into());
        }
        // The old run stops first, so no late event of its own overwrites the new status.
        if let Some(old) = run.take() {
            old.stop(RESTART_GRACE);
        }
        self.tracker.relaunch(if forget { "forgetting Tor's data" } else { "reconnecting" });
        let forgot = if forget { forget_files(&self.dir) } else { Ok(()) };
        let new = self.launch()?;
        new.wake();
        *run = Some(new);
        forgot
    }

    /// Closes the port and stops Arti, waiting at most `grace`. A reconnect in progress
    /// finishes first.
    pub fn stop(&self, grace: Duration) {
        self.stopped.store(true, Ordering::SeqCst);
        let run = self.run.lock().unwrap().take();
        self.listener.lock().unwrap().take();
        if let Some(run) = run {
            run.stop(grace);
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(run) = self.run.get_mut().unwrap().take() {
            run.runtime.shutdown_background();
        }
    }
}

fn forget_files(dir: &Path) -> Result<(), String> {
    for sub in ["state", "cache"] {
        let d = dir.join(sub);
        match std::fs::remove_dir_all(&d) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", d.display())),
            _ => {}
        }
    }
    Ok(())
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

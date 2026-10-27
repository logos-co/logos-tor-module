//! The running module: Arti in a tokio runtime, which modules reach with requests over IPC
//! and, when the user turns it on, other programs reach through a SOCKS port. Arti joins the
//! Tor network only once something asks for it: an app's status() call or request, a SOCKS
//! client, or the user. The SOCKS port outlives each run of Arti, so a reconnect keeps it.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::{oneshot, watch};
use tor_socksproto::SocksStatus;

use crate::http::{self, Pool, Prepared, Spec};
use crate::requests::{Polled, Requests, PER_MODULE};
use crate::socks::{self, Dial, Dialed, Target};
use crate::status::{from_progress, Progress, Sink, State, Status, Tracker};
use crate::tor::{Client, Tor};
use crate::usage::{now_ms, AppCounts, Counts, Meter, Usage};

/// A join that failed is tried again after this long.
const RETRY: Duration = Duration::from_secs(60);

/// What a reconnect gives the old run to stop: blocking work past it is left to finish.
const RESTART_GRACE: Duration = Duration::from_millis(500);

/// Where the SOCKS port listens when the user turns it on and names no address: clear of a
/// system Tor's 9050 and Tor Browser's 9150.
pub const DEFAULT_SOCKS: &str = "127.0.0.1:9250";

/// What answers behind the IPC requests and the SOCKS port: Arti in the module, a fake in tests.
pub trait Engine: Send + Sync + 'static {
    /// Opens Tor with its files under `dir`, without joining. Runs inside the run's runtime.
    fn launch(&self, dir: &Path, tracker: &Tracker) -> Result<Arc<dyn Backend>, String>;

    /// The roots TLS requests trust: the Mozilla set, unless a test brings its own.
    fn roots(&self) -> rustls::RootCertStore {
        http::webpki_roots()
    }
}

/// Tor, as the requests and the SOCKS port reach it.
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

/// Answers every connection with why Tor is not running.
struct Down(String);

impl Backend for Down {
    fn wake(&self) {}
}

impl Dial for Down {
    fn dial(&self, _: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        Box::pin(async move { Err((SocksStatus::GENERAL_FAILURE, self.0.clone())) })
    }
}

/// The SOCKS port setting: off unless the user turns it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocksSetting {
    pub enabled: bool,
    pub address: String,
}

impl Default for SocksSetting {
    fn default() -> Self {
        Self { enabled: false, address: DEFAULT_SOCKS.into() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    #[serde(default)]
    socks: SocksSetting,
}

/// The SOCKS port as it is: the setting, where it listens, or why it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksState {
    pub setting: SocksSetting,
    pub listening: Option<SocketAddr>,
    pub error: Option<String>,
}

struct Socks {
    setting: SocksSetting,
    listener: Option<std::net::TcpListener>,
    error: Option<String>,
}

fn bind(address: SocketAddr) -> Result<std::net::TcpListener, String> {
    let listener = std::net::TcpListener::bind(address).map_err(|e| format!("cannot listen on {address}: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| format!("cannot listen on {address}: {e}"))?;
    Ok(listener)
}

fn socks_url(listener: &std::net::TcpListener) -> Option<String> {
    listener.local_addr().ok().map(|a| format!("socks5h://{a}"))
}

struct Run {
    runtime: Runtime,
    backend: Arc<dyn Backend>,
    http: Arc<http::Ctx>,
    socks_stop: Option<watch::Sender<bool>>,
}

impl Run {
    fn wake(&self) {
        let _in = self.runtime.enter();
        self.backend.wake();
    }

    fn stop_socks(&mut self) {
        if let Some(stop) = self.socks_stop.take() {
            let _ = stop.send(true);
        }
    }

    /// Serves a handle to `listener`, in place of any port served before.
    fn serve_socks(&mut self, listener: &std::net::TcpListener, usage: &Arc<Usage>) -> Result<(), String> {
        self.stop_socks();
        let _in = self.runtime.enter();
        let handle = listener.try_clone().and_then(TcpListener::from_std).map_err(|e| format!("socks port: {e}"))?;
        let (stop, stopped) = watch::channel(false);
        self.runtime.spawn(socks::serve(handle, self.backend.clone(), stopped, usage.clone()));
        self.socks_stop = Some(stop);
        Ok(())
    }

    fn stop(mut self, grace: Duration) {
        self.stop_socks();
        self.runtime.shutdown_timeout(grace);
    }
}

pub struct Service {
    dir: PathBuf,
    settings: Option<PathBuf>,
    engine: Arc<dyn Engine>,
    tls: Arc<rustls::ClientConfig>,
    tracker: Tracker,
    usage: Arc<Usage>,
    requests: Requests,
    run: Mutex<Option<Run>>,
    // Locked after `run` wherever both are held.
    socks: Mutex<Socks>,
    stopped: AtomicBool,
    started_at: u64,
}

impl Service {
    /// Opens Tor with its files under `dir`; it joins once something asks. The SOCKS port
    /// opens when `settings` says so. When Tor cannot start, the status says why and every
    /// request and SOCKS client is answered with a failure.
    pub fn start(dir: &Path, settings: Option<PathBuf>, sink: Sink) -> Result<Self, String> {
        Self::start_with(dir, settings, sink, Arc::new(Arti))
    }

    pub fn start_with(dir: &Path, settings: Option<PathBuf>, sink: Sink, engine: Arc<dyn Engine>) -> Result<Self, String> {
        let saved: Settings = settings
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let tracker = Tracker::new(sink);
        let mut socks = Socks { setting: saved.socks, listener: None, error: None };
        if socks.setting.enabled {
            match socks.setting.address.parse::<SocketAddr>().map_err(|_| format!("bad address {}", socks.setting.address)).and_then(bind) {
                Ok(l) => socks.listener = Some(l),
                Err(e) => socks.error = Some(e),
            }
        }
        if let Some(url) = socks.listener.as_ref().and_then(socks_url) {
            tracker.update(|s| s.socks = Some(url));
        }
        let service = Self {
            dir: dir.to_path_buf(),
            settings,
            tls: http::tls_config(engine.roots())?,
            engine,
            tracker,
            usage: Arc::default(),
            requests: Requests::default(),
            run: Mutex::new(None),
            socks: Mutex::new(socks),
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
        let backend = {
            let _in = runtime.enter();
            self.engine.launch(&self.dir, &self.tracker).unwrap_or_else(|e| {
                self.tracker.update(|s| (s.state, s.detail) = (State::Failed, e.clone()));
                Arc::new(Down(e))
            })
        };
        let http = Arc::new(http::Ctx { dialer: backend.clone(), tls: self.tls.clone(), pool: Pool::default(), usage: self.usage.clone() });
        let mut run = Run { runtime, backend, http, socks_stop: None };
        if let Some(listener) = self.socks.lock().unwrap().listener.as_ref() {
            run.serve_socks(listener, &self.usage)?;
        }
        Ok(run)
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

    /// Starts `spec` for `owner` and returns the id its response is asked for by. Tor joins
    /// first if it has not.
    pub fn request(&self, owner: &str, spec: Spec, body: Vec<u8>) -> Result<String, String> {
        let prepared = Prepared::new(spec, body.len())?;
        if self.requests.in_flight(owner) >= PER_MODULE {
            return Err(format!("too many requests in flight (at most {PER_MODULE} per module)"));
        }
        let timeout = prepared.timeout;
        let run = self.run.lock().unwrap();
        let run = run.as_ref().ok_or("Tor is not running")?;
        run.wake();
        let (tx, rx) = oneshot::channel();
        let (ctx, who, app) = (run.http.clone(), owner.to_string(), self.usage.request_by(owner));
        let task = run.runtime.spawn(async move {
            let _ = tx.send(http::send(ctx, who, prepared, body, app).await);
        });
        self.requests.add(owner, timeout, rx, task.abort_handle())
    }

    /// None when `owner` started no such request; a finished one is handed over once.
    pub fn response(&self, owner: &str, id: &str) -> Option<Polled> {
        self.requests.poll(owner, id)
    }

    pub fn cancel(&self, owner: &str, id: &str) -> bool {
        self.requests.cancel(owner, id)
    }

    pub fn status(&self) -> Status {
        self.tracker.get()
    }

    pub fn usage(&self) -> Counts {
        self.usage.counts()
    }

    pub fn apps(&self) -> Vec<AppCounts> {
        self.usage.apps()
    }

    pub fn socks_traffic(&self) -> &Meter {
        self.usage.socks()
    }

    /// Unix milliseconds when the module started Tor the first time.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Arti's files: `state/` (the entry guards it picked) and `cache/` (the directory).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn socks(&self) -> SocksState {
        let s = self.socks.lock().unwrap();
        SocksState {
            setting: s.setting.clone(),
            listening: s.listener.as_ref().and_then(|l| l.local_addr().ok()),
            error: s.error.clone(),
        }
    }

    /// Opens the SOCKS port at `address`, or closes it, and saves the choice. An address
    /// that cannot be listened on is refused and the port stays as it was.
    pub fn set_socks(&self, enabled: bool, address: &str) -> Result<SocksState, String> {
        let address = address.trim();
        let wanted: SocketAddr = address.parse().map_err(|_| format!("{address} is not an IP address and a port"))?;
        let mut run = self.run.lock().unwrap();
        if self.stopped.load(Ordering::SeqCst) {
            return Err("stopped".into());
        }
        let mut socks = self.socks.lock().unwrap();
        let current = socks.listener.as_ref().and_then(|l| l.local_addr().ok());
        let listener = match (enabled, socks.listener.take()) {
            (false, _) => None,
            // Already there: binding again would find our own port taken.
            (true, Some(l)) if current == Some(wanted) || (wanted.port() == 0 && current.map(|c| c.ip()) == Some(wanted.ip())) => Some(l),
            (true, old) => match bind(wanted) {
                Ok(l) => Some(l),
                Err(e) => {
                    socks.listener = old;
                    return Err(e);
                }
            },
        };
        if let Some(run) = run.as_mut() {
            run.stop_socks();
            if let Some(l) = listener.as_ref() {
                run.serve_socks(l, &self.usage)?;
            }
        }
        let url = listener.as_ref().and_then(socks_url);
        (socks.listener, socks.setting, socks.error) = (listener, SocksSetting { enabled, address: address.to_string() }, None);
        let saved = Settings { socks: socks.setting.clone() };
        drop(socks);
        drop(run);
        self.tracker.update(|s| s.socks = url);
        if let Some(path) = &self.settings {
            let text = serde_json::to_string_pretty(&saved).map_err(|e| e.to_string())?;
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, path)).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(self.socks())
    }

    /// Stops Arti and starts it again, joining at once; requests and SOCKS streams in flight
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

    /// Closes the SOCKS port and stops Arti, waiting at most `grace`. A reconnect in progress
    /// finishes first.
    pub fn stop(&self, grace: Duration) {
        self.stopped.store(true, Ordering::SeqCst);
        let run = self.run.lock().unwrap().take();
        self.socks.lock().unwrap().listener.take();
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

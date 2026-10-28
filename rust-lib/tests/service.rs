//! The service around a fake Tor, offline: the port across reconnects, the counts, the
//! files forgotten, and a Tor that cannot start.

mod common;

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{ping, Echo};
use logos_tor::service::{Backend, Engine, Service};
use logos_tor::socks::{Dial, Dialed, Target};
use logos_tor::status::{State, Status, Tracker};
use logos_tor::usage::Counts;
use tokio::io::AsyncReadExt;
use tokio_socks::tcp::Socks5Stream;

/// A Tor that is ready as soon as something wakes it, unless it fails to open.
#[derive(Default)]
struct Fake {
    launches: AtomicUsize,
    fail: bool,
}

impl Engine for Fake {
    fn launch(&self, dir: &Path, tracker: &Tracker) -> Result<Arc<dyn Backend>, String> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err("no Tor here".into());
        }
        for sub in ["state", "cache"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Ok(Arc::new(FakeTor { echo: Echo::default(), tracker: tracker.clone(), woken: AtomicBool::new(false) }))
    }
}

struct FakeTor {
    echo: Echo,
    tracker: Tracker,
    woken: AtomicBool,
}

impl Backend for FakeTor {
    fn wake(&self) {
        if !self.woken.swap(true, Ordering::SeqCst) {
            self.tracker.update(|s| (s.state, s.progress) = (State::Ready, 100));
        }
    }
}

impl Dial for FakeTor {
    fn dial(&self, target: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        self.wake();
        self.echo.dial(target)
    }
}

type Heard = Arc<Mutex<Vec<Status>>>;

fn start(dir: &Path, fake: Arc<Fake>) -> (Service, Heard) {
    let heard: Heard = Arc::default();
    let log = heard.clone();
    let service = Service::start_with(dir, Arc::new(move |s| log.lock().unwrap().push(s.clone())), fake).unwrap();
    (service, heard)
}

fn proxy(service: &Service) -> String {
    service.status().socks.unwrap().trim_start_matches("socks5h://").to_string()
}

/// The SOCKS relay counts bytes once it has passed them on, on the service's own threads, so
/// a client can read them before they are counted.
fn settled(service: &Service, done: impl Fn(&Counts) -> bool) -> Counts {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let c = service.usage();
        if done(&c) || Instant::now() >= until {
            return c;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn client() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

#[test]
fn a_reconnect_keeps_the_port_and_the_counts() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(Fake::default());
    let (service, heard) = start(dir.path(), fake.clone());
    let (addr, rt) = (proxy(&service), client());
    service.demand();
    assert_eq!(service.status().state, State::Ready);

    let mut held = rt.block_on(Socks5Stream::connect(addr.as_str(), ("zec.rocks", 443))).unwrap();
    assert_eq!(&rt.block_on(ping(&mut held)), b"ping");
    assert_eq!(settled(&service, |c| c.received == 4), Counts { sent: 4, received: 4, opened: 1, open: 1 });

    service.reconnect(false).unwrap();
    assert_eq!(fake.launches.load(Ordering::SeqCst), 2);
    assert_eq!(proxy(&service), addr, "the same port");
    let states: Vec<_> = heard.lock().unwrap().iter().map(|s| s.state).collect();
    assert_eq!(states[states.len() - 2..], [State::Connecting, State::Ready], "{states:?}");

    // The stream from the old run ended with it.
    let mut rest = Vec::new();
    let ended = rt.block_on(async { tokio::time::timeout(Duration::from_secs(5), held.read_to_end(&mut rest)).await });
    assert!(matches!(ended, Ok(Ok(0)) | Ok(Err(_))), "{ended:?}");

    let mut again = rt.block_on(Socks5Stream::connect(addr.as_str(), ("zec.rocks", 443))).unwrap();
    assert_eq!(&rt.block_on(ping(&mut again)), b"ping");
    let c = settled(&service, |c| c.received == 8);
    assert_eq!((c.sent, c.received, c.opened), (8, 8, 2), "counted since the module started");
    service.stop(Duration::from_millis(500));
}

#[test]
fn tor_waits_until_an_app_asks_or_connects() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = start(dir.path(), Arc::new(Fake::default()));
    assert_eq!(service.status().state, State::Idle, "nothing asked yet");
    assert!(service.status().socks.is_some(), "the port listens while idle");
    service.demand();
    assert_eq!(service.status().state, State::Ready);
    service.stop(Duration::from_millis(500));

    let (service, _) = start(dir.path(), Arc::new(Fake::default()));
    let rt = client();
    let mut s = rt.block_on(Socks5Stream::connect(proxy(&service).as_str(), ("zec.rocks", 443))).unwrap();
    assert_eq!(&rt.block_on(ping(&mut s)), b"ping");
    assert_eq!(service.status().state, State::Ready, "a connection wakes it too");
    service.stop(Duration::from_millis(500));
}

#[test]
fn a_reconnect_starts_an_idle_tor() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = start(dir.path(), Arc::new(Fake::default()));
    service.reconnect(false).unwrap();
    assert_eq!(service.status().state, State::Ready);
    service.stop(Duration::from_millis(500));
}

#[test]
fn forgetting_deletes_the_state_and_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = start(dir.path(), Arc::new(Fake::default()));
    std::fs::write(dir.path().join("state/guards"), b"g").unwrap();
    std::fs::write(dir.path().join("cache/dir_blobs"), b"d").unwrap();
    std::fs::write(dir.path().join("keep.json"), b"k").unwrap();
    service.reconnect(true).unwrap();
    assert!(!dir.path().join("state/guards").exists() && !dir.path().join("cache/dir_blobs").exists());
    assert!(dir.path().join("keep.json").exists(), "only Arti's two directories go");
    assert_eq!(service.status().state, State::Ready);
    service.stop(Duration::from_millis(500));
}

#[test]
fn a_tor_that_cannot_start_fails_each_client() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = start(dir.path(), Arc::new(Fake { fail: true, ..Default::default() }));
    let st = service.status();
    assert_eq!((st.state, st.detail.as_str()), (State::Failed, "no Tor here"));
    let rt = client();
    let refused = rt.block_on(Socks5Stream::connect(proxy(&service).as_str(), ("zec.rocks", 443)));
    assert!(matches!(refused, Err(tokio_socks::Error::GeneralSocksServerFailure)), "{refused:?}");
    service.stop(Duration::from_millis(500));
}

#[test]
fn after_stop_the_port_is_closed_and_reconnect_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = start(dir.path(), Arc::new(Fake::default()));
    let addr = proxy(&service);
    service.stop(Duration::from_millis(500));
    assert_eq!(service.reconnect(false), Err("stopped".to_string()));
    assert!(std::net::TcpStream::connect(addr.as_str()).is_err(), "the port still accepts");
}

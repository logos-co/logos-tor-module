//! Joins the real Tor network; ignored by default. Run with
//! cargo test --no-default-features --test live -- --ignored --nocapture

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use logos_tor::service::Service;
use logos_tor::status::{State, Status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_socks::tcp::Socks5Stream;

/// torproject.org's onion service.
const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

async fn http_head(proxy: &str, host: &str, user: &str) -> String {
    let mut s = Socks5Stream::connect_with_password(proxy, (host, 80), user, "x").await.unwrap();
    s.write_all(format!("HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut first = vec![0u8; 12];
    s.read_exact(&mut first).await.unwrap();
    String::from_utf8_lossy(&first).into_owned()
}

#[test]
#[ignore]
fn joins_tor_and_reaches_a_site_and_an_onion() {
    let dir = tempfile::tempdir().unwrap();
    let heard: Arc<Mutex<Vec<Status>>> = Arc::default();
    let log = heard.clone();
    let t0 = Instant::now();
    let service = Service::start(dir.path(), Arc::new(move |s| log.lock().unwrap().push(s.clone()))).unwrap();
    while service.status().state != State::Ready {
        assert!(t0.elapsed() < Duration::from_secs(180), "not ready: {:?}", service.status());
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("ready in {:.1}s after {} status events", t0.elapsed().as_secs_f64(), heard.lock().unwrap().len());
    let proxy = service.status().socks.unwrap().trim_start_matches("socks5h://").to_string();

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for (host, user) in [("example.com", "one"), (ONION, "two")] {
        let t = Instant::now();
        let head = rt.block_on(http_head(&proxy, host, user));
        println!("{host}: {head:?} in {:.1}s", t.elapsed().as_secs_f64());
        assert!(head.starts_with("HTTP/1."), "{host}: {head:?}");
    }

    let t = Instant::now();
    service.stop(Duration::from_millis(1500));
    assert!(t.elapsed() < Duration::from_secs(2), "stop took {:?}", t.elapsed());
}

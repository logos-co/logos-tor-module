//! Joins the real Tor network, three times (the last one cold, about 7 MB), and reaches it
//! through the SOCKS port and with requests; ignored by default. Run with
//! cargo test --no-default-features --test live -- --ignored --nocapture

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use logos_tor::requests::Polled;
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
    let service = Service::start(dir.path(), None, Arc::new(move |s| log.lock().unwrap().push(s.clone()))).unwrap();
    assert_eq!(service.status().state, State::Idle);
    service.set_socks(true, "127.0.0.1:0").unwrap();
    service.demand();
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

    // Requests over IPC: gRPC over HTTP/2 to a lightwalletd server, then the onion service.
    let ask = |owner: &str, spec: serde_json::Value, body: &[u8]| {
        let t = Instant::now();
        let id = service.request(owner, serde_json::from_value(spec).unwrap(), body.to_vec()).unwrap();
        loop {
            match service.response(owner, &id) {
                Some(Polled::Pending) => std::thread::sleep(Duration::from_millis(50)),
                Some(Polled::Done(answer)) => break (answer.unwrap(), t.elapsed()),
                None => panic!("lost {id}"),
            }
        }
    };
    let grpc = serde_json::json!({
        "method": "POST", "url": "https://testnet.zec.rocks/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
        "http2": true, "isolation": "grpc", "headers": [["content-type", "application/grpc"], ["te", "trailers"]],
    });
    let (info, took) = ask("zcash_node_module", grpc.clone(), &[0, 0, 0, 0, 0]);
    println!("GetLightdInfo: {} {:?}, {} bytes in {:.1}s", info.status, info.trailers, info.body.len(), took.as_secs_f64());
    assert!(info.status == 200 && info.trailers.contains(&("grpc-status".into(), "0".into())) && info.body.len() > 5);
    let (_, again) = ask("zcash_node_module", grpc, &[0, 0, 0, 0, 0]);
    println!("again on the same key and connection in {:.1}s", again.as_secs_f64());
    let (page, took) = ask("live_test", serde_json::json!({ "url": format!("http://{ONION}/") }), b"");
    println!("{ONION} over HTTP/1.1: {} in {:.1}s", page.status, took.as_secs_f64());
    assert!((200..400).contains(&page.status));
    println!("by module: {:?}", service.apps());

    // Again on the same port: warm after a reconnect, cold after forgetting Tor's data.
    for forget in [false, true] {
        let t = Instant::now();
        service.reconnect(forget).unwrap();
        while service.status().state != State::Ready {
            assert!(t.elapsed() < Duration::from_secs(180), "not ready again: {:?}", service.status());
            std::thread::sleep(Duration::from_millis(200));
        }
        let st = service.status();
        println!("forget={forget}: ready again in {:.1}s (joinMs {:?})", t.elapsed().as_secs_f64(), st.join_ms);
        assert_eq!(st.socks.unwrap().trim_start_matches("socks5h://"), proxy);
        let head = rt.block_on(http_head(&proxy, "example.com", if forget { "four" } else { "three" }));
        assert!(head.starts_with("HTTP/1."), "{head:?}");
    }
    let c = service.usage();
    println!("sent {} B, received {} B over {} streams", c.sent, c.received, c.opened);
    assert_eq!(c.opened, 6);

    let t = Instant::now();
    service.stop(Duration::from_millis(1500));
    assert!(t.elapsed() < Duration::from_secs(2), "stop took {:?}", t.elapsed());
}

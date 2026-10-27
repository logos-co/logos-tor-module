//! Requests over IPC against a fake Tor whose far side is an in-process TLS, HTTP/1.1 and
//! HTTP/2 server, offline: the protocols, gRPC's trailers, the circuits each module and key
//! get, who may read an answer, and the failures.

use std::convert::Infallible;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use logos_tor::http::Spec;
use logos_tor::requests::Polled;
use logos_tor::service::{Backend, Engine, Service};
use logos_tor::socks::{Dial, Dialed, Stream, Target};
use logos_tor::status::{State, Tracker};
use logos_tor::tor::Isolation;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

struct Far {
    /// Offers h2 and http/1.1.
    tls: Arc<rustls::ServerConfig>,
    /// Offers http/1.1 only, as old.example.
    tls_h1: Arc<rustls::ServerConfig>,
    roots: rustls::RootCertStore,
    dials: Mutex<Vec<Target>>,
}

impl Far {
    fn new() -> Arc<Self> {
        let names = vec!["zec.example".to_string(), "old.example".to_string(), "slow.example".to_string()];
        let made = rcgen::generate_simple_self_signed(names).unwrap();
        let der = made.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(made.key_pair.serialize_der().into());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let config = |alpn: &[&[u8]]| {
            let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![der.clone()], key.clone_key())
                .unwrap();
            c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            Arc::new(c)
        };
        Arc::new(Self { tls: config(&[b"h2", b"http/1.1"]), tls_h1: config(&[b"http/1.1"]), roots, dials: Mutex::default() })
    }

    fn dials(&self) -> Vec<Target> {
        self.dials.lock().unwrap().clone()
    }
}

type Body = BoxBody<Bytes, Infallible>;

/// Echoes the request as text; `/grpc` echoes the body with gRPC's trailers; `/slow` never answers.
async fn answer(req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let (parts, body) = req.into_parts();
    if parts.uri.path() == "/slow" {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
    let body = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
    if parts.uri.path() == "/grpc" {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        let frames = vec![Ok::<_, Infallible>(Frame::data(body)), Ok(Frame::trailers(trailers))];
        let streamed = StreamBody::new(futures::stream::iter(frames)).boxed();
        return Ok(Response::builder().header("content-type", "application/grpc").body(streamed).unwrap());
    }
    let test = parts.headers.get("x-test").map(|v| v.to_str().unwrap().to_string()).unwrap_or("-".into());
    let text = format!("{} {} {:?} {} {}", parts.method, parts.uri.path(), parts.version, test, String::from_utf8_lossy(&body));
    Ok(Response::new(Full::new(Bytes::from(text)).boxed()))
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: S) {
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), hyper::service::service_fn(answer))
        .await;
}

struct FarTor {
    far: Arc<Far>,
    tracker: Tracker,
}

impl Backend for FarTor {
    fn wake(&self) {
        self.tracker.update(|s| (s.state, s.progress) = (State::Ready, 100));
    }
}

impl Dial for FarTor {
    fn dial(&self, target: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        self.far.dials.lock().unwrap().push(target.clone());
        let tls = match (target.port, target.host.as_str()) {
            (443, "old.example") => Some(self.far.tls_h1.clone()),
            (443, _) => Some(self.far.tls.clone()),
            _ => None,
        };
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                match tls {
                    Some(config) => {
                        if let Ok(s) = tokio_rustls::TlsAcceptor::from(config).accept(theirs).await {
                            serve(s).await;
                        }
                    }
                    None => serve(theirs).await,
                }
            });
            Ok(Box::new(ours) as Box<dyn Stream>)
        })
    }
}

struct Fake(Arc<Far>);

impl Engine for Fake {
    fn launch(&self, _dir: &Path, tracker: &Tracker) -> Result<Arc<dyn Backend>, String> {
        Ok(Arc::new(FarTor { far: self.0.clone(), tracker: tracker.clone() }))
    }

    fn roots(&self) -> rustls::RootCertStore {
        self.0.roots.clone()
    }
}

fn start() -> (Service, Arc<Far>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let far = Far::new();
    let service = Service::start_with(dir.path(), None, Arc::new(|_| {}), Arc::new(Fake(far.clone()))).unwrap();
    (service, far, dir)
}

fn spec(v: serde_json::Value) -> Spec {
    serde_json::from_value(v).unwrap()
}

fn ask(service: &Service, owner: &str, v: serde_json::Value, body: &[u8]) -> Result<logos_tor::http::Response, String> {
    let id = service.request(owner, spec(v), body.to_vec())?;
    for _ in 0..1000 {
        match service.response(owner, &id) {
            Some(Polled::Pending) => std::thread::sleep(Duration::from_millis(10)),
            Some(Polled::Done(answer)) => return answer,
            None => panic!("{owner} lost request {id}"),
        }
    }
    panic!("no answer to {id}")
}

fn text(a: &logos_tor::http::Response) -> String {
    String::from_utf8(a.body.clone()).unwrap()
}

#[test]
fn https_speaks_http2_where_offered_and_http1_elsewhere() {
    let (service, _far, _dir) = start();
    let a = ask(&service, "m", json!({ "url": "https://zec.example/hello", "headers": [["x-test", "1"]] }), b"").unwrap();
    assert_eq!((a.status, a.http2, text(&a).as_str()), (200, true, "GET /hello HTTP/2.0 1 "));
    let a = ask(&service, "m", json!({ "method": "post", "url": "https://old.example/post", "headers": [["x-test", "2"]] }), b"body").unwrap();
    assert_eq!((a.http2, text(&a).as_str()), (false, "POST /post HTTP/1.1 2 body"));
    let e = ask(&service, "m", json!({ "url": "https://old.example/", "http2": true }), b"").unwrap_err();
    assert!(e.contains("does not speak HTTP/2"), "{e}");
    service.stop(Duration::from_millis(500));
}

#[test]
fn grpc_gets_its_trailers_over_tls_and_from_an_onion() {
    let (service, _far, _dir) = start();
    let grpc = |url: String| {
        json!({ "method": "POST", "url": url, "http2": true,
                "headers": [["content-type", "application/grpc"], ["te", "trailers"]] })
    };
    let framed = [0u8, 0, 0, 0, 3, 1, 2, 3];
    for url in ["https://zec.example/grpc".to_string(), format!("http://{ONION}/grpc")] {
        let a = ask(&service, "zcash_wallet_core_module", grpc(url.clone()), &framed).unwrap();
        assert_eq!((a.status, a.http2, a.body.as_slice()), (200, true, framed.as_slice()), "{url}");
        assert!(a.trailers.contains(&("grpc-status".to_string(), "0".to_string())), "{url}: {:?}", a.trailers);
    }
    // Plain HTTP/1.1 to the onion service too.
    let a = ask(&service, "m", json!({ "url": format!("http://{ONION}/") }), b"").unwrap();
    assert_eq!(text(&a), "GET / HTTP/1.1 - ");
    service.stop(Duration::from_millis(500));
}

#[test]
fn circuits_follow_the_module_and_its_key() {
    let (service, far, _dir) = start();
    let on = |key: &str| json!({ "url": "https://zec.example/", "isolation": key });
    for _ in 0..2 {
        ask(&service, "m", on("a"), b"").unwrap();
    }
    assert_eq!(far.dials().len(), 1, "one key, one connection");
    assert_eq!(far.dials()[0].isolation, Isolation::App { module: "m".into(), key: "a".into() });
    ask(&service, "m", on("b"), b"").unwrap();
    ask(&service, "other", on("a"), b"").unwrap();
    let dials = far.dials();
    assert_eq!(dials.len(), 3, "another key, or another module with the same key, gets its own");
    assert_eq!(dials[2].isolation, Isolation::App { module: "other".into(), key: "a".into() });
    for _ in 0..2 {
        ask(&service, "m", on(""), b"").unwrap();
    }
    let dials = far.dials();
    assert_eq!(dials.len(), 5, "no key: a circuit and a connection each");
    assert_ne!(dials[3].isolation, dials[4].isolation);
    service.stop(Duration::from_millis(500));
}

#[test]
fn only_the_module_that_asked_reads_the_answer() {
    let (service, _far, _dir) = start();
    let id = service.request("zcash_wallet_core_module", spec(json!({ "url": "https://zec.example/" })), vec![]).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(service.response("bitcoin_wallet_core_module", &id).is_none());
    assert!(!service.cancel("bitcoin_wallet_core_module", &id));
    assert!(matches!(service.response("zcash_wallet_core_module", &id), Some(Polled::Done(Ok(_)))));
    assert!(service.response("zcash_wallet_core_module", &id).is_none(), "handed over once");
    service.stop(Duration::from_millis(500));
}

#[test]
fn a_certificate_for_another_name_fails() {
    let (service, _far, _dir) = start();
    // The far side answers other.example with zec.example's certificate.
    let e = ask(&service, "m", json!({ "url": "https://other.example/" }), b"").unwrap_err();
    assert!(e.starts_with("tls:"), "{e}");
    service.stop(Duration::from_millis(500));
}

#[test]
fn a_silent_server_times_out_and_a_reconnect_interrupts() {
    let (service, _far, _dir) = start();
    let e = ask(&service, "m", json!({ "url": "https://slow.example/slow", "timeoutMs": 1000 }), b"").unwrap_err();
    assert_eq!(e, "no answer within 1 s");
    let id = service.request("m", spec(json!({ "url": "https://slow.example/slow" })), vec![]).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    service.reconnect(false).unwrap();
    assert!(matches!(service.response("m", &id), Some(Polled::Done(Err(ref e))) if e.contains("interrupted")));
    let id = service.request("m", spec(json!({ "url": "https://slow.example/slow" })), vec![]).unwrap();
    assert!(service.cancel("m", &id) && service.response("m", &id).is_none());
    service.stop(Duration::from_millis(500));
}

#[test]
fn each_modules_traffic_is_counted_and_nothing_goes_unless_asked() {
    let (service, far, _dir) = start();
    assert_eq!(service.status().state, State::Idle);
    assert!(service.request("m", spec(json!({ "url": "http://example.com/" })), vec![]).unwrap_err().contains("onion services only"));
    assert!(far.dials().is_empty() && service.apps().is_empty());
    ask(&service, "zcash_node_module", json!({ "url": "https://zec.example/" }), b"").unwrap();
    assert_eq!(service.status().state, State::Ready, "a request starts Tor");
    let apps = service.apps();
    assert_eq!((apps.len(), apps[0].module.as_str(), apps[0].requests), (1, "zcash_node_module", 1));
    assert!(apps[0].sent > 0 && apps[0].received > 0, "{apps:?}");
    assert_eq!(service.usage().opened, 1);
    service.stop(Duration::from_millis(500));
}

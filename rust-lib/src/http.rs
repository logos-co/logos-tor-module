//! HTTP requests through Tor, for modules over IPC: HTTP/1.1, or HTTP/2 as gRPC needs, with
//! TLS checked against the Mozilla roots. Plain http goes to onion services only, which Tor
//! encrypts end to end; anywhere else the exit relay would read it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use serde::Deserialize;

use crate::socks::{Dial, Stream, Target};
use crate::tor::Isolation;
use crate::usage::{AppMeter, Counted, Reads, Usage};

/// Largest request body a module may send.
pub const MAX_BODY: usize = 8 << 20;
/// Largest response body kept for a module.
pub const MAX_RESPONSE: usize = 64 << 20;
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
/// A pooled connection unused this long is closed.
const POOL_IDLE: Duration = Duration::from_secs(60);

/// What a module asks for: `{ method, url, headers: [[name, value]], http2, isolation, timeoutMs }`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    #[serde(default = "get")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// HTTP/2 only: the one protocol offered over TLS, and spoken from the start over plain
    /// http (h2c), as gRPC to an onion service needs.
    #[serde(default)]
    pub http2: bool,
    /// Requests of one module with the same key may share a circuit and a connection; with
    /// none, each request gets its own.
    #[serde(default)]
    pub isolation: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn get() -> String {
    "GET".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Origin {
    https: bool,
    host: String,
    port: u16,
}

/// A request checked before it starts, so a bad one is refused at once.
#[derive(Debug)]
pub struct Prepared {
    method: Method,
    uri: Uri,
    origin: Origin,
    headers: Vec<(HeaderName, HeaderValue)>,
    http2: bool,
    isolation: String,
    pub timeout: Duration,
}

/// Hop-by-hop headers belong to the connection, which this module owns.
const CONNECTION_HEADERS: [&str; 7] =
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host", "content-length"];

pub fn is_onion(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|name| !name.is_empty())
}

/// This computer or its network, which Tor cannot reach.
fn is_local(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => host == "localhost" || host.ends_with(".localhost"),
    }
}

impl Prepared {
    pub fn new(spec: Spec, body_len: usize) -> Result<Self, String> {
        if body_len > MAX_BODY {
            return Err(format!("the body is larger than {} MB", MAX_BODY >> 20));
        }
        let uri: Uri = spec.url.parse().map_err(|_| format!("bad url {}", spec.url))?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err("the url must be http:// or https://".into()),
        };
        let host = uri.host().ok_or("the url has no host")?.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        if is_local(&host) {
            return Err(format!("Tor cannot reach {host}: it is on this computer or its network"));
        }
        if !https && !is_onion(&host) {
            return Err("plain http goes to onion services only: anywhere else the exit relay would read it".into());
        }
        let method = Method::from_bytes(spec.method.to_ascii_uppercase().as_bytes()).map_err(|_| format!("bad method {}", spec.method))?;
        let mut headers = Vec::new();
        for (name, value) in spec.headers {
            let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| format!("bad header name {name}"))?;
            let value = HeaderValue::from_str(value.trim()).map_err(|_| format!("bad value for header {name}"))?;
            if CONNECTION_HEADERS.contains(&name.as_str()) || (name == header::TE && value != "trailers") {
                continue;
            }
            headers.push((name, value));
        }
        let timeout = Duration::from_millis(spec.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).clamp(1_000, MAX_TIMEOUT_MS));
        Ok(Self { method, uri, origin: Origin { https, host, port }, headers, http2: spec.http2, isolation: spec.isolation, timeout })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub trailers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub http2: bool,
}

impl Response {
    /// `{ state: "done", status, headers, trailers, body (base64), http2 }`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": "done",
            "status": self.status,
            "headers": self.headers,
            "trailers": self.trailers,
            "body": base64::engine::general_purpose::STANDARD.encode(&self.body),
            "http2": self.http2,
        })
    }
}

type Sender = http2::SendRequest<Full<Bytes>>;
/// The module, its key, and the origin.
type PoolKey = (String, String, Origin);

/// HTTP/2 connections by module, key and origin, so a module's requests on one key share a
/// connection, as a gRPC client's calls do.
#[derive(Default)]
pub struct Pool(Mutex<HashMap<PoolKey, (Sender, Instant)>>);

impl Pool {
    fn take(&self, key: &PoolKey) -> Option<Sender> {
        let mut pool = self.0.lock().unwrap();
        pool.retain(|_, (s, used)| !s.is_closed() && used.elapsed() < POOL_IDLE);
        pool.get(key).map(|(s, _)| s.clone())
    }

    fn put(&self, key: PoolKey, sender: Sender) {
        self.0.lock().unwrap().insert(key, (sender, Instant::now()));
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn webpki_roots() -> rustls::RootCertStore {
    rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

pub fn tls_config(roots: rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// What a run of Tor lends the requests made through it.
pub struct Ctx {
    pub dialer: Arc<dyn Dial>,
    pub tls: Arc<rustls::ClientConfig>,
    pub pool: Pool,
    pub usage: Arc<Usage>,
}

fn fresh_key() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    hex::encode(bytes)
}

fn pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers.iter().map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect()
}

/// Sends `req` for `owner` and collects the answer, within the request's timeout.
pub async fn send(ctx: Arc<Ctx>, owner: String, req: Prepared, body: Vec<u8>, app: Arc<AppMeter>) -> Result<Response, String> {
    let seconds = req.timeout.as_secs();
    tokio::time::timeout(req.timeout, exchange(&ctx, &owner, &req, body, &app))
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {seconds} s")))
}

async fn exchange(ctx: &Ctx, owner: &str, req: &Prepared, body: Vec<u8>, app: &AppMeter) -> Result<Response, String> {
    let pooled = (!req.isolation.is_empty()).then(|| (owner.to_string(), req.isolation.clone(), req.origin.clone()));
    if let Some(mut sender) = pooled.as_ref().and_then(|k| ctx.pool.take(k)) {
        if sender.ready().await.is_ok() {
            return send_h2(&mut sender, req, body).await;
        }
    }
    let isolation = Isolation::App {
        module: owner.to_string(),
        key: if req.isolation.is_empty() { fresh_key() } else { req.isolation.clone() },
    };
    let target = Target { host: req.origin.host.clone(), port: req.origin.port, ipv4_only: false, isolation };
    let stream = ctx.dialer.dial(target).await.map_err(|(_, why)| format!("connect: {why}"))?;
    let open = ctx.usage.open_stream();
    let stream = Counted::new(stream, app.meter.clone(), Reads::Received);
    let (io, h2): (Box<dyn Stream>, bool) = if req.origin.https {
        let mut config = (*ctx.tls).clone();
        config.alpn_protocols = if req.http2 { vec![b"h2".to_vec()] } else { vec![b"h2".to_vec(), b"http/1.1".to_vec()] };
        let name = ServerName::try_from(req.origin.host.clone()).map_err(|e| format!("tls: {e}"))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await.map_err(|e| {
            // A server without HTTP/2 may refuse the handshake rather than settle for another.
            let refused = matches!(
                e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol))
            );
            if refused && req.http2 { "the server does not speak HTTP/2".to_string() } else { format!("tls: {e}") }
        })?;
        let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        if req.http2 && !h2 {
            return Err("the server does not speak HTTP/2".into());
        }
        (Box::new(tls), h2)
    } else {
        (Box::new(stream), req.http2)
    };
    if h2 {
        let (mut sender, conn) =
            http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await.map_err(|e| format!("http/2: {e}"))?;
        tokio::spawn(async move {
            let _open = open;
            let _ = conn.await;
        });
        let answer = send_h2(&mut sender, req, body).await;
        if let Some(key) = pooled {
            ctx.pool.put(key, sender);
        }
        answer
    } else {
        let (mut sender, conn) = http1::handshake(TokioIo::new(io)).await.map_err(|e| format!("http: {e}"))?;
        tokio::spawn(async move {
            let _open = open;
            let _ = conn.await;
        });
        let mut request = Request::builder().method(req.method.clone()).uri(req.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
        let authority = req.uri.authority().map(|a| a.as_str().to_string()).unwrap_or_else(|| req.origin.host.clone());
        request = request.header(header::HOST, authority);
        for (k, v) in &req.headers {
            request = request.header(k, v);
        }
        let request = request.body(Full::new(Bytes::from(body))).map_err(|e| format!("http: {e}"))?;
        let response = sender.send_request(request).await.map_err(|e| format!("http: {e}"))?;
        collect(response, false).await
    }
}

async fn send_h2(sender: &mut Sender, req: &Prepared, body: Vec<u8>) -> Result<Response, String> {
    let mut request = Request::builder().method(req.method.clone()).uri(req.uri.clone());
    for (k, v) in &req.headers {
        request = request.header(k, v);
    }
    let request = request.body(Full::new(Bytes::from(body))).map_err(|e| format!("http/2: {e}"))?;
    let response = sender.send_request(request).await.map_err(|e| format!("http/2: {e}"))?;
    collect(response, true).await
}

async fn collect(response: http::Response<hyper::body::Incoming>, http2: bool) -> Result<Response, String> {
    let (parts, body) = response.into_parts();
    let collected = Limited::new(body, MAX_RESPONSE).collect().await.map_err(|e| {
        if e.is::<http_body_util::LengthLimitError>() {
            format!("the response is larger than {} MB", MAX_RESPONSE >> 20)
        } else {
            format!("http: {e}")
        }
    })?;
    let trailers = collected.trailers().map(pairs).unwrap_or_default();
    Ok(Response { status: parts.status.as_u16(), headers: pairs(&parts.headers), trailers, body: collected.to_bytes().to_vec(), http2 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(url: &str) -> Spec {
        serde_json::from_value(serde_json::json!({ "url": url })).unwrap()
    }

    #[test]
    fn a_spec_takes_defaults_and_refuses_unknown_keys() {
        let s = spec("https://zec.rocks/");
        assert_eq!((s.method.as_str(), s.http2, s.isolation.as_str(), s.timeout_ms), ("GET", false, "", None));
        let full = r#"{"method":"post","url":"https://a.example/x?y=1","headers":[["content-type","application/grpc"],["te","trailers"]],"http2":true,"isolation":"k","timeoutMs":5000}"#;
        let s: Spec = serde_json::from_str(full).unwrap();
        assert_eq!(s.headers.len(), 2);
        assert!(serde_json::from_str::<Spec>(r#"{"url":"https://a.example","proxy":"x"}"#).is_err());
    }

    #[test]
    fn plain_http_only_to_onions_and_nothing_local() {
        assert!(Prepared::new(spec("https://zec.rocks:9067/"), 0).is_ok());
        let onion = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/";
        let p = Prepared::new(spec(onion), 0).unwrap();
        assert_eq!((p.origin.https, p.origin.port), (false, 80));
        assert!(Prepared::new(spec("http://example.com/"), 0).unwrap_err().contains("onion services only"));
        for local in ["https://127.0.0.1/", "https://[::1]:8443/", "https://192.168.1.4/", "https://localhost/", "https://10.1.2.3/"] {
            assert!(Prepared::new(spec(local), 0).unwrap_err().contains("cannot reach"), "{local}");
        }
        for bad in ["ftp://example.com/", "example.com", "https:///x"] {
            assert!(Prepared::new(spec(bad), 0).is_err(), "{bad}");
        }
        assert!(Prepared::new(spec("https://zec.rocks/"), MAX_BODY + 1).unwrap_err().contains("larger"));
    }

    #[test]
    fn connection_headers_are_this_modules() {
        let s = Spec {
            headers: vec![
                ("Host".into(), "evil.example".into()),
                ("Connection".into(), "close".into()),
                ("TE".into(), "gzip".into()),
                ("te".into(), "trailers".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            ..spec("https://zec.rocks/")
        };
        let p = Prepared::new(s, 0).unwrap();
        let names: Vec<&str> = p.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["te", "content-type"]);
        assert_eq!(p.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        let fast = Spec { timeout_ms: Some(1), ..spec("https://zec.rocks/") };
        assert_eq!(Prepared::new(fast, 0).unwrap().timeout, Duration::from_secs(1));
    }
}

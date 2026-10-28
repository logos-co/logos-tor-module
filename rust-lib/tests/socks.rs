//! The SOCKS port against a dialer that records each target and echoes, offline.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use logos_tor::socks::{serve, Dial, Dialed, Stream, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_socks::tcp::Socks5Stream;
use tor_socksproto::{SocksAuth, SocksStatus};

#[derive(Default)]
struct Echo {
    seen: Mutex<Vec<Target>>,
}

impl Dial for Echo {
    fn dial(&self, target: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        Box::pin(async move {
            let gone = target.host == "gone.onion";
            self.seen.lock().unwrap().push(target);
            if gone {
                return Err((SocksStatus::HS_DESC_NOT_FOUND, "no descriptor".into()));
            }
            let (ours, theirs) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(Box::new(ours) as Box<dyn Stream>)
        })
    }
}

async fn start() -> (SocketAddr, Arc<Echo>, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let echo = Arc::new(Echo::default());
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(serve(listener, echo.clone(), stopped));
    (addr, echo, stop)
}

async fn ping(stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin)) -> [u8; 4] {
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    back
}

fn target(host: &str, port: u16, ipv4_only: bool, isolation: SocksAuth) -> Target {
    Target { host: host.into(), port, ipv4_only, isolation }
}

#[tokio::test]
async fn socks5_relays_and_passes_the_credentials() {
    let (addr, echo, _stop) = start().await;
    let mut s = Socks5Stream::connect_with_password(addr, ("zec.rocks", 443), "a1", "b2").await.unwrap();
    assert_eq!(&ping(&mut s).await, b"ping");
    let mut s = Socks5Stream::connect(addr, ("abc.onion", 9067)).await.unwrap();
    assert_eq!(&ping(&mut s).await, b"ping");
    let user = SocksAuth::Username(b"a1".to_vec(), b"b2".to_vec());
    assert_eq!(
        *echo.seen.lock().unwrap(),
        [target("zec.rocks", 443, false, user), target("abc.onion", 9067, false, SocksAuth::NoAuth)]
    );
}

#[tokio::test]
async fn socks4a_names_the_host_and_its_user_id() {
    let (addr, echo, _stop) = start().await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    // CONNECT to port 18081 at 0.0.0.1, which means "the name follows" (4a).
    let mut request = vec![4, 1, 0x46, 0xa1, 0, 0, 0, 1];
    request.extend_from_slice(b"wallet\0node.example\0");
    c.write_all(&request).await.unwrap();
    let mut reply = [0u8; 8];
    c.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x5a, "request granted");
    assert_eq!(&ping(&mut c).await, b"ping");
    assert_eq!(*echo.seen.lock().unwrap(), [target("node.example", 18081, true, SocksAuth::Socks4(b"wallet".to_vec()))]);
}

/// A SOCKS5 request on a fresh connection, without authentication: the reply code, or
/// None when the port closes instead.
async fn socks5_reply(addr: SocketAddr, command: u8, host: &str) -> Option<u8> {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut chosen = [0u8; 2];
    c.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [5, 0]);
    let mut request = vec![5, command, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&80u16.to_be_bytes());
    c.write_all(&request).await.unwrap();
    let mut reply = [0u8; 2];
    c.read_exact(&mut reply).await.ok().map(|_| reply[1])
}

#[tokio::test]
async fn failures_answer_with_their_socks_status() {
    let (addr, echo, _stop) = start().await;
    assert_eq!(socks5_reply(addr, 1, "gone.onion").await, Some(0xf0), "onion descriptor not found");
    assert_eq!(socks5_reply(addr, 0xf0, "resolve.example").await, Some(0x07), "Tor's RESOLVE is not served");
    // As on Arti's own port, the handshake refuses BIND: the port closes without a reply.
    assert_eq!(socks5_reply(addr, 2, "bind.example").await, None);
    assert_eq!(echo.seen.lock().unwrap().len(), 1, "only the CONNECT was dialled");
}

#[tokio::test]
async fn stop_closes_the_port() {
    let (addr, _echo, stop) = start().await;
    stop.send(true).unwrap();
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the port still accepts after stop");
}

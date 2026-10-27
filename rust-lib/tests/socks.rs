//! The SOCKS port against a dialer that records each target and echoes, offline.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{ping, Echo};
use logos_tor::socks::{serve, Target};
use logos_tor::usage::{Counts, Usage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_socks::tcp::Socks5Stream;
use tor_socksproto::SocksAuth;

async fn start() -> (SocketAddr, Arc<Echo>, watch::Sender<bool>, Arc<Usage>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let echo = Arc::new(Echo::default());
    let usage = Arc::new(Usage::default());
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(serve(listener, echo.clone(), stopped, usage.clone()));
    (addr, echo, stop, usage)
}

fn target(host: &str, port: u16, ipv4_only: bool, isolation: SocksAuth) -> Target {
    Target { host: host.into(), port, ipv4_only, isolation }
}

#[tokio::test]
async fn socks5_relays_and_passes_the_credentials() {
    let (addr, echo, _stop, _) = start().await;
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
    let (addr, echo, _stop, _) = start().await;
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
    let (addr, echo, _stop, _) = start().await;
    assert_eq!(socks5_reply(addr, 1, "gone.onion").await, Some(0xf0), "onion descriptor not found");
    assert_eq!(socks5_reply(addr, 0xf0, "resolve.example").await, Some(0x07), "Tor's RESOLVE is not served");
    // As on Arti's own port, the handshake refuses BIND: the port closes without a reply.
    assert_eq!(socks5_reply(addr, 2, "bind.example").await, None);
    assert_eq!(echo.seen.lock().unwrap().len(), 1, "only the CONNECT was dialled");
}

#[tokio::test]
async fn stop_closes_the_port() {
    let (addr, _echo, stop, _) = start().await;
    stop.send(true).unwrap();
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the port still accepts after stop");
}

#[tokio::test]
async fn counts_what_the_apps_send_and_receive() {
    let (addr, _echo, _stop, usage) = start().await;
    let mut s = Socks5Stream::connect(addr, ("zec.rocks", 443)).await.unwrap();
    assert_eq!(&ping(&mut s).await, b"ping");
    assert_eq!(usage.counts(), Counts { sent: 4, received: 4, opened: 1, open: 1 }, "the handshake is not counted");
    drop(s);
    for _ in 0..50 {
        if usage.counts().open == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(usage.counts(), Counts { sent: 4, received: 4, opened: 1, open: 0 });
    // A dial that fails opens no stream.
    assert!(Socks5Stream::connect(addr, ("gone.onion", 80)).await.is_err());
    assert_eq!(usage.counts().opened, 1);
}

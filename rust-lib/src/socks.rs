//! The SOCKS port: SOCKS4, 4a and 5 on loopback, CONNECT only. Streams whose SOCKS
//! credentials differ never share a circuit (Tor's IsolateSOCKSAuth), so a caller that
//! wants a fresh circuit sends fresh credentials.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tor_socksproto::{Handshake as _, NextStep, SocksCmd, SocksRequest, SocksStatus, SocksVersion};

use crate::tor::Isolation;
use crate::usage::{Counted, Reads, Usage};

/// A client that names no target within this long is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// Where a client asked to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// SOCKS4 and 4a carry IPv4 only.
    pub ipv4_only: bool,
    /// Which circuit it may share: a SOCKS client's credentials, or a module's key.
    pub isolation: Isolation,
}

/// The stream, or the SOCKS status to answer with and why.
pub type Dialed = Result<Box<dyn Stream>, (SocksStatus, String)>;

/// Opens the stream a client asked for: Tor in the module, a fake in tests.
pub trait Dial: Send + Sync + 'static {
    fn dial(&self, target: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>>;
}

/// Serves clients until `stop` turns true, counting their traffic into `usage`. Nothing about
/// a client's target is logged.
pub async fn serve(listener: TcpListener, dialer: Arc<dyn Dial>, mut stop: watch::Receiver<bool>, usage: Arc<Usage>) {
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let (dialer, usage) = (dialer.clone(), usage.clone());
                    tokio::spawn(async move {
                        let _ = handle(&*dialer, stream, usage).await;
                    });
                }
                // Out of file descriptors, say: wait instead of spinning.
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            },
            _ = stop.changed() => return,
        }
    }
}

async fn handle(dialer: &dyn Dial, mut stream: TcpStream, usage: Arc<Usage>) -> Result<(), String> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream))
        .await
        .map_err(|_| "handshake timed out".to_string())??;
    if request.command() != SocksCmd::CONNECT {
        return reply(&mut stream, &request, SocksStatus::COMMAND_NOT_SUPPORTED).await;
    }
    let target = Target {
        host: request.addr().to_string(),
        port: request.port(),
        ipv4_only: request.version() == SocksVersion::V4,
        isolation: Isolation::Socks(request.auth().clone()),
    };
    match dialer.dial(target).await {
        Ok(mut remote) => {
            reply(&mut stream, &request, SocksStatus::SUCCEEDED).await?;
            let _open = usage.open_stream();
            let mut app = Counted::new(stream, usage.socks().clone(), Reads::Sent);
            // Either side closing ends the relay; how it ended concerns no one.
            let _ = tokio::io::copy_bidirectional(&mut app, &mut remote).await;
            Ok(())
        }
        Err((status, why)) => {
            reply(&mut stream, &request, status).await?;
            Err(why)
        }
    }
}

async fn handshake(stream: &mut TcpStream) -> Result<SocksRequest, String> {
    let mut handshake = tor_socksproto::SocksProxyHandshake::new();
    let mut buf = tor_socksproto::Buffer::new();
    loop {
        match handshake.step(&mut buf).map_err(|e| e.to_string())? {
            NextStep::Recv(mut recv) => {
                let n = stream.read(recv.buf()).await.map_err(|e| e.to_string())?;
                recv.note_received(n).map_err(|e| e.to_string())?;
            }
            NextStep::Send(data) => stream.write_all(&data).await.map_err(|e| e.to_string())?,
            NextStep::Finished(done) => return done.into_output_forbid_pipelining().map_err(|e| e.to_string()),
        }
    }
}

async fn reply(stream: &mut TcpStream, request: &SocksRequest, status: SocksStatus) -> Result<(), String> {
    let bytes = request.reply(status, None).map_err(|e| e.to_string())?;
    stream.write_all(&bytes).await.map_err(|e| e.to_string())
}

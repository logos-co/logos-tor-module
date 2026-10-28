//! A dialer that records each target and echoes, so the SOCKS port is tested offline.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use logos_tor::socks::{Dial, Dialed, Stream, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_socksproto::SocksStatus;

#[derive(Default)]
pub struct Echo {
    pub seen: Mutex<Vec<Target>>,
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

pub async fn ping(stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin)) -> [u8; 4] {
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    back
}

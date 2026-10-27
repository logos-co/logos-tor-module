//! Arti: its state and cache under the module's directory, and the dialer the SOCKS port
//! and requests use.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::isolation::IsolationHelper;
use arti_client::{ErrorKind, HasKind, IntoTorAddr, StreamPrefs, TorClient};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{SocksAuth, SocksStatus};

use crate::socks::{Dial, Dialed, Stream, Target};

pub type Client = Arc<TorClient<PreferredRuntime>>;

/// What decides which streams may share a circuit: only streams whose isolation is equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Isolation {
    /// A SOCKS client's credentials, as Tor's IsolateSOCKSAuth.
    Socks(SocksAuth),
    /// A module's request over IPC: the module, and a key it chose. No two modules share.
    App { module: String, key: String },
}

/// An isolation as Arti sees it. Each time an exit fails one of its streams, its streams
/// move on to circuits of the next generation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Circuits {
    isolation: Isolation,
    generation: u32,
}

impl IsolationHelper for Circuits {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        (self == other).then(|| self.clone())
    }
}

/// Tries per stream, as Tor's own client retries a stream an exit failed on another circuit.
const ATTEMPTS: u32 = 3;
/// How long a move off a failed circuit lasts: Arti gives a circuit new streams for 10
/// minutes after its first, so by then the failed one takes none.
const MOVED_FOR: Duration = Duration::from_secs(15 * 60);

/// The isolations an exit failed, with the generation of circuits they moved to.
#[derive(Default)]
struct Moves(Mutex<HashMap<Isolation, (u32, Instant)>>);

impl Moves {
    fn generation(&self, isolation: &Isolation) -> u32 {
        let mut moves = self.0.lock().unwrap();
        moves.retain(|_, (_, at)| at.elapsed() < MOVED_FOR);
        moves.get(isolation).map_or(0, |(g, _)| *g)
    }

    fn move_off(&self, isolation: &Isolation, failed: u32) {
        let mut moves = self.0.lock().unwrap();
        let entry = moves.entry(isolation.clone()).or_insert((0, Instant::now()));
        *entry = (entry.0.max(failed + 1), Instant::now());
    }
}

/// The exit failed the stream, not Tor or the destination: a name it could not resolve, its
/// exit policy, a timeout or an error there, or the circuit falling apart.
fn exit_failed(kind: ErrorKind) -> bool {
    use ErrorKind as EK;
    matches!(
        kind,
        EK::RemoteHostResolutionFailed
            | EK::ExitPolicyRejected
            | EK::ExitTimeout
            | EK::RemoteNetworkTimeout
            | EK::RemoteNetworkFailed
            | EK::RemoteStreamError
            | EK::RelayTooBusy
            | EK::CircuitCollapse
    )
}

/// Runs `connect` with the isolation's circuit generation, and again on a fresh one each
/// time an exit fails it, up to ATTEMPTS in all.
async fn with_fresh_circuits<S, F, Fut>(moves: &Moves, isolation: &Isolation, mut connect: F) -> Result<S, (ErrorKind, String)>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<S, (ErrorKind, String)>>,
{
    let mut attempt = 1;
    loop {
        let generation = moves.generation(isolation);
        match connect(generation).await {
            Err((kind, _)) if exit_failed(kind) && attempt < ATTEMPTS => {
                moves.move_off(isolation, generation);
                tracing::info!(target: "tor_module", "an exit relay failed a stream ({kind}); trying a fresh circuit");
                attempt += 1;
            }
            other => return other,
        }
    }
}

#[derive(Clone)]
pub struct Tor {
    client: Client,
    moves: Arc<Moves>,
}

impl Tor {
    /// Arti with `state/` and `cache/` under `dir`, not joined yet: a connection or
    /// `client().bootstrap()` starts that. Runs inside the tokio runtime that drives it.
    pub fn create(dir: &Path) -> Result<Self, String> {
        // Arti's TLS needs a process-wide rustls provider; the process is this module's own.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (state, cache) = (dir.join("state"), dir.join("cache"));
        for d in [&state, &cache] {
            private_dir(d)?;
        }
        let config = TorClientConfigBuilder::from_directories(state, cache)
            .build()
            .map_err(|e| format!("tor config: {e}"))?;
        let client = TorClient::builder()
            .config(config)
            .create_unbootstrapped()
            .map_err(|e| format!("tor: {e}"))?;
        Ok(Self { client, moves: Arc::default() })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

/// Arti refuses state that other users could change.
fn private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

impl Dial for Tor {
    fn dial(&self, target: Target) -> Pin<Box<dyn Future<Output = Dialed> + Send + '_>> {
        Box::pin(async move {
            let addr = (target.host.clone(), target.port)
                .into_tor_addr()
                .map_err(|e| (SocksStatus::ADDRTYPE_NOT_SUPPORTED, e.to_string()))?;
            let connected = with_fresh_circuits(&self.moves, &target.isolation, |generation| {
                let mut prefs = StreamPrefs::new();
                if target.ipv4_only {
                    prefs.ipv4_only();
                }
                prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
                prefs.set_isolation(Circuits { isolation: target.isolation.clone(), generation });
                let (client, addr) = (self.client.clone(), addr.clone());
                async move { client.connect_with_prefs(&addr, &prefs).await.map_err(|e| (e.kind(), e.to_string())) }
            })
            .await;
            match connected {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn Stream>),
                Err((kind, why)) => Err((socks_status(kind), why)),
            }
        })
    }
}

/// As Arti's own SOCKS port answers, onion service failures included (proposal 304).
fn socks_status(kind: ErrorKind) -> SocksStatus {
    use ErrorKind as EK;
    match kind {
        EK::RemoteNetworkFailed => SocksStatus::TTL_EXPIRED,
        EK::OnionServiceNotFound => SocksStatus::HS_DESC_NOT_FOUND,
        EK::OnionServiceAddressInvalid => SocksStatus::HS_BAD_ADDRESS,
        EK::OnionServiceMissingClientAuth => SocksStatus::HS_MISSING_CLIENT_AUTH,
        EK::OnionServiceWrongClientAuth => SocksStatus::HS_WRONG_CLIENT_AUTH,
        EK::OnionServiceNotRunning | EK::OnionServiceConnectionFailed | EK::OnionServiceProtocolViolation => {
            SocksStatus::HS_INTRO_FAILED
        }
        _ => SocksStatus::GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(key: &str) -> Isolation {
        Isolation::App { module: "wallet".into(), key: key.into() }
    }

    /// Connects through `with_fresh_circuits` with one answer per try; returns the outcome and
    /// the generation each try used.
    async fn run(moves: &Moves, isolation: &Isolation, answers: Vec<Result<(), ErrorKind>>) -> (Result<(), ErrorKind>, Vec<u32>) {
        let mut answers = answers.into_iter();
        let mut used = vec![];
        let r = with_fresh_circuits(moves, isolation, |generation| {
            used.push(generation);
            let answer = answers.next().expect("an answer per try");
            async move { answer.map_err(|kind| (kind, kind.to_string())) }
        })
        .await;
        (r.map_err(|(kind, _)| kind), used)
    }

    #[tokio::test]
    async fn a_stream_an_exit_failed_moves_with_its_key_to_a_fresh_circuit() {
        let moves = Moves::default();
        let r = run(&moves, &app("sync"), vec![Err(ErrorKind::RemoteHostResolutionFailed), Ok(())]).await;
        assert_eq!(r, (Ok(()), vec![0, 1]));
        // The key's later streams stay off the failed circuit; other keys keep theirs.
        assert_eq!(run(&moves, &app("sync"), vec![Ok(())]).await.1, vec![1]);
        assert_eq!(run(&moves, &app("tip"), vec![Ok(())]).await.1, vec![0]);
    }

    #[tokio::test]
    async fn three_tries_at_most() {
        let moves = Moves::default();
        let timeout = || Err(ErrorKind::ExitTimeout);
        let r = run(&moves, &app("sync"), vec![timeout(), timeout(), timeout()]).await;
        assert_eq!(r, (Err(ErrorKind::ExitTimeout), vec![0, 1, 2]));
    }

    #[tokio::test]
    async fn failures_elsewhere_are_not_retried() {
        let moves = Moves::default();
        for kind in [ErrorKind::RemoteConnectionRefused, ErrorKind::RemoteHostNotFound, ErrorKind::TorNetworkTimeout] {
            assert_eq!(run(&moves, &app("sync"), vec![Err(kind)]).await, (Err(kind), vec![0]));
        }
    }
}

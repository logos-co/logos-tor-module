//! Arti: its state and cache under the module's directory, and the dialer the SOCKS port
//! uses.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::isolation::IsolationHelper;
use arti_client::{ErrorKind, HasKind, IntoTorAddr, StreamPrefs, TorClient};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::{SocksAuth, SocksStatus};

use crate::socks::{Dial, Dialed, Stream, Target};

pub type Client = Arc<TorClient<PreferredRuntime>>;

/// What decides which streams may share a circuit: only streams whose isolation is equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Isolation {
    /// A SOCKS client's credentials, as Tor's IsolateSOCKSAuth.
    Socks(SocksAuth),
    /// A module's request over IPC: the module, and a key it chose. No two modules share.
    App { module: String, key: String },
}

impl IsolationHelper for Isolation {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        (self == other).then(|| self.clone())
    }
}

#[derive(Clone)]
pub struct Tor {
    client: Client,
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
        Ok(Self { client })
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
            let mut prefs = StreamPrefs::new();
            if target.ipv4_only {
                prefs.ipv4_only();
            }
            prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
            prefs.set_isolation(target.isolation);
            let addr = (target.host, target.port)
                .into_tor_addr()
                .map_err(|e| (SocksStatus::ADDRTYPE_NOT_SUPPORTED, e.to_string()))?;
            match self.client.connect_with_prefs(&addr, &prefs).await {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn Stream>),
                Err(e) => Err((socks_status(e.kind()), e.to_string())),
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

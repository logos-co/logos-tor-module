//! Logos glue for `tor_module` (rust-first, `concurrency: "multi"`). Replies are flat JSON
//! strings, `{ ok, ... }` or `{ ok: false, error }`.

use std::sync::Arc;
use std::time::Duration;

use logos_rust_sdk::{AboutToUnload, Shutdown};

use crate::service::Service;

pub trait TorModule: Send + Sync + 'static {
    /// `{ ok, state, progress, detail, socks }`. `state` is connecting, ready, blocked or
    /// failed; `progress` is the percent joined; `socks` is `socks5h://127.0.0.1:PORT`
    /// once the port listens, or null. Connections made while connecting wait for Tor.
    fn status(&self) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

#[allow(dead_code)] // Read by logos-lidl-gen, which generates the emitters.
pub trait TorModuleEvents {
    /// status()'s reply, when the state, the progress or the port changed.
    fn status_changed(&self, payload: String);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
pub struct TorModuleImpl {
    // Qualified: the generated scaffold already imports `Mutex` into this module.
    service: std::sync::Mutex<Option<Result<Service, String>>>,
}

impl TorModule for TorModuleImpl {
    fn status(&self) -> String {
        match self.service.lock().unwrap().as_ref() {
            Some(Ok(s)) => s.status().to_json(),
            Some(Err(e)) => serde_json::json!({ "ok": false, "error": e }).to_string(),
            None => serde_json::json!({ "ok": false, "error": "starting" }).to_string(),
        }
    }

    /// Opens the SOCKS port and starts joining Tor, with Arti's files under `arti/`.
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path).join("arti");
        let started = Service::start(&dir, Arc::new(|s| emit_status_changed(&s.to_json())));
        if let Err(e) = &started {
            eprintln!("tor_module: {e}");
        }
        *self.service.lock().unwrap() = Some(started);
    }
}

impl AboutToUnload for TorModuleImpl {
    /// Closes the SOCKS port and stops Arti within ~1.5 s, inside the host's grace period.
    fn about_to_unload(&self) -> Shutdown {
        if let Some(Ok(s)) = self.service.lock().unwrap().take() {
            s.stop(Duration::from_millis(1500));
        }
        Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(TorModuleImpl);
}

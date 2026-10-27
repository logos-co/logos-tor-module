//! Logos glue for `tor_module` (rust-first, `concurrency: "multi"`). Replies are flat JSON
//! strings, `{ ok, ... }` or `{ ok: false, error }`; gate.rs says who may call.

use std::sync::Arc;
use std::time::Duration;

use logos_rust_sdk::{AboutToUnload, LogosCaller, Shutdown};

use crate::gate::{Caller, Callers, APP};
use crate::logbook::Logbook;
use crate::service::Service;
use crate::usage::{self, now_ms, Followers};

const NOT_AUTHORIZED: &str = r#"{"ok":false,"error":"not authorized"}"#;

pub trait TorModule: Send + Sync + 'static {
    /// `{ ok, state, progress, detail, socks, since, joinMs }`. `state` is connecting, ready,
    /// blocked or failed; `progress` is the percent joined; `socks` is
    /// `socks5h://127.0.0.1:PORT`, the same for as long as the module is loaded; `since` is
    /// when the state began (unix ms); `joinMs` is how long the last start took to be ready.
    /// Connections made while connecting wait for Tor. A module that asks counts as an app
    /// following Tor for 90 s.
    fn status(&self) -> String;
    /// `{ ok, startedAt, sent, received, streams: { open, total }, files, memory,
    /// apps: [{ module, seenAt }] }`: bytes the apps sent and received through Tor and the
    /// streams it opened since `startedAt`, the bytes in Tor's files, this process's memory
    /// (null when unknown), and the modules following Tor. The Tor app only.
    fn usage(&self) -> String;
    /// `{ ok, entries: [{ at, level, target, message }] }`: Arti's last `lines` log entries,
    /// INFO and up, oldest first. The Tor app only.
    fn log_tail(&self, lines: i64) -> String;
    /// Stops Arti and starts it again on the same SOCKS port; open streams end. `{ ok }`
    /// once it is joining again. The Tor app only.
    fn reconnect(&self) -> String;
    /// Reconnects with Arti's state and directory cache deleted in between: new entry
    /// guards, and the directory downloaded again (about 7 MB). The Tor app only.
    fn forget_data(&self) -> String;

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
    service: std::sync::Mutex<Option<Result<Arc<Service>, String>>>,
    callers: std::sync::Mutex<Callers>,
    followers: Followers,
    logbook: Logbook,
}

fn caller() -> Caller {
    match logos_rust_sdk::current_caller() {
        LogosCaller::Module { name, .. } => Caller::Module(name),
        LogosCaller::HostAnchor => Caller::Host,
        LogosCaller::Unknown => Caller::Unknown,
        _ => Caller::Other,
    }
}

fn err(e: &str) -> String {
    serde_json::json!({ "ok": false, "error": e }).to_string()
}

impl TorModuleImpl {
    /// Cloned out, so a reconnect in progress never holds up status().
    fn service(&self) -> Result<Arc<Service>, String> {
        match self.service.lock().unwrap().as_ref() {
            Some(Ok(s)) => Ok(s.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("starting".into()),
        }
    }

    /// Runs `f` for a caller allowed to manage Tor. The caller is read first, on the
    /// dispatching thread.
    fn managed(&self, f: impl FnOnce(&Service) -> String) -> String {
        if !self.callers.lock().unwrap().admits(&caller()) {
            return NOT_AUTHORIZED.into();
        }
        match self.service() {
            Ok(s) => f(&s),
            Err(e) => err(&e),
        }
    }
}

impl TorModule for TorModuleImpl {
    fn status(&self) -> String {
        if let Caller::Module(name) = caller() {
            if name != APP {
                self.followers.saw(&name, now_ms());
            }
        }
        match self.service() {
            Ok(s) => s.status().to_json(),
            Err(e) => err(&e),
        }
    }

    fn usage(&self) -> String {
        self.managed(|s| {
            let c = s.usage();
            let apps: Vec<_> = self
                .followers
                .recent(now_ms())
                .into_iter()
                .map(|(module, at)| serde_json::json!({ "module": module, "seenAt": at }))
                .collect();
            serde_json::json!({
                "ok": true,
                "startedAt": s.started_at(),
                "sent": c.sent,
                "received": c.received,
                "streams": { "open": c.open, "total": c.opened },
                "files": usage::dir_size(s.dir()),
                "memory": usage::memory(),
                "apps": apps,
            })
            .to_string()
        })
    }

    fn log_tail(&self, lines: i64) -> String {
        self.managed(|_| {
            let entries = self.logbook.tail(lines.clamp(0, crate::logbook::KEEP as i64) as usize);
            serde_json::json!({ "ok": true, "entries": entries }).to_string()
        })
    }

    fn reconnect(&self) -> String {
        self.managed(|s| match s.reconnect(false) {
            Ok(()) => r#"{"ok":true}"#.into(),
            Err(e) => err(&e),
        })
    }

    fn forget_data(&self) -> String {
        self.managed(|s| match s.reconnect(true) {
            Ok(()) => r#"{"ok":true}"#.into(),
            Err(e) => err(&e),
        })
    }

    /// Opens the SOCKS port and starts joining Tor, with Arti's files under `arti/`.
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path);
        let callers = std::fs::read_to_string(dir.join("callers.json")).ok();
        *self.callers.lock().unwrap() = Callers::from_file(callers.as_deref());
        if !self.logbook.install() {
            eprintln!("tor_module: a tracing subscriber was already set; the log stays empty");
        }
        let started = Service::start(&dir.join("arti"), Arc::new(|s| emit_status_changed(&s.to_json()))).map(Arc::new);
        if let Err(e) = &started {
            eprintln!("tor_module: {e}");
        }
        *self.service.lock().unwrap() = Some(started);
    }
}

impl AboutToUnload for TorModuleImpl {
    /// Closes the SOCKS port and stops Arti within ~1.5 s, inside the host's grace period; a
    /// reconnect in progress adds at most ~0.6 s.
    fn about_to_unload(&self) -> Shutdown {
        let service = self.service.lock().unwrap().take();
        if let Some(Ok(s)) = service {
            s.stop(Duration::from_millis(1500));
        }
        Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(TorModuleImpl);
}

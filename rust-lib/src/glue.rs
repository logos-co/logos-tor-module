//! Logos glue for `tor_module` (rust-first, `concurrency: "single"`: each reply goes to its
//! caller alone, where a multi module's results reach every module connected to it). Every
//! call returns at once; a request runs in the background and is asked after. Replies are
//! flat JSON strings, `{ ok, ... }` or `{ ok: false, error }`; gate.rs says who may call.

use std::sync::Arc;
use std::time::Duration;

use logos_rust_sdk::{AboutToUnload, LogosCaller, Shutdown};

use crate::gate::{Caller, Callers, APP};
use crate::http::Spec;
use crate::logbook::Logbook;
use crate::requests::Polled;
use crate::service::{Service, SocksState};
use crate::usage::{self, now_ms, Followers, FOLLOW_WINDOW_MS};

const NOT_AUTHORIZED: &str = r#"{"ok":false,"error":"not authorized"}"#;

pub trait TorModule: Send + Sync + 'static {
    /// `{ ok, state, progress, detail, socks, since, joinMs }`. `state` is idle, connecting,
    /// ready, blocked or failed; `progress` is the percent joined; `socks` is the SOCKS port,
    /// `socks5h://IP:PORT`, where it listens, else null (turned off); `since` is when the state
    /// began (unix ms); `joinMs` is how long the last start took to be ready. A module that
    /// asks starts Tor if it is idle, so it never reads idle itself, and counts as an app
    /// following Tor for 90 s.
    fn status(&self) -> String;
    /// Starts an HTTP request through Tor and answers `{ ok, request }` at once. `spec` is
    /// `{ method, url, headers: [[name, value]], http2, isolation, timeoutMs }` and `body` its
    /// bytes. https anywhere; plain http to onion services only. `http2` asks for HTTP/2 alone
    /// (gRPC). Requests with the same `isolation` share a circuit and a connection; with none
    /// each gets its own; no two modules ever share. Any module.
    fn request(&self, spec: String, body: Vec<u8>) -> String;
    /// `{ ok, state: "pending" }`, then once `{ ok, state: "done", status, headers, trailers,
    /// body (base64), http2 }` or `{ ok, state: "failed", error }`. The module that started
    /// the request alone may ask.
    fn response(&self, request: String) -> String;
    /// `{ ok, cancelled }`. The module that started the request alone may cancel it.
    fn cancel(&self, request: String) -> String;
    /// `{ ok, startedAt, sent, received, streams: { open, total }, files, memory,
    /// apps: [{ module, seenAt, active, sent, received, requests }], socks: { sent, received } }`:
    /// bytes into Tor and out of it and the Tor streams opened since `startedAt`; each module's
    /// share, and the SOCKS port's; Arti's files; this process's memory (null when unknown).
    /// The Tor app only.
    fn usage(&self) -> String;
    /// `{ ok, socks: { enabled, address, listening, error } }`. The Tor app only.
    fn settings(&self) -> String;
    /// Opens the SOCKS port for other programs at `address` (IP:PORT), or closes it, and
    /// saves the choice; the same reply as settings(). The Tor app only.
    fn set_socks(&self, enabled: bool, address: String) -> String;
    /// `{ ok, entries: [{ at, level, target, message }] }`: Arti's last `lines` log entries,
    /// INFO and up, oldest first. The Tor app only.
    fn log_tail(&self, lines: i64) -> String;
    /// Stops Arti and starts it again; requests and SOCKS streams in flight end. `{ ok }` once
    /// it is joining again. Starts an idle Tor. The Tor app only.
    fn reconnect(&self) -> String;
    /// Reconnects with Arti's state and directory cache deleted in between: new entry
    /// guards, and the directory downloaded again (about 7 MB). The Tor app only.
    fn forget_data(&self) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

#[allow(dead_code)] // Read by logos-lidl-gen, which generates the emitters.
pub trait TorModuleEvents {
    /// status()'s reply, when the state, the progress or the SOCKS port changed.
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

fn socks_json(s: &SocksState) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "socks": {
            "enabled": s.setting.enabled,
            "address": s.setting.address,
            "listening": s.listening.map(|a| format!("socks5h://{a}")),
            "error": s.error,
        }
    })
}

impl TorModuleImpl {
    /// Cloned out, so a reconnect in progress never holds up another call.
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

    /// Runs `f` for the module that is calling, which owns the requests it starts. A host
    /// anchor, such as `logosctl call`, only when callers.json allows it.
    fn as_owner(&self, f: impl FnOnce(&Service, &str) -> String) -> String {
        let owner = match caller() {
            Caller::Module(name) if !name.is_empty() => name,
            Caller::Host if self.callers.lock().unwrap().allow_host => "host".to_string(),
            _ => return NOT_AUTHORIZED.into(),
        };
        if owner != APP {
            self.followers.saw(&owner, now_ms());
        }
        match self.service() {
            Ok(s) => f(&s, &owner),
            Err(e) => err(&e),
        }
    }
}

impl TorModule for TorModuleImpl {
    fn status(&self) -> String {
        let app = match caller() {
            Caller::Module(name) if name != APP => Some(name),
            _ => None,
        };
        match self.service() {
            Ok(s) => {
                if let Some(name) = app {
                    self.followers.saw(&name, now_ms());
                    s.demand();
                }
                s.status().to_json()
            }
            Err(e) => err(&e),
        }
    }

    fn request(&self, spec: String, body: Vec<u8>) -> String {
        self.as_owner(|s, owner| {
            let spec: Spec = match serde_json::from_str(&spec) {
                Ok(spec) => spec,
                Err(e) => return err(&format!("request spec: {e}")),
            };
            match s.request(owner, spec, body) {
                Ok(id) => serde_json::json!({ "ok": true, "request": id }).to_string(),
                Err(e) => err(&e),
            }
        })
    }

    fn response(&self, request: String) -> String {
        self.as_owner(|s, owner| match s.response(owner, &request) {
            None => err("no such request"),
            Some(Polled::Pending) => r#"{"ok":true,"state":"pending"}"#.into(),
            Some(Polled::Done(Ok(answer))) => {
                let mut v = answer.to_json();
                v["ok"] = true.into();
                v.to_string()
            }
            Some(Polled::Done(Err(e))) => serde_json::json!({ "ok": true, "state": "failed", "error": e }).to_string(),
        })
    }

    fn cancel(&self, request: String) -> String {
        self.as_owner(|s, owner| serde_json::json!({ "ok": true, "cancelled": s.cancel(owner, &request) }).to_string())
    }

    fn usage(&self) -> String {
        self.managed(|s| {
            let now = now_ms();
            let c = s.usage();
            let seen: std::collections::HashMap<String, u64> = self.followers.all().into_iter().collect();
            let mut apps: Vec<serde_json::Value> = s
                .apps()
                .into_iter()
                .map(|a| {
                    let at = seen.get(&a.module).copied();
                    serde_json::json!({
                        "module": a.module, "seenAt": at, "active": at.is_some_and(|t| now.saturating_sub(t) <= FOLLOW_WINDOW_MS),
                        "sent": a.sent, "received": a.received, "requests": a.requests,
                    })
                })
                .collect();
            let asked_only: Vec<(String, u64)> =
                seen.into_iter().filter(|(m, _)| !apps.iter().any(|a| a["module"] == m.as_str())).collect();
            for (module, at) in asked_only {
                apps.push(serde_json::json!({
                    "module": module, "seenAt": at, "active": now.saturating_sub(at) <= FOLLOW_WINDOW_MS,
                    "sent": 0, "received": 0, "requests": 0,
                }));
            }
            apps.sort_by(|a, b| a["module"].as_str().cmp(&b["module"].as_str()));
            let socks = s.socks_traffic();
            serde_json::json!({
                "ok": true,
                "startedAt": s.started_at(),
                "sent": c.sent,
                "received": c.received,
                "streams": { "open": c.open, "total": c.opened },
                "files": usage::dir_size(s.dir()),
                "memory": usage::memory(),
                "apps": apps,
                "socks": { "sent": socks.sent(), "received": socks.received() },
            })
            .to_string()
        })
    }

    fn settings(&self) -> String {
        self.managed(|s| socks_json(&s.socks()).to_string())
    }

    fn set_socks(&self, enabled: bool, address: String) -> String {
        self.managed(|s| match s.set_socks(enabled, &address) {
            Ok(state) => socks_json(&state).to_string(),
            Err(e) => err(&e),
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

    /// Opens Tor with its files under `arti/`, and the SOCKS port if settings.json says so.
    /// Tor joins when an app asks.
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path);
        let callers = std::fs::read_to_string(dir.join("callers.json")).ok();
        *self.callers.lock().unwrap() = Callers::from_file(callers.as_deref());
        if !self.logbook.install() {
            eprintln!("tor_module: a tracing subscriber was already set; the log stays empty");
        }
        let sink = Arc::new(|s: &crate::status::Status| emit_status_changed(&s.to_json()));
        let started = Service::start(&dir.join("arti"), Some(dir.join("settings.json")), sink).map(Arc::new);
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

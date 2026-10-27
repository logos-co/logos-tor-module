//! What status() answers and status_changed carries.

use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Joining the Tor network; connections wait until it is done.
    Connecting,
    /// Joined: connections go out at once.
    Ready,
    /// No progress for a while: no network, or Tor blocked on this one.
    Blocked,
    /// Tor could not start, or joining failed; it is retried.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    /// Percent joined.
    pub progress: u8,
    /// Arti's own words.
    pub detail: String,
    /// `socks5h://127.0.0.1:PORT`, once the port listens.
    pub socks: Option<String>,
}

impl Status {
    pub fn starting() -> Self {
        Self { state: State::Connecting, progress: 0, detail: "starting".into(), socks: None }
    }

    /// `{ ok: true, state, progress, detail, socks }`.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "ok": true,
            "state": self.state,
            "progress": self.progress,
            "detail": self.detail,
            "socks": self.socks,
        })
        .to_string()
    }
}

/// Arti's bootstrap status as plain values.
pub struct Progress<'a> {
    pub fraction: f32,
    pub ready: bool,
    pub blocked: Option<&'a str>,
    pub detail: &'a str,
}

/// What Arti's status means here; `joined` once bootstrap() returned. Blocked wins: a
/// joined client can lose the network too.
pub fn from_progress(p: &Progress, joined: bool) -> (State, u8, String) {
    let pct = (p.fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
    match p.blocked {
        Some(why) => (State::Blocked, pct, why.to_string()),
        None if joined || p.ready => (State::Ready, 100, p.detail.to_string()),
        None => (State::Connecting, pct.min(99), p.detail.to_string()),
    }
}

pub type Sink = Arc<dyn Fn(&Status) + Send + Sync>;

/// The current status. Listeners hear of a change in state, progress or port, not in the
/// detail, which changes with every batch of directory documents.
#[derive(Clone)]
pub struct Tracker {
    status: Arc<Mutex<Status>>,
    sink: Sink,
}

impl Tracker {
    pub fn new(sink: Sink) -> Self {
        Self { status: Arc::new(Mutex::new(Status::starting())), sink }
    }

    pub fn get(&self) -> Status {
        self.status.lock().unwrap().clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut Status)) {
        let now = {
            let mut s = self.status.lock().unwrap();
            let before = (s.state, s.progress, s.socks.clone());
            f(&mut s);
            (before != (s.state, s.progress, s.socks.clone())).then(|| s.clone())
        };
        if let Some(s) = now {
            (self.sink)(&s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(fraction: f32, ready: bool, blocked: Option<&str>) -> (State, u8, String) {
        let progress = Progress { fraction, ready, blocked, detail: "d" };
        from_progress(&progress, false)
    }

    #[test]
    fn progress_maps_to_states() {
        assert_eq!(p(0.45, false, None), (State::Connecting, 45, "d".into()));
        // 100% alone is not Ready: only Arti's ready, or a finished join, is.
        assert_eq!(p(1.0, false, None).0, State::Connecting);
        assert_eq!(p(1.0, false, None).1, 99);
        assert_eq!(p(0.85, true, None), (State::Ready, 100, "d".into()));
        assert_eq!(p(0.3, false, Some("no network")), (State::Blocked, 30, "no network".into()));
        let joined = Progress { fraction: 0.85, ready: false, blocked: None, detail: "d" };
        assert_eq!(from_progress(&joined, true).0, State::Ready);
        let lost = Progress { fraction: 0.85, ready: false, blocked: Some("lost"), detail: "d" };
        assert_eq!(from_progress(&lost, true).0, State::Blocked);
    }

    #[test]
    fn listeners_hear_state_and_progress_not_detail() {
        let heard: Arc<Mutex<Vec<String>>> = Arc::default();
        let log = heard.clone();
        let tracker = Tracker::new(Arc::new(move |s| log.lock().unwrap().push(s.to_json())));
        tracker.update(|s| s.detail = "fetching 10/9185".into());
        tracker.update(|s| s.socks = Some("socks5h://127.0.0.1:9".into()));
        tracker.update(|s| s.detail = "fetching 20/9185".into());
        tracker.update(|s| (s.state, s.progress) = (State::Ready, 100));
        let heard = heard.lock().unwrap();
        assert_eq!(heard.len(), 2);
        let last: serde_json::Value = serde_json::from_str(&heard[1]).unwrap();
        assert_eq!(last, serde_json::json!({ "ok": true, "state": "ready", "progress": 100, "detail": "fetching 20/9185", "socks": "socks5h://127.0.0.1:9" }));
    }
}

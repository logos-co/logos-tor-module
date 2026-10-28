//! What status() answers and status_changed carries.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;

use crate::usage::now_ms;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Not started: no app has asked for Tor since the module loaded.
    Idle,
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
    /// Unix milliseconds when the state began.
    pub since: u64,
    /// How long the last start took to reach Ready.
    pub join_ms: Option<u64>,
}

impl Status {
    pub fn idle() -> Self {
        Self { state: State::Idle, progress: 0, detail: String::new(), socks: None, since: now_ms(), join_ms: None }
    }

    /// `{ ok: true, state, progress, detail, socks, since, joinMs }`.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "ok": true,
            "state": self.state,
            "progress": self.progress,
            "detail": self.detail,
            "socks": self.socks,
            "since": self.since,
            "joinMs": self.join_ms,
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
    launched: Arc<Mutex<Instant>>,
    sink: Sink,
}

impl Tracker {
    pub fn new(sink: Sink) -> Self {
        Self { status: Arc::new(Mutex::new(Status::idle())), launched: Arc::new(Mutex::new(Instant::now())), sink }
    }

    pub fn get(&self) -> Status {
        self.status.lock().unwrap().clone()
    }

    /// Tor starts again: connecting from 0%, and the join is timed from now.
    pub fn relaunch(&self, detail: &str) {
        *self.launched.lock().unwrap() = Instant::now();
        self.update(|s| (s.state, s.progress, s.detail, s.join_ms, s.since) = (State::Connecting, 0, detail.to_string(), None, now_ms()));
    }

    pub fn update(&self, f: impl FnOnce(&mut Status)) {
        let now = {
            let mut s = self.status.lock().unwrap();
            let before = (s.state, s.progress, s.socks.clone());
            f(&mut s);
            if s.state != before.0 {
                s.since = now_ms();
                if s.state == State::Ready && s.join_ms.is_none() {
                    s.join_ms = Some(self.launched.lock().unwrap().elapsed().as_millis() as u64);
                }
            }
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
        let mut last: serde_json::Value = serde_json::from_str(&heard[1]).unwrap();
        assert!(last["since"].as_u64().unwrap() > 0 && last["joinMs"].is_u64(), "{last}");
        for k in ["since", "joinMs"] {
            last.as_object_mut().unwrap().remove(k);
        }
        assert_eq!(last, serde_json::json!({ "ok": true, "state": "ready", "progress": 100, "detail": "fetching 20/9185", "socks": "socks5h://127.0.0.1:9" }));
    }

    #[test]
    fn a_relaunch_times_the_next_join() {
        let tracker = Tracker::new(Arc::new(|_| {}));
        tracker.update(|s| s.state = State::Ready);
        let first = tracker.get();
        assert!(first.join_ms.is_some());
        tracker.relaunch("reconnecting");
        let again = tracker.get();
        assert_eq!((again.state, again.progress, again.join_ms, again.detail.as_str()), (State::Connecting, 0, None, "reconnecting"));
        assert!(again.since >= first.since);
        tracker.update(|s| s.progress = 40);
        assert_eq!(tracker.get().since, again.since, "progress alone keeps since");
        tracker.update(|s| s.state = State::Ready);
        assert!(tracker.get().join_ms.is_some());
    }
}

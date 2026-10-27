//! What status() answers and status_changed carries.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// No progress for a while, for the reason `blockage` gives.
    Blocked,
    /// Tor could not start, or joining failed; it is retried.
    Failed,
}

/// What Arti judges keeps Tor from getting through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Blockage {
    /// No connection opens: this computer looks offline.
    Offline,
    /// Connections open but no Tor handshake completes: something on the way filters Tor.
    Filtering,
    /// The clock is off, so relays' certificates and the directory look wrong.
    Clock,
    /// Some other trouble reaching Tor's relays.
    CantReachTor,
    /// Directory downloads keep failing or stalling: mostly a slow or unsteady connection.
    Directory,
}

/// A directory that keeps stalling during the first join reads as slow, not blocked, this long:
/// on a slow connection its downloads time out again and again before one completes.
pub const DIRECTORY_GRACE: Duration = Duration::from_secs(180);

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
    /// While Arti reports one.
    pub blockage: Option<Blockage>,
}

impl Status {
    pub fn idle() -> Self {
        Self { state: State::Idle, progress: 0, detail: String::new(), socks: None, since: now_ms(), join_ms: None, blockage: None }
    }

    /// `{ ok: true, state, progress, detail, socks, since, joinMs, blockage }`.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "ok": true,
            "state": self.state,
            "progress": self.progress,
            "detail": self.detail,
            "socks": self.socks,
            "since": self.since,
            "joinMs": self.join_ms,
            "blockage": self.blockage,
        })
        .to_string()
    }
}

/// Arti's bootstrap status as plain values.
pub struct Progress<'a> {
    pub fraction: f32,
    pub ready: bool,
    pub blocked: Option<(Blockage, &'a str)>,
    pub detail: &'a str,
}

/// What Arti's status means here; `joined` once bootstrap() returned, `stalled` how long the
/// directory has read stuck. Blocked wins, as a joined client can lose the network too; but
/// during the first join a stuck directory reads as connecting for DIRECTORY_GRACE.
pub fn from_progress(p: &Progress, joined: bool, stalled: Duration) -> (State, u8, String, Option<Blockage>) {
    let pct = (p.fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
    match p.blocked {
        Some((Blockage::Directory, why)) if !joined && stalled < DIRECTORY_GRACE => {
            (State::Connecting, pct.min(99), why.to_string(), Some(Blockage::Directory))
        }
        Some((kind, why)) => (State::Blocked, pct, why.to_string(), Some(kind)),
        None if joined || p.ready => (State::Ready, 100, p.detail.to_string(), None),
        None => (State::Connecting, pct.min(99), p.detail.to_string(), None),
    }
}

pub type Sink = Arc<dyn Fn(&Status) + Send + Sync>;

/// The current status. Listeners hear of a change in state, progress, port or blockage, not
/// in the detail, which changes with every batch of directory documents.
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
        self.update(|s| {
            (s.state, s.progress, s.detail, s.join_ms, s.since, s.blockage) = (State::Connecting, 0, detail.to_string(), None, now_ms(), None)
        });
    }

    pub fn update(&self, f: impl FnOnce(&mut Status)) {
        let now = {
            let mut s = self.status.lock().unwrap();
            let before = (s.state, s.progress, s.socks.clone(), s.blockage);
            f(&mut s);
            if s.state != before.0 {
                s.since = now_ms();
                if s.state == State::Ready && s.join_ms.is_none() {
                    s.join_ms = Some(self.launched.lock().unwrap().elapsed().as_millis() as u64);
                }
            }
            (before != (s.state, s.progress, s.socks.clone(), s.blockage)).then(|| s.clone())
        };
        if let Some(s) = now {
            (self.sink)(&s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(fraction: f32, ready: bool, blocked: Option<(Blockage, &str)>) -> (State, u8, String, Option<Blockage>) {
        let progress = Progress { fraction, ready, blocked, detail: "d" };
        from_progress(&progress, false, Duration::ZERO)
    }

    #[test]
    fn progress_maps_to_states() {
        assert_eq!(p(0.45, false, None), (State::Connecting, 45, "d".into(), None));
        // 100% alone is not Ready: only Arti's ready, or a finished join, is.
        assert_eq!(p(1.0, false, None).0, State::Connecting);
        assert_eq!(p(1.0, false, None).1, 99);
        assert_eq!(p(0.85, true, None), (State::Ready, 100, "d".into(), None));
        let offline = p(0.3, false, Some((Blockage::Offline, "no network")));
        assert_eq!(offline, (State::Blocked, 30, "no network".into(), Some(Blockage::Offline)));
        let joined = Progress { fraction: 0.85, ready: false, blocked: None, detail: "d" };
        assert_eq!(from_progress(&joined, true, Duration::ZERO).0, State::Ready);
        let lost = Progress { fraction: 0.85, ready: false, blocked: Some((Blockage::Filtering, "lost")), detail: "d" };
        assert_eq!(from_progress(&lost, true, Duration::ZERO).0, State::Blocked);
    }

    #[test]
    fn a_stuck_directory_reads_as_slow_before_blocked() {
        let stuck = Progress { fraction: 0.26, ready: false, blocked: Some((Blockage::Directory, "can't make progress")), detail: "d" };
        let early = from_progress(&stuck, false, Duration::from_secs(60));
        assert_eq!(early, (State::Connecting, 26, "can't make progress".into(), Some(Blockage::Directory)));
        assert_eq!(from_progress(&stuck, false, DIRECTORY_GRACE).0, State::Blocked);
        // Joined already: no grace.
        assert_eq!(from_progress(&stuck, true, Duration::ZERO).0, State::Blocked);
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
        assert!(last["since"].as_u64().unwrap() > 0 && last["joinMs"].is_u64() && last["blockage"].is_null(), "{last}");
        for k in ["since", "joinMs", "blockage"] {
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

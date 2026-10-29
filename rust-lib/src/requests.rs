//! Requests in flight, each readable by the module that started it and by no other. A module
//! starts one and asks for its response until it is done; the answer is handed over once.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::http::Response;

/// Requests one module may have in flight.
pub const PER_MODULE: usize = 64;
const TOTAL: usize = 1024;
/// A request nobody asked about this long after its timeout is dropped.
const UNREAD: Duration = Duration::from_secs(60);

pub type Answer = Result<Response, String>;

pub enum Polled {
    Pending,
    Done(Answer),
}

struct Entry {
    owner: String,
    expires: Instant,
    answer: oneshot::Receiver<Answer>,
    task: AbortHandle,
}

#[derive(Default)]
pub struct Requests(Mutex<HashMap<String, Entry>>);

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    hex::encode(bytes)
}

impl Requests {
    /// Registers a started request; its task's answer arrives on `answer`.
    pub fn add(&self, owner: &str, timeout: Duration, answer: oneshot::Receiver<Answer>, task: AbortHandle) -> Result<String, String> {
        let mut live = self.0.lock().unwrap();
        let now = Instant::now();
        live.retain(|_, e| {
            let keep = e.expires > now;
            if !keep {
                e.task.abort();
            }
            keep
        });
        if live.len() >= TOTAL || live.values().filter(|e| e.owner == owner).count() >= PER_MODULE {
            task.abort();
            return Err(format!("too many requests in flight (at most {PER_MODULE} per module)"));
        }
        let id = new_id();
        live.insert(id.clone(), Entry { owner: owner.to_string(), expires: now + timeout + UNREAD, answer, task });
        Ok(id)
    }

    /// None when `owner` started no such request.
    pub fn poll(&self, owner: &str, id: &str) -> Option<Polled> {
        let mut live = self.0.lock().unwrap();
        let entry = live.get_mut(id).filter(|e| e.owner == owner)?;
        let answer = match entry.answer.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => return Some(Polled::Pending),
            Ok(answer) => answer,
            // Its task went with the run it was in.
            Err(oneshot::error::TryRecvError::Closed) => Err("interrupted: Tor restarted".into()),
        };
        live.remove(id);
        Some(Polled::Done(answer))
    }

    pub fn cancel(&self, owner: &str, id: &str) -> bool {
        let mut live = self.0.lock().unwrap();
        match live.get(id) {
            Some(e) if e.owner == owner => {
                e.task.abort();
                live.remove(id);
                true
            }
            _ => false,
        }
    }

    pub fn in_flight(&self, owner: &str) -> usize {
        self.0.lock().unwrap().values().filter(|e| e.owner == owner).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> Response {
        Response { status: 200, headers: vec![], trailers: vec![], body: b"ok".to_vec(), http2: false }
    }

    #[tokio::test]
    async fn only_the_owner_reads_it_and_only_once() {
        let r = Requests::default();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(async {}).abort_handle();
        let id = r.add("zcash_node_module", Duration::from_secs(5), rx, task).unwrap();
        assert_eq!(id.len(), 32);
        assert!(r.poll("bitcoin_wallet_core", &id).is_none(), "another module cannot read it");
        assert!(!r.cancel("bitcoin_wallet_core", &id), "nor cancel it");
        assert!(matches!(r.poll("zcash_node_module", &id), Some(Polled::Pending)));
        tx.send(Ok(response())).unwrap();
        assert!(matches!(r.poll("zcash_node_module", &id), Some(Polled::Done(Ok(ref a))) if a.body == b"ok"));
        assert!(r.poll("zcash_node_module", &id).is_none(), "handed over once");
    }

    #[tokio::test]
    async fn a_dropped_task_reads_as_interrupted() {
        let r = Requests::default();
        let (tx, rx) = oneshot::channel::<Answer>();
        let id = r.add("m", Duration::from_secs(5), rx, tokio::spawn(async {}).abort_handle()).unwrap();
        drop(tx);
        assert!(matches!(r.poll("m", &id), Some(Polled::Done(Err(ref e))) if e.contains("interrupted")));
    }

    #[tokio::test]
    async fn a_module_has_a_limit() {
        let r = Requests::default();
        let mut keep = Vec::new();
        for _ in 0..PER_MODULE {
            let (tx, rx) = oneshot::channel();
            keep.push(tx);
            r.add("m", Duration::from_secs(5), rx, tokio::spawn(async {}).abort_handle()).unwrap();
        }
        let (_tx, rx) = oneshot::channel();
        assert!(r.add("m", Duration::from_secs(5), rx, tokio::spawn(async {}).abort_handle()).unwrap_err().contains("too many"));
        let (_tx2, rx) = oneshot::channel();
        assert!(r.add("other", Duration::from_secs(5), rx, tokio::spawn(async {}).abort_handle()).is_ok());
        assert_eq!(r.in_flight("m"), PER_MODULE);
    }
}

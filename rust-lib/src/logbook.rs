//! Arti's log, INFO and up, kept in memory for the Tor app and never written to disk. Arti
//! scrubs addresses from what it logs unless told otherwise, and this module never tells it.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::usage::now_ms;

/// Entries kept; older ones drop off.
pub const KEEP: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Unix milliseconds.
    pub at: u64,
    pub level: &'static str,
    /// The Arti crate that logged it, such as `tor_dirmgr`.
    pub target: String,
    pub message: String,
}

#[derive(Clone, Default)]
pub struct Logbook(Arc<Mutex<VecDeque<Entry>>>);

impl Logbook {
    /// The last `n` entries, oldest first.
    pub fn tail(&self, n: usize) -> Vec<Entry> {
        let log = self.0.lock().unwrap();
        log.iter().skip(log.len().saturating_sub(n)).cloned().collect()
    }

    fn push(&self, entry: Entry) {
        let mut log = self.0.lock().unwrap();
        if log.len() == KEEP {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Makes this the process's tracing subscriber; false when one is set already.
    pub fn install(&self) -> bool {
        use tracing_subscriber::layer::SubscriberExt;
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(self.clone())).is_ok()
    }
}

fn kept(level: &Level) -> bool {
    *level <= Level::INFO
}

impl<S: Subscriber> Layer<S> for Logbook {
    // Arti's DEBUG and TRACE are never even formatted.
    fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
        if kept(meta.level()) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn enabled(&self, meta: &Metadata<'_>, _: Context<'_, S>) -> bool {
        kept(meta.level())
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::INFO)
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut text = Text::default();
        event.record(&mut text);
        let meta = event.metadata();
        let message = if text.fields.is_empty() { text.message } else { format!("{}{}", text.message, text.fields) };
        self.push(Entry { at: now_ms(), level: meta.level().as_str(), target: meta.target().to_string(), message });
    }
}

/// The message, then the other fields as ` name=value`.
#[derive(Default)]
struct Text {
    message: String,
    fields: String,
}

impl Visit for Text {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn keeps_info_and_up_with_their_fields() {
        let book = Logbook::default();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(book.clone()), || {
            tracing::info!(target: "tor_dirmgr", "Marked consensus usable.");
            tracing::debug!(target: "tor_dirmgr", "not kept");
            tracing::trace!("not kept either");
            tracing::warn!(target: "tor_guardmgr", n = 3, why = "timeout", "Guards failed");
        });
        let got = book.tail(10);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!((got[0].level, got[0].target.as_str(), got[0].message.as_str()), ("INFO", "tor_dirmgr", "Marked consensus usable."));
        assert_eq!((got[1].level, got[1].message.as_str()), ("WARN", "Guards failed n=3 why=timeout"));
        assert!(got[0].at > 0 && got[0].at <= got[1].at);
    }

    #[test]
    fn keeps_the_last_entries_only() {
        let book = Logbook::default();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(book.clone()), || {
            for i in 0..KEEP + 5 {
                tracing::info!("line {i}");
            }
        });
        assert_eq!(book.tail(usize::MAX).len(), KEEP);
        let last = book.tail(2);
        assert_eq!(last.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(), [format!("line {}", KEEP + 3), format!("line {}", KEEP + 4)]);
    }
}

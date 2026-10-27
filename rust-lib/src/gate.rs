//! Who may call what: status() is open; reading usage and the log, reconnecting and
//! forgetting Tor's data are the Tor app's. `callers.json` widens that for tests.

use serde::Deserialize;

pub const APP: &str = "tor_ui";

/// The caller as the host reported it, mirrored so this file needs no SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    Host,
    Module(String),
    Other,
}

/// Callers admitted beyond the Tor app.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Callers {
    #[serde(default)]
    pub modules: Vec<String>,
    /// Admits calls that carry a host anchor, such as `logosctl call`.
    #[serde(default)]
    pub allow_host: bool,
}

impl Callers {
    /// Absent or unreadable file: the Tor app only, so a typo never opens the door.
    pub fn from_file(contents: Option<&str>) -> Self {
        contents.and_then(|t| serde_json::from_str(t).ok()).unwrap_or_default()
    }

    /// May `caller` manage Tor.
    pub fn admits(&self, caller: &Caller) -> bool {
        match caller {
            Caller::Module(name) if !name.is_empty() => name == APP || self.modules.iter().any(|m| m == name),
            Caller::Host => self.allow_host,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str) -> Caller {
        Caller::Module(name.into())
    }

    #[test]
    fn the_app_only_by_default() {
        let c = Callers::default();
        assert!(c.admits(&m(APP)));
        for who in [m("zcash_node_module"), m(""), Caller::Host, Caller::Unknown, Caller::Other] {
            assert!(!c.admits(&who), "{who:?}");
        }
    }

    #[test]
    fn the_file_widens_it() {
        let c = Callers::from_file(Some(r#"{"modules": ["tor_test"], "allowHost": true}"#));
        assert!(c.admits(&m("tor_test")) && c.admits(&Caller::Host) && c.admits(&m(APP)));
        assert!(!c.admits(&m("zcash_node_module")));
        // A typo or an unknown key leaves the defaults.
        for bad in [r#"{"module": ["tor_test"]}"#, "not json", ""] {
            assert_eq!(Callers::from_file(Some(bad)), Callers::default(), "{bad}");
        }
        assert_eq!(Callers::from_file(None), Callers::default());
    }
}

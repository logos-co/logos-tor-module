//! Tor for Logos modules: Arti in this process, behind a SOCKS port on loopback.

pub mod service;
pub mod socks;
pub mod status;
pub mod tor;

#[cfg(feature = "logos_module")]
mod glue;

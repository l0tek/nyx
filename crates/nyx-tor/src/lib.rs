//! Tor-only transport boundary using Arti.
//!
//! Security invariant: failure to bootstrap Tor must fail closed. There is no
//! direct TCP/Clearnet fallback path in this crate.

use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct OnionEndpoint {
    pub host: String,
    pub port: u16,
}

impl OnionEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if !host.ends_with(".onion") {
            bail!("Tor-only mode accepts .onion endpoints only");
        }
        Ok(Self { host, port })
    }
}

pub struct TorTransport;

impl TorTransport {
    pub async fn bootstrap() -> Result<Self> {
        // TODO: instantiate arti_client::TorClient and bootstrap it.
        // Keep all Arti-specific configuration inside this crate.
        bail!("Arti bootstrap not implemented in scaffold")
    }
}

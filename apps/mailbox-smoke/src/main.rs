//! Opt-in live Tor smoke test for a running Nyx mailbox Onion Service.
//!
//! This tool generates random synthetic bytes. It never transmits user content.

use anyhow::{Context, Result, bail};
use nyx_protocol::{Envelope, PROTOCOL_VERSION};
use nyx_tor::{OnionEndpoint, TorTransport};
use rand::{RngCore, rngs::OsRng};

const DEFAULT_ONION_PORT: u16 = 443;

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let host = arguments.next().context(
        "usage: nyx-mailbox-smoke <v3-address.onion> [port]; requires a running mailbox server",
    )?;
    let port = arguments
        .next()
        .map(|value| value.parse::<u16>().context("invalid Onion Service port"))
        .transpose()?
        .unwrap_or(DEFAULT_ONION_PORT);
    if arguments.next().is_some() {
        bail!("too many arguments; usage: nyx-mailbox-smoke <v3-address.onion> [port]");
    }
    let endpoint = OnionEndpoint::new(host, port)?;

    let mut mailbox_token = [0_u8; 32];
    let mut synthetic_ciphertext = vec![0_u8; 256];
    OsRng.fill_bytes(&mut mailbox_token);
    OsRng.fill_bytes(&mut synthetic_ciphertext);

    println!("Bootstrapping Tor...");
    let transport = TorTransport::bootstrap().await?;
    let receipt = transport
        .deposit(
            &endpoint,
            Envelope {
                version: PROTOCOL_VERSION,
                mailbox_token,
                ciphertext: synthetic_ciphertext.clone(),
            },
        )
        .await?;
    println!("Deposit succeeded.");

    let messages = transport.fetch(&endpoint, mailbox_token, 10).await?;
    let received = messages.iter().find(|message| message.receipt == receipt);
    let Some(received) = received else {
        bail!("deposited envelope was not returned by fetch");
    };
    if received.envelope.ciphertext != synthetic_ciphertext {
        bail!("fetched synthetic ciphertext differs from deposited bytes");
    }
    println!("Fetch succeeded and returned identical opaque bytes.");

    let deleted = transport
        .acknowledge(&endpoint, mailbox_token, vec![receipt])
        .await?;
    if deleted != 1 {
        bail!("acknowledgement deleted {deleted} envelopes instead of one");
    }
    let remaining = transport.fetch(&endpoint, mailbox_token, 10).await?;
    if remaining.iter().any(|message| message.receipt == receipt) {
        bail!("acknowledged envelope is still present");
    }

    println!("ACK succeeded; the smoke-test envelope was deleted.");
    println!("Nyx mailbox Tor smoke test passed.");
    Ok(())
}

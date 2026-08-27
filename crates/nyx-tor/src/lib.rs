//! Tor-only transport boundary using Arti.
//!
//! Security invariant: failure to bootstrap Tor must fail closed. There is no
//! direct TCP/Clearnet fallback path in this crate.

use anyhow::{Context, Result, bail};
use arti_client::{TorClient, TorClientConfig};
use futures::{AsyncReadExt, AsyncWriteExt};
use nyx_protocol::{
    Envelope, MAX_FRAME_SIZE, MailboxRequest, MailboxResponse, StoredEnvelope, decode_response,
    encode_request,
};
use nyx_store::DeliveryQueue;
use std::{sync::Arc, time::Duration};
use tor_hsservice::HsId;
use tor_rtcompat::PreferredRuntime;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct OnionEndpoint {
    pub host: String,
    pub port: u16,
}

impl OnionEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        host.parse::<HsId>()
            .context("Tor-only mode requires a valid v3 .onion address")?;
        if port == 0 {
            bail!("onion endpoint port must not be zero");
        }
        Ok(Self { host, port })
    }
}

/// An Arti-backed transport that can only connect to validated Onion endpoints.
pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReport {
    pub attempted: usize,
    pub delivered: usize,
}

impl TorTransport {
    pub async fn bootstrap() -> Result<Self> {
        let client = TorClient::create_bootstrapped(TorClientConfig::default())
            .await
            .context("bootstrap Tor")?;
        Ok(Self { client })
    }

    pub async fn request(
        &self,
        endpoint: &OnionEndpoint,
        request: &MailboxRequest,
    ) -> Result<MailboxResponse> {
        let operation = async {
            // OnionEndpoint is the only accepted target type. This crate exposes no
            // method that can connect to a Clearnet hostname or IP address.
            let mut stream = self
                .client
                .connect((endpoint.host.as_str(), endpoint.port))
                .await
                .context("connect to mailbox onion service")?;
            let encoded = encode_request(request).context("encode mailbox request")?;
            let length = u32::try_from(encoded.len()).context("request frame too large")?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(&encoded).await?;
            stream.flush().await?;

            let mut length_bytes = [0_u8; 4];
            stream
                .read_exact(&mut length_bytes)
                .await
                .context("read response frame length")?;
            let response_length = u32::from_be_bytes(length_bytes) as usize;
            if response_length == 0 || response_length > MAX_FRAME_SIZE {
                bail!("mailbox returned an invalid response frame length");
            }
            let mut response = vec![0_u8; response_length];
            stream
                .read_exact(&mut response)
                .await
                .context("read mailbox response")?;
            decode_response(&response).context("decode mailbox response")
        };
        tokio::time::timeout(REQUEST_TIMEOUT, operation)
            .await
            .context("mailbox request timed out")?
    }

    pub async fn deposit(&self, endpoint: &OnionEndpoint, envelope: Envelope) -> Result<[u8; 32]> {
        match self
            .request(endpoint, &MailboxRequest::Deposit(envelope))
            .await?
        {
            MailboxResponse::Deposited { receipt } => Ok(receipt),
            MailboxResponse::Error(code) => bail!("mailbox rejected deposit: {code:?}"),
            _ => bail!("mailbox returned an unexpected response to deposit"),
        }
    }

    pub async fn health(&self, endpoint: &OnionEndpoint) -> Result<()> {
        match self
            .request(
                endpoint,
                &MailboxRequest::Health {
                    version: nyx_protocol::PROTOCOL_VERSION,
                },
            )
            .await?
        {
            MailboxResponse::Ready {
                version: nyx_protocol::PROTOCOL_VERSION,
            } => Ok(()),
            MailboxResponse::Error(nyx_protocol::MailboxErrorCode::MalformedRequest) => {
                bail!("mailbox server does not support health checks; restart the updated server")
            }
            MailboxResponse::Error(code) => bail!("mailbox health check failed: {code:?}"),
            _ => bail!("mailbox returned an unexpected health response"),
        }
    }

    pub async fn fetch(
        &self,
        endpoint: &OnionEndpoint,
        mailbox_token: [u8; 32],
        limit: u16,
    ) -> Result<Vec<StoredEnvelope>> {
        match self
            .request(
                endpoint,
                &MailboxRequest::Fetch {
                    mailbox_token,
                    limit,
                },
            )
            .await?
        {
            MailboxResponse::Messages(messages) => Ok(messages),
            MailboxResponse::Error(code) => bail!("mailbox rejected fetch: {code:?}"),
            _ => bail!("mailbox returned an unexpected response to fetch"),
        }
    }

    pub async fn acknowledge(
        &self,
        endpoint: &OnionEndpoint,
        mailbox_token: [u8; 32],
        receipts: Vec<[u8; 32]>,
    ) -> Result<u16> {
        match self
            .request(
                endpoint,
                &MailboxRequest::Acknowledge {
                    mailbox_token,
                    receipts,
                },
            )
            .await?
        {
            MailboxResponse::Acknowledged { deleted } => Ok(deleted),
            MailboxResponse::Error(code) => bail!("mailbox rejected acknowledgement: {code:?}"),
            _ => bail!("mailbox returned an unexpected response to acknowledgement"),
        }
    }

    /// Sends pending ciphertexts in queue order and retains the first failed
    /// item for a later retry. A delivery is removed from the pending view only
    /// after the mailbox confirms its receipt.
    pub async fn flush_delivery_queue(
        &self,
        endpoint: &OnionEndpoint,
        queue: &DeliveryQueue,
        limit: u16,
    ) -> Result<DeliveryReport> {
        let pending = queue
            .pending(limit)
            .context("read pending delivery queue")?;
        let mut report = DeliveryReport {
            attempted: 0,
            delivered: 0,
        };
        for delivery in pending {
            report.attempted += 1;
            queue
                .record_attempt(delivery.id)
                .context("record mailbox delivery attempt")?;
            self.deposit(endpoint, delivery.envelope)
                .await
                .context("deposit queued MLS ciphertext")?;
            queue
                .mark_delivered(delivery.id)
                .context("mark mailbox delivery complete")?;
            report.delivered += 1;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_onion_endpoints() {
        let valid = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        assert!(OnionEndpoint::new(valid, 443).is_ok());
        assert!(OnionEndpoint::new("example.com", 443).is_err());
        assert!(OnionEndpoint::new("127.0.0.1", 443).is_err());
        assert!(OnionEndpoint::new(valid, 0).is_err());
    }
}

use anyhow::{Context, Result, bail};
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{TorClient, config::TorClientConfigBuilder};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use nyx_mailbox_server::{DEFAULT_RETENTION, MailboxStore};
use nyx_protocol::{
    DEFAULT_MAILBOX_ONION, MAX_FRAME_SIZE, MailboxErrorCode, MailboxResponse, decode_request,
    encode_response,
};
use safelog::DisplayRedacted;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{HsNickname, handle_rend_requests};
use tor_proto::stream::IncomingStreamRequest;

const ONION_PORT: u16 = 443;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<()> {
    // Loads the nearest .env for local development. Existing process
    // environment variables retain precedence.
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nyx_mailbox_server=info,tor_hsservice=info".into()),
        )
        .init();

    let data_dir = std::env::var_os("NYX_MAILBOX_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("nyx-mailbox-data"));
    std::fs::create_dir_all(&data_dir).context("create mailbox data directory")?;
    let store = Arc::new(MailboxStore::open(
        data_dir.join("mailbox.sqlite3"),
        DEFAULT_RETENTION,
    )?);

    let arti_state_dir = std::env::var_os("NYX_MAILBOX_ARTI_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("arti-state"));
    let arti_cache_dir = std::env::var_os("NYX_MAILBOX_ARTI_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("arti-cache"));
    let tor_config = TorClientConfigBuilder::from_directories(&arti_state_dir, &arti_cache_dir)
        .build()
        .context("build persistent Tor configuration")?;

    tracing::info!(
        state_dir = %arti_state_dir.display(),
        "bootstrapping Tor with persistent Onion identity; no Clearnet listener will be opened"
    );
    let client = TorClient::create_bootstrapped(tor_config)
        .await
        .context("bootstrap Tor")?;
    let nickname: HsNickname = "nyx-mailbox".parse().context("invalid service nickname")?;
    let service_config = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .build()
        .context("build onion service configuration")?;
    let Some((service, rend_requests)) = client
        .launch_onion_service(service_config)
        .context("launch onion service")?
    else {
        bail!("onion service is disabled");
    };

    let onion_address = service
        .onion_address()
        .map(|id| id.display_unredacted().to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    let expected_onion = std::env::var("NYX_MAILBOX_EXPECTED_ONION")
        .unwrap_or_else(|_| DEFAULT_MAILBOX_ONION.to_owned());
    if onion_address != expected_onion {
        bail!(
            "persistent Onion identity mismatch: expected {expected_onion}, got {onion_address}; restore the matching Arti keystore in {}",
            arti_state_dir.display()
        );
    }
    tracing::info!(address = %onion_address, port = ONION_PORT, "Nyx mailbox onion service running");

    let stream_requests = handle_rend_requests(rend_requests);
    futures::pin_mut!(stream_requests);
    loop {
        tokio::select! {
            request = stream_requests.next() => {
                let Some(request) = request else {
                    bail!("onion service request stream ended unexpectedly");
                };
                let accepted_port = matches!(
                    request.request(),
                    IncomingStreamRequest::Begin(begin) if begin.port() == ONION_PORT
                );
                if !accepted_port {
                    tracing::debug!("rejected onion stream on unsupported port or command");
                    continue;
                }
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let result = async {
                        let stream = request
                            .accept(Connected::new_empty())
                            .await
                            .context("accept onion stream")?;
                        serve_stream(stream, store).await
                    };
                    match tokio::time::timeout(REQUEST_TIMEOUT, result).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::debug!(error = %error, "onion stream failed"),
                        Err(_) => tracing::debug!("onion stream timed out"),
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("install Ctrl-C handler")?;
                tracing::info!("shutting down mailbox server");
                break;
            }
        }
    }
    drop(service);
    Ok(())
}

async fn serve_stream<S>(mut stream: S, store: Arc<MailboxStore>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .context("read frame length")?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_FRAME_SIZE {
        write_response(
            &mut stream,
            &MailboxResponse::Error(MailboxErrorCode::MalformedRequest),
        )
        .await?;
        return Ok(());
    }

    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .await
        .context("read request frame")?;
    let response = match decode_request(&frame) {
        Ok(request) => store.handle(request),
        Err(_) => MailboxResponse::Error(MailboxErrorCode::MalformedRequest),
    };
    write_response(&mut stream, &response).await?;
    stream.close().await.context("close onion stream")?;
    Ok(())
}

async fn write_response<S>(stream: &mut S, response: &MailboxResponse) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let encoded = encode_response(response).context("encode mailbox response")?;
    let length = u32::try_from(encoded.len()).context("response frame too large")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

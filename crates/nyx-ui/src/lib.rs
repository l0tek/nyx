use dioxus::prelude::*;
use nyx_crypto::MlsConversation;
use nyx_store::DeliveryQueue;
use nyx_tor::{OnionEndpoint, TorTransport};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const CSS: &str = r#"
:root { font-family: Inter, system-ui, sans-serif; background: #090d12; color: #e6edf3; }
* { box-sizing: border-box; }
body { margin: 0; }
button, input { font: inherit; }
.app { min-height: 100vh; display: grid; grid-template-columns: 290px 1fr; }
.sidebar { padding: 26px; border-right: 1px solid #26303a; background: #10161d; }
.brand { margin: 0; letter-spacing: .08em; }
.eyebrow { color: #7d8996; font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }
.status { display: flex; gap: 8px; align-items: center; font-size: 13px; color: #8dd39e; margin: 18px 0 28px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #62c47c; box-shadow: 0 0 12px #62c47c; }
.contact { padding: 14px; border: 1px solid #2a3540; border-radius: 12px; background: #151d26; }
.contact strong, .contact span { display: block; }
.contact span { color: #8793a0; font-size: 12px; margin-top: 4px; }
.main { padding: 34px; display: flex; justify-content: center; }
.panel { width: min(850px, 100%); display: grid; grid-template-rows: auto 1fr auto; min-height: calc(100vh - 68px); border: 1px solid #26303a; border-radius: 16px; overflow: hidden; background: #0e141b; }
.header { padding: 20px 24px; border-bottom: 1px solid #26303a; display: flex; justify-content: space-between; align-items: center; }
.header h2 { margin: 0 0 5px; font-size: 18px; }
.subtle { color: #8793a0; font-size: 12px; }
.badge { color: #9ee6af; border: 1px solid #315c3b; background: #13251a; padding: 7px 10px; border-radius: 999px; font-size: 12px; }
.messages { padding: 24px; overflow: auto; display: flex; flex-direction: column; gap: 14px; }
.empty { margin: auto; max-width: 490px; color: #8b98a5; text-align: center; line-height: 1.55; }
.bubble { align-self: flex-end; max-width: 72%; background: #17324a; border: 1px solid #28557a; padding: 13px 15px; border-radius: 14px 14px 3px 14px; }
.bubble.incoming { align-self: flex-start; background: #18231d; border-color: #34513e; border-radius: 14px 14px 14px 3px; }
.bubble p { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; }
.meta { margin-top: 8px; color: #91abc1; font-size: 11px; }
.error { color: #ffb4ab; background: #351614; border: 1px solid #71322e; padding: 12px; border-radius: 10px; }
.composer { border-top: 1px solid #26303a; padding: 18px; display: grid; grid-template-columns: 1fr auto; gap: 12px; }
.composer input { color: #edf4fa; background: #0a1016; border: 1px solid #33404d; border-radius: 10px; padding: 12px 14px; outline: none; }
.composer input:focus { border-color: #4a87b7; box-shadow: 0 0 0 3px #17324a; }
.composer button { border: 0; border-radius: 10px; padding: 0 20px; color: #061018; background: #8dd39e; font-weight: 700; cursor: pointer; }
.composer button:disabled { opacity: .4; cursor: default; }
.warning { margin-top: 26px; color: #d8b96e; font-size: 12px; line-height: 1.5; }
.vault { margin-top: 28px; padding-top: 20px; border-top: 1px solid #26303a; }
.vault input { width: 100%; color: #edf4fa; background: #0a1016; border: 1px solid #33404d; border-radius: 9px; padding: 10px; margin: 9px 0; }
.vault-actions { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
.vault button { color: #cdd9e3; background: #1a2530; border: 1px solid #33404d; border-radius: 8px; padding: 8px; cursor: pointer; }
.vault button:disabled { opacity: .4; cursor: default; }
.vault-result { color: #91abc1; font-size: 11px; margin-top: 9px; overflow-wrap: anywhere; }
.transport { margin-top: 18px; padding: 12px; border: 1px solid #2a3540; border-radius: 10px; background: #0c1218; }
.transport-state { margin-top: 6px; color: #91abc1; font-size: 11px; line-height: 1.4; overflow-wrap: anywhere; }
@media (max-width: 760px) { .app { grid-template-columns: 1fr; } .sidebar { display: none; } .main { padding: 12px; } .panel { min-height: calc(100vh - 24px); } }
"#;

#[derive(Clone)]
struct DisplayMessage {
    plaintext: String,
    ciphertext_size: usize,
    queued: bool,
    incoming: bool,
}

#[component]
pub fn App() -> Element {
    // Development convenience only: production secrets belong in an encrypted
    // vault or service manager, not a dotenv file.
    let _ = dotenvy::dotenv();
    let mut conversation = use_signal(|| {
        MlsConversation::new_1to1(b"local-device".to_vec(), b"peer-device".to_vec())
            .map_err(|error| error.to_string())
    });
    let mut draft = use_signal(String::new);
    let mut messages = use_signal(Vec::<DisplayMessage>::new);
    let mut last_error = use_signal(|| None::<String>);
    let mut vault_password = use_signal(String::new);
    let mut vault_status = use_signal(|| None::<String>);
    let autosave_password = use_signal(|| Zeroizing::new(Vec::<u8>::new()));
    let mut vault_last_activity = use_signal(|| None::<Instant>);
    let delivery_queue = use_signal(|| {
        DeliveryQueue::open(delivery_queue_path()).map_err(|error| error.to_string())
    });
    let mailbox_token = token_from_environment("NYX_RECIPIENT_MAILBOX_TOKEN_HEX").ok();
    let local_mailbox_token = token_from_environment("NYX_LOCAL_MAILBOX_TOKEN_HEX").ok();
    let transport_status =
        use_signal(|| "Tor worker disabled: NYX_MAILBOX_ONION is not set".to_owned());
    use_future(move || {
        run_delivery_worker(
            transport_status,
            local_mailbox_token,
            conversation,
            messages,
            last_error,
            autosave_password,
        )
    });
    use_future(move || {
        run_vault_lock_timer(
            autosave_password,
            vault_last_activity,
            conversation,
            messages,
            vault_status,
        )
    });

    let mls_ready = conversation.read().is_ok();
    let member_count = conversation
        .read()
        .as_ref()
        .map(MlsConversation::member_count)
        .unwrap_or(0);

    rsx! {
        style { {CSS} }
        div { class: "app",
            aside { class: "sidebar",
                div { class: "eyebrow", "Private messaging prototype" }
                h1 { class: "brand", "NYX" }
                div { class: "status",
                    span { class: "dot" }
                    if mls_ready { "MLS session ready" } else { "MLS initialization failed" }
                }
                div { class: "eyebrow", "Conversation" }
                div { class: "contact",
                    strong { "Peer device" }
                    span { "1:1 · {member_count} MLS members" }
                }
                p { class: "warning",
                    if mailbox_token.is_some() { "MLS ciphertext is persisted to the Tor delivery queue." } else { "Set NYX_RECIPIENT_MAILBOX_TOKEN_HEX to enable durable delivery queueing." }
                }
                div { class: "transport",
                    div { class: "eyebrow", "Tor delivery" }
                    div { class: "transport-state", "{transport_status}" }
                }
                div { class: "vault",
                    div { class: "eyebrow", "Encrypted MLS state" }
                    input {
                        r#type: "password",
                        value: "{vault_password}",
                        placeholder: "Vault password",
                        oninput: move |event| {
                            vault_password.set(event.value());
                            touch_vault(&mut vault_last_activity, &autosave_password);
                        },
                    }
                    div { class: "vault-actions",
                        button {
                            disabled: !mls_ready || vault_password.read().is_empty(),
                            onclick: move |_| save_session(&conversation, &mut vault_password, autosave_password, &mut vault_last_activity, &mut vault_status),
                            "Save"
                        }
                        button {
                            disabled: vault_password.read().is_empty(),
                            onclick: move |_| load_session(&mut conversation, &mut vault_password, autosave_password, &mut vault_last_activity, &mut messages, &mut last_error, &mut vault_status),
                            "Unlock"
                        }
                        button {
                            disabled: autosave_password.read().is_empty(),
                            onclick: move |_| lock_session(&mut conversation, autosave_password, &mut vault_last_activity, &mut messages, &mut vault_status),
                            "Lock"
                        }
                    }
                    if let Some(status) = vault_status.read().as_ref() {
                        div { class: "vault-result", "{status}" }
                    }
                }
            }
            main { class: "main",
                section { class: "panel",
                    header { class: "header",
                        div {
                            h2 { "MLS conversation" }
                            div { class: "subtle", "X25519 · AES-128-GCM · SHA-256 · Ed25519" }
                        }
                        span { class: "badge", "RFC 9420 active" }
                    }
                    div { class: "messages",
                        if messages.read().is_empty() {
                            div { class: "empty",
                                h3 { "End-to-end encryption is initialized" }
                                p { "Every message entered below is converted into a real OpenMLS PrivateMessage and decrypted by the simulated peer group before it appears here." }
                            }
                        }
                        for (index, message) in messages.read().iter().enumerate() {
                            div { class: if message.incoming { "bubble incoming" } else { "bubble" }, key: "{index}",
                                p { "{message.plaintext}" }
                                div { class: "meta",
                                    "MLS ciphertext: {message.ciphertext_size} bytes · "
                                    if message.queued { "queued for Tor delivery" } else { "local only" }
                                    " · decrypted by peer"
                                }
                            }
                        }
                        if let Some(error) = last_error.read().as_ref() {
                            div { class: "error", "{error}" }
                        }
                    }
                    div { class: "composer",
                        input {
                            value: "{draft}",
                            placeholder: "Write a message for the MLS peer…",
                            disabled: !mls_ready,
                            oninput: move |event| {
                                draft.set(event.value());
                                touch_vault(&mut vault_last_activity, &autosave_password);
                            },
                            onkeydown: move |event| {
                                if event.key() == Key::Enter {
                                    touch_vault(&mut vault_last_activity, &autosave_password);
                                    send_message(&mut conversation, &delivery_queue, &mailbox_token, &mut draft, &mut messages, &mut last_error);
                                }
                            }
                        }
                        button {
                            disabled: !mls_ready || draft.read().trim().is_empty(),
                            onclick: move |_| {
                                touch_vault(&mut vault_last_activity, &autosave_password);
                                send_message(&mut conversation, &delivery_queue, &mailbox_token, &mut draft, &mut messages, &mut last_error);
                            },
                            "Encrypt & send"
                        }
                    }
                }
            }
        }
    }
}

fn state_path() -> PathBuf {
    std::env::var_os("NYX_DESKTOP_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("nyx-desktop-state.nyx"))
}

fn delivery_queue_path() -> PathBuf {
    std::env::var_os("NYX_DELIVERY_QUEUE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("nyx-delivery.sqlite3"))
}

fn token_from_environment(name: &str) -> Result<[u8; 32], String> {
    let encoded = std::env::var(name).map_err(|_| format!("{name} is not configured"))?;
    if encoded.len() != 64 {
        return Err("recipient mailbox token must contain 64 hexadecimal characters".into());
    }
    let mut token = [0_u8; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| "recipient mailbox token contains invalid hexadecimal data")?;
    }
    Ok(token)
}

async fn run_delivery_worker(
    mut status: Signal<String>,
    local_mailbox_token: Option<[u8; 32]>,
    mut conversation: Signal<Result<MlsConversation, String>>,
    mut messages: Signal<Vec<DisplayMessage>>,
    mut last_error: Signal<Option<String>>,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
) {
    let host = match std::env::var("NYX_MAILBOX_ONION") {
        Ok(host) => host,
        Err(_) => return,
    };
    let port = match std::env::var("NYX_MAILBOX_PORT") {
        Ok(value) => match value.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                status.set("Tor worker disabled: NYX_MAILBOX_PORT is invalid".into());
                return;
            }
        },
        Err(_) => 443,
    };
    let endpoint = match OnionEndpoint::new(host, port) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            status.set(format!("Tor worker disabled: {error}"));
            return;
        }
    };
    let queue = match DeliveryQueue::open(delivery_queue_path()) {
        Ok(queue) => queue,
        Err(error) => {
            status.set(format!("Delivery queue unavailable: {error}"));
            return;
        }
    };

    loop {
        status.set("Bootstrapping Tor…".into());
        let transport = match TorTransport::bootstrap().await {
            Ok(transport) => transport,
            Err(error) => {
                status.set(format!("Tor bootstrap failed; retrying: {error}"));
                tokio::time::sleep(Duration::from_secs(15)).await;
                continue;
            }
        };
        status.set("Tor ready; watching delivery queue".into());

        loop {
            match transport.flush_delivery_queue(&endpoint, &queue, 32).await {
                Ok(report) if report.delivered > 0 => status.set(format!(
                    "Tor ready; delivered {} queued message(s)",
                    report.delivered
                )),
                Ok(_) => status.set("Tor ready; delivery queue is empty".into()),
                Err(error) => status.set(format!("Delivery failed; queued for retry: {error}")),
            }

            if let Some(token) = local_mailbox_token {
                match transport.fetch(&endpoint, token, 32).await {
                    Ok(envelopes) => {
                        let mut receipts = Vec::new();
                        for stored in envelopes {
                            let already_processed =
                                conversation.read().as_ref().is_ok_and(|conversation| {
                                    conversation.has_inbound_receipt(&stored.receipt)
                                });
                            if already_processed {
                                receipts.push(stored.receipt);
                                continue;
                            }
                            if autosave_password.read().is_empty() {
                                last_error.set(Some(
                                    "Unlock or save the encrypted MLS vault before receiving messages"
                                        .into(),
                                ));
                                break;
                            }
                            let decrypted = match conversation.write().as_mut() {
                                Ok(conversation) => conversation
                                    .process_inbound_and_save(
                                        &stored.envelope.ciphertext,
                                        stored.receipt,
                                        stored.expires_unix_ms,
                                        state_path(),
                                        autosave_password.read().as_slice(),
                                    )
                                    .map_err(|error| error.to_string()),
                                Err(error) => Err(error.clone()),
                            };
                            match decrypted {
                                Ok(plaintext) => {
                                    receipts.push(stored.receipt);
                                    match String::from_utf8(plaintext) {
                                        Ok(plaintext) => messages.write().push(DisplayMessage {
                                            plaintext,
                                            ciphertext_size: stored.envelope.ciphertext.len(),
                                            queued: false,
                                            incoming: true,
                                        }),
                                        Err(_) => last_error.set(Some(
                                            "Received MLS application data is not UTF-8".into(),
                                        )),
                                    }
                                }
                                Err(error) => last_error
                                    .set(Some(format!("Inbound MLS message rejected: {error}"))),
                            }
                        }
                        if !receipts.is_empty() {
                            match transport.acknowledge(&endpoint, token, receipts).await {
                                Ok(deleted) => status.set(format!(
                                    "Tor ready; received and acknowledged {deleted} message(s)"
                                )),
                                Err(error) => status.set(format!(
                                    "Messages decrypted; mailbox acknowledgement failed: {error}"
                                )),
                            }
                        }
                    }
                    Err(error) => status.set(format!("Mailbox fetch failed; retrying: {error}")),
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

fn save_session(
    conversation: &Signal<Result<MlsConversation, String>>,
    password: &mut Signal<String>,
    mut autosave_password: Signal<Zeroizing<Vec<u8>>>,
    last_activity: &mut Signal<Option<Instant>>,
    status: &mut Signal<Option<String>>,
) {
    let path = state_path();
    let result: Result<(), String> = match conversation.read().as_ref() {
        Ok(conversation) => conversation
            .save_encrypted(&path, password.read().as_bytes())
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.clone()),
    };
    match result {
        Ok(()) => {
            autosave_password.set(Zeroizing::new(password.read().as_bytes().to_vec()));
            last_activity.set(Some(Instant::now()));
            status.set(Some(format!(
                "Saved encrypted state to {}; inbound safe-save is active",
                path.display()
            )));
        }
        Err(error) => status.set(Some(format!("Save failed: {error}"))),
    }
    password.write().zeroize();
}

fn load_session(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    password: &mut Signal<String>,
    mut autosave_password: Signal<Zeroizing<Vec<u8>>>,
    last_activity: &mut Signal<Option<Instant>>,
    messages: &mut Signal<Vec<DisplayMessage>>,
    last_error: &mut Signal<Option<String>>,
    status: &mut Signal<Option<String>>,
) {
    let path = state_path();
    let result = MlsConversation::load_encrypted(&path, password.read().as_bytes());
    match result {
        Ok(restored) => {
            autosave_password.set(Zeroizing::new(password.read().as_bytes().to_vec()));
            last_activity.set(Some(Instant::now()));
            conversation.set(Ok(restored));
            messages.write().clear();
            last_error.set(None);
            status.set(Some(format!("Unlocked MLS state from {}", path.display())));
        }
        Err(error) => status.set(Some(format!("Unlock failed: {error}"))),
    }
    password.write().zeroize();
}

fn send_message(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    delivery_queue: &Signal<Result<DeliveryQueue, String>>,
    mailbox_token: &Option<[u8; 32]>,
    draft: &mut Signal<String>,
    messages: &mut Signal<Vec<DisplayMessage>>,
    last_error: &mut Signal<Option<String>>,
) {
    let plaintext = draft.read().trim().to_owned();
    if plaintext.is_empty() {
        return;
    }
    let result = match conversation.write().as_mut() {
        Ok(conversation) => (|| {
            let ciphertext = conversation
                .encrypt_from_alice(plaintext.as_bytes())
                .map_err(|error| error.to_string())?;
            let queued = match (delivery_queue.read().as_ref(), mailbox_token.as_ref()) {
                (Ok(queue), Some(token)) => {
                    queue
                        .enqueue(*token, &ciphertext)
                        .map_err(|error| error.to_string())?;
                    true
                }
                _ => false,
            };
            let ciphertext_size = ciphertext.len();
            let decrypted = conversation
                .decrypt_for_bob(&ciphertext)
                .map_err(|error| error.to_string())?;
            Ok((ciphertext_size, decrypted, queued))
        })(),
        Err(error) => Err(error.clone()),
    };
    match result {
        Ok((ciphertext_size, decrypted, queued)) => match String::from_utf8(decrypted) {
            Ok(decrypted) => {
                messages.write().push(DisplayMessage {
                    plaintext: decrypted,
                    ciphertext_size,
                    queued,
                    incoming: false,
                });
                draft.set(String::new());
                last_error.set(None);
            }
            Err(_) => last_error.set(Some("Peer returned invalid UTF-8 application data".into())),
        },
        Err(error) => last_error.set(Some(error)),
    }
}

fn touch_vault(
    last_activity: &mut Signal<Option<Instant>>,
    autosave_password: &Signal<Zeroizing<Vec<u8>>>,
) {
    if !autosave_password.read().is_empty() {
        last_activity.set(Some(Instant::now()));
    }
}

fn lock_session(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    mut autosave_password: Signal<Zeroizing<Vec<u8>>>,
    last_activity: &mut Signal<Option<Instant>>,
    messages: &mut Signal<Vec<DisplayMessage>>,
    status: &mut Signal<Option<String>>,
) {
    autosave_password.set(Zeroizing::new(Vec::new()));
    last_activity.set(None);
    conversation.set(Err(
        "Vault is locked; enter the password and select Unlock".into()
    ));
    messages.write().clear();
    status.set(Some(
        "Vault locked; MLS state and autosave password were removed from memory".into(),
    ));
}

async fn run_vault_lock_timer(
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    last_activity: Signal<Option<Instant>>,
    mut conversation: Signal<Result<MlsConversation, String>>,
    mut messages: Signal<Vec<DisplayMessage>>,
    mut status: Signal<Option<String>>,
) {
    let timeout = vault_lock_timeout();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let expired = last_activity
            .read()
            .as_ref()
            .is_some_and(|activity| activity.elapsed() >= timeout);
        if expired && !autosave_password.read().is_empty() {
            let mut activity = last_activity;
            lock_session(
                &mut conversation,
                autosave_password,
                &mut activity,
                &mut messages,
                &mut status,
            );
        }
    }
}

fn vault_lock_timeout() -> Duration {
    parse_vault_lock_timeout(std::env::var("NYX_VAULT_LOCK_TIMEOUT_SECS").ok().as_deref())
}

fn parse_vault_lock_timeout(value: Option<&str>) -> Duration {
    const DEFAULT_SECONDS: u64 = 300;
    const MINIMUM_SECONDS: u64 = 30;
    const MAXIMUM_SECONDS: u64 = 86_400;
    let seconds = value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (MINIMUM_SECONDS..=MAXIMUM_SECONDS).contains(seconds))
        .unwrap_or(DEFAULT_SECONDS);
    Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::parse_vault_lock_timeout;

    #[test]
    fn vault_timeout_is_bounded_and_defaults_safely() {
        assert_eq!(parse_vault_lock_timeout(None).as_secs(), 300);
        assert_eq!(parse_vault_lock_timeout(Some("120")).as_secs(), 120);
        assert_eq!(parse_vault_lock_timeout(Some("0")).as_secs(), 300);
        assert_eq!(parse_vault_lock_timeout(Some("86401")).as_secs(), 300);
        assert_eq!(parse_vault_lock_timeout(Some("invalid")).as_secs(), 300);
    }
}

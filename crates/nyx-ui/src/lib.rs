use dioxus::prelude::*;
use nyx_crypto::MlsConversation;
use std::path::PathBuf;
use zeroize::Zeroize;

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
.vault-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.vault button { color: #cdd9e3; background: #1a2530; border: 1px solid #33404d; border-radius: 8px; padding: 8px; cursor: pointer; }
.vault button:disabled { opacity: .4; cursor: default; }
.vault-result { color: #91abc1; font-size: 11px; margin-top: 9px; overflow-wrap: anywhere; }
@media (max-width: 760px) { .app { grid-template-columns: 1fr; } .sidebar { display: none; } .main { padding: 12px; } .panel { min-height: calc(100vh - 24px); } }
"#;

#[derive(Clone)]
struct DisplayMessage {
    plaintext: String,
    ciphertext_size: usize,
}

#[component]
pub fn App() -> Element {
    let mut conversation = use_signal(|| {
        MlsConversation::new_1to1(b"local-device".to_vec(), b"peer-device".to_vec())
            .map_err(|error| error.to_string())
    });
    let mut draft = use_signal(String::new);
    let mut messages = use_signal(Vec::<DisplayMessage>::new);
    let mut last_error = use_signal(|| None::<String>);
    let mut vault_password = use_signal(String::new);
    let mut vault_status = use_signal(|| None::<String>);

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
                    "Local cryptographic demo. Tor mailbox delivery is not connected to this UI yet."
                }
                div { class: "vault",
                    div { class: "eyebrow", "Encrypted MLS state" }
                    input {
                        r#type: "password",
                        value: "{vault_password}",
                        placeholder: "Vault password",
                        oninput: move |event| vault_password.set(event.value()),
                    }
                    div { class: "vault-actions",
                        button {
                            disabled: !mls_ready || vault_password.read().is_empty(),
                            onclick: move |_| save_session(&conversation, &mut vault_password, &mut vault_status),
                            "Save"
                        }
                        button {
                            disabled: vault_password.read().is_empty(),
                            onclick: move |_| load_session(&mut conversation, &mut vault_password, &mut messages, &mut last_error, &mut vault_status),
                            "Unlock"
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
                            div { class: "bubble", key: "{index}",
                                p { "{message.plaintext}" }
                                div { class: "meta", "MLS ciphertext: {message.ciphertext_size} bytes · decrypted by peer" }
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
                            oninput: move |event| draft.set(event.value()),
                            onkeydown: move |event| {
                                if event.key() == Key::Enter {
                                    send_message(&mut conversation, &mut draft, &mut messages, &mut last_error);
                                }
                            }
                        }
                        button {
                            disabled: !mls_ready || draft.read().trim().is_empty(),
                            onclick: move |_| send_message(&mut conversation, &mut draft, &mut messages, &mut last_error),
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

fn save_session(
    conversation: &Signal<Result<MlsConversation, String>>,
    password: &mut Signal<String>,
    status: &mut Signal<Option<String>>,
) {
    let path = state_path();
    let result: Result<(), String> = match conversation.read().as_ref() {
        Ok(conversation) => conversation
            .save_encrypted(&path, password.read().as_bytes())
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.clone()),
    };
    password.write().zeroize();
    match result {
        Ok(()) => status.set(Some(format!("Saved encrypted state to {}", path.display()))),
        Err(error) => status.set(Some(format!("Save failed: {error}"))),
    }
}

fn load_session(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    password: &mut Signal<String>,
    messages: &mut Signal<Vec<DisplayMessage>>,
    last_error: &mut Signal<Option<String>>,
    status: &mut Signal<Option<String>>,
) {
    let path = state_path();
    let result = MlsConversation::load_encrypted(&path, password.read().as_bytes());
    password.write().zeroize();
    match result {
        Ok(restored) => {
            conversation.set(Ok(restored));
            messages.write().clear();
            last_error.set(None);
            status.set(Some(format!("Unlocked MLS state from {}", path.display())));
        }
        Err(error) => status.set(Some(format!("Unlock failed: {error}"))),
    }
}

fn send_message(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    draft: &mut Signal<String>,
    messages: &mut Signal<Vec<DisplayMessage>>,
    last_error: &mut Signal<Option<String>>,
) {
    let plaintext = draft.read().trim().to_owned();
    if plaintext.is_empty() {
        return;
    }
    let result = match conversation.write().as_mut() {
        Ok(conversation) => conversation
            .round_trip_from_alice(plaintext.as_bytes())
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.clone()),
    };
    match result {
        Ok((ciphertext_size, decrypted)) => match String::from_utf8(decrypted) {
            Ok(decrypted) => {
                messages.write().push(DisplayMessage {
                    plaintext: decrypted,
                    ciphertext_size,
                });
                draft.set(String::new());
                last_error.set(None);
            }
            Err(_) => last_error.set(Some("Peer returned invalid UTF-8 application data".into())),
        },
        Err(error) => last_error.set(Some(error)),
    }
}

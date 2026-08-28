use dioxus::prelude::*;
use nyx_crypto::{ContactRecord, DeviceIdentity, MlsConversation};
use nyx_protocol::{
    ClientPayload, DEFAULT_MAILBOX_ONION, decode_client_payload, encode_client_payload,
};
use nyx_store::DeliveryQueue;
use nyx_tor::{OnionEndpoint, TorTransport};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod mesh_fragment;
#[cfg(target_os = "android")]
mod meshtastic_ble;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod meshtastic_usb;

pub const CONFIG_MENU_ID: &str = "nyx-file-configuration";
pub const IMPORT_CONTACT_MENU_ID: &str = "nyx-contact-import";
pub const EXPORT_CONTACT_MENU_ID: &str = "nyx-contact-export";
const RETIRED_MAILBOX_ONION: &str =
    "g3dafmnogfvgst67jmfujbglj2sj4egeieexriyg3jcbp3w3dgd4lnad.onion";
const CSS: &str = r#"
:root { font-family: Inter, system-ui, sans-serif; background: #090d12; color: #e6edf3; }
* { box-sizing: border-box; }
body { margin: 0; }
button, input { font: inherit; }
.auth-shell { min-height: 100vh; display: grid; place-items: center; padding: 24px; background: radial-gradient(circle at top, #162331, #090d12 55%); }
.auth-card { width: min(460px, 100%); padding: 34px; border: 1px solid #2a3540; border-radius: 20px; background: #10161df2; box-shadow: 0 24px 70px #0008; }
.auth-card h1 { margin: 8px 0; font-size: 34px; letter-spacing: .12em; }
.auth-card p { color: #8c99a6; line-height: 1.55; }
.startup-spinner { width: 46px; height: 46px; margin: 24px auto; border: 4px solid #2a3540; border-top-color: #8dd39e; border-radius: 50%; animation: nyx-spin .8s linear infinite; }
@keyframes nyx-spin { to { transform: rotate(360deg); } }
.field { display: grid; gap: 6px; margin-top: 16px; }
.field label { color: #8997a5; font-size: 12px; }
.field input, .field textarea, .field select { width: 100%; color: #edf4fa; background: #090f15; border: 1px solid #33404d; border-radius: 10px; padding: 12px; resize: vertical; }
.primary { width: 100%; margin-top: 18px; border: 0; border-radius: 10px; padding: 12px; background: #8dd39e; color: #07110a; font-weight: 700; cursor: pointer; }
.primary:disabled { opacity: .45; }
.app { min-height: 100vh; display: grid; grid-template-columns: 290px 1fr; }
.sidebar { padding: 26px; border-right: 1px solid #26303a; background: #10161d; }
.brand { margin: 0; letter-spacing: .08em; }
.eyebrow { color: #7d8996; font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }
.status { display: flex; gap: 8px; align-items: center; font-size: 13px; color: #8dd39e; margin: 18px 0 28px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #62c47c; box-shadow: 0 0 12px #62c47c; }
.contact { padding: 14px; border: 1px solid #2a3540; border-radius: 12px; background: #151d26; }
.contact strong, .contact span { display: block; }
.contact span { color: #8793a0; font-size: 12px; margin-top: 4px; }
.contact-list { display: grid; gap: 8px; margin-top: 9px; }
.contact-item { width: 100%; text-align: left; color: #dce7ef; background: #111922; border: 1px solid #2a3540; border-radius: 10px; padding: 10px; cursor: pointer; }
.contact-item.active { border-color: #4e8a61; background: #14221a; }
.contact-item small { display: block; color: #778593; margin-top: 3px; }
.identity-card { margin: 16px 0; padding: 12px; border: 1px solid #2a3540; border-radius: 10px; background: #0c1218; }
.fingerprint { margin-top: 5px; color: #7f91a0; font: 9px ui-monospace, monospace; overflow-wrap: anywhere; }
.mini-button { margin-top: 8px; color: #cdd9e3; background: #1a2530; border: 1px solid #33404d; border-radius: 8px; padding: 7px 9px; cursor: pointer; }
.contact-tools { padding: 18px 22px; border-bottom: 1px solid #26303a; background: #0b1117; display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.contact-tools textarea { min-height: 76px; color: #dce7ef; background: #080e13; border: 1px solid #303d49; border-radius: 9px; padding: 9px; resize: vertical; font-size: 11px; }
.tool-actions { display: flex; gap: 8px; }
.tool-actions button { color: #dbe7ef; background: #18232d; border: 1px solid #354553; border-radius: 8px; padding: 7px 10px; cursor: pointer; }
.tool-status { color: #8fa0ad; font-size: 11px; margin-top: 6px; }
.main { padding: 34px; display: flex; flex-direction: column; align-items: center; }
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
.connection-line { display: flex; align-items: center; gap: 8px; margin-top: 8px; font-size: 12px; }
.connection-dot { width: 8px; height: 8px; border-radius: 50%; background: #66717d; }
.connection-dot.connecting { background: #d8b96e; box-shadow: 0 0 9px #d8b96e; }
.connection-dot.connected { background: #62c47c; box-shadow: 0 0 9px #62c47c; }
.connection-dot.degraded { background: #ef7d72; box-shadow: 0 0 9px #ef7d72; }
.transport-endpoint { margin-top: 6px; color: #6f7d89; font-size: 10px; overflow-wrap: anywhere; }
.config { width: min(680px, 100%); align-self: flex-start; padding: 28px; border: 1px solid #26303a; border-radius: 16px; background: #0e141b; }
.config h2 { margin-top: 0; }
.config-actions { display: flex; gap: 10px; margin-top: 22px; }
.config-actions .primary { width: auto; margin: 0; padding-inline: 24px; }
.navigation { width: min(850px, 100%); display: flex; gap: 8px; margin-bottom: 10px; }
.navigation button { color: #dce7ef; background: #111922; border: 1px solid #2a3540; border-radius: 8px; padding: 7px 13px; cursor: pointer; }
.navigation button:disabled { opacity: .35; cursor: default; }
.screen-title { flex: 1; align-self: center; text-align: center; color: #aab7c3; font-size: 13px; font-weight: 700; }
.hamburger { display: none; font-size: 20px; line-height: 1; }
.mobile-drawer-backdrop { display: none; }
.mobile-drawer { display: none; }
.drawer-entry { padding: 13px 4px; border-bottom: 1px solid #26303a; color: #dce7ef; cursor: pointer; }
.drawer-entry small { display: block; margin-top: 3px; color: #778593; }
.drawer-section { margin: 20px 0 7px; color: #7d8996; font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
.status-page { width: min(680px, 100%); align-self: flex-start; padding: 28px; border: 1px solid #26303a; border-radius: 16px; background: #0e141b; }
@media (max-width: 760px) {
  .app { grid-template-columns: 1fr; }
  .sidebar { display: none; }
  .main { padding: 12px; }
  .panel { min-height: calc(100vh - 76px); }
  .navigation { position: sticky; top: 0; z-index: 20; padding: 8px; margin: 0 0 10px; border: 1px solid #26303a; border-radius: 12px; background: #10161df5; }
  .navigation button { min-width: 42px; padding: 8px; }
  .hamburger { display: block; }
  .mobile-drawer-backdrop { display: block; position: fixed; inset: 0; z-index: 30; background: #0009; }
  .mobile-drawer { display: block; position: fixed; z-index: 31; top: 0; right: 0; width: min(330px, 88vw); height: 100vh; padding: 22px; overflow-y: auto; background: #10161d; border-left: 1px solid #33404d; box-shadow: -20px 0 50px #0008; }
}
"#;

#[derive(Clone)]
struct DisplayMessage {
    contact_device_id: Option<uuid::Uuid>,
    plaintext: String,
    ciphertext_size: usize,
    queued: bool,
    incoming: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionPhase {
    Disabled,
    Bootstrapping,
    Connecting,
    Connected,
    Degraded,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppView {
    Status,
    Chat,
    Configuration,
    ContactImport,
    ContactExport,
}

#[derive(Clone, Copy)]
enum MailboxAction {
    Add,
    Update(usize),
    Select(usize),
    Remove(usize),
}

#[derive(Clone)]
struct MailboxConnectionStatus {
    phase: ConnectionPhase,
    detail: String,
    endpoint: Option<String>,
    last_success: Option<Instant>,
}

#[derive(Clone, PartialEq, Eq)]
struct MeshtasticStatus {
    connected: bool,
    detail: String,
}

impl MeshtasticStatus {
    fn idle() -> Self {
        Self {
            connected: false,
            detail: "Kein Meshtastic-Gerät verbunden".into(),
        }
    }
}

impl MailboxConnectionStatus {
    fn initial() -> Self {
        Self {
            phase: ConnectionPhase::Disabled,
            detail: "NYX_MAILBOX_ONION is not configured".into(),
            endpoint: None,
            last_success: None,
        }
    }

    fn phase_label(&self) -> &'static str {
        match self.phase {
            ConnectionPhase::Disabled => "Disabled",
            ConnectionPhase::Bootstrapping => "Tor bootstrap",
            ConnectionPhase::Connecting => "Checking mailbox",
            ConnectionPhase::Connected => "Mailbox connected",
            ConnectionPhase::Degraded => "Mailbox unreachable",
        }
    }

    fn dot_class(&self) -> &'static str {
        match self.phase {
            ConnectionPhase::Disabled => "connection-dot",
            ConnectionPhase::Bootstrapping | ConnectionPhase::Connecting => {
                "connection-dot connecting"
            }
            ConnectionPhase::Connected => "connection-dot connected",
            ConnectionPhase::Degraded => "connection-dot degraded",
        }
    }

    fn last_success_label(&self) -> String {
        self.last_success.map_or_else(
            || "No successful mailbox check yet".into(),
            |instant| format!("Last successful check {}s ago", instant.elapsed().as_secs()),
        )
    }
}

#[component]
pub fn App() -> Element {
    // Development convenience only: production secrets belong in an encrypted
    // vault or service manager, not a dotenv file.
    let _ = dotenvy::dotenv();
    let mut identity = use_signal(|| Ok(None::<DeviceIdentity>));
    let mut conversation = use_signal(|| Err("Sign in to unlock the MLS state".into()));
    let mut draft = use_signal(String::new);
    let mut messages = use_signal(Vec::<DisplayMessage>::new);
    let mut last_error = use_signal(|| None::<String>);
    let mut auth_name = use_signal(String::new);
    let mut auth_password = use_signal(String::new);
    let mut auth_status = use_signal(|| None::<String>);
    let mut vault_status = use_signal(|| None::<String>);
    let autosave_password = use_signal(|| Zeroizing::new(Vec::<u8>::new()));
    let mut vault_last_activity = use_signal(|| None::<Instant>);
    let mut invitation_output = use_signal(String::new);
    let mut invitation_input = use_signal(String::new);
    let mut contact_status = use_signal(|| None::<String>);
    let mut reconnect_confirm = use_signal(|| None::<uuid::Uuid>);
    let mut mobile_menu_open = use_signal(|| false);
    let mut app_view = use_signal(|| AppView::Status);
    let mut back_history = use_signal(Vec::<AppView>::new);
    let mut forward_history = use_signal(Vec::<AppView>::new);
    let mut config_name = use_signal(String::new);
    let mut config_onion = use_signal(default_mailbox_onion);
    let mut config_status = use_signal(|| None::<String>);
    let mut meshtastic_ports = use_signal(Vec::<String>::new);
    let mut meshtastic_port = use_signal(String::new);
    let meshtastic_status = use_signal(MeshtasticStatus::idle);
    let meshtastic_session = use_signal(|| 0_u64);
    let mailbox_onion = use_signal(default_mailbox_onion);
    let mut startup_ready = use_signal(|| false);
    let mut startup_error = use_signal(|| None::<String>);
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    dioxus::desktop::use_muda_event_handler(move |event| {
        if event.id().0 == CONFIG_MENU_ID {
            open_configuration(
                &identity,
                &mut config_name,
                &mut config_onion,
                &mut config_status,
            );
            navigate_to(
                &mut app_view,
                AppView::Configuration,
                &mut back_history,
                &mut forward_history,
            );
        } else if event.id().0 == IMPORT_CONTACT_MENU_ID {
            navigate_to(
                &mut app_view,
                AppView::ContactImport,
                &mut back_history,
                &mut forward_history,
            );
        } else if event.id().0 == EXPORT_CONTACT_MENU_ID {
            navigate_to(
                &mut app_view,
                AppView::ContactExport,
                &mut back_history,
                &mut forward_history,
            );
        }
    });
    let mut selected_contact = use_signal(|| None::<uuid::Uuid>);
    let mut delivery_queue = use_signal(|| Err("Lokaler Speicher wird vorbereitet".into()));
    let recipient_mailbox_token =
        use_signal(|| token_from_environment("NYX_RECIPIENT_MAILBOX_TOKEN_HEX").ok());
    let local_mailbox_token = use_signal(|| {
        token_from_environment("NYX_LOCAL_MAILBOX_TOKEN_HEX")
            .ok()
            .into_iter()
            .collect::<Vec<_>>()
    });
    let transport_status = use_signal(MailboxConnectionStatus::initial);
    use_future(move || async move {
        let result = initialize_local_storage();
        match result {
            Ok(queue) => {
                delivery_queue.set(Ok(queue));
                startup_ready.set(true);
            }
            Err(error) => startup_error.set(Some(error)),
        }
    });
    use_future(move || {
        run_delivery_worker(
            startup_ready,
            transport_status,
            mailbox_onion,
            local_mailbox_token,
            conversation,
            identity,
            messages,
            last_error,
            autosave_password,
            selected_contact,
            app_view,
        )
    });
    use_future(move || {
        run_vault_lock_timer(
            autosave_password,
            vault_last_activity,
            conversation,
            identity,
            messages,
            vault_status,
        )
    });

    let account_exists = identity_path().exists();
    let authenticated = identity
        .read()
        .as_ref()
        .is_ok_and(|identity| identity.is_some());
    let mls_ready = conversation.read().is_ok();
    let mailbox_status = transport_status.read().clone();
    let mailbox_last_success = mailbox_status.last_success_label();
    let (profile_name, profile_fingerprint, contacts, configured_mailboxes) = identity
        .read()
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .map(|identity| {
            (
                identity.display_name().to_owned(),
                identity.fingerprint(),
                identity.contacts().to_vec(),
                identity.mailboxes().to_vec(),
            )
        })
        .unwrap_or_default();
    let active_contact = contacts
        .iter()
        .find(|contact| Some(contact.device_id) == *selected_contact.read())
        .cloned();
    let remote_session_ready = active_contact.as_ref().is_some_and(|contact| {
        identity
            .read()
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_some_and(|identity| identity.has_session(contact.device_id))
    });
    let keydown_contact = active_contact.clone();
    let click_contact = active_contact.clone();
    let active_contact_id = active_contact.as_ref().map(|contact| contact.device_id);
    let visible_messages = messages
        .read()
        .iter()
        .filter(|message| message.contact_device_id == active_contact_id)
        .cloned()
        .collect::<Vec<_>>();
    let current_screen = match *app_view.read() {
        AppView::Status => "Status",
        AppView::Chat => active_contact
            .as_ref()
            .map_or("Kontakt", |contact| contact.display_name.as_str()),
        AppView::Configuration => "Konfiguration",
        AppView::ContactImport => "Kontakt importieren",
        AppView::ContactExport => "Kontakt exportieren",
    };

    rsx! {
        style { {CSS} }
        if !*startup_ready.read() {
            div { class: "auth-shell",
                section { class: "auth-card", style: "text-align:center",
                    div { class: "eyebrow", "Nyx wird gestartet" }
                    h1 { "NYX" }
                    if let Some(error) = startup_error.read().as_ref() {
                        div { class: "error", "Lokaler Speicher konnte nicht initialisiert werden: {error}" }
                    } else {
                        div { class: "startup-spinner", role: "progressbar", aria_label: "App wird vorbereitet" }
                        p { "Lokale Identität und verschlüsselter Speicher werden vorbereitet …" }
                    }
                }
            }
        } else if !authenticated {
            div { class: "auth-shell",
                section { class: "auth-card",
                    div { class: "eyebrow", "Local encrypted identity" }
                    h1 { "NYX" }
                    if account_exists {
                        h2 { "Unlock this device" }
                        p { "Your profile, device keys, contacts and MLS state stay encrypted on this computer." }
                    } else {
                        h2 { "Create a local identity" }
                        p { "No server account, email address or global username is created." }
                        div { class: "field",
                            label { "Display name" }
                            input {
                                value: "{auth_name}",
                                placeholder: "Name shown in signed invitations",
                                oninput: move |event| auth_name.set(event.value()),
                            }
                        }
                    }
                    div { class: "field",
                        label { "Vault password" }
                        input {
                            r#type: "password",
                            value: "{auth_password}",
                            placeholder: "At least 12 characters",
                            oninput: move |event| auth_password.set(event.value()),
                            onkeydown: move |event| {
                                if event.key() == Key::Enter {
                                    authenticate_account(account_exists, &mut identity, &mut conversation, &mut auth_name, &mut auth_password, autosave_password, &mut vault_last_activity, recipient_mailbox_token, local_mailbox_token, mailbox_onion, &mut selected_contact, &mut auth_status);
                                }
                            }
                        }
                    }
                    button {
                        class: "primary",
                        disabled: auth_password.read().len() < 12 || (!account_exists && auth_name.read().trim().is_empty()),
                        onclick: move |_| authenticate_account(account_exists, &mut identity, &mut conversation, &mut auth_name, &mut auth_password, autosave_password, &mut vault_last_activity, recipient_mailbox_token, local_mailbox_token, mailbox_onion, &mut selected_contact, &mut auth_status),
                        if account_exists { "Unlock" } else { "Create identity" }
                    }
                    if let Some(status) = auth_status.read().as_ref() {
                        div { class: "error", style: "margin-top: 14px", "{status}" }
                    }
                }
            }
        } else {
        div { class: "app",
            aside { class: "sidebar",
                div { class: "eyebrow", "Private messaging" }
                h1 { class: "brand", "NYX" }
                div { class: "status",
                    span { class: "dot" }
                    "Local identity unlocked"
                }
                div { class: "identity-card",
                    strong { "{profile_name}" }
                    div { class: "fingerprint", "{profile_fingerprint}" }
                    button {
                        class: "mini-button",
                        onclick: move |_| lock_account(&mut conversation, &mut identity, autosave_password, &mut vault_last_activity, &mut messages, &mut vault_status),
                        "Lock device"
                    }
                }
                div { class: "eyebrow", "Contacts" }
                div { class: "contact-list",
                    if contacts.is_empty() {
                        div { class: "contact", span { "No signed contacts imported" } }
                    }
                    for contact in contacts.iter() {
                        button {
                            class: if Some(contact.device_id) == *selected_contact.read() { "contact-item active" } else { "contact-item" },
                            key: "{contact.device_id}",
                            onclick: {
                                let contact = contact.clone();
                                move |_| {
                                    select_contact(&contact, &mut selected_contact, recipient_mailbox_token, local_mailbox_token);
                                    navigate_to(&mut app_view, AppView::Chat, &mut back_history, &mut forward_history);
                                }
                            },
                            "{contact.display_name}"
                            small { if contact.verified { "Fingerprint verified" } else { "Verification required" } }
                        }
                    }
                }
                div { class: "transport",
                    div { class: "eyebrow", "Tor delivery" }
                    div { class: "connection-line",
                        span { class: mailbox_status.dot_class() }
                        strong { "{mailbox_status.phase_label()}" }
                    }
                    div { class: "transport-state", "{mailbox_status.detail}" }
                    div { class: "transport-state", "{mailbox_last_success}" }
                    if let Some(endpoint) = mailbox_status.endpoint.as_ref() {
                        div { class: "transport-endpoint", "{endpoint}" }
                    }
                }
            }
            main { class: "main",
                nav { class: "navigation",
                    button { title: "Zurück", disabled: back_history.read().is_empty(), onclick: move |_| navigate_back(&mut app_view, &mut back_history, &mut forward_history), "←" }
                    button { title: "Vor", disabled: forward_history.read().is_empty(), onclick: move |_| navigate_forward(&mut app_view, &mut back_history, &mut forward_history), "→" }
                    div { class: "screen-title", "{current_screen}" }
                    button { class: "hamburger", title: "Menü", aria_label: "Menü öffnen", onclick: move |_| mobile_menu_open.set(true), "☰" }
                }
                if *mobile_menu_open.read() {
                    div { class: "mobile-drawer-backdrop", onclick: move |_| mobile_menu_open.set(false) }
                    aside { class: "mobile-drawer",
                        div { class: "eyebrow", "Nyx Menü" }
                        h2 { "Navigation" }
                        div { class: "drawer-entry", onclick: move |_| { mobile_menu_open.set(false); navigate_to(&mut app_view, AppView::Status, &mut back_history, &mut forward_history); }, "Status" }
                        div { class: "drawer-entry", onclick: move |_| { mobile_menu_open.set(false); open_configuration(&identity, &mut config_name, &mut config_onion, &mut config_status); navigate_to(&mut app_view, AppView::Configuration, &mut back_history, &mut forward_history); }, "Konfiguration" }
                        div { class: "drawer-entry", onclick: move |_| { mobile_menu_open.set(false); navigate_to(&mut app_view, AppView::ContactImport, &mut back_history, &mut forward_history); }, "Kontakt importieren" }
                        div { class: "drawer-entry", onclick: move |_| { mobile_menu_open.set(false); navigate_to(&mut app_view, AppView::ContactExport, &mut back_history, &mut forward_history); }, "Kontakt exportieren" }
                        div { class: "drawer-section", "Importierte Kontakte" }
                        if contacts.is_empty() {
                            div { class: "drawer-entry", small { "Noch keine Kontakte importiert" } }
                        }
                        for contact in contacts.iter() {
                            div {
                                class: "drawer-entry",
                                key: "drawer-{contact.device_id}",
                                onclick: {
                                    let contact = contact.clone();
                                    move |_| {
                                        select_contact(&contact, &mut selected_contact, recipient_mailbox_token, local_mailbox_token);
                                        mobile_menu_open.set(false);
                                        navigate_to(&mut app_view, AppView::Chat, &mut back_history, &mut forward_history);
                                    }
                                },
                                "{contact.display_name}"
                                small { if contact.verified { "Fingerprint bestätigt" } else { "Bestätigung erforderlich" } }
                            }
                        }
                    }
                }
                if *app_view.read() == AppView::Status {
                    section { class: "status-page",
                        div { class: "eyebrow", "Nyx Desktop" }
                        h2 { "Status" }
                        div { class: "connection-line", span { class: mailbox_status.dot_class() } strong { "{mailbox_status.phase_label()}" } }
                        p { class: "transport-state", "{mailbox_status.detail}" }
                        p { class: "transport-state", "{mailbox_last_success}" }
                        if let Some(endpoint) = mailbox_status.endpoint.as_ref() { p { class: "transport-endpoint", "{endpoint}" } }
                        if let Some(error) = last_error.read().as_ref() { div { class: "error", "{error}" } }
                        div { class: "transport",
                            div { class: "eyebrow", "Meshtastic" }
                            div { class: "connection-line",
                                span { class: if meshtastic_status.read().connected { "connection-dot connected" } else { "connection-dot" } }
                                strong { if meshtastic_status.read().connected { "Meshtastic verbunden" } else { "Meshtastic nicht verbunden" } }
                            }
                            p { class: "transport-state", "{meshtastic_status.read().detail}" }
                            if !meshtastic_port.read().trim().is_empty() {
                                p { class: "transport-endpoint", if cfg!(target_os = "android") { "Bluetooth: {meshtastic_port}" } else { "USB: {meshtastic_port}" } }
                            }
                            button {
                                class: "mini-button",
                                onclick: move |_| {
                                    open_configuration(&identity, &mut config_name, &mut config_onion, &mut config_status);
                                    navigate_to(&mut app_view, AppView::Configuration, &mut back_history, &mut forward_history);
                                },
                                if meshtastic_status.read().connected { "Meshtastic verwalten" } else { "Meshtastic einrichten" }
                            }
                        }
                        div { class: "identity-card", strong { "{profile_name}" } div { class: "fingerprint", "{profile_fingerprint}" } }
                    }
                } else if *app_view.read() == AppView::Configuration {
                    section { class: "config",
                        div { class: "eyebrow", "Local device" }
                        h2 { "Configuration" }
                        p { class: "subtle", "Edit the master data stored in your encrypted device identity." }
                        div { class: "field",
                            label { "Display name" }
                            input { value: "{config_name}", oninput: move |event| config_name.set(event.value()) }
                        }
                        div { class: "field",
                            label { "Onion mailbox address" }
                            input { value: "{config_onion}", placeholder: "56-character-v3-address.onion", oninput: move |event| config_onion.set(event.value()) }
                        }
                        div { class: "config-actions",
                            button { class: "primary", onclick: move |_| change_mailbox(&mut identity, autosave_password, &config_onion, MailboxAction::Add, mailbox_onion, &mut config_status), "Mailbox hinzufügen" }
                        }
                        div { class: "contact-list",
                            for (index, address) in configured_mailboxes.iter().enumerate() {
                                div { class: "contact", key: "{address}",
                                    strong { "{address}" }
                                    span { if Some(address.as_str()) == identity.read().as_ref().ok().and_then(Option::as_ref).and_then(DeviceIdentity::mailbox_onion) { "Aktiv" } else { "Verfügbar" } }
                                    div { class: "tool-actions",
                                        button { onclick: move |_| change_mailbox(&mut identity, autosave_password, &config_onion, MailboxAction::Select(index), mailbox_onion, &mut config_status), "Auswählen" }
                                        button { onclick: move |_| change_mailbox(&mut identity, autosave_password, &config_onion, MailboxAction::Update(index), mailbox_onion, &mut config_status), "Mit Eingabe ersetzen" }
                                        button { onclick: move |_| change_mailbox(&mut identity, autosave_password, &config_onion, MailboxAction::Remove(index), mailbox_onion, &mut config_status), "Entfernen" }
                                    }
                                }
                            }
                        }
                        if let Some(status) = config_status.read().as_ref() {
                            div { class: "tool-status", "{status}" }
                        }
                        div { class: "transport",
                            div { class: "eyebrow", "Meshtastic" }
                            h3 { if cfg!(target_os = "android") { "Bluetooth-Verbindung" } else { "USB-Verbindung" } }
                            p { class: "subtle", if cfg!(target_os = "android") { "Meshtastic-Funkgerät über Bluetooth Low Energy verbinden." } else { "Meshtastic-Funkgerät über USB-Serial (115200 Baud) verbinden." } }
                            div { class: "connection-line",
                                span { class: if meshtastic_status.read().connected { "connection-dot connected" } else { "connection-dot" } }
                                strong { if meshtastic_status.read().connected { "Verbunden" } else { "Nicht verbunden" } }
                            }
                            p { class: "transport-state", "{meshtastic_status.read().detail}" }
                            div { class: "field",
                                label { if cfg!(target_os = "android") { "Bluetooth-Adresse manuell" } else { "Seriellen Port manuell eingeben" } }
                                input {
                                    value: "{meshtastic_port}",
                                    placeholder: if cfg!(target_os = "android") { "Bluetooth-Adresse" } else { "/dev/ttyACM0 oder COM3" },
                                    oninput: move |event| meshtastic_port.set(event.value()),
                                }
                            }
                            if !meshtastic_ports.read().is_empty() {
                                div { class: "field",
                                    label { if cfg!(target_os = "android") { "Gefundenes Bluetooth-Gerät auswählen" } else { "Gefundenen seriellen Port auswählen" } }
                                    select {
                                        value: "{meshtastic_port}",
                                        onchange: move |event| meshtastic_port.set(event.value()),
                                        option { value: "", "Bitte auswählen …" }
                                        for port in meshtastic_ports.read().iter() {
                                            option { key: "{port}", value: "{port}", "{port}" }
                                        }
                                    }
                                }
                            }
                            if meshtastic_status.read().connected {
                                div { class: "identity-card",
                                    strong { "Meshtastic-Geräteinformationen" }
                                    p { class: "transport-state", "{meshtastic_status.read().detail}" }
                                    p { class: "transport-endpoint", if cfg!(target_os = "android") { "Transport: Bluetooth Low Energy · Meshtastic GATT" } else { "Transport: USB-Serial · 115200 Baud · Meshtastic Stream API" } }
                                }
                            }
                            div { class: "tool-actions",
                                button { onclick: move |_| refresh_meshtastic_ports(&mut meshtastic_ports, &mut meshtastic_port, meshtastic_status), "Geräte suchen" }
                                button {
                                    disabled: meshtastic_port.read().trim().is_empty() || meshtastic_status.read().connected,
                                    onclick: move |_| connect_meshtastic_usb(meshtastic_port.read().trim().to_owned(), meshtastic_status, meshtastic_session),
                                    "Verbinden"
                                }
                                button {
                                    disabled: !meshtastic_status.read().connected,
                                    onclick: move |_| disconnect_meshtastic_usb(meshtastic_status, meshtastic_session),
                                    "Trennen"
                                }
                            }
                        }
                        div { class: "config-actions",
                            button { class: "primary", onclick: move |_| save_configuration(&mut identity, autosave_password, &config_name, &config_onion, mailbox_onion, &mut config_status), "Save" }
                        }
                    }
                } else if *app_view.read() == AppView::ContactExport {
                    section { class: "config",
                        div { class: "eyebrow", "Kontakte" }
                        h2 { "Kontakt exportieren" }
                        p { class: "subtle", "Erzeuge eine signierte Einladung und teile sie über einen verifizierten externen Kanal." }
                        div { class: "field", label { "Signierte Einladung" } textarea { readonly: true, value: "{invitation_output}", placeholder: "Einladung erzeugen" } }
                        button { class: "primary", onclick: move |_| create_contact_invitation(&mut identity, autosave_password, &mut invitation_output, &mut contact_status, recipient_mailbox_token, local_mailbox_token), "Export erzeugen" }
                        if !invitation_output.read().is_empty() {
                            {
                                let svg = qr_svg(invitation_output.read().as_str())
                                    .unwrap_or_else(|error| format!("<p style='color:#900'>QR error: {error}</p>"));
                                rsx! {
                                    p { class: "subtle", "Diese signierte Kontakteinladung kann direkt von der anderen Nyx-App gescannt werden." }
                                    div { style: "background: white; padding: 12px; width: min(420px, 100%); border: 2px solid #8dd39e", dangerous_inner_html: svg }
                                }
                            }
                        }
                        if let Some(status) = contact_status.read().as_ref() { div { class: "tool-status", "{status}" } }
                    }
                } else if *app_view.read() == AppView::ContactImport {
                    section { class: "config",
                        div { class: "eyebrow", "Kontakte" }
                        h2 { "Kontakt importieren" }
                        p { class: "subtle", "Füge hier eine signierte Nyx-Einladung ein." }
                        div { class: "field", label { "Signierte Einladung" } textarea { value: "{invitation_input}", placeholder: "Einladung einfügen", oninput: move |event| invitation_input.set(event.value()) } }
                        if cfg!(target_os = "android") {
                            video { id: "nyx-contact-qr-camera", autoplay: true, playsinline: true, style: "display:none; width:100%; margin-top:12px; border-radius:10px" }
                            button { class: "primary", onclick: move |_| { spawn(scan_contact_qr(invitation_input, contact_status)); }, "QR-Code mit Kamera scannen" }
                        }
                        button {
                            class: "primary",
                            disabled: invitation_input.read().trim().is_empty(),
                            onclick: move |_| {
                                if import_contact_invitation(&mut identity, autosave_password, &mut invitation_input, &mut contact_status, recipient_mailbox_token, local_mailbox_token, &mut selected_contact) {
                                    navigate_to(&mut app_view, AppView::Chat, &mut back_history, &mut forward_history);
                                }
                            },
                            "Prüfen und importieren"
                        }
                        if let Some(status) = contact_status.read().as_ref() { div { class: "tool-status", "{status}" } }
                    }
                } else {
                section { class: "panel",
                    header { class: "header",
                        div {
                            h2 { if let Some(contact) = active_contact.as_ref() { "{contact.display_name}" } else { "Contact setup" } }
                            div { class: "subtle", "Persistent Ed25519 identity · OpenMLS KeyPackage" }
                        }
                        span { class: "badge", if remote_session_ready { "MLS session active" } else if mls_ready { "Device ready" } else { "Locked" } }
                    }
                    div { class: "messages",
                        if let Some(contact) = active_contact.as_ref() {
                            div { class: "empty",
                                h3 { "{contact.display_name}" }
                                p { "Kontakt importiert. Vergleiche diesen Fingerprint über einen zweiten, vertrauenswürdigen Kanal mit deinem Kontakt:" }
                                div { class: "fingerprint", "{contact.identity_fingerprint}" }
                                p { if remote_session_ready { "Die verschlüsselte MLS-Verbindung ist bereit." } else if contact.verified { "Fingerprint bestätigt. Nimm jetzt die Einladung an, um die verschlüsselte Verbindung aufzubauen." } else { "Wenn beide Fingerprints übereinstimmen, bestätige den Vergleich mit dem Button." } }
                                if !contact.verified {
                                    button {
                                        class: "mini-button",
                                        onclick: {
                                            let device_id = contact.device_id;
                                            move |_| verify_contact_fingerprint(&mut identity, device_id, autosave_password, &mut contact_status)
                                        },
                                        "Fingerprint stimmt überein"
                                    }
                                }
                                if contact.verified && !remote_session_ready {
                                    button {
                                        class: "mini-button",
                                        onclick: {
                                            let device_id = contact.device_id;
                                            move |_| accept_contact_invitation(&mut identity, device_id, autosave_password, &delivery_queue, &mut contact_status)
                                        },
                                        "Einladung annehmen und Verbindung aufbauen"
                                    }
                                }
                                if *reconnect_confirm.read() == Some(contact.device_id) {
                                    p { class: "warning", "Der bisherige Kontakt und seine lokale MLS-Sitzung werden entfernt. Danach muss ein neuer QR-Code importiert werden." }
                                    button {
                                        class: "mini-button",
                                        onclick: {
                                            let device_id = contact.device_id;
                                            move |_| {
                                                if remove_contact_for_reconnect(&mut identity, device_id, autosave_password, recipient_mailbox_token, local_mailbox_token, &mut selected_contact, &mut contact_status) {
                                                    reconnect_confirm.set(None);
                                                    navigate_to(&mut app_view, AppView::ContactImport, &mut back_history, &mut forward_history);
                                                }
                                            }
                                        },
                                        "Entfernen und neu verbinden"
                                    }
                                    button { class: "mini-button", onclick: move |_| reconnect_confirm.set(None), "Abbrechen" }
                                } else {
                                    button {
                                        class: "mini-button",
                                        onclick: {
                                            let device_id = contact.device_id;
                                            move |_| reconnect_confirm.set(Some(device_id))
                                        },
                                        "Kontakt neu verbinden"
                                    }
                                }
                            }
                        } else if messages.read().is_empty() {
                            div { class: "empty",
                                h3 { "Create or import a contact invitation" }
                                p { "Invitations are Ed25519-signed, carry a validated RFC 9420 KeyPackage and use separate mailbox capabilities for each direction." }
                            }
                        }
                        for (index, message) in visible_messages.iter().enumerate() {
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
                            placeholder: if remote_session_ready { "Write an end-to-end encrypted message" } else if active_contact.is_some() { "Verify contact and establish MLS session" } else { "Select a contact" },
                            disabled: !remote_session_ready || !active_contact.as_ref().is_some_and(|contact| contact.verified),
                            oninput: move |event| {
                                draft.set(event.value());
                                touch_vault(&mut vault_last_activity, &autosave_password);
                            },
                            onkeydown: move |event| {
                                if event.key() == Key::Enter {
                                    touch_vault(&mut vault_last_activity, &autosave_password);
                                    if let Some(contact) = keydown_contact.as_ref() {
                                        send_remote_message(&mut identity, contact, &delivery_queue, &mut draft, &mut messages, &mut last_error, &autosave_password);
                                    }
                                }
                            }
                        }
                        button {
                            disabled: !remote_session_ready || !active_contact.as_ref().is_some_and(|contact| contact.verified),
                            onclick: move |_| {
                                touch_vault(&mut vault_last_activity, &autosave_password);
                                if let Some(contact) = click_contact.as_ref() {
                                    send_remote_message(&mut identity, contact, &delivery_queue, &mut draft, &mut messages, &mut last_error, &autosave_password);
                                }
                            },
                            "Encrypt & send"
                        }
                    }
                }
                }
            }
        }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn refresh_meshtastic_ports(
    ports: &mut Signal<Vec<String>>,
    selected: &mut Signal<String>,
    mut status: Signal<MeshtasticStatus>,
) {
    match meshtastic_usb::available_ports() {
        Ok(found) => {
            if selected.read().trim().is_empty() && found.len() == 1 {
                selected.set(found[0].clone());
            }
            status.set(MeshtasticStatus {
                connected: false,
                detail: format!("{} serieller Port(s) gefunden", found.len()),
            });
            ports.set(found);
        }
        Err(error) => status.set(MeshtasticStatus {
            connected: false,
            detail: error,
        }),
    }
}

#[cfg(target_os = "android")]
fn refresh_meshtastic_ports(
    ports: &mut Signal<Vec<String>>,
    selected: &mut Signal<String>,
    mut status: Signal<MeshtasticStatus>,
) {
    match meshtastic_ble::scan_devices() {
        Ok(detail) => {
            status.set(MeshtasticStatus {
                connected: false,
                detail,
            });
            let mut ports = *ports;
            let mut selected = *selected;
            spawn(async move {
                tokio::time::sleep(Duration::from_secs(11)).await;
                match meshtastic_ble::list_devices() {
                    Ok(found) => {
                        let scan_state = meshtastic_ble::scan_status()
                            .unwrap_or_else(|error| format!("ERROR: {error}"));
                        if selected.read().trim().is_empty() && found.len() == 1 {
                            selected.set(found[0].clone());
                        }
                        let detail = if scan_state.starts_with("ERROR:") {
                            scan_state
                        } else if found.is_empty() {
                            "Suche beendet: kein Bluetooth-LE-Gerät empfangen".to_owned()
                        } else {
                            format!(
                                "Suche beendet: {} Bluetooth-LE-Gerät(e) gefunden; Meshtastic wird beim Verbinden geprüft",
                                found.len()
                            )
                        };
                        ports.set(found);
                        status.set(MeshtasticStatus {
                            connected: false,
                            detail,
                        });
                    }
                    Err(error) => status.set(MeshtasticStatus {
                        connected: false,
                        detail: error,
                    }),
                }
            });
        }
        Err(error) => status.set(MeshtasticStatus {
            connected: false,
            detail: error,
        }),
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn connect_meshtastic_usb(
    port: String,
    mut status: Signal<MeshtasticStatus>,
    mut session: Signal<u64>,
) {
    let id = session().wrapping_add(1);
    session.set(id);
    status.set(MeshtasticStatus {
        connected: false,
        detail: format!("Verbinde mit {port} …"),
    });
    spawn(async move { meshtastic_usb::run_session(port, id, status, session).await });
}

#[cfg(target_os = "android")]
fn connect_meshtastic_usb(
    port: String,
    mut status: Signal<MeshtasticStatus>,
    mut session: Signal<u64>,
) {
    let id = session().wrapping_add(1);
    session.set(id);
    match meshtastic_ble::connect_device(&port) {
        Ok(detail) => {
            status.set(MeshtasticStatus {
                connected: false,
                detail,
            });
            spawn(async move { meshtastic_ble::monitor(id, status, session).await });
        }
        Err(error) => status.set(MeshtasticStatus {
            connected: false,
            detail: error,
        }),
    }
}

fn disconnect_meshtastic_usb(mut status: Signal<MeshtasticStatus>, mut session: Signal<u64>) {
    session.set(session().wrapping_add(1));
    #[cfg(target_os = "android")]
    if let Err(error) = meshtastic_ble::disconnect_device() {
        status.set(MeshtasticStatus {
            connected: false,
            detail: error,
        });
        return;
    }
    status.set(MeshtasticStatus {
        connected: false,
        detail: "Meshtastic-Verbindung wird getrennt …".into(),
    });
}

fn state_path() -> PathBuf {
    std::env::var_os("NYX_DESKTOP_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_path("nyx-desktop-state.nyx"))
}

fn identity_path() -> PathBuf {
    std::env::var_os("NYX_DEVICE_IDENTITY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_path("nyx-device-identity.nyx"))
}

fn delivery_queue_path() -> PathBuf {
    std::env::var_os("NYX_DELIVERY_QUEUE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_path("nyx-delivery.sqlite3"))
}

fn initialize_local_storage() -> Result<DeliveryQueue, String> {
    let identity = identity_path();
    let parent = identity
        .parent()
        .ok_or_else(|| "App-Datenverzeichnis ist nicht verfügbar".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("App-Datenverzeichnis kann nicht erstellt werden: {error}"))?;
    DeliveryQueue::open(delivery_queue_path())
        .map_err(|error| format!("Nachrichtenwarteschlange kann nicht geöffnet werden: {error}"))
}

#[cfg(not(target_os = "android"))]
fn app_data_path(filename: &str) -> PathBuf {
    PathBuf::from(filename)
}

#[cfg(target_os = "android")]
fn app_data_path(filename: &str) -> PathBuf {
    android_files_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(filename)
}

#[cfg(target_os = "android")]
fn android_files_dir() -> Option<PathBuf> {
    use jni::{JavaVM, objects::JObject};
    use std::mem::ManuallyDrop;

    let context = ndk_context::android_context();
    if context.vm().is_null() || context.context().is_null() {
        return None;
    }
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }.ok()?;
    let mut env = vm.attach_current_thread().ok()?;
    let context = ManuallyDrop::new(unsafe { JObject::from_raw(context.context().cast()) });
    let directory = env
        .call_method(&*context, "getFilesDir", "()Ljava/io/File;", &[])
        .ok()?
        .l()
        .ok()?;
    let absolute_path = env
        .call_method(directory, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .ok()?
        .l()
        .ok()?;
    let absolute_path = jni::objects::JString::from(absolute_path);
    let path: String = env.get_string(&absolute_path).ok()?.into();
    Some(PathBuf::from(path))
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

fn default_mailbox_onion() -> String {
    std::env::var("NYX_MAILBOX_ONION").unwrap_or_else(|_| DEFAULT_MAILBOX_ONION.to_owned())
}

#[allow(clippy::too_many_arguments)]
async fn run_delivery_worker(
    startup_ready: Signal<bool>,
    mut status: Signal<MailboxConnectionStatus>,
    mailbox_onion: Signal<String>,
    local_mailbox_token: Signal<Vec<[u8; 32]>>,
    mut conversation: Signal<Result<MlsConversation, String>>,
    mut identity: Signal<Result<Option<DeviceIdentity>, String>>,
    mut messages: Signal<Vec<DisplayMessage>>,
    mut last_error: Signal<Option<String>>,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    mut selected_contact: Signal<Option<uuid::Uuid>>,
    mut app_view: Signal<AppView>,
) {
    while !*startup_ready.read() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let host = mailbox_onion.read().trim().to_owned();
    if host.is_empty() {
        return;
    }
    let port = match std::env::var("NYX_MAILBOX_PORT") {
        Ok(value) => match value.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                update_connection_status(
                    &mut status,
                    ConnectionPhase::Disabled,
                    "NYX_MAILBOX_PORT is invalid".into(),
                    Some(host),
                    false,
                );
                return;
            }
        },
        Err(_) => 443,
    };
    let mut endpoint = match OnionEndpoint::new(host, port) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            update_connection_status(
                &mut status,
                ConnectionPhase::Disabled,
                format!("Invalid Onion endpoint: {error}"),
                None,
                false,
            );
            return;
        }
    };
    let queue = match DeliveryQueue::open(delivery_queue_path()) {
        Ok(queue) => queue,
        Err(error) => {
            update_connection_status(
                &mut status,
                ConnectionPhase::Degraded,
                format!("Delivery queue unavailable: {error}"),
                Some(endpoint.host.clone()),
                false,
            );
            return;
        }
    };

    loop {
        update_connection_status(
            &mut status,
            ConnectionPhase::Bootstrapping,
            "Building a Tor circuit".into(),
            Some(endpoint.host.clone()),
            false,
        );
        let transport = match TorTransport::bootstrap_in(app_data_path("arti-client")).await {
            Ok(transport) => transport,
            Err(error) => {
                let fallback = attempt_meshtastic_fallback(&queue).await;
                update_connection_status(
                    &mut status,
                    ConnectionPhase::Degraded,
                    match fallback {
                        Ok(count) if count > 0 => format!(
                            "Tor bootstrap failed ({error:#}); dispatched {count} queued message(s) to Meshtastic fallback"
                        ),
                        Ok(_) => format!("Tor bootstrap failed; retrying: {error:#}"),
                        Err(mesh_error) => format!(
                            "Tor bootstrap failed ({error:#}); Meshtastic fallback unavailable: {mesh_error}"
                        ),
                    },
                    Some(endpoint.host.clone()),
                    false,
                );
                tokio::time::sleep(Duration::from_secs(15)).await;
                continue;
            }
        };
        update_connection_status(
            &mut status,
            ConnectionPhase::Connecting,
            "Tor ready; checking Onion mailbox".into(),
            Some(endpoint.host.clone()),
            false,
        );

        loop {
            let configured_host = mailbox_onion.read().trim().to_owned();
            if !configured_host.is_empty() && configured_host != endpoint.host {
                match OnionEndpoint::new(configured_host, port) {
                    Ok(updated) => endpoint = updated,
                    Err(error) => {
                        update_connection_status(
                            &mut status,
                            ConnectionPhase::Disabled,
                            format!("Invalid Onion endpoint: {error}"),
                            None,
                            false,
                        );
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                }
            }
            let health_started = Instant::now();
            match transport.health(&endpoint).await {
                Ok(()) => update_connection_status(
                    &mut status,
                    ConnectionPhase::Connected,
                    format!(
                        "Protocol v{} ready · {} ms",
                        nyx_protocol::PROTOCOL_VERSION,
                        health_started.elapsed().as_millis()
                    ),
                    Some(endpoint.host.clone()),
                    true,
                ),
                Err(error) => {
                    let fallback = attempt_meshtastic_fallback(&queue).await;
                    update_connection_status(
                        &mut status,
                        ConnectionPhase::Degraded,
                        match fallback {
                            Ok(count) if count > 0 => format!(
                                "Mailbox health check failed ({error}); dispatched {count} queued message(s) to Meshtastic fallback"
                            ),
                            Ok(_) => format!("Mailbox health check failed: {error}"),
                            Err(mesh_error) => format!(
                                "Mailbox health check failed ({error}); Meshtastic fallback unavailable: {mesh_error}"
                            ),
                        },
                        Some(endpoint.host.clone()),
                        false,
                    );
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }
            if !autosave_password.read().is_empty() {
                if let Err(error) = sync_remote_outbound_journal(
                    &mut identity,
                    &queue,
                    autosave_password.read().as_slice(),
                ) {
                    update_connection_detail(
                        &mut status,
                        format!("Remote queue recovery failed; will retry: {error}"),
                    );
                }
                match sync_outbound_journal(
                    &mut conversation,
                    &queue,
                    autosave_password.read().as_slice(),
                ) {
                    Ok(recovered) if recovered > 0 => update_connection_detail(
                        &mut status,
                        format!("Recovered {recovered} outbound message(s) into delivery queue"),
                    ),
                    Ok(_) => {}
                    Err(error) => update_connection_detail(
                        &mut status,
                        format!("Outbound journal recovery failed; will retry: {error}"),
                    ),
                }
            }
            let fallback_tokens = local_mailbox_token.read().clone();
            let mut receive_tokens = Vec::new();
            if let Some(device) = identity.read().as_ref().ok().and_then(Option::as_ref) {
                for invitation in device.issued_invitations().iter().rev() {
                    add_receive_token(&mut receive_tokens, invitation.inviter_receive_token);
                }
                for contact in device.contacts().iter().rev() {
                    add_receive_token(&mut receive_tokens, contact.receive_mailbox_token);
                }
            }
            for token in fallback_tokens {
                add_receive_token(&mut receive_tokens, token);
            }
            match transport.flush_delivery_queue(&endpoint, &queue, 32).await {
                Ok(report) if report.delivered > 0 => update_connection_detail(
                    &mut status,
                    format!("Delivered {} queued message(s)", report.delivered),
                ),
                Ok(_) => update_connection_detail(
                    &mut status,
                    format!(
                        "Delivery queue is empty · checking {} inbox(es)",
                        receive_tokens.len()
                    ),
                ),
                Err(error) => {
                    let fallback = attempt_meshtastic_fallback(&queue).await;
                    update_connection_detail(
                        &mut status,
                        match fallback {
                            Ok(count) if count > 0 => format!(
                                "Tor delivery failed ({error}); dispatched {count} queued message(s) to Meshtastic fallback"
                            ),
                            Ok(_) => format!("Delivery failed; queued for retry: {error}"),
                            Err(mesh_error) => format!(
                                "Tor delivery failed ({error}); Meshtastic fallback unavailable: {mesh_error}"
                            ),
                        },
                    );
                }
            }

            for (inbox_index, token) in receive_tokens.into_iter().enumerate() {
                match transport.fetch(&endpoint, token, 32).await {
                    Ok(envelopes) => {
                        tracing::debug!(
                            inbox_index,
                            message_count = envelopes.len(),
                            "checking contact inbox"
                        );
                        let mut receipts = Vec::new();
                        for stored in envelopes {
                            let already_processed =
                                conversation.read().as_ref().is_ok_and(|conversation| {
                                    conversation.has_inbound_receipt(&stored.receipt)
                                }) || identity
                                    .read()
                                    .as_ref()
                                    .ok()
                                    .and_then(Option::as_ref)
                                    .is_some_and(|device| {
                                        device.has_remote_inbound_receipt(&stored.receipt)
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
                            let payload = decode_client_payload(&stored.envelope.ciphertext);
                            tracing::debug!(
                                inbox_index,
                                payload_kind = match &payload {
                                    Ok(ClientPayload::InvitationAcceptance(_)) => {
                                        "invitation-acceptance"
                                    }
                                    Ok(ClientPayload::MlsApplication { .. }) => "mls-application",
                                    Err(_) => "legacy-or-invalid",
                                },
                                "processing inbox payload"
                            );
                            let decrypted = match payload {
                                Ok(ClientPayload::InvitationAcceptance(acceptance)) => {
                                    let mut state = identity.write();
                                    let device = state
                                        .as_mut()
                                        .map_err(|error| error.clone())
                                        .and_then(|device| {
                                            device
                                                .as_mut()
                                                .ok_or_else(|| "Device is locked".to_owned())
                                        });
                                    match device {
                                        Ok(device) => device
                                            .process_invitation_acceptance(&acceptance)
                                            .and_then(|contact| {
                                                device.save_encrypted(
                                                    identity_path(),
                                                    autosave_password.read().as_slice(),
                                                )?;
                                                selected_contact.set(Some(contact.device_id));
                                                app_view.set(AppView::Chat);
                                                Ok((
                                                    format!(
                                                        "Neue Kontaktanfrage von {} angenommen",
                                                        contact.display_name
                                                    )
                                                    .into_bytes(),
                                                    Some(contact.device_id),
                                                ))
                                            })
                                            .map_err(|error| error.to_string()),
                                        Err(error) => Err(error),
                                    }
                                }
                                Ok(ClientPayload::MlsApplication {
                                    sender_device,
                                    ciphertext,
                                }) => {
                                    let mut state = identity.write();
                                    match state.as_mut().map_err(|error| error.clone()).and_then(
                                        |device| {
                                            device
                                                .as_mut()
                                                .ok_or_else(|| "Device is locked".to_owned())
                                        },
                                    ) {
                                        Ok(device) => {
                                            if !device.has_session(sender_device) {
                                                // A contact acceptance may be waiting in another
                                                // inbox. Leave this message untouched and keep
                                                // searching for the handshake first.
                                                continue;
                                            }
                                            device
                                                .process_remote_inbound_and_save(
                                                    sender_device,
                                                    &ciphertext,
                                                    stored.receipt,
                                                    stored.expires_unix_ms,
                                                    identity_path(),
                                                    autosave_password.read().as_slice(),
                                                )
                                                .map(|plaintext| (plaintext, Some(sender_device)))
                                                .map_err(|error| error.to_string())
                                        }
                                        Err(error) => Err(error),
                                    }
                                }
                                Err(_) => match conversation.write().as_mut() {
                                    Ok(conversation) => conversation
                                        .process_inbound_and_save(
                                            &stored.envelope.ciphertext,
                                            stored.receipt,
                                            stored.expires_unix_ms,
                                            state_path(),
                                            autosave_password.read().as_slice(),
                                        )
                                        .map(|plaintext| (plaintext, None))
                                        .map_err(|error| error.to_string()),
                                    Err(error) => Err(error.clone()),
                                },
                            };
                            match decrypted {
                                Ok((plaintext, contact_device_id)) => {
                                    receipts.push(stored.receipt);
                                    match String::from_utf8(plaintext) {
                                        Ok(plaintext) => messages.write().push(DisplayMessage {
                                            contact_device_id,
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
                                Err(error) => {
                                    last_error.set(Some(format!(
                                        "Inbound MLS message rejected: {error}"
                                    )));
                                    // Preserve the first causal failure. Later
                                    // application messages depend on a preceding
                                    // successful invitation acceptance and would
                                    // otherwise overwrite the useful error.
                                    // A stale or malformed item in one capability must not
                                    // prevent a valid contact acceptance waiting in another
                                    // inbox from establishing its MLS session.
                                    break;
                                }
                            }
                        }
                        if !receipts.is_empty() {
                            match transport.acknowledge(&endpoint, token, receipts).await {
                                Ok(deleted) => update_connection_detail(
                                    &mut status,
                                    format!("Received and acknowledged {deleted} message(s)"),
                                ),
                                Err(error) => update_connection_detail(
                                    &mut status,
                                    format!("Mailbox acknowledgement failed: {error}"),
                                ),
                            }
                        }
                    }
                    Err(error) => update_connection_status(
                        &mut status,
                        ConnectionPhase::Degraded,
                        format!("Mailbox fetch failed; retrying: {error}"),
                        Some(endpoint.host.clone()),
                        false,
                    ),
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
async fn attempt_meshtastic_fallback(queue: &DeliveryQueue) -> Result<usize, String> {
    let mut dispatched = 0;
    for item in queue.pending(8).map_err(|error| error.to_string())? {
        if meshtastic_usb::dispatch_fallback(item.id, item.envelope.ciphertext).await? {
            dispatched += 1;
        }
    }
    Ok(dispatched)
}

#[cfg(target_os = "android")]
async fn attempt_meshtastic_fallback(_queue: &DeliveryQueue) -> Result<usize, String> {
    Err("Android BLE fallback data transport is not available yet".into())
}

fn update_connection_status(
    status: &mut Signal<MailboxConnectionStatus>,
    phase: ConnectionPhase,
    detail: String,
    endpoint: Option<String>,
    successful: bool,
) {
    let last_success = if successful {
        Some(Instant::now())
    } else {
        status.read().last_success
    };
    status.set(MailboxConnectionStatus {
        phase,
        detail,
        endpoint,
        last_success,
    });
}

fn update_connection_detail(status: &mut Signal<MailboxConnectionStatus>, detail: String) {
    status.write().detail = detail;
}

#[allow(clippy::too_many_arguments)]
fn authenticate_account(
    account_exists: bool,
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    conversation: &mut Signal<Result<MlsConversation, String>>,
    display_name: &mut Signal<String>,
    password: &mut Signal<String>,
    mut autosave_password: Signal<Zeroizing<Vec<u8>>>,
    last_activity: &mut Signal<Option<Instant>>,
    mut recipient_token: Signal<Option<[u8; 32]>>,
    mut local_token: Signal<Vec<[u8; 32]>>,
    mut mailbox_onion: Signal<String>,
    selected_contact: &mut Signal<Option<uuid::Uuid>>,
    status: &mut Signal<Option<String>>,
) {
    let password_bytes = Zeroizing::new(password.read().as_bytes().to_vec());
    let result = (|| -> Result<(DeviceIdentity, MlsConversation), String> {
        if password_bytes.len() < 12 {
            return Err("Vault password must contain at least 12 characters".into());
        }
        let mut device = if account_exists {
            DeviceIdentity::load_encrypted(identity_path(), &password_bytes)
                .map_err(|error| error.to_string())?
        } else {
            let device = DeviceIdentity::generate(display_name.read().as_str())
                .map_err(|error| error.to_string())?;
            device
                .save_encrypted(identity_path(), &password_bytes)
                .map_err(|error| error.to_string())?;
            device
        };
        if let Some(index) = device
            .mailboxes()
            .iter()
            .position(|address| address == RETIRED_MAILBOX_ONION)
        {
            device
                .update_mailbox(index, DEFAULT_MAILBOX_ONION)
                .map_err(|error| error.to_string())?;
            device
                .save_encrypted(identity_path(), &password_bytes)
                .map_err(|error| error.to_string())?;
        }
        if device.mailbox_onion().is_none() && !mailbox_onion.read().trim().is_empty() {
            let current_name = device.display_name().to_owned();
            device
                .update_profile(current_name, mailbox_onion.read().as_str())
                .map_err(|error| error.to_string())?;
            device
                .save_encrypted(identity_path(), &password_bytes)
                .map_err(|error| error.to_string())?;
        }
        let conversation = if account_exists && state_path().exists() {
            MlsConversation::load_encrypted(state_path(), &password_bytes)
                .map_err(|error| error.to_string())?
        } else {
            let conversation = MlsConversation::new_1to1(
                device.device_id().as_bytes().to_vec(),
                b"pending-contact-session".to_vec(),
            )
            .map_err(|error| error.to_string())?;
            conversation
                .save_encrypted(state_path(), &password_bytes)
                .map_err(|error| error.to_string())?;
            conversation
        };
        Ok((device, conversation))
    })();
    match result {
        Ok((device, restored_conversation)) => {
            if let Some(onion) = device.mailbox_onion() {
                mailbox_onion.set(onion.to_owned());
            }
            let mut receive_tokens = local_token.read().clone();
            for contact in device.contacts() {
                add_receive_token(&mut receive_tokens, contact.receive_mailbox_token);
            }
            for invitation in device.issued_invitations() {
                add_receive_token(&mut receive_tokens, invitation.inviter_receive_token);
            }
            local_token.set(receive_tokens);
            if let Some(contact) = device.contacts().first() {
                recipient_token.set(Some(contact.send_mailbox_token));
                selected_contact.set(Some(contact.device_id));
            }
            identity.set(Ok(Some(device)));
            conversation.set(Ok(restored_conversation));
            autosave_password.set(Zeroizing::new(password_bytes.to_vec()));
            last_activity.set(Some(Instant::now()));
            status.set(None);
        }
        Err(error) => status.set(Some(error)),
    }
    password.write().zeroize();
}

fn open_configuration(
    identity: &Signal<Result<Option<DeviceIdentity>, String>>,
    name: &mut Signal<String>,
    onion: &mut Signal<String>,
    status: &mut Signal<Option<String>>,
) {
    if let Some(device) = identity.read().as_ref().ok().and_then(Option::as_ref) {
        name.set(device.display_name().to_owned());
        if let Some(address) = device.mailbox_onion() {
            onion.set(address.to_owned());
        }
    }
    status.set(None);
}

fn navigate_to(
    current: &mut Signal<AppView>,
    destination: AppView,
    back: &mut Signal<Vec<AppView>>,
    forward: &mut Signal<Vec<AppView>>,
) {
    let previous = *current.read();
    if previous != destination {
        back.write().push(previous);
        forward.write().clear();
        current.set(destination);
    }
}

fn navigate_back(
    current: &mut Signal<AppView>,
    back: &mut Signal<Vec<AppView>>,
    forward: &mut Signal<Vec<AppView>>,
) {
    if let Some(destination) = back.write().pop() {
        forward.write().push(*current.read());
        current.set(destination);
    }
}

fn navigate_forward(
    current: &mut Signal<AppView>,
    back: &mut Signal<Vec<AppView>>,
    forward: &mut Signal<Vec<AppView>>,
) {
    if let Some(destination) = forward.write().pop() {
        back.write().push(*current.read());
        current.set(destination);
    }
}

fn save_configuration(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    name: &Signal<String>,
    onion: &Signal<String>,
    mut mailbox_onion: Signal<String>,
    status: &mut Signal<Option<String>>,
) {
    let result = (|| -> Result<String, String> {
        let mut state = identity.write();
        let device = state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        device
            .update_profile(name.read().as_str(), onion.read().as_str())
            .map_err(|error| error.to_string())?;
        device
            .save_encrypted(identity_path(), autosave_password.read().as_slice())
            .map_err(|error| error.to_string())?;
        Ok(device.mailbox_onion().unwrap_or_default().to_owned())
    })();
    match result {
        Ok(address) => {
            mailbox_onion.set(address);
            status.set(Some(
                "Configuration saved in the encrypted device identity".into(),
            ));
        }
        Err(error) => status.set(Some(format!("Configuration rejected: {error}"))),
    }
}

fn change_mailbox(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    onion: &Signal<String>,
    action: MailboxAction,
    mut mailbox_onion: Signal<String>,
    status: &mut Signal<Option<String>>,
) {
    let result = (|| -> Result<String, String> {
        let mut state = identity.write();
        let device = state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        match action {
            MailboxAction::Add => device.add_mailbox(onion.read().as_str()),
            MailboxAction::Update(index) => device.update_mailbox(index, onion.read().as_str()),
            MailboxAction::Select(index) => device.select_mailbox(index),
            MailboxAction::Remove(index) => device.remove_mailbox(index),
        }
        .map_err(|error| error.to_string())?;
        device
            .save_encrypted(identity_path(), autosave_password.read().as_slice())
            .map_err(|error| error.to_string())?;
        Ok(device.mailbox_onion().unwrap_or_default().to_owned())
    })();
    match result {
        Ok(address) => {
            mailbox_onion.set(address);
            status.set(Some("Mailbox configuration saved".into()));
        }
        Err(error) => status.set(Some(format!("Mailbox change rejected: {error}"))),
    }
}

fn qr_svg(payload: &str) -> Result<String, String> {
    let code = qrcode::QrCode::with_error_correction_level(payload.as_bytes(), qrcode::EcLevel::L)
        .map_err(|error| error.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(360, 360)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

fn create_contact_invitation(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    output: &mut Signal<String>,
    status: &mut Signal<Option<String>>,
    mut recipient_token: Signal<Option<[u8; 32]>>,
    mut local_token: Signal<Vec<[u8; 32]>>,
) {
    let result = (|| -> Result<String, String> {
        let mut identity_state = identity.write();
        let device = identity_state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        let onion = device
            .mailbox_onion()
            .ok_or_else(|| "Configure the Onion mailbox address first".to_owned())?
            .to_owned();
        let invitation = device
            .create_invitation(onion)
            .map_err(|error| error.to_string())?;
        let directions =
            DeviceIdentity::verify_invitation(&invitation).map_err(|error| error.to_string())?;
        device
            .save_encrypted(identity_path(), autosave_password.read().as_slice())
            .map_err(|error| error.to_string())?;
        recipient_token.set(Some(directions.receive_mailbox_token));
        let mut receive_tokens = local_token.read().clone();
        add_receive_token(&mut receive_tokens, directions.send_mailbox_token);
        local_token.set(receive_tokens);
        Ok(invitation)
    })();
    match result {
        Ok(invitation) => {
            output.set(invitation);
            status.set(Some(
                "Signed invitation created; share it over a verified out-of-band channel".into(),
            ));
        }
        Err(error) => status.set(Some(format!("Invitation failed: {error}"))),
    }
}

async fn scan_contact_qr(mut invitation_input: Signal<String>, mut status: Signal<Option<String>>) {
    status.set(Some("Kamera wird geöffnet …".into()));
    let result = dioxus::document::eval(
        r#"
        return await (async () => {
            const video = document.getElementById('nyx-contact-qr-camera');
            if (!video) throw new Error('camera preview is unavailable');
            if (!navigator.mediaDevices?.getUserMedia) {
                throw new Error('camera access is not supported by this Android WebView');
            }
            if (!('BarcodeDetector' in window)) {
                throw new Error('QR recognition is not supported by this Android WebView');
            }
            const formats = await BarcodeDetector.getSupportedFormats();
            if (!formats.includes('qr_code')) throw new Error('QR recognition is unavailable');
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: { ideal: 'environment' } },
                audio: false
            });
            video.srcObject = stream;
            video.style.display = 'block';
            await video.play();
            const detector = new BarcodeDetector({ formats: ['qr_code'] });
            try {
                const deadline = Date.now() + 45000;
                while (Date.now() < deadline) {
                    const codes = await detector.detect(video);
                    const invitation = codes.find(code => code.rawValue)?.rawValue;
                    if (invitation) return invitation;
                    await new Promise(resolve => setTimeout(resolve, 180));
                }
                throw new Error('no QR code recognized within 45 seconds');
            } finally {
                stream.getTracks().forEach(track => track.stop());
                video.srcObject = null;
                video.style.display = 'none';
            }
        })();
        "#,
    )
    .join::<String>()
    .await;
    match result {
        Ok(invitation) => {
            invitation_input.set(invitation);
            status.set(Some(
                "QR-Code erkannt; Einladung kann jetzt geprüft und importiert werden".into(),
            ));
        }
        Err(error) => status.set(Some(format!("QR-Scan fehlgeschlagen: {error}"))),
    }
}

#[allow(clippy::too_many_arguments)]
fn import_contact_invitation(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    input: &mut Signal<String>,
    status: &mut Signal<Option<String>>,
    mut recipient_token: Signal<Option<[u8; 32]>>,
    mut local_token: Signal<Vec<[u8; 32]>>,
    selected_contact: &mut Signal<Option<uuid::Uuid>>,
) -> bool {
    let result = (|| -> Result<ContactRecord, String> {
        let mut identity_state = identity.write();
        let device = identity_state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        let contact = device
            .import_invitation(input.read().trim())
            .map_err(|error| error.to_string())?;
        device
            .save_encrypted(identity_path(), autosave_password.read().as_slice())
            .map_err(|error| error.to_string())?;
        Ok(contact)
    })();
    match result {
        Ok(contact) => {
            recipient_token.set(Some(contact.send_mailbox_token));
            let mut receive_tokens = local_token.read().clone();
            add_receive_token(&mut receive_tokens, contact.receive_mailbox_token);
            local_token.set(receive_tokens);
            selected_contact.set(Some(contact.device_id));
            input.set(String::new());
            status.set(Some(format!(
                "Kontakt {} wurde geprüft und importiert",
                contact.display_name
            )));
            true
        }
        Err(error) => {
            status.set(Some(format!("Import abgelehnt: {error}")));
            false
        }
    }
}

fn select_contact(
    contact: &ContactRecord,
    selected_contact: &mut Signal<Option<uuid::Uuid>>,
    mut recipient_token: Signal<Option<[u8; 32]>>,
    mut local_token: Signal<Vec<[u8; 32]>>,
) {
    selected_contact.set(Some(contact.device_id));
    recipient_token.set(Some(contact.send_mailbox_token));
    let mut receive_tokens = local_token.read().clone();
    add_receive_token(&mut receive_tokens, contact.receive_mailbox_token);
    local_token.set(receive_tokens);
}

fn add_receive_token(tokens: &mut Vec<[u8; 32]>, token: [u8; 32]) {
    if !tokens.contains(&token) {
        tokens.push(token);
    }
}

#[allow(clippy::too_many_arguments)]
fn remove_contact_for_reconnect(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    device_id: uuid::Uuid,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    mut recipient_token: Signal<Option<[u8; 32]>>,
    mut local_tokens: Signal<Vec<[u8; 32]>>,
    selected_contact: &mut Signal<Option<uuid::Uuid>>,
    status: &mut Signal<Option<String>>,
) -> bool {
    let result = (|| -> Result<ContactRecord, String> {
        let mut state = identity.write();
        let device = state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        let removed = device
            .remove_contact(device_id)
            .map_err(|error| error.to_string())?;
        device
            .save_encrypted(identity_path(), autosave_password.read().as_slice())
            .map_err(|error| error.to_string())?;
        Ok(removed)
    })();
    match result {
        Ok(removed) => {
            local_tokens
                .write()
                .retain(|token| token != &removed.receive_mailbox_token);
            recipient_token.set(None);
            selected_contact.set(None);
            status.set(Some(
                "Alter Kontakt entfernt. Importiere jetzt den neuen QR-Code.".into(),
            ));
            true
        }
        Err(error) => {
            status.set(Some(format!(
                "Kontakt konnte nicht entfernt werden: {error}"
            )));
            false
        }
    }
}

fn verify_contact_fingerprint(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    device_id: uuid::Uuid,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    status: &mut Signal<Option<String>>,
) {
    let result = (|| -> Result<(), String> {
        let mut identity_state = identity.write();
        let device = identity_state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        device
            .mark_contact_verified(device_id)
            .map_err(|error| error.to_string())?;
        device
            .save_encrypted(identity_path(), autosave_password.read().as_slice())
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(()) => status.set(Some("Contact fingerprint marked as verified".into())),
        Err(error) => status.set(Some(format!("Verification update failed: {error}"))),
    }
}

fn accept_contact_invitation(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    device_id: uuid::Uuid,
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    delivery_queue: &Signal<Result<DeliveryQueue, String>>,
    status: &mut Signal<Option<String>>,
) {
    let result = (|| -> Result<(), String> {
        let mut state = identity.write();
        let device = state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        let contact = device
            .contacts()
            .iter()
            .find(|contact| contact.device_id == device_id)
            .cloned()
            .ok_or_else(|| "Contact does not exist".to_owned())?;
        if !contact.verified {
            return Err("Verify the contact fingerprint first".into());
        }
        let acceptance = device
            .accept_invitation(device_id)
            .map_err(|error| error.to_string())?;
        let payload = encode_client_payload(&ClientPayload::InvitationAcceptance(acceptance))
            .map_err(|error| error.to_string())?;
        let pending = device
            .journal_remote_payload_and_save(
                payload,
                contact.send_mailbox_token,
                identity_path(),
                autosave_password.read().as_slice(),
            )
            .map_err(|error| error.to_string())?;
        let queue_state = delivery_queue.read();
        let queue = queue_state.as_ref().map_err(|error| error.clone())?;
        queue
            .enqueue_idempotent(pending.id, pending.mailbox_token, &pending.ciphertext)
            .map_err(|error| error.to_string())?;
        device
            .mark_remote_outbound_queued_and_save(
                pending.id,
                identity_path(),
                autosave_password.read().as_slice(),
            )
            .map_err(|error| error.to_string())
    })();
    status.set(Some(match result {
        Ok(()) => "MLS session created; signed Welcome queued for Tor delivery".into(),
        Err(error) => format!("Could not accept invitation: {error}"),
    }));
}

fn send_remote_message(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    contact: &ContactRecord,
    delivery_queue: &Signal<Result<DeliveryQueue, String>>,
    draft: &mut Signal<String>,
    messages: &mut Signal<Vec<DisplayMessage>>,
    last_error: &mut Signal<Option<String>>,
    autosave_password: &Signal<Zeroizing<Vec<u8>>>,
) {
    let plaintext = draft.read().trim().to_owned();
    if plaintext.is_empty() {
        return;
    }
    let result = (|| -> Result<usize, String> {
        let mut state = identity.write();
        let device = state
            .as_mut()
            .map_err(|error| error.clone())?
            .as_mut()
            .ok_or_else(|| "Device is locked".to_owned())?;
        let pending = device
            .create_remote_outbound_and_save(
                contact.device_id,
                plaintext.as_bytes(),
                contact.send_mailbox_token,
                identity_path(),
                autosave_password.read().as_slice(),
            )
            .map_err(|error| error.to_string())?;
        let ciphertext_size = pending.ciphertext.len();
        delivery_queue
            .read()
            .as_ref()
            .map_err(|error| error.clone())?
            .enqueue_idempotent(pending.id, pending.mailbox_token, &pending.ciphertext)
            .map_err(|error| error.to_string())?;
        device
            .mark_remote_outbound_queued_and_save(
                pending.id,
                identity_path(),
                autosave_password.read().as_slice(),
            )
            .map_err(|error| error.to_string())?;
        Ok(ciphertext_size)
    })();
    match result {
        Ok(ciphertext_size) => {
            messages.write().push(DisplayMessage {
                contact_device_id: Some(contact.device_id),
                plaintext,
                ciphertext_size,
                queued: true,
                incoming: false,
            });
            draft.set(String::new());
            last_error.set(None);
        }
        Err(error) => last_error.set(Some(error)),
    }
}

fn sync_outbound_journal(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    queue: &DeliveryQueue,
    password: &[u8],
) -> Result<usize, String> {
    let mut conversation_state = conversation.write();
    let conversation = conversation_state.as_mut().map_err(|error| error.clone())?;
    let pending = conversation.pending_outbound();
    let mut recovered = 0;
    for item in pending {
        queue
            .enqueue_idempotent(item.id, item.mailbox_token, &item.ciphertext)
            .map_err(|error| error.to_string())?;
        conversation
            .mark_outbound_queued_and_save(item.id, state_path(), password)
            .map_err(|error| error.to_string())?;
        recovered += 1;
    }
    Ok(recovered)
}

fn sync_remote_outbound_journal(
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
    queue: &DeliveryQueue,
    password: &[u8],
) -> Result<usize, String> {
    let mut state = identity.write();
    let device = state
        .as_mut()
        .map_err(|error| error.clone())?
        .as_mut()
        .ok_or_else(|| "Device is locked".to_owned())?;
    let pending = device.remote_pending_outbound();
    let mut recovered = 0;
    for item in pending {
        queue
            .enqueue_idempotent(item.id, item.mailbox_token, &item.ciphertext)
            .map_err(|error| error.to_string())?;
        device
            .mark_remote_outbound_queued_and_save(item.id, identity_path(), password)
            .map_err(|error| error.to_string())?;
        recovered += 1;
    }
    Ok(recovered)
}

fn touch_vault(
    last_activity: &mut Signal<Option<Instant>>,
    autosave_password: &Signal<Zeroizing<Vec<u8>>>,
) {
    if !autosave_password.read().is_empty() {
        last_activity.set(Some(Instant::now()));
    }
}

fn lock_account(
    conversation: &mut Signal<Result<MlsConversation, String>>,
    identity: &mut Signal<Result<Option<DeviceIdentity>, String>>,
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
    identity.set(Ok(None));
    messages.write().clear();
    status.set(Some(
        "Vault locked; MLS state and autosave password were removed from memory".into(),
    ));
}

async fn run_vault_lock_timer(
    autosave_password: Signal<Zeroizing<Vec<u8>>>,
    last_activity: Signal<Option<Instant>>,
    mut conversation: Signal<Result<MlsConversation, String>>,
    mut identity: Signal<Result<Option<DeviceIdentity>, String>>,
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
            lock_account(
                &mut conversation,
                &mut identity,
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

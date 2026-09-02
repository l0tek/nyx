use super::MeshtasticStatus;
use crate::mesh_fragment;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dioxus::prelude::*;
use jni::objects::{JClass, JString, JValue};
use meshtastic::Message;
use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
    time::Duration,
};

static NYX_CHANNEL: OnceLock<Mutex<Option<meshtastic::protobufs::Channel>>> = OnceLock::new();
static INBOUND_EVENTS: OnceLock<Mutex<VecDeque<mesh_fragment::InboundEvent>>> = OnceLock::new();
static REASSEMBLER: OnceLock<Mutex<mesh_fragment::Reassembler>> = OnceLock::new();
static FALLBACK_ATTEMPTED: OnceLock<Mutex<Vec<(uuid::Uuid, std::time::Instant)>>> = OnceLock::new();

pub(super) fn drain_inbound_events() -> Vec<mesh_fragment::InboundEvent> {
    INBOUND_EVENTS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .map(|mut events| events.drain(..).collect())
        .unwrap_or_default()
}

fn push_inbound_event(event: mesh_fragment::InboundEvent) {
    if let Ok(mut events) = INBOUND_EVENTS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
    {
        if events.len() >= 128 {
            events.pop_front();
        }
        events.push_back(event);
    }
}

pub(super) fn nyx_channel_bootstrap() -> Option<Vec<u8>> {
    NYX_CHANNEL
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()?
        .as_ref()
        .map(Message::encode_to_vec)
}

pub(super) fn install_nyx_channel_if_missing(
    encoded: &[u8],
    own_node: u32,
) -> Result<Option<u32>, String> {
    let mut current = NYX_CHANNEL
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "Meshtastic-Kanalspeicher ist nicht verfügbar")?;
    if current.is_some() {
        return Ok(None);
    }
    let channel = meshtastic::protobufs::Channel::decode(encoded)
        .map_err(|_| "Signierte Einladung enthält keine gültige Meshtastic-Kanalkonfiguration")?;
    let index = u32::try_from(channel.index)
        .ok()
        .filter(|index| (1..=7).contains(index))
        .ok_or_else(|| "Signierter NYX-Kanal verwendet einen ungültigen Index".to_owned())?;
    let settings = channel
        .settings
        .as_ref()
        .ok_or_else(|| "Signierter NYX-Kanal enthält keine Einstellungen".to_owned())?;
    if settings.name != "NYX"
        || !matches!(settings.psk.len(), 16 | 32)
        || channel.role != meshtastic::protobufs::channel::Role::Secondary as i32
    {
        return Err("Signierte NYX-Kanalkonfiguration ist ungültig".into());
    }
    let admin = meshtastic::protobufs::AdminMessage {
        payload_variant: Some(
            meshtastic::protobufs::admin_message::PayloadVariant::SetChannel(channel.clone()),
        ),
        session_passkey: Vec::new(),
    };
    let packet_uuid = uuid::Uuid::new_v4();
    let packet_id = u32::from_le_bytes(
        packet_uuid.as_bytes()[..4]
            .try_into()
            .map_err(|_| "Meshtastic-Paket-ID konnte nicht erzeugt werden")?,
    );
    let packet = meshtastic::protobufs::MeshPacket {
        from: own_node,
        to: own_node,
        id: packet_id,
        want_ack: true,
        channel: 0,
        payload_variant: Some(meshtastic::protobufs::mesh_packet::PayloadVariant::Decoded(
            meshtastic::protobufs::Data {
                portnum: meshtastic::protobufs::PortNum::AdminApp as i32,
                payload: admin.encode_to_vec(),
                want_response: true,
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let to_radio = meshtastic::protobufs::ToRadio {
        payload_variant: Some(meshtastic::protobufs::to_radio::PayloadVariant::Packet(
            packet,
        )),
    };
    send_to_radio(&to_radio.encode_to_vec())?;
    *current = Some(channel);
    Ok(Some(index))
}

// Keep the FFI declaration so Manganis packages the Kotlin plugin. Calls are
// made manually below: JNI FindClass cannot see application classes when Rust
// invokes it from an attached background thread.
mod packaged_plugin {
    #[manganis::ffi("/src/android/meshtastic-ble")]
    extern "Kotlin" {
        type MeshtasticBle;
        fn status(this: &MeshtasticBle) -> String;
    }
}

fn call_plugin(method: &str, argument: Option<&str>) -> Result<String, String> {
    manganis::android::with_activity(|env, activity| {
        let result = (|| -> jni::errors::Result<String> {
            let loader = env
                .call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
                .l()?;
            let class_name = env.new_string("com.example.MeshtasticBle")?;
            let class_object = env
                .call_method(
                    &loader,
                    "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                    &[JValue::Object(class_name.as_ref())],
                )?
                .l()?;
            let class = JClass::from(class_object);
            let instance = env.new_object(
                &class,
                "(Landroid/app/Activity;)V",
                &[JValue::Object(activity)],
            )?;

            let value = if let Some(argument) = argument {
                let argument = env.new_string(argument)?;
                env.call_method(
                    &instance,
                    method,
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(argument.as_ref())],
                )?
            } else {
                env.call_method(&instance, method, "()Ljava/lang/String;", &[])?
            };
            let string = JString::from(value.l()?);
            Ok(env.get_string(&string)?.into())
        })();

        if result.is_err() && env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
        Some(result.map_err(|error| format!("Meshtastic Bluetooth: {error}")))
    })
    .unwrap_or_else(|| Err("Android-Activity ist nicht verfügbar".to_owned()))
}

pub(super) fn scan_devices() -> Result<String, String> {
    call_plugin("startScan", None)
}

pub(super) fn list_devices() -> Result<Vec<String>, String> {
    Ok(call_plugin("devices", None)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect())
}

pub(super) fn scan_status() -> Result<String, String> {
    call_plugin("status", None)
}

pub(super) fn connect_device(selection: &str) -> Result<String, String> {
    let address = selection.split_whitespace().next().unwrap_or(selection);
    call_plugin("connect", Some(address))
}

pub(super) fn disconnect_device() -> Result<String, String> {
    call_plugin("disconnect", None)
}

pub(super) fn send_to_radio(packet: &[u8]) -> Result<(), String> {
    let result = call_plugin("sendToRadio", Some(&STANDARD.encode(packet)))?;
    if let Some(error) = result.strip_prefix("ERROR: ") {
        Err(error.to_owned())
    } else {
        Ok(())
    }
}

pub(super) fn dispatch_fallback(
    id: uuid::Uuid,
    destination: u32,
    ciphertext: &[u8],
    channel_index: u32,
) -> Result<bool, String> {
    let mut attempted = FALLBACK_ATTEMPTED
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .map_err(|_| "Meshtastic BLE fallback lock is poisoned")?;
    attempted.retain(|(_, sent)| sent.elapsed() < Duration::from_secs(60));
    if attempted
        .iter()
        .any(|(attempted_id, _)| attempted_id == &id)
    {
        return Ok(false);
    }
    for fragment in mesh_fragment::fragment(id, ciphertext)? {
        send_private_packet(destination, channel_index, fragment)?;
    }
    attempted.push((id, std::time::Instant::now()));
    Ok(true)
}

pub(super) fn dispatch_receipt(
    destination: u32,
    id: uuid::Uuid,
    digest: [u8; 8],
    signature: [u8; 64],
    channel_index: u32,
) -> Result<(), String> {
    send_private_packet(
        destination,
        channel_index,
        mesh_fragment::receipt(id, digest, signature),
    )
}

fn send_private_packet(
    destination: u32,
    channel_index: u32,
    payload: Vec<u8>,
) -> Result<(), String> {
    let packet = meshtastic::protobufs::MeshPacket {
        to: destination,
        channel: channel_index,
        id: uuid::Uuid::new_v4().as_u128() as u32,
        want_ack: true,
        payload_variant: Some(meshtastic::protobufs::mesh_packet::PayloadVariant::Decoded(
            meshtastic::protobufs::Data {
                portnum: meshtastic::protobufs::PortNum::PrivateApp as i32,
                payload,
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let to_radio = meshtastic::protobufs::ToRadio {
        payload_variant: Some(meshtastic::protobufs::to_radio::PayloadVariant::Packet(
            packet,
        )),
    };
    send_to_radio(&to_radio.encode_to_vec())
}

fn handle_mesh_packet(packet: &meshtastic::protobufs::MeshPacket) {
    if packet.from == 0 {
        return;
    }
    let Some(meshtastic::protobufs::mesh_packet::PayloadVariant::Decoded(data)) =
        &packet.payload_variant
    else {
        return;
    };
    if data.portnum != meshtastic::protobufs::PortNum::PrivateApp as i32 {
        return;
    }
    match mesh_fragment::parse(&data.payload) {
        Ok(mesh_fragment::MeshFrame::Receipt {
            id,
            digest,
            signature,
        }) => push_inbound_event(mesh_fragment::InboundEvent::Receipt {
            source: packet.from,
            id,
            digest,
            signature,
        }),
        Ok(mesh_fragment::MeshFrame::Fragment(_)) => {
            if let Ok(mut reassembler) = REASSEMBLER
                .get_or_init(|| Mutex::new(mesh_fragment::Reassembler::default()))
                .lock()
            {
                match reassembler.push(packet.from, &data.payload) {
                    Ok(Some(message)) => push_inbound_event(mesh_fragment::InboundEvent::Message {
                        source: packet.from,
                        id: message.id,
                        digest: message.digest,
                        payload: message.payload,
                    }),
                    Ok(None) => {}
                    Err(error) => {
                        super::append_log("WARN", &format!("BLE-Nachricht verworfen: {error}"))
                    }
                }
            }
        }
        Err(_) => {}
    }
}

pub(super) async fn monitor(
    id: u64,
    mut state: Signal<MeshtasticStatus>,
    session: Signal<u64>,
    mut own_node: Signal<Option<u32>>,
    mut channel_index: Signal<u32>,
    port: String,
) {
    let mut connected_polls = 0_u8;
    let mut requested_config = false;
    let mut previous_detail = String::new();
    while *session.peek() == id {
        tokio::time::sleep(Duration::from_millis(500)).await;
        match call_plugin("status", None) {
            Ok(detail) => {
                if detail != previous_detail {
                    super::append_log("INFO", &format!("BLE-Status: {detail}"));
                    previous_detail.clone_from(&detail);
                }
                let connected = detail.starts_with("CONNECTED:");
                let failed = detail.starts_with("ERROR:") || detail == "DISCONNECTED";
                state.set(MeshtasticStatus { connected, detail });
                if connected {
                    connected_polls = connected_polls.saturating_add(1);
                }
                // Let Android finish service discovery and pairing before the
                // first GATT write. Failure of this optional identity request
                // must never tear down the working BLE transport.
                let bonded = call_plugin("bondStatus", None).is_ok_and(|value| value == "BONDED");
                if connected && bonded && connected_polls >= 3 && !requested_config {
                    let request = meshtastic::protobufs::ToRadio {
                        payload_variant: Some(
                            meshtastic::protobufs::to_radio::PayloadVariant::WantConfigId(
                                uuid::Uuid::new_v4().as_u128() as u32,
                            ),
                        ),
                    };
                    match send_to_radio(&request.encode_to_vec()) {
                        Ok(()) => super::append_log("INFO", "BLE-Node-ID-Abfrage gesendet"),
                        Err(error) => super::append_log(
                            "WARN",
                            &format!(
                                "BLE bleibt verbunden; Node-ID-Abfrage fehlgeschlagen: {error}"
                            ),
                        ),
                    }
                    requested_config = true;
                }
                if connected && requested_config {
                    match call_plugin("readFromRadio", None) {
                        Ok(encoded) if !encoded.is_empty() => {
                            if let Ok(bytes) = STANDARD.decode(encoded) {
                                if let Ok(packet) =
                                    meshtastic::protobufs::FromRadio::decode(bytes.as_slice())
                                {
                                    match packet.payload_variant {
                                        Some(meshtastic::protobufs::from_radio::PayloadVariant::MyInfo(info)) => {
                                            own_node.set(Some(info.my_node_num));
                                            let _ = super::save_meshtastic_settings(&port, Some(info.my_node_num), *channel_index.peek());
                                            super::append_log("INFO", &format!("Lokale BLE-Node erkannt: !{:08x}", info.my_node_num));
                                        }
                                        Some(meshtastic::protobufs::from_radio::PayloadVariant::Channel(channel))
                                            if channel.settings.as_ref().is_some_and(|settings| settings.name == "NYX")
                                                && channel.role != meshtastic::protobufs::channel::Role::Disabled as i32 =>
                                        {
                                            if let Ok(index) = u32::try_from(channel.index) {
                                                if let Ok(mut current) = NYX_CHANNEL.get_or_init(|| Mutex::new(None)).lock() {
                                                    *current = Some(channel.clone());
                                                }
                                                channel_index.set(index);
                                                let _ = super::save_meshtastic_settings(&port, *own_node.peek(), index);
                                                super::append_log("INFO", &format!("Privater Meshtastic-Kanal NYX auf BLE-Index {index} erkannt"));
                                            }
                                        }
                                        Some(meshtastic::protobufs::from_radio::PayloadVariant::Packet(packet)) => handle_mesh_packet(&packet),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(error) => super::append_log(
                            "WARN",
                            &format!("BLE-FromRadio-Lesen fehlgeschlagen: {error}"),
                        ),
                    }
                }
                if failed {
                    break;
                }
            }
            Err(error) => {
                state.set(MeshtasticStatus {
                    connected: false,
                    detail: error,
                });
                break;
            }
        }
    }
}

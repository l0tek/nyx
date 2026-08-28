use super::MeshtasticStatus;
use crate::mesh_fragment;
use dioxus::prelude::*;
use meshtastic::{api::StreamApi, protobufs::from_radio::PayloadVariant, utils};
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

struct FallbackCommand {
    id: Uuid,
    ciphertext: Vec<u8>,
    result: oneshot::Sender<Result<bool, String>>,
}

static FALLBACK_SENDER: OnceLock<Mutex<Option<mpsc::UnboundedSender<FallbackCommand>>>> =
    OnceLock::new();

pub(super) async fn dispatch_fallback(id: Uuid, ciphertext: Vec<u8>) -> Result<bool, String> {
    let sender = FALLBACK_SENDER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "Meshtastic fallback lock is poisoned")?
        .clone()
        .ok_or_else(|| "no configured Meshtastic USB session".to_owned())?;
    let (result_tx, result_rx) = oneshot::channel();
    sender
        .send(FallbackCommand {
            id,
            ciphertext,
            result: result_tx,
        })
        .map_err(|_| "Meshtastic session ended")?;
    result_rx.await.map_err(|_| "Meshtastic session ended")?
}

pub(super) fn available_ports() -> Result<Vec<String>, String> {
    utils::stream::available_serial_ports()
        .map_err(|error| format!("Serielle Ports konnten nicht gelesen werden: {error}"))
}

pub(super) async fn run_session(
    port: String,
    id: u64,
    mut status: Signal<MeshtasticStatus>,
    session: Signal<u64>,
) {
    let serial = match utils::stream::build_serial_stream(port.clone(), None, None, None) {
        Ok(serial) => serial,
        Err(error) => {
            status.set(MeshtasticStatus {
                connected: false,
                detail: format!("{port} konnte nicht geöffnet werden: {error}"),
            });
            return;
        }
    };

    let (mut packets, api) = StreamApi::new().connect(serial).await;
    let mut api = match api.configure(utils::generate_rand_id()).await {
        Ok(api) => api,
        Err(error) => {
            status.set(MeshtasticStatus {
                connected: false,
                detail: format!("Meshtastic-Konfiguration fehlgeschlagen: {error}"),
            });
            return;
        }
    };

    status.set(MeshtasticStatus {
        connected: true,
        detail: format!("Meshtastic über {port} verbunden · Konfiguration wird gelesen"),
    });
    let mut packet_count = 0_u64;
    let mut node_count = None::<u32>;
    let mut own_node = None::<u32>;
    let mut environment = None::<String>;
    let mut radio_name = None::<String>;
    let mut hardware = None::<String>;
    let mut battery = None::<u32>;
    let mut voltage = None::<f32>;
    let mut utilization = None::<f32>;
    let destination = match meshtastic_destination() {
        Ok(destination) => destination,
        Err(error) => {
            status.set(MeshtasticStatus {
                connected: false,
                detail: error,
            });
            return;
        }
    };
    let (fallback_tx, mut fallback_rx) = mpsc::unbounded_channel();
    if let Ok(mut sender) = FALLBACK_SENDER.get_or_init(|| Mutex::new(None)).lock() {
        *sender = Some(fallback_tx);
    }
    let mut fallback_attempted = HashSet::<Uuid>::new();
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    status.set(MeshtasticStatus { connected: false, detail: format!("Verbindung zu {port} wurde beendet") });
                    break;
                };
                packet_count += 1;
                match packet.payload_variant {
                    Some(PayloadVariant::MyInfo(info)) => {
                        own_node = Some(info.my_node_num);
                        node_count = Some(info.nodedb_count);
                        if !info.pio_env.is_empty() { environment = Some(info.pio_env); }
                    }
                    Some(PayloadVariant::NodeInfo(info)) => {
                        node_count = Some(node_count.unwrap_or(0).max(1));
                        if own_node == Some(info.num) {
                            if let Some(user) = info.user {
                                if !user.long_name.is_empty() { radio_name = Some(user.long_name); }
                                hardware = meshtastic::protobufs::HardwareModel::try_from(user.hw_model)
                                    .ok()
                                    .map(|model| model.as_str_name().to_owned());
                            }
                            if let Some(metrics) = info.device_metrics {
                                battery = metrics.battery_level;
                                voltage = metrics.voltage;
                                utilization = metrics.channel_utilization;
                            }
                        }
                    }
                    _ => {}
                }
                let node = own_node.map_or_else(|| "noch unbekannt".into(), |num| format!("!{num:08x}"));
                let nodes = node_count.map_or_else(|| "noch unbekannt".into(), |count| count.to_string());
                let firmware = environment.as_deref().unwrap_or("noch unbekannt");
                let name = radio_name.as_deref().unwrap_or("noch unbekannt");
                let model = hardware.as_deref().unwrap_or("noch unbekannt");
                let battery = battery.map_or_else(|| "–".into(), |value| format!("{value}%"));
                let voltage = voltage.map_or_else(|| "–".into(), |value| format!("{value:.2} V"));
                let utilization = utilization.map_or_else(|| "–".into(), |value| format!("{value:.1}%"));
                status.set(MeshtasticStatus {
                    connected: true,
                    detail: format!("Name: {name} · Modell: {model} · eigener Node: {node} · bekannte Nodes: {nodes} · Akku: {battery} · Spannung: {voltage} · Kanalauslastung: {utilization} · Firmware-Umgebung: {firmware} · API-Pakete: {packet_count}"),
                });
            }
            Some(command) = fallback_rx.recv() => {
                let result = if fallback_attempted.contains(&command.id) {
                    Ok(false)
                } else if own_node.is_none() {
                    Err("Meshtastic node identity is not available yet".into())
                } else {
                    send_fallback_fragments(&mut api, own_node.unwrap_or_default(), destination, command.id, &command.ciphertext)
                        .await
                        .map(|()| {
                            fallback_attempted.insert(command.id);
                            true
                        })
                };
                let _ = command.result.send(result);
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                if session() != id {
                    let detail = match api.disconnect().await {
                        Ok(_) => "Meshtastic-Verbindung getrennt".to_owned(),
                        Err(error) => format!("Verbindung getrennt; Abschlussfehler: {error}"),
                    };
                    status.set(MeshtasticStatus { connected: false, detail });
                    break;
                }
            }
        }
    }
    if let Ok(mut sender) = FALLBACK_SENDER.get_or_init(|| Mutex::new(None)).lock() {
        *sender = None;
    }
}

fn meshtastic_destination() -> Result<u32, String> {
    let value = std::env::var("NYX_MESHTASTIC_DESTINATION")
        .map_err(|_| "NYX_MESHTASTIC_DESTINATION is not configured")?;
    let value = value.trim().trim_start_matches('!');
    u32::from_str_radix(value, 16)
        .or_else(|_| value.parse())
        .map_err(|_| "NYX_MESHTASTIC_DESTINATION must be a node ID such as !a1b2c3d4".into())
}

async fn send_fallback_fragments(
    api: &mut meshtastic::api::ConnectedStreamApi,
    source: u32,
    destination: u32,
    id: Uuid,
    ciphertext: &[u8],
) -> Result<(), String> {
    let fragments = mesh_fragment::fragment(id, ciphertext)?;
    for fragment in fragments {
        let packet = meshtastic::protobufs::MeshPacket {
            from: source,
            to: destination,
            id: utils::generate_rand_id(),
            want_ack: true,
            payload_variant: Some(meshtastic::protobufs::mesh_packet::PayloadVariant::Decoded(
                meshtastic::protobufs::Data {
                    portnum: meshtastic::protobufs::PortNum::PrivateApp as i32,
                    payload: fragment,
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        api.send_to_radio_packet(Some(
            meshtastic::protobufs::to_radio::PayloadVariant::Packet(packet),
        ))
        .await
        .map_err(|error| format!("Meshtastic fragment dispatch failed: {error}"))?;
    }
    Ok(())
}

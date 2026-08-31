use super::MeshtasticStatus;
use crate::mesh_fragment;
use dioxus::prelude::*;
use meshtastic::{Message, api::StreamApi, protobufs::from_radio::PayloadVariant, utils};
use meshtastic::{packet::PacketRouter, types::NodeId};
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

struct FallbackCommand {
    id: Uuid,
    destination: u32,
    ciphertext: Vec<u8>,
    result: oneshot::Sender<Result<bool, String>>,
}

struct FallbackSession {
    id: u64,
    sender: mpsc::UnboundedSender<FallbackCommand>,
}

struct PendingAcknowledgement {
    packet_ids: HashSet<u32>,
    deadline: Instant,
    result: oneshot::Sender<Result<bool, String>>,
}

static FALLBACK_SESSION: OnceLock<Mutex<Option<FallbackSession>>> = OnceLock::new();
static NYX_CHANNEL: OnceLock<Mutex<Option<meshtastic::protobufs::Channel>>> = OnceLock::new();

pub(super) fn nyx_channel_bootstrap() -> Option<Vec<u8>> {
    NYX_CHANNEL
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()?
        .as_ref()
        .map(Message::encode_to_vec)
}

fn remember_nyx_channel(channel: meshtastic::protobufs::Channel) {
    if let Ok(mut current) = NYX_CHANNEL.get_or_init(|| Mutex::new(None)).lock() {
        *current = Some(channel);
    }
}

struct LocalRouter(u32);

impl PacketRouter<(), std::convert::Infallible> for LocalRouter {
    fn handle_packet_from_radio(
        &mut self,
        _packet: meshtastic::protobufs::FromRadio,
    ) -> Result<(), std::convert::Infallible> {
        Ok(())
    }

    fn handle_mesh_packet(
        &mut self,
        _packet: meshtastic::protobufs::MeshPacket,
    ) -> Result<(), std::convert::Infallible> {
        Ok(())
    }

    fn source_node_id(&self) -> NodeId {
        self.0.into()
    }
}

pub(super) async fn dispatch_fallback(
    id: Uuid,
    destination: u32,
    ciphertext: Vec<u8>,
) -> Result<bool, String> {
    let sender = FALLBACK_SESSION
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "Meshtastic fallback lock is poisoned")?
        .as_ref()
        .map(|session| session.sender.clone())
        .ok_or_else(|| "no configured Meshtastic USB session".to_owned())?;
    let (result_tx, result_rx) = oneshot::channel();
    sender
        .send(FallbackCommand {
            id,
            destination,
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
    mut own_node_signal: Signal<Option<u32>>,
    mut channel_index_signal: Signal<u32>,
) {
    let mut channel_index = *channel_index_signal.peek();
    super::append_log("INFO", &format!("Öffne Meshtastic USB-Port {port}"));
    let serial = match utils::stream::build_serial_stream(port.clone(), None, None, None) {
        Ok(serial) => serial,
        Err(error) => {
            super::append_log(
                "ERROR",
                &format!("USB-Port {port} konnte nicht geöffnet werden: {error}"),
            );
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
            super::append_log(
                "ERROR",
                &format!("Meshtastic-Konfiguration über {port} fehlgeschlagen: {error}"),
            );
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
    super::append_log("INFO", &format!("Meshtastic über {port} verbunden"));
    let mut packet_count = 0_u64;
    let mut node_count = None::<u32>;
    // The node ID is persisted together with the selected port. Reuse it
    // immediately after reconnecting instead of blocking outbound packets
    // until the radio happens to emit another MyInfo packet.
    let mut own_node = *own_node_signal.peek();
    let mut environment = None::<String>;
    let mut radio_name = None::<String>;
    let mut hardware = None::<String>;
    let mut battery = None::<u32>;
    let mut voltage = None::<f32>;
    let mut utilization = None::<f32>;
    let mut configured_channels = Vec::<meshtastic::protobufs::Channel>::new();
    let mut channel_setup_complete = false;
    let (fallback_tx, mut fallback_rx) = mpsc::unbounded_channel();
    if let Ok(mut session) = FALLBACK_SESSION.get_or_init(|| Mutex::new(None)).lock() {
        *session = Some(FallbackSession {
            id,
            sender: fallback_tx,
        });
    }
    let mut fallback_attempted = HashSet::<Uuid>::new();
    let mut pending_acknowledgements = Vec::<PendingAcknowledgement>::new();
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    super::append_log("WARN", &format!("Meshtastic-Verbindung zu {port} wurde beendet"));
                    status.set(MeshtasticStatus { connected: false, detail: format!("Verbindung zu {port} wurde beendet") });
                    break;
                };
                packet_count += 1;
                if let Some(PayloadVariant::Packet(mesh_packet)) = &packet.payload_variant
                    && let Some((request_id, acknowledgement)) = routing_acknowledgement(mesh_packet)
                    && let Some(index) = pending_acknowledgements
                        .iter()
                        .position(|pending| pending.packet_ids.contains(&request_id))
                {
                    if let Err(error) = acknowledgement {
                        let pending = pending_acknowledgements.swap_remove(index);
                        let _ = pending.result.send(Err(error));
                    } else {
                        let pending = &mut pending_acknowledgements[index];
                        pending.packet_ids.remove(&request_id);
                        if pending.packet_ids.is_empty() {
                            let pending = pending_acknowledgements.swap_remove(index);
                            let _ = pending.result.send(Ok(true));
                        }
                    }
                }
                match packet.payload_variant {
                    Some(PayloadVariant::MyInfo(info)) => {
                        super::append_log("INFO", &format!("Lokale Meshtastic-Node erkannt: !{:08x}", info.my_node_num));
                        own_node = Some(info.my_node_num);
                        own_node_signal.set(own_node);
                        let _ = super::save_meshtastic_settings(&port, own_node, channel_index);
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
                    Some(PayloadVariant::Channel(channel)) => {
                        configured_channels.retain(|current| current.index != channel.index);
                        configured_channels.push(channel);
                    }
                    Some(PayloadVariant::ConfigCompleteId(_)) if !channel_setup_complete => {
                        channel_setup_complete = true;
                        match ensure_nyx_channel(&mut api, own_node, &configured_channels).await {
                            Ok(index) => {
                                channel_index = index;
                                channel_index_signal.set(index);
                                let _ = super::save_meshtastic_settings(&port, own_node, index);
                                super::append_log("INFO", &format!("Privater Meshtastic-Kanal NYX auf Index {index} aktiv"));
                            }
                            Err(error) => {
                                super::append_log("ERROR", &error);
                                status.set(MeshtasticStatus { connected: true, detail: error });
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
                if fallback_attempted.contains(&command.id) {
                    let _ = command.result.send(Ok(false));
                } else if own_node.is_none() {
                    let _ = command.result.send(Err(
                        "Meshtastic node identity is not available yet".into(),
                    ));
                } else {
                    match send_fallback_fragments(&mut api, own_node.unwrap_or_default(), command.destination, command.id, &command.ciphertext, channel_index).await {
                        Ok(packet_ids) => {
                            fallback_attempted.insert(command.id);
                            pending_acknowledgements.push(PendingAcknowledgement {
                                packet_ids: packet_ids.into_iter().collect(),
                                deadline: Instant::now() + Duration::from_secs(15),
                                result: command.result,
                            });
                        }
                        Err(error) => {
                            let _ = command.result.send(Err(error));
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                let now = Instant::now();
                let mut index = 0;
                while index < pending_acknowledgements.len() {
                    if pending_acknowledgements[index].deadline <= now {
                        let pending = pending_acknowledgements.swap_remove(index);
                        let _ = pending.result.send(Err(
                            "keine Meshtastic-Zustellbestätigung innerhalb von 15 Sekunden".into(),
                        ));
                    } else {
                        index += 1;
                    }
                }
                if *session.peek() != id {
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
    if let Ok(mut session) = FALLBACK_SESSION.get_or_init(|| Mutex::new(None)).lock()
        && session.as_ref().is_some_and(|current| current.id == id)
    {
        *session = None;
    }
}

async fn ensure_nyx_channel(
    api: &mut meshtastic::api::ConnectedStreamApi,
    own_node: Option<u32>,
    channels: &[meshtastic::protobufs::Channel],
) -> Result<u32, String> {
    if let Some(channel) = channels.iter().find(|channel| {
        channel
            .settings
            .as_ref()
            .is_some_and(|settings| settings.name == "NYX")
            && channel.role != meshtastic::protobufs::channel::Role::Disabled as i32
    }) {
        remember_nyx_channel(channel.clone());
        return u32::try_from(channel.index).map_err(|_| "NYX-Kanalindex ist ungültig".into());
    }
    let index = (1..=7)
        .find(|index| !channels.iter().any(|channel| channel.index == *index))
        .ok_or_else(|| "Kein freier Meshtastic-Kanal für NYX verfügbar".to_owned())?;
    let source = own_node.ok_or_else(|| "Lokale Meshtastic-Node-ID fehlt".to_owned())?;
    let mut psk = vec![0_u8; 32];
    OsRng.fill_bytes(&mut psk);
    let channel = meshtastic::protobufs::Channel {
        index,
        role: meshtastic::protobufs::channel::Role::Secondary as i32,
        settings: Some(meshtastic::protobufs::ChannelSettings {
            psk,
            name: "NYX".into(),
            id: utils::generate_rand_id(),
            ..Default::default()
        }),
    };
    api.update_channel_config(&mut LocalRouter(source), channel.clone())
        .await
        .map_err(|error| {
            format!("Privater Meshtastic-Kanal NYX konnte nicht angelegt werden: {error}")
        })?;
    remember_nyx_channel(channel);
    Ok(index as u32)
}

async fn send_fallback_fragments(
    api: &mut meshtastic::api::ConnectedStreamApi,
    source: u32,
    destination: u32,
    id: Uuid,
    ciphertext: &[u8],
    channel_index: u32,
) -> Result<Vec<u32>, String> {
    let fragments = mesh_fragment::fragment(id, ciphertext)?;
    let mut packet_ids = Vec::with_capacity(fragments.len());
    for fragment in fragments {
        let packet_id = utils::generate_rand_id();
        let packet = meshtastic::protobufs::MeshPacket {
            from: source,
            to: destination,
            id: packet_id,
            channel: channel_index,
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
        packet_ids.push(packet_id);
    }
    Ok(packet_ids)
}

fn routing_acknowledgement(
    packet: &meshtastic::protobufs::MeshPacket,
) -> Option<(u32, Result<(), String>)> {
    let meshtastic::protobufs::mesh_packet::PayloadVariant::Decoded(data) =
        packet.payload_variant.as_ref()?
    else {
        return None;
    };
    if data.portnum != meshtastic::protobufs::PortNum::RoutingApp as i32 || data.request_id == 0 {
        return None;
    }
    let routing = meshtastic::protobufs::Routing::decode(data.payload.as_slice()).ok()?;
    let result = match routing.variant {
        Some(meshtastic::protobufs::routing::Variant::ErrorReason(reason)) if reason != 0 => {
            let detail = match meshtastic::protobufs::routing::Error::try_from(reason) {
                Ok(meshtastic::protobufs::routing::Error::NoChannel) =>
                    "NO_CHANNEL – Ziel konnte das Paket nicht entschlüsseln; Channel-PSK und Meshtastic-Public-Keys beider Nodes aktualisieren".to_owned(),
                Ok(error) => error.as_str_name().to_owned(),
                Err(_) => format!("unbekannter Routing-Fehler {reason}"),
            };
            Err(format!("Meshtastic-Zustellung abgelehnt: {detail}"))
        }
        _ => Ok(()),
    };
    Some((data.request_id, result))
}

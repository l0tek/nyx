# NYX – Codex Handoff

## Ziel

NYX ist ein sicherer, dezentraler Chat-Client in Rust.

Technologien:
- Rust
- Dioxus
- Meshtastic
- Tor / Onion Services
- später ggf. weitere Transportwege

Ziel ist eine klare Trennung zwischen UI, Messaging,
Transport, Kryptografie und Persistenz.

## Aktueller Stand

Repository:
- Rust Workspace
- Desktop-App unter `apps/desktop`
- Dioxus als UI-Framework

Aktuelles Entwicklungsgerät:
- Linux
- Rust stable
- Meshtastic-Gerät über `/dev/ttyUSB0`

Meshtastic:
- Gerät wird über CLI erkannt
- Hardware: HELTEC_V3
- Region: EU_868
- LoRa funktioniert
- Bluetooth wird aktuell untersucht

## Architektur

Wichtige Komponenten:

- UI
  Dioxus Desktop

- Core
  Nachrichtenmodell und Anwendungslogik

- Transport
  Abstraktion für verschiedene Transportwege

- Meshtastic Transport
  Kommunikation mit Meshtastic Nodes

- Tor Transport
  Kommunikation über Onion Services

- Crypto
  Verschlüsselung und Schlüsselverwaltung

Keine Transportlogik direkt in UI-Komponenten implementieren.

## Wichtige Entscheidungen

- Rust bleibt Hauptsprache.
- Dioxus bleibt UI-Framework.
- Transportwege sollen über Traits abstrahiert werden.
- Meshtastic ist ein Transport und nicht Teil der Core-Logik.
- Kryptografie nicht selbst erfinden.
- Keine großen Architekturumbauten ohne konkreten Grund.

## Aktuelle Probleme

1. Meshtastic-Integration weiter stabilisieren.
2. Bluetooth-Kopplung des Heltec-V3 testen.
3. Desktop-App mit realem Meshtastic-Gerät verbinden.
4. Fehlerbehandlung bei Verbindungsabbruch verbessern.

## Nächster Task

Untersuche die bestehende Meshtastic-Integration im Repository.

Ziel:

1. vorhandenen Code verstehen
2. Verbindung zu `/dev/ttyUSB0` prüfen
3. bestehende Architektur beibehalten
4. nur notwendige Änderungen durchführen
5. danach Build und Tests ausführen

Nicht sofort große Refactorings durchführen.

## Build

```bash
cargo check
cargo test
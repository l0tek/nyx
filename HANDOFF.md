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
- Desktop-Gerät ist unter `/dev/ttyUSB0` erreichbar
- Hardware: HELTEC_V3
- Region: EU_868
- LoRa funktioniert
- NYX erkennt die lokale Desktop-Node `!9e76506c`
- Android BLE verbindet sich und kann GATT-Lese-/Schreiboperationen ausführen
- Testkontakt auf Android/Handy: `!9e7638c4`

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

1. Der Desktop-Test wartet jetzt auf echte Meshtastic-Routing-ACKs und meldet
   Fehler beziehungsweise einen Timeout nach 15 Sekunden.
2. Android serialisiert GATT-Lese- und Schreiboperationen; dadurch wird der
   Testschreibvorgang nicht mehr von einem parallelen `FromRadio`-Read abgelehnt.
3. Ein zusätzlicher privater Kanal `NYX` ist auf beiden Test-Nodes als Index 1
   eingerichtet. Broadcast und bestätigte CLI-Direktnachricht funktionieren.
4. NYX erkennt den Kanal automatisch. Desktop legt ihn bei Bedarf mit einem
   zufälligen 256-Bit-PSK an; Android erkennt den importierten Kanal. Der lokale
   Index wird persistent für USB- beziehungsweise BLE-Testpakete verwendet.
5. Neue signierte Kontakt-QR-Codes enthalten die aktive `NYX`-Kanalkonfiguration.
   Android installiert sie nur, wenn das verbundene Funkgerät noch keinen
   aktiven Kanal `NYX` besitzt.

## Nächster Task

Die Funkverbindung in NYX neu aufbauen, die automatische Erkennung von Kanal
`NYX` prüfen und den Zustellungstest zu `!9e7638c4` durchführen.

Ziel:

1. beide Nodes sehen einander mit aktuellen Public Keys in ihrer NodeDB
2. beide Nodes verwenden denselben LoRa-Kanal einschließlich PSK
3. normale Meshtastic-Direktnachricht funktioniert
4. NYX meldet danach `zugestellt und bestätigt`

Nicht sofort große Refactorings durchführen.

## Verifiziert

- USB-Verbindung und lokale Node-Erkennung mit realem HELTEC_V3
- Android Universal-Debug-APK erfolgreich gebaut
- APK: `dist/nyx-android-meshtastic-bluetooth-universal-debug.apk`
- SHA-256: `6de36e882ba7a9409ba051b883117e79105c7f0b05c69d389d600cb23391f512`
- 43 Workspace-Tests erfolgreich

## Build

```bash
cargo check
cargo test
./scripts/build-android.sh
```

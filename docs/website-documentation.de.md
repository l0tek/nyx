---
title: "Nyx – vollständige Projektdokumentation"
description: "Architektur, Installation, Bedienung und Sicherheitsmodell des Tor- und MLS-basierten Nyx-Messengers mit experimenteller Meshtastic-Unterstützung."
lang: de
date: 2026-08-28
---

# Nyx

Nyx ist ein experimenteller, sicherheitsorientierter Messenger für Desktop und
Android. Das Projekt kombiniert Ende-zu-Ende-Verschlüsselung mit MLS, anonyme
Netzwerktransporte über Tor Onion Services, lokale verschlüsselte Identitäten
und einen optionalen Meshtastic-Funktransport.

> **Wichtiger Sicherheitshinweis:** Nyx befindet sich im Architektur- und
> MVP-Stadium. Das Projekt wurde nicht unabhängig auditiert und ist nicht für
> sensible oder produktive Kommunikation geeignet. Die Dokumentation beschreibt
> den aktuellen Entwicklungsstand und ist kein Sicherheitsversprechen.

## Inhalt

1. [Ziele und Grundprinzipien](#ziele-und-grundprinzipien)
2. [Aktueller Funktionsumfang](#aktueller-funktionsumfang)
3. [Systemarchitektur](#systemarchitektur)
4. [Sicherheitsmodell](#sicherheitsmodell)
5. [Installation und Build](#installation-und-build)
6. [Erste Einrichtung](#erste-einrichtung)
7. [Kontakte und MLS-Sitzungen](#kontakte-und-mls-sitzungen)
8. [Nachrichtenversand über Tor](#nachrichtenversand-über-tor)
9. [Meshtastic-Unterstützung](#meshtastic-unterstützung)
10. [Mailbox-Server](#mailbox-server)
11. [Konfiguration](#konfiguration)
12. [Dateien und Datensicherung](#dateien-und-datensicherung)
13. [Fehlerbehebung](#fehlerbehebung)
14. [Entwicklung und Tests](#entwicklung-und-tests)
15. [Bekannte Grenzen](#bekannte-grenzen)
16. [Roadmap](#roadmap)

## Ziele und Grundprinzipien

Nyx folgt fünf grundlegenden Regeln:

- Nachrichteninhalte werden unabhängig vom Transport Ende-zu-Ende
  verschlüsselt.
- Internetverkehr erfolgt ausschließlich über Tor. Es gibt keinen automatischen
  Clearnet-Fallback.
- Der Mailbox-Server verarbeitet nur undurchsichtige Ciphertexte und
  pseudonyme Zugriffstoken.
- Identitäten und Schlüssel werden lokal gespeichert. Ein zentrales Konto,
  eine Telefonnummer oder E-Mail-Adresse sind nicht erforderlich.
- Kontakte werden außerhalb von Nyx verifiziert, beispielsweise persönlich
  durch den Vergleich eines Fingerabdrucks.

Tor und MLS erfüllen unterschiedliche Aufgaben. Tor schützt den Transportweg
und verbirgt die IP-Adressen der Kommunikationspartner vor dem Mailbox-Dienst.
MLS schützt Inhalt, Authentizität und Sitzungszustand der Nachrichten. Keine
dieser Schichten ersetzt die andere.

## Aktueller Funktionsumfang

### Desktop und Android

Die gemeinsame Dioxus-Oberfläche bietet:

- lokale Registrierung und Anmeldung mit einem Vault-Passwort;
- eine persistente Geräteidentität mit Ed25519-Signaturschlüssel;
- Anzeige des Gerätefingerabdrucks;
- signierte Kontakteinladungen als Text und QR-Code;
- QR-Code-Scan auf Android;
- Import, Auswahl, Verifikation und erneute Verbindung von Kontakten;
- Aufbau einer echten Zwei-Personen-MLS-Sitzung;
- verschlüsselten Nachrichtenversand und -empfang über eine Onion-Mailbox;
- eine dauerhafte Ausgangswarteschlange mit Wiederholungsversuchen;
- Statusanzeigen für Tor, Onion-Mailbox und Meshtastic;
- automatische Vault-Sperre nach Inaktivität;
- Verwaltung mehrerer Mailbox-Einträge;
- Desktop-Meshtastic über USB-Serial;
- Android-Meshtastic-Erkennung und Verbindung über Bluetooth.

### Mailbox-Server

Der Mailbox-Dienst:

- veröffentlicht einen persistenten Tor-v3-Onion-Service;
- akzeptiert ausschließlich Onion-Verbindungen auf dem virtuellen Port 443;
- öffnet keinen lokalen oder öffentlichen Clearnet-TCP-Port;
- speichert Ciphertexte in SQLite;
- unterstützt Ablage, Abruf und Quittierung;
- behandelt wiederholte Ablagen idempotent;
- entfernt bestätigte oder abgelaufene Nachrichten;
- protokolliert weder Mailbox-Token noch Ciphertexte oder Nachrichteninhalte.

## Systemarchitektur

Das Rust-Workspace ist in klar getrennte Komponenten aufgeteilt:

```text
nyx/
├── apps/
│   ├── desktop/          Desktop- und Android-Einstiegspunkt
│   ├── mailbox-server/   Tor-Onion-Mailbox
│   └── mailbox-smoke/    manueller Live-Tor-Funktionstest
├── crates/
│   ├── nyx-core/         Domänenmodell und Anwendungslogik
│   ├── nyx-crypto/       OpenMLS- und Kryptografiegrenze
│   ├── nyx-protocol/     Transportobjekte und Framing
│   ├── nyx-store/        verschlüsselter Vault und Warteschlange
│   ├── nyx-tor/          Arti-/Tor-Transport
│   └── nyx-ui/           gemeinsame Dioxus-Oberfläche
├── docs/                 Architektur- und Statusdokumente
└── scripts/              reproduzierbare Buildskripte
```

Der logische Datenfluss sieht so aus:

```text
Benutzeroberfläche
        │
        ▼
Identität, Kontakte und Anwendungslogik
        │
        ├── OpenMLS: Verschlüsselung und Authentifizierung
        ├── verschlüsselter lokaler Vault
        └── dauerhafte Ciphertext-Warteschlange
                    │
                    ▼
           Tor/Arti-Transport
                    │
                    ▼
             Onion-Mailbox

Optional bei Tor-Fehler auf Desktop:
Ciphertext-Warteschlange → Fragmentierung → Meshtastic USB
```

### Transportobjekt

Der Mailbox-Server sieht ein äußeres Objekt dieser Art:

```text
Envelope {
    version,
    mailbox_token,
    ciphertext,
}
```

Informationen wie Absendergerät, Unterhaltung, Inhaltstyp und Nachrichtentext
liegen innerhalb der MLS-verschlüsselten Nutzlast. Der Server soll sie nicht
interpretieren können.

### Zustellung und Absturzsicherheit

Vor dem Versand speichert Nyx den fortgeschrittenen MLS-Zustand, eine stabile
Queue-ID, den Empfänger-Token und den Ciphertext atomar im verschlüsselten
Vault. Die Übergabe an SQLite ist idempotent. Dadurch soll ein Prozessabbruch
zwischen MLS-Ratchet-Fortschritt und Queue-Eintrag weder eine Nachricht doppelt
erzeugen noch einen veralteten Ratchet-Zustand wiederverwenden.

Beim Empfang wird der fortgeschrittene MLS-Zustand zusammen mit der
Mailbox-Quittung gespeichert, bevor Nyx die Nachricht auf dem Server bestätigt.
Schlägt die Bestätigung fehl, kann sie nach einem Neustart wiederholt werden,
ohne die MLS-Nachricht erneut zu verarbeiten.

## Sicherheitsmodell

### Eingesetzte Verfahren

- **MLS:** OpenMLS 0.8.1, orientiert an RFC 9420.
- **MLS-Ciphersuite:** X25519, AES-128-GCM und SHA-256.
- **Gerätesignaturen:** Ed25519.
- **Lokaler Vault:** Argon2id plus XChaCha20-Poly1305.
- **Integritätsdigest für Funkfragmente:** BLAKE3.
- **Anonymisierter Internettransport:** Arti/Tor 0.45 und v3 Onion Services.

Nyx implementiert keine eigenen kryptografischen Primitive. Die
Anwendungslogik legt jedoch Protokollabläufe und Persistenz fest; genau diese
Integration muss vor einem produktiven Einsatz unabhängig geprüft werden.

### Bedrohungen im Geltungsbereich

Das Design soll Nachrichteninhalte schützen und Metadaten reduzieren gegenüber:

- dem lokalen Internetanbieter oder Netzwerkbetreiber;
- passiver Aufzeichnung des Netzwerkverkehrs;
- einem neugierigen oder kompromittierten Mailbox-Server;
- dem Diebstahl der serverseitigen Nachrichtendatenbank;
- einzelnen bösartigen Tor-Relays;
- später kompromittierten Sitzungsschlüsseln, soweit MLS Forward Secrecy bietet.

### Nur teilweise entschärfte Risiken

Nicht vollständig verhindert werden:

- zeitliche Korrelation von Sende- und Empfangsereignissen;
- globale passive Überwachung;
- Analyse von Nachrichtengrößen und Abrufmustern;
- Wiedererkennung langfristig verwendeter Mailbox-Token;
- Funkmetadaten wie Meshtastic-Knotenkennung, Kanal und Sendezeit.

Padding, Token-Rotation, Batching und Cover Traffic sind mögliche Maßnahmen,
aber derzeit nicht vollständig implementiert.

### Außerhalb des Geltungsbereichs

Nyx schützt nicht vor:

- einem kompromittierten Betriebssystem;
- Keyloggern, Bildschirmaufzeichnung oder bösartigen Bedienungshilfen;
- physischem Zugriff auf ein entsperrtes Gerät;
- einem Gesprächspartner, der entschlüsselten Inhalt kopiert;
- unbekannten Fehlern in Betriebssystem, Tor oder Kryptobibliotheken;
- Verlust des Vault-Passworts oder der Identitätsdateien.

### Verbindliche Sicherheitsregeln

- Kein Clearnet-Fallback, wenn Tor nicht verfügbar ist.
- Keine Protokollierung von Klartext, geheimen Schlüsseln oder ungekürzten
  Zugangsdaten.
- Kontaktfingerabdrücke über einen unabhängigen Kanal vergleichen.
- Onion-Identität, Clientidentität und Transporttoken getrennt behandeln.
- Vor jeder Aussage wie „sicher“ oder „anonym“ ein unabhängiges Audit
  durchführen.

## Installation und Build

### Voraussetzungen

Für den Rust-Build werden benötigt:

- Rust 1.91 oder neuer;
- Cargo;
- ein für Dioxus 0.7 passendes `dx`-CLI;
- plattformspezifische Dioxus-/WebView-Abhängigkeiten;
- für Android: Android SDK, NDK, Java/Gradle und eingerichtete Rust-Targets.

Repository klonen und Workspace prüfen:

```bash
git clone <repository-url> nyx
cd nyx
cargo build --workspace
```

### Desktop-Client im Entwicklungsmodus

```bash
cd apps/desktop
dx serve --desktop
```

Die Anwendung lädt die nächste `.env`-Datei, überschreibt aber keine bereits
gesetzten Prozessvariablen.

### Desktop-Paket bauen

```bash
dx build --desktop --release --locked --package nyx-desktop
```

Der genaue Ausgabeordner wird vom Dioxus-CLI ausgegeben. Vor einer öffentlichen
Binärdistribution muss die Lizenzsituation der eingebundenen offiziellen Rust-
Meshtastic-Bibliothek geprüft werden; sie wird unter GPL-3.0 angeboten.

### Android-APK bauen

Das bereitgestellte Skript erzeugt eine universelle Debug-APK für `arm64-v8a`
und `x86_64`:

```bash
./scripts/build-android.sh
```

Ausgabe:

```text
dist/nyx-android-meshtastic-bluetooth-universal-debug.apk
```

Das Skript kopiert zusätzlich die von Arti benötigten OpenSSL-Bibliotheken in
beide ABI-Verzeichnisse. Einzelne `dx build --target`-Aufrufe ohne diesen
Verpackungsschritt können eine APK erzeugen, die beim Start wegen fehlender
`libssl.so` oder `libcrypto.so` abstürzt.

Installation per USB-Debugging:

```bash
adb install -r dist/nyx-android-meshtastic-bluetooth-universal-debug.apk
```

Die erzeugte APK ist ein Entwicklungsartefakt und kein signiertes
Produktionsrelease.

## Erste Einrichtung

### 1. Lokalen Vault anlegen

Beim ersten Start wird eine lokale Registrierung durchgeführt. Das gewählte
Passwort verschlüsselt den Vault auf diesem Gerät. Es gibt keinen zentralen
Account und derzeit keine Wiederherstellungsfunktion.

Wichtig:

- ein langes, einzigartiges Passwort verwenden;
- Passwort und Identitätsdateien getrennt sichern;
- nicht davon ausgehen, dass eine Neuinstallation die Identität
  wiederherstellen kann;
- die Anwendung bei Nichtbenutzung sperren.

### 2. Mailbox konfigurieren

In der Konfiguration kann eine v3-Onion-Adresse hinzugefügt oder ausgewählt
werden. Der Port ist standardmäßig `443`. Für gerichtete Zustellung verwendet
Nyx zufällige 256-Bit-Mailbox-Fähigkeiten. Sender und Empfänger benötigen
unterschiedliche Token.

### 3. Tor-Status prüfen

Die Statusansicht unterscheidet:

- Tor-Bootstrap;
- Erreichbarkeit der Onion-Mailbox;
- Antwortzeit des letzten Health Checks;
- Zeitpunkt der letzten erfolgreichen Prüfung;
- Fehler bei Zustellung oder Wiederholung.

Ein inhaltloser Health Check läuft im Normalfall alle zehn Sekunden. Scheitert
er, verbleiben Nachrichten in der lokalen Warteschlange.

## Kontakte und MLS-Sitzungen

### Einladung exportieren

Eine Kontakteinladung enthält unter anderem:

- Gerätekennung und öffentlichen Signaturschlüssel;
- Gerätefingerabdruck;
- v3-Onion-Endpunkt;
- validiertes MLS-KeyPackage;
- getrennte zufällige Fähigkeiten für beide Zustellrichtungen;
- Zeit- und Größenbegrenzungen;
- eine Ed25519-Signatur über alle Felder.

Die Einladung kann als URL-sicherer Base64-Text oder QR-Code übertragen werden.
Der QR-Code exportiert keine lokale private Identität und kein Vault-Passwort.

### Einladung importieren

Beim Import prüft Nyx Signatur, Zeitangaben, Onion-Syntax, KeyPackage-Signatur,
KeyPackage-Lebensdauer, Ciphersuite, Größenlimits und doppelte Gerätekennungen.

### Fingerabdruck verifizieren

Der angezeigte Fingerabdruck muss über einen unabhängigen, vertrauenswürdigen
Kanal verglichen werden – idealerweise persönlich oder per bereits
authentifiziertem Gespräch. Erst danach sollte der Kontakt als verifiziert
markiert werden.

### MLS-Verbindung herstellen

Das annehmende Gerät erzeugt eine Zwei-Personen-MLS-Gruppe, fügt das persistierte
KeyPackage des Einladenden hinzu und sendet ein signiertes Welcome zurück. Der
Einladende prüft die Signatur und tritt mit seinem privaten KeyPackage-Material
der Gruppe bei. Nachrichten werden erst freigeschaltet, wenn Kontaktprüfung und
MLS-Sitzung abgeschlossen sind.

Allgemeine Gruppenchats, Mehrgerätebetrieb, Mitgliederentfernung, Updates und
KeyPackage-Rotation sind noch nicht implementiert.

## Nachrichtenversand über Tor

### Ausgang

1. Die Anwendung erzeugt eine MLS PrivateMessage.
2. Ratchet-Zustand und Queue-Übergabe werden im verschlüsselten Vault
   journalisiert.
3. Der Ciphertext wird idempotent in SQLite eingereiht.
4. Der Hintergrundprozess bootstrapt Tor und prüft die Onion-Mailbox.
5. Die Nachricht wird in Reihenfolge abgelegt.
6. Erst die positive Serverantwort markiert den Queue-Eintrag als zugestellt.

### Eingang

1. Der Client fragt die Fähigkeiten der Kontakte und offenen Einladungen ab.
2. Er verarbeitet nur gültige, erwartete Nutzlasttypen.
3. Die MLS-Nachricht wird lokal entschlüsselt.
4. Ratchet und Empfangsquittung werden atomar gespeichert.
5. Erst danach bestätigt Nyx die Nachricht gegenüber der Mailbox.

Die sichtbare Chat-Historie ist derzeit nicht Bestandteil des verschlüsselten
MLS-Snapshots. Der sichere Ratchet-Zustand wird gespeichert, eine vollständige
dauerhafte Verlaufsspeicherung steht jedoch noch aus.

## Meshtastic-Unterstützung

Meshtastic ist ein zusätzlicher lokaler Funktransport. Die MLS-verschlüsselte
Nutzlast bleibt auch über Funk verschlüsselt; Meshtastic-Kanalverschlüsselung
ist lediglich eine zusätzliche Schicht und kein Ersatz für MLS.

### Desktop: USB-Serial

Linux, Windows und macOS verwenden die offizielle Rust-Meshtastic-Bibliothek und
die Meshtastic Stream API über einen seriellen Port mit 115200 Baud.

Einrichtung:

1. Meshtastic-Gerät per USB anschließen.
2. **Konfiguration → Meshtastic** öffnen.
3. **Geräte suchen** wählen.
4. Einen gefundenen Port auswählen oder manuell eingeben, beispielsweise
   `/dev/ttyACM0`, `/dev/ttyUSB0` oder `COM3`.
5. **Verbinden** auswählen.

Wenn die Firmware die Daten liefert, zeigt der Desktop-Client:

- seriellen Port;
- lokale Node-ID und Knotenname;
- Hardwaremodell;
- Firmware-/Umgebungsinformationen;
- Zahl bekannter Knoten;
- Batterie und Spannung;
- Kanalauslastung;
- beobachtete PhoneAPI-Pakete.

Unter Linux kann der Benutzer Zugriffsrechte auf den seriellen Port benötigen,
zum Beispiel über die passende Systemgruppe oder eine udev-Regel.

### Android: Bluetooth

Android verwendet keinen USB-Transport. Eine native Kotlin/JNI-Komponente sucht
parallel über BLE Low-Latency und klassische Bluetooth-Discovery. Das ist
notwendig, weil einige Geräte oder Android-Hersteller Meshtastic-Namen nicht in
jedem BLE-Scanpfad gleich sichtbar machen.

Benötigte Berechtigungen:

- Bluetooth-Scan;
- Verbindung mit Geräten in der Nähe;
- auf betroffenen Android-/Samsung-Versionen Standortzugriff;
- auf älteren Android-Versionen die klassischen Bluetooth-Berechtigungen.

Einrichtung:

1. Bluetooth und das Meshtastic-Gerät einschalten.
2. Android-Bluetooth-Einstellungen schließen, damit kein konkurrierender
   Dauerscan läuft.
3. In Nyx **Konfiguration → Meshtastic → Geräte suchen** wählen.
4. Alle angeforderten Berechtigungen erlauben.
5. Zehn Sekunden bis zum Scanende warten.
6. Ein Gerät wie `Meshtastic_38c4` aus der Liste auswählen.
7. **Verbinden** wählen.

Nyx prüft nach dem Verbinden, ob das Gerät den offiziellen
Meshtastic-GATT-Dienst `6ba1b218-15a8-461f-9fa8-5dcae273eafd` bereitstellt.
Geräte ohne diesen Dienst werden abgelehnt.

### Tor-first, Meshtastic-Fallback

Der aktuelle Versand folgt einer Tor-first-Strategie:

1. Nyx versucht Tor zu bootstrappen.
2. Nyx prüft die Onion-Mailbox.
3. Nyx versucht die normale Mailbox-Ablage.
4. Erst bei einem Fehler werden noch ausstehende, bereits MLS-verschlüsselte
   Nutzlasten einer aktiven Desktop-USB-Meshtastic-Sitzung angeboten.

Der Zielknoten wird im jeweiligen verifizierten Nyx-Kontakt gespeichert. Die
Node-ID muss hexadezimal angegeben werden, beispielsweise `!a1b2c3d4`. Nyx
ordnet wartende Nachrichten anhand der kontaktbezogenen Mailbox-Fähigkeit dem
richtigen Funkziel zu.

### Funkfragmentierung

Eine MLS-Nachricht kann größer als ein Meshtastic-Anwendungspaket sein. Nyx
verwendet daher ein versioniertes `NYXM`-Fragmentformat mit:

- stabiler UUID des Queue-Eintrags;
- Fragmentindex und Fragmentanzahl;
- gekürztem BLAKE3-Digest der Gesamtnachricht;
- Größenbegrenzung unterhalb des 233-Byte-Anwendungslimits;
- maximal 16 KiB Gesamtnutzlast;
- Unicast über `PRIVATE_APP`;
- `want_ack` für jedes Fragment.

Ein Funk-ACK beweist nur die Annahme eines Pakets durch die Funkstrecke. Er
beweist nicht, dass die Gegenstelle alle Fragmente zusammengesetzt, die
MLS-Nachricht verarbeitet und dauerhaft gespeichert hat. Deshalb entfernt Nyx
den ursprünglichen Tor-Queue-Eintrag nach dem aktuellen Funkversand bewusst
nicht. Tor darf später erneut zustellen; MLS-Replay-Schutz soll Duplikate
abweisen.

### Derzeitige Meshtastic-Grenzen

Noch nicht implementiert sind:

- eingehende `NYXM`-Reassemblierung;
- Ende-zu-Ende-Verarbeitungsquittungen;
- selektive Wiederholung fehlender Fragmente;
- persistenter Fragmentzustand;
- Nutzlastversand über Android-BLE;
- authentifizierte automatische Erkennung der Node-ID eines Kontakts;
- Übertragung initialer MLS-Welcome-/KeyPackage-Daten über Funk;
- große Dateien oder Anhänge.

Der Meshtastic-Pfad ist daher ein experimenteller ausgehender Desktop-Fallback
und noch kein vollständiger alternativer Nachrichtentransport. Der öffentliche
Standardkanal `LongFast` ist für vertrauliche Kommunikation ungeeignet.

## Mailbox-Server

### Lokale Konfiguration

```bash
cp .env.example .env
```

Alle Platzhalter müssen ersetzt werden. `.env` ist für lokale Entwicklung
gedacht, wird nicht in Git eingecheckt und ist kein Produktions-Secretsystem.

Server starten:

```bash
cargo run -p nyx-mailbox-server
```

Onion-Identität bewusst neu initialisieren:

```bash
cargo run -p nyx-mailbox-server -- --reinitialize-onion-identity
```

Der Schalter verschiebt den bisherigen `arti-state` in ein datiertes
`arti-state.backup-*`-Verzeichnis und erzeugt eine neue Onion-Adresse. Die
`mailbox.sqlite3` mit wartenden Nachrichten bleibt erhalten. Anschließend
müssen `NYX_MAILBOX_EXPECTED_ONION` und alle Clients auf die im Serverlog
ausgegebene neue Adresse aktualisiert werden.

Beim Start bootstrapt Arti Tor und lädt die persistente Onion-Identität. Der
Server verweigert den Start, wenn die erzeugte Adresse nicht mit
`NYX_MAILBOX_EXPECTED_ONION` übereinstimmt. Das verhindert einen unbemerkten
Identitätswechsel.

### Datenhaltung und Grenzen

Standardmäßig liegen die Daten unter `nyx-mailbox-data/`:

```text
nyx-mailbox-data/
├── mailbox.sqlite3
├── arti-state/       persistente Onion-Identität
└── arti-cache/       Tor-Cache
```

Aktuelle Schutzgrenzen:

- maximal 1 MiB pro Protokollframe;
- maximal 128 Elemente pro Abruf oder Quittierung;
- maximal 1.024 gespeicherte Nachrichten je Mailbox-Token;
- sieben Tage Aufbewahrung;
- 30 Sekunden Stream-Timeout;
- gebundene Antwortgrößen.

Die SQLite-Seiten des Servers sind nicht zusätzlich verschlüsselt. Der
Nachrichtenkörper soll bereits MLS-Ciphertext sein, aber Token, Größen und
Zeitpunkte bleiben bei Datenbankzugriff sichtbar.

### Onion-Identität sichern

`arti-state/` enthält die langlebige Onion-Service-Identität. Verlust erzeugt
eine neue Onion-Adresse; Diebstahl kann die Dienstidentität kompromittieren.
Das Verzeichnis muss mit restriktiven Dateirechten, Datenträgerverschlüsselung
und einem getesteten Backup geschützt werden.

### Live-Tor-Smoke-Test

Bei laufendem Server:

```bash
cargo run -p nyx-mailbox-smoke -- <v3-adresse.onion>
```

Der Test erzeugt einen zufälligen Token und synthetischen Ciphertext, prüft
Ablage, byteidentischen Abruf, Quittierung und Löschung. Er verwendet keine
echten Nachrichteninhalte. Der Test ist manuell und derzeit nicht Teil der CI.

## Konfiguration

| Variable | Standard/Zweck |
|---|---|
| `NYX_MAILBOX_ONION` | v3-Onion-Adresse der ausgewählten Mailbox |
| `NYX_MAILBOX_EXPECTED_ONION` | vom Server erwartete eigene Onion-Adresse |
| `NYX_MAILBOX_PORT` | virtueller Onion-Port, Standard `443` |
| `NYX_LOCAL_MAILBOX_TOKEN_HEX` | eigener 32-Byte-Empfangstoken als 64 Hexzeichen |
| `NYX_RECIPIENT_MAILBOX_TOKEN_HEX` | Empfängertoken als 64 Hexzeichen |
| `NYX_MAILBOX_DATA_DIR` | Serverdaten, Standard `nyx-mailbox-data` |
| `NYX_MAILBOX_ARTI_STATE_DIR` | persistenter Arti-Zustand und Onion-Identität |
| `NYX_MAILBOX_ARTI_CACHE_DIR` | Arti-Cache |
| `NYX_MAILBOX_REINITIALIZE_ONION_IDENTITY` | `1`/`true`: Onion-Identität beim nächsten Serverstart sichern und neu erzeugen |
| `NYX_DESKTOP_STATE_PATH` | verschlüsselter MLS-Zustand |
| `NYX_DEVICE_IDENTITY_PATH` | verschlüsselte Geräteidentität |
| `NYX_DELIVERY_QUEUE_PATH` | lokale SQLite-Ciphertext-Warteschlange |
| `NYX_VAULT_LOCK_TIMEOUT_SECS` | Inaktivität bis zur Sperre, 30–86.400 Sekunden |
| `RUST_LOG` | optionale Rust-Protokollfilterung ohne Geheimdaten |

Beispiel für lokale Entwicklung:

```dotenv
NYX_MAILBOX_ONION=<v3-adresse.onion>
NYX_MAILBOX_PORT=443
NYX_LOCAL_MAILBOX_TOKEN_HEX=<64-zufällige-hexzeichen>
NYX_RECIPIENT_MAILBOX_TOKEN_HEX=<andere-64-zufällige-hexzeichen>
NYX_VAULT_LOCK_TIMEOUT_SECS=300
# Die Meshtastic-Node-ID wird im verifizierten Kontakt gespeichert.
```

Token niemals zwischen Sende- und Empfangsrichtung wiederverwenden oder in
Logs, Screenshots und öffentliche Konfigurationsdateien aufnehmen.

## Dateien und Datensicherung

Standarddateien des Clients:

| Datei | Inhalt | Schutz |
|---|---|---|
| `nyx-device-identity.nyx` | Geräteschlüssel, Kontakte, KeyPackage, Fähigkeiten | Argon2id + XChaCha20-Poly1305 |
| `nyx-desktop-state.nyx` | OpenMLS-Providerzustand und Ratchets | Argon2id + XChaCha20-Poly1305 |
| `nyx-delivery.sqlite3` | ausstehende Ciphertexte und Zustellversuche | nicht zusätzlich verschlüsselt; keine MLS-Schlüssel |

Vault-Dateien werden atomar ersetzt. Unter Unix erhalten temporäre Dateien den
Modus `0600`. Abgeleitete Schlüssel und geladener Klartext werden nach
Möglichkeit zeroisiert.

Für ein konsistentes Backup sollte Nyx beendet sein. Identitäts- und
MLS-Zustandsdatei gehören zusammen und müssen zusammen mit dem Passwort
verfügbar sein. Eine offiziell getestete Wiederherstellungs- oder
Migrationsprozedur existiert noch nicht.

## Fehlerbehebung

### Tor verbindet nicht

- Systemzeit und Internetverbindung prüfen.
- Sicherstellen, dass die Adresse eine gültige v3-`.onion`-Adresse ist.
- Arti-State- und Cacheverzeichnisse müssen beschreibbar sein.
- Firewalls oder restriktive Netze können den Bootstrap verzögern.
- Nyx weicht bei Tor-Fehlern nicht auf Clearnet aus.

### Mailbox ist nicht erreichbar

- Prüfen, ob der Onion-Service läuft und Port `443` veröffentlicht.
- `NYX_MAILBOX_ONION` und `NYX_MAILBOX_EXPECTED_ONION` nicht verwechseln.
- Bei einer absichtlichen Onion-Schlüsselrotation müssen Server und alle Clients
  gemeinsam neu konfiguriert werden.

### Anmeldung schlägt fehl

- Den richtigen Pfad zu Identitäts- und MLS-Datei prüfen.
- Das Vault-Passwort kann nicht zentral zurückgesetzt werden.
- Keine einzelne Zustandsdatei aus einem anderen Backupstand einspielen.

### Kontakt kann keine Nachrichten senden

- Fingerabdruck muss verifiziert sein.
- Die MLS-Sitzung muss nach Einladung und Welcome aktiv sein.
- Richtungsgebundene Mailbox-Token müssen stimmen.
- Tor- und Mailboxstatus sowie die lokale Warteschlange prüfen.

### Desktop findet keinen seriellen Meshtastic-Port

- Datenfähiges USB-Kabel verwenden.
- Meshtastic-Gerät und seriellen Treiber prüfen.
- Port manuell eintragen.
- Unter Linux Gruppenrechte oder udev-Regeln prüfen.
- Andere Programme schließen, die den Port geöffnet halten.

### Android findet keine Meshtastic-Geräte

- Bluetooth, „Geräte in der Nähe“ und Standortberechtigung erlauben.
- Auf Samsung gegebenenfalls auch den systemweiten Standort einschalten.
- Die Android-Bluetooth-Einstellungen schließen, bevor Nyx scannt.
- Mindestens zehn Sekunden warten und nicht wiederholt schnell scannen.
- Sicherstellen, dass kein anderer Meshtastic-Client verbunden ist.
- Funkgerät neu starten und erneut nach Namen wie `Meshtastic_38c4` suchen.

### Android-App stürzt beim Start ab

Die Universal-APK muss `libssl.so` und `libcrypto.so` für die Gerätearchitektur
enthalten. APKs ausschließlich mit `scripts/build-android.sh` erzeugen. Diagnose:

```bash
adb logcat AndroidRuntime:E libc:F '*:S'
```

### Android-App stürzt beim Scan ab

Aktuelle Builds laden das Kotlin-Bluetooth-Plugin über den Classloader der
Android-Activity. Bei älteren APKs konnte ein JNI-Aufruf aus einem
Rust-Hintergrundthread zu `ClassNotFoundException: com.example.MeshtasticBle`
führen. Eine aktuelle APK installieren und die alte Version ersetzen.

## Entwicklung und Tests

### Qualitätsprüfungen

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
```

Die Tests decken unter anderem ab:

- MLS-Gruppenerstellung, Welcome und Nachrichtenverarbeitung;
- Replay-Ablehnung;
- Export und Wiederherstellung des MLS-Zustands;
- falsche Vault-Passwörter;
- Einladungssignaturen und Manipulationserkennung;
- KeyPackage-Validierung;
- Richtungstrennung der Mailbox-Fähigkeiten;
- idempotente Queue-Übergabe;
- Rollback bei fehlgeschlagenem Safe-Save;
- Mailbox-Lebenszyklus und Quittungsbindung;
- Größen- und Eingabegrenzen;
- Meshtastic-Fragmentgrenzen und stabile Nachrichtenkennung.

Kompilieren und Unit-Tests beweisen weder die Erreichbarkeit eines öffentlichen
Onion-Service noch die Sicherheit des Gesamtsystems. Live-Tor-, Hardware-,
Last-, Fuzz- und Wiederherstellungstests müssen gesondert erfolgen.

### Beitragsregeln für sicherheitskritischen Code

- Keine selbst entworfenen kryptografischen Primitive.
- Keine geheimen Werte in Testausgaben oder Traces.
- Parser und Netzwerkgrenzen strikt begrenzen.
- Fehler auf nicht vertrauenswürdigen Eingaben ohne Panic behandeln.
- Sicherheitsrelevante Dependency-Updates einzeln prüfen.
- Änderungen an Ratchet-Persistenz und Queue-Übergabe mit Crashfällen testen.
- Kein neuer Clearnet-Verbindungspfad im Tor-Modus.

## Bekannte Grenzen

Nyx ist noch kein fertiger Messenger. Insbesondere fehlen:

- vollständige MLS-Gruppenverwaltung;
- Mehrgeräteunterstützung;
- KeyPackage-Rotation und Einladungswiderruf;
- verschlüsselte dauerhafte Chat-Historie;
- Anhänge und Dateien;
- Padding-Buckets, Batching und Cover Traffic;
- rotierende Mailbox-Token;
- exponentielles Retry-Backoff;
- Onion Client Authorization;
- produktionsreife Quoten und Missbrauchsabwehr;
- Datenbankmigrationen;
- Parser-Fuzzing und Lasttests;
- automatisierte Live-Tor-Tests in CI;
- geprüfte Backup-/Restore-Prozeduren;
- unabhängiges Sicherheits- und Log-Redaktionsaudit;
- vollständiger bidirektionaler Meshtastic-Transport.

Der OpenMLS-Snapshot bildet derzeit interne Strukturen des MemoryStorage ab.
Vor Dependency-Upgrades sind explizite Migrationstests erforderlich.

## Roadmap

Die nächsten Meshtastic-Schritte sind:

1. authentifizierte eingehende Fragmentreassemblierung;
2. Ende-zu-Ende-Quittung nach erfolgreicher MLS-Verarbeitung;
3. selektive Wiederholung fehlender Fragmente;
4. persistenter Empfangszustand;
5. verifizierte Bindung zwischen Kontakt und Funk-Node-ID;
6. Android-BLE-Nutzlasttransport;
7. sichere Behandlung von Tor-/Funk-Doppelzustellungen.

Weitere zentrale Schritte sind eine verschlüsselte Chat-Historie, vollständige
MLS-Lebenszyklen, automatisierte Live-Tor-Integrationstests, Fuzzing,
Backup-/Restore-Tests, Dependency-Audits und schließlich ein unabhängiges
Sicherheitsaudit.

## Betriebshinweis und Haftung

Nyx darf im aktuellen Zustand nicht als geprüft sicherer, anonymer oder
produktiver Messenger beworben werden. Betreiber sind für den Schutz der
Onion-Identität, der Serverdaten und der Clientbackups verantwortlich. Benutzer
müssen davon ausgehen, dass Größen-, Zeit-, Zugriffs- und Funkmetadaten sichtbar
bleiben können.

Diese Dokumentation entspricht dem Entwicklungsstand vom **28. August 2026**.
Der verbindliche aktuelle Implementierungsstand steht zusätzlich in
`docs/project-status.md`; Sicherheitsregeln und Bedrohungsmodell stehen in
`SECURITY.md` und `THREAT_MODEL.md`.

# Nyx Threat Model

## Goals

Protect message content and reduce network/application metadata against passive network observers, compromised delivery servers and individual malicious Tor relays.

## In scope

- ISP/local network observation.
- compromised or curious mailbox server.
- passive traffic capture.
- message database theft on the server.
- single-relay observation.
- historical session-key compromise, to the extent provided by MLS forward secrecy.

## Partially mitigated

- traffic correlation and timing analysis.
- global passive adversaries.
- contact discovery via access-pattern analysis.

Mitigations include padding buckets, rotating mailbox tokens, optional cover traffic and delayed/batched polling, but these do not eliminate correlation.

## Out of scope

- compromised endpoint OS.
- keyloggers, screen capture or malicious accessibility tooling.
- unlocked-device physical access.
- malicious chat partner who can copy plaintext after decryption.
- undisclosed vulnerabilities in Tor, cryptographic libraries or operating systems.


### `AGENTS.md` dagegen

Da gehören **keine temporären Probleme** hinein. Sie sollte eher so aussehen:

```markdown
# AGENTS.md

## Project

NYX is a secure decentralized messaging application written in Rust.

## Rules

- Preserve the existing workspace architecture.
- Prefer small, focused changes.
- Do not rewrite working code without a concrete reason.
- Keep UI, application logic and transport implementations separated.
- Transport implementations must not leak into UI components.
- Do not implement custom cryptographic primitives.
- Never log private keys, secrets or message plaintext unnecessarily.

## Rust

After changes run:

cargo fmt
cargo check
cargo test

Prefer:
- explicit error handling
- typed errors
- small modules
- traits at architectural boundaries

Avoid:
- unwrap() in production paths
- unnecessary cloning
- global mutable state
- unnecessary dependencies

## Dioxus

Keep business logic outside Dioxus components wherever possible.

## Meshtastic

Treat Meshtastic as a transport implementation.
Do not couple the application core directly to serial/BLE details.

## Communication

- Always respond to the user in German.
- Code, identifiers, commit messages and technical terms may remain in English where appropriate.

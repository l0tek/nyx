use dioxus::prelude::*;

const CSS: &str = r#"
:root { font-family: Inter, system-ui, sans-serif; background: #0b0f14; color: #e6edf3; }
body { margin: 0; }
.app { min-height: 100vh; display: grid; grid-template-columns: 280px 1fr; }
.sidebar { padding: 24px; border-right: 1px solid #26303a; background: #10161d; }
.main { padding: 32px; }
.status { font-size: 13px; color: #8dd39e; margin-top: 8px; }
.card { border: 1px solid #26303a; border-radius: 12px; padding: 18px; max-width: 760px; }
.warning { color: #f0c674; }
"#;

#[component]
pub fn App() -> Element {
    rsx! {
        style { {CSS} }
        div { class: "app",
            aside { class: "sidebar",
                h1 { "Nyx" }
                div { class: "status", "Tor: not connected (scaffold)" }
                hr {}
                p { "Contacts" }
                p { "Alice" }
                p { "Bob" }
            }
            main { class: "main",
                div { class: "card",
                    h2 { "Security-oriented messenger scaffold" }
                    p { "Dioxus UI is running. Tor and MLS integration are intentionally not enabled yet." }
                    p { class: "warning", "Do not use this scaffold for sensitive communication before implementation, tests and an independent audit." }
                }
            }
        }
    }
}

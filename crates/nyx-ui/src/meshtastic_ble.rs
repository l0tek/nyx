use super::MeshtasticStatus;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dioxus::prelude::*;
use jni::objects::{JClass, JString, JValue};
use std::time::Duration;

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

pub(super) async fn monitor(id: u64, mut state: Signal<MeshtasticStatus>, session: Signal<u64>) {
    while session() == id {
        tokio::time::sleep(Duration::from_millis(500)).await;
        match call_plugin("status", None) {
            Ok(detail) => {
                let connected = detail.starts_with("CONNECTED:");
                let failed = detail.starts_with("ERROR:") || detail == "DISCONNECTED";
                state.set(MeshtasticStatus { connected, detail });
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

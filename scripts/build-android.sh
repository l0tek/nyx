#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
android_project="$workspace_dir/target/dx/nyx-desktop/release/android/app"
openssl_root="${XDG_DATA_HOME:-$HOME/.local/share}/.dx/prebuilt/openssl-1.1.1q-beta-1/ssl/libs"

cd "$workspace_dir"
dx build --android --release --locked --package nyx-desktop --target aarch64-linux-android
dx build --android --release --locked --package nyx-desktop --target x86_64-linux-android

install -d \
    "$android_project/app/src/main/jniLibs/arm64-v8a" \
    "$android_project/app/src/main/jniLibs/x86_64"
install -m 0644 "$openssl_root/android.arm64-v8a/libssl.so" "$android_project/app/src/main/jniLibs/arm64-v8a/libssl.so"
install -m 0644 "$openssl_root/android.arm64-v8a/libcrypto.so" "$android_project/app/src/main/jniLibs/arm64-v8a/libcrypto.so"
install -m 0644 "$openssl_root/android.x86_64/libssl.so" "$android_project/app/src/main/jniLibs/x86_64/libssl.so"
install -m 0644 "$openssl_root/android.x86_64/libcrypto.so" "$android_project/app/src/main/jniLibs/x86_64/libcrypto.so"

cd "$android_project"
./gradlew assembleDebug

output="$workspace_dir/dist/nyx-android-meshtastic-bluetooth-universal-debug.apk"
install -D -m 0644 app/build/outputs/apk/debug/app-debug.apk "$output"
printf 'APK: %s\n' "$output"
sha256sum "$output"

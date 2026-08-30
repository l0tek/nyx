#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn main() {
    use dioxus::desktop::{Config, muda};

    let menu = muda::Menu::new();
    let file_menu = muda::Submenu::new("Datei", true);
    file_menu
        .append_items(&[
            &muda::MenuItem::with_id(nyx_ui::CONFIG_MENU_ID, "Konfiguration", true, None),
            &muda::MenuItem::with_id(nyx_ui::LOG_MENU_ID, "Log anzeigen", true, None),
            &muda::PredefinedMenuItem::separator(),
            &muda::PredefinedMenuItem::quit(Some("Nyx beenden")),
        ])
        .expect("Datei-Menü erstellen");
    let contacts_menu = muda::Submenu::new("Kontakte", true);
    contacts_menu
        .append_items(&[
            &muda::MenuItem::with_id(
                nyx_ui::IMPORT_CONTACT_MENU_ID,
                "Kontakt importieren",
                true,
                None,
            ),
            &muda::MenuItem::with_id(
                nyx_ui::EXPORT_CONTACT_MENU_ID,
                "Kontakt exportieren",
                true,
                None,
            ),
        ])
        .expect("Kontakte-Menü erstellen");
    menu.append_items(&[&file_menu, &contacts_menu])
        .expect("Menüleiste erstellen");

    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_menu(menu))
        .launch(nyx_ui::App);
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn main() {
    dioxus::launch(nyx_ui::App);
}

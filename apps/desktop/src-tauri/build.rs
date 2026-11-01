// The app's own commands (src/lib.rs) are permissions like any plugin's: capabilities/main.json grants them to the
// main window, and no other page can call them.
const COMMANDS: &[&str] = &[
    "session_load",
    "session_save",
    "session_clear",
    "notify_permission",
    "notify_request",
    "notify_show",
    "notify_close",
    "notify_close_all",
    "badge",
    "page_ready",
    "passkey_capability",
    "passkey_create",
    "passkey_prf",
    "passkey_sign_in",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri-build failed");
}

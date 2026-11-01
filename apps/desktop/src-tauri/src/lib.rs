//! The segv.sh desktop app (docs/PROTOCOL.md §11.14): the UI of @segv/ui, built into the app's own package and shown
//! at `tauri://localhost`, with the platform that a web view lacks in native code: the remembered session under a key
//! of the system's key store (session.rs), passkeys of the canonical host (passkey.rs), the system's notifications
//! (notify.rs). The app keeps running with its window closed, with an icon in the menu bar or the system tray, MAY
//! start hidden when the user signs in to the system, tells the page when the system wakes, and opens `segv:` links.

mod notify;
mod passkey;
mod session;
#[cfg(target_os = "macos")]
mod wake;

use tauri::image::Image;
use tauri::menu::{CheckMenuItemBuilder, MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as _};
use tauri_plugin_deep_link::DeepLinkExt as _;

/// The argument that the login item passes: start in the menu bar, without the window.
const HIDDEN: &str = "--hidden";

fn show_main(app: &AppHandle<Wry>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// A `segv:` link (§11.14 "Links"): `segv://open#c/<ref>` opens that conversation, any other one the app.
fn open_link(app: &AppHandle<Wry>, url: &tauri::Url) {
    if url.scheme() != "segv" {
        return;
    }
    let open = url
        .fragment()
        .and_then(|f| f.strip_prefix("c/"))
        .map(notify::open_of)
        .unwrap_or_default();
    notify::open_in_app(app, &open);
}

fn tray(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let login = CheckMenuItemBuilder::with_id("login", "Open at Login")
        .checked(app.autolaunch().is_enabled().unwrap_or(false))
        .build(app)?;
    let menu = MenuBuilder::new(app)
        .item(&MenuItemBuilder::with_id("open", "Open segv.sh").build(app)?)
        .separator()
        .item(&login)
        .separator()
        .item(
            &MenuItemBuilder::with_id("quit", "Quit segv.sh")
                .accelerator("CmdOrCtrl+Q")
                .build(app)?,
        )
        .build()?;
    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .tooltip("segv.sh")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(move |app, e| match e.id().as_ref() {
            "open" => show_main(app),
            "login" => {
                let a = app.autolaunch();
                let on = !a.is_enabled().unwrap_or(false);
                let _ = if on { a.enable() } else { a.disable() };
                let _ = login.set_checked(a.is_enabled().unwrap_or(on));
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

pub fn run() {
    let app = tauri::Builder::default()
        .manage(notify::Opens::default())
        // A second launch (or a link opened on Windows and Linux) goes to the running app.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| show_main(app)))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![HIDDEN]),
        ))
        .invoke_handler(tauri::generate_handler![
            session::session_load,
            session::session_save,
            session::session_clear,
            notify::notify_permission,
            notify::notify_request,
            notify::notify_show,
            notify::notify_close,
            notify::notify_close_all,
            notify::badge,
            notify::page_ready,
            passkey::passkey_capability,
            passkey::passkey_create,
            passkey::passkey_prf,
            passkey::passkey_sign_in,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            notify::init(&handle);
            #[cfg(target_os = "macos")]
            wake::observe(&handle);
            tray(&handle)?;
            let links = handle.clone();
            app.deep_link().on_open_url(move |e| {
                for url in e.urls() {
                    open_link(&links, &url);
                }
            });
            let launched_by = app.deep_link().get_current().ok().flatten().unwrap_or_default();
            if !std::env::args().any(|a| a == HIDDEN) || !launched_by.is_empty() {
                show_main(&handle);
            }
            for url in launched_by {
                open_link(&handle, &url);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the app running in the menu bar, with its realtime socket (§11.14 "Desktop").
            if let WindowEvent::CloseRequested { api, .. } = event
                && window.label() == "main"
            {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("could not start segv.sh");

    app.run(|app, event| {
        // The Dock icon of a running app whose window is closed.
        #[cfg(target_os = "macos")]
        if let RunEvent::Reopen { .. } = event {
            show_main(app);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (app, event);
    });
}

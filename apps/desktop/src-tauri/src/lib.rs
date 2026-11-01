//! The segv.sh desktop app (docs/PROTOCOL.md §11.14) for macOS and Windows: the UI of @segv/ui, built into the app's
//! own package and shown at `tauri://localhost` (`https://tauri.localhost` on Windows), with the platform that a web
//! view lacks in native code: the remembered session under a key of the system's key store (session.rs), passkeys of
//! the canonical host (passkey.rs), the system's notifications and the app's badge (notify.rs, badge.rs). The app
//! keeps running with its window closed, with an icon in the menu bar or the system tray, MAY start hidden when the
//! user signs in to the system, tells the page when the system wakes (wake.rs), and opens `segv:` links.

#[cfg(any(windows, test))]
mod badge;
mod notify;
mod passkey;
mod session;
mod wake;

use tauri::image::Image;
use tauri::menu::{CheckMenuItemBuilder, MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
#[cfg(not(target_os = "macos"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{AppHandle, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as _};
use tauri_plugin_deep_link::DeepLinkExt as _;

/// The argument that the login item passes: start in the menu bar, without the window.
const HIDDEN: &str = "--hidden";

/// The app's AppUserModelID on Windows: its bundle identifier, which Tauri's installer gives the Start menu shortcut.
/// The process takes it too, so that its taskbar button, its badge and its notifications belong to that shortcut.
#[cfg(windows)]
pub(crate) const AUMID: &str = "sh.segv.desktop";

fn show_main(app: &AppHandle<Wry>) {
    notify::show_window(app);
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
    let login = CheckMenuItemBuilder::with_id(
        "login",
        if cfg!(windows) {
            "Start with Windows"
        } else {
            "Open at Login"
        },
    )
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
    let tray = TrayIconBuilder::with_id("main")
        .tooltip("segv.sh")
        .menu(&menu)
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
        });
    // The menu bar's icon is a template that the system tints, and a click opens the menu.
    #[cfg(target_os = "macos")]
    let tray = tray
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .show_menu_on_left_click(true);
    // The system tray's icon is the app's, a click opens the window and a right click the menu.
    #[cfg(not(target_os = "macos"))]
    let tray = tray
        .icon(Image::from_bytes(include_bytes!("../icons/32x32.png"))?)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = e
            {
                show_main(tray.app_handle());
            }
        });
    tray.build(app)?;
    Ok(())
}

/// The main window on Windows, which tauri.windows.conf.json leaves to this function: Mica behind the page on Windows 11,
/// and an opaque window before it, where a transparent one would show the desktop through the page. The script tells
/// the page which, in a global that it reads before anything else (chrome.ts): it runs before the document is parsed,
/// when the document may not have its root element yet.
#[cfg(windows)]
fn main_window(app: &AppHandle<Wry>) -> tauri::Result<()> {
    use tauri::utils::config::WindowEffectsConfig;
    use tauri::window::Effect;
    let Some(conf) = app.config().app.windows.iter().find(|w| w.label == "main").cloned() else {
        return Ok(());
    };
    let mica = windows_version::OsVersion::current().build >= 22000;
    let backdrop = if mica { "mica" } else { "none" };
    let mut window = tauri::WebviewWindowBuilder::from_config(app, &conf)?
        .initialization_script(format!(
            "Object.defineProperty(window,\"__SEGV_WINDOW__\",{{value:Object.freeze({{os:\"windows\",backdrop:\"{backdrop}\"}})}});"
        ))
        .transparent(mica);
    if mica {
        window = window.effects(WindowEffectsConfig {
            effects: vec![Effect::Mica],
            ..Default::default()
        });
    }
    window.build()?;
    Ok(())
}

pub fn run() {
    // Before any window: the taskbar groups the app's windows under the AppUserModelID that they start with.
    #[cfg(windows)]
    let _ = unsafe {
        windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID(&windows::core::HSTRING::from(AUMID))
    };
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
            #[cfg(windows)]
            main_window(&handle)?;
            session::prepare();
            notify::init(&handle);
            wake::observe(&handle);
            tray(&handle)?;
            // The installer registers the scheme on Windows; a development build registers itself.
            #[cfg(all(windows, debug_assertions))]
            let _ = app.deep_link().register_all();
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
        if let tauri::RunEvent::Reopen { .. } = event {
            show_main(app);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (app, event);
    });
}

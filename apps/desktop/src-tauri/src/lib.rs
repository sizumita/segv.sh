//! The segv.sh desktop app (docs/PROTOCOL.md §11.14) for macOS and Windows: the UI of @segv/ui, built into the app's
//! own package and shown at `tauri://localhost` (`https://tauri.localhost` on Windows), with the platform that a web
//! view lacks in native code: the remembered session under a key of the system's key store (session.rs), passkeys of
//! the canonical host (passkey.rs), the system's notifications and the app's badge (notify.rs, badge.rs). The app
//! keeps running with its window closed, with an icon in the menu bar or the system tray and its page hidden
//! (background.rs), MAY start hidden when the user signs in to the system, keeps the page's timers on schedule while it
//! is hidden (alarm.rs), tells the page when the system wakes or the network changes (wake.rs), opens `segv:` links and
//! sends the page's links to other sites to the browser (links.rs), and a published build updates itself (update.rs).

mod alarm;
mod background;
#[cfg(any(windows, test))]
mod badge;
mod links;
mod notify;
mod passkey;
mod session;
mod update;
mod wake;

use tauri::image::Image;
use tauri::menu::{CheckMenuItemBuilder, MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
#[cfg(not(target_os = "macos"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{AppHandle, Emitter as _, Manager as _, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as _};
use tauri_plugin_deep_link::DeepLinkExt as _;

/// The argument that the login item passes: start in the menu bar, without the window.
const HIDDEN: &str = "--hidden";

/// The app's AppUserModelID on Windows: its bundle identifier (`sh.segv.desktop`, or `sh.segv.desktop.canary` for
/// segv.sh Canary), which Tauri's installer gives the Start menu shortcut. The process takes it too, so that its
/// taskbar button, its badge and its notifications belong to that shortcut.
#[cfg(windows)]
static AUMID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(windows)]
pub(crate) fn aumid() -> &'static str {
    AUMID.get().map_or("sh.segv.desktop", String::as_str)
}

fn show_main(app: &AppHandle<Wry>) {
    notify::show_window(app);
}

/// The scheme of the app's links (§11.14 "Links"): the first of the deep-link plugin's desktop schemes, `segv` for the
/// app of segv.sh and `segv-canary` for segv.sh Canary (scripts/bundle.mjs).
pub(crate) fn link_scheme(app: &AppHandle<Wry>) -> Option<String> {
    let desktop = app.config().plugins.0.get("deep-link")?.get("desktop")?;
    Some(desktop.get("schemes")?.get(0)?.as_str()?.to_owned())
}

/// A link of the app's scheme (§11.14 "Links"): `segv://open#c/<ref>` opens that conversation, any other one the app.
fn open_link(app: &AppHandle<Wry>, url: &tauri::Url) {
    if link_scheme(app).as_deref() != Some(url.scheme()) {
        return;
    }
    let open = url
        .fragment()
        .and_then(|f| f.strip_prefix("c/"))
        .map(notify::open_of)
        .unwrap_or_default();
    notify::open_in_app(app, &open);
}

/// Shows the window and asks the page to open its settings (apps/desktop/src/main.tsx).
fn open_settings(app: &AppHandle<Wry>) {
    show_main(app);
    let _ = app.emit_to("main", "segv:settings", ());
}

/// The app's menu in the menu bar on macOS: the system's default one, with "Check for Updates…" (in a build that has a
/// feed) and "Settings…" (⌘,) under the app's name, where a Mac app has them. On Windows the window has no menu bar;
/// the page opens its settings on Ctrl+, itself.
#[cfg(target_os = "macos")]
fn app_menu(app: &AppHandle<Wry>) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItemKind, PredefinedMenuItem};
    let menu = Menu::default(app)?;
    // About, a separator, then the system's items (Services, Hide, Quit).
    if let Some(MenuItemKind::Submenu(named)) = menu.items()?.into_iter().next() {
        let mut at = 1;
        if let Some(update) = update::menu_item(app)? {
            named.insert(&update, at)?;
            at += 1;
        }
        named.insert(&PredefinedMenuItem::separator(app)?, at)?;
        named.insert(
            &MenuItemBuilder::with_id("settings", "Settings…")
                .accelerator("Cmd+,")
                .build(app)?,
            at + 1,
        )?;
    }
    app.set_menu(menu)?;
    Ok(())
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
    // The product's name: "segv.sh", or "segv.sh Canary" (scripts/bundle.mjs).
    let name = &app.package_info().name;
    let mut menu = MenuBuilder::new(app)
        .item(&MenuItemBuilder::with_id("open", format!("Open {name}")).build(app)?)
        .separator();
    if let Some(update) = update::menu_item(app)? {
        menu = menu.item(&update).separator();
    }
    let menu = menu
        .item(&login)
        .separator()
        .item(
            &MenuItemBuilder::with_id("quit", format!("Quit {name}"))
                .accelerator("CmdOrCtrl+Q")
                .build(app)?,
        )
        .build()?;
    // The events of every menu: the tray's, and the app's on macOS.
    app.on_menu_event(move |app, e| match e.id().as_ref() {
        "open" => show_main(app),
        "settings" => open_settings(app),
        "login" => {
            let a = app.autolaunch();
            let on = !a.is_enabled().unwrap_or(false);
            let _ = if on { a.enable() } else { a.disable() };
            let _ = login.set_checked(a.is_enabled().unwrap_or(on));
        }
        "update" => update::clicked(app),
        "quit" => update::quit(app),
        _ => {}
    });
    let tray = TrayIconBuilder::with_id("main").tooltip(name).menu(&menu);
    // The menu bar's icon is a template that the system tints, and a click opens the menu.
    #[cfg(target_os = "macos")]
    let tray = tray
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .show_menu_on_left_click(true);
    // The system tray's icon is the app's (the one of its executable on Windows, segv.sh Canary's for that app), a click
    // opens the window and a right click the menu.
    #[cfg(not(target_os = "macos"))]
    let tray = tray
        .icon(match app.default_window_icon() {
            Some(icon) => icon.clone(),
            None => Image::from_bytes(include_bytes!("../icons/32x32.png"))?,
        })
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

/// The main window, which tauri.conf.json leaves to this function, so that the page's links to other sites open in
/// the browser (links.rs) rather than nowhere.
///
/// On Windows: Mica behind the page on Windows 11, and an opaque window before it, where a transparent one would show
/// the desktop through the page. The script tells the page which, in a global that it reads before anything else
/// (chrome.ts): it runs before the document is parsed, when the document may not have its root element yet.
fn main_window(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let Some(conf) = app.config().app.windows.iter().find(|w| w.label == "main").cloned() else {
        return Ok(());
    };
    let dev = cfg!(debug_assertions)
        .then(|| app.config().build.dev_url.clone())
        .flatten();
    let window = tauri::WebviewWindowBuilder::from_config(app, &conf)?
        .title(&app.package_info().name)
        .on_new_window(|url, _| {
            links::open(&url);
            tauri::webview::NewWindowResponse::Deny
        })
        .on_navigation(move |url| {
            if links::external(url, dev.as_ref()) {
                links::open(url);
                return false;
            }
            true
        });
    #[cfg(windows)]
    let window = {
        use tauri::utils::config::WindowEffectsConfig;
        use tauri::window::Effect;
        let mica = windows_version::OsVersion::current().build >= 22000;
        let backdrop = if mica { "mica" } else { "none" };
        let mut window = window
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
        window
    };
    window.build()?;
    Ok(())
}

/// Tauri's async runtime with two workers, not one per core: its work is a few commands that wait on the system and
/// the updater's requests, which leave more workers idle with their stacks.
fn async_runtime() {
    if let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        tauri::async_runtime::set(runtime.handle().clone());
        // Runs as long as the app.
        std::mem::forget(runtime);
    }
}

pub fn run() {
    async_runtime();
    let context = tauri::generate_context!();
    // Before any window: the taskbar groups the app's windows under the AppUserModelID that they start with.
    #[cfg(windows)]
    {
        let _ = AUMID.set(context.config().identifier.clone());
        let _ = unsafe {
            windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID(&windows::core::HSTRING::from(aumid()))
        };
    }
    let mut builder = tauri::Builder::default()
        .manage(notify::Opens::default())
        // A second launch (or a link opened on Windows and Linux) goes to the running app.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| show_main(app)))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![HIDDEN]),
        ));
    // The plugin's commands stay out of the page's reach: capabilities/main.json grants none of them.
    let updates = update::configured(context.config());
    if updates {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }
    let app = builder
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
            alarm::alarm,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            main_window(&handle)?;
            session::prepare();
            notify::init(&handle);
            alarm::init(&handle);
            wake::observe(&handle);
            if updates {
                update::init(&handle);
            }
            #[cfg(target_os = "macos")]
            app_menu(&handle)?;
            tray(&handle)?;
            update::start(&handle);
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
            // The restart of an update keeps the window as it was; another launch shows it unless the login item's.
            let hidden = update::relaunched_hidden(&handle).unwrap_or_else(|| std::env::args().any(|a| a == HIDDEN));
            if !hidden || !launched_by.is_empty() {
                show_main(&handle);
            } else if let Some(window) = handle.get_webview_window("main") {
                background::hidden(&window);
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
                if let Some(window) = window.app_handle().get_webview_window("main") {
                    background::hidden(&window);
                }
                update::window_closed(window.app_handle());
            }
        })
        .build(context)
        .expect("could not start segv.sh");

    app.run(|app, event| {
        #[cfg(target_os = "macos")]
        match event {
            // The Dock icon of a running app whose window is closed.
            tauri::RunEvent::Reopen { .. } => show_main(app),
            tauri::RunEvent::Exit => update::exiting(app),
            _ => {}
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (app, event);
    });
}

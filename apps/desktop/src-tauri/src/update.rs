//! Updates of a published app (docs/PROTOCOL.md §11.14 "Updates"). The app reads its channel's feed a minute after
//! launch and every four hours after that, downloads a newer version in the background, and installs it when that
//! interrupts nothing: at once while its window is closed, starting again in the menu bar or the system tray without
//! the window; otherwise when the window is next closed, when the app quits, or when the user picks "Restart to
//! Update" in the tray's menu. Before anything is installed, the updater plugin checks the package's signature against
//! the channel's key, that the signature is for the version that the feed names, and that this version is newer than
//! the running one (scripts/bundle.mjs). Only builds made with SEGV_UPDATES=1 have a feed; any other build never looks.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tauri::menu::MenuItem;
use tauri::{AppHandle, Config, Manager, Wry};
use tauri_plugin_updater::{Update, UpdaterExt as _};

/// The first look, after launch: the page and its realtime socket come first.
const FIRST: Duration = Duration::from_secs(60);
/// How long after a look the app looks again, by the wall clock, which also runs while the system sleeps.
const EVERY: Duration = Duration::from_secs(4 * 60 * 60);
/// How often the app compares the clock with its last look.
const TICK: Duration = Duration::from_secs(10 * 60);
/// How long the menu says that a look that the user asked for found nothing, or that something failed.
const SAY: Duration = Duration::from_secs(60);
/// The longest that an update's request and download may take.
const TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// The file that tells the next launch, if it comes within `RELAUNCH_FOR`, whether to show the window: the restart of
/// an update keeps the window as it was, whatever the arguments of the first launch said.
const RELAUNCH: &str = "relaunch";
const RELAUNCH_FOR: Duration = Duration::from_secs(10 * 60);

const CHECK: &str = "Check for Updates…";

enum Phase {
    Idle,
    /// Looking at the feed, or downloading.
    Busy,
    /// Downloaded and verified, waiting to be installed.
    Ready(Box<(Update, Vec<u8>)>),
    Installing,
}

/// What follows an install.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    /// The app starts again in the menu bar or the system tray, without its window.
    Hidden,
    /// The app starts again with its window.
    Shown,
    /// The app quits.
    Quit,
}

pub struct Updates {
    phase: Mutex<Phase>,
    last: Mutex<Option<SystemTime>>,
    item: Mutex<Option<MenuItem<Wry>>>,
}

impl Updates {
    fn set(&self, phase: Phase) {
        if let Ok(mut p) = self.phase.lock() {
            *p = phase;
        }
    }

    /// Idle becomes Busy; false if the app was not idle.
    fn begin(&self) -> bool {
        let Ok(mut p) = self.phase.lock() else {
            return false;
        };
        if !matches!(*p, Phase::Idle) {
            return false;
        }
        *p = Phase::Busy;
        true
    }

    /// The downloaded update, which is being installed from now on.
    fn take_ready(&self) -> Option<(Update, Vec<u8>)> {
        let mut p = self.phase.lock().ok()?;
        if !matches!(*p, Phase::Ready(_)) {
            return None;
        }
        match std::mem::replace(&mut *p, Phase::Installing) {
            Phase::Ready(ready) => Some(*ready),
            _ => None,
        }
    }

    fn ready(&self) -> bool {
        self.phase.lock().is_ok_and(|p| matches!(*p, Phase::Ready(_)))
    }

    fn label(&self, text: &str, enabled: bool) {
        if let Ok(item) = self.item.lock()
            && let Some(item) = item.as_ref()
        {
            let _ = item.set_text(text);
            let _ = item.set_enabled(enabled);
        }
    }

    /// Says `text` in the menu for a minute, then offers to look again if nothing else happened meanwhile.
    fn say(&self, app: &AppHandle<Wry>, text: &str) {
        self.label(text, false);
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(SAY);
            let updates = app.state::<Updates>();
            if updates.phase.lock().is_ok_and(|p| matches!(*p, Phase::Idle)) {
                updates.label(CHECK, true);
            }
        });
    }
}

/// Whether this build has a feed (scripts/bundle.mjs, SEGV_UPDATES).
pub fn configured(config: &Config) -> bool {
    config
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("endpoints"))
        .and_then(|e| e.as_array())
        .is_some_and(|e| !e.is_empty())
}

/// Called once at launch, before the tray is made, in a build that has a feed.
pub fn init(app: &AppHandle<Wry>) {
    app.manage(Updates {
        phase: Mutex::new(Phase::Idle),
        last: Mutex::new(None),
        item: Mutex::new(None),
    });
}

/// The tray's menu item of the updates, in a build that has a feed.
pub fn menu_item(app: &AppHandle<Wry>) -> tauri::Result<Option<MenuItem<Wry>>> {
    let Some(updates) = app.try_state::<Updates>() else {
        return Ok(None);
    };
    let item = MenuItem::with_id(app, "update", CHECK, true, None::<&str>)?;
    if let Ok(mut i) = updates.item.lock() {
        *i = Some(item.clone());
    }
    Ok(Some(item))
}

/// Looks at the feed after `FIRST`, then whenever `EVERY` has passed since the last look.
pub fn start(app: &AppHandle<Wry>) {
    if app.try_state::<Updates>().is_none() {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(FIRST);
        loop {
            // A clock set back counts as due.
            let due = app
                .state::<Updates>()
                .last
                .lock()
                .is_ok_and(|last| last.is_none_or(|t| !t.elapsed().is_ok_and(|e| e < EVERY)));
            if due {
                tauri::async_runtime::spawn(check(app.clone(), false));
            }
            std::thread::sleep(TICK);
        }
    });
}

/// The menu item: installs the downloaded update now, or looks for one.
pub fn clicked(app: &AppHandle<Wry>) {
    let Some(updates) = app.try_state::<Updates>() else {
        return;
    };
    if updates.ready() {
        apply(app, if window_shown(app) { After::Shown } else { After::Hidden });
    } else {
        tauri::async_runtime::spawn(check(app.clone(), true));
    }
}

/// The window was closed: a downloaded update is installed now.
pub fn window_closed(app: &AppHandle<Wry>) {
    if app.try_state::<Updates>().is_some_and(|u| u.ready()) {
        apply(app, After::Hidden);
    }
}

/// The user quits from the tray's menu. On Windows a downloaded update is installed first, without a restart: the
/// installer runs as the app exits. On macOS the app's exit installs it (`exiting`), whichever way the app quits.
pub fn quit(app: &AppHandle<Wry>) {
    #[cfg(windows)]
    if app.try_state::<Updates>().is_some_and(|u| u.ready()) {
        apply(app, After::Quit);
    }
    app.exit(0);
}

/// The app exits (RunEvent::Exit). On macOS a downloaded update is installed, without a restart: the new version
/// starts at the next launch. An exit that an install's restart asked for finds nothing ready.
#[cfg(target_os = "macos")]
pub fn exiting(app: &AppHandle<Wry>) {
    if app.try_state::<Updates>().is_some_and(|u| u.ready()) {
        apply(app, After::Quit);
    }
}

/// Whether to start without the window, if the restart of an update says so: `Some(true)` for hidden, `Some(false)`
/// for shown. The file is removed either way.
pub fn relaunched_hidden(app: &AppHandle<Wry>) -> Option<bool> {
    let path = relaunch_path(app)?;
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < RELAUNCH_FOR);
    let hidden = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    fresh.then(|| hidden.trim() == "hidden")
}

fn relaunch_path(app: &AppHandle<Wry>) -> Option<PathBuf> {
    Some(app.path().app_local_data_dir().ok()?.join(RELAUNCH))
}

fn mark_relaunch(app: &AppHandle<Wry>, after: After) {
    let Some(path) = relaunch_path(app) else {
        return;
    };
    let text = match after {
        After::Hidden => "hidden",
        After::Shown => "shown",
        After::Quit => return,
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, text);
}

fn clear_relaunch(app: &AppHandle<Wry>) {
    if let Some(path) = relaunch_path(app) {
        let _ = std::fs::remove_file(path);
    }
}

fn window_shown(app: &AppHandle<Wry>) -> bool {
    app.get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false)
}

/// Looks at the feed and downloads a newer version; installs it at once while the window is closed.
async fn check(app: AppHandle<Wry>, asked: bool) {
    let updates = app.state::<Updates>();
    if !updates.begin() {
        return;
    }
    if let Ok(mut last) = updates.last.lock() {
        *last = Some(SystemTime::now());
    }
    updates.label("Checking for Updates…", false);
    match fetch(&app, &updates).await {
        Ok(Some(ready)) => {
            updates.label(&format!("Restart to Update ({})", ready.0.version), true);
            updates.set(Phase::Ready(Box::new(ready)));
            if !window_shown(&app) {
                apply(&app, After::Hidden);
            }
        }
        Ok(None) => {
            updates.set(Phase::Idle);
            if asked {
                updates.say(&app, &format!("{} Is Up to Date", app.package_info().name));
            } else {
                updates.label(CHECK, true);
            }
        }
        Err(e) => {
            eprintln!("segv: could not update: {e}");
            updates.set(Phase::Idle);
            if asked {
                updates.say(&app, "Could Not Check for Updates");
            } else {
                updates.label(CHECK, true);
            }
        }
    }
}

/// A newer version than this one, downloaded and verified, if the feed names one.
async fn fetch(app: &AppHandle<Wry>, updates: &Updates) -> tauri_plugin_updater::Result<Option<(Update, Vec<u8>)>> {
    let builder = app.updater_builder().timeout(TIMEOUT);
    // The installer runs as the app exits: the tray's icon and the single-instance lock go first.
    #[cfg(windows)]
    let builder = {
        let app = app.clone();
        builder.on_before_exit(move || app.cleanup_before_exit())
    };
    let Some(update) = builder.build()?.check().await? else {
        return Ok(None);
    };
    updates.label("Downloading Update…", false);
    let bytes = update.download(|_, _| {}, || {}).await?;
    Ok(Some((update, bytes)))
}

/// Installs the downloaded update, then restarts or lets the app quit.
fn apply(app: &AppHandle<Wry>, after: After) {
    // Where the user cannot replace the app themselves (an app that an administrator installed, or one that runs from
    // its disk image), installing asks for an administrator's password: only the user's own click may do that.
    #[cfg(target_os = "macos")]
    if after != After::Shown && !replaceable() {
        return;
    }
    let updates = app.state::<Updates>();
    let Some((update, bytes)) = updates.take_ready() else {
        return;
    };
    updates.label("Installing Update…", false);
    let handle = app.clone();
    let run = move || {
        if let Err(e) = install(&handle, &update, &bytes, after) {
            eprintln!("segv: could not install the update: {e}");
            clear_relaunch(&handle);
            let updates = handle.state::<Updates>();
            updates.set(Phase::Idle);
            updates.say(&handle, "Could Not Install the Update");
        }
    };
    // On macOS, the package is unpacked off the main thread, except as the app exits, which must wait for it.
    #[cfg(target_os = "macos")]
    if after == After::Quit {
        run();
    } else {
        std::thread::spawn(run);
    }
    // On Windows, the installer starts from the main thread, which removes the tray's icon before the app exits.
    #[cfg(windows)]
    {
        let _ = app.run_on_main_thread(run);
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    run();
}

/// macOS replaces the app's bundle and restarts it; Windows runs the installer, which replaces the app after this
/// process has exited and starts it again unless the app was quitting. `install` only returns on a failure there.
fn install(app: &AppHandle<Wry>, update: &Update, bytes: &[u8], after: After) -> Result<(), String> {
    mark_relaunch(app, after);
    #[cfg(windows)]
    let update = &update.clone().restart_after_install(after != After::Quit);
    update.install(bytes).map_err(|e| e.to_string())?;
    if after != After::Quit {
        app.request_restart();
    }
    Ok(())
}

/// Whether this user may replace the app's bundle: write access to it and to the folder that holds it.
#[cfg(target_os = "macos")]
fn replaceable() -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(exe) = tauri::utils::platform::current_exe() else {
        return false;
    };
    // <name>.app/Contents/MacOS/<binary>
    let Some(bundle) = exe.ancestors().nth(3) else {
        return false;
    };
    if bundle.extension().is_none_or(|e| e != "app") {
        return false;
    }
    let writable = |p: &std::path::Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0)
    };
    writable(bundle) && bundle.parent().is_some_and(writable)
}

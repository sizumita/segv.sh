//! The system's notifications of an app without push (docs/PROTOCOL.md §11.13 "Apps without push", "Presentation"):
//! the engine decides what each one says and when (packages/engine/src/local-notify.ts); this module shows it, groups
//! a conversation's notifications under its `ref`, removes them once the conversation is read, and opens the
//! conversation when one is clicked. A notification's identifier is its tag, so a newer one replaces the older, and a
//! click finds what to open from the identifier alone: nothing else is handed to the system.

use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use tauri::{AppHandle, Emitter, Manager, Runtime, State, Wry};

/// One notification, as the engine's LocalNotification.
#[derive(Deserialize)]
pub struct Note {
    tag: String,
    title: String,
    body: String,
}

/// The tag of the fixed notification (`segv`), which opens the start page.
const FIXED_TAG: &str = "segv";

/// A tag the engine makes: the fixed one, or a conversation's ref (12 base64url characters).
fn valid_tag(tag: &str) -> bool {
    tag == FIXED_TAG || (tag.len() == 12 && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// What a click on a notification of `tag` opens: its conversation's URL fragment, or the start page.
pub fn open_of(tag: &str) -> String {
    if tag == FIXED_TAG || !valid_tag(tag) {
        String::new()
    } else {
        format!("#c/{tag}")
    }
}

static APP: OnceLock<AppHandle<Wry>> = OnceLock::new();

/// What the page is asked to open before it listens: a link or a notification click that launched the app arrives
/// before the page has loaded, so the newest one waits here until the page says that it is ready (`page_ready`).
#[derive(Default)]
pub struct Opens {
    ready: AtomicBool,
    pending: Mutex<Option<String>>,
}

/// The app's badge as the page last set it: Windows forgets a taskbar button's overlay while the window is hidden,
/// so it is set again whenever the window shows.
#[cfg(windows)]
static BADGE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Shows the main window, in front.
pub fn show_window<R: Runtime>(app: &AppHandle<R>) {
    let Some(w) = app.get_webview_window("main") else {
        return;
    };
    let _ = w.unminimize();
    let _ = w.show();
    let _ = w.set_focus();
    #[cfg(windows)]
    {
        let overlay = |w: &tauri::WebviewWindow<R>| {
            let _ = w.set_overlay_icon(crate::badge::overlay(BADGE.load(Ordering::SeqCst)));
        };
        overlay(&w);
        // The taskbar makes the window's button a moment after the window shows, and ignores an overlay before it.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            overlay(&w);
        });
    }
}

/// Shows the main window and asks the page to open `open` (a conversation's fragment, or "" for the start page).
pub fn open_in_app<R: Runtime>(app: &AppHandle<R>, open: &str) {
    show_window(app);
    let opens = app.state::<Opens>();
    if opens.ready.load(Ordering::SeqCst) {
        let _ = app.emit_to("main", "segv:open", open.to_string());
    } else if let Ok(mut p) = opens.pending.lock() {
        *p = Some(open.to_string());
    }
}

/// The page listens for `segv:open` from now on; it gets what was asked of it before, if anything.
#[tauri::command]
pub fn page_ready(opens: State<'_, Opens>) -> Option<String> {
    let mut p = opens.pending.lock().ok()?;
    opens.ready.store(true, Ordering::SeqCst);
    p.take()
}

/// Called once at launch, before the system can deliver a click that launched the app.
pub fn init(app: &AppHandle<Wry>) {
    let _ = APP.set(app.clone());
    imp::init();
}

#[tauri::command]
pub async fn notify_permission() -> Result<String, String> {
    imp::permission().await
}

#[tauri::command]
pub async fn notify_request() -> Result<String, String> {
    imp::request().await
}

#[tauri::command]
pub fn notify_show(n: Note) -> Result<(), String> {
    if !valid_tag(&n.tag) {
        return Err("invalid tag".into());
    }
    imp::show(&n);
    Ok(())
}

#[tauri::command]
pub fn notify_close(tag: String) -> Result<(), String> {
    if valid_tag(&tag) {
        imp::close(&tag);
    }
    Ok(())
}

#[tauri::command]
pub fn notify_close_all() {
    imp::close_all();
}

/// The app's badge (§11.13): the Dock tile's label on macOS, the taskbar button's overlay on Windows.
#[tauri::command]
pub fn badge<R: Runtime>(app: AppHandle<R>, count: u32) -> Result<(), String> {
    #[cfg(windows)]
    BADGE.store(count, Ordering::SeqCst);
    let Some(w) = app.get_webview_window("main") else {
        return Ok(());
    };
    #[cfg(windows)]
    let set = w.set_overlay_icon(crate::badge::overlay(count));
    #[cfg(not(windows))]
    let set = w.set_badge_count(if count > 0 { Some(i64::from(count)) } else { None });
    set.map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{APP, Note, open_in_app, open_of};
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject};
    use objc2::{AnyThread, define_class, msg_send};
    use objc2_foundation::{NSArray, NSBundle, NSError, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent, UNNotification,
        UNNotificationPresentationOptions, UNNotificationRequest, UNNotificationResponse, UNNotificationSettings,
        UNNotificationSound, UNUserNotificationCenter, UNUserNotificationCenterDelegate,
    };
    use std::ptr::NonNull;
    use std::sync::mpsc;

    define_class!(
        /// Shows notifications while the app is in front too (the engine has already decided that this device is not
        /// in use), and turns a click into opening the conversation.
        #[unsafe(super(NSObject))]
        #[name = "SegvNotificationDelegate"]
        struct Delegate;

        unsafe impl NSObjectProtocol for Delegate {}

        unsafe impl UNUserNotificationCenterDelegate for Delegate {
            #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
            fn will_present(
                &self,
                _center: &UNUserNotificationCenter,
                _notification: &UNNotification,
                handler: &block2::DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
            ) {
                handler.call((UNNotificationPresentationOptions::Banner
                    | UNNotificationPresentationOptions::List
                    | UNNotificationPresentationOptions::Sound,));
            }

            #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
            fn did_receive(
                &self,
                _center: &UNUserNotificationCenter,
                response: &UNNotificationResponse,
                handler: &block2::DynBlock<dyn Fn()>,
            ) {
                let tag = response.notification().request().identifier().to_string();
                if let Some(app) = APP.get() {
                    open_in_app(app, &open_of(&tag));
                }
                handler.call(());
            }
        }
    );

    impl Delegate {
        fn new() -> Retained<Self> {
            let this = Self::alloc().set_ivars(());
            unsafe { msg_send![super(this), init] }
        }
    }

    /// The notification center exists only for an app bundle: a development binary run outside one has none.
    fn center() -> Option<Retained<UNUserNotificationCenter>> {
        let bundled = NSBundle::mainBundle().bundlePath().to_string().ends_with(".app");
        bundled.then(UNUserNotificationCenter::currentNotificationCenter)
    }

    pub fn init() {
        let Some(c) = center() else { return };
        let d = Delegate::new();
        c.setDelegate(Some(ProtocolObject::from_ref(&*d)));
        // The center keeps its delegate weakly: this one lives as long as the app.
        std::mem::forget(d);
    }

    fn status(s: UNAuthorizationStatus) -> &'static str {
        match s {
            UNAuthorizationStatus::NotDetermined => "default",
            UNAuthorizationStatus::Denied => "denied",
            _ => "granted",
        }
    }

    pub async fn permission() -> Result<String, String> {
        // The center and the block stay out of the future, which may move to another thread.
        let rx = {
            let Some(c) = center() else {
                return Ok("denied".into());
            };
            let (tx, rx) = mpsc::channel();
            let block = RcBlock::new(move |s: NonNull<UNNotificationSettings>| {
                let _ = tx.send(status(unsafe { s.as_ref() }.authorizationStatus()));
            });
            c.getNotificationSettingsWithCompletionHandler(&block);
            rx
        };
        wait(rx).await
    }

    pub async fn request() -> Result<String, String> {
        let rx = {
            let Some(c) = center() else {
                return Ok("denied".into());
            };
            let (tx, rx) = mpsc::channel();
            let block = RcBlock::new(move |granted: Bool, _err: *mut NSError| {
                let _ = tx.send(if granted.as_bool() { "granted" } else { "denied" });
            });
            c.requestAuthorizationWithOptions_completionHandler(
                UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound | UNAuthorizationOptions::Badge,
                &block,
            );
            rx
        };
        wait(rx).await
    }

    async fn wait(rx: mpsc::Receiver<&'static str>) -> Result<String, String> {
        tauri::async_runtime::spawn_blocking(move || rx.recv())
            .await
            .map_err(|e| e.to_string())?
            .map(str::to_string)
            .map_err(|_| "no answer from the notification center".to_string())
    }

    pub fn show(n: &Note) {
        let Some(c) = center() else { return };
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&n.title));
        content.setBody(&NSString::from_str(&n.body));
        // A conversation's notifications are grouped under its ref (§11.13 "Presentation").
        content.setThreadIdentifier(&NSString::from_str(&n.tag));
        content.setSound(Some(&UNNotificationSound::defaultSound()));
        let request =
            UNNotificationRequest::requestWithIdentifier_content_trigger(&NSString::from_str(&n.tag), &content, None);
        c.addNotificationRequest_withCompletionHandler(&request, None);
    }

    pub fn close(tag: &str) {
        let Some(c) = center() else { return };
        let ids = NSArray::from_retained_slice(&[NSString::from_str(tag)]);
        c.removePendingNotificationRequestsWithIdentifiers(&ids);
        c.removeDeliveredNotificationsWithIdentifiers(&ids);
    }

    pub fn close_all() {
        let Some(c) = center() else { return };
        c.removeAllPendingNotificationRequests();
        c.removeAllDeliveredNotifications();
    }
}

/// Windows: toasts of the app's AppUserModelID (lib.rs), each with its conversation's ref as its tag in one group, so
/// that a newer one replaces the older and a read conversation's can be removed. A click opens the toast's `segv:`
/// link (protocol activation), which reaches the app as any link does (lib.rs), whether or not it still runs: nothing
/// else is handed to the system.
#[cfg(windows)]
mod imp {
    use super::{FIXED_TAG, Note};
    use tauri::Manager;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{NotificationSetting, ToastNotification, ToastNotificationManager, ToastNotifier};
    use windows::core::{HSTRING, Result};

    /// The group of every toast of the app.
    const GROUP: &str = "segv";

    fn aumid() -> HSTRING {
        HSTRING::from(crate::AUMID)
    }

    fn notifier() -> Result<ToastNotifier> {
        ToastNotificationManager::CreateToastNotifierWithId(&aumid())
    }

    /// The COM class that the AppUserModelID names as its activator. Nothing implements it: every toast of the app
    /// activates its `segv:` link instead, and Windows keeps an unpackaged app's toasts in the notification center
    /// only for an AppUserModelID that names an activator.
    const ACTIVATOR: &str = "{2E4D9E66-065F-478E-80DF-E4A3BDEBE88F}";

    /// Registers the AppUserModelID for the user, with the name and the icon that the notification center shows, as
    /// the Windows App SDK does for an unpackaged app. The installer's Start menu shortcut carries the same ID; this
    /// also covers a development build, which has none. The uninstaller removes the key (windows/hooks.nsh).
    pub fn init() {
        let register = || -> windows::core::Result<()> {
            let key =
                windows_registry::CURRENT_USER.create(format!(r"Software\Classes\AppUserModelId\{}", crate::AUMID))?;
            key.set_string("DisplayName", "segv.sh")?;
            key.set_string("CustomActivator", ACTIVATOR)?;
            let icon = super::APP
                .get()
                .and_then(|app| app.path().resource_dir().ok())
                .map(|dir| dir.join("notification.png"))
                .filter(|p| p.is_file());
            if let Some(icon) = icon {
                key.set_string("IconUri", icon.to_string_lossy())?;
            }
            Ok(())
        };
        if let Err(e) = register() {
            eprintln!("segv: could not register for notifications: {e}");
        }
    }

    /// Windows asks no permission: the user turns an app's notifications off in Settings, which the notifier reports.
    fn setting() -> String {
        match notifier().and_then(|n| n.Setting()) {
            Ok(NotificationSetting::Enabled) => "granted",
            _ => "denied",
        }
        .into()
    }

    pub async fn permission() -> std::result::Result<String, String> {
        Ok(setting())
    }

    pub async fn request() -> std::result::Result<String, String> {
        Ok(setting())
    }

    fn escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                // Characters that XML 1.0 does not allow.
                c if ((c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r'))
                    || matches!(c, '\u{fffe}' | '\u{ffff}') => {}
                c => out.push(c),
            }
        }
        out
    }

    fn toast(n: &Note) -> Result<ToastNotification> {
        // The tag has been checked: the fixed one, or 12 base64url characters.
        let link = if n.tag == FIXED_TAG {
            "segv://open".to_string()
        } else {
            format!("segv://open#c/{}", n.tag)
        };
        let xml = format!(
            "<toast activationType=\"protocol\" launch=\"{}\"><visual><binding template=\"ToastGeneric\">\
             <text hint-maxLines=\"1\">{}</text><text>{}</text></binding></visual></toast>",
            escape(&link),
            escape(&n.title),
            escape(&n.body),
        );
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(xml))?;
        let t = ToastNotification::CreateToastNotification(&doc)?;
        t.SetTag(&HSTRING::from(n.tag.as_str()))?;
        t.SetGroup(&HSTRING::from(GROUP))?;
        Ok(t)
    }

    pub fn show(n: &Note) {
        if let Err(e) = toast(n).and_then(|t| notifier()?.Show(&t)) {
            eprintln!("segv: could not show a notification: {e}");
        }
    }

    pub fn close(tag: &str) {
        if let Ok(h) = ToastNotificationManager::History() {
            let _ = h.RemoveGroupedTagWithId(&HSTRING::from(tag), &HSTRING::from(GROUP), &aumid());
        }
    }

    pub fn close_all() {
        if let Ok(h) = ToastNotificationManager::History() {
            let _ = h.ClearWithId(&aumid());
        }
    }
}

/// Linux: not supported yet (the engine then reports the permission as denied).
#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use super::Note;

    pub fn init() {}

    pub async fn permission() -> Result<String, String> {
        Ok("denied".into())
    }

    pub async fn request() -> Result<String, String> {
        Ok("denied".into())
    }

    pub fn show(_n: &Note) {}

    pub fn close(_tag: &str) {}

    pub fn close_all() {}
}

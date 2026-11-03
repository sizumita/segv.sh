//! Tells the page when the system wakes from sleep, or when the network changes (docs/PROTOCOL.md §11.14 "Desktop"):
//! the engine then pings its realtime sockets at once, replaces those that have heard nothing for a while or that do
//! not answer, reconnects a closed one without waiting for its back-off, and catches up, instead of waiting for a ping
//! to go unanswered. A page hears of neither by itself: a hidden web view's page gets no event for a new Wi-Fi network,
//! a VPN that comes up or goes down, or a network that comes back without having been reported as gone.

use tauri::{AppHandle, Emitter, Wry};

fn woke(app: &AppHandle<Wry>) {
    let _ = app.emit_to("main", "segv:wake", ());
}

/// How long the network must stay unchanged before the page is told: a change comes as a burst of notifications
/// (an address goes, another comes, the routes follow), and the page should reconnect once, on the network it ends on.
#[cfg(any(target_os = "macos", windows))]
const SETTLE: std::time::Duration = std::time::Duration::from_secs(2);
/// The least time between two wakes for network changes, so that a network that keeps changing cannot make the page
/// reconnect and catch up over and over.
#[cfg(any(target_os = "macos", windows))]
const MIN_GAP: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(any(target_os = "macos", windows))]
static CHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(any(target_os = "macos", windows))]
static LAST: std::sync::Mutex<Option<tokio::time::Instant>> = std::sync::Mutex::new(None);

/// The network changed: the page is told once it has settled.
#[cfg(any(target_os = "macos", windows))]
fn network_changed(app: &AppHandle<Wry>) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let n = CHANGES.fetch_add(1, Ordering::SeqCst) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SETTLE).await;
        // A later change waits for itself.
        if CHANGES.load(Ordering::SeqCst) != n {
            return;
        }
        let gap = LAST
            .lock()
            .ok()
            .and_then(|l| *l)
            .map_or(Duration::ZERO, |t| MIN_GAP.saturating_sub(t.elapsed()));
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
            if CHANGES.load(Ordering::SeqCst) != n {
                return;
            }
        }
        if let Ok(mut l) = LAST.lock() {
            *l = Some(tokio::time::Instant::now());
        }
        woke(&app);
    });
}

pub fn observe(app: &AppHandle<Wry>) {
    imp::observe(app);
}

#[cfg(target_os = "macos")]
mod imp {
    use block2::RcBlock;
    use objc2_app_kit::{NSWorkspace, NSWorkspaceDidWakeNotification};
    use objc2_foundation::{NSNotification, NSOperationQueue};
    use std::ffi::{c_int, c_void};
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tauri::{AppHandle, Wry};

    // Network.framework's path monitor, whose update handler runs at its start and at every change of the path that
    // connections would take: the interfaces, their addresses and routes, and whether the network is reachable at all.
    #[link(name = "Network", kind = "framework")]
    unsafe extern "C" {
        fn nw_path_monitor_create() -> *mut c_void;
        fn nw_path_monitor_set_update_handler(monitor: *mut c_void, handler: &block2::DynBlock<dyn Fn(*mut c_void)>);
        fn nw_path_monitor_set_queue(monitor: *mut c_void, queue: *mut c_void);
        fn nw_path_monitor_start(monitor: *mut c_void);
        fn nw_path_get_status(path: *mut c_void) -> c_int;
    }

    unsafe extern "C" {
        fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut c_void;
    }

    /// `nw_path_status_satisfied`: the path can reach the network.
    const SATISFIED: c_int = 1;
    /// `QOS_CLASS_UTILITY`.
    const UTILITY: isize = 0x11;

    pub fn observe(app: &AppHandle<Wry>) {
        let wake = app.clone();
        let block = RcBlock::new(move |_n: NonNull<NSNotification>| super::woke(&wake));
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        let token = unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceDidWakeNotification),
                None,
                Some(&NSOperationQueue::mainQueue()),
                &block,
            )
        };
        // Observed for as long as the app runs.
        std::mem::forget(token);

        let app = app.clone();
        let started = AtomicBool::new(false);
        // A path that cannot reach the network is not worth a reconnect: the one that follows it, which can, is.
        let changed = RcBlock::new(move |path: *mut c_void| {
            let first = !started.swap(true, Ordering::SeqCst);
            if !first && unsafe { nw_path_get_status(path) } == SATISFIED {
                super::network_changed(&app);
            }
        });
        unsafe {
            let monitor = nw_path_monitor_create();
            if monitor.is_null() {
                return;
            }
            nw_path_monitor_set_update_handler(monitor, &changed);
            nw_path_monitor_set_queue(monitor, dispatch_get_global_queue(UTILITY, 0));
            nw_path_monitor_start(monitor);
        }
        // The monitor holds a copy of the handler, and both live as long as the app.
        std::mem::forget(changed);
    }
}

/// The system's suspend and resume notifications, and its notifications of changed interfaces and addresses, which
/// call back on threads of the system: no window is needed.
#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use tauri::{AppHandle, Wry};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, MibInitialNotification,
        NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    use windows::Win32::System::Power::{DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification};
    use windows::Win32::UI::WindowsAndMessaging::{DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC};

    static APP: OnceLock<AppHandle<Wry>> = OnceLock::new();

    /// Every resume sends PBT_APMRESUMEAUTOMATIC; PBT_APMRESUMESUSPEND follows only if the user woke the system.
    unsafe extern "system" fn power(_context: *const c_void, kind: u32, _setting: *const c_void) -> u32 {
        if kind == PBT_APMRESUMEAUTOMATIC
            && let Some(app) = APP.get()
        {
            super::woke(app);
        }
        0
    }

    /// An interface connected, disconnected or changed: a Wi-Fi network joined again keeps its address.
    unsafe extern "system" fn interface(
        _context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        kind: MIB_NOTIFICATION_TYPE,
    ) {
        changed(kind);
    }

    /// An address came or went: another network, or a VPN.
    unsafe extern "system" fn address(
        _context: *const c_void,
        _row: *const MIB_UNICASTIPADDRESS_ROW,
        kind: MIB_NOTIFICATION_TYPE,
    ) {
        changed(kind);
    }

    fn changed(kind: MIB_NOTIFICATION_TYPE) {
        if kind != MibInitialNotification
            && let Some(app) = APP.get()
        {
            super::network_changed(app);
        }
    }

    pub fn observe(app: &AppHandle<Wry>) {
        if APP.set(app.clone()).is_err() {
            return;
        }
        // Registered for as long as the app runs, so the parameters live as long.
        let params: &'static mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
            Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
                Callback: Some(power),
                Context: std::ptr::null_mut(),
            }));
        let mut registration = std::ptr::null_mut();
        let _ = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                HANDLE(std::ptr::from_mut(params).cast()),
                &mut registration,
            )
        };
        // Registered for as long as the app runs.
        let mut handle = HANDLE::default();
        let _ = unsafe { NotifyIpInterfaceChange(AF_UNSPEC, Some(interface), None, false, &mut handle) };
        let mut handle = HANDLE::default();
        let _ = unsafe { NotifyUnicastIpAddressChange(AF_UNSPEC, Some(address), None, false, &mut handle) };
    }
}

/// Linux: the engine notices a dead socket by its pings.
#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use tauri::{AppHandle, Wry};

    pub fn observe(_app: &AppHandle<Wry>) {}
}

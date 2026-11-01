//! Tells the page when the system wakes from sleep (docs/PROTOCOL.md §11.14 "Desktop"): the engine then replaces its
//! realtime sockets at once and catches up, instead of waiting for a ping to go unanswered.

use tauri::{AppHandle, Emitter, Wry};

fn woke(app: &AppHandle<Wry>) {
    let _ = app.emit_to("main", "segv:wake", ());
}

pub fn observe(app: &AppHandle<Wry>) {
    imp::observe(app);
}

#[cfg(target_os = "macos")]
mod imp {
    use block2::RcBlock;
    use objc2_app_kit::{NSWorkspace, NSWorkspaceDidWakeNotification};
    use objc2_foundation::{NSNotification, NSOperationQueue};
    use std::ptr::NonNull;
    use tauri::{AppHandle, Wry};

    pub fn observe(app: &AppHandle<Wry>) {
        let app = app.clone();
        let block = RcBlock::new(move |_n: NonNull<NSNotification>| super::woke(&app));
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
    }
}

/// The system's suspend and resume notifications, which call back on a thread of the system: no window is needed.
#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use tauri::{AppHandle, Wry};
    use windows::Win32::Foundation::HANDLE;
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
    }
}

/// Linux: the engine notices a dead socket by its pings.
#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use tauri::{AppHandle, Wry};

    pub fn observe(_app: &AppHandle<Wry>) {}
}

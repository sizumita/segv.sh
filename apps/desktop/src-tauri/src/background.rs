//! The app with its window closed (docs/PROTOCOL.md §11.14 "Desktop"): the page keeps running, with its realtime socket
//! and its notifications, but has nothing to draw. On macOS, WebKit sees that the window is closed and treats the page
//! as hidden by itself. On Windows, WebView2 does not see it: hiding the window leaves its web view "visible", so the
//! web view is hidden with the window, and asked to keep its memory low (WebView2 trims its processes' working sets).
//! Both are undone before the window shows again. The page's scripts run either way: tauri.windows.conf.json keeps
//! WebView2 from throttling a hidden page's timers.

use tauri::{Runtime, WebviewWindow};

/// The window was closed, or the app started without it.
pub fn hidden<R: Runtime>(window: &WebviewWindow<R>) {
    imp::set(window, false);
}

/// The window is about to show.
pub fn shown<R: Runtime>(window: &WebviewWindow<R>) {
    imp::set(window, true);
}

#[cfg(windows)]
mod imp {
    use tauri::{Runtime, WebviewWindow};
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW, COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL, ICoreWebView2_19,
    };
    use windows::core::Interface as _;

    pub fn set<R: Runtime>(window: &WebviewWindow<R>, shown: bool) {
        let _ = window.with_webview(move |webview| {
            let controller = webview.controller();
            let level = if shown {
                COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL
            } else {
                COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW
            };
            unsafe {
                let _ = controller.SetIsVisible(shown);
                // ICoreWebView2_19 needs WebView2 Runtime 114 or later; an older one only hides the web view.
                if let Ok(core) = controller.CoreWebView2().and_then(|c| c.cast::<ICoreWebView2_19>()) {
                    let _ = core.SetMemoryUsageTargetLevel(level);
                }
            }
        });
    }
}

#[cfg(not(windows))]
mod imp {
    use tauri::{Runtime, WebviewWindow};

    pub fn set<R: Runtime>(_window: &WebviewWindow<R>, _shown: bool) {}
}

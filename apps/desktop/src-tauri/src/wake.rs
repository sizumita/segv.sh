//! Tells the page when the system wakes from sleep (docs/PROTOCOL.md §11.14 "Desktop"): the engine then replaces its
//! realtime sockets at once and catches up, instead of waiting for a ping to go unanswered.

use block2::RcBlock;
use objc2_app_kit::{NSWorkspace, NSWorkspaceDidWakeNotification};
use objc2_foundation::{NSNotification, NSOperationQueue};
use std::ptr::NonNull;
use tauri::{AppHandle, Emitter, Wry};

pub fn observe(app: &AppHandle<Wry>) {
    let app = app.clone();
    let block = RcBlock::new(move |_n: NonNull<NSNotification>| {
        let _ = app.emit_to("main", "segv:wake", ());
    });
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

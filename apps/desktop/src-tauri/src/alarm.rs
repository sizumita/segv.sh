//! The page's alarm (apps/desktop/src/clock.ts, docs/PROTOCOL.md §11.14 "Desktop"): while the window is closed, the
//! engine's timers (the realtime socket's pings and reconnects, the catch-up, the notifications) must keep their
//! schedule, which a hidden web view does not promise: WebView2 runs a hidden page's renderer in the background, and
//! either system may run its timers late. So the page also asks for one alarm at its earliest timer, which this module
//! keeps on Tauri's runtime and delivers as the event `segv:alarm`; an event reaches a hidden page on time. Signal
//! Desktop keeps its socket's timers outside Chromium's for the same reason.

use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State, Wry};
use tokio::sync::watch;
use tokio::time::Instant;

/// The latest alarm that the page may ask for: its timers are minutes apart at most.
const MAX_MS: u64 = 3_600_000;

/// The time of the one pending alarm, or none.
pub struct Alarm(watch::Sender<Option<Instant>>);

/// Sets the alarm `ms` from now, replacing the pending one; `None` cancels it.
#[tauri::command]
pub fn alarm(state: State<'_, Alarm>, ms: Option<u64>) {
    state
        .0
        .send_replace(ms.map(|ms| Instant::now() + Duration::from_millis(ms.min(MAX_MS))));
}

pub fn init(app: &AppHandle<Wry>) {
    let (tx, mut rx) = watch::channel(None::<Instant>);
    app.manage(Alarm(tx));
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let Some(at) = *rx.borrow_and_update() else {
                if rx.changed().await.is_err() {
                    return;
                }
                continue;
            };
            match tokio::time::timeout_at(at, rx.changed()).await {
                // The page asked for another alarm, or none.
                Ok(Ok(())) => {}
                Ok(Err(_)) => return,
                Err(_) => {
                    // Cleared only if the page has not asked for another one meanwhile.
                    app.state::<Alarm>().0.send_if_modified(|v| {
                        let due = *v == Some(at);
                        if due {
                            *v = None;
                        }
                        due
                    });
                    let _ = app.emit_to("main", "segv:alarm", ());
                }
            }
        }
    });
}

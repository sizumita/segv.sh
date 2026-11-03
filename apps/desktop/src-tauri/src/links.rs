//! Links of the page that lead out of the app: a message's links (`target="_blank"`, packages/ui/src/msg-text.tsx)
//! open in the system's default browser. The web view would otherwise drop them, since the app makes no windows of its
//! own for them, and the window never loads another page than the app's own (docs/PROTOCOL.md §11.14 "Origin"), so a
//! navigation away from it opens in the browser too.

use tauri::Url;

/// Whether `url` is a page of the app itself: its own origin (`tauri://localhost`, `https://tauri.localhost` on
/// Windows), or the dev server's in a development build.
fn own(url: &Url, dev: Option<&Url>) -> bool {
    match url.scheme() {
        "tauri" => true,
        "http" | "https" => {
            url.host_str() == Some("tauri.localhost") || dev.is_some_and(|d| d.origin() == url.origin())
        }
        _ => false,
    }
}

/// An `http` or `https` URL of another site: one that the browser opens.
pub fn external(url: &Url, dev: Option<&Url>) -> bool {
    matches!(url.scheme(), "http" | "https") && !own(url, dev)
}

/// Opens `url` in the default browser, if it is an `http` or `https` URL; any other is ignored.
pub fn open(url: &Url) {
    if !matches!(url.scheme(), "http" | "https") {
        return;
    }
    imp::open(url.as_str());
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2_app_kit::NSWorkspace;
    use objc2_foundation::{NSString, NSURL};

    pub fn open(url: &str) {
        let Some(u) = NSURL::URLWithString(&NSString::from_str(url)) else {
            return;
        };
        if !NSWorkspace::sharedWorkspace().openURL(&u) {
            eprintln!("segv: could not open a link");
        }
    }
}

#[cfg(windows)]
mod imp {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, w};

    pub fn open(url: &str) {
        // ShellExecute answers a value above 32 when it succeeds.
        let r = unsafe { ShellExecuteW(None, w!("open"), &HSTRING::from(url), None, None, SW_SHOWNORMAL) };
        if r.0 as usize <= 32 {
            eprintln!("segv: could not open a link ({})", r.0 as usize);
        }
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    pub fn open(url: &str) {
        if let Err(e) = std::process::Command::new("xdg-open").arg(url).spawn() {
            eprintln!("segv: could not open a link: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn the_apps_own_pages_stay() {
        assert!(!external(&u("tauri://localhost/index.html#c/abcdefghijkl"), None));
        assert!(!external(&u("https://tauri.localhost/"), None));
        assert!(!external(&u("http://tauri.localhost/"), None));
        let dev = u("http://localhost:1420");
        assert!(!external(&u("http://localhost:1420/#c/abcdefghijkl"), Some(&dev)));
    }

    #[test]
    fn other_sites_open_in_the_browser() {
        assert!(external(&u("https://example.com/a?b#c"), None));
        assert!(external(&u("http://localhost:1420/"), None));
        let dev = u("http://localhost:1420");
        assert!(external(&u("http://localhost:8080/"), Some(&dev)));
        assert!(external(&u("https://tauri.localhost.example.com/"), None));
    }

    #[test]
    fn other_schemes_are_neither() {
        assert!(!external(&u("about:blank"), None));
        assert!(!external(&u("file:///C:/Windows/System32/calc.exe"), None));
        assert!(!external(&u("segv://open#c/abcdefghijkl"), None));
    }
}

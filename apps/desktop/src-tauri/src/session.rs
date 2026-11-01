//! The remembered session (docs/PROTOCOL.md §11.11, §11.14 "Storage"): the account key, sealed with AES-256-GCM in a
//! file of the app's own data directory, under a device key that the system's key store holds and that never leaves
//! this device (on macOS the data protection keychain, readable from the first unlock after a restart on, never synced
//! and never in a backup). The web view's storage holds no copy.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager, Runtime};

const FILE: &str = "session.json";

/// What the file holds: the uid in the clear (it names the account, as the web app's store does) and the sealed key.
#[derive(Serialize, Deserialize)]
struct Stored {
    v: u8,
    uid: String,
    nonce: String,
    ct: String,
}

/// What the web view gets back: the uid and the account key, both base64url.
#[derive(Serialize)]
pub struct Loaded {
    uid: String,
    ak: String,
}

fn path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join(FILE))
}

/// Binds the sealed key to its account, as the web app's store does (`segv.sh/v2/session/<uid>`).
fn aad(uid: &str) -> Vec<u8> {
    format!("segv.sh/v2/session/{uid}").into_bytes()
}

#[tauri::command]
pub async fn session_load<R: Runtime>(app: AppHandle<R>) -> Result<Option<Loaded>, String> {
    let Ok(text) = fs::read_to_string(path(&app)?) else {
        return Ok(None);
    };
    // Anything unreadable is no session: the device signs in again (§11.15 deletes what does not open).
    let Ok(s) = serde_json::from_str::<Stored>(&text) else {
        return Ok(None);
    };
    if s.v != 1 {
        return Ok(None);
    }
    let Some(key) = keystore::get()? else {
        return Ok(None);
    };
    let (Ok(nonce), Ok(ct)) = (B64.decode(&s.nonce), B64.decode(&s.ct)) else {
        return Ok(None);
    };
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let Ok(nonce) = Nonce::try_from(&nonce[..]) else {
        return Ok(None);
    };
    let Ok(ak) = cipher.decrypt(
        &nonce,
        Payload {
            msg: &ct,
            aad: &aad(&s.uid),
        },
    ) else {
        return Ok(None);
    };
    Ok(Some(Loaded {
        uid: s.uid,
        ak: B64.encode(ak),
    }))
}

#[tauri::command]
pub async fn session_save<R: Runtime>(app: AppHandle<R>, uid: String, ak: String) -> Result<(), String> {
    let ak = B64.decode(ak).map_err(|_| "invalid key".to_string())?;
    if ak.len() != 32 || uid.is_empty() || uid.len() > 64 {
        return Err("invalid session".into());
    }
    // A new device key for every session: one that ended can never open again.
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| e.to_string())?;
    keystore::set(&key)?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ak,
                aad: &aad(&uid),
            },
        )
        .map_err(|_| "could not seal the session".to_string())?;
    let stored = Stored {
        v: 1,
        uid,
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    };
    let p = path(&app)?;
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    // Written beside, then renamed: a crash leaves the old file or the new one, never half of one.
    let tmp = p.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec(&stored).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    restrict(&tmp);
    fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn session_clear<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    match fs::remove_file(path(&app)?) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    keystore::delete()
}

/// The file is the user's only (mode 0600).
fn restrict(p: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = p;
}

/// The device key in the system's key store.
#[cfg(target_os = "macos")]
mod keystore {
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::base::Error;
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    const SERVICE: &str = "sh.segv.desktop.session";
    const ACCOUNT: &str = "device-key";
    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    const MISSING_ENTITLEMENT: i32 = -34018; // errSecMissingEntitlement

    /// The data protection keychain, available from the first unlock after a restart, on this device only. It needs
    /// the app's signature (its application identifier); an unsigned development build falls back to the login keychain.
    fn options(protected: bool, write: bool) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        if protected {
            o.use_protected_keychain();
            o.set_access_synchronized(Some(false));
            if write
                && let Ok(ac) = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                    0,
                )
            {
                o.set_access_control(ac);
            }
        }
        o
    }

    fn fallback(e: &Error) -> bool {
        cfg!(debug_assertions) && e.code() == MISSING_ENTITLEMENT
    }

    pub fn get() -> Result<Option<Vec<u8>>, String> {
        let read = |protected| match generic_password(options(protected, false)) {
            Ok(k) => Ok(Some(k)),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(e),
        };
        match read(true) {
            Err(e) if fallback(&e) => read(false).map_err(|e| e.to_string()),
            r => r.map_err(|e| e.to_string()),
        }
    }

    pub fn set(key: &[u8]) -> Result<(), String> {
        let write = |protected| {
            // Replaced whole, so that the item keeps the access control it was created with.
            match delete_generic_password_options(options(protected, false)) {
                Ok(()) => {}
                Err(e) if e.code() == NOT_FOUND => {}
                Err(e) => return Err(e),
            }
            set_generic_password_options(key, options(protected, true))
        };
        match write(true) {
            Err(e) if fallback(&e) => write(false).map_err(|e| e.to_string()),
            r => r.map_err(|e| e.to_string()),
        }
    }

    pub fn delete() -> Result<(), String> {
        let del = |protected| match delete_generic_password_options(options(protected, false)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(e),
        };
        match del(true) {
            Err(e) if fallback(&e) => del(false).map_err(|e| e.to_string()),
            r => r.map_err(|e| e.to_string()),
        }
    }
}

/// Windows and Linux have no key store here yet: the session is not remembered there.
#[cfg(not(target_os = "macos"))]
mod keystore {
    const UNSUPPORTED: &str = "this system's key store is not supported yet";

    pub fn get() -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    pub fn set(_key: &[u8]) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }

    pub fn delete() -> Result<(), String> {
        Ok(())
    }
}

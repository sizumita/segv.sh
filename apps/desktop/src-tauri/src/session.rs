//! The remembered session (docs/PROTOCOL.md §11.11, §11.14 "Storage"): the account key, sealed with AES-256-GCM in a
//! file of the app's own local data directory (on Windows the one that a roaming profile does not carry), under a
//! device key that the system's key store holds and that never leaves this device (on macOS the data protection
//! keychain, readable from the first unlock after a restart on, never synced and never in a backup). The web view's
//! storage holds no copy.

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

/// The app's local data directory: the same one as its data directory on macOS and Linux.
fn dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path().app_local_data_dir().map_err(|e| e.to_string())
}

fn path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(dir(app)?.join(FILE))
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
    let d = dir(&app)?;
    let Some(key) = blocking(move || keystore::get(&d)).await? else {
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
    let d = dir(&app)?;
    blocking(move || keystore::set(&d, &key)).await?;
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
    let d = dir(&app)?;
    blocking(move || keystore::delete(&d)).await
}

/// Runs a call of the system's key store off the async runtime: it may wait for the system (the keychain, a TPM).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

/// Prepares the system's key store at launch, off the main thread, so that the first sign-in need not wait for it.
pub fn prepare() {
    #[cfg(windows)]
    std::thread::spawn(keystore::prepare);
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
    use std::path::Path;

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

    pub fn get(_dir: &Path) -> Result<Option<Vec<u8>>, String> {
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

    pub fn set(_dir: &Path, key: &[u8]) -> Result<(), String> {
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

    pub fn delete(_dir: &Path) -> Result<(), String> {
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

/// Windows: the device key wrapped by a key of the TPM, which never leaves it, so that the file opens on this device
/// only; on a device without a usable TPM (none, turned off, a virtual machine without one), sealed with DPAPI for
/// the signed-in user instead. Either lies in a file beside the session's, in the local data directory.
#[cfg(windows)]
mod keystore {
    use std::fs;
    use std::path::Path;

    const TPM_FILE: &str = "device-key.tpm";
    const DPAPI_FILE: &str = "device-key.dpapi";

    /// Makes the TPM's wrapping key ahead of the first sign-in, since a TPM may take seconds to make an RSA key.
    pub fn prepare() {
        tpm::prepare();
    }

    pub fn get(dir: &Path) -> Result<Option<Vec<u8>>, String> {
        // A key that does not open (the TPM was cleared, another user's, another device's) is no key: the device
        // signs in again.
        let key = if let Ok(sealed) = fs::read(dir.join(TPM_FILE)) {
            tpm::open(&sealed)
        } else if let Ok(sealed) = fs::read(dir.join(DPAPI_FILE)) {
            dpapi::open(&sealed)
        } else {
            None
        };
        Ok(key.filter(|k| k.len() == 32))
    }

    pub fn set(dir: &Path, key: &[u8]) -> Result<(), String> {
        let (file, other, sealed) = match tpm::seal(key) {
            Some(sealed) => (TPM_FILE, DPAPI_FILE, sealed),
            None => (DPAPI_FILE, TPM_FILE, dpapi::seal(key)?),
        };
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let p = dir.join(file);
        let tmp = p.with_extension("tmp");
        fs::write(&tmp, sealed).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
        remove(&dir.join(other))
    }

    /// The wrapped key goes; the TPM's wrapping key stays for the next session, and opens nothing without it.
    pub fn delete(dir: &Path) -> Result<(), String> {
        remove(&dir.join(TPM_FILE))?;
        remove(&dir.join(DPAPI_FILE))
    }

    fn remove(p: &Path) -> Result<(), String> {
        match fs::remove_file(p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// A non-exportable RSA key of the user's in the Microsoft Platform Crypto Provider, which wraps the device key
    /// with RSA-OAEP (SHA-256). Every call is silent: none may ask the user anything.
    mod tpm {
        use std::sync::Mutex;
        use windows::Win32::Security::Cryptography::{
            BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC,
            MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG,
            NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt,
            NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
        };
        use windows::core::{PCWSTR, w};

        const NAME: PCWSTR = w!("sh.segv.desktop device key wrap");

        /// One caller at a time makes or uses the key: two that both found none would each make one.
        static LOCK: Mutex<()> = Mutex::new(());

        struct Provider(NCRYPT_PROV_HANDLE);
        impl Drop for Provider {
            fn drop(&mut self) {
                let _ = unsafe { NCryptFreeObject(self.0.into()) };
            }
        }

        struct Key(NCRYPT_KEY_HANDLE);
        impl Drop for Key {
            fn drop(&mut self) {
                let _ = unsafe { NCryptFreeObject(self.0.into()) };
            }
        }

        fn provider() -> Option<Provider> {
            let mut p = NCRYPT_PROV_HANDLE::default();
            unsafe { NCryptOpenStorageProvider(&mut p, MS_PLATFORM_CRYPTO_PROVIDER, 0) }.ok()?;
            Some(Provider(p))
        }

        fn open_key(p: &Provider) -> Option<Key> {
            let mut k = NCRYPT_KEY_HANDLE::default();
            unsafe { NCryptOpenKey(p.0, &mut k, NAME, CERT_KEY_SPEC(0), NCRYPT_SILENT_FLAG) }.ok()?;
            Some(Key(k))
        }

        fn create_key(p: &Provider) -> Option<Key> {
            let mut k = NCRYPT_KEY_HANDLE::default();
            unsafe {
                NCryptCreatePersistedKey(
                    p.0,
                    &mut k,
                    BCRYPT_RSA_ALGORITHM,
                    NAME,
                    CERT_KEY_SPEC(0),
                    NCRYPT_FLAGS(0),
                )
            }
            .ok()?;
            let key = Key(k);
            unsafe {
                NCryptSetProperty(
                    key.0.into(),
                    NCRYPT_LENGTH_PROPERTY,
                    &2048u32.to_le_bytes(),
                    NCRYPT_SILENT_FLAG,
                )
            }
            .ok()?;
            unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) }.ok()?;
            Some(key)
        }

        fn key(p: &Provider) -> Option<Key> {
            open_key(p).or_else(|| create_key(p))
        }

        fn padding() -> BCRYPT_OAEP_PADDING_INFO {
            BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
                pbLabel: std::ptr::null_mut(),
                cbLabel: 0,
            }
        }

        /// NCryptEncrypt or NCryptDecrypt.
        type Cipher = unsafe fn(
            NCRYPT_KEY_HANDLE,
            Option<&[u8]>,
            Option<*const core::ffi::c_void>,
            Option<&mut [u8]>,
            *mut u32,
            NCRYPT_FLAGS,
        ) -> windows::core::Result<()>;

        /// Applies `f`, which first gives the output's size and then the output.
        fn apply(key: &Key, input: &[u8], f: Cipher) -> Option<Vec<u8>> {
            let pad = padding();
            let pad = Some(std::ptr::from_ref(&pad).cast());
            let flags = NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG;
            let mut n = 0u32;
            unsafe { f(key.0, Some(input), pad, None, &mut n, flags) }.ok()?;
            let mut out = vec![0u8; n as usize];
            unsafe { f(key.0, Some(input), pad, Some(&mut out), &mut n, flags) }.ok()?;
            out.truncate(n as usize);
            Some(out)
        }

        pub fn prepare() {
            let _held = LOCK.lock();
            if let Some(p) = provider() {
                let _ = key(&p);
            }
        }

        /// The wrapped key, if this device's TPM unwraps it again: only what opens is kept.
        pub fn seal(device_key: &[u8]) -> Option<Vec<u8>> {
            let _held = LOCK.lock();
            let p = provider()?;
            let k = key(&p)?;
            let sealed = apply(&k, device_key, NCryptEncrypt)?;
            (apply(&k, &sealed, NCryptDecrypt)?.as_slice() == device_key).then_some(sealed)
        }

        pub fn open(sealed: &[u8]) -> Option<Vec<u8>> {
            let _held = LOCK.lock();
            let p = provider()?;
            let k = open_key(&p)?;
            apply(&k, sealed, NCryptDecrypt)
        }
    }

    /// DPAPI for the signed-in user: Windows opens it for any program of that user's, on this device or wherever their
    /// credentials (a roaming profile, a domain's backup key) reach.
    mod dpapi {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        };
        use windows::core::w;

        /// Binds the sealed key to this use, so that another program of the user's that unseals DPAPI blobs by habit
        /// does not open this one by accident.
        const ENTROPY: &[u8] = b"segv.sh/v2/desktop/device-key";

        fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
            CRYPT_INTEGER_BLOB {
                cbData: b.len() as u32,
                pbData: b.as_ptr().cast_mut(),
            }
        }

        /// Takes the bytes that DPAPI allocated, and frees them.
        fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
            let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
            unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
            v
        }

        pub fn seal(key: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = CRYPT_INTEGER_BLOB::default();
            unsafe {
                CryptProtectData(
                    &blob(key),
                    w!("segv.sh device key"),
                    Some(&blob(ENTROPY)),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            }
            .map_err(|e| e.to_string())?;
            Ok(take(out))
        }

        pub fn open(sealed: &[u8]) -> Option<Vec<u8>> {
            let mut out = CRYPT_INTEGER_BLOB::default();
            unsafe {
                CryptUnprotectData(
                    &blob(sealed),
                    None,
                    Some(&blob(ENTROPY)),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            }
            .ok()?;
            Some(take(out))
        }
    }
}

/// Linux has no key store here yet: the session is not remembered there.
#[cfg(not(any(target_os = "macos", windows)))]
mod keystore {
    use std::path::Path;

    const UNSUPPORTED: &str = "this system's key store is not supported yet";

    pub fn get(_dir: &Path) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    pub fn set(_dir: &Path, _key: &[u8]) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }

    pub fn delete(_dir: &Path) -> Result<(), String> {
        Ok(())
    }
}

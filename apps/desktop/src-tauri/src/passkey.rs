//! Passkeys through the platform's own API (docs/PROTOCOL.md §2.3, §2.5, §11.14 "Passkeys"): the app's pages have the
//! origin `tauri://localhost` (`https://tauri.localhost` on Windows), whose web view cannot use the canonical host as RP
//! ID, so the engine's PasskeyPlatform calls these commands instead. That one passkey gives the same 32 bytes in the
//! app and on the web is what §2.3 requires, and §11.14 has it checked once against a browser for each system: a
//! passkey made on the web must unlock here.
//!
//! - macOS: AuthenticationServices with the app's associated domain (`webcredentials:<host>`), so the app shares the
//!   web app's passkeys. The PRF input is the one a browser evaluates as `prf.eval.first`, passed as AuthenticationServices'
//!   PRF input values, which Apple documents as WebAuthn's PRF values: the system then applies the WebAuthn PRF prefix,
//!   as a browser does (checked against a browser).
//! - Windows: the WebAuthn API of Windows (webauthn.dll), which browsers on Windows use too, so the app reaches the same
//!   passkeys as they do through it: Windows Hello, security keys, phones and the passkey managers that Windows lists.
//!   It takes any RP ID from a desktop app. The app hashes the PRF input into the hmac-secret salt as WebAuthn's PRF
//!   extension defines, `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`, and tells the system that the salt is already hashed,
//!   as Chromium does.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use tauri::{AppHandle, Runtime};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Created {
    cred_id: String,
    prf: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedIn {
    cred_id: String,
    uid: Option<String>,
    prf: Option<String>,
}

/// What a ceremony gives back.
pub enum Outcome {
    Created {
        cred_id: Vec<u8>,
        prf: Option<Vec<u8>>,
    },
    Asserted {
        cred_id: Vec<u8>,
        uid: Option<Vec<u8>>,
        prf: Option<Vec<u8>>,
    },
}

#[cfg(windows)]
type Answer = Result<Outcome, String>;

/// The hmac-secret salt of a PRF input, as WebAuthn's PRF extension defines it and browsers compute it:
/// `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`. Windows is told that the salt is already hashed.
#[cfg(any(windows, test))]
fn prf_salt(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(input);
    h.finalize().into()
}

fn decode(what: &str, s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|_| format!("invalid {what}"))
}

/// The PRF result, only when it is the 32 bytes of §2.3.
fn prf32(p: Option<Vec<u8>>) -> Option<String> {
    p.filter(|p| p.len() == 32).map(|p| B64.encode(p))
}

/// Whether this system can evaluate the PRF extension with its passkeys (macOS 15 and later; on Windows a WebAuthn API
/// of version 4 or later, though Windows Hello itself evaluates it only from the February 2026 updates of Windows 11
/// 24H2 and 25H2 on).
#[tauri::command]
pub fn passkey_capability() -> Option<bool> {
    Some(imp::supported())
}

#[tauri::command]
pub async fn passkey_create<R: Runtime>(
    app: AppHandle<R>,
    rp_id: String,
    uid: String,
    handle: String,
    prf_input: String,
) -> Result<Created, String> {
    let uid = decode("uid", &uid)?;
    let input = decode("PRF input", &prf_input)?;
    if uid.is_empty() || uid.len() > 64 || handle.is_empty() {
        return Err("invalid account".into());
    }
    match imp::run(
        &app,
        imp::Ceremony::Create {
            rp_id,
            uid,
            handle,
            input,
        },
    )
    .await?
    {
        Outcome::Created { cred_id, prf } => Ok(Created {
            cred_id: B64.encode(cred_id),
            prf: prf32(prf),
        }),
        Outcome::Asserted { .. } => Err("unexpected passkey answer".into()),
    }
}

#[tauri::command]
pub async fn passkey_prf<R: Runtime>(
    app: AppHandle<R>,
    rp_id: String,
    cred_id: String,
    prf_input: String,
) -> Result<Option<String>, String> {
    let cred_id = decode("credential id", &cred_id)?;
    let input = decode("PRF input", &prf_input)?;
    match imp::run(
        &app,
        imp::Ceremony::Assert {
            rp_id,
            allow: Some(cred_id),
            input,
        },
    )
    .await?
    {
        Outcome::Asserted { prf, .. } => Ok(prf32(prf)),
        Outcome::Created { .. } => Err("unexpected passkey answer".into()),
    }
}

#[tauri::command]
pub async fn passkey_sign_in<R: Runtime>(
    app: AppHandle<R>,
    rp_id: String,
    prf_input: String,
) -> Result<SignedIn, String> {
    let input = decode("PRF input", &prf_input)?;
    match imp::run(
        &app,
        imp::Ceremony::Assert {
            rp_id,
            allow: None,
            input,
        },
    )
    .await?
    {
        Outcome::Asserted { cred_id, uid, prf } => Ok(SignedIn {
            cred_id: B64.encode(cred_id),
            uid: uid.filter(|u| !u.is_empty()).map(|u| B64.encode(u)),
            prf: prf32(prf),
        }),
        Outcome::Created { .. } => Err("unexpected passkey answer".into()),
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Outcome;
    use objc2::rc::Retained;
    use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
    use objc2::{AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send};
    use objc2_app_kit::NSWindow;
    use objc2_authentication_services::{
        ASAuthorization, ASAuthorizationController, ASAuthorizationControllerDelegate,
        ASAuthorizationControllerPresentationContextProviding, ASAuthorizationError, ASAuthorizationErrorDomain,
        ASAuthorizationPlatformPublicKeyCredentialAssertion, ASAuthorizationPlatformPublicKeyCredentialDescriptor,
        ASAuthorizationPlatformPublicKeyCredentialProvider, ASAuthorizationPlatformPublicKeyCredentialRegistration,
        ASAuthorizationPublicKeyCredentialAssertion, ASAuthorizationPublicKeyCredentialAssertionRequest,
        ASAuthorizationPublicKeyCredentialPRFAssertionInput, ASAuthorizationPublicKeyCredentialPRFAssertionInputValues,
        ASAuthorizationPublicKeyCredentialPRFRegistrationInput, ASAuthorizationPublicKeyCredentialRegistrationRequest,
        ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired, ASAuthorizationRequest,
        ASPresentationAnchor, ASPublicKeyCredential,
    };
    use objc2_foundation::{NSArray, NSData, NSError, NSOperatingSystemVersion, NSProcessInfo, NSString};
    use std::cell::RefCell;
    use std::sync::mpsc;
    use tauri::{AppHandle, Manager, Runtime};

    pub enum Ceremony {
        Create {
            rp_id: String,
            uid: Vec<u8>,
            handle: String,
            input: Vec<u8>,
        },
        Assert {
            rp_id: String,
            allow: Option<Vec<u8>>,
            input: Vec<u8>,
        },
    }

    type Answer = Result<Outcome, String>;

    pub fn supported() -> bool {
        NSProcessInfo::processInfo().isOperatingSystemAtLeastVersion(NSOperatingSystemVersion {
            majorVersion: 15,
            minorVersion: 0,
            patchVersion: 0,
        })
    }

    pub struct Ivars {
        tx: RefCell<Option<mpsc::Sender<Answer>>>,
        anchor: Retained<NSWindow>,
    }

    define_class!(
        /// The controller's delegate and presentation anchor: sends the one answer of its ceremony.
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "SegvPasskeyDelegate"]
        #[ivars = Ivars]
        struct Delegate;

        unsafe impl NSObjectProtocol for Delegate {}

        unsafe impl ASAuthorizationControllerDelegate for Delegate {
            #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
            fn did_complete(&self, _controller: &ASAuthorizationController, auth: &ASAuthorization) {
                self.answer(outcome(auth));
            }

            #[unsafe(method(authorizationController:didCompleteWithError:))]
            fn did_fail(&self, _controller: &ASAuthorizationController, error: &NSError) {
                self.answer(Err(explain(error)));
            }
        }

        unsafe impl ASAuthorizationControllerPresentationContextProviding for Delegate {
            #[unsafe(method_id(presentationAnchorForAuthorizationController:))]
            fn anchor(&self, _controller: &ASAuthorizationController) -> Retained<ASPresentationAnchor> {
                let w: Retained<NSObject> = Retained::into_super(Retained::into_super(self.ivars().anchor.clone()));
                w
            }
        }
    );

    impl Delegate {
        fn new(mtm: MainThreadMarker, tx: mpsc::Sender<Answer>, anchor: Retained<NSWindow>) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(Ivars {
                tx: RefCell::new(Some(tx)),
                anchor,
            });
            unsafe { msg_send![super(this), init] }
        }

        fn answer(&self, a: Answer) {
            if let Some(tx) = self.ivars().tx.borrow_mut().take() {
                let _ = tx.send(a);
            }
        }
    }

    thread_local! {
        /// The ceremony in progress: the controller holds its delegate weakly, so both live here until the next one.
        static ACTIVE: RefCell<Option<(Retained<ASAuthorizationController>, Retained<Delegate>)>> =
            const { RefCell::new(None) };
    }

    fn explain(e: &NSError) -> String {
        if &*e.domain() == unsafe { ASAuthorizationErrorDomain } && e.code() == ASAuthorizationError::Canceled.0 {
            return "passkey prompt was cancelled or timed out".into();
        }
        format!(
            "passkey error: {} ({} {})",
            e.localizedDescription(),
            e.domain(),
            e.code()
        )
    }

    fn outcome(auth: &ASAuthorization) -> Answer {
        let cred = unsafe { auth.credential() };
        let any: &objc2::runtime::AnyObject = cred.as_ref();
        if let Some(r) = any.downcast_ref::<ASAuthorizationPlatformPublicKeyCredentialRegistration>() {
            let prf = unsafe { r.prf() }
                .and_then(|o| unsafe { o.first() })
                .map(|d| d.to_vec());
            return Ok(Outcome::Created {
                cred_id: unsafe { r.credentialID() }.to_vec(),
                prf,
            });
        }
        if let Some(a) = any.downcast_ref::<ASAuthorizationPlatformPublicKeyCredentialAssertion>() {
            let prf = unsafe { a.prf() }.map(|o| unsafe { o.first() }.to_vec());
            return Ok(Outcome::Asserted {
                cred_id: unsafe { a.credentialID() }.to_vec(),
                uid: Some(unsafe { a.userID() }.to_vec()),
                prf,
            });
        }
        Err("the passkey provider gave no passkey".into())
    }

    fn prf_values(input: &[u8]) -> Retained<ASAuthorizationPublicKeyCredentialPRFAssertionInputValues> {
        unsafe {
            ASAuthorizationPublicKeyCredentialPRFAssertionInputValues::initWithSaltInput1_saltInput2(
                ASAuthorizationPublicKeyCredentialPRFAssertionInputValues::alloc(),
                &NSData::with_bytes(input),
                None,
            )
        }
    }

    fn request(c: &Ceremony) -> Retained<ASAuthorizationRequest> {
        let rp = |id: &str| unsafe {
            ASAuthorizationPlatformPublicKeyCredentialProvider::initWithRelyingPartyIdentifier(
                ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
                &NSString::from_str(id),
            )
        };
        let mut challenge = [0u8; 32];
        let _ = getrandom::fill(&mut challenge);
        let challenge = NSData::with_bytes(&challenge);
        let uv = unsafe { ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired }
            .expect("AuthenticationServices constant");
        match c {
            Ceremony::Create {
                rp_id,
                uid,
                handle,
                input,
            } => unsafe {
                let r = rp(rp_id).createCredentialRegistrationRequestWithChallenge_name_userID(
                    &challenge,
                    &NSString::from_str(handle),
                    &NSData::with_bytes(uid),
                );
                r.setUserVerificationPreference(uv);
                r.setPrf(Some(
                    &ASAuthorizationPublicKeyCredentialPRFRegistrationInput::initWithInputValues(
                        ASAuthorizationPublicKeyCredentialPRFRegistrationInput::alloc(),
                        Some(&prf_values(input)),
                    ),
                ));
                Retained::into_super(r)
            },
            Ceremony::Assert { rp_id, allow, input } => unsafe {
                let r = rp(rp_id).createCredentialAssertionRequestWithChallenge(&challenge);
                r.setUserVerificationPreference(uv);
                if let Some(id) = allow {
                    let d = ASAuthorizationPlatformPublicKeyCredentialDescriptor::initWithCredentialID(
                        ASAuthorizationPlatformPublicKeyCredentialDescriptor::alloc(),
                        &NSData::with_bytes(id),
                    );
                    r.setAllowedCredentials(&NSArray::from_retained_slice(&[d]));
                }
                r.setPrf(Some(
                    &ASAuthorizationPublicKeyCredentialPRFAssertionInput::initWithInputValues_perCredentialInputValues(
                        ASAuthorizationPublicKeyCredentialPRFAssertionInput::alloc(),
                        Some(&prf_values(input)),
                        None,
                    ),
                ));
                Retained::into_super(r)
            },
        }
    }

    /// Runs one ceremony on the main thread, presented over the main window, and waits for its answer.
    pub async fn run<R: Runtime>(app: &AppHandle<R>, c: Ceremony) -> Result<Outcome, String> {
        if !supported() {
            return Err("passkeys with the PRF extension need macOS 15 or later".into());
        }
        let window = app.get_webview_window("main").ok_or("no window")?;
        let ns = window.ns_window().map_err(|e| e.to_string())? as usize;
        let (tx, rx) = mpsc::channel::<Answer>();
        let fail = tx.clone();
        app.run_on_main_thread(move || {
            let Some(mtm) = MainThreadMarker::new() else {
                let _ = fail.send(Err("not on the main thread".into()));
                return;
            };
            let Some(anchor) = (unsafe { Retained::retain(ns as *mut NSWindow) }) else {
                let _ = fail.send(Err("no window".into()));
                return;
            };
            ACTIVE.with(|a| {
                // A newer ceremony replaces one still showing (its own answer is "cancelled").
                if let Some((old, _)) = a.borrow_mut().take() {
                    unsafe { old.cancel() };
                }
                let delegate = Delegate::new(mtm, tx, anchor);
                let requests = NSArray::from_retained_slice(&[request(&c)]);
                let controller = unsafe {
                    ASAuthorizationController::initWithAuthorizationRequests(
                        ASAuthorizationController::alloc(),
                        &requests,
                    )
                };
                unsafe {
                    controller.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
                    controller.setPresentationContextProvider(Some(ProtocolObject::from_ref(&*delegate)));
                    controller.performRequests();
                }
                *a.borrow_mut() = Some((controller, delegate));
            });
        })
        .map_err(|e| e.to_string())?;
        tauri::async_runtime::spawn_blocking(move || rx.recv())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|_| "the passkey prompt ended without an answer".to_string())?
    }

    // Brings the protocol traits' methods into scope for the requests and credentials above.
    #[allow(unused_imports)]
    use {
        ASAuthorizationPublicKeyCredentialAssertion as _, ASAuthorizationPublicKeyCredentialAssertionRequest as _,
        ASAuthorizationPublicKeyCredentialRegistrationRequest as _, ASPublicKeyCredential as _,
    };
}

#[cfg(windows)]
mod imp {
    use super::Outcome;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use std::ffi::c_void;
    use std::sync::Mutex;
    use tauri::{AppHandle, Manager, Runtime};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Networking::WindowsWebServices::*;
    use windows::core::{BOOL, GUID, HRESULT, HSTRING, PCWSTR, w};

    pub enum Ceremony {
        Create {
            rp_id: String,
            uid: Vec<u8>,
            handle: String,
            input: Vec<u8>,
        },
        Assert {
            rp_id: String,
            allow: Option<Vec<u8>>,
            input: Vec<u8>,
        },
    }

    const TIMEOUT_MS: u32 = 180_000;

    /// The API version that evaluates the PRF at sign-in (the salts of get-assertion options v6, the result in
    /// assertion v3), and the one that also evaluates it when it creates a passkey (make-credential options v8,
    /// attestation v7).
    const PRF_ON_GET: u32 = WEBAUTHN_API_VERSION_4;
    const PRF_ON_CREATE: u32 = 8;

    fn api() -> u32 {
        unsafe { WebAuthNGetApiVersionNumber() }
    }

    pub fn supported() -> bool {
        api() >= PRF_ON_GET
    }

    /// Make-credential options of version 8: the windows crate's version 7, then the fields that version 8 adds
    /// (webauthn.h). Version 7 ends with a pointer, so the fields follow it at the same offsets as in C.
    #[repr(C)]
    struct MakeCredentialOptions8 {
        v7: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        prf_global_eval: *mut WEBAUTHN_HMAC_SECRET_SALT,
        credential_hints: u32,
        credential_hint_list: *const PCWSTR,
        third_party_payment: BOOL,
    }

    /// An attestation of version 7: version 6 and the PRF result that version 7 adds.
    #[repr(C)]
    struct Attestation7 {
        v6: WEBAUTHN_CREDENTIAL_ATTESTATION,
        hmac_secret: *mut WEBAUTHN_HMAC_SECRET_SALT,
    }

    // Each extended struct ends right after its last field, a pointer, so that the added fields follow it as in C.
    const _: () = assert!(
        std::mem::offset_of!(WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, pbJsonExt) + size_of::<*mut u8>()
            == size_of::<WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS>()
    );
    const _: () = assert!(
        std::mem::offset_of!(WEBAUTHN_CREDENTIAL_ATTESTATION, pbUnsignedExtensionOutputs) + size_of::<*mut u8>()
            == size_of::<WEBAUTHN_CREDENTIAL_ATTESTATION>()
    );

    /// Client data for the ceremony. Nothing checks it: the server never sees WebAuthn data (§2.3), and the PRF does
    /// not depend on it.
    fn client_data(kind: &str, rp_id: &str) -> Vec<u8> {
        let mut challenge = [0u8; 32];
        let _ = getrandom::fill(&mut challenge);
        format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"https://{rp_id}","crossOrigin":false}}"#,
            B64.encode(challenge)
        )
        .into_bytes()
    }

    /// A host name, as an RP ID is: it goes into the client data's JSON as it is.
    fn valid_rp_id(rp_id: &str) -> bool {
        !rp_id.is_empty()
            && rp_id.len() <= 253
            && rp_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }

    unsafe fn bytes(p: *const u8, n: u32) -> Vec<u8> {
        if p.is_null() || n == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(p, n as usize) }.to_vec()
    }

    fn explain(e: windows::core::Error) -> String {
        const NTE_USER_CANCELLED: HRESULT = HRESULT(0x8009_0036_u32 as i32);
        const ERROR_CANCELLED: HRESULT = HRESULT(0x8007_04c7_u32 as i32);
        const NTE_EXISTS: HRESULT = HRESULT(0x8009_000f_u32 as i32);
        match e.code() {
            NTE_USER_CANCELLED | ERROR_CANCELLED => "passkey prompt was cancelled or timed out".into(),
            NTE_EXISTS => "this passkey is already registered".into(),
            hr => {
                let name = unsafe { WebAuthNGetErrorName(hr) };
                let name = if name.is_null() {
                    String::new()
                } else {
                    unsafe { name.to_string() }.unwrap_or_default()
                };
                format!("passkey error: {name} ({:#010x})", hr.0 as u32)
            }
        }
    }

    fn create(hwnd: HWND, mut cancel: GUID, rp_id: &str, uid: &[u8], handle: &str, input: &[u8]) -> super::Answer {
        let api = api();
        let rp_id_w = HSTRING::from(rp_id);
        let handle_w = HSTRING::from(handle);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id_w.as_ptr()),
            pwszName: w!("segv.sh"),
            pwszIcon: PCWSTR::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: uid.len() as u32,
            pbId: uid.as_ptr().cast_mut(),
            pwszName: PCWSTR(handle_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(handle_w.as_ptr()),
        };
        // The web app's algorithms, in its order: Ed25519, P-256, RSA.
        let mut params = [
            -8,
            WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
            WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256,
        ]
        .map(|alg| WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: alg,
        });
        let cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: params.len() as u32,
            pCredentialParameters: params.as_mut_ptr(),
        };
        let json = client_data("webauthn.create", rp_id);
        let cd = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_ptr().cast_mut(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        // The hmac-secret extension, which the PRF extension is made of.
        let mut on = BOOL::from(true);
        let mut ext = [WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: size_of::<BOOL>() as u32,
            pvExtension: std::ptr::from_mut(&mut on).cast::<c_void>(),
        }];
        let mut first = super::prf_salt(input);
        let mut eval = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: first.len() as u32,
            pbFirst: first.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        };
        let eval_now = api >= PRF_ON_CREATE;
        let opts = MakeCredentialOptions8 {
            v7: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
                dwVersion: 8,
                dwTimeoutMilliseconds: TIMEOUT_MS,
                Extensions: WEBAUTHN_EXTENSIONS {
                    cExtensions: ext.len() as u32,
                    pExtensions: ext.as_mut_ptr(),
                },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                bRequireResidentKey: true.into(),
                dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                dwFlags: if eval_now {
                    WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG
                } else {
                    0
                },
                pCancellationId: &mut cancel,
                bEnablePrf: true.into(),
                ..Default::default()
            },
            prf_global_eval: if eval_now { &mut eval } else { std::ptr::null_mut() },
            credential_hints: 0,
            credential_hint_list: std::ptr::null(),
            third_party_payment: false.into(),
        };
        let att = unsafe {
            WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &cose, &cd, Some(std::ptr::from_ref(&opts).cast()))
        }
        .map_err(explain)?;
        let a = unsafe { &*att };
        let cred_id = unsafe { bytes(a.pbCredentialId, a.cbCredentialId) };
        let prf = (a.dwVersion >= 7)
            .then(|| unsafe { (*att.cast::<Attestation7>()).hmac_secret })
            .filter(|p| !p.is_null())
            .map(|p| unsafe { bytes((*p).pbFirst, (*p).cbFirst) });
        unsafe { WebAuthNFreeCredentialAttestation(Some(att)) };
        Ok(Outcome::Created { cred_id, prf })
    }

    fn assert(hwnd: HWND, mut cancel: GUID, rp_id: &str, allow: Option<&[u8]>, input: &[u8]) -> super::Answer {
        let rp_id_w = HSTRING::from(rp_id);
        let json = client_data("webauthn.get", rp_id);
        let cd = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_ptr().cast_mut(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut allowed: Vec<WEBAUTHN_CREDENTIAL> = allow
            .map(|id| WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_ptr().cast_mut(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
            .into_iter()
            .collect();
        let mut first = super::prf_salt(input);
        let mut global = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: first.len() as u32,
            pbFirst: first.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut global,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: std::ptr::null_mut(),
        };
        let opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_7,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            // An empty list lets the user pick any passkey of the RP ID (a discoverable sign-in).
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: allowed.len() as u32,
                pCredentials: if allowed.is_empty() {
                    std::ptr::null_mut()
                } else {
                    allowed.as_mut_ptr()
                },
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwFlags: WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG,
            pCancellationId: &mut cancel,
            pHmacSecretSaltValues: &mut salts,
            ..Default::default()
        };
        let a = unsafe { WebAuthNAuthenticatorGetAssertion(hwnd, &rp_id_w, &cd, Some(&opts)) }.map_err(explain)?;
        let r = unsafe { &*a };
        let cred_id = unsafe { bytes(r.Credential.pbId, r.Credential.cbId) };
        let uid = Some(unsafe { bytes(r.pbUserId, r.cbUserId) });
        let prf = (r.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 && !r.pHmacSecret.is_null())
            .then(|| unsafe { bytes((*r.pHmacSecret).pbFirst, (*r.pHmacSecret).cbFirst) });
        unsafe { WebAuthNFreeAssertion(a) };
        Ok(Outcome::Asserted { cred_id, uid, prf })
    }

    /// The ceremony in progress: a newer one cancels it (its own answer is "cancelled").
    static ACTIVE: Mutex<Option<GUID>> = Mutex::new(None);

    /// Runs one ceremony, modal to the main window, on a thread of its own: the system's call blocks until the user
    /// has answered.
    pub async fn run<R: Runtime>(app: &AppHandle<R>, c: Ceremony) -> Result<Outcome, String> {
        if !supported() {
            return Err("passkeys with the PRF extension need a newer version of Windows".into());
        }
        let rp_id = match &c {
            Ceremony::Create { rp_id, .. } | Ceremony::Assert { rp_id, .. } => rp_id,
        };
        if !valid_rp_id(rp_id) {
            return Err("invalid RP ID".into());
        }
        let window = app.get_webview_window("main").ok_or("no window")?;
        // The handle crosses to the ceremony's thread as a number.
        let hwnd = window.hwnd().map_err(|e| e.to_string())?.0 as usize;
        let id = unsafe { WebAuthNGetCancellationId() }.map_err(|e| e.to_string())?;
        if let Ok(mut active) = ACTIVE.lock()
            && let Some(old) = active.replace(id)
        {
            let _ = unsafe { WebAuthNCancelCurrentOperation(&old) };
        }
        let answer = tauri::async_runtime::spawn_blocking(move || {
            let hwnd = HWND(hwnd as *mut c_void);
            match c {
                Ceremony::Create {
                    rp_id,
                    uid,
                    handle,
                    input,
                } => create(hwnd, id, &rp_id, &uid, &handle, &input),
                Ceremony::Assert { rp_id, allow, input } => assert(hwnd, id, &rp_id, allow.as_deref(), &input),
            }
        })
        .await
        .map_err(|e| e.to_string())?;
        if let Ok(mut active) = ACTIVE.lock()
            && *active == Some(id)
        {
            *active = None;
        }
        answer
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use super::Outcome;
    use tauri::{AppHandle, Runtime};

    pub enum Ceremony {
        Create {
            rp_id: String,
            uid: Vec<u8>,
            handle: String,
            input: Vec<u8>,
        },
        Assert {
            rp_id: String,
            allow: Option<Vec<u8>>,
            input: Vec<u8>,
        },
    }

    pub fn supported() -> bool {
        false
    }

    pub async fn run<R: Runtime>(_app: &AppHandle<R>, _c: Ceremony) -> Result<Outcome, String> {
        Err("passkeys are not supported in this app on this system yet; use your recovery code".into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn prf_salt_of_the_protocol_input() {
        // PRF_INPUT of packages/protocol; the value is SHA-256 of "WebAuthn PRF", a zero byte and the input.
        let salt = super::prf_salt(b"segv.sh/v2/prf");
        let hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "b9fa37e70aed9223ae6c0152d625038e7fcd00a4fa897bb470d50a688941109a");
    }
}

//! Passkeys through the platform's own API (docs/PROTOCOL.md §2.3, §2.5, §11.14 "Passkeys"): the app's pages have the
//! origin `tauri://localhost`, whose web view cannot use the canonical host as RP ID, so the engine's PasskeyPlatform
//! calls these commands instead. On macOS they use AuthenticationServices with the app's associated domain
//! (`webcredentials:<host>`), so the app shares the web app's passkeys. The PRF input is the one a browser evaluates as
//! `prf.eval.first`, passed as AuthenticationServices' PRF input values, which Apple documents as WebAuthn's PRF values:
//! the system then applies the WebAuthn PRF prefix, as a browser does. That one passkey gives the same 32 bytes in the
//! app and on the web is what §2.3 requires, and §11.14 has it checked once against a browser: a passkey made on the
//! web must unlock here. If it does not, pass `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)` instead.

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

fn decode(what: &str, s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|_| format!("invalid {what}"))
}

/// The PRF result, only when it is the 32 bytes of §2.3.
fn prf32(p: Option<Vec<u8>>) -> Option<String> {
    p.filter(|p| p.len() == 32).map(|p| B64.encode(p))
}

/// Whether this system can evaluate the PRF extension with its passkeys (macOS 15 and later).
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

#[cfg(not(target_os = "macos"))]
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

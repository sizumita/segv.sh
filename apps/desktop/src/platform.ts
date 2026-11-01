// The platform that the desktop app gives the engine (docs/PROTOCOL.md §11.14; EngineOptions): the deployment's
// canonical origin, passkeys through the system's own API (AuthenticationServices on macOS, the WebAuthn API of
// Windows), the remembered session in the app's own files under a key of the system's key store, and notifications that
// the app shows itself while it runs (§11.13 "Apps without push"). Each one is a command of the app's native code
// (src-tauri/src).
import type {
  EngineOptions,
  LocalNotification,
  LocalNotifier,
  LocalPermission,
  PasskeyPlatform,
  SessionStore,
} from "@segv/engine";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const b64u = (b: Uint8Array): string => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const fromB64u = (s: string): Uint8Array => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

/** A command's rejection is its message: an Error, so that the UI shows it as any other. */
async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw e instanceof Error ? e : new Error(String(e));
  }
}

const passkeys: PasskeyPlatform = {
  capability: () => call<boolean | null>("passkey_capability"),
  async create(rpId, uid, handle, prfInput) {
    const r = await call<{ credId: string; prf: string | null }>("passkey_create", {
      rpId,
      uid: b64u(uid),
      handle,
      prfInput: b64u(prfInput),
    });
    return { credId: fromB64u(r.credId), prf: r.prf ? fromB64u(r.prf) : null };
  },
  async prfFor(rpId, credId, prfInput) {
    const prf = await call<string | null>("passkey_prf", {
      rpId,
      credId: b64u(credId),
      prfInput: b64u(prfInput),
    });
    return prf ? fromB64u(prf) : null;
  },
  async signIn(rpId, prfInput) {
    const r = await call<{ credId: string; uid: string | null; prf: string | null }>(
      "passkey_sign_in",
      { rpId, prfInput: b64u(prfInput) },
    );
    return {
      credId: fromB64u(r.credId),
      uid: r.uid ? fromB64u(r.uid) : null,
      prf: r.prf ? fromB64u(r.prf) : null,
    };
  },
  // Neither AuthenticationServices nor the WebAuthn API of Windows can tell a provider that a credential is useless
  // (Windows can only delete a passkey of Windows Hello, which the app leaves to the user).
  forget: async () => {},
};

const session: SessionStore = {
  async load() {
    const s = await call<{ uid: string; ak: string } | null>("session_load");
    return s ? { uid: s.uid, AK: fromB64u(s.ak) } : null;
  },
  save: (uid, AK) => call<void>("session_save", { uid, ak: b64u(AK) }),
  clear: () => call<void>("session_clear"),
};

/** Fire and forget: a notification that fails to show is no reason to stop the engine. */
const send = (cmd: string, args?: Record<string, unknown>) => {
  call<void>(cmd, args).catch((e: unknown) => console.error(`segv: ${cmd}`, e));
};

const notifier: LocalNotifier = {
  permission: () => call<LocalPermission>("notify_permission"),
  requestPermission: () => call<LocalPermission>("notify_request"),
  show: (n: LocalNotification) => send("notify_show", { n }),
  close: (tag) => send("notify_close", { tag }),
  closeAll: () => send("notify_close_all"),
  badge: (count) => send("badge", { count }),
};

const CHAT = /^#c\/[A-Za-z0-9_-]{12}$/;

/**
 * A clicked notification or an opened `segv:` link (src-tauri/src/notify.rs): the native code has shown the window,
 * and the page moves to the conversation it names, or to the start page for "" (the fixed notification, §11.13), as
 * a link would (packages/ui/src/route.ts follows the fragment). Once the page listens, it asks for the one that
 * launched the app, which came before the page did (null: none).
 */
export async function followOpens(): Promise<void> {
  const open = (to: string | null) => {
    if (to === null || (to !== "" && !CHAT.test(to)) || location.hash === to) return;
    location.hash = to;
  };
  await listen<string>("segv:open", (e) => open(e.payload));
  open(await call<string | null>("page_ready"));
}

export function platform(): EngineOptions {
  const origin = import.meta.env.SEGV_ORIGIN;
  return {
    // "" in `tauri dev`, whose page reaches the API through the dev server at its own origin (vite.config.ts).
    origin: origin || undefined,
    passkeys,
    session,
    // No push transport (§11.14 "Notifications"): the app notifies from the rows that reach it while it runs.
    push: { platform: null },
    local: { notifier },
    onWake: (fn) => void listen("segv:wake", () => fn()),
  };
}

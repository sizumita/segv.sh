// Accounts (docs/PROTOCOL.md §2.4–§2.6): register, passkey and recovery login, adding a passkey, unwrapFrom, and the
// registration of an alias (a temporary handle). Ported from the v1 engine, with the v2 directory lookups.
import * as P from "@segv/protocol/proto";
import {
  ApiError,
  isTransient,
  type Api,
  type DirWrapJson,
  type Progress,
  type UserJson,
} from "./api";
import { UserError, message } from "./errors";
import { prfInput, type PasskeyPlatform } from "./webauthn";

/** The passkey API and the RP ID (§2.5): the page's host in a browser, the canonical host in a native app. */
export interface Passkeys {
  platform: PasskeyPlatform;
  rpId: string;
}

/** What a successful unlock yields. */
export interface Unlocked {
  AK: Uint8Array;
  uid: Uint8Array;
}

const NO_PRF =
  "this passkey provider does not support the WebAuthn PRF extension, so it cannot hold encryption keys. " +
  "try iCloud Keychain, Google Password Manager, Windows Hello (Windows 11 24H2+) or a FIDO2 security key.";

/** §2.5 step 1: a chosen handle never starts with `_`, which alias handles start with (§2.6). */
export const ALIAS_HANDLE_RESERVED = "handles starting with _ are reserved for temporary handles";
/** `createAlias` failed (§2.6 "Creating", §11.11). */
export const ALIAS_CREATE_FAILED = "could not create a temporary handle; try again";

/** §2.5 step 1: trim, lowercase, strip one leading "@". */
export function normaliseHandle(handleIn: string): string {
  return handleIn.trim().toLowerCase().replace(/^@/, "");
}

/** Creates a passkey for `uid` and returns its id and PRF secret, asking a second time when needed (§2.5 step 5). */
async function newPasskey(
  pk: Passkeys,
  uid: Uint8Array,
  name: string,
  progress: Progress,
): Promise<{ credId: Uint8Array; prf: Uint8Array }> {
  progress("creating passkey…");
  const { credId, prf: prf0 } = await pk.platform.create(pk.rpId, uid, name, prfInput());
  let prf = prf0;
  if (!prf) {
    progress("confirm the passkey once more to derive your keys…");
    prf = await pk.platform.prfFor(pk.rpId, credId, prfInput());
  }
  if (!prf) {
    await pk.platform.forget(pk.rpId, credId);
    throw new UserError(NO_PRF);
  }
  return { credId, prf };
}

/**
 * Registers a new account (§2.5): handle check by prefix, keys, passkey, `POST /api/v2/register`, and the
 * lost-response check. Resolves with the unlocked account, its handle and the recovery code (shown once).
 */
export async function registerAccount(
  api: Api,
  pk: Passkeys,
  handleIn: string,
  progress: Progress,
): Promise<Unlocked & { handle: string; recoveryCode: string; regNow: number | null }> {
  const handle = normaliseHandle(handleIn);
  if (P.isAliasHandle(handle)) throw new UserError(ALIAS_HANDLE_RESERVED);
  if (!P.HANDLE_RE.test(handle)) throw new UserError("handle must be 3–20 characters: a–z, 0–9, _");
  progress("checking handle…");
  if (await api.userByHandle(handle, true)) throw new UserError(`@${handle} is taken`);
  const AK = P.random(32);
  const uid = P.random(16);
  const id = P.deriveIdentity(AK);
  const { bundle, sig } = P.makeBundle(uid, handle, id, Date.now());
  const { credId, prf } = await newPasskey(pk, uid, handle, progress);
  const code = P.newRecoveryCode();
  const rk = P.recoveryKem(code);
  const now = Date.now();
  const wraps = [
    P.makeWrap(uid, "passkey", credId, P.credKem(prf, credId), AK, id, now),
    P.makeWrap(uid, "recovery", rk.id, rk, AK, id, now),
  ];
  // The registration's server time, when its response arrived: the first inbox cursor starts there (§11.1).
  let regNow: number | null = null;
  try {
    // A network error, a 429 or a 5xx is answered by sending the identical registration again (§2.5 step 8): the
    // directory answers one it already logged as it did the first time.
    regNow = (await api.register({ bundle, sig, wraps }, progress)).now;
  } catch (e) {
    // A definitive rejection (4xx): the account does not exist, so the new passkey is useless (§2.5 steps 7, 8).
    if (e instanceof ApiError && !e.transient) {
      await pk.platform.forget(pk.rpId, credId);
      if (e.status === 409) throw new UserError(`@${handle} is taken`);
      throw e;
    }
    // Still no answer after the last send: whether the account exists is unknown, so the passkey stays.
    throw e;
  }
  return { AK, uid, handle, recoveryCode: P.formatRecoveryCode(code), regNow };
}

/** Discoverable passkey login (§2.5): the wraps filed under the credential id (and the user handle, if any). */
export async function loginWithPasskey(
  api: Api,
  pk: Passkeys,
  progress: Progress,
): Promise<Unlocked> {
  progress("waiting for passkey…");
  const { credId, uid, prf } = await pk.platform.signIn(pk.rpId, prfInput());
  if (!prf)
    throw new UserError(
      "this passkey did not return a PRF secret (unsupported provider or browser). use your recovery code instead.",
    );
  progress("unlocking…");
  const found = unwrapFrom(
    await api.wraps(credId, uid),
    "passkey",
    credId,
    P.credKem(prf, credId),
    uid,
  );
  if (!found) throw new UserError("no account key for this passkey on this server");
  return found;
}

/** Recovery-code login (§2.5): the wraps filed under the recovery id. */
export async function loginWithCode(
  api: Api,
  codeText: string,
  progress: Progress,
): Promise<Unlocked> {
  let code: Uint8Array;
  try {
    code = P.parseRecoveryCode(codeText);
  } catch (e) {
    throw new UserError(message(e));
  }
  progress("unlocking…");
  const rk = P.recoveryKem(code);
  const found = unwrapFrom(await api.wraps(rk.id, null), "recovery", rk.id, rk, null);
  if (!found) throw new UserError("recovery code not recognised");
  return found;
}

/**
 * Adds a passkey to a signed-in account (§2.5): a credential bound to the same uid, then `POST /api/v2/wraps`.
 * `stillSignedIn` throws once the session ended. After a network error or 5xx the add succeeded iff the exact record
 * is listed by `GET /api/v2/dir/wraps/{id}?uid=`; a 400 or 409 is never success (§10.6).
 */
export async function addPasskeyTo(
  api: Api,
  pk: Passkeys,
  acc: { uid: Uint8Array; AK: Uint8Array; id: P.Identity; handle: string },
  progress: Progress,
  stillSignedIn: () => void,
): Promise<void> {
  const { credId, prf } = await newPasskey(pk, acc.uid, acc.handle || "segv", progress);
  stillSignedIn();
  const wrap = P.makeWrap(
    acc.uid,
    "passkey",
    credId,
    P.credKem(prf, credId),
    acc.AK,
    acc.id,
    Date.now(),
  );
  try {
    await api.postWrap(wrap, progress);
  } catch (e) {
    if (!isTransient(e)) {
      await pk.platform.forget(pk.rpId, credId);
      throw e;
    }
    let listed = false;
    try {
      listed = (await api.wraps(credId, acc.uid)).some(
        (w) => w.record === wrap.record && w.sig === wrap.sig,
      );
    } catch {
      throw e;
    }
    if (!listed) throw e;
  }
}

/**
 * §2.4 Unlock: opens the records for `id` with the unlock key. Wraps are bound to the unlock secret (`auth`), so a
 * record filed by someone else under our public id cannot open; the opened AK must re-derive the record's signing
 * key. If records of more than one account open, refuse instead of guessing.
 */
export function unwrapFrom(
  wraps: readonly Pick<DirWrapJson, "record" | "sig">[],
  kind: P.WrapKind,
  id: Uint8Array,
  key: P.UnlockKey,
  expectUid: Uint8Array | null,
): Unlocked | null {
  let found: Unlocked | null = null;
  for (const w of wraps) {
    let rec: P.WrapRecord;
    let AK: Uint8Array;
    try {
      rec = P.parseWrap(w.record, w.sig);
      if (rec.kind !== kind || !P.equalBytes(rec.id, id)) continue;
      if (expectUid && rec.uid !== P.b64u(expectUid)) continue;
      AK = P.openWrap(rec, key);
      if (!P.verify(P.fromB64u(w.sig), P.wrapSigMsg(w.record), P.deriveIdentity(AK).sigPk))
        continue;
    } catch {
      continue; // not ours, or corrupted: try the next one
    }
    const uid = P.fromB64u(rec.uid);
    if (found && !P.equalBytes(found.uid, uid))
      throw new UserError("this key opens more than one account; refusing to guess");
    found ??= { AK, uid };
  }
  return found;
}

// ───────────────────────── aliases (§2.6) ─────────────────────────

/** What a device derives for alias i of an owner: its account key, uid and keys (§2.6 "Keys"). */
export interface AliasKeys {
  i: number;
  AK: Uint8Array;
  uid: Uint8Array;
  uidB: string;
  id: P.Identity;
}

export function aliasKeys(AK: Uint8Array, i: number): AliasKeys {
  const AKi = P.aliasKey(AK, i);
  const uid = P.aliasUid(AKi);
  return { i, AK: AKi, uid, uidB: P.b64u(uid), id: P.deriveIdentity(AKi) };
}

/**
 * A directory entry is alias `k`'s (§2.6): registered under its uid, with a valid bundle of exactly its derived keys,
 * and a handle that is `aliasHandle` of them for some c.
 */
export function isAliasEntry(u: UserJson | null, k: AliasKeys): boolean {
  if (!u) return false;
  try {
    const b = P.verifyBundle(u.bundle, u.sig);
    return (
      u.uid === k.uidB &&
      b.uid === k.uidB &&
      b.handle === u.handle &&
      P.equalBytes(b.sigPk, k.id.sigPk) &&
      P.equalBytes(b.kemPk, k.id.kemPk) &&
      P.aliasHandleTry(u.handle, k.uid, b.sigPk, b.kemPk) >= 0
    );
  } catch {
    return false;
  }
}

/** Exact lookups of an alias's uid tried this often when they fail transiently (§2.6 "Creating" step 4). */
const ALIAS_LOOKUPS = 5;

/** A random bundle `ts` of 53 bits (§2.6 "Bundle"): two creations, on two devices or one, never send the same body. */
export function aliasBundleTs(): number {
  const b = P.random(7);
  let x = b[0] & 0x1f;
  for (let k = 1; k < 7; k++) x = x * 256 + b[k];
  return x;
}

/** What registering an alias came to (§2.6 "Creating" steps 3–4). */
export interface AliasRegistration {
  /** another device registered it: this device's register request got no 200, so it writes no registration HEADS */
  exists: boolean;
  /** the `c` of its registered handle, which the table now holds */
  c: number;
  /** `x-segv-now` of the 200 that answered this device's own register request (§11.1), else null */
  regNow: number | null;
  /** its directory entry, when the lookup after a 409 read it */
  user: UserJson | null;
}

/**
 * §2.6 "Creating" steps 3–4 for alias `k`, whose table entry holds `c`: its bundle with that handle and a random `ts`,
 * kept for every resend, registered without wraps and sent again as §2.5 step 8 says (`api.register`). On a 409, an
 * exact lookup of its uid: registered with the derived keys and the handle of some c′ means that another device
 * registered it (`exists`; c′ written into the table by `setC` when it differs); not registered means that the handle
 * is taken (the next c written into the table by `setC`, then registered again, failing after c = 3). Anything else
 * fails with ALIAS_CREATE_FAILED. A transient failure that outlasts the resends or the lookups is thrown as it is, and
 * SessionEnded from `check`.
 */
export async function registerAlias(
  api: Api,
  k: AliasKeys,
  c0: number,
  progress: Progress,
  ctl: {
    wait(ms: number): Promise<void>;
    check(): void;
    retryBase: number;
    setC(c: number): Promise<void>;
  },
): Promise<AliasRegistration> {
  const ts = aliasBundleTs();
  for (let c = c0; c < P.ALIAS_TRIES;) {
    const handle = P.aliasHandle(k.uid, k.id.sigPk, k.id.kemPk, c);
    const { bundle, sig } = P.makeBundle(k.uid, handle, k.id, ts);
    let ok: { now: number | null } | null = null;
    try {
      ok = await api.register({ bundle, sig, wraps: [] }, progress);
    } catch (e) {
      ctl.check();
      if (isTransient(e)) throw e;
      if (!(e instanceof ApiError) || e.status !== 409) throw new UserError(ALIAS_CREATE_FAILED);
    }
    ctl.check();
    if (ok) return { exists: false, c, regNow: ok.now, user: null };
    // a 409: the uid is registered, or the handle is taken
    let u: UserJson | null = null;
    for (let attempt = 0; ; attempt++) {
      try {
        u = await api.userByUid(k.uid);
        break;
      } catch (e) {
        ctl.check();
        if (!isTransient(e)) throw new UserError(ALIAS_CREATE_FAILED);
        if (attempt + 1 >= ALIAS_LOOKUPS) throw e;
        await ctl.wait(ctl.retryBase * 2 ** attempt);
        ctl.check();
      }
    }
    ctl.check();
    if (u && isAliasEntry(u, k)) {
      const c1 = P.aliasHandleTry(u.handle, k.uid, k.id.sigPk, k.id.kemPk);
      if (c1 !== c) await ctl.setC(c1);
      ctl.check();
      return { exists: true, c: c1, regNow: null, user: u };
    }
    if (u || c + 1 >= P.ALIAS_TRIES) throw new UserError(ALIAS_CREATE_FAILED);
    c++;
    await ctl.setC(c);
    ctl.check();
  }
  throw new UserError(ALIAS_CREATE_FAILED);
}

// Accounts (docs/PROTOCOL-v2.md §2.4–§2.5): register, passkey and recovery login, adding a passkey, and unwrapFrom.
// Ported from v1's engine (3de5f5e:src/client/engine.ts) with the v2 directory lookups.
import * as P from "~/lib/proto";
import { ApiError, isTransient, type Api, type DirWrapJson, type Progress } from "./api";
import { UserError, message } from "./errors";
import { createPasskey, forgetCredential, prfForCredential, signInWithPasskey } from "./webauthn";

/** What a successful unlock yields. */
export interface Unlocked {
  AK: Uint8Array;
  uid: Uint8Array;
}

const NO_PRF =
  "this passkey provider does not support the WebAuthn PRF extension, so it cannot hold encryption keys. " +
  "try iCloud Keychain, Google Password Manager, Windows Hello (Windows 11 24H2+) or a FIDO2 security key.";

/** §2.5 step 1: trim, lowercase, strip one leading "@". */
export function normaliseHandle(handleIn: string): string {
  return handleIn.trim().toLowerCase().replace(/^@/, "");
}

/** Creates a passkey for `uid` and returns its id and PRF secret, asking a second time when needed (§2.5 step 5). */
async function newPasskey(
  uid: Uint8Array,
  name: string,
  progress: Progress,
): Promise<{ credId: Uint8Array; prf: Uint8Array }> {
  progress("creating passkey…");
  const { credId, prf: prf0 } = await createPasskey(uid, name);
  let prf = prf0;
  if (!prf) {
    progress("confirm the passkey once more to derive your keys…");
    prf = await prfForCredential(credId);
  }
  if (!prf) {
    await forgetCredential(credId);
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
  handleIn: string,
  progress: Progress,
): Promise<Unlocked & { handle: string; recoveryCode: string; regNow: number | null }> {
  const handle = normaliseHandle(handleIn);
  if (!P.HANDLE_RE.test(handle)) throw new UserError("handle must be 3–20 characters: a–z, 0–9, _");
  progress("checking handle…");
  if (await api.userByHandle(handle, true)) throw new UserError(`@${handle} is taken`);
  const AK = P.random(32);
  const uid = P.random(16);
  const id = P.deriveIdentity(AK);
  const { bundle, sig } = P.makeBundle(uid, handle, id, Date.now());
  const { credId, prf } = await newPasskey(uid, handle, progress);
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
    regNow = (await api.register({ bundle, sig, wraps }, progress)).now;
  } catch (e) {
    // A definitive rejection (4xx): the account does not exist, so the new passkey is useless (§2.5 step 7).
    if (e instanceof ApiError && !e.transient) {
      await forgetCredential(credId);
      if (e.status === 409) throw new UserError(`@${handle} is taken`);
      throw e;
    }
    // A network error or 5xx: the server may have committed before the response was lost (§2.5 step 8). It landed
    // only if the directory returns exactly this bundle for the handle.
    progress("checking whether the account was created…");
    let landed: Awaited<ReturnType<Api["userByHandle"]>>;
    try {
      landed = await api.userByHandle(handle, true);
    } catch {
      throw e;
    }
    if (!landed || landed.bundle !== bundle) {
      if (landed) await forgetCredential(credId);
      throw e;
    }
  }
  return { AK, uid, handle, recoveryCode: P.formatRecoveryCode(code), regNow };
}

/** Discoverable passkey login (§2.5): the wraps filed under the credential id (and the user handle, if any). */
export async function loginWithPasskey(api: Api, progress: Progress): Promise<Unlocked> {
  progress("waiting for passkey…");
  const { credId, uid, prf } = await signInWithPasskey();
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
  acc: { uid: Uint8Array; AK: Uint8Array; id: P.Identity; handle: string },
  progress: Progress,
  stillSignedIn: () => void,
): Promise<void> {
  const { credId, prf } = await newPasskey(acc.uid, acc.handle || "segv", progress);
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
      await forgetCredential(credId);
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

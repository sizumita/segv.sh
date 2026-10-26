// Passkeys with the WebAuthn PRF extension (docs/PROTOCOL.md §2.4–2.5). Browser only.
// The PRF output never leaves this module's callers; nothing here talks to the server.
import * as P from "~/lib/proto";

const prfInput = () => P.utf8(P.PRF_INPUT);

/** Normalises the PRF result (ArrayBuffer, typed array, or the plain Array some extensions return). */
function toBytes(x: unknown): Uint8Array | null {
  if (x instanceof ArrayBuffer) return new Uint8Array(x.slice(0));
  if (ArrayBuffer.isView(x))
    return new Uint8Array(x.buffer.slice(x.byteOffset, x.byteOffset + x.byteLength));
  if (Array.isArray(x) && x.every((v) => Number.isInteger(v) && v >= 0 && v < 256))
    return Uint8Array.from(x);
  return null;
}

function prfFirst(cred: PublicKeyCredential): Uint8Array | null {
  const ext = cred.getClientExtensionResults() as { prf?: { results?: { first?: unknown } } };
  const out = toBytes(ext.prf?.results?.first);
  return out && out.length === 32 ? out : null;
}

/** true/false when the browser can tell, null when unknown. Only says the *browser* supports PRF. */
export async function prfCapability(): Promise<boolean | null> {
  try {
    if (typeof PublicKeyCredential === "undefined") return false;
    const get = (
      PublicKeyCredential as unknown as {
        getClientCapabilities?: () => Promise<Record<string, boolean>>;
      }
    ).getClientCapabilities;
    if (!get) return null;
    const caps = await get.call(PublicKeyCredential);
    return typeof caps["extension:prf"] === "boolean" ? caps["extension:prf"] : null;
  } catch {
    return null;
  }
}

const rpId = () => location.hostname;

export class PasskeyError extends Error {}

function explain(e: unknown): Error {
  if (e instanceof DOMException) {
    if (e.name === "NotAllowedError")
      return new PasskeyError("passkey prompt was cancelled or timed out");
    if (e.name === "InvalidStateError")
      return new PasskeyError("this passkey is already registered");
    if (e.name === "SecurityError")
      return new PasskeyError("passkeys are not allowed on this origin (needs https or localhost)");
    return new PasskeyError(`passkey error: ${e.name}`);
  }
  return e instanceof Error ? e : new PasskeyError(String(e));
}

/** Creates a discoverable passkey bound to `uid`. Returns the PRF output if the authenticator gave it at creation. */
export async function createPasskey(
  uid: Uint8Array,
  handle: string,
): Promise<{ credId: Uint8Array; prf: Uint8Array | null }> {
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId(), name: "segv.sh" },
        user: { id: uid as BufferSource, name: handle, displayName: handle },
        challenge: P.random(32) as BufferSource,
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        attestation: "none",
        timeout: 180_000,
        extensions: {
          prf: { eval: { first: prfInput() as BufferSource } },
        } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (e) {
    throw explain(e);
  }
  if (!cred) throw new PasskeyError("no passkey was created");
  return { credId: new Uint8Array(cred.rawId.slice(0)), prf: prfFirst(cred) };
}

/** Evaluates the PRF for a specific credential (second ceremony after registration). */
export async function prfForCredential(credId: Uint8Array): Promise<Uint8Array | null> {
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        rpId: rpId(),
        challenge: P.random(32) as BufferSource,
        allowCredentials: [{ type: "public-key", id: credId as BufferSource }],
        userVerification: "required",
        timeout: 180_000,
        extensions: {
          prf: { eval: { first: prfInput() as BufferSource } },
        } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (e) {
    throw explain(e);
  }
  return cred ? prfFirst(cred) : null;
}

/** Discoverable sign-in: the user picks a passkey; returns its id, user handle (= uid) and PRF output. */
export async function signInWithPasskey(): Promise<{
  credId: Uint8Array;
  uid: Uint8Array | null;
  prf: Uint8Array | null;
}> {
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        rpId: rpId(),
        challenge: P.random(32) as BufferSource,
        allowCredentials: [],
        userVerification: "required",
        timeout: 180_000,
        extensions: {
          prf: { eval: { first: prfInput() as BufferSource } },
        } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (e) {
    throw explain(e);
  }
  if (!cred) throw new PasskeyError("no passkey was selected");
  const resp = cred.response as AuthenticatorAssertionResponse;
  const uid = resp.userHandle ? new Uint8Array(resp.userHandle.slice(0)) : null;
  return { credId: new Uint8Array(cred.rawId.slice(0)), uid, prf: prfFirst(cred) };
}

/** Best effort: tell the passkey provider a credential is useless (e.g. registration failed after creating it). */
export async function forgetCredential(credId: Uint8Array): Promise<void> {
  try {
    const signal = (
      PublicKeyCredential as unknown as {
        signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
      }
    ).signalUnknownCredential;
    await signal?.call(PublicKeyCredential, { rpId: rpId(), credentialId: P.b64u(credId) });
  } catch {
    /* unsupported */
  }
}

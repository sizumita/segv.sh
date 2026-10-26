// X25519 for invite scanning. Every client runs one X25519 per invite row in the log, so this is
// the hot path of a fresh sync. Uses native WebCrypto X25519 when available (self-tested against
// @noble/curves once), otherwise falls back to noble.
import { x25519 } from "@noble/curves/ed25519.js";
import * as P from "~/lib/proto";

export type Scanner = (eph: Uint8Array) => Promise<Uint8Array | null>;

async function webcryptoScanner(scanSk: Uint8Array): Promise<Scanner | null> {
  try {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) return null;
    const jwk: JsonWebKey = {
      kty: "OKP",
      crv: "X25519",
      d: P.b64u(scanSk),
      x: P.b64u(x25519.getPublicKey(scanSk)),
    };
    const priv = await subtle.importKey("jwk", jwk, { name: "X25519" }, false, ["deriveBits"]);
    const derive = async (eph: Uint8Array) => {
      const pub = await subtle.importKey("raw", eph as BufferSource, { name: "X25519" }, false, []);
      return new Uint8Array(
        await subtle.deriveBits(
          { name: "X25519", public: pub } as unknown as AlgorithmIdentifier,
          priv,
          256,
        ),
      );
    };
    // Self-test: must agree with noble for a random point.
    const probe = x25519.getPublicKey(x25519.utils.randomSecretKey());
    if (!P.equalBytes(await derive(probe), x25519.getSharedSecret(scanSk, probe))) return null;
    return async (eph) => {
      try {
        return await derive(eph);
      } catch {
        return null; // invalid / low-order point
      }
    };
  } catch {
    return null;
  }
}

export async function makeScanner(scanSk: Uint8Array): Promise<Scanner> {
  const fast = await webcryptoScanner(scanSk);
  if (fast) return fast;
  return async (eph) => {
    try {
      return x25519.getSharedSecret(scanSk, eph);
    } catch {
      return null;
    }
  };
}

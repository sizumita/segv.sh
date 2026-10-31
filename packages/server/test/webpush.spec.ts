/** Web Push primitives (docs/PROTOCOL.md §9.8): RFC 8291 encryption, the VAPID key and JWT, the payload. */
import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";
import * as P from "@segv/protocol/proto";
import {
  VapidSigner,
  encryptPayload,
  isP256Point,
  parseVapidKey,
  pushPayload,
  vapidPublicKey,
} from "../src/webpush";

const b = (s: string): Uint8Array => P.fromB64u(s.replace(/\s+/g, ""));
const hexB = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((x) => parseInt(x, 16)));
const N = p256.Point.Fn.ORDER;
const scalar = (x: bigint): Uint8Array => hexB(x.toString(16).padStart(64, "0"));

/** A user agent's key pair, its public key uncompressed (as `getKey("p256dh")` gives it). */
function uaKeys(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = p256.utils.randomSecretKey();
  return { secretKey, publicKey: p256.getPublicKey(secretKey, false) };
}

/** The receiving side of RFC 8291 (one record), to check what encryptPayload produced. */
function decryptPayload(body: Uint8Array, uaPrivate: Uint8Array, auth: Uint8Array): Uint8Array {
  const salt = body.subarray(0, 16);
  const rs = new DataView(body.buffer, body.byteOffset).getUint32(16);
  expect(rs).toBe(4096);
  expect(body[20]).toBe(65);
  const asPublic = body.subarray(21, 86);
  const uaPublic = p256.getPublicKey(uaPrivate, false);
  const ecdh = p256.getSharedSecret(uaPrivate, asPublic, true).subarray(1);
  const one = Uint8Array.of(1);
  const prkKey = P.HMAC(auth, ecdh);
  const ikm = P.HMAC(prkKey, P.concat(P.utf8("WebPush: info\0"), uaPublic, asPublic, one));
  const prk = P.HMAC(salt, ikm);
  const cek = P.HMAC(prk, P.concat(P.utf8("Content-Encoding: aes128gcm\0"), one)).slice(0, 16);
  const nonce = P.HMAC(prk, P.concat(P.utf8("Content-Encoding: nonce\0"), one)).slice(0, 12);
  const padded = gcm(cek, nonce).decrypt(body.subarray(86));
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end--;
  expect(padded[end]).toBe(2); // the last record's delimiter
  return padded.slice(0, end);
}

// RFC 8291 §5 and Appendix A.
const RFC = {
  plaintext: "When I grow up, I want to be a watermelon",
  auth: b("BTBZMqHH6r4Tts7J_aSIgg"),
  salt: b("DGv6ra1nlYgDCS1FRnbzlw"),
  asPrivate: b("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"),
  asPublic: b("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"),
  uaPrivate: b("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"),
  uaPublic: b("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
  header: b("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8"),
  ciphertext: b("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs bI_0LpXMuGvnzQ"),
  body: b(
    "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
      "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
      "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
  ),
};

describe("encryptPayload (RFC 8291)", () => {
  it("reproduces RFC 8291 Appendix A byte for byte", async () => {
    // The vectors agree with each other.
    expect(p256.getPublicKey(RFC.asPrivate, false)).toEqual(RFC.asPublic);
    expect(p256.getPublicKey(RFC.uaPrivate, false)).toEqual(RFC.uaPublic);
    expect(RFC.body).toEqual(P.concat(RFC.header, RFC.ciphertext));
    const body = await encryptPayload(P.utf8(RFC.plaintext), RFC.uaPublic, RFC.auth, {
      salt: RFC.salt,
      asPrivate: RFC.asPrivate,
    });
    expect(body.length).toBe(86 + RFC.plaintext.length + 1 + 16);
    expect(body).toEqual(RFC.body);
    expect(P.fromUtf8(decryptPayload(RFC.body, RFC.uaPrivate, RFC.auth))).toBe(RFC.plaintext);
  });

  it("round-trips the payload with a fresh key pair and salt per push", async () => {
    const ua = uaKeys();
    const auth = P.random(16);
    const payload = pushPayload("segv.test");
    const a = await encryptPayload(payload, ua.publicKey, auth);
    const c = await encryptPayload(payload, ua.publicKey, auth);
    expect(decryptPayload(a, ua.secretKey, auth)).toEqual(payload);
    expect(decryptPayload(c, ua.secretKey, auth)).toEqual(payload);
    expect(a.subarray(0, 16)).not.toEqual(c.subarray(0, 16)); // salt
    expect(a.subarray(21, 86)).not.toEqual(c.subarray(21, 86)); // as_public
    expect(isP256Point(a.subarray(21, 86))).toBe(true);
  });

  it("refuses a bad p256dh, a bad auth and a payload over one record", async () => {
    const ua = uaKeys();
    const auth = P.random(16);
    await expect(encryptPayload(P.utf8("x"), ua.publicKey.subarray(1), auth)).rejects.toThrow();
    await expect(encryptPayload(P.utf8("x"), ua.publicKey, P.random(15))).rejects.toThrow();
    await expect(encryptPayload(new Uint8Array(4096 - 17), ua.publicKey, auth)).resolves.toBeInstanceOf(Uint8Array);
    await expect(encryptPayload(new Uint8Array(4096 - 16), ua.publicKey, auth)).rejects.toThrow();
  });
});

describe("pushPayload", () => {
  const zero = "A".repeat(86); // b64u of 64 zero bytes
  it("is the text of §9.8, with the bells zero-padded to 64 bytes", () => {
    expect(P.fromUtf8(pushPayload("segv.sh"))).toBe(
      `{"web_push":8030,"mutable":true,"notification":{"title":"segv.sh","body":"new messages","navigate":"https://segv.sh/","tag":"segv","data":{"bells":"${zero}"}}}`,
    );
    const b1 = P.random(16);
    const b2 = P.random(16);
    const j = JSON.parse(P.fromUtf8(pushPayload("segv.test", [b1, b2]))) as Record<string, unknown>;
    expect(j).toEqual({
      web_push: 8030,
      mutable: true,
      notification: {
        title: "segv.sh",
        body: "new messages",
        navigate: "https://segv.test/",
        tag: "segv",
        data: { bells: P.b64u(P.concat(b1, b2, new Uint8Array(32))) },
      },
    });
  });

  it("has the same length for 0 to 4 bells, keeps the first 4 of more, and refuses a bell that is not 16 bytes", () => {
    const lens = [0, 1, 2, 3, 4, 6].map((n) => pushPayload("segv.sh", Array.from({ length: n }, () => P.random(16))).length);
    expect(new Set(lens).size).toBe(1);
    const bs = Array.from({ length: 6 }, () => P.random(16));
    const j = JSON.parse(P.fromUtf8(pushPayload("segv.sh", bs))) as { notification: { data: { bells: string } } };
    expect(j.notification.data.bells).toBe(P.b64u(P.concat(...bs.slice(0, 4))));
    expect(() => pushPayload("segv.sh", [P.random(15)])).toThrow();
  });
});

describe("VAPID key", () => {
  it("accepts exactly the scalars 1 ≤ d < n", () => {
    expect(parseVapidKey(P.b64u(scalar(0n)))).toBeNull();
    expect(parseVapidKey(P.b64u(scalar(N)))).toBeNull();
    expect(parseVapidKey(P.b64u(scalar(N + 1n)))).toBeNull();
    expect(parseVapidKey(P.b64u(scalar(1n)))).toEqual(scalar(1n));
    expect(parseVapidKey(P.b64u(scalar(N - 1n)))).toEqual(scalar(N - 1n));
    expect(parseVapidKey(` ${P.b64u(scalar(7n))}\n`)).toEqual(scalar(7n));
    expect(parseVapidKey(P.b64u(P.random(31)))).toBeNull();
    expect(parseVapidKey(P.b64u(P.concat(Uint8Array.of(0), scalar(5n))))).toBeNull(); // 33 bytes
    expect(parseVapidKey("not base64url!")).toBeNull();
    expect(parseVapidKey(`${P.b64u(scalar(5n))}=`)).toBeNull();
    expect(parseVapidKey("")).toBeNull();
  });

  it("derives [d]G uncompressed", () => {
    const G = hexB(
      "04" +
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    expect(vapidPublicKey(scalar(1n))).toEqual(G);
    const k = uaKeys();
    expect(vapidPublicKey(k.secretKey)).toEqual(k.publicKey);
    expect(vapidPublicKey(k.secretKey).length).toBe(65);
  });
});

describe("isP256Point", () => {
  it("accepts on-curve uncompressed points only", () => {
    const G = vapidPublicKey(scalar(1n));
    expect(isP256Point(G)).toBe(true);
    expect(isP256Point(uaKeys().publicKey)).toBe(true);
    const off = G.slice();
    off[64] ^= 1;
    expect(isP256Point(off)).toBe(false);
    expect(isP256Point(G.subarray(1))).toBe(false); // 64 bytes
    const c = G.slice();
    c[0] = 0x02;
    expect(isP256Point(c)).toBe(false);
    expect(isP256Point(p256.getPublicKey(scalar(1n), true))).toBe(false); // compressed, 33 bytes
    expect(isP256Point(new Uint8Array(65))).toBe(false);
  });
});

describe("VapidSigner (RFC 8292)", () => {
  const parse = (h: string) => {
    const m = /^vapid t=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+), k=([A-Za-z0-9_-]+)$/.exec(h);
    expect(m).not.toBeNull();
    const [, hd, cl, sg, k] = m!;
    return { hd, cl, sg, k, signing: `${hd}.${cl}` };
  };

  it("signs an ES256 JWT with the exact header and claims", async () => {
    const d = parseVapidKey(P.b64u(p256.utils.randomSecretKey()))!;
    const signer = new VapidSigner(d, "mailto:ops@segv.test");
    expect(signer.publicKey).toEqual(vapidPublicKey(d));
    const now = 1_800_000_000_123;
    const h = await signer.authorization("https://web.push.apple.com", now);
    const { hd, cl, sg, k, signing } = parse(h);
    expect(P.fromUtf8(P.fromB64u(hd))).toBe('{"typ":"JWT","alg":"ES256"}');
    const claims = JSON.parse(P.fromUtf8(P.fromB64u(cl))) as Record<string, unknown>;
    expect(claims).toEqual({ aud: "https://web.push.apple.com", exp: Math.floor(now / 1000) + 12 * 3600, sub: "mailto:ops@segv.test" });
    expect(claims.exp as number).toBeLessThanOrEqual(now / 1000 + 12 * 3600);
    expect(P.fromB64u(k)).toEqual(signer.publicKey);
    const sig = P.fromB64u(sg);
    expect(sig.length).toBe(64);
    expect(p256.verify(sig, P.utf8(signing), signer.publicKey, { lowS: false })).toBe(true);
    // And by WebCrypto, as a push service would check it.
    const buf = (x: Uint8Array): BufferSource => x as Uint8Array<ArrayBuffer>;
    const key = await crypto.subtle.importKey("raw", buf(signer.publicKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buf(sig), buf(P.utf8(signing)))).toBe(true);
  });

  it("reuses a JWT per aud until one hour before its exp", async () => {
    const signer = new VapidSigner(p256.utils.randomSecretKey(), "https://segv.test/contact");
    const t0 = 1_800_000_000_000;
    const a = await signer.authorization("https://fcm.googleapis.com", t0);
    expect(await signer.authorization("https://fcm.googleapis.com", t0 + 3600_000)).toBe(a);
    expect(await signer.authorization("https://fcm.googleapis.com", t0 + 11 * 3600_000 - 1000)).toBe(a);
    const later = await signer.authorization("https://fcm.googleapis.com", t0 + 11 * 3600_000);
    expect(later).not.toBe(a);
    const exp = (JSON.parse(P.fromUtf8(P.fromB64u(parse(later).cl))) as { exp: number }).exp;
    expect(exp).toBe(Math.floor(t0 / 1000) + 23 * 3600);
    const other = await signer.authorization("https://updates.push.services.mozilla.com", t0);
    expect(other).not.toBe(a);
    expect((JSON.parse(P.fromUtf8(P.fromB64u(parse(other).cl))) as { aud: string }).aud).toBe(
      "https://updates.push.services.mozilla.com",
    );
  });
});

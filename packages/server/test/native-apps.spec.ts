/**
 * The server side of the native apps (docs/PROTOCOL.md §9.7 "App origins", §10.1 "Cross-origin requests", §10.8,
 * §11.14 "Association files"): APP_ORIGINS, the CORS headers and preflights, the realtime socket's Origin rule, and
 * the association files. Through ../entry.ts (api) where the Worker entry matters, through handleApi (direct) or the
 * module functions where a setting is replaced.
 */
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import * as W from "@segv/protocol/wire";
import { _resetSettingLogsForTests } from "../src/env";
import { parseAppOrigins } from "../src/origins";
import { AASA_PATH, ASSETLINKS_PATH, parseAndroidApps, parseAppleAppIds, wellKnown } from "../src/well-known";
import { ORIGIN, api, direct, envWith, errorOf, nowOf, powHeader, rtClient, rtUpgrade, sleep, until, type ApiInit } from "./helpers";

/** The APP_ORIGINS of ../wrangler.test.jsonc. */
const APP = ["tauri://localhost", "https://tauri.localhost", "capacitor://app.segv.test", "https://app.segv.test"];
/** Origins that are not app origins: other sites, the deployment's own origin, and near misses of the app origins. */
const FOREIGN = [
  "https://evil.example",
  ORIGIN,
  "null",
  "tauri://localhost.evil.example",
  "TAURI://localhost",
  "tauri://Localhost",
  "tauri://localhost/",
  "https://tauri.localhost:443",
  "http://tauri.localhost",
  "capacitor://app.segv.test.evil.example",
];
const CORS = ["access-control-allow-origin", "access-control-expose-headers", "vary"];
const PREFLIGHT = ["access-control-allow-methods", "access-control-allow-headers", "access-control-max-age"];

/** workerd's caches.default (the DOM lib typing does not know it). */
const edgeCache = (): Cache => (caches as unknown as { default: Cache }).default;

function expectCors(res: Response, origin: string, what: string): void {
  expect(res.headers.get("access-control-allow-origin"), what).toBe(origin);
  expect(res.headers.get("access-control-expose-headers"), what).toBe("x-segv-now, retry-after");
  expect(res.headers.get("vary"), what).toBe("origin");
  expect(res.headers.get("access-control-allow-credentials"), what).toBeNull();
}

function expectNoCors(res: Response, what: string): void {
  for (const h of [...CORS, ...PREFLIGHT, "access-control-allow-credentials"]) expect(res.headers.get(h), `${what}: ${h}`).toBeNull();
}

const withOrigin = (origin: string, init: ApiInit = {}): ApiInit => ({
  ...init,
  headers: { ...(init.headers as Record<string, string> | undefined), origin },
});

const preflight = (origin: string | null, method = "POST", extra: Record<string, string> = {}): ApiInit => ({
  method: "OPTIONS",
  headers: {
    ...(origin === null ? {} : { origin }),
    "access-control-request-method": method,
    "access-control-request-headers": "content-type, x-segv-pow",
    ...extra,
  },
});

/** A rate-limit binding that refuses every token and counts the calls. */
function denyAll() {
  const l = { calls: 0, limit: async (): Promise<{ success: boolean }> => (l.calls++, { success: false }) };
  return l;
}

/** console.error lines that mention `needle`, while `fn` runs. */
async function logsDuring(needle: string, fn: () => Promise<void>): Promise<string[]> {
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await fn();
    return log.mock.calls.map((c) => String(c[0])).filter((l) => l.includes(needle));
  } finally {
    log.mockRestore();
  }
}

beforeEach(() => _resetSettingLogsForTests());

// ───────────────────────────── APP_ORIGINS ─────────────────────────────

describe("APP_ORIGINS (§9.7)", () => {
  it("parses a list of https:, capacitor: and tauri: origins", () => {
    expect(parseAppOrigins("capacitor://app.segv.sh,https://app.segv.sh,tauri://localhost,https://tauri.localhost")).toEqual([
      "capacitor://app.segv.sh",
      "https://app.segv.sh",
      "tauri://localhost",
      "https://tauri.localhost",
    ]);
    expect(parseAppOrigins(" tauri://localhost , https://a-b.example.com,tauri://localhost")).toEqual(["tauri://localhost", "https://a-b.example.com"]);
    expect(parseAppOrigins(`https://${"a".repeat(63)}.example`)).toEqual([`https://${"a".repeat(63)}.example`]);
    const longest = `${Array.from({ length: 3 }, () => "a".repeat(63)).join(".")}.${"b".repeat(61)}`; // 253 characters
    expect(parseAppOrigins(`tauri://${longest}`)).toEqual([`tauri://${longest}`]);
    expect(parseAppOrigins(`tauri://${longest}b`)).toBeNull();
    // Unset or empty: no app origins, and nothing invalid.
    for (const raw of [undefined, null, "", "  "]) expect(parseAppOrigins(raw), String(raw)).toEqual([]);
  });

  it("refuses the whole list when any entry is not the serialization of such an origin", () => {
    const bad = [
      "http://app.segv.sh", // scheme
      "wss://app.segv.sh",
      "file://localhost",
      "https://app.segv.sh:443", // port
      "tauri://localhost:1430",
      "https://app.segv.sh/", // path
      "https://app.segv.sh/app",
      "tauri://localhost/index.html",
      "https://user@app.segv.sh", // userinfo
      "https://app.segv.sh?x=1", // query
      "https://app.segv.sh#x", // fragment
      "HTTPS://app.segv.sh", // not the serialization (lowercase)
      "https://App.segv.sh",
      "https://", // no host
      "tauri:localhost",
      "tauri:/localhost",
      "https://*.segv.sh",
      "https://-app.segv.sh",
      "https://app-.segv.sh",
      "https://app..segv.sh",
      "https://app.segv.sh.",
      "https://[::1]",
      `https://${"a".repeat(64)}.example`, // label over 63
      `https://${Array.from({ length: 64 }, () => "abc").join(".")}`, // host over 253
      "null",
      "*",
      "tauri://localhost,", // empty entry
      "tauri://localhost,,https://app.segv.sh",
      "tauri://localhost https://app.segv.sh",
      "tauri://localhost,https://app.segv.sh:8443", // one bad entry spoils the list
    ];
    for (const raw of bad) expect(parseAppOrigins(raw), raw).toBeNull();
    expect(parseAppOrigins(42)).toBeNull();
  });

  it("an invalid APP_ORIGINS counts as empty: the apps are refused, nothing else changes, and the setting is logged once by name", async () => {
    const value = "tauri://localhost,https://app.segv.test:8443";
    const over = { APP_ORIGINS: value };
    const lines = await logsDuring("native apps", async () => {
      for (const origin of APP) {
        const res = await direct("/api/v2/params", withOrigin(origin), over);
        expect(res.status).toBe(200);
        expectNoCors(res, origin);
        const pf = await direct("/api/v2/put", preflight(origin), over);
        expect(pf.status).toBe(405);
        expectNoCors(pf, origin);
        const ws = await direct("/api/v2/rt", { headers: { upgrade: "websocket", origin } }, over);
        expect(ws.status).toBe(403);
      }
    });
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual({ msg: "native apps are refused: invalid setting", setting: "APP_ORIGINS" });
    expect(lines[0]).not.toContain("tauri");
    // Unset or empty: refused too, and nothing is logged.
    for (const APP_ORIGINS of [undefined, ""]) {
      const quiet = await logsDuring("native apps", async () => {
        const res = await direct("/api/v2/params", withOrigin(APP[0]), { APP_ORIGINS });
        expect(res.status).toBe(200);
        expectNoCors(res, String(APP_ORIGINS));
      });
      expect(quiet).toEqual([]);
    }
  });
});

// ───────────────────────────── CORS ─────────────────────────────

describe("cross-origin requests (§10.1)", () => {
  it("an answer to an app origin carries allow-origin, expose-headers and vary; never allow-credentials", async () => {
    for (const origin of APP) {
      const res = await api("/api/v2/params", withOrigin(origin));
      expect(res.status).toBe(200);
      expectCors(res, origin, origin);
      nowOf(res);
    }
  });

  it("error answers carry them too: 404, 405, 403, 413, 426, 421, 429 and 503", async () => {
    const origin = APP[0];
    const E = P.era(Date.now());
    const deny = denyAll();
    const answers: [number, Response][] = [
      [404, await api("/api/v2/nope", withOrigin(origin))],
      [404, await api("/api/log", withOrigin(origin))],
      [405, await api("/api/v2/params", withOrigin(origin, { method: "POST", body: new Uint8Array(1) }))],
      [405, await api("/api/v2/params", withOrigin(origin, { method: "OPTIONS" }))], // OPTIONS that is not a preflight
      [403, await api("/api/v2/put", withOrigin(origin, { method: "POST", body: new Uint8Array(3) }))],
      [413, await api("/api/v2/put", withOrigin(origin, { method: "POST", body: new Uint8Array(W.PUT_MAX_BYTES + 1) }))],
      [426, await api("/api/v2/rt", withOrigin(origin))],
      [421, await api("/api/v2/params", withOrigin(origin, { origin: "https://elsewhere.example" }))],
      [429, await direct(`/api/v2/era/${E}`, withOrigin(origin), { RL_READ: deny })],
      [503, await direct("/api/v2/params", withOrigin(origin), { SRV_KEY: undefined })],
    ];
    for (const [status, res] of answers) {
      expect(res.status, `${status}`).toBe(status);
      expectCors(res, origin, `${status}`);
      nowOf(res);
      if (status === 429) expect(res.headers.get("retry-after")).not.toBeNull();
      await errorOf(res);
    }
  });

  it("an answer to any other origin, or to a request without Origin, carries none of these headers", async () => {
    for (const origin of FOREIGN) {
      const ok = await api("/api/v2/params", withOrigin(origin));
      expect(ok.status, origin).toBe(200);
      expectNoCors(ok, origin);
      const nf = await api("/api/v2/nope", withOrigin(origin));
      expect(nf.status, origin).toBe(404);
      expectNoCors(nf, origin);
    }
    const none = await api("/api/v2/params");
    expect(none.status).toBe(200);
    expectNoCors(none, "no Origin");
  });

  it("a preflight from an app origin is 204 with the allowed methods and headers, x-segv-now, and no body", async () => {
    const cases: [string, string][] = [
      ["/api/v2/put", "POST"],
      ["/api/v2/params", "GET"],
      [`/api/v2/blob/${P.b64u(P.random(32))}`, "PUT"],
      ["/api/v2/register", "POST"],
      ["/api/v2/push/sub", "POST"],
      ["/api/v2/rt", "GET"],
    ];
    for (const origin of APP) {
      for (const [path, method] of cases) {
        const what = `${origin} ${path}`;
        const res = await api(path, preflight(origin, method));
        expect(res.status, what).toBe(204);
        expect(res.headers.get("access-control-allow-origin"), what).toBe(origin);
        expect(res.headers.get("access-control-allow-methods"), what).toBe("GET, POST, PUT");
        expect(res.headers.get("access-control-allow-headers"), what).toBe("content-type, x-segv-pow");
        expect(res.headers.get("access-control-max-age"), what).toBe("600");
        expect(res.headers.get("vary"), what).toBe("origin");
        expect(res.headers.get("access-control-allow-credentials"), what).toBeNull();
        expect(res.headers.get("allow"), what).toBeNull();
        nowOf(res);
        expect((await res.arrayBuffer()).byteLength, what).toBe(0);
      }
    }
  });

  it("the preflight is answered before the rate limit and after the configuration check", async () => {
    const write = denyAll();
    const read = denyAll();
    const res = await direct("/api/v2/put", preflight(APP[0]), { RL_WRITE: write, RL_READ: read });
    expect(res.status).toBe(204);
    expect(write.calls + read.calls).toBe(0);
    const bad = await direct("/api/v2/put", preflight(APP[0]), { ROUTE_KEY: undefined });
    expect(bad.status).toBe(503);
    expectCors(bad, APP[0], "503");
    // Path before method: an unknown path, or a push path while push is off, is still a 404.
    const nf = await api("/api/v2/nope", preflight(APP[0]));
    expect(nf.status).toBe(404);
    expectCors(nf, APP[0], "404");
    const off = await direct("/api/v2/push/sub", preflight(APP[0]), { VAPID_SK: undefined });
    expect(off.status).toBe(404);
  });

  it("a preflight from any other origin, or without Origin, is a wrong method (405) without CORS headers", async () => {
    for (const origin of [...FOREIGN, null]) {
      const res = await api("/api/v2/put", preflight(origin));
      expect(res.status, String(origin)).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
      expectNoCors(res, String(origin));
      nowOf(res);
    }
  });

  it("a cached answer gets them on the way out; the stored copy has none of them", async () => {
    const origin = APP[1];
    const { blob, id } = P.encryptBlob(P.utf8("cors and caches"));
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
    const put = await api(
      `/api/v2/blob/${id}`,
      withOrigin(origin, { method: "PUT", body: blob, headers: { "content-type": "application/octet-stream", "x-segv-pow": pow } }),
    );
    expect(put.status, await put.clone().text()).toBe(201);
    expectCors(put, origin, "201");
    const g1 = await api(`/api/v2/blob/${id}`, withOrigin(origin));
    expect(g1.status).toBe(200);
    expectCors(g1, origin, "first GET");
    const key = `${ORIGIN}/api/v2/blob/${id}`;
    let stored: Response | undefined;
    await until(async () => (stored = await edgeCache().match(key)) !== undefined, "cache entry", 3000);
    for (const h of [...CORS, "x-segv-now"]) expect(stored!.headers.get(h), h).toBeNull();
    await stored!.arrayBuffer();
    // Gone from R2: only caches.default can answer now.
    await env.BLOBS.delete(`b/${id}`);
    await sleep(10);
    const g2 = await api(`/api/v2/blob/${id}`, withOrigin(origin));
    expect(g2.status).toBe(200);
    expect(new Uint8Array(await g2.arrayBuffer())).toEqual(blob);
    expectCors(g2, origin, "cached GET");
    nowOf(g2);
    const other = await api(`/api/v2/blob/${id}`, withOrigin(APP[2]));
    expectCors(other, APP[2], "cached GET, another app origin");
    const foreign = await api(`/api/v2/blob/${id}`, withOrigin("https://evil.example"));
    expect(foreign.status).toBe(200);
    expectNoCors(foreign, "cached GET, foreign origin");
    const again = await edgeCache().match(key);
    for (const h of CORS) expect(again?.headers.get(h), h).toBeNull();
    await again?.arrayBuffer();
    await edgeCache().delete(key);
  });
});

// ───────────────────────────── realtime ─────────────────────────────

describe("realtime Origin (§10.8)", () => {
  it("accepts the socket of an app origin, with a 101 that carries no CORS headers", async () => {
    for (const origin of APP) {
      const res = await rtUpgrade({ origin });
      expect(res.status, origin).toBe(101);
      expectNoCors(res, origin);
      const c = rtClient(res.webSocket!);
      try {
        await c.until(() => c.hello !== null, "HELLO");
      } finally {
        c.close();
      }
    }
  });

  it("refuses any other foreign origin with 403, which an app origin cannot read", async () => {
    for (const origin of FOREIGN.filter((o) => o !== ORIGIN)) {
      const res = await rtUpgrade({ origin });
      expect(res.status, origin).toBe(403);
      expectNoCors(res, origin);
      expect(await errorOf(res)).toMatch(/cross-origin/);
    }
  });
});

// ───────────────────────────── association files ─────────────────────────────

const FP1 = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5";
const FP2 = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

/** wellKnown() with some settings replaced, on the canonical test host. */
function wk(path: string, overrides: Record<string, unknown> = {}, method = "GET"): Response | null {
  const url = new URL(`${ORIGIN}${path}`);
  return wellKnown(new Request(url, { method }), envWith(overrides), url);
}

describe("association files (§11.14)", () => {
  it("serves apple-app-site-association at the canonical host: the app IDs for webcredentials and for applinks on /", async () => {
    const res = await api(AASA_PATH, { headers: { origin: APP[0] } });
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expectNoCors(res, "AASA");
    const ids = ["ABCDE12345.test.segv.desktop", "ABCDE12345.test.segv.ios"];
    expect(await res.json()).toEqual({
      applinks: { details: [{ appIDs: ids, components: [{ "/": "/" }] }] },
      webcredentials: { apps: ids },
    });
  });

  it("serves assetlinks.json: get_login_creds and handle_all_urls for each package and its fingerprints", async () => {
    const relation = ["delegate_permission/common.get_login_creds", "delegate_permission/common.handle_all_urls"];
    const res = await api(ASSETLINKS_PATH);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    expectNoCors(res, "assetlinks");
    expect(await res.json()).toEqual([
      { relation, target: { namespace: "android_app", package_name: "test.segv.app", sha256_cert_fingerprints: [FP1] } },
    ]);
    const two = wk(ASSETLINKS_PATH, { ANDROID_APPS: `sh.segv.app@${FP1}, sh.segv.app@${FP2},sh.segv.beta@${FP2}` })!;
    expect(await two.json()).toEqual([
      { relation, target: { namespace: "android_app", package_name: "sh.segv.app", sha256_cert_fingerprints: [FP1, FP2] } },
      { relation, target: { namespace: "android_app", package_name: "sh.segv.beta", sha256_cert_fingerprints: [FP2] } },
    ]);
  });

  it("HEAD has no body; other methods are 405; other paths are not association files", async () => {
    const head = wk(AASA_PATH, {}, "HEAD")!;
    expect(head.status).toBe(200);
    expect(head.body).toBeNull();
    const post = wk(AASA_PATH, {}, "POST")!;
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
    for (const path of ["/.well-known/apple-app-site-association/", "/apple-app-site-association", "/.well-known/assetlinks", "/"]) {
      expect(wk(path), path).toBeNull();
    }
  });

  it("an unset or empty setting makes its file a 404, without a log line", async () => {
    const lines = await logsDuring("association file", async () => {
      for (const v of [undefined, "", " "]) {
        const a = wk(AASA_PATH, { APPLE_APP_IDS: v })!;
        expect(a.status, String(v)).toBe(404);
        expect(a.headers.get("cache-control")).toBe("no-store");
        expect(wk(ASSETLINKS_PATH, { ANDROID_APPS: v })!.status, String(v)).toBe(404);
      }
    });
    expect(lines).toEqual([]);
  });

  it("an invalid setting makes its file a 404, logged once by name, never by value", async () => {
    const appleBad = [
      "nbdp5vk335.sh.segv.desktop", // Team ID in lowercase
      "NBDP5VK33.sh.segv.desktop", // 9 characters
      "NBDP5VK3355.sh.segv.desktop", // 11 characters
      "NBDP5VK335", // no bundle ID
      "NBDP5VK335.",
      "NBDP5VK335.sh..desktop",
      "NBDP5VK335.sh.segv_desktop",
      `NBDP5VK335.${"a".repeat(156)}`,
      "NBDP5VK335.sh.segv.desktop,",
      "NBDP5VK335.sh.segv.desktop;NBDP5VK335.sh.segv.ios",
    ];
    const androidBad = [
      `sh.segv.app${FP1}`, // no @
      `sh.segv.app@${FP1.toLowerCase()}`,
      `sh.segv.app@${FP1.slice(3)}`, // 31 pairs
      `sh.segv.app@${FP1}:00`, // 33 pairs
      `sh.segv.app@${FP1.replaceAll(":", "")}`,
      `app@${FP1}`, // one segment
      `sh.1segv.app@${FP1}`,
      `sh.segv.app@${FP1},`,
    ];
    for (const raw of appleBad) expect(parseAppleAppIds(raw), raw).toBeNull();
    for (const raw of androidBad) expect(parseAndroidApps(raw), raw).toBeNull();
    expect(parseAppleAppIds("NBDP5VK335.sh.segv.desktop, NBDP5VK335.sh.segv-ios")).toEqual(["NBDP5VK335.sh.segv.desktop", "NBDP5VK335.sh.segv-ios"]);
    const lines = await logsDuring("association file", async () => {
      for (const raw of appleBad) expect(wk(AASA_PATH, { APPLE_APP_IDS: raw })!.status, raw).toBe(404);
      for (const raw of androidBad) expect(wk(ASSETLINKS_PATH, { ANDROID_APPS: raw })!.status, raw).toBe(404);
      // The other file is unaffected.
      expect(wk(ASSETLINKS_PATH, { APPLE_APP_IDS: appleBad[0] })!.status).toBe(200);
    });
    expect(lines.map((l) => JSON.parse(l))).toEqual([
      { msg: "association file not served: invalid setting", setting: "APPLE_APP_IDS" },
      { msg: "association file not served: invalid setting", setting: "ANDROID_APPS" },
    ]);
    for (const l of lines) expect(l).not.toMatch(/NBDP|segv\.app/);
  });
});

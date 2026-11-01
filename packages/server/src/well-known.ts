/**
 * The native apps' association files (docs/PROTOCOL.md §11.14, "Association files"), which the Worker serves after
 * host pinning, so at the canonical host:
 *  - /.well-known/apple-app-site-association from APPLE_APP_IDS, comma-separated app IDs `<Team ID>.<bundle ID>`
 *    (the Team ID is 10 uppercase letters or digits): `webcredentials.apps` lists them, for passkeys, and `applinks`
 *    names them for the path `/`;
 *  - /.well-known/assetlinks.json from ANDROID_APPS, comma-separated `<package name>@<fingerprint>`, the SHA-256
 *    fingerprint of the app's signing certificate as 32 colon-separated pairs of uppercase hex digits: the statements
 *    get_login_creds, for passkeys, and handle_all_urls.
 * Each is a 200 `application/json` that names the apps and nothing else, never a redirect (Apple's CDN follows none),
 * and carries no CORS headers. A setting that is unset or empty makes its file a 404, and so does an invalid one,
 * which is logged once per isolate by name, never by value.
 */
import { listVar, logSettingOnce } from "./env";
import { SECURITY_HEADERS, errorResponse, finalize } from "./http";

export const AASA_PATH = "/.well-known/apple-app-site-association";
export const ASSETLINKS_PATH = "/.well-known/assetlinks.json";

/** `<Team ID>.<bundle ID>`; a bundle ID has at most 155 characters. */
const APPLE_APP_ID_RE = /^[A-Z0-9]{10}\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/;
const APPLE_APP_ID_MAX = 11 + 155;
/** `<package name>@<SHA-256 fingerprint>`; a package name has at least two segments. */
const ANDROID_APP_RE = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+@[0-9A-F]{2}(?::[0-9A-F]{2}){31}$/;
const ANDROID_APP_MAX = 255 + 1 + 95;

/** The app IDs of an APPLE_APP_IDS value: [] when it is unset or empty, null when it is invalid. */
export function parseAppleAppIds(raw: unknown): string[] | null {
  return listVar(raw, (id) => id.length <= APPLE_APP_ID_MAX && APPLE_APP_ID_RE.test(id));
}

/** The apps of an ANDROID_APPS value: [] when it is unset or empty, null when it is invalid. */
export function parseAndroidApps(raw: unknown): { pkg: string; fp: string }[] | null {
  const list = listVar(raw, (a) => a.length <= ANDROID_APP_MAX && ANDROID_APP_RE.test(a));
  return list?.map((a) => {
    const at = a.indexOf("@");
    return { pkg: a.slice(0, at), fp: a.slice(at + 1) };
  }) ?? null;
}

function aasa(ids: string[]): string {
  return JSON.stringify({
    applinks: { details: [{ appIDs: ids, components: [{ "/": "/" }] }] },
    webcredentials: { apps: ids },
  });
}

function assetlinks(apps: { pkg: string; fp: string }[]): string {
  const fps = new Map<string, string[]>();
  for (const a of apps) fps.set(a.pkg, [...(fps.get(a.pkg) ?? []), a.fp]);
  return JSON.stringify(
    [...fps].map(([pkg, sha256]) => ({
      relation: ["delegate_permission/common.get_login_creds", "delegate_permission/common.handle_all_urls"],
      target: { namespace: "android_app", package_name: pkg, sha256_cert_fingerprints: sha256 },
    })),
  );
}

interface FileSpec {
  setting: string;
  /** The file's JSON, null when the setting is unset or empty, false when it is invalid. */
  build: (raw: unknown) => string | null | false;
}

const FILES: ReadonlyMap<string, FileSpec> = new Map([
  [
    AASA_PATH,
    {
      setting: "APPLE_APP_IDS",
      build: (raw: unknown) => {
        const ids = parseAppleAppIds(raw);
        return ids === null ? false : ids.length > 0 ? aasa(ids) : null;
      },
    },
  ],
  [
    ASSETLINKS_PATH,
    {
      setting: "ANDROID_APPS",
      build: (raw: unknown) => {
        const apps = parseAndroidApps(raw);
        return apps === null ? false : apps.length > 0 ? assetlinks(apps) : null;
      },
    },
  ],
]);

const built = new Map<string, { raw: unknown; body: string | null | false }>();

function bodyOf(env: Env, file: FileSpec): string | null {
  const raw = (env as unknown as Record<string, unknown>)[file.setting];
  let b = built.get(file.setting);
  if (b === undefined || b.raw !== raw) built.set(file.setting, (b = { raw, body: file.build(raw) }));
  if (b.body === false) logSettingOnce("association file not served: invalid setting", file.setting);
  return b.body || null;
}

/** The answer for an association file path, or null for any other path. GET and HEAD only. */
export function wellKnown(request: Request, env: Env, url: URL): Response | null {
  const file = FILES.get(url.pathname);
  if (!file) return null;
  if (request.method !== "GET" && request.method !== "HEAD") {
    return finalize(errorResponse(405, "method not allowed", { allow: "GET, HEAD" }), url);
  }
  const body = bodyOf(env, file);
  if (body === null) return finalize(errorResponse(404, "not found"), url);
  const headers = { "content-type": "application/json", "cache-control": "public, max-age=3600", ...SECURITY_HEADERS };
  return finalize(new Response(request.method === "HEAD" ? null : body, { headers }), url);
}

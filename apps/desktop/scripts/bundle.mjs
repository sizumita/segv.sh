// Builds the desktop app's bundle for a deployment and signs it (docs/DEVELOPMENT.md, "Desktop app").
//
//   node scripts/bundle.mjs [--debug] [tauri build options…]
//
// Environment:
//   SEGV_ORIGIN                  the deployment's canonical origin (default https://segv.sh); another one (a local
//                                `pnpm run dev` at http://localhost:5173, say) is added to the page's CSP
//   APPLE_TEAM_ID                the team of the signing identity and the profile (macOS)
//   APPLE_SIGNING_IDENTITY       the codesign identity, its name or SHA-1 (macOS)
//   APPLE_PROVISIONING_PROFILE   a provisioning profile of the app's bundle id with the Associated Domains capability
//                                (macOS): passkeys need it (§11.14 "Passkeys"); without one the app is signed ad hoc
//                                and offers the recovery code only
//
// The entitlements are written here: a signed app names its team (the application identifier, which the data
// protection keychain and the deployment's apple-app-site-association need) and the deployment's host as its
// associated domain (webcredentials:<host>); src-tauri/Entitlements.plist shows segv.sh's. An app signed ad hoc gets
// none of them.
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const APP = join(import.meta.dirname, "..");
const TAURI = join(APP, "src-tauri");
const OUT = join(APP, "..", "..", "target", "segv-desktop");
const conf = JSON.parse(readFileSync(join(TAURI, "tauri.conf.json"), "utf8"));

const origin = process.env.SEGV_ORIGIN ?? "https://segv.sh";
const u = new URL(origin);
if (u.origin !== origin)
  throw new Error(`SEGV_ORIGIN must be an origin, without a path: ${origin}`);
const overlay = { bundle: { macOS: {} }, app: { security: { csp: { ...conf.app.security.csp } } } };
if (origin !== "https://segv.sh") {
  const ws = `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}`;
  const csp = overlay.app.security.csp;
  csp["connect-src"] = csp["connect-src"].replace(
    "https://segv.sh wss://segv.sh",
    `${origin} ${ws}`,
  );
}

/** An entitlements plist of these entries, each a key and its XML value. */
const plist = (entries) =>
  [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    "<dict>",
    ...entries.map(([k, v]) => `\t<key>${k}</key>\n\t${v}`),
    "</dict>",
    "</plist>",
    "",
  ].join("\n");

const team = process.env.APPLE_TEAM_ID;
const identity = process.env.APPLE_SIGNING_IDENTITY;
const profile = process.env.APPLE_PROVISIONING_PROFILE;
if (process.platform === "darwin") {
  const path = join(OUT, "Entitlements.plist");
  mkdirSync(dirname(path), { recursive: true });
  if (identity && profile && team) {
    if (!/^[A-Z0-9]{10}$/.test(team))
      throw new Error("APPLE_TEAM_ID must be 10 characters A-Z, 0-9");
    const appId = `${team}.${conf.identifier}`;
    writeFileSync(
      path,
      plist([
        ["com.apple.application-identifier", `<string>${appId}</string>`],
        ["com.apple.developer.team-identifier", `<string>${team}</string>`],
        ["keychain-access-groups", `<array><string>${appId}</string></array>`],
        // The passkeys of the deployment that the app calls: their RP ID is its host (§2.5), whose association file
        // names the app. A deployment without https has none.
        ...(u.protocol === "https:"
          ? [
              [
                "com.apple.developer.associated-domains",
                `<array><string>webcredentials:${u.hostname}</string></array>`,
              ],
            ]
          : []),
      ]),
    );
    Object.assign(overlay.bundle.macOS, {
      signingIdentity: identity,
      entitlements: path,
      // A macOS app carries its profile at Contents/embedded.provisionprofile.
      files: { "embedded.provisionprofile": profile },
    });
  } else {
    console.warn(
      "bundle: APPLE_TEAM_ID, APPLE_SIGNING_IDENTITY or APPLE_PROVISIONING_PROFILE unset: signing ad hoc, without passkeys",
    );
    // No restricted entitlement: without a profile that allows it, the system refuses to launch the app.
    writeFileSync(path, plist([]));
    Object.assign(overlay.bundle.macOS, { signingIdentity: "-", entitlements: path });
  }
}

const configPath = join(OUT, "tauri.overlay.json");
mkdirSync(OUT, { recursive: true });
writeFileSync(configPath, JSON.stringify(overlay, null, 2));
const r = spawnSync(
  "pnpm",
  ["exec", "tauri", "build", "--config", configPath, ...process.argv.slice(2)],
  {
    cwd: APP,
    stdio: "inherit",
    env: { ...process.env, SEGV_ORIGIN: origin },
  },
);
process.exit(r.status ?? 1);

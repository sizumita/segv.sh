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
//   WINDOWS_SIGN_COMMAND         the command that signs each Windows binary and the installer, with %1 for the file
//                                (Tauri's bundle.windows.signCommand); without one they are not signed
//
// The macOS entitlements are written here: a signed app names its team (the application identifier, which the data
// protection keychain and the deployment's apple-app-site-association need) and the deployment's host as its
// associated domain (webcredentials:<host>); src-tauri/Entitlements.plist shows segv.sh's. An app signed ad hoc gets
// none of them. A Windows app needs neither: the WebAuthn API of Windows takes the RP ID from the app.
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const APP = join(import.meta.dirname, "..");
const TAURI = join(APP, "src-tauri");
const OUT = join(APP, "..", "..", "target", "segv-desktop");
const read = (name) => JSON.parse(readFileSync(join(TAURI, name), "utf8"));
// `pnpm run bundle -- …` passes its `--` on, which Tauri would take as the start of cargo's arguments.
const args = process.argv.slice(2);
if (args[0] === "--") args.shift();

/** The system that the build is for: the one of `--target <triple>` (a cross build), or else this one. */
const target = (() => {
  const i = args.findIndex((a) => a === "--target" || a === "-t");
  const triple = i >= 0 ? args[i + 1] : args.find((a) => a.startsWith("--target="))?.slice(9);
  if (triple?.includes("windows")) return "windows";
  if (triple?.includes("apple-darwin")) return "macos";
  if (triple?.includes("linux")) return "linux";
  return { darwin: "macos", win32: "windows" }[process.platform] ?? "linux";
})();

/** The page's CSP for that system: tauri.conf.json's, with what tauri.<system>.conf.json changes. */
const csp = (() => {
  const base = read("tauri.conf.json").app.security.csp;
  try {
    return { ...base, ...read(`tauri.${target}.conf.json`).app?.security?.csp };
  } catch {
    return base;
  }
})();

const origin = process.env.SEGV_ORIGIN ?? "https://segv.sh";
const u = new URL(origin);
if (u.origin !== origin)
  throw new Error(`SEGV_ORIGIN must be an origin, without a path: ${origin}`);
const overlay = { bundle: { macOS: {}, windows: {} }, app: { security: {} } };
if (origin !== "https://segv.sh") {
  const ws = `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}`;
  overlay.app.security.csp = {
    ...csp,
    "connect-src": csp["connect-src"].replace("https://segv.sh wss://segv.sh", `${origin} ${ws}`),
  };
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
if (target === "macos") {
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

if (target === "windows") {
  const sign = process.env.WINDOWS_SIGN_COMMAND;
  if (sign) overlay.bundle.windows.signCommand = sign;
  else console.warn("bundle: WINDOWS_SIGN_COMMAND unset: the app and its installer are not signed");
}

const configPath = join(OUT, "tauri.overlay.json");
mkdirSync(OUT, { recursive: true });
writeFileSync(configPath, JSON.stringify(overlay, null, 2));
// Tauri's CLI through this Node, without a shell, which Windows would need for pnpm's .cmd shim.
const cli = createRequire(import.meta.url).resolve("@tauri-apps/cli/tauri.js");
const r = spawnSync(process.execPath, [cli, "build", "--config", configPath, ...args], {
  cwd: APP,
  stdio: "inherit",
  env: { ...process.env, SEGV_ORIGIN: origin },
});
process.exit(r.status ?? 1);

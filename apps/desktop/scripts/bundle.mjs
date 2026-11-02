// Builds the desktop app's bundle for a deployment and signs it (docs/DEVELOPMENT.md, "Desktop app").
//
//   node scripts/bundle.mjs [--debug] [tauri build options…]
//   node scripts/bundle.mjs bundle [--debug] [tauri bundle options…]
//
// The first form runs `tauri build`. The second bundles and signs an app that `tauri build --no-bundle` built before,
// with the same environment and options: CI builds without the signing secrets and gives them to that step alone.
//
// Environment:
//   SEGV_CHANNEL                 `release` (default): segv.sh, identifier sh.segv.desktop, links `segv:`.
//                                `canary`: segv.sh Canary, a separate app (sh.segv.desktop.canary, links `segv-canary:`,
//                                its own icon and data) for canary.segv.sh
//   SEGV_ORIGIN                  the deployment's canonical origin (default https://segv.sh, https://canary.segv.sh for
//                                the Canary); another one than segv.sh's (a local `pnpm run dev` at
//                                http://localhost:5173, say) replaces segv.sh in the page's CSP
//   SEGV_VERSION                 the app's version, X.Y.Z or X.Y.Z-canary.N, instead of tauri.conf.json's
//                                (scripts/version.mjs)
//   SEGV_BUILD                   the build number, digits: CFBundleVersion on macOS (by default the version)
//   SEGV_UPDATES                 `1`: the app updates itself from its channel's feed (src/update.rs), and the bundle
//                                gets the update packages, signed with TAURI_SIGNING_PRIVATE_KEY (the channel's key,
//                                which only the channel's GitHub environment holds). Only the published builds of
//                                .github/workflows/desktop.yml set it: any other build would replace itself with the
//                                published one
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
const conf = read("tauri.conf.json");
// `pnpm run bundle -- …` passes its `--` on, which Tauri would take as the start of cargo's arguments.
const args = process.argv.slice(2);
if (args[0] === "--") args.shift();
const command = args[0] === "bundle" ? args.shift() : "build";

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
  const base = conf.app.security.csp;
  try {
    return { ...base, ...read(`tauri.${target}.conf.json`).app?.security?.csp };
  } catch {
    return base;
  }
})();

const channel = process.env.SEGV_CHANNEL || "release";
if (channel !== "release" && channel !== "canary")
  throw new Error(`SEGV_CHANNEL must be release or canary: ${channel}`);
const canary = channel === "canary";

const origin = process.env.SEGV_ORIGIN || (canary ? "https://canary.segv.sh" : "https://segv.sh");
const u = new URL(origin);
if (u.origin !== origin)
  throw new Error(`SEGV_ORIGIN must be an origin, without a path: ${origin}`);
const overlay = { bundle: { macOS: {}, windows: {} }, app: { security: {} }, plugins: {} };

// The Canary is another app, so that it installs next to segv.sh: its own bundle identifier (and with it its own data
// directory, keychain items and notifications), name, icon and link scheme (§11.14 "Links").
if (canary) {
  Object.assign(overlay, {
    identifier: `${conf.identifier}.canary`,
    productName: `${conf.productName} Canary`,
  });
  overlay.plugins["deep-link"] = { desktop: { schemes: ["segv-canary"] } };
  overlay.bundle.icon = conf.bundle.icon.map((p) =>
    join(TAURI, p.replace(/^icons\//, "icons/canary/")),
  );
  // The icon of the Windows notifications (src/notify.rs). null removes segv.sh's from the merged configuration.
  if (target === "windows")
    overlay.bundle.resources = {
      "icons/128x128.png": null,
      [join(TAURI, "icons/canary/128x128.png")]: "notification.png",
    };
}
const identifier = overlay.identifier ?? conf.identifier;

const version = process.env.SEGV_VERSION;
if (version) {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-canary\.(0|[1-9]\d*))?$/.test(version))
    throw new Error(`SEGV_VERSION must be X.Y.Z or X.Y.Z-canary.N: ${version}`);
  overlay.version = version;
}
// Where each channel's app looks for its updates, and the public key of the channel's update key: the app installs
// only a package that this key's private half signed for the version that the feed names, and only a newer version
// than its own (docs/PROTOCOL.md §11.14 "Updates"). The feed is the release's latest.json, which
// .github/workflows/desktop.yml writes.
const UPDATES = {
  release: {
    endpoint: "https://github.com/sizumita/segv.sh/releases/latest/download/latest.json",
    // minisign key 9A590B3E98CE5672
    pubkey:
      "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDlBNTkwQjNFOThDRTU2NzIKUldSeVZzNllQZ3RabXBGTXREaWV2S1VQZmhsZ21zOWZoUnVJOW5LQ0Rva3hzNUJOR05YSys2eEEK",
  },
  canary: {
    endpoint: "https://github.com/sizumita/segv.sh/releases/download/canary/latest.json",
    // minisign key C29D59D33460AB4F
    pubkey:
      "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEMyOUQ1OUQzMzQ2MEFCNEYKUldSUHEyQTAwMW1kd3RITE5DM3diVmVnWUU1YUVCWkNWaFVtUXE4M1F3WE1FNVR6YXArZm5lQU4K",
  },
};
const updates = process.env.SEGV_UPDATES;
if (updates && updates !== "1") throw new Error(`SEGV_UPDATES must be 1 or unset: ${updates}`);
if (updates) {
  overlay.plugins.updater = {
    endpoints: [UPDATES[channel].endpoint],
    pubkey: UPDATES[channel].pubkey,
    requireSignedVersion: true,
    // The installer runs without a window, and starts the app again unless it was quitting (src/update.rs).
    windows: { installMode: "quiet" },
  };
  overlay.bundle.createUpdaterArtifacts = true;
}

const build = process.env.SEGV_BUILD;
if (build) {
  if (!/^[1-9]\d{0,8}$/.test(build))
    throw new Error(`SEGV_BUILD must be a positive number: ${build}`);
  overlay.bundle.macOS.bundleVersion = build;
}

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
    const appId = `${team}.${identifier}`;
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
    if (!args.includes("--no-bundle"))
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
const r = spawnSync(process.execPath, [cli, command, "--config", configPath, ...args], {
  cwd: APP,
  stdio: "inherit",
  env: { ...process.env, SEGV_ORIGIN: origin },
});
process.exit(r.status ?? 1);

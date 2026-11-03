# Development

This guide sets up a local instance of segv.sh and runs its tests. For the overall design, read the
[README](../README.md) first.

## Requirements

- Node.js 26 (`^26.0.0`).
- pnpm 12, at the release that `packageManager` in `package.json` pins. pnpm does not switch to that release by itself
  (`pmOnFail` in `pnpm-workspace.yaml`); install it with `pnpm self-update <version>`.
- To use the app by hand: a browser whose passkey provider supports the WebAuthn PRF extension. Passkeys created on
  `localhost` are separate from the passkeys of any deployment.
- For the end-to-end tests: Playwright's Chromium, installed once with
  `pnpm --filter @segv/web exec playwright install chromium`.

## Local setup

1. Install the dependencies:

   ```bash
   pnpm install
   ```

2. Create `apps/web/.dev.vars` with the two server secrets, each 32 random bytes in base64url. `ROUTE_KEY` keys the
   routing of rows to shards, and `SRV_KEY` is the seed of the server's Ed25519 key, which signs write receipts and
   checkpoints. Without them, every `/api/v2/*` request answers 503 `server misconfigured`. The file is gitignored.

   ```bash
   node -e 'const k = () => require("node:crypto").randomBytes(32).toString("base64url"); console.log(`ROUTE_KEY=${k()}\nSRV_KEY=${k()}`)' > apps/web/.dev.vars
   ```

3. Create the local D1 database:

   ```bash
   pnpm run db:migrate:local
   ```

4. Start the development server:

   ```bash
   pnpm run dev
   ```

   `vp dev` runs the Qwik app with server-side rendering, the API and every Durable Object inside workerd, through
   `@cloudflare/vite-plugin`. Open the local URL that it prints.

Local data (D1, R2 and the Durable Objects' storage) lives in `apps/web/.wrangler/state`; delete that directory and run
`pnpm run db:migrate:local` again to start over. The deployment parameters in `apps/web/wrangler.jsonc` apply locally
too, so proof of work costs as much as in production, and a membership change or a new conversation takes at least Δ +
SKEW = 12 seconds to become visible to the other members.

To try the production build locally, run `pnpm run preview`: it builds the app and serves it with `wrangler dev`, which
also reads `apps/web/.dev.vars`.

The root scripts (`dev`, `build`, `preview`, `deploy`, `db:migrate:local`, `test:e2e`) run the web app's scripts. Run
other Wrangler commands in `apps/web`, where `wrangler.jsonc` is.

## Desktop app

`apps/desktop` is the desktop app (docs/PROTOCOL.md §11.14), built with [Tauri 2](https://tauri.app) for macOS and
Windows: the UI of `packages/ui`, rendered in the client only (Qwik's CSR mode) into one static page that the app
carries in its package and shows at `tauri://localhost` (`https://tauri.localhost` on Windows). The engine gets the
app's platform through `EngineOptions` (`apps/desktop/src/platform.ts`): the deployment's canonical origin for every API
call and the realtime socket, passkeys through the system's own API (AuthenticationServices on macOS, the WebAuthn API
of Windows; the RP ID stays the canonical host), the remembered session in a file of the app's local data directory
sealed under a key of the system's key store (the data protection keychain on macOS; on Windows a key of the TPM, or
DPAPI on a device without one), notifications that the app shows itself while it runs, also with its window closed
(§11.13, "Apps without push"), and a clock whose timers the native code also fires while the page is hidden
(`alarmClock` of `packages/engine`, `src-tauri/src/alarm.rs`), so that the realtime socket keeps its pings and
reconnects with the window closed. The native code tells the page when the system wakes and when the network changes
(`src-tauri/src/wake.rs`), and opens the page's links to other sites in the browser (`src-tauri/src/links.rs`). Their
native side is in `apps/desktop/src-tauri/src`; the commands that the page may call are listed in `build.rs` and granted
in `capabilities/main.json`. The window is Liquid Glass on macOS 26 and later and Mica on Windows 11 (`windowEffects` in
`tauri.conf.json`; `src/lib.rs` makes the window), and
`apps/desktop/src/desktop.css` lets it show through the page's chrome. `tauri.windows.conf.json` holds what differs on
Windows: a window with the system's title bar, the page's CSP (Tauri's bridge answers at `https://ipc.localhost` there),
WebView2's switches that keep the page's timers running while the window is closed, and the installer.

Requirements: Rust (the workspace's `Cargo.toml` is at the root); on macOS Xcode, on Windows the MSVC build tools
(Visual Studio Build Tools with "Desktop development with C++") and WebView2, which Windows 11 includes. The app runs
on macOS 15 or later, and on Windows 10 22H2 or Windows 11.

- `pnpm --filter @segv/desktop run dev` runs `tauri dev`: the page comes from a Vite server at `http://localhost:1420`,
  which passes `/api/*` on to `SEGV_DEV_API` (default `http://localhost:5173`, the local `pnpm run dev`). On macOS a
  binary run outside an app bundle has no notification center and no associated domains, so notifications and passkeys
  only work in a bundle.
- `pnpm --filter @segv/desktop run bundle -- --debug --bundles app` builds `target/debug/bundle/macos/segv.sh.app`
  (`scripts/bundle.mjs`). It calls `SEGV_ORIGIN` (default `https://segv.sh`); a local server needs
  `SEGV_ORIGIN=http://localhost:5173`, and `APP_ORIGINS` in `apps/web/wrangler.jsonc` already lets
  `tauri://localhost` and `https://tauri.localhost` call it. To sign the app with passkeys, set `APPLE_TEAM_ID`,
  `APPLE_SIGNING_IDENTITY` (the identity's name or SHA-1) and `APPLE_PROVISIONING_PROFILE` (a macOS profile of
  `sh.segv.desktop` with the Associated Domains capability, which needs a paid Apple Developer Program team; a
  development profile lists the Macs it runs on). Without them the app is signed ad hoc and signs in with the
  recovery code only. Passkeys of a deployment also need its `/.well-known/apple-app-site-association` to name the app
  (`APPLE_APP_IDS`, see [DEPLOYMENT.md](DEPLOYMENT.md)), and macOS reads it only for an app in `/Applications`.
  `SEGV_CHANNEL=canary` builds segv.sh Canary instead (`segv.sh Canary.app`, on Windows too, "Releases" below), which
  calls `https://canary.segv.sh` unless `SEGV_ORIGIN` says otherwise. A local build never updates itself: only the
  published builds have a feed ("Updates" below).
- On Windows, `pnpm --filter @segv/desktop run bundle -- --debug --bundles nsis` builds
  `target/debug/bundle/nsis/segv.sh_0.1.0_x64-setup.exe`, an installer for the current user that needs no administrator.
  It makes the Start menu shortcut with the app's AppUserModelID (`sh.segv.desktop`), under which the app registers
  itself for notifications at every launch (`src/notify.rs`), and registers the `segv:` scheme that a click on a
  notification opens. A development build registers the scheme itself, to its own binary, until the app is installed
  again. To try a branch without building on Windows, use the workflow "Desktop app for Windows"
  (`.github/workflows/desktop-windows.yml`): it builds unsigned installers for x64 and ARM64 for every pull request that
  changes the desktop app, or when started from the Actions tab, and keeps them as the run's artifacts for 14 days.
  They do not update themselves. The published installers come from the workflow "Desktop app" ("Releases" below).
  Passkeys need no signing and no association file: the WebAuthn API of Windows takes the RP ID from the app. It reaches
  the passkeys of Windows Hello, security keys, phones and the passkey managers that Windows lists, but not those that a
  browser keeps itself (Chrome's in Google Password Manager, say). Windows Hello evaluates the PRF extension from the
  February 2026 updates of Windows 11 24H2 and 25H2 on (KB5077181); security keys with hmac-secret do on earlier
  versions too. Windows 11 24H2 and later ask once whether the app may use passkeys (Settings > Privacy & security >
  Passkey access). Set `WINDOWS_SIGN_COMMAND` to sign the binaries and the installer (Tauri's
  `bundle.windows.signCommand`, with `%1` for the file); unsigned, SmartScreen warns when the installer runs.
- `cargo clippy -p segv-desktop` and `cargo fmt --all` check and format the native code.
  `cargo clippy -p segv-desktop --target x86_64-pc-windows-msvc` checks the Windows code from macOS too (after
  `rustup target add x86_64-pc-windows-msvc`); CI runs the check on macOS and on Windows.

Linux builds compile, but they neither keep the session nor show notifications yet: the key store and the
notifications of Linux are not wired up.

## Releases

segv.sh ships from two places. Every push to `main` deploys <https://canary.segv.sh> and builds segv.sh Canary; a
release tag `vX.Y.Z` on a commit of `main` deploys <https://segv.sh> and builds segv.sh
([DEPLOYMENT.md](DEPLOYMENT.md), "Canary" and "Deploying from GitHub Actions").

|                 | Canary                                                          | Release                                                         |
| --------------- | --------------------------------------------------------------- | --------------------------------------------------------------- |
| Started by      | a push to `main` (the desktop app: one that changes it)         | a tag `vX.Y.Z` on a commit of `main`                            |
| Web app and API | <https://canary.segv.sh>, with accounts of its own              | <https://segv.sh>                                               |
| Desktop app     | segv.sh Canary, `sh.segv.desktop.canary`, links `segv-canary:`  | segv.sh, `sh.segv.desktop`, links `segv:`                       |
| App version     | `X.Y.Z-canary.N`                                                | `X.Y.Z`                                                         |
| Downloads       | the prerelease `canary`                                         | the latest release                                              |
| A file's link   | `https://github.com/sizumita/segv.sh/releases/download/canary/` | `https://github.com/sizumita/segv.sh/releases/latest/download/` |

| File                         | Canary                           | Release                   |
| ---------------------------- | -------------------------------- | ------------------------- |
| macOS (Apple silicon, Intel) | `segv.sh-Canary.dmg`             | `segv.sh.dmg`             |
| Windows x64                  | `segv.sh-Canary-x64-setup.exe`   | `segv.sh-x64-setup.exe`   |
| Windows ARM64                | `segv.sh-Canary-arm64-setup.exe` | `segv.sh-arm64-setup.exe` |

segv.sh Canary is another app, so that it installs next to segv.sh: its own data, key store items, notifications and
login item, its own icon, and the account of canary.segv.sh, which has nothing of segv.sh's. The macOS apps are
universal, signed with the team's Developer ID and notarized by Apple, and keep their passkeys in `/Applications`
only. The Windows installers install for the current user and are not signed yet, so SmartScreen warns when one runs
for the first time. Both systems' apps then update themselves ("Updates" below).

`apps/desktop/scripts/version.mjs` gives the versions. A release has its tag's. A Canary build is a prerelease of the
next version: the last release tag before it with its patch raised, or `version` in `tauri.conf.json` when that is
higher (raise it there before a minor or a major release), and N is the number of commits since that tag. By semver,
every Canary build sorts above the release before it and below the release after it. The build number
(`CFBundleVersion`) is the number of commits of the build's history.

To release, tag a commit of `main` that canary.segv.sh has run, and push the tag:

```bash
git tag v0.1.0 <commit>
git push origin v0.1.0
```

`.github/workflows/deploy.yml` deploys it to segv.sh, and `.github/workflows/desktop.yml` builds the desktop app and
publishes the tag's release, whose notes GitHub writes from the pull requests since the previous tag. Apply the
release's D1 migrations to segv.sh before pushing the tag ([DEPLOYMENT.md](DEPLOYMENT.md), "Updating").

### Signing the macOS app

`desktop.yml` compiles the app in a job without secrets, then bundles, signs and notarizes that binary in a job of the
environment `canary` (for `main`) or `production` (for release tags), which holds these secrets. Set them up once:

1. A **Developer ID Application** certificate of the team, which only the team's Account Holder can create (Apple
   Developer › Certificates). Export it with its private key from Keychain Access as a `.p12` file with a password.
2. The App IDs `sh.segv.desktop` and `sh.segv.desktop.canary`, each with the **Associated Domains** capability.
3. A **Developer ID** provisioning profile for each App ID, with that certificate (Apple Developer › Profiles). Unlike a
   development profile, it lists no Macs. The system checks it at every launch of the app; it is valid for 18 years,
   and a new certificate needs new profiles.
4. An **App Store Connect API key** for notarization (App Store Connect › Users and Access › Integrations, a team key
   with the Developer role). Note its key ID and issuer ID, and download its `.p8` file, which Apple offers only once.
5. The secrets. Both environments get the same certificate and API key, and each its own app's profile:

   ```bash
   for env in canary production; do
     base64 -i DeveloperID.p12 | gh secret set APPLE_CERTIFICATE --env "$env"
     gh secret set APPLE_CERTIFICATE_PASSWORD --env "$env"
     gh secret set APPLE_SIGNING_IDENTITY --env "$env"   # Developer ID Application: <name> (NBDP5VK335)
     gh secret set APPLE_API_KEY --env "$env"            # the key ID
     gh secret set APPLE_API_ISSUER --env "$env"         # the issuer ID
     gh secret set APPLE_API_PRIVATE_KEY --env "$env" < AuthKey_<key ID>.p8
   done
   base64 -i segv.sh_Canary_Developer_ID.provisionprofile | gh secret set APPLE_PROVISIONING_PROFILE_BASE64 --env canary
   base64 -i segv.sh_Developer_ID.provisionprofile | gh secret set APPLE_PROVISIONING_PROFILE_BASE64 --env production
   ```

The Canary's passkeys also need `canary.segv.sh` to name the app (`APPLE_APP_IDS` of `env.canary` in
`apps/web/wrangler.jsonc`), as segv.sh names `sh.segv.desktop`.

### Updates

The published apps update themselves (`apps/desktop/src-tauri/src/update.rs`, docs/PROTOCOL.md §11.14 "Updates"). A
minute after launch and then every four hours, an app reads its channel's feed: `latest.json` of the latest release,
or of the prerelease `canary` for segv.sh Canary, which `desktop.yml` uploads once every file that it names is in
place. A newer version is downloaded in the background, and Tauri's updater installs it only if its signature verifies
under the channel's update key and names the version that the feed names. If the app's window is closed, it installs
the update at once and starts again in the menu bar or the tray, without the window. Otherwise the tray's menu offers
"Restart to Update", and the update is installed when the window is next closed or the app quits. On macOS the app
replaces its own bundle; where that would ask for an administrator (an app that another user installed, or one run
from its disk image), it waits for the menu. On Windows the installer runs without a window once the app has exited,
and starts it again.

Only builds made with `SEGV_UPDATES=1` have a feed. `desktop.yml` sets it; any other build never looks for updates.
`UPDATES` in `apps/desktop/scripts/bundle.mjs` holds each channel's feed and the public half of its update key.

Each channel has its own update key, a minisign key pair that Tauri's CLI makes. Only the environment of its channel
holds the private key, as the secret `TAURI_SIGNING_PRIVATE_KEY`. Make them once:

```bash
pnpm --filter @segv/desktop exec tauri signer generate -w ~/.tauri/segv-canary.key
pnpm --filter @segv/desktop exec tauri signer generate -w ~/.tauri/segv-release.key
gh secret set TAURI_SIGNING_PRIVATE_KEY --env canary < ~/.tauri/segv-canary.key
gh secret set TAURI_SIGNING_PRIVATE_KEY --env production < ~/.tauri/segv-release.key
```

A key with a password needs it as `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` in the same environment. The `.pub` files go to
`UPDATES`. Keep each private key somewhere safe outside GitHub, which never shows a secret again: the installed apps of
a channel accept only its key, so without it they cannot be updated, and every user has to download the app again. To
change a key, publish one more version with the old key whose app carries the new public key, then replace the secret.

To try updates locally, make a key for the test, and build two versions with `SEGV_UPDATES=1`, `SEGV_VERSION`,
`TAURI_SIGNING_PRIVATE_KEY` set to that key, and one more `--config` file that sets `plugins.updater` to the test key's
public key, an `http://127.0.0.1:…/latest.json` endpoint and `"dangerousInsecureTransportProtocol": true`, and another
`identifier` (or the build hands off to an installed segv.sh). Serve a `latest.json` that names the newer build's
`.app.tar.gz` and the contents of its `.sig`, then start the older build.

## Tests

`pnpm test` runs `vp test run`, which runs the Vitest project of each package (`packages/*/vite.config.ts`):

| Project    | Files                                                    | What it covers                                                                                                                                                                                                          |
| ---------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `protocol` | `packages/protocol/src/*.test.ts`                        | The cryptographic core and the wire formats, in Node                                                                                                                                                                    |
| `engine`   | `packages/engine/src/*.test.ts`, `packages/engine/test/` | The engine's modules, and the real engine against `FakeWorld`, an in-memory implementation of the server: accounts, conversations, delivery, membership, restore, integrity, links, and how the cost of a restore grows |
| `ui`       | `packages/ui/src/*.test.ts`                              | The UI's helpers (routing, formatting), in Node                                                                                                                                                                         |
| `server`   | `packages/server/test/`                                  | The API, the Durable Objects and the D1 directory on the Workers runtime, configured by `packages/server/test/wrangler.test.jsonc` (Δ = 1 s, SKEW = 0)                                                                  |

To run one project or one file:

```bash
pnpm exec vp test run --project engine
pnpm exec vp test run packages/engine/test/restore.spec.ts
```

`pnpm run typecheck` type-checks every package with its own `tsconfig.json`, each with the globals of where its code
runs: `packages/protocol` has no DOM, and `packages/server` sees only the Workers runtime (its
`worker-configuration.d.ts`, from `pnpm run cf-typegen` in that package). The web app's check also covers the packages
it imports, against the bindings of `apps/web/wrangler.jsonc`.

### End-to-end tests

`pnpm run test:e2e` builds the app, starts `wrangler dev` on port 8817 with a generated configuration (low proof of
work, Δ = 1 s, fresh secrets and its own state in `apps/web/.wrangler/e2e`), and drives headless Chromium with virtual
authenticators that support PRF. It never touches the data of `pnpm run dev`.

```bash
pnpm run test:e2e --no-build      # reuse the last build
HEADED=1 pnpm run test:e2e        # watch the browsers
E2E_PORT=9000 pnpm run test:e2e   # use another port
```

The tests check only what needs the whole system: the production Worker with its Durable Objects, D1 and R2, the UI it
renders, passkeys, and several devices at once (`apps/web/test/e2e/web.mjs`). The rules themselves are tested where
they are enforced, in the packages' tests. On the way, the run takes a screenshot of each screen in the light and the
dark color scheme and at a phone's width, in `apps/web/.wrangler/e2e/shots/web`, or under the directory in `E2E_SHOTS`.

A heavier run, not part of the tests, measures what the page keeps as messages arrive: bob sends messages and images
to alice in several conversations, first while her page is hidden, as a closed desktop window is, then while it shows
them, and each phase prints alice's live JS heap after a full garbage collection, the highest heap of the phase and its
script time. Compare the numbers before and after a change to the engine or the UI:

```bash
cd apps/web && node test/e2e/memory.mjs --convs 6 --messages 150   # --snapshot <file> saves a heap snapshot
```

On Windows, the same run can drive the installed desktop app instead (`apps/web/test/e2e/windows.mjs`): the accounts
are made in Chromium, and the app unlocks with a recovery code, since a test cannot answer the system's passkey
requests. Build the app for the local deployment, install it, and pass its program:

```bash
SEGV_ORIGIN=http://localhost:8817 pnpm --filter @segv/desktop run bundle -- --bundles nsis
pnpm run test:e2e --windows-app "$LOCALAPPDATA/segv.sh/segv-desktop.exe"
```

Its web view (WebView2) opens a DevTools port for the run (`E2E_CDP_PORT`, 9222), which Playwright drives as it drives
Chromium. WebView2 takes that flag from the environment only when the app is not elevated: run it from a normal
terminal (CI, whose processes are elevated, sets a machine-wide policy instead). WKWebView has no such port, so the
macOS app is not tested this way.

### Screenshots in pull requests

When a pull request changes what the apps show (the paths in `.github/scripts/screenshots.mjs`), CI also runs the
Windows app's end-to-end test, and the Screenshots workflow (`.github/workflows/screenshots.yml`) posts the screens of
both runs in one comment on the pull request, which each later run updates. The images are committed to
`refs/screenshots/pr-<number>`, outside the branches, so that no clone fetches them; delete such a ref with
`git push origin --delete refs/screenshots/pr-<number>`. To see the comment for local screenshots:

```bash
node .github/scripts/screenshots.mjs preview apps/web/.wrangler/e2e/shots
```

## Before a pull request

Run the checks listed in [CONTRIBUTING.md](../CONTRIBUTING.md#development). `pnpm run check` runs the formatter in
check mode and the linter; `pnpm run fmt` formats the sources. The CI workflow (`.github/workflows/ci.yml`) runs the
same checks, the end-to-end test and the dependency audit on every pull request.

## Workspace

The repository is a pnpm workspace. Each directory under `apps/` is something that ships; each one under `packages/` is
code that apps are built from. Nothing is published: a package exports its TypeScript sources, and the app that
imports it compiles them (Vite and Qwik's optimizer, or Node's type stripping in the end-to-end test).

```text
apps/desktop ──▶ packages/ui ──▶ packages/engine ──▶ packages/protocol
                   ▲                                      ▲
apps/web ──────────┘                                      │
   └──────────▶ packages/server ──────────────────────────┘
```

- Dependencies point one way. An app may import any package; `ui` imports `engine`; `engine` and `server` import
  `protocol`. Nothing imports an app, and `ui` and `server` never import each other. pnpm refuses a cycle
  (`disallowWorkspaceCycles` in `pnpm-workspace.yaml`).
- That `ui` cannot import `server` is also what keeps server code out of the browser: Qwik refuses a client import
  from a `server/` directory only inside the app's own `src/`, so code under `packages/` would be bundled silently.
- A package exposes only what the `exports` of its `package.json` lists. Other packages import it by name
  (`@segv/engine/types`), never by a path into its directory and never through a path alias.
- Each package declares every package it imports, test and build tools included: a third-party package with
  `"catalog:"`, a workspace package with `"workspace:*"`. pnpm links only a package's own dependencies into its
  `node_modules` and hoists nothing else, so an import that works only because another package depends on it fails.
  The one exception is the workspace's own `devDependencies`, which Node finds from every directory below the root:
  declare them in each package that imports them all the same.
- `@segv/ui` takes `@qwik.dev/core` as a peer dependency: the app provides the one copy of Qwik.
- Code that needs one platform belongs to the app that ships on that platform. A native shell is an app of its own
  that builds `@segv/ui` and gives the engine its platform (`EngineOptions`), as `apps/desktop` does; `packages/` never
  import a platform's SDK.
- `pnpm run check:workspace` checks these rules, which pnpm does not enforce by itself
  (`scripts/check-workspace.mjs`): versions only from the catalog or the workspace, the allowed dependencies between
  packages (`ALLOWED` in the script), no platform SDK under `packages/`, and every import declared by the package that
  makes it. It also checks that the lockfile is deduplicated and that every peer dependency is satisfied. CI runs it.
- The workspace's `vite.config.ts` holds the lint and format settings and lists the test projects. An app's own
  `vite.config.ts` holds its development server and its build.

## Dependencies

- Every third-party package has one exact version, in the `catalog` of `pnpm-workspace.yaml`, and each `package.json`
  names `"catalog:"` instead of a version. `pnpm add <name>@<version> --filter <package>` adds a new package to the
  catalog and names `"catalog:"` in that package; `catalogMode: strict` refuses a version other than the catalog's, so
  an upgrade changes the catalog entry and every package moves with it. pnpm takes
  its settings from that file only; it also holds the overrides, each with its reason.
- No dependency runs install scripts (`allowBuilds`), and pnpm installs a release only once it has been published for a
  day (`minimumReleaseAge`).
- Upgrades wait 30 days. Dependabot proposes one only once the new release has been published for 30 days (`cooldown`
  in `.github/dependabot.yml`), and holds the transitive dependencies it resolves for it to the same window where a
  release that old satisfies them. It looks every Monday, for the dependencies and for the actions of the workflows.
- Security fixes do not wait. Dependabot opens a security update as soon as an advisory affects a locked version. A fix
  published less than a day ago installs only once `minimumReleaseAgeExclude` in `pnpm-workspace.yaml` names its
  version. Security updates need Dependabot alerts and Dependabot security updates turned on for the repository:

  ```bash
  gh api -X PUT 'repos/{owner}/{repo}/vulnerability-alerts'
  gh api -X PUT 'repos/{owner}/{repo}/automated-security-fixes'
  ```

- `pnpm-lock.yaml` stays a single YAML document, which CI checks. GitHub's dependency graph reads only the first
  document, so a second one would hide every dependency from Dependabot. pnpm adds the second document when it records
  its own release in the lockfile, which `pmOnFail: ignore` in `pnpm-workspace.yaml` prevents.
- Some versions move together:
  - `vite-plus`, the `vite` alias (`npm:@voidzero-dev/vite-plus-core`) and `vitest` in the catalog of
    `pnpm-workspace.yaml`; the `vite` and `vitest` overrides follow the catalog. `vp toolchain vitest` prints the Vitest
    version that Vite+ bundles. Dependabot proposes only `vite-plus`; upgrade the rest in its pull request.
  - `wrangler`, `@cloudflare/vite-plugin` and `@cloudflare/vitest-plugin`. Each plugin depends on the exact Wrangler it
    was released with, so choose the plugin releases that depend on the chosen Wrangler.
- `pnpm audit` must report nothing. CI checks it, and the registry signatures (`pnpm audit signatures`), on every pull
  request and every week. Fix an advisory by upgrading, or with an override scoped to the version of the package that
  brings it in; accept one only by listing its GHSA under `auditConfig.ignoreGhsas` in `pnpm-workspace.yaml`, with the
  reason.

## Reading the code

- [docs/PROTOCOL.md](PROTOCOL.md) is the normative specification. Code comments cite its sections as `§n.m`.
- `packages/protocol/src/proto.ts` implements the primitives, derivations and record formats of the specification, and
  `packages/protocol/src/wire.ts` the binary API formats. Both are shared by the browser and the server.
- `packages/engine/src/engine.ts` is the client engine that the UI talks to through the `Engine` interface in
  `packages/engine/src/types.ts`; the other modules in `packages/engine/src/` implement its parts.
- `packages/server/src/api.ts` handles every `/api/v2/*` request, and each Durable Object lives in its own file in
  `packages/server/src/`.
- `apps/web/src/entry.cloudflare-workers.ts` is the Worker: it sends `/api/*` to the server package and everything else
  to Qwik's server-side rendering of `packages/ui`.

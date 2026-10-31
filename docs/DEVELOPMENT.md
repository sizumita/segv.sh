# Development

This guide sets up a local instance of segv.sh and runs its tests. For the overall design, read the
[README](../README.md) first.

## Requirements

- Node.js `^22.18.0`, `^24.11.0` or `>=26.0.0`.
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

Screenshots are written to `apps/web/.wrangler/e2e/shots`, or to the directory in `E2E_SHOTS`.

## Before a pull request

Run the checks listed in [CONTRIBUTING.md](../CONTRIBUTING.md#development). `pnpm run check` runs the formatter in
check mode and the linter; `pnpm run fmt` formats the sources. The CI workflow (`.github/workflows/ci.yml`) runs the
same checks, the end-to-end test and the dependency audit on every pull request.

## Workspace

The repository is a pnpm workspace. Each directory under `apps/` is something that ships; each one under `packages/` is
code that apps are built from. Nothing is published: a package exports its TypeScript sources, and the app that
imports it compiles them (Vite and Qwik's optimizer, or Node's type stripping in the end-to-end test).

```text
apps/web ──▶ packages/ui ──▶ packages/engine ──▶ packages/protocol
   │                                                  ▲
   └──────────▶ packages/server ──────────────────────┘
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
- Code that needs one platform belongs to the app that ships on that platform. A native shell would be an app of its
  own that builds `@segv/ui` and gives the engine its platform (`EngineOptions`); `packages/` never import a platform's
  SDK.
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

# Development

This guide sets up a local instance of segv.sh and runs its tests. For the overall design, read the
[README](../README.md) first.

## Requirements

- Node.js `^22.18.0`, `^24.11.0` or `>=26.0.0`.
- pnpm 12, at the release that `packageManager` in `package.json` pins. pnpm does not switch to that release by itself
  (`pmOnFail` in `pnpm-workspace.yaml`); install it with `pnpm self-update <version>`.
- To use the app by hand: a browser whose passkey provider supports the WebAuthn PRF extension. Passkeys created on
  `localhost` are separate from the passkeys of any deployment.
- For the end-to-end tests: Playwright's Chromium, installed once with `pnpm exec playwright install chromium`.

## Local setup

1. Install the dependencies:

   ```bash
   pnpm install
   ```

2. Create `.dev.vars` with the two server secrets, each 32 random bytes in base64url. `ROUTE_KEY` keys the routing of
   rows to shards, and `SRV_KEY` is the seed of the server's Ed25519 key, which signs write receipts and checkpoints.
   Without them, every `/api/v2/*` request answers 503 `server misconfigured`. The file is gitignored.

   ```bash
   node -e 'const k = () => require("node:crypto").randomBytes(32).toString("base64url"); console.log(`ROUTE_KEY=${k()}\nSRV_KEY=${k()}`)' > .dev.vars
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

Local data (D1, R2 and the Durable Objects' storage) lives in `.wrangler/state`; delete that directory and run
`pnpm run db:migrate:local` again to start over. The deployment parameters in `wrangler.jsonc` apply locally too, so
proof of work costs as much as in production, and a membership change or a new conversation takes at least
Δ + SKEW = 12 seconds to become visible to the other members.

To try the production build locally, run `pnpm run preview`: it builds the app and serves it with `wrangler dev`, which
also reads `.dev.vars`.

## Tests

`pnpm test` runs `vp test run`, which has three Vitest projects:

| Project   | Files                   | What it covers                                                                                                                                                                                       |
| --------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unit`    | `src/**/*.test.ts`      | The cryptographic core, the wire formats and the UI helpers, in Node                                                                                                                                 |
| `workers` | `test/worker/*.spec.ts` | The API, the Durable Objects and the D1 directory on the Workers runtime, configured by `test/worker/wrangler.test.jsonc` (Δ = 1 s, SKEW = 0)                                                        |
| `engine`  | `test/engine/*.spec.ts` | The real client engine against `FakeWorld`, an in-memory implementation of the server: accounts, conversations, delivery, membership, restore, integrity, links, and how the cost of a restore grows |

To run one project or one file:

```bash
pnpm exec vp test run --project engine
pnpm exec vp test run test/engine/restore.spec.ts
```

The test directories have TypeScript configurations of their own. Check them with
`pnpm exec tsc --noEmit -p test/engine` and `pnpm exec tsc --noEmit -p test/worker`, and the app with
`pnpm exec tsc --noEmit -p .`.

### End-to-end tests

`pnpm run test:e2e` builds the app, starts `wrangler dev` on port 8817 with a generated configuration (low proof of
work, Δ = 1 s, fresh secrets and its own state in `.wrangler/e2e`), and drives headless Chromium with virtual
authenticators that support PRF. It never touches the data of `pnpm run dev`.

```bash
pnpm run test:e2e --no-build      # reuse the last build
HEADED=1 pnpm run test:e2e        # watch the browsers
E2E_PORT=9000 pnpm run test:e2e   # use another port
```

Screenshots are written to `.wrangler/e2e/shots`, or to the directory in `E2E_SHOTS`.

## Before a pull request

Run the checks listed in [CONTRIBUTING.md](../CONTRIBUTING.md#development). `pnpm run check` runs the formatter in
check mode and the linter; `pnpm run fmt` formats the sources. The CI workflow (`.github/workflows/ci.yml`) runs the
same checks, the end-to-end test and the dependency audit on every pull request.

## Dependencies

- Every dependency in `package.json` is pinned to an exact version, and `pnpm add` keeps it that way (`saveExact` in
  `pnpm-workspace.yaml`). pnpm takes its settings from that file only; it also holds the overrides, each with its
  reason.
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
  - `vite-plus`, the `vite` alias (`npm:@voidzero-dev/vite-plus-core`) and `vitest` in `package.json`, and the `vite`
    and `vitest` overrides in `pnpm-workspace.yaml`. `vp toolchain vitest` prints the Vitest version that Vite+ bundles.
    Dependabot proposes only `vite-plus`; upgrade the rest in its pull request.
  - `wrangler`, `@cloudflare/vite-plugin` and `@cloudflare/vitest-plugin`. Each plugin depends on the exact Wrangler it
    was released with, so choose the plugin releases that depend on the chosen Wrangler.
- `pnpm audit` must report nothing. CI checks it, and the registry signatures (`pnpm audit signatures`), on every pull
  request and every week. Fix an advisory by upgrading, or with an override scoped to the version of the package that
  brings it in; accept one only by listing its GHSA under `auditConfig.ignoreGhsas` in `pnpm-workspace.yaml`, with the
  reason.

## Reading the code

- [docs/PROTOCOL.md](PROTOCOL.md) is the normative specification. Code comments cite its sections as `§n.m`.
- `src/lib/proto.ts` implements the primitives, derivations and record formats of the specification, and
  `src/lib/wire.ts` the binary API formats. Both are shared by the browser and the server.
- `src/client/engine.ts` is the client engine that the UI talks to through the `Engine` interface in
  `src/client/types.ts`; the other modules in `src/client/` implement its parts.
- `src/server/api.ts` handles every `/api/v2/*` request, and each Durable Object lives in its own file in
  `src/server/`.

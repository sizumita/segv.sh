# Development

This guide sets up a local instance of segv.sh and runs its tests. For the overall design, read the
[README](../README.md) first.

## Requirements

- Node.js `^22.18.0`, `^24.11.0` or `>=26.0.0`, with npm.
- To use the app by hand: a browser whose passkey provider supports the WebAuthn PRF extension. Passkeys created on
  `localhost` are separate from the passkeys of any deployment.
- For the end-to-end tests: Playwright's Chromium, installed once with `npx playwright install chromium`.

## Local setup

1. Install the dependencies:

   ```bash
   npm install
   ```

2. Create `.dev.vars` with the two server secrets, each 32 random bytes in base64url. `ROUTE_KEY` keys the routing of
   rows to shards, and `SRV_KEY` is the seed of the server's Ed25519 key, which signs write receipts and checkpoints.
   Without them, every `/api/v2/*` request answers 503 `server misconfigured`. The file is gitignored.

   ```bash
   node -e 'const k = () => require("node:crypto").randomBytes(32).toString("base64url"); console.log(`ROUTE_KEY=${k()}\nSRV_KEY=${k()}`)' > .dev.vars
   ```

3. Create the local D1 database:

   ```bash
   npm run db:migrate:local
   ```

4. Start the development server:

   ```bash
   npm run dev
   ```

   `vp dev` runs the Qwik app with server-side rendering, the API and every Durable Object inside workerd, through
   `@cloudflare/vite-plugin`. Open the local URL that it prints.

Local data (D1, R2 and the Durable Objects' storage) lives in `.wrangler/state`; delete that directory and run
`npm run db:migrate:local` again to start over. The deployment parameters in `wrangler.jsonc` apply locally too, so
proof of work costs as much as in production, and a membership change or a new conversation takes at least
Δ + SKEW = 12 seconds to become visible to the other members.

To try the production build locally, run `npm run preview`: it builds the app and serves it with `wrangler dev`, which
also reads `.dev.vars`.

## Tests

`npm test` runs `vp test run`, which has three Vitest projects:

| Project   | Files                   | What it covers                                                                                                                                                                                       |
| --------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unit`    | `src/**/*.test.ts`      | The cryptographic core, the wire formats and the UI helpers, in Node                                                                                                                                 |
| `workers` | `test/worker/*.spec.ts` | The API, the Durable Objects and the D1 directory on the Workers runtime, configured by `test/worker/wrangler.test.jsonc` (Δ = 1 s, SKEW = 0)                                                        |
| `engine`  | `test/engine/*.spec.ts` | The real client engine against `FakeWorld`, an in-memory implementation of the server: accounts, conversations, delivery, membership, restore, integrity, links, and how the cost of a restore grows |

To run one project or one file:

```bash
npx vp test run --project engine
npx vp test run test/engine/restore.spec.ts
```

The test directories have TypeScript configurations of their own. Check them with `npx tsc --noEmit -p test/engine` and
`npx tsc --noEmit -p test/worker`, and the app with `npx tsc --noEmit -p .`.

### End-to-end tests

`npm run test:e2e` builds the app, starts `wrangler dev` on port 8817 with a generated configuration (low proof of
work, Δ = 1 s, fresh secrets and its own state in `.wrangler/e2e`), and drives headless Chromium with virtual
authenticators that support PRF. It never touches the data of `npm run dev`.

```bash
npm run test:e2e -- --no-build   # reuse the last build
HEADED=1 npm run test:e2e        # watch the browsers
E2E_PORT=9000 npm run test:e2e   # use another port
```

Screenshots are written to `.wrangler/e2e/shots`, or to the directory in `E2E_SHOTS`.

## Before a pull request

Run the checks listed in [CONTRIBUTING.md](../CONTRIBUTING.md#development). `npm run check` runs the formatter in check
mode and the linter; `npm run fmt` formats the sources.

## Reading the code

- [docs/PROTOCOL.md](PROTOCOL.md) is the normative specification. Code comments cite its sections as `§n.m`.
- `src/lib/proto.ts` implements the primitives, derivations and record formats of the specification, and
  `src/lib/wire.ts` the binary API formats. Both are shared by the browser and the server.
- `src/client/engine.ts` is the client engine that the UI talks to through the `Engine` interface in
  `src/client/types.ts`; the other modules in `src/client/` implement its parts.
- `src/server/api.ts` handles every `/api/v2/*` request, and each Durable Object lives in its own file in
  `src/server/`.

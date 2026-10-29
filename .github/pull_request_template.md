## What and why

## Protocol

- [ ] This changes nothing that docs/PROTOCOL.md defines.
- [ ] This implements a change to the specification agreed in an issue: #

## Checks

- [ ] `pnpm run check`
- [ ] `pnpm exec tsc --noEmit -p .`, `pnpm exec tsc --noEmit -p test/engine` and `pnpm exec tsc --noEmit -p test/worker`
- [ ] `pnpm test`
- [ ] `pnpm run build`
- [ ] `pnpm run test:e2e` (for changes to the client, the UI or the Worker)

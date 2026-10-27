# Contributing to segv.sh

Thank you for helping. Bug reports, fixes, tests and documentation are all welcome.

- **Security problems:** do not open a public issue; follow [SECURITY.md](SECURITY.md).
- **Bugs:** open an issue with the browser, the operating system and the passkey provider you used, and the steps to
  reproduce. Never paste a recovery code or any other secret.
- **Larger changes:** open an issue first, so that the approach can be agreed on before you write code.

## The specification comes first

[docs/PROTOCOL.md](docs/PROTOCOL.md) is normative, and the implementation follows it byte for byte. A change to
anything the specification defines needs a change to the specification first: the bytes that are written, served or
accepted, the labels, the verdicts, the texts of warnings and system lines, the requests a client makes, and the
server's status codes, headers and bodies. Open an issue that describes the change and its effect on the guarantees
(§0.3 and §0.4) and on the leakage table (§13). Pull requests do not edit `docs/PROTOCOL.md` directly: the maintainer
applies accepted changes to the specification, and the implementation follows it.

What the specification leaves to the implementation, such as the names of functions and types, failure codes, log
lines, and the order of checks that it does not fix, can change freely (see the preamble of `docs/PROTOCOL.md`).

## Existing data

The deployment at <https://segv.sh> holds real data. A change must keep everything that is already stored readable:
rows, self-lane records, key bundles, images, directory records, and what browsers keep locally.

## Development

Set up a local instance as described in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Before you open a pull request,
run:

```bash
npm run check
npx tsc --noEmit -p .
npx tsc --noEmit -p test/engine
npx tsc --noEmit -p test/worker
npm test
npm run build
```

When you change the client, the UI or the Worker, also run `npm run test:e2e`. When you change `wrangler.jsonc`, also
run `npx wrangler deploy --dry-run` after `npm run build`.

## Guidelines

- **Tests.** Test each rule where it is enforced: unit tests for the cryptographic core and the wire formats
  (`src/lib/*.test.ts`), Workers-runtime tests for the server (`test/worker/`), and engine tests against `FakeWorld`
  for client behaviour (`test/engine/`). Cite the section of the specification that a test checks, such as `§6.4`.
- **Cryptographic core.** `src/lib/proto.ts` runs in the browser, the Worker and the Durable Objects. Keep its only
  dependencies the `@noble/*` libraries.
- **Logs.** Server logs must not contain request bodies, client addresses or headers, uids, handles, labels, topics,
  blob ids or credential ids (§9.7 of the specification). Workers invocation logs stay disabled.
- **Served code.** Every byte of JavaScript the site serves can read users' keys. Do not add third-party scripts,
  styles, fonts or network requests: the Content Security Policy in `src/routes/plugin@csp.ts` allows only the site's
  own origin. Add runtime dependencies only for a strong reason.
- **Formatting.** `npm run fmt` formats the sources; `npm run check` must pass.
- **Commits.** Keep each commit focused, and explain in its message why the change is needed.

## License

By contributing, you agree that your contributions are licensed under the
[GNU Affero General Public License v3.0 only](LICENSE), the license of this project.

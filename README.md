# segv.sh

English | [日本語](README.ja.md)

segv.sh is an end-to-end encrypted messenger for the web, for one-to-one and group conversations with text and
images. A passkey unlocks your keys in the browser through the WebAuthn PRF extension, and any device can restore all
of your conversations and their history with that passkey or a recovery code.

The server is designed to be public: anyone may read every byte of conversation data it stores, so that data holds
nothing secret. Each client computes the labels of the rows meant for it and fetches only those rows. The one
exception is optional: a deployment that offers notifications keeps a sealed registration for each device that turns
them on, and never serves it (see [Notifications](#notifications)).

The reference deployment runs at <https://segv.sh>.

> **Status: experimental.** The protocol and this implementation have not had an independent security review. Read
> the [security model](#security-model) before you rely on segv.sh.

## Features

- One-to-one and group conversations (up to 32 members) with text and images.
- Sign-in with a passkey. A recovery code, shown once at registration, unlocks the account without a passkey, and
  more passkeys can be added later.
- Restore on any device: a passkey or the recovery code brings back every conversation and its history, including the
  history from before membership changes.
- Membership changes: add and remove members, or leave. The remaining members then move to a new key.
- A fingerprint for every account, to compare keys out of band.
- Integrity warnings when the server rewrites or rolls back data, drops rows from a sender's sequence, or shows
  members different views.
- Optional notifications (Web Push), off by default and turned on per device. A notification says "new messages", or,
  if the user chooses so on that device, the conversation's name or its name and newest message, which the device
  decrypts itself; invites, requests and reactions never notify.
- A URL for each conversation (`/#c/…`) that opens it from a link, a reload or a notification. The part after `#`
  never reaches the server, and it is not the conversation's secret id.
- Installable as an app (a web app manifest; on iPhone and iPad, "Add to Home Screen").

## How it works

Everything a conversation produces is stored as **rows** in a public, create-only store:

```
(era, label) → (time, size class, ciphertext)
```

- An **era** is one week. A **label** is 16 bytes that only the intended readers can compute (a PRF output). The time
  is rounded to Δ seconds (10 s in production), and the ciphertext has one of four fixed sizes.
- The first write of a label wins and is never changed. Nothing else is stored about a row: no sender, recipient,
  conversation, epoch, counter, arrival order or IP address.
- A client computes the labels it expects and fetches exactly those rows by key. New rows arrive over WebSocket topics
  that the server never stores. Clients never download or scan data meant for others, with one exception:
  first-contact invites in the global inbox, which every client trial-decrypts.

The specification calls this design a Label-Indexed Store. On top of it:

- **Accounts.** The root of an account is a random 32-byte account key (AK). It is sealed to an X-Wing key derived
  from each passkey's PRF output and to one derived from the recovery code, and these wraps are kept in the public
  directory. The AK stays in memory, unless you choose to remember the device, which keeps it wrapped by a
  non-extractable WebCrypto key in IndexedDB.
- **Conversations.** One-to-one chats and groups use the same protocol: a sequence of epochs, each with a fresh random
  epoch key that is delivered to every member with X-Wing (X25519 + ML-KEM-768). Each message is signed with Ed25519
  and then encrypted with XChaCha20-Poly1305. Membership changes are signed claims on a control lane, and every member
  evaluates them the same way.
- **State across devices.** The conversations you joined, their epoch keys, how far each lane has been processed, and
  your contacts and pinned keys are appended to an encrypted self lane that only your account can find and read.
- **Images** are re-encoded in the browser, which strips EXIF and location data, then encrypted with a random key,
  padded, and stored in R2 under the hash of the ciphertext. The key travels only inside the message.

### Why not Double Ratchet or MLS?

If a passkey alone can restore the full history on a new device, then the passkey's PRF output and the public data are
enough to read that history, whatever the protocol: forward secrecy is out of reach for this goal. Synced passkeys also
return the same PRF output on every device, so they cannot tell devices apart, and ratchet state would have to be
synchronised between devices, which brings back the same problem and risks key or nonce reuse. And because all data
is public, anyone can archive it and decrypt it later with a quantum computer, so post-quantum key delivery matters
more here than forward secrecy. [docs/DESIGN.md](docs/DESIGN.md) §1 (in Japanese) has the full reasoning.

## Status

The current implementation is stage 1 of protocol v2. Working:

- registration with a passkey, and sign-in with a passkey or the recovery code;
- one-to-one and group conversations with text and images;
- restore after a reload or on another device, including the history of earlier epochs;
- adding and removing members, leaving, and moving to a new key after a leave;
- integrity checks: the signed checkpoint chain, write receipts, detection of missing rows, and split-view detection;
- invite links, inside the client engine (there is no UI for them yet).

Not implemented yet:

- self-lane snapshots ([PROTOCOL.md §7.4](docs/PROTOCOL.md#74-snapshots)). Without them a restore reads the account's
  whole self lane, so restoring takes longer as an account accumulates history;
- the work planned for later stages, such as paging old eras into R2, anonymous write tokens, OHTTP, groups larger than
  32 members and inclusion proofs ([PROTOCOL.md §14](docs/PROTOCOL.md#14-deferred-to-stage-2--3)).

## Security model

The protocol considers three adversaries: the **public**, who reads and archives every stored byte forever and may
later own a quantum computer; the **operator**, who runs the server, sees every request as it happens and can run any
server code, but cannot break the cryptography; and **malicious members** of a conversation.

segv.sh protects:

- **Confidentiality, including against a future quantum computer.** Message text, images, conversation names and
  member lists can be read only with a member's passkey PRF output, recovery code or account key, or with the epoch
  key. Every key is delivered with X-Wing, and everything else uses 256-bit symmetric cryptography.
- **Unlinkability in the public data.** Rows carry no sender, recipient or conversation, and labels are independent
  PRF outputs. The public data shows the era, rounded time and size class of each row, inbox counts per time slot, the
  directory of handles and public keys, and, once per hour, whether any image or key bundle was uploaded.
- **Anonymous invites.** The recipient of a first-contact invite cannot be identified from the public data, even with
  a quantum computer.
- **Authenticity among members.** Every row is signed by its sender inside the encryption, and replaying it into
  another slot, era, epoch or conversation fails.
- **Forward exclusion.** Removed members cannot read later epochs and do not learn who was added (they do learn which
  of the earlier members stayed).
- **Membership liveness.** Junk rows cannot block membership changes. A member who signs a bad change can still freeze
  them, but is named in the warning, and every member reaches the same verdict.
- **Portability.** A passkey or the recovery code restores everything on any device.
- **Partial detection of server misbehaviour:** changed rows, rows missing from a sender's sequence, rewritten or
  rolled-back history (through a signed checkpoint chain that each browser keeps), and split views between members.
  Signed receipts prove that a write was accepted.
- A database leak exposes nothing new: the conversation data is public by design. The one store that is not public,
  the optional notification registrations, is sealed under a server key and holds no account, conversation or
  address.

segv.sh does not protect against:

- **The operator learning the social graph:** which topics each connection subscribes to, which labels each client
  fetches, the IP address of every write, and a prefix of every directory lookup. Hiding these needs OHTTP or private
  information retrieval, which later stages plan.
- **The operator omitting rows or giving members different answers** (about rows, uploads or the directory). Clients
  detect some of this, as listed above, but cannot prove it: there are no inclusion proofs or witnesses yet.
- **Key compromise.** There is no forward secrecy: anyone who obtains a passkey's PRF output (for example by taking
  over the cloud account that syncs the passkey), the recovery code or the account key can read everything that
  account could read, forever. There is no post-compromise security within an epoch.
- **Malicious JavaScript.** Code served by the operator, an XSS bug or a compromised dependency can capture the PRF
  output at the next unlock. This is inherent in end-to-end encrypted web apps. segv.sh narrows it with a strict
  Content Security Policy (Trusted Types, no third-party scripts); code transparency is future work.
- **Malicious members**, who can freeze membership changes for the whole conversation (and are named for it; if the
  change removed someone, messaging in that conversation stops too) or spam.
- **Inbox flooding:** anyone who pays the proof of work can fill the global inbox's daily cap, which delays first
  contacts and inbox deliveries for everyone.
- **Directory key substitution by the operator**, which is detected only by comparing fingerprints, by pinned keys,
  and by disagreement with the keys listed in conversations.
- Deniability among members, deletion (the archive is public), censorship resistance, and post-quantum signatures
  (signatures use Ed25519).
- **What notifications reveal**, on the devices that turn them on: see [Notifications](#notifications).

### Notifications

Notifications are off unless the deployment configures them and the user turns them on, per device. A device that
does registers a "bell" for each conversation it accepted: a value derived from that conversation's epoch key, which
every member can compute and no one else can. After sending a text or an image, a client asks the server to ring the
other members' bells, and the server sends each registered device one contentless push, at most once a minute. The
push names, encrypted to the device, the bells that rang. By default the device shows the fixed text "new messages". A
device that keeps its session can instead show the conversation's name, or its name and newest message: it looks the
bell up in a cache sealed on the device and, for the message, fetches and decrypts the new rows itself.

- The server stores, per device, its push endpoint and keys sealed under a server key, keyed hashes of its bells, and
  the day of its last registration: no account, conversation, topic or address, and nothing about which devices a
  message reached. It writes registration changes only once a day, because the platform keeps a 30-day history of the
  storage; that history can still suggest, on a quiet day, which devices changed together.
- The browser's push service (Apple for every iPhone and iPad web app, Google, Mozilla or Microsoft) learns that the
  device uses segv.sh and when it is notified, and can guess from the timing which of its devices share a
  conversation.
- The operator sees, at each ring, which devices a message is for, including devices that are offline.
- A member can make other members' devices show the notification, at most once a minute, or hold the registration
  places of their bells and so keep their devices from being notified.
- A preview hands the conversation's name, and with messages their text, to the device's notification system: it can
  show them on the lock screen and keep them in its notification history after the messages or the app are gone. With
  message previews the device fetches the new rows after each push, also while the app is closed, so the operator
  learns the device's address each time.

[docs/PROTOCOL.md](docs/PROTOCOL.md) §9.8, §10.10, §11.13 and §13.4 are the normative statements.

Protocol v2 replaced an earlier design, v1, in which every client downloaded the whole public log. v2 makes a client's
cost independent of everyone else's data, at the price of some guarantees that v1 had.
[docs/DESIGN.md](docs/DESIGN.md) §3 (in Japanese) lists every guarantee and non-guarantee, and every point where v2 is
weaker or stronger than v1; [docs/PROTOCOL.md](docs/PROTOCOL.md) §0.3–§0.4 and §13 are the normative statements.

## Architecture

The app is a Qwik v2 site with a client engine that runs entirely in the browser, served by one Cloudflare Worker.

| Component               | Role                                                                                                                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Worker                  | The binary and JSON API under `/api/v2/*` and the realtime WebSocket; host pinning, proof-of-work checks and per-IP rate limits (IP addresses are never stored); server-side rendering of the app |
| `ShardDO` (one per era) | Stores rows: create-only, batched every Δ seconds into a hash chain, sealed when the era ends                                                                                                     |
| `InboxDO` (one per era) | The global inbox for first-contact invites; clients read the last 4 eras                                                                                                                          |
| `BlobRegDO`             | Registers uploads to R2 and their times, which membership changes depend on                                                                                                                       |
| `RealtimeDO`            | Hibernatable WebSockets that push new rows to the topics each client subscribed to                                                                                                                |
| `CheckpointDO`          | Every 60 seconds, signs the heads of the shard, inbox, upload registry and directory into a checkpoint chain                                                                                      |
| `PushDO` (optional)     | The sealed notification registrations of the devices that turned notifications on, and the notifications; written once a day                                                                      |
| D1                      | The directory (handle ↔ account id ↔ public keys, key wraps) and its public, hash-chained log                                                                                                     |
| R2                      | Encrypted images and key bundles, content-addressed and immutable                                                                                                                                 |

The server keeps no sessions and no login state: signing in means unlocking keys in the browser. Writes are anonymous;
abuse is limited by proof of work, which grows with the number of bytes stored, and by per-IP rate limits.

Built with TypeScript, [Qwik](https://qwik.dev/) v2 (release candidate), Vite+ (`vite-plus`), Cloudflare Workers,
Durable Objects (SQLite), D1 and R2. All cryptography comes from the [noble](https://paulmillr.com/noble/) libraries:
`@noble/curves`, `@noble/post-quantum` (X-Wing), `@noble/ciphers` and `@noble/hashes`.

### Repository layout

| Path                              | Contents                                                                                                                         |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `src/lib/proto.ts`                | The protocol's cryptographic core and encodings, shared by the browser, the Worker and the Durable Objects; uses only `@noble/*` |
| `src/lib/wire.ts`                 | Strict encoders and decoders for the binary API formats (put, get, inbox, feed and realtime frames)                              |
| `src/client/`                     | The browser-only engine: unlock and accounts, conversations, membership, delivery, restore, integrity, passkeys, images          |
| `src/routes/`, `src/components/`  | The Qwik UI                                                                                                                      |
| `src/server/`                     | The Worker's API, the Durable Objects and the D1 directory                                                                       |
| `src/entry.cloudflare-workers.ts` | The Worker entry: `/api/*` goes to the API, everything else to Qwik's server-side rendering                                      |
| `migrations/`                     | The D1 schema                                                                                                                    |
| `src/**/*.test.ts`                | Unit tests: the cryptographic core and wire formats (cross-checks, tampering, known-answer vectors, fuzzing) and UI helpers      |
| `test/worker/`                    | API, Durable Object and directory tests on the Workers runtime                                                                   |
| `test/engine/`                    | `FakeWorld`, an in-memory server, and tests of the real client engine against it                                                 |
| `test/e2e/`                       | End-to-end tests with Playwright and virtual passkeys that support PRF                                                           |
| `docs/`                           | The specification and the design rationale                                                                                       |

## Getting started

You need Node.js 22.18+, 24.11+ or 26+, and a browser whose passkey provider supports the WebAuthn PRF extension.
Without PRF support you can still unlock an account with its recovery code.

```bash
npm install
# Local server secrets: two random 32-byte values in base64url (the file is gitignored).
node -e 'const k = () => require("node:crypto").randomBytes(32).toString("base64url"); console.log(`ROUTE_KEY=${k()}\nSRV_KEY=${k()}`)' > .dev.vars
npm run db:migrate:local
npm run dev
```

Open the local URL that `npm run dev` prints. In development the passkey's relying party is `localhost`.
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers the details.

## Checks and tests

```bash
npm run check                    # formatting and lint
npx tsc --noEmit -p .            # type check: the app
npx tsc --noEmit -p test/engine  # type check: the engine tests
npx tsc --noEmit -p test/worker  # type check: the Workers-runtime tests
npm test                         # unit, Workers-runtime and engine tests
npm run build                    # production build, including a type check and lint
npm run test:e2e                 # production build + wrangler dev + headless Chromium
```

The end-to-end tests need Playwright's Chromium (`npx playwright install chromium`). They run against their own local
state, with low proof of work and generated secrets, and do not touch your development data.

## Deployment

segv.sh deploys to Cloudflare with `npm run deploy` once the D1 database, the R2 bucket, the secrets and the domain are
set up; [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) walks through it. Some choices cannot be changed later:

- **Fix the domain before the first user registers.** Passkeys and their PRF outputs are bound to the domain (the
  WebAuthn relying party ID), so moving to another domain locks every user out of their keys.
- **`DELTA_S` and `INBOX_SLOT_S` are constants of a deployment.** Once it has stored data, they must never change.
- **Keep `SRV_KEY` and `ROUTE_KEY` for the life of the deployment.** Every client pins the server's signing key and
  warns if it changes.

Run staging as a separate deployment, with its own Worker name, D1 database, R2 bucket, secrets and host name.

## Documentation

- [docs/PROTOCOL.md](docs/PROTOCOL.md): the normative, byte-level specification of protocol v2 (English)
- [docs/DESIGN.md](docs/DESIGN.md): why the design looks the way it does, and what it guarantees and does not
  (Japanese)
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): local development and tests
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): deploying your own instance

## Contributing

Bug reports, fixes, tests and documentation are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Changes to the
protocol start as a proposal against the specification.

## Reporting a vulnerability

Please do not open a public issue. Report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/sizumita/segv.sh/security/advisories/new); see
[SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 sizumita.

segv.sh is free software, licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(`AGPL-3.0-only`). If you run a modified version as a network service, the license requires you to offer its source
code to the people who use it.

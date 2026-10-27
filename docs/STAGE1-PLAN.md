# segv.sh stage 1 (LIS v2): implementation plan

The normative target is `stage1-spec.md`, called **SPEC** below. In the repository it is `docs/PROTOCOL-v2.md` until M9
renames it to `docs/PROTOCOL.md` (round 8). Paths are relative to the repository root.

**Copies in the repository (round 10).** The implementing session copies every revision verbatim (`cp`), in a commit
of its own: SPEC over `docs/PROTOCOL-v2.md` (after M9, `docs/PROTOCOL.md`) and this plan over `docs/STAGE1-PLAN.md`.
At c993e83 they still hold the `sent-2a/` spec and the `sent-1/` plan, which describes the parallel build that rounds
8–9 replaced, so the first copy lands before M6a. Both files stay in `vite.config.ts`'s `fmt.ignorePatterns`.

**Checks (round 8).** Every milestone lands with these green: `vp check`, `vp test run` (projects `unit`, `workers`
and `engine`), `npx tsc -p test/engine`, `npx tsc -p test/worker` and `npm run build` (the client and Worker bundles,
the root `tsc` and lint); after a change to `wrangler.jsonc`, also `npx wrangler deploy --dry-run` after
`npm run build`. From M6b on, every milestone also lands with `npm run test:e2e` green on the steps §5 lists for it.
From 8092e98 until M6b the app is not usable end to end: `src/client/engine.ts` is a placeholder that starts in the
`fatal` phase, and `npm run test:e2e` is red.

**Baseline (round 9).** HEAD is c993e83 ("Stage 1: apply spec revision sent-2a to M0–M5"), which follows 8092e98 and
implements every "Affects M0–M5" item of `sent-2a/` except the LEFT record. Line numbers in this plan are at c993e83
unless marked "at 8092e98"; tests are also cited by name. The open M0–M5 items (round 10) are M1's LEFT record,
`powSolve` and `acceptOldRow`, and M4's feed tokens (`changes-since-sent-2a.md` (a)); round 11 adds only two doc
comments in M1 (`acceptOldRow`'s list contract and `EpochRec.claim`) and the 9 MiB test's comment in M4
(`test/worker/api.spec.ts:2343`); round 12 adds one M1 check, `B ≥ m` in `claimShapeValid` (SPEC §6.4 "Order of
requests").

## 0. Strategy

### 0.1 v2 replaces v1 in place (round 8)

Commit 8092e98 replaced v1 in place, and c993e83 brought M0–M5 to the `sent-2a/` delta. Nothing of v1 is kept,
migrated or made compatible, and existing local v1 data is dropped (nothing was ever deployed). There is no parallel
build and no cut-over:

- **Protocol core.** `src/lib/proto.ts` holds the v2 core and the shared encoding and primitives. Its tests are
  `src/lib/proto.test.ts` (core) and `src/lib/proto-conv.test.ts` (M, D, J, SGB2, claims, self lane); `src/lib/wire.ts`
  and `wire.test.ts` hold the binary codecs.
- **Server.** `src/server/*`. Every endpoint is under `/api/v2/*` (`handleApi` in `src/server/api.ts`), and any other
  `/api/*` path is a 404. Wire domain strings are `segv.sh/v2/...`.
- **Client.** The engine modules of M6–M8 and M10 go in `src/client/*` (§0.6). M6a replaces the placeholder class in
  `src/client/engine.ts` with `SegvEngine`. `src/components/real-engine.ts` already re-exports `getEngine` from that
  module, so no import line and no build flag changes at any point.
- **Tests.** Unit tests are `src/**/*.test.ts` (vitest project `unit`), Worker tests `test/worker/*.spec.ts`
  (`workers`), engine tests `test/engine/*.spec.ts` against the FakeWorld of `test/engine/harness.ts` and
  `test/engine/fake/*` (`engine`), and E2E `test/e2e/run.mjs` (§5).
- **v1 sources.** v1 code and tests no longer exist in the tree. Where this plan says "port" or cites a v1 file or line
  (v1's engine, API client and harness, the v1 `test/engine/*.spec.ts`, v1's `test/worker/api.spec.ts` and
  `log-do.spec.ts`, `src/server/log-do.ts`), read it at commit 3de5f5e (`git show 3de5f5e:<path>`); this plan writes
  such paths as `3de5f5e:<path>`. Ported code is rewritten for v2; it is never kept beside v2 code.
- **Names.** No identifier has a `V2` suffix (`SegvEngine`, `handleApi`, `checkPow`, `powParams`, `routeLabel`,
  `stampResponse`, `checkBundleShape`, `checkRecordShape`); `v2Params` and `v2ParamsValid` keep their names. Earlier
  versions of this plan (`sent-1/`) used `src/lib/proto2.ts`, `src/server/v2/`, `src/client/v2/`, `test/worker/v2/`,
  `test/engine2/` (vitest project `engine2`) and `V2`-suffixed identifiers; none of them exists any more. The wire
  names `/api/v2/…` and `segv.sh/v2/…` are unchanged.
- **Local data.** State from before 8092e98 is not migrated. Anyone holding an older `.wrangler/state` deletes it and
  runs `npm run db:migrate:local`, because `0001_init.sql` was rewritten under the same name and the DO tag `v1` now
  lists other classes. `test/e2e/run.mjs` wipes `.wrangler/e2e` itself.
- **The app is down until M6b.** From 8092e98 until the end of M6b the UI shows the placeholder's fatal screen and
  `npm run test:e2e` is red. M6 is ordered so that the minimal end-to-end path (register/unlock, 1:1 creation, send,
  receive, restore) works first (M6a, M6b), and `test/e2e/run.mjs` is rewritten for v2 as soon as it does (§5).

### 0.2 Session ownership rule

Everything listed here is inside the repository. The implementing session owns it.

### 0.3 `src/client/types.ts` (round 8)

The `Engine` interface keeps every shape that already fits v2, and changes where v2 state would otherwise be squeezed
into a v1 shape. The changes land in M6a, together with `src/client/mock-engine.ts` (still used by `?mock` in dev) and
the UI changes of §0.4:

- **`ConversationView.blocked: "" | "removed" | "left" | "pending" | "frozen"`** (new): why `canSend` is false, and
  `""` when it is true, so `canSend === (blocked === "")`.
  - `removed` / `left`: self is no longer a member (if both hold, `removed`);
  - `pending`: an undecided control slot, or a winner not yet final or processed, has stayed so for 30 s (the
    step-2 wait, an `EngineOptions` delay), so a TEXT would fail (SPEC §11.3 step 2). A shorter wait shows nothing,
    and a send made meanwhile waits in step 2 (round 9);
  - `frozen`: frozen by a change whose `rm` removed a member who had not left (SPEC §6.6 step 6).
- **`ConversationView.frozen: boolean`** (new): the members can no longer change (SPEC §6.6 steps 4 and 6), so
  `addMembers` / `removeMember` fail with "can no longer change". Sending (unless `blocked = "frozen"`) and `leave`
  still work.
- **`ConversationView.request: boolean`** (new): a request copy (SPEC §11.5). Opening it (`markRead`) accepts it and
  makes `D.by` a contact.

Kept as they are: `Phase`, `Me`, `MemberView`, `ImageRef`, `MessageView`, the other `ConversationView` fields and every
`Engine` method; `EngineState.head` stays `{seq, h}` (SPEC §12.3 defines it as `{seq: q, h: b64u(C_q)}`) and
`EngineState.warnings` stays `string[]` (critical first, then noise with "(×n)"). Links stay off `Engine`
(SPEC §11.11), and pending invitations get no field (Q10).

The doc comments change as follows:

| field | new comment |
| ----- | ----------- |
| `Phase` `"fatal"` | "unrecoverable (account check failure: account missing from the directory, or keys mismatch)" |
| `MessageView.seq` | "local application order (stable tie-breaker), not a server sequence; 0 for a local echo" |
| `MessageView.ts` | "ms; sender time clamped to the row's public time ± 5 min (SPEC §11.8)" |
| `ConversationView.messages` | "display order (SPEC §11.8); local echoes last" |
| `ConversationView.canSend` | "true iff `blocked` is `""`: false once this user was removed or left, while an undecided control slot, or a winning claim not yet final or processed, has stayed so for 30 s (rounds 9–10), and in a frozen conversation whose freezing change removed a member who had not left, by the current leave state (SPEC §11.3 step 2; round 11); otherwise a frozen member can still send" |
| `ConversationView.id` | "opaque copy key (`b64u(conv)`, or `b64u(conv)~i` for a later copy, SPEC §7.3); secret, only ever used locally" |
| `MessageView.key` | "stable unique key (era and label hex for a row, `local:<n>` for a local echo)" |
| `MemberView.left` | "recorded as left in the current epoch (its LEAVE row, or a LEFT record at restore) and not yet rotated out" |
| `MemberView.handle` | "handle, or `?` + 8 uid characters for a member not (or not validly, or not yet) resolved in the directory (SPEC §11.2)" |
| `EngineState.head` | "latest verified checkpoint: {seq: q, h: b64u(C_q)}; `{seq: 0, h: ""}` until M8" |
| `EngineState.syncing` | "restoring or catching up" |
| `EngineState.connected` | "realtime socket (/api/v2/rt) is open" |

The rest of the contract:

- `src/components/state.ts` `initialEngineState` is unchanged (the new fields are per conversation).
- `src/client/mock-engine.ts` sets `blocked`, `frozen` and `request` on every conversation it builds, keeps one
  removed, one pending, one frozen-with-removal and one request conversation for UI work, and replaces its v1 warning
  samples ("… log head at seq 1093 …") with v2 texts of SPEC §12.
- Warning and error strings stay where the spec keeps them (SPEC §11.1, §11.3, §11.9, §6.6, §6.7, §12.1–§12.5). New
  strings (none of them occurs in v1's engine, `3de5f5e:src/client/engine.ts`):
  - critical: "@by made an invalid membership change; the members of this conversation can no longer change"
    (frozen, `D'` invalid); "@by's membership change was never delivered to you; the members of this conversation can
    no longer change" (frozen, own entry did not open; replaces v1's unnamed text); "the public keys of @x changed" (a
    pin mismatch, or a descriptor key that differs from the directory); "the server is hiding messages from @x" and
    "the server is showing different messages from @x to different members" (§12.2); "the server changed a stored
    entry: history was rewritten" (§12.1); "the server's signing key changed" (§12.3); "the server returned an invalid
    receipt" (§12.5);
  - noise: "ignored an invalid membership change" (e-invalid control rows); "@x has not been notified yet; retrying";
    "the directory answered fewer accounts than expected";
  - errors: "a removed member could still read this conversation; start a new conversation" (SPEC §11.3 step 2);
    fatal "your account was not found in the directory of this server" (SPEC §11.1, replacing v1's "…in the log of
    this server").

  Kept from v1 and used in new places: "the conversation is changing membership; try again in a moment" (a send while
  a claim is pending, SPEC §11.3 step 2), "ignored a conversation key with an invalid signature" (a failed `D.by` key
  check, SPEC §6.7).
- `MemberView.handle` is `?` + 8 uid characters for an unknown member (SPEC §11.2), which now also covers a member
  whose `sigPk` or `kh` (the hash of its KEM key) in the descriptor differs from the directory's, and members of an
  unopened request other than the inviter.
- **Semantics** (document them in the doc comments of `types.ts`):
  - `createConversation` resolves after the bundle upload and the first self row (SPEC §6.1 step 5); invitations
    finish in the background (≥ Δ + SKEW later).
  - `addMembers` / `removeMember` resolve after the switch and the first delivery attempt (SPEC §6.3).
  - `markRead(convId)` is also the "conversation opened" hint: it accepts a request copy and starts scrollback once
    (SPEC §11.10–§11.11), even when `unread` is 0.
  - Links are implemented inside the engine (`createLink`, `openLink`) but are **not** added to `Engine` in stage 1
    (SPEC §11.11; M10).

### 0.4 UI (round 8)

The UI stays minimal. Required changes, in M6a except where noted:

- `src/components/conversation.tsx:16-26` (M6b): today `markRead(id)` runs only `if (unread > 0 && …)`. After a reload
  every conversation has `unread = 0` (SPEC §11.8), so scrollback (SPEC §11.10) would never start, a device would show
  at most 30 rows per lane, and a request copy would never be accepted by opening it. Add a second `useVisibleTask$`
  that tracks `props.conv.id` and calls `markRead(id)` once each time the pane opens (and the page is visible),
  whatever `unread` is. Keep the existing task for unread changes.
- `src/components/composer.tsx`: take `blocked` instead of `canSend`.
  - `removed` / `left` keep today's text, "you are no longer a member of this conversation. you can read its history
    but cannot send." (`test/e2e/run.mjs` waits for it);
  - `pending` shows "the conversation is changing membership; you can send again in a moment.";
  - `frozen` shows "a removed member could still read this conversation; start a new conversation."
- `src/components/members.tsx`: the remove buttons and the add form need `canSend && !frozen`; "leave conversation"
  needs only `blocked !== "removed" && blocked !== "left"`, because a frozen member can still leave (SPEC §6.6 step 6).
- `src/components/conv-list.tsx:129`: mark a conversation `gone` for `blocked === "removed" || blocked === "left"`
  instead of `!canSend`, and show a dim "request" marker on request copies.
- `src/components/chat.tsx:27-28` (M8): "log #N" becomes "checkpoint #N" once `head` holds the verified checkpoint.

Behaviours the UI already depends on are kept:

- `createConversation` inserts the conversation into `conversations` before resolving (`app.tsx:72` clears `active`
  otherwise). It now resolves in about one round trip plus the blob upload, not after the ≥ 12 s commit wait.

**CSP** (`src/routes/plugin@csp.ts`; M6c). It changes once, for the trial-decryption Web Worker of SPEC §11.5 step 2.
It sends `require-trusted-types-for 'script'` with `trusted-types 'none'`, and `new Worker(url)` is a Trusted Types
sink (TrustedScriptURL), so Chromium would throw and report a violation. Replace `"trusted-types 'none'"` with
`"trusted-types segv-worker"`. The worker is created in its own module, `src/client/inbox-worker-url.ts` (round 9),
which starts with `/// <reference types="vite/client" />` (the `*?worker&url` declaration comes from `vite/client`,
which `test/engine/tsconfig.json` does not load) and takes the bundled worker URL from
`import workerUrl from "./inbox-worker.ts?worker&url"` (Vite emits the worker and its imports as one same-origin file).
When `window.trustedTypes` exists, it creates the policy once,
`trustedTypes.createPolicy("segv-worker", { createScriptURL: (u) => { if (u !== workerUrl) throw new TypeError("unexpected worker URL"); return u; } })`
(a second `createPolicy` with that name throws), and calls `new Worker(policy.createScriptURL(workerUrl), {type: "module"})`;
without Trusted Types it passes the plain URL. The engine never imports that module statically: it creates the worker
through `EngineOptions.inboxWorker?: (() => Promise<Worker | null>) | null`, whose default (the option absent) imports
`inbox-worker-url.ts` dynamically; a factory that resolves to `null` and the option `null` both mean no worker, and
trial decryption runs on the same thread (round 10). The engine tests set the option to `null`, so they always take
the same-thread path, and
`npx tsc -p test/engine`, which still checks the module through the dynamic import, gets the declaration from its
reference directive (round 9). `worker-src 'self'` already allows the file. `/api/v2/rt` is same-origin `ws:`/`wss:`
and needs no change. The e2e step "no page errors or CSP violations" covers both.

### 0.5 Configuration (done at 8092e98; round 8)

This configuration is the baseline. A later class or schema change adds a new DO migration tag (`v2`, …) or a new
`migrations/0002_….sql`; it never edits the existing ones.

- **`wrangler.jsonc`.**
  - Bindings: `DB` (D1), `BLOBS` (R2), `SHARD`/`ShardDO`, `BLOBREG`/`BlobRegDO`, `INBOX`/`InboxDO`, `RT`/`RealtimeDO`
    and `CKPT`/`CheckpointDO`.
  - One migration, `{ "tag": "v1", "new_sqlite_classes": ["ShardDO", "BlobRegDO", "InboxDO", "RealtimeDO",
    "CheckpointDO"] }` (no LogDO, no `deleted_classes`).
  - Rate limits: `RL_WRITE` 1001, `RL_BLOB` 1002, `RL_READ` 1003 and `RL_INBOX` 1004 (10 per 60 s).
  - Vars: `POW_REGISTER` 20, `POW_WRAP` 18, `POW_PUT` 16, `POW_INBOX` 18, `POW_BLOB` 18, `DELTA_S` 10, `SKEW_S` 2,
    `INBOX_SLOT_S` 10, `E_FIRST` (the era of the first deploy) and `APP_HOSTS` "segv.sh,localhost".
- **Secrets.** `ROUTE_KEY` (32 B, b64u) and `SRV_KEY` (32-byte Ed25519 seed, b64u). They come from `wrangler secret put`
  in production, from `.dev.vars` for `vp dev`, and from `vars` in `test/worker/wrangler.test.jsonc` and in the
  generated e2e config (§5). When either is missing, `/api/v2/*` answers 503 "server misconfigured".
- **`test/worker/wrangler.test.jsonc`** mirrors the bindings with `DELTA_S` 1, `SKEW_S` 0, `INBOX_SLOT_S` 1,
  `E_FIRST` 1, low PoW and fixed test secrets.
- **D1.** One `migrations/0001_init.sql` holds the directory tables `user`, `wrap`, `dirlog` and `dirmeta`, and the
  `INSERT OR IGNORE INTO dirmeta (k, v) VALUES ('users', 0)` row that the registration `UPDATE` needs (SPEC §9.6).
- **DO classes** are exported from `src/entry.cloudflare-workers.ts` and `test/worker/entry.ts`. `Env` in
  `worker-configuration.d.ts` lists every binding, var and secret above (regenerate it with `npm run cf-typegen`
  after a change).
- **`test/e2e/run.mjs`** generates its config from `wrangler.jsonc`; its overrides, readiness probe and audit are in
  §5.

### 0.6 File layout (round 8; ✓ = exists at 8092e98 and c993e83)

```
src/lib/proto.ts             ✓ v2 core (SPEC §1–§8, §9 commitments, §10.2 PoW, §12 hashes) + shared encoding/primitives
src/lib/proto.test.ts        ✓ core: node:crypto re-implementation, tamper, fuzz, KATs
src/lib/proto-conv.test.ts   ✓ conversation codecs: M, D, J, SGB2, claims, self lane
src/lib/wire.ts, wire.test.ts ✓ binary codecs for /put, /get, /inbox, /feed, rt frames (Worker, client, FakeWorld, e2e)
src/server/api.ts            ✓ router + handlers: handleApi, routeLabel, stampResponse
src/server/env.ts            ✓ params from env (Δ, SKEW, Δin, E_FIRST), era bounds, server keys, kroute/kcommit, signing
src/server/batch.ts          ✓ batch commitments, head chain and alarm discipline (ShardDO, BlobRegDO)
src/server/types.ts          ✓ DO RPC types and stub names (v2; keep)
src/server/{shard-do,blobreg-do,inbox-do,realtime-do,ckpt-do}.ts   ✓ the five Durable Objects
src/server/directory.ts      ✓ D1 directory + dirlog
src/server/{http,b64,hosts,abuse,validate}.ts   ✓ abuse.ts scopes {register,wrap,put,inbox,blob}; validate.ts shapes
src/client/engine.ts         M6a: SegvEngine (replaces the placeholder class), getEngine()
src/client/api.ts            M6a: HTTP + rt client (binary), params, clock samples, PoW (new; v1's was deleted)
src/client/{accounts,selflane,restore,conv,deliver,send,inbox,realtime,history}.ts   M6a–M6c
src/client/inbox-worker.ts   M6c: trial-decryption Web Worker (§0.4 CSP)
src/client/inbox-worker-url.ts  M6c: the `?worker&url` import and the Trusted Types policy (§0.4; round 9)
src/client/claims.ts M7      src/client/integrity.ts M8      src/client/links.ts M10
src/client/{session,webauthn,image,types,mock-engine}.ts   ✓ kept (session AAD and PRF input already v2; types.ts and
                             mock-engine.ts change per §0.3)
test/engine/harness.ts, harness.spec.ts, fake/*.ts   ✓ FakeWorld (M5); M6a fills newEngine, engineFor, settle and I
test/engine/*.spec.ts        M6–M10 engine specs
test/worker/*.spec.ts        ✓ Worker specs (M2–M4)
test/e2e/run.mjs             rewritten for v2 in M6b (§5)
```

None of the new client files clashes with an existing one: `engine.ts` is replaced in place, and `src/client/inbox.ts`
is distinct from `src/server/inbox-do.ts`. The §2.3 builders other than `junkRow` do not exist yet: M6c and M7 add
them (round 9). The module split is a recommendation that keeps each file under about 600
lines; a single `engine.ts` is also acceptable.

## 1. Milestones

Each milestone lists the files to add, change and delete, what it reuses, its tests, and its acceptance criteria.
Every await point added on the client MUST re-check the session (`assertSession(acc, gen)`); this carries over the
engine-11 invariant.

### M0. Groundwork (done; round 8)

- `docs/PROTOCOL-v2.md` is the in-repository copy of SPEC until M9 renames it, and `docs/STAGE1-PLAN.md` that of this
  plan; the implementing session refreshes both by `cp` on every revision (header; round 10).
- Local state from before 8092e98 is deleted once (§0.1 "Local data").
- `docs/DESIGN.md` is rewritten in M9.

### M1. Protocol core: `src/lib/proto.ts`, `src/lib/wire.ts` (2–3 days; done at c993e83 except the delta's open "Affects M1" items: the LEFT record, `powSolve` and `acceptOldRow`, with two doc comments of round 11, and `claimShapeValid`'s `B ≥ m` of round 12; rounds 9–12)

**`src/lib/proto.ts`** (merged from `proto2.ts` at 8092e98) holds the shared primitives and implements the following.

| area | functions | SPEC |
| ---- | --------- | ---- |
| time | `T0_MS`, `ERA_MS`, `era()`, `secOf()`, `tpub(ms, Δ)`, `NONE`, `posCmp()` | §3.1 |
| classes | `CLASSES = [256, 1024, 4096, 16384]`, `BODY_LENS`, `INBOX_BODY_LEN = 1416`, `clsFor(len)` | §3.2 |
| accounts | `deriveIdentity` (v2 labels, no scan key, plus `kS`/`rS`/`nS`); `makeBundle`, `parseBundle`, `verifyBundle` (v2 JSON); `validSigPk(pk)` (canonical, not of small order, in the prime-order subgroup; memoised per key) and the pinned `verify` (noble strict cofactored verification plus `validSigPk`, SPEC §1.1), used by every v2 signature check; `checkUserKeys(sigPk, kemPk)`; `fingerprint` (v2); `pin()`; `credKem`, `recoveryKem` (v2 labels); `makeWrap`, `parseWrap`, `verifyWrap`, `openWrap`, `unwrapAK` (v2 labels, `segv.sh/v2/ak-wrap`); `PRF_INPUT = "segv.sh/v2/prf"`; `hpre()`, `upre()` | §1.1, §2 |
| sealing | `seal`/`open` with info `segv.sh/v2/seal`; `dummySeal(label, ctx, n)` | §1.4 |
| epochs | `epochKeys(EK, conv, e) → {rk, mk, kc, nk, dk}`, `ekc()`, `Lmsg`, `Lctl`, `topicConv`, `Lself`, `Lsnap`, `topicSelf` | §4 |
| links | `linkKeys(s)`, `Lhello`, `topicLink`, `encodeLink`, `parseLink` | §4.3, §5.5 |
| descriptor | `encodeD`, `parseD` (all §5.1 rules: `(uid, sigPk, kh)` members, `validSigPk` for every key, ≤ 2896 B; the name only as `nlen ≤ 256` and valid UTF-8 of 1–64 code points counted with `strictUtf8` (`ignoreBOM: true`, a leading BOM counts): neither function calls `validName`, `\p{…}` or `normalize`, which the engine applies to new names and to display, SPEC §5.1), `kemHash(kemPk)` (`kh`), `hashD`, `signD`, `verifyD` (under D's own key for `by`), `dPrimeChecks({D, dsig, kc, pks, EK}, De, {from, hD, rm}, bundle)` (every D′ check of §6.6 step 4 after the decryption: `parseD` inside, a failure returns `"desc"`; the `kh` and `pks` checks and the byte-for-byte recomputation of every kept entry; it MAY skip the separate encapsulation for kept members), `checkPks(D, pks, B)` (the `pks` checks shared with §6.7 step 2) | §5.1, §6.6, §6.7 |
| join | `encodeJ` / `parseJ`; `makeInvite(kemPk, E, bucket, J)` → `{eid, body}`; `tryOpenInvite(kemSk, E, bucket, eid, body)` → J or null (catches decapsulation throws, SPEC §1.1); `makeHello` / `openHello`; `checkJoinBundle(J, blob, self)` (§6.7 steps 1–2 on a fetched blob: hash, size, header with zero reserved bytes, `descCt` and `pkCt` open, D parses, `dsig`, `checkPks`, self listed with its own `sigPk` **and** `kh`; returns D, `dsig`, keys and `pks`) | §5.2–5.5, §6.7 |
| SGB2 | `buildBundle({conv, e, D, dsig, EK, pks: kemPk[], prevMembers: uid[], rm, B})` (`descCt` padded to [4096], 4136 B; `pkCt` of `B·1216` bytes; `sealDet` entries for kept old members, dummies for `rm` bit 1 and for padding); `sealDet(pk, conv, e, i, EK)` (§5.4: `rr_e`, `ρ`, X-Wing `encapsulate(pk, ρ[0..64])`, nonce `ρ[64..88]`); `parseBundleBlob` (strict header, `B` from the size: 23456 or 81248); `openEntry(kemSk, conv, e, i, blob)` → `EK \| null` (a throw → null); `openDesc(dk, conv, e, blob)`, `openPks(dk, conv, e, blob)` | §5.4 |
| envelope M | `encodeM` / `parseM` (62-byte header with `ck16`, types 1, 2, 8, 16, 17; every other type is rejected); `signRow` / `verifyRow` (`segv.sh/v2/msg-sig`, always under the key in D); `sealRow(mk, E, label, M, sig)` / `openRow`; `prevh(label, body)` | §3.3 |
| claims | `encodeClaim` / `parseClaim` (`137 + 6m`, with `rm`), `rmBits(De, Dnext)`, `claimShapeValid(claim, m, from, Estart, E)` (SPEC §6.4(a), (b), (e), (f) and the local clauses of (g) and (h): `bundleSize ∈ {23456, 81248}` and, round 12, `B ≥ m` with B from `bundleSize`, so it checks every local rule of §6.4 "Order of requests" before any request), `bundleShapeValid(blob, size, id, m)` (§6.4(h)), `cutBefore(cut, E, n)`, `acceptOldRow(...)` (the §6.8 walk as a pure function; round 10: an epoch whose claim is null while the next epoch is held continues by membership, since the sender's bit is 0 iff the next D lists it, and the call throws when the sender is not listed there, because the caller must first read that claim, SPEC §6.8; round 11: its doc comment says that `epochs` are consecutive held epochs, so a skip re-add ends the list, and that the caller passes the claim that ended the last listed epoch whenever one exists, read at the position of the next held epoch's EPOCH record when it was not processed), `processClaim(...)` (§6.6 steps 3–4 for one member: `removed`, frozen `nokey`, `invalid` with the failed check, or accept with EK′, D′, `dsig′`, keys and `pks′`; `openDesc` and `openPks` inside one `try`, a throw is D′-invalid) | §6.2, §6.4, §6.6, §6.8 |
| self lane | `encodeS` / `parseS`, a record codec for every rtype (CONV_JOIN, EPOCH (flags: only bit1; with bit1 its position names the claim that removed self, not NONE, which needs no codec rule, only the `EpochRec.claim` doc comment; round 11), EPOCH_PENDING with `t_reg`, LEAVE, CONTACT, LINK, PREFS, partial HEADS with followed lanes (68 + 6m + 12f B per entry), CONFIRMED, DELIVERED, REQUEST, DESC (`dlen ≤ 2960`), MEMBER (`uid | sigPk | kh | pin | hlen | handle`, 113 + hlen B), LEFT (`conv | root | e | uid | t | E | n`, 78 B, `(E, n)` a position field; rounds 7 and 9), SNAP; unknown rtypes are skipped, known ones parsed strictly by the parse rules of SPEC §7.1, and a row or S2 that breaks one is rejected as a whole), `sealSelf` / `openSelf` (with the forced class-1 padding for rows carrying EPOCH_PENDING or DELIVERED; SNAP pointer rows with NONE / `ZERO16` prev fields, which `encodeS` enforces), `encodeSnapshot` / `parseSnapshot`, `encryptBlob` / `decryptBlob` with the v2 labels (`segv.sh/v2/blob`, `segv.sh/v2/snapshot`) | §7, §8.1 |
| commitments | `leafShard`, `leafInbox`, `leafBlob`, `mth(leafHashes)`, `nextHead(cid, head, t, n, root)`, `ckptHd(heads)`, `ckptC(prevC, q, sec, hd)`, `ckptSigMsg`, `receiptMsg`, `dirlogRefUser`, `dirlogRefWrap`, `dirlogH` | §9, §12 |
| PoW | `PowScope = 'register' \| 'wrap' \| 'put' \| 'inbox' \| 'blob'`; `powDifficulty` (unit 4 KiB for put and inbox); `powPre` with `segv.sh/v2/pow`; `powSolve` searches nonces upward up to 2^53 − 1, setting both halves of the `u64` (round 9), from an optional start nonce, and can be stopped (round 10: the caller restarts it with the new window when the window it searches in stops being current) | §10.2 |
| directory | `prefixRange(p, x)` → `{lo, hi}` with arithmetic (no shifts); `clientP(P, dirSeq)` | §9.6, §10.6 |

**Add `src/lib/wire.ts`.** Encoders and decoders for:

- the put request and response, and the get request and response (SPEC §10.3–10.4);
- the inbox post (1..32 invites) and read (SPEC §10.5);
- the feed (SPEC §10.9);
- the rt frames SUB, UNSUB, RESUME (by `seq`), HELLO (with `seq`), ROWS (per-row `seq`), GAP and RESUMED (SPEC §10.8).

Every decoder is strict: exact lengths, enums, counts within limits, and no trailing bytes.

**Reuse.** The shared encoding and primitives of `src/lib/proto.ts`, unchanged. The test style of v1's
`proto.test.ts` (an independent node:crypto re-implementation, then cross-checks).

**Tests.** `src/lib/proto.test.ts` (core), `src/lib/proto-conv.test.ts` (conversation codecs) and
`src/lib/wire.test.ts`:

1. Re-implement every v2 construct with node:crypto plus noble ML-KEM only where unavoidable, and compare with
   `src/lib/proto.ts`:
   - the label derivations;
   - `encodeM`, D and J;
   - the inbox body and SGB2 lengths: 1416, 23456, 81248; a maximal D (32 members, a 64-code-point 4-byte name) is
     2896 B and `D ‖ dsig` fits the [4096] descriptor class; `pkCt` is `B·1216 + 40` B;
   - `sealDet`: a node:crypto + noble re-implementation of `rr_e`, `ρ`, `encapsulate(pk, ρ[0..64])` and the AEAD with
     nonce `ρ[64..88]` gives the same 1192 bytes, and `open` opens it to EK;
   - claims, S and S2;
   - the commitments (an RFC 6962 MTH test vector: 1, 2, 3, 5 and 7 leaves);
   - the checkpoint chain and the dirlog chain.
2. **KATs**, fixed with deterministic randomness through the injectable RNG that `src/lib/proto.ts` already has
   (`_setRandomForTests`; round 9): every label,
   `epochKeys`, `Lmsg`/`Lctl`/`Lself`/`Lsnap`/`Lhello`, topics, `encodeD`, `kh`, `encodeJ`, the invite body, the
   bundle, `rr_e` and one `sealDet` entry (fixed EK, pk and i; no RNG involved), `encodeM` + sig, the claim, the self
   row, a HEADS record (its length is `68 + 6m + 12f` per entry), a MEMBER record (`113 + hlen` B, with `kh`), a LEFT
   record (78 B; round 9), the snapshot, the receipt message, `ckptC`, `hpre`, `upre`, the fingerprint and `pin`.
3. **Tamper and bit-flip tests.** Flipping any byte of a row body, the label (AAD), `E` (AAD), `conv` or `e`
   (signature) makes the row fail to open or verify.
4. **Parser fuzzing.** Random truncations and extensions are rejected; unknown types and enums are rejected; an
   unknown self `rtype` is skipped; a LEFT record of 77 or 79 bytes, or one whose `(E, n)` is `(0xFFFF, n)` with
   `n ≠ 0xFFFFFFFF`, makes its row (or S2) malformed (round 9).
5. **Era math.** Boundaries at `T0`, `T0 + ERA_MS − 1` and `T0 + ERA_MS`; `tpub` for Δ ∈ {1, 10}; `posCmp` with NONE.
6. **Class selection.** A 129-byte text lands in class 0 and a 130-byte one in class 1; 897 and 898 bytes split
   classes 1 and 2. A 12000-byte text lands in class 3. Claims for m = 1 and m = 32 land in class 1. A self row with
   an EPOCH_PENDING for `a = 0`, and a self row with only a DELIVERED for `a = 0`, `a = 8` and `a = 31`, are class 1.
   Types 18 and 19 are rejected by `parseM`.
7. **SGB2.** A member kept at index i opens EK, and its entry equals `sealDet` recomputed by another member; a removed
   member's entry, a padding entry and a random key open for nobody (null). `bundleShapeValid` rejects each failure
   separately: a size outside {23456, 81248}, a hash mismatch, a bad magic, version or `B`, and `B < m`.
   `dPrimeChecks` rejects a bundle in which one kept entry is a dummy, a fresh-randomness `seal` to the right key, or
   a `sealDet` to another key; and `pkCt` with a key whose hash is not its `kh`, a malformed key, or a non-zero tail.
8. **Inbox trial decryption.** The recipient opens it; another key returns null without throwing.
9. **Throwing decapsulation** (SPEC §1.1). A ciphertext whose X25519 component is a low-order point makes
   `tryOpenInvite`, `openEntry`, `openHello` and `openWrap` return null (or "does not open"), for every recipient key.
10. **Claims.** `rm` bits round-trip; `claimShapeValid` rejects a bit at or above m, the committer's own bit, cuts
    outside `[E_start, E]`, and (round 12) `bundleSize` 23456 (B = 8) with m = 9, while 81248 with m = 9 and 23456
    with m = 8 pass. `acceptOldRow` matches a table of cases: a low cut, a high cut, `t_R` equal to `t(C)`
    before and after the cut, a later claim that removes the sender, a frozen reader, and a row at NONE (a carried
    LEFT record, round 9) with `t_R = t(C)`, which is dropped. Round 10 (SPEC §6.8, "The bit without `C_j`"): with
    `epochs[0].claim = null` and `epochs[1]` held, a member listed in `D_{e+1}` whom `C_{e+1}` removes is dropped for
    `t_R ≥ t(C_{e+1})` and accepted below it (the walk continues by membership), and a member not listed in
    `D_{e+1}` makes the call throw; with no `epochs[1]` a null claim still accepts. `dPrimeChecks` rejects each
    failure separately: `hD`, `conv`, `e`, `prev`, `by`, `dsig′` under the `D_e` key, `D′ ∩ D_e` ≠ the `rm`-kept set,
    a continuing member whose `sigPk` or `kh` changed, `|D′| > B`, and a kept entry that does not recompute; `parseD`
    rejects a small-order or mixed-order `sigPk` and duplicate uids, and a name that is invalid UTF-8, longer than 64
    code points or over 256 bytes (a 64-code-point name after a leading U+FEFF is rejected; a lone U+FEFF is a valid
    1-code-point name), but accepts names that `validName` rejects (U+202E inside, a leading `@`, U+1FAE9, which older
    Unicode tables leave unassigned), and so does `dPrimeChecks` for a D′ carrying one (SPEC §5.1). `openDesc` and
    `openPks` throw on a corrupted `descCt` or `pkCt`
    and on a wrong `EK′` (never return garbage), so the caller can map the throw to D′-invalid (SPEC §6.6 step 4).
11. **Directory prefixes.** `prefixRange` for p = 0, 1, 31 and 32 and x at both ends; `clientP` bounds by `dirSeq`.
12. **Descriptor keys.** `verifyRow` and `verifyD` take the key from D only (no directory argument exists in the
    API); a D listing a uid with a key other than the uid's bundle key still verifies rows signed by the listed key.
    `buildBundle` takes every `kemPk` as an argument (no directory argument exists): a continuing member's comes from
    the previous bundle's `pks`.
13. **Signatures** (SPEC §1.1). A mixed-order key (a real `sigPk` plus a point of order 8) is rejected by
    `validSigPk`, `checkUserKeys`, `parseD` (the D does not parse) and `verify`, even with a signature that the
    cofactored equation accepts (`R = rB`, `S = r + k·a`). A non-canonical encoding (`y ≥ p`), the identity and an
    order-8 key are rejected. Under a valid key, a signature whose `R = rB + T` carries torsion verifies (this pins the
    cofactored equation), and signatures with `S ≥ L` or a non-canonical R do not.
14. **Join and claim helpers.** `checkJoinBundle` rejects a self listed with a foreign `kh` (own `sigPk`), a `pks`
    entry whose hash is not its `kh`, a non-zero `pks` tail, `|D| > B`, a non-zero reserved header byte and a
    corrupted `pkCt`. `processClaim` returns `removed` for an `rm` bit, `nokey` for a dummy own entry or an `ekc`
    mismatch, `invalid` for a corrupted `descCt` or `pkCt` (never a throw) and for every failing D′ check, and
    `accept` with `pks′` otherwise.
15. **PoW search** (SPEC §10.2; round 9). `powSolve` started just below 2^32 (a start argument) with difficulty 8
    returns a nonce that `powCheck` accepts, also when it lies above 2^32: the search does not stop at 2^32. Round 10:
    a search that is stopped (for example through an `AbortSignal`) ends without a nonce, so the caller can restart
    it with the next window.

**Acceptance.** The `unit` project and `vp check` are green, and `src/lib/proto.ts` has no DOM or Workers APIs.

### M2. Storage Durable Objects (3–4 days; done at c993e83; round 9)

**Add.**

- `src/server/env.ts` (params, era bounds, server keys, kroute/kcommit) and `src/server/batch.ts` (batch commitments
  and alarms, with leaves and heads from `src/lib/proto.ts`).
- `src/server/shard-do.ts` (SPEC §9.1), `blobreg-do.ts` (§9.2), `inbox-do.ts` (§9.3), `realtime-do.ts` (§9.4) and
  `ckpt-do.ts` (§9.5). The CheckpointDO's dirlog head reads D1. Until M3 creates the table, it uses ZERO32 when the
  table is missing.
- Export the classes from `src/entry.cloudflare-workers.ts` and `test/worker/entry.ts`.

**Change.** `wrangler.jsonc`, `test/worker/wrangler.test.jsonc`, `worker-configuration.d.ts` (§0.5; done).

**Reuse.**

- From v1's `src/server/log-do.ts` (3de5f5e), for `realtime-do.ts`:
  - the WebSocket `fetch` with its caps, the `setWebSocketAutoResponse("ping", "pong")`, `expired`, `liveCount`,
    `closeSocket` and `wsTagKey()` / `meta`;
  - the `wsLimits` instance-field pattern;
  - `waitAtMost`;
  - `ab()` for SQL binding.
- The alarm-arming discipline (arm in the same synchronous block as the commit). New: per-era DOs derive `(E, i)` from
  `ctx.id.name` (the Worker uses `getByName`) and arm `min(getAlarm(), due)` inside `blockConcurrencyWhile` in the
  constructor; DOs of ended eras arm nothing and seal in `prepare()` (SPEC §9).
- Not reused: log-do's `liveCount()` deserialises every attachment. RealtimeDO counts with `getWebSockets(tag)` on the
  client tag and an accept-hour tag (SPEC §9.4).

**Testability.** Each DO reads time through a protected `clock = () => Date.now()` instance field. Inbox jitter comes
from a protected `jitter()` field, and the RealtimeDO ring limits are a protected field too. Tests override them with
`runInDurableObject`, the way v1 tests override `wsLimits`.

**Tests** (`test/worker/*.spec.ts`).

`shard-do.spec.ts`:

- In a CAS race of two `put` calls on the same label, the first wins and the second gets CONFLICT with the first body.
- BAD lengths. A duplicate inside one put.
- WRONG_ERA: a DO of a past era (`E_now − 1`, with the clock past `end`) and a future era.
- `MISS(sealed = 0)` before the seal alarm and `MISS(sealed = 1)` after `runDurableObjectAlarm`. A put after the seal
  gets WRONG_ERA.
- Batch close: the head chain recomputed with `nextHead` of `src/lib/proto.ts` over the feed RPCs' output (`feedBatches`,
  `feedRows`) matches `head()`. This also holds after `evictDurableObject`, with nothing lost. Leaves come from the
  stored `bh`, which equals `H(body)` (SPEC §9.1).
- Feed pagination never splits a batch; a batch above the budget is read through `feedRows` chunks; the feed never
  closes a due open batch.
- With a clock stepping back, `t` never decreases (`last_t`).
- Close a batch through the alarm, step the clock back by SKEW, and put: the row gets `t = closed_t + Δ`, `closeBatch`
  never sees a duplicate `t`, and the head chain recomputes from the feed RPCs (IMP-7).
- Early acceptance: with the clock at `start(E) − SKEW·1000 + 1`, `shard/E` accepts with `t = sec(start(E))`; at
  `start(E) − SKEW·1000 − 1` it answers WRONG_ERA. With two DOs whose clocks differ by SKEW, a write at the boundary is
  accepted by at least one of them.
- A DO of an era that has already ended arms no alarm in its constructor and seals in `prepare()` (CMP-18; spy on
  `setAlarm`).
- The DO reads `(E, i)` from `ctx.id.name`; a constructor wake with a pending batch alarm keeps the earlier alarm.
- With the deployment Δ changed after the pin, the DO keeps the pinned Δ and logs the mismatch exactly once per
  instance (spy on `console.error`; SPEC §3.1). The same for `blobreg-do.spec.ts`.

`blobreg-do.spec.ts`:

- Create-only: a second `register` returns the original `t` with `created = false`.
- `meta` MISS reports `now`. After a MISS at `now = x`, a registration with the clock set back by 5 s still gets
  `t ≥ tpub(x)` (the high-water mark), and `hw` is written at most once per Δ.
- The `closed_t` case of the shard, for registrations.

`inbox-do.spec.ts`:

- `rel` and `closed` math with fixed jitter: a row is invisible until its slot closes, then visible.
- A post at an exact slot boundary with `j = 0` gets `rel = closed + 1` (CMP-21).
- After a read reported `closed = c`, a restart with the clock stepped back still gives new rows `rel > c`
  (`closed_hw`, COR-12/IMP-8).
- `ended` is persisted at `end(E) + SKEW`; posts after it get WRONG_ERA; the final `closed` is
  `max(largest rel, closed_hw)` and never lower than a `closed` reported before (also for an empty era); `head()`
  persists `closed_hw` like `read` (SPEC §9.3).
- A post in the SKEW window before `start(E)` counts against the era's first day (`d = max(⌊sec/86400⌋, 7·E)`).
- A post of 32 invites returns 32 results; the day cap turns the rows past the cap into `full` while earlier rows
  succeed.
- Whole rel groups per page. The eid-idempotent retry. `conflict` on a reused eid. WRONG_ERA. Slot commitments.
- Early acceptance (IMP-9): with the clock at `start(E) − SKEW·1000 + 1`, `inbox/E` accepts a post; at
  `start(E) − SKEW·1000 − 1` it answers WRONG_ERA. An ended-era InboxDO arms no alarm (CMP-18). An alarm that fires
  before `end(E) + SKEW` (clock override) sets no `ended` and re-arms at `max(end(E) + SKEW, now + 1000)` (SPEC §9).
- A post at `end(E) − D/2` with jitter `D − 1` gets `rel = (end(E) − T0)/D + 1`, above the `closed` of every read
  before `end(E) + D`; a read after `ended` returns it (the window that SPEC §11.5 step 3 covers on the client).

`realtime-do.spec.ts`:

- HELLO on connect. SUB, then a publish to two topics: the socket receives only its topic.
- UNSUB. RESUME with the current boot replays ring rows newer than `since` and sends RESUMED. RESUME with a stale boot,
  or `since` older than the ring, gets GAP.
- RESUME by `seq`: two rows published in the same millisecond are both replayed; a RESUME answered with GAP still
  installs its topics. RESUME with `since` above the last seq, or with more than 2 MiB of matching rows, gets GAP;
  a large replay is split into ROWS frames of at most 512 KiB of rows (SPEC §10.8).
- Ping/pong. A non-ping text, a bad binary frame, more than 256 topics, a frame over 8 KiB, a second RESUME, or more
  than 30 SUB/UNSUB frames (or 2 048 topic changes) in a minute closes with 1008.
- With the pair budget lowered (protected field), a SUB beyond it closes with 1013.
- Per-client and global caps: 429 and 503, counted through tags (no attachment is deserialised: spy on
  `deserializeAttachment`).
- Max age gives close 4000.
- Hibernated sockets still receive after `evictDurableObject` (port of the log-do lifecycle test).

`ckpt-do.spec.ts`:

- `C_q` chains. Unchanged heads create no new q. The signature verifies under the public key derived from `SRV_KEY`.
- A sealed previous-era shard is included once more, then dropped.
- A failing component keeps its previous head; one that has never answered is left out (never ZERO32); `sec` never
  decreases when the clock steps back (SPEC §9.5).
- The blob registry head changes in checkpoints at most once per hour, even when blobs are registered every minute.
- The alarm is armed from the constructor; calling `ensure()` repeatedly makes no extra writes.

**Acceptance.** All worker specs are green, and `npm run build` followed by `npx wrangler deploy --dry-run` accepts the
five DO classes.

### M3. D1 directory (2 days; done at c993e83; round 9)

**Add.**

- `migrations/0001_init.sql` (the directory tables; `0003_v2_directory.sql` at 3de5f5e, squashed at 8092e98).
- `src/server/directory.ts`:
  - `dirRegister` and `dirAddWrap`, using one D1 `batch()` with explicit dirlog seqs (plus the `dirmeta.users`
    increment) and up to 16 optimistic retries with random back-off;
  - error mapping: `user.handle` or `user.uid` → 409, `dirlog.seq` → retry, anything else → 503;
  - `dirByPrefix` with `BETWEEN lo AND hi` from `prefixRange` of `src/lib/proto.ts` (never shifts), `dirByUid`,
    `dirWrapsById` (≤ 64 by dirseq), `dirlogPage` and `dirlogHead`, `currentP()` (cached 60 s from `dirmeta.users`,
    never `count(*)`).
- `src/server/validate.ts`: `checkBundleShape` and `checkRecordShape` (canonical JSON, `MAX_SIGNED_TEXT`).

**Reuse.** `validate.ts` (`canonical`, `MAX_SIGNED_TEXT`, the signature helpers) and `http.ts` (`ed25519Verify`).

**Tests** (`test/worker/directory.spec.ts`):

- Register is atomic (user + wraps + dirlog).
- 409 on a taken handle or uid, and nothing is written.
- 400 cases (bad signature, foreign wrap, malformed bodies, 413), as v1's "POST /api/register" tests had them
  (3de5f5e).
- `addWrap`: 404 for an unknown uid, 400 for a bad signature, the 64-per-uid cap, and 409 for a duplicate `(uid, id)`.
- Prefix queries: any `p ≤ P + 1` is accepted (409 with `P` above), p = 0, 1 and 32 return exactly the matching rows,
  the query plan uses `user_hpre` for a narrow range and walks the uid primary key for a wide one (`EXPLAIN QUERY
  PLAN`, SPEC §9.6), paging with `after` (257 rows read, 256 returned, `more` from the 257th), and verification of
  the returned bundles. A mixed-order `sigPk` is refused at registration (400).
- `wrapsById` is oldest first, filters by `uid`, and returns an empty list for unknown ids.
- 8 concurrent registrations all succeed, and the dirlog chain recomputes from `dirlogH` without gaps;
  `dirmeta.users` equals the number of users. On a freshly migrated database the first registration makes
  `dirmeta.users = 1` (the migration inserted the `'users'` row, CONS3-12), and `currentP()` follows it.
- A failing D1 (a proxy swapped in `env.DB`, as v1's `log-do.spec.ts` did) gives 503.

**Acceptance.** Green.

### M4. HTTP and WebSocket API (3 days; done at c993e83 except the round-8 feed-token change of delta M4; rounds 9–11)

**`src/server/api.ts`**, with `handleApi(request, env, ctx, url)` and these routes:

| route | notes |
| ----- | ----- |
| every route | `x-segv-now` and the §9.7 security headers (HSTS on https, `nosniff`, `no-referrer`) on every response except the `101` upgrade of `/api/v2/rt` (immutable headers from the RealtimeDO, passed on untouched by `stampResponse`: it gets none of them), stamped by `stampResponse` on the response actually returned (after any `caches.default` lookup), and deleted from the copy given to `cache.put` (SPEC §9.7, §10.1); the era bounds of SPEC §9.7 before any DO call; `caches.default` before the rate limiter for immutable responses and the inbox tail. |
| `GET /api/v2/params` | Calls `CKPT.ensure()` at most once per isolate (a module-level flag), never per request (the DO also arms itself in its constructor). |
| `GET /api/v2/era/{E}` | No `kroute` (SPEC §10.9). Answered by the Worker alone (no DO); `sealed` by the Worker clock. |
| `POST /api/v2/put` | Body ≤ 263 345 B. Grouped ShardDO RPCs (`getByName`), receipts signed with `SRV_KEY` (WebCrypto Ed25519 or noble), and `waitUntil(RT.publish(okRowsWithTopic))` with one retry. |
| `POST /api/v2/get` | Grouped RPCs, the 4 MiB body budget, then SKIPPED for every later body-mode key (SPEC §10.4); a failed DO call is 503 for the whole request. |
| `POST /api/v2/inbox`, `GET /api/v2/inbox/{E}/{bucket}` | Posts of 1..32 invites with per-row results; 410 for `E < E_now − 3`; `public, max-age=Δin` for the current era (served from `caches.default`); immutable only after the InboxDO reports `ended`. |
| `PUT /api/v2/blob/{id}`, `GET /api/v2/blob/{id}`, `GET /api/v2/blob/{id}/meta` | Blob GETs served from `caches.default` when present. |
| `GET /api/v2/rt` | |
| `GET /api/v2/ckpt/latest`, `/ckpt/{q}`, `/ckpt/range` | |
| `GET /api/v2/feed/{E}/{i}` | Whole batches up to 4 MiB per page; a larger batch is streamed alone through `feedRows` chunks and not stored in `caches.default` (SPEC §9.7, §10.9). A request that misses the cache takes `min(⌈bytes / 4 MiB⌉, 64)` `RL_READ` tokens, `bytes` being the sum of the page's batch encodings (no page header): the extra ones after `feedBatches`, before the first byte (rounds 7–8). |
| directory routes | §10.6 |

**Change.**

- `src/entry.cloudflare-workers.ts` and `test/worker/entry.ts` send every `/api/*` path to `handleApi`; a path outside
  `/api/v2/*` is a 404.
- `src/server/abuse.ts`: `PowScope` from `src/lib/proto.ts`, and `POW_DEFAULTS`/`POW_VARS` for `put` and `inbox`
  (no `append`). A nonce above 2^53 − 1 is 403 "malformed proof of work" (SPEC §10.2, round 8; already so).
- `routeLabel`: path labels that redact ids, handles, prefixes and eras.

**Reuse from v1's `src/server/api.ts` (3de5f5e):**

- `putBlob`/`getBlob`, almost verbatim (streaming R2 put with `sha256`, the header set). Insert `BLOBREG.meta()` before
  the R2 head check and `BLOBREG.register()` after the put. Delete `recordBlob`.
- `ws()` becomes `rt()`: the Origin check, the opaque client tag (the key now lives in RealtimeDO `wsTagKey`), and the
  minimal forwarded request.
- `methods`, `HttpError` handling, `finalize`, `readBody`, `exactKeys`, `intParam`, `rl()`, `rateLimit`, `checkPow`.

**Tests** (`test/worker/api.spec.ts`, ported section by section from v1's at 3de5f5e):

| v1 section | v2 version |
| ---------- | ---------- |
| params | adds the era fields, `srvKey`, `kcommit`, `p` |
| register / wraps | v2 directory routes |
| `POST /api/append` | `POST /api/v2/put`: OK, CONFLICT with the occupant, WRONG_ERA, BAD → 400 layout errors, 16 class-3 rows (263 345 B) accepted and 263 346 B → 413, PoW priced by size, receipts verify under `srvKey`, a topic row is published, a zero topic is not |
| `GET /api/log` | `POST /api/v2/get`: modes, MISS sealed, SKIPPED past the budget, NO_ERA. Plus `GET /api/v2/feed`: verify roots and heads against `/ckpt/latest` |
| lookups | `dir/h`, `dir/u`, `dir/uid`, `dir/wraps` |
| blobs | all v1 cases, plus `meta` HIT/MISS and an idempotent PUT returning the original `t` |
| proof of work | scopes `put`, `inbox`, `blob`, `register`, `wrap`: all failure modes |
| rate limiting | plus `RL_INBOX` |
| `GET /api/ws` | `GET /api/v2/rt`: 426, the Origin check, caps, ping, close 1008 on other frames, max age 4000, SUB-filtered delivery end to end through put |
| hosts and HSTS | unchanged on `/api/v2/*`, plus 503 when `ROUTE_KEY`/`SRV_KEY` are missing |
| (new) era bounds | put and inbox with `E = 65000` and `E = 0` (below `E_FIRST`) answer without creating a DO (spy on the namespace); get gives NO_ERA and `MISS(sealed = 1)` |
| (new) server time | every v2 response except the `101` upgrade carries `x-segv-now`, `nosniff` and `no-referrer` (and HSTS on https), and the `101` is returned exactly as the RealtimeDO built it; a blob GET served twice (the second from `caches.default`, where the runtime has it) carries a fresh value the second time, and the entry stored in `caches.default` has no `x-segv-now` (inspect it with `caches.default.match` in the test) |
| (new) params | 100 params requests make at most one `ensure()` call |
| (new) inbox | `POST /api/v2/inbox`: a body of exactly `7 + 1432·count` B is accepted and any other length gives 400; `bucket ≠ 0` gives 400; 1..32 invites give per-row results (`rel`, `conflict`, `full`); `E` outside the Worker's era bounds gives 409 `{error: "wrong era", era}` without a DO call. `GET /api/v2/inbox/{E}/0`: 410 for `E < E_now − 3`, 400 for `E > era(now + SKEW)`; the current era is `public, max-age=Δin` and a second identical read within Δin is served from `caches.default` without consuming `RL_READ`; an era is `immutable` only after its InboxDO reports `ended` (and only for `more = 0`) |
| (new) era | `GET /api/v2/era/{E}` has exactly the keys of SPEC §10.9 and no `kroute` (CMP-23) |
| (new) feed tokens | a page of one 9 MiB batch takes 3 `RL_READ` tokens; with fewer left it answers 429 with `retry-after` and makes no `feedRows` call; an inline page takes one token, and a page served from `caches.default` none; the token count is a pure helper that the route calls, and it is 1 for 4 194 304 B of batches, 2 for 4 194 305 B and for 8 388 608 B, 3 for 8 388 609 B, 16 for 64 MiB, and 64 for 600·4 MiB + 1 B, for 300 MiB and for 2.6 GB (the cap keeps any page readable, rounds 8 and 10); with `countingLimiter(63)` and a reported batch of 2.6 GB the request answers 429 with `retry-after` after 64 limiter calls and makes no `feedRows` call (round 11). At c993e83 the streamed-page table of the test ("The 5-byte page header counts") expects the header term: (8 MiB − 5 B, 2), (8 MiB − 4 B, 3), (64 MiB, 17); it becomes (8 MiB, 2), (8 MiB + 1 B, 3), (4 MiB + 1 B, 2), (64 MiB, 16), without that comment, and the comment of the 9 MiB case (`api.spec.ts:2343`, "⌈(5 + 9 MiB) / 4 MiB⌉ = 3 tokens") becomes ⌈9 MiB / 4 MiB⌉ = 3 (SPEC §10.9, rounds 7, 8, 10 and 11) |

Also add `test/worker/helpers.ts` helpers: `putRows`, `getKeys`, `makeAccount`, `registerOk`, `rtUpgrade`/`rtClient`,
and the binary codecs from `src/lib/wire.ts`.

**Acceptance.** All worker specs are green. `curl` against `vp dev` shows the routes working.

### M5. FakeWorld engine harness (2 days; done at c993e83; round 9)

**`test/engine/harness.ts`** with the FakeWorld in `test/engine/fake/*.ts` (§2.1), and `test/engine/harness.spec.ts`,
which self-tests the fake against the same `src/lib/wire.ts` codecs and the semantics of SPEC §9–10:

- CAS and CONFLICT;
- WRONG_ERA after `world.advanceEra()`, and early acceptance within SKEW;
- sealing;
- the inbox closed slot, `rel = ⌊(ms + j)/D⌋ + 1` with the `inboxJitter` knob (§2.1), `closed_hw`, batched posts,
  per-row `full`, and 409 `wrong era` for a post naming an era the fake no longer accepts;
- blob meta high-water;
- rt RESUME by `seq` and GAP;
- the rate-limit knob (429 with `retry-after`);
- `x-segv-now` on every response except the `101` upgrade, with `cache-control` as the Worker sets it, and the
  `staleNow` knob (§2.1);
- separate clocks for the shard, BlobReg and the inbox (`world.shardLagMs`, `world.inboxLagMs`), and the `failGet`,
  `failMeta` and `failDir` knobs (§2.1).

**`vite.config.ts`.** The `engine` test project includes `test/engine/**/*.spec.ts` (done).

**Acceptance.** `harness.spec.ts` is green. The M5 items of the delta (the blob GET's `content-length`, `/era` sealed
by the clock, `inboxJitter`, `wrongEraOnce`, `inboxLagMs`, `failMeta`, `failDir`) landed at c993e83, not at 8092e98
(round 9). Round 8 adds to the FakeWorld the clock API of §2.1 (`tick`, per-engine clocks), with M6a.

### M6. Engine: accounts, restore, 1:1 and group messaging, images (5–7 days, in three steps M6a–M6c; round 8)

**Add to `src/client/`** (beside the kept `image.ts`, `mock-engine.ts`, `session.ts`, `types.ts` and `webauthn.ts`;
`engine.ts` replaces the placeholder), implementing SPEC §11:

| file | contents |
| ---- | -------- |
| `api.ts` | Binary put, get, inbox, feed and rt clients; JSON params, directory and ckpt. Params cache (5 min), with the bounds of SPEC §3.1 checked (a params answer with an impossible `delta`, `skew` or `inboxSlot` is a failed request); the server-time estimate from clock samples of `no-store` responses and HELLO, by minimum RTT within 10 minutes (the newest among equal RTTs), anchored on the monotonic clock, with every older sample discarded when a new one disagrees with it by more than `(rtt_old + rtt_new)/2 + SKEW + 1 s` (SPEC §10.1); `serverNowMs()`. Prefix lookups use `P* = max(P, ⌊log2(dirSeq/2080)⌋)` in place of `P` and retry once on 409 `{p}` with `min(P*, P′)` (SPEC §10.6). `postPow` and `ApiError` taken from v1's `3de5f5e:src/client/api.ts` (deleted at 8092e98), with the scopes `put`/`inbox`; the PoW search stops and restarts with the new window when the window it searches in stops being current, so no stale proof is sent (SPEC §10.2; round 10). |
| `realtime.ts` | The socket with SUB, UNSUB and RESUME, the topic set, backoff + jitter, ping every 30 s; emits rows, GAP and connection state. |
| `accounts.ts` | register, login, recovery, addPasskey, `unwrapFrom`. Ported from `3de5f5e:src/client/engine.ts:180-300` and `497-523`, with v2 lookups: the handle check through `dir/h` plus local filtering; the lost-response check by comparing the handle-prefix result with our bundle; after a lost `POST /wraps` response, the exact `dir/wraps/{id}?uid=` lookup (a 400 or 409 is never success, SPEC §10.6). |
| `selflane.ts` | Record fold (including the CONFIRMED check on CONV_JOIN and the REQUEST bound), CAS writes with batching at era `max(E_now, head era)`, no sibling wait, the durability order of SPEC §7.3 (one poll's joins over as many cls-3 rows as needed, the cursor's HEADS in the last; no REQUEST that the limit drops at once; a copy's HEADS entry held at the epoch of a lane with a parked join), snapshot write and read (original record order; complete EPOCH_PENDINGs dropped; DESC records for the current epoch and the copy's previous held epoch, k below a skip, SPEC §7.4, round 12; EPOCH records only above the root epoch, a skip's with the position of the claim that removed self, SPEC §7.2, round 11; the LEAVE record with the highest e; the LEFT records of the HEADS entry's epoch; `(Eh, nh)` never past an unsealed previous era, SPEC §7.4), partial HEADS, and LEFT records for others' leaves, each with its LEAVE row's stored time and position (NONE once carried into a later epoch; SPEC §7.2–§7.3; round 9), beside every HEADS entry of their epoch: every HEADS entry for epoch e sits in the same row or snapshot as a LEFT record for every member the writing device records as left in e (round 8), and a snapshot that copies an older or a sibling's entry adds the writer's own LEFT records for that epoch (SPEC §7.4; round 9). The fold keeps, per `(conv, root, e, uid)`, the LEFT record with the least `(t, position)` (NONE after every real position), and a row or snapshot carries exactly one LEFT record per member left in the entry's epoch, naming the kept source, so repeated HEADS rows and snapshots never pile up copies (SPEC §6.9, §7.3, §7.4; round 10). No HEADS entry is held back because of a leave (round 9: round 8's finality rule is deleted). The LEFT parts of this row land with M7's leave; M6 writes HEADS entries without LEFT records (round 10). |
| `restore.ts` | SPEC §11.4, including the skip-re-add rule (which also clears `left`), `E_start` from `blob/meta` when no record holds it, the followed lanes of the HEADS epoch taken exactly from the HEADS entry, a HEADS entry that does not fit its D ignored (SPEC §7.2; for a copy without e−1, only its followed lanes), the leaves of the HEADS epoch from LEFT records (per member the record with the least key; round 10), each decided by the §6.8 walk with the record's time and position as its LEAVE row would be (§6.8, §7.3, §11.4 step 5; round 9: `acceptOldRow` with `{t, E, n}` from the record, the walk starting at the record's epoch; NONE is never before a cut; with M7), rows on the followed lanes of c−1 decided by the §6.8 walk with the sender's bit in `C_{c−1}` read from `D_c` (a restore that took `EK_c` from a snapshot's EPOCH record never processed `C_{c−1}`, and must not accept a row for lack of it; one without a snapshot processed it on its way to c; round 11), and an ending claim `C_j` read at the position of the next held epoch's EPOCH record (j+1, or the skip re-add after a removal at j+1; round 11) wherever a removed sender's row or the initial history needs it, the initial history taking the previous held epoch (k below a skip, nothing below the root; round 11) (SPEC §6.8 "The bit without `C_j`", §11.4 steps 5–6; round 10), the control lanes processed from the copy's highest epoch whose key a snapshot record gives (its root epoch when there is none), or from the HEADS epoch when that is lower, each from `(E_start, 0)` and the HEADS epoch from its HEADS position, so the restore holds every held epoch, those below a skip re-add included, and the previous held epoch is the highest held epoch below (SPEC §11.4 step 5; round 12), the initial history's rows processed as scrollback's (a LEAVE applied by the kept-source rule; SPEC §11.4 step 6; round 12), DESC and REQUEST `desc` checked before use (§7.2), and the snapshot-pointer fallback to older pointers or to no snapshot (§11.4 step 3). |
| `conv.ts` | Copies, epochs, D from DESC records or the bundle (signatures always under the keys in D), names shown only when they pass the local `validName` (otherwise unnamed; rename lines compare displayed names, SPEC §5.1, §11.9), unknown members (no bundle, or a directory `sigPk` or `kh` that differs from D's, decided against the MEMBER record without a lookup) and MEMBER records (written from every verified directory bundle, whatever D lists; only a uid without a bundle is looked up again, SPEC §7.3), J acceptance (§6.7 incl. the check order `bundleSize` → `meta` → blob, parking on transient failures, the `pks` checks, the "claimed" rule, the `D.by` key check for skip and first contact with its noise-only failure, a skip's EPOCH record naming the claim that removed self (SPEC §6.7 step 7, §7.2; round 11), copies, ⚠, confirmed without self), lanes with dense prefixes, processed positions (never past an unsealed previous era, SPEC §7.2), followed lanes (epoch c−1 of each member silent in c, none when the copy does not hold c−1, SPEC §11.2), the sweep of old-epoch lanes before they leave the expected-label map, the §6.8 acceptance walk, leave (row first, then the record; a leaver keeps processing WELCOMEs until it is dropped; while its leave is current (no skip re-add since the latest LEAVE record, which also clears `left`) it repeats its LEAVE in the current epoch whenever the latest LEAVE record names an earlier epoch, after every catch-up and restore, SPEC §6.9; receivers record a leave only in the consecutive epochs that still list the leaver, each with a LEFT record carrying the row's stored time and, for the row's own epoch, its position (NONE for an epoch the leave was carried into; rounds 9–10); per copy, epoch and member they keep only the source with the least key `(t, position)`, NONE after every real position, whatever the order in which the LEAVE rows and carried leaves arrive: a smaller key replaces the kept source and writes its LEFT record, an equal or larger one changes nothing (SPEC §6.9 "Several sources"; round 10); a leave stands while §6.8 accepts its kept source, and is un-recorded when that source is dropped on recomputation (rounds 8 and 10), also when the leave came from a LEFT record (round 9); the latest LEAVE record is the one with the highest e), system lines (a claim's removed and rotated lines follow the current leave state, derived again whenever a source is added, replaced or dropped, SPEC §6.6 step 5, §11.9; round 11; a LEAVE row R of x in epoch k shows "@x left" while it is the kept source of x's leave in k, §6.8 accepts it, and x is not recorded as left in k−1, so one leave shows one line: R loses it when a smaller source replaces R (the line moves to that source when it is a LEAVE row of k), when §6.8 drops R, or when x becomes recorded as left in k−1, SPEC §11.9; round 12), views. The leave parts of this row land with M7 (round 10). |
| `deliver.ts` | The J delivery queue of SPEC §6.12 (WELCOME only in a 1:1 where the recipient has posted in the current epoch and has not left, and that self has not left and was not removed from, checked again by `send.ts` for the epoch the row is built in, with an inbox invite instead when that epoch no longer qualifies; otherwise batched inbox invites sealed to `pks` of the bundle; one padded DELIVERED row after the first attempts; 409 `wrong era` rebuilds the invites; retry, resume per §6.11). M6b implements the first batched inbox post, the 409 rebuild and the DELIVERED row; M6c adds WELCOMEs, retry and resume (round 10). |
| `send.ts` | SPEC §11.3: the control-lane probe before every send (every era as §6.5 says; a failed probe fails the send), the refusals of step 2 (pending claim after 30 s; frozen with a removal; a WELCOME whose epoch no longer meets §6.12 step 1, which also covers a copy self left or was removed from, gets an inbox invite; a repeated LEAVE is not refused as "you left"), the send's epoch e fixed by step 2 (a switch through realtime or a catch-up never moves the row; it triggers the fresh probe), the slot era `max(E_now, head era)`, the fresh-probe check before every put attempt (`(Δ + SKEW)/2`, by the monotonic clock, the wall clock or the server-time estimate, or the copy no longer in e; it re-runs steps 1–3, so a rotation and the WELCOME check apply to the new epoch), CONFLICT handling, junk galloping, the late-row check of step 8, and the retry of a failed echo (steps 1–3 first). |
| `inbox.ts` | Poll with the era clamp, per-era `after` and the era-completion rule (SPEC §11.5 step 3), the read rules of SPEC §10.5 (decreasing `rel` or a `more = 1` page without progress is a failed read; rows outside `(after, closed]` are ignored), trial decryption (same thread in M6b; in `inbox-worker.ts` from M6c, created through `EngineOptions.inboxWorker`, which the engine tests set to `null`, §0.4; round 9), parked joins, request copies (probed with `2·m + 3` keys) and their transitions. |
| `history.ts` | Initial history for the 20 most recent copies, scrollback to 500 on the first `markRead` per copy, era-crossing probes, the re-probe past the swept head of an older epoch's lane plus slot 0 of every later era up to the era after the claim that ended the epoch, and, for an epoch this session never swept, slot 0 of every era from `E_start(e)` to that era with galloping (never the claim's cuts); the claim that ended an older epoch read at the position of the next held epoch's EPOCH record (the skip re-add's for an epoch self was removed from; round 11) when this session did not process it, before a removed sender's rows of that epoch are decided (SPEC §6.8, §11.10; round 10); below an epoch reached by a skip, scrollback continues in the epoch self was removed from, and it ends below the root epoch (round 11); a LEAVE found below the processed position is applied as SPEC §6.9 says (it replaces the kept source only when its key is smaller; round 10) (SPEC §11.10); the previous held epoch is the highest held epoch below, which the restore holds (SPEC §11.4 step 5; round 12); a claim that history reads without processing it shows its lines as a processed claim would, from the leave state the loaded rows give its epoch, so below the HEADS epoch a removal line can show until the leave's source is loaded (SPEC §11.9; round 12). |
| `engine.ts` | `SegvEngine implements Engine` (replaces the placeholder class; `getEngine()` keeps its name): state, emit throttling, warnings (critical and noise), `logout`, the generation guards. |

**Order inside M6 (rounds 8 and 10).** The app is down until the minimal path works (§0.1), so M6 lands in three steps, each
with its own commit and the checks of the header green.

- **M6a — sign-in (1–2 days).**
  - Code: `api.ts` (params with the bounds of SPEC §3.1, clock samples, PoW, the directory routes); `accounts.ts`;
    `engine.ts` (`SegvEngine` replaces the placeholder class; `getEngine()` keeps its name and module, so
    `src/components/real-engine.ts` does not change); the self-lane fold and the writes of registration (HEADS and the
    inbox cursor, `selflane.ts`); restore of an account without conversations; the `Engine` and UI changes of
    §0.3–§0.4.
  - Harness: the bodies of `newEngine`, `engineFor`, `settle` and `I` in `test/engine/harness.ts` (at c993e83 they
    throw "needs the v2 engine (milestone M6)"), and the clock API of §2.1–§2.2. No §2.3 builder is needed yet.
    Rewrite the `settle` doc comment (`harness.ts:286-295`), which still tells a round needing a fresh checkpoint to
    call `server().advance(CKPT_PERIOD_MS, { keepSockets: true })`: it calls `world.tick(CKPT_PERIOD_MS)` (§2.2; the
    server-only `advance` leaves the engines' clocks behind; round 10).
  - Tests: `accounts.spec.ts` (10).
  - By hand in `vp dev`: register, sign out, sign in by passkey and by recovery code; the UI reaches "ready" with an
    empty list.
- **M6b — the minimal end-to-end path (2 days).**
  - Code: creation by handle of a 1:1 and of a group, with a name at creation (`validName` on the new name, D's name,
    the "# name" display, SPEC §5.1, §6.1; round 10: the e2e group step names its group, §5); every J as a batched
    inbox invite, with the first batched post, the 409 `wrong era` rebuild and the padded DELIVERED row after the
    first attempts (SPEC §6.12 steps 2–4; round 10: without that row a restore would see an incomplete
    EPOCH_PENDING(e = 0)); WELCOMEs, retry and resume wait for M6c; `inbox.ts` (poll, cursor, same-thread trial
    decryption); request copies and their acceptance by `markRead`
    (SPEC §11.5; a first-contact 1:1 is a request on the recipient's side); `conv.ts` (J acceptance, lanes, views);
    `send.ts` (TEXT, with the control-lane probe); `realtime.ts`; catch-up; `restore.ts` from the self lane without a
    snapshot; the `conversation.tsx` change of §0.4.
  - Tests: flows "1:1 both ways", "later device", "unknown handles", "group # names" and "name sanitisation" (round
    10: names at creation are M6b code); `restore.spec.ts` test 1 (without the snapshot part) and test 5.
  - E2E: rewrite `test/e2e/run.mjs` for v2 (§5) and make it green on the M6b steps; make `src/lib/proto.ts` and
    `src/lib/wire.ts` strippable first (§5 step 3; round 9).
  - README (round 9): the app works and e2e is v2 and green from here, so update `README.md` in the same commit: the
    "現在の状態" note (lines 6–7 at c993e83), the `src/client/` row (18: the engine is no longer a placeholder), the
    `test/engine/` row (25: engine tests exist), the `test/e2e/` row (26: v2, not "M8") and the e2e remark (47). M9
    changes only the spec link (line 9) and the `docs/DESIGN.md` remark (line 10).
- **M6c — the rest of M6 (2–3 days).**
  - Code: images; WELCOMEs through a qualifying 1:1 and the rest of the delivery queue (`deliver.ts`: retry with
    backoff, resume per SPEC §6.11; round 10); `history.ts`;
    snapshots; HEADS splitting; CONTACT and MEMBER records; the trial-decryption Web Worker (`inbox-worker.ts`,
    `inbox-worker-url.ts`, `EngineOptions.inboxWorker`) with the CSP change of §0.4; era rollover; stale server time;
    client-side limits.
  - Harness (round 9): the builders `signEpoch`, `buildBundleFor`, `forgeJoin` and `buildMessage` of §2.3 (tests 10,
    13 and 18, `images.spec.ts` #61).
  - Tests: `images.spec.ts` (4); `restore.spec.ts` test 1 (snapshot part) and tests 2–4 and 6–18. The parts that need
    commits or leaves land with M7 (round 10): test 8's add variant, test 10's era variant, test 12's variants
    that need claims, test 17's epoch-2 snapshot and its LEAVE-record part (unless the test writes those self records
    directly), and test 18's claim part.
  - E2E: the M6c steps of §5.
- **Leaves (round 10).** Applying LEAVE rows and everything about LEFT records (writing them beside HEADS entries and
  in snapshots, the kept-source rule of SPEC §6.9, their use at restore) land with M7's leave: the leave parts of the
  `conv.ts`, `selflane.ts` and `restore.ts` rows above are M7 work, and M6 writes HEADS entries without LEFT records,
  since no M6 path records a leave. The LEFT codec is M1.

M6 implements **creation** (SPEC §6.1: blob first, then CONV_JOIN + EPOCH_PENDING(e = 0) in one class-1 self row,
the wait, the decoy, J via a 1:1 WELCOME or batched inbox invites, the class-1 DELIVERED row) and the J delivery queue
with retry and resume (§6.11–§6.12), but not yet claims. It also implements:

- the server-time estimate from the `x-segv-now` samples of `no-store` responses (`api.ts`, SPEC §10.1), and the
  monotonic commit wait;
- the engine options object (`EngineOptions`, test-only) for every protocol delay of SPEC §11, the transport, the
  injectable clock (independent monotonic and wall clocks, timers on the monotonic clock) and the `beforePutAttempt`
  hook (§2.2; round 8);
- restore by processed positions (HEADS, trusted), DESC records, `P0 = 2` probes, bodies from the processed position to
  the head in **every epoch since the HEADS epoch** (SPEC §11.4), MEMBER records instead of directory lookups for
  known members, initial history for the 20 most recent copies, and 429 back-off;
- request copies (REQUEST records, cheap probing, no subscription, the transitions of SPEC §11.5);
- CONTACT and MEMBER records in the HEADS row (a request's `D.by` MEMBER in the REQUEST's row), HEADS at most every
  30 minutes and right after registration, and the durability order of SPEC §7.3;
- `markRead` as the open hint (scrollback once, request acceptance) and the UI changes of §0.3–§0.4 of this plan
  (round 8);
- trial decryption in a Web Worker (`src/client/inbox-worker.ts`, created through the `segv-worker` Trusted Types
  policy of §0.4; M6c, round 8). The same-thread path (chunked, yielding between chunks) is used by the engine tests
  and by M6b until the worker lands.

**Reuse** (v1 sources at 3de5f5e, §0.1).

- From `3de5f5e:src/client/engine.ts`: `authFlow`, `remember`, `assertSession`,
  `warn`/`die`/`patch`/`scheduleEmit`/`emitNow`, `views()`, `cleanName`, `resolveHandles` (now asynchronous through
  prefixes), `addEcho`/`markEcho`, the `sendChains` serialisation, `loadImage` + `imageCache`, and the image path of
  `sendImage`.
- In the tree and unchanged: `src/client/image.ts`, `webauthn.ts` (PRF input already `segv.sh/v2/prf`) and
  `session.ts` (AAD already `segv.sh/v2/session/<uid>` since 8092e98). `dh.ts` was deleted at 8092e98.

**Tests.** Port these spec files from `3de5f5e:test/engine/` into `test/engine/` (mapping in §3 of this plan):
`accounts.spec.ts` (10), `images.spec.ts` (4), and from `flows.spec.ts` the tests "1:1 both ways", "later device",
"unknown handles", "group # names" and "name sanitisation" (5). New tests in `test/engine/restore.spec.ts`:

1. A reload restores conversations from the self lane without a snapshot, then a snapshot is written and the next
   restore uses it.
2. Two devices write self records concurrently: both are applied once, and copy numbering is equal on both, also when
   one restores from a snapshot and the other from the lane (COR-25).
3. An era rollover during a session (`world.advanceEra()`): sends go to `(E+1, 0)` with `prev` pointing into E, and the
   receivers follow. Two devices write `(E, 6)` and `(E+1, 0)` of one lane around the boundary, in both orders: live
   receivers, restore and scrollback show both (COR-21, LIVE3-7). **Self-lane variant** (LIVE3-7): device A writes a
   HEADS at `Lself(E+1, 0)`, then device B writes a CONV_JOIN at `Lself(E, n)` with its `Tself` frame dropped; A's next
   snapshot has `(Eh, nh)` in E+1 only after `(E, n+1)` was observed `MISS(sealed = 1)`, and a restore from it holds
   the conversation. A device whose clock estimate steps back across the boundary still writes in E+1. A repeated
   WRONG_ERA waits until `end(min(E, E')) + SKEW` before the next attempt (COR-20).
4. A restore after `advanceEra() × 3` with idle lanes probes one key per idle era, and a catch-up 10 eras later probes
   at most `W + 1` keys per idle lane (CMP-15).
5. `createConversation` resolves with the conversation present in `conversations`, before the commit wait ends. A
   `sendText` issued right after it resolves stays `sending` until the decoy is stored, and its row's `t` is not
   below the decoy's (SEC-9, CMP-20). A failed handle lookup (FakeWorld `failDir`: 503 once) fails the creation with
   the request error, never "unknown: @x" (ADV3-9); only a complete answer without the handle gives "unknown".
6. **Creation crash** (COR-6, IMP-3, CMP-2): the creator logs out during the Δ + SKEW wait; a second device of the
   creator delivers J after `RESUME_AFTER` (knob), and the invitee holds the conversation. A creator whose engine is
   aborted before the PUT leaves no copy.
7. **Delivery under limits** (COR-7, IMP-2, CMP-3): with the FakeWorld rate limiter on (10 inbox posts per 60 s) and the
   day cap at 5, a 32-member creation with strangers sends one batched post; the rows past the cap retry after the
   fake day rolls over, with the "has not been notified yet" warning; every invitee joins. Variant (LIVE3-13;
   rewritten in round 10, R8-5): with `dayCap` at its default (2000) and the world's `skew = 1`, a `beforeRequest`
   hook on the first `POST /api/v2/inbox` moves the server clock to `end(E) − 500 ms` (`world.advance(…,
   {keepSockets: true})`; E is the era of the world clock when the hook runs, the era the engine posts) and calls
   `world.inbox.wrongEraOnce(E + 1)`. The engine rebuilds the invites for E+1 (fresh `eid`, AAD with E+1) and posts
   them at once: exactly two inbox posts, the second for E+1, with no wait in between; it writes no DELIVERED for the
   refused post, and every invitee joins. (Creation waits Δ + SKEW before it posts, so the clock is moved in the
   hook, not before `createConversation`.) Second variant: mid-era, `wrongEraOnce()` refuses with 409 `{era: E}` (the
   posted era, which a real InboxDO never reports); the engine makes no further inbox post before `end(E) + SKEW` by
   its clock, then its post for E gets the Worker's 409 `{era: E+1}`, and it posts for E+1 at once.
8. **WELCOME beyond the window** (SEC-11, COR-5): dave has posted in his 1:1 with alice (so it qualifies, SPEC §6.12)
   and goes offline; alice creates G with carol and dave (round 10: a creation, so M6c needs no commit; dave's J is a
   WELCOME in their 1:1) and then sends 40 texts in the 1:1; dave unlocks and holds G. Variant: dave never posted in
   the 1:1, so alice's J goes by inbox, and dave still holds G. Add variant (lands with M7): alice adds dave to an
   existing G by a commit, with the same result.
9. **Inbox cursor** (CMP-4, COR-19): a device that polled 1 h ago restores and fetches only the inbox rows since; a
   join whose CONV_JOIN write fails is not passed by the persisted cursor. Variants: (a) a cursor 5 eras old gets a
   410, moves to `(E_now − 3, 0)` and reads later eras from `after = 0` (COR-13); (b) **era rollover** (LIVE3-2): with
   `inboxJitter` at its maximum, an invite posted `D/2` before the era end is not visible to a poll `D/2` after the
   boundary; the cursor stays in the old era until a read issued at `end(E) + (2·SKEW + 2·Δin)` s or later, and the
   invitee holds the conversation;
   (c) **transient join failures** (LIVE3-3): the J's blob GET (or its `blob/meta`) answers 503 twice; the join is
   parked, the persisted cursor stays before it, and the join is accepted once the fake recovers. A blob that is
   absent with `meta` MISS drops the join with a noise warning.
10. **Requests** (SEC-13, SEC-17, CMP-5, COR-16, CMP-12): a stranger's group with carol offline; alice and bob post;
    carol restores with the realtime fake disabled and sees both; opening the copy (`markRead`) accepts it. 100 spam
    joins cost ≤ 1 blob GET, ≤ 1 `blob/meta` and ≤ 1 directory request each, keep ≤ 64 REQUESTs, add no topics, and
    leave the next restore's requests within the budget of `2·m + 3` keys per request, with no directory request for
    them (each REQUEST's row carries the MEMBER of its `D.by`, also when D lists `D.by` with its real `sigPk` but a
    foreign `kh`, READV5-6). The request's other members show as `?…` until carol
    opens it. Era variant (CONS3-4; lands with M7, round 10): a member commits in a later era (`advanceEra()` first);
    the request copy finds the claim through control `(E_now, 0)`. Size variant (READV4-3): 10 joins name one registered 12 MiB blob with
    `bundleSize = 23456`; each costs one `blob/meta` and no blob GET, and gives a noise warning.
11. **HEADS splitting** (CMP-13): an account with 200 copies writes HEADS across several rows and restores from it.
12. **Scrollback after reload** (IMP-1, CMP-6): a reloaded engine calls `markRead` on a 1:1 with 100 messages and
    shows more than 60. Variant (SPEC §5.2, §11.10; needs the claims of M7, so it lands with them): a WELCOME that
    only scrollback reaches is accepted. Alice's second device writes it into her lane of the 1:1's epoch e after bob
    swept that lane (her first device already posted in e+1: the own-device race of SPEC §11.2; `beforePut` holds the
    put). Bob finds it when he opens the 1:1, both live and after a reload, where no sweep head of e is known and
    scrollback probes slot 0 of every era from `E_start(e)` and gallops (READV6-3). **Inflated-cut variant**
    (READV6-3): the claim that ended e names alice's cut as `(E_last + 1, 0)` (or `(E_last, 2^32 − 1)`); after a
    reload bob's scrollback still shows alice's rows of e, with a bounded number of `get` requests. **Era-crossing variant** (READV5-5): alice's lane of
    e was last written in era E; after `advanceEra()` the claim that ends e lands at `(E+1, 0)` of the control lane,
    and the second device's WELCOME at `(E+1, 0)` of alice's lane; bob's scrollback finds it (live and after a reload)
    by probing slot 0 of E+1 (and E+2), not only the `W` slots after the head in E.
13. **Unknown members** (SEC-3, RC-1): a conversation that lists an unregistered uid U (with a key mallory holds) is
    joined; U shows as `?…`, and U's rows verify under the key in D and are shown at once, under `?…`. After
    `world.dir.register(U)` with that key, the next restore shows U's handle and writes a MEMBER. Variant: D lists
    bob's uid with mallory's key; alice shows that member as `?…` (never `@bob`) and raises "the public keys of @bob
    changed", while bob himself rejects the join with a noise warning (D does not list him with his own key). Variant
    (READV4-1): D lists bob with his own `sigPk` but the `kh` of a key mallory holds; bob rejects the join the same
    way, and alice shows that member as `?…` (never `@bob`), raises "the public keys of @bob changed", writes a MEMBER
    for bob from his directory bundle, and after a reload still shows `?…` and raises the warning **without a
    directory lookup** (READV5-6: the restore compares D with the MEMBER); her other conversations with bob still show
    `@bob`. With a MEMBER for bob already in alice's self lane (from an earlier conversation), the same D shows `?…`
    without a lookup.
14. **MEMBER records** (RC-4): alice is in 5 groups with 30 distinct co-members (all in different prefixes at the test
    `p`); after a snapshot, a reload makes exactly one directory request (`dir/uid` for herself), no prefix lookup and
    no `dirlog` read. Variant: the HEADS row carrying the MEMBER records was never written (crash), so the first reload
    makes ≤ 30 prefix requests, writes the MEMBERs, and the second reload makes none.
15. **Stale server time** (RC-9): with FakeWorld `staleNow` on, blob GETs and inbox reads (both `public`) carry an
    `x-segv-now` three weeks old. After loading an image and polling the inbox, the engine's server-time estimate is
    unchanged (within the test clock's resolution), the next send picks the current era without a WRONG_ERA, and PoW
    windows are accepted. **Sample variant** (round 7, SPEC §10.1; rewritten in rounds 8 and 9): after
    `world.advanceEra(1, {keepSockets: true})` (the server only: the engine's clocks do not move, so its monotonic
    clock looks held still across the jump, and no reconnect brings a HELLO first), the next `no-store` response gets
    an `rtt` of at least 1 s (`I(e).clock.advance(1000, {mono: true})` from `beforeRequest`; still below the 2 s of a
    poor sample and far below the week of disagreement). It discards the older samples, and the estimate follows the
    world (the next send picks `E_now` without a WRONG_ERA). Assert that `I(e).timeSample.rtt < 1000` just before the
    jump (the sample in use is the one with the smallest `rtt`, so every sample the estimate could prefer was below
    1 s) and that afterwards `I(e).timeSample` is the new sample, with `rtt ≥ 1000` (round 10: §2.3 exposes only the
    sample in use), so with the larger `rtt` only the discard rule can have made the estimate follow (round 9: the
    5 ms of round 8 could be smaller than real elapsed time on a loaded runner, a silent false pass). Separately, with `I(e).clock.pauseMono()`, two `no-store` responses (e.g. two `I(e).catchUp()` calls) give
    two samples with `rtt = 0`, 500 ms of server time apart (`world.advance(500, {keepSockets: true})`, below the 1 s
    discard margin); `I(e).timeSample` is the newer one; then `resumeMono()`.
16. **Client-side limits and probes** (CONS3-8): a directory page for `p ≥ 1` with fewer than 8 users gives the noise
    warning "the directory answered fewer accounts than expected" (SEC-10); an engine with 300 copies subscribes at
    most 256 topics per socket and opens at most 2 sockets; after a 1008 or 1013 close it waits at least 60 s before
    reconnecting (COR-17); a SUB of a new topic is followed by a one-shot probe of its expected slots, which finds a row
    published just before the SUB (COR-22). **Prefix bits** (round 7, SPEC §10.6), at unit level in `api.ts`: with
    params `P = 0` and `dirSeq = 20 000` a lookup asks `p = 2` (`P* = 3`), not `p = 0`; a 409 `{p: 0}` retry asks
    `p = 0` (`clientP(min(3, 0), 20 000)`) and is not raised again (round 8: a server whose `P` is 1 accepts `p = 2`,
    so the 409 names `P′ = 0`).
17. **Self-lane fold** (SEC-16, LIVE3-15): a CONV_JOIN for a conv that already holds a different copy with a
    CONFIRMED record is dropped with the critical warning, and a corroboration writes CONFIRMED before the CONV_JOIN in
    the same row; a snapshot written after every invitee of a creation is covered contains neither its EPOCH_PENDING
    nor its DELIVERED records, and the next restore still holds the epoch key. **Round 7** (SPEC §7.4, §6.9; lands
    with M7, which makes the commits and leaves, unless the test writes these self records directly; round 10): a
    snapshot of a created copy (root epoch 0) that reached epoch 2 holds EPOCH records for 1 and 2 only and parses;
    with the records LEAVE(3), a skip EPOCH(6), LEAVE(7) and then a late row's LEAVE(5), in that order, the snapshot
    keeps LEAVE(7) (the highest e, which is neither the first nor the last record; round 8), and the restored copy's
    leave stays current.
18. **Names never decide validity** (READV5-2): mallory creates G with alice and bob under the name "@bob" (built
    with `signEpoch`, without `validName`); both join it and show it unnamed (alice's view name is "@bob, @mallory",
    never "# @bob"). With the claims of M7: a `commitChange` that renames G to U+202E followed by "evil" is accepted by
    every member (nobody is frozen) and shows no rename line, only "@mallory rotated the conversation keys" (both names
    display as absent, SPEC §11.9), and a reload restores the same epoch from its DESC record. A later rename to "team"
    shows "@mallory renamed the conversation to “team”", and a rename back to U+202E + "evil" shows "@mallory removed
    the conversation name" (RECONS6-5). A later honest rotation by alice carries the name over byte for byte and is
    accepted by everyone.

**Acceptance.** The listed specs are green in the `engine` project, and `npm run test:e2e` is green on every M6b and
M6c step of §5 (round 8).

### M7. Membership: control lane, claims, cuts, leave, copies (5–7 days; round 8: current paths, 3de5f5e sources; round 10: LEFT records land here with leave; round 11: leave-dependent lines derived, skip EPOCH position; round 12: one "@x left" line per leave, lines after a reload, every held epoch at restore)

**Add / extend `src/client/claims.ts`:**

- control-lane probing and dense prefixes;
- three-valued e-validity (a)–(h): `rm` and cut bounds, the bundle fetch (only after rule (g) holds) and shape, no
  request before the local rules pass, then (f)'s `meta`, (g)'s and (h)'s in that order (SPEC §6.4; round 11; round
  12: the local rules, which `claimShapeValid` checks, include `bundleSize` and `B ≥ |D_e|`, and the `get` of the row
  itself, or of its `t_row` after a realtime frame, is not ordered), the BlobReg MISS decisiveness, and undecided
  results for network errors, timeouts, 429 and 5xx;
- the winner (every earlier slot decided) and finality across eras (sealed observations or own HEADS);
- `processWinningClaim`: `rm`-based removal, the single frozen state (own entry not opened, or `D′` invalid; no
  skipping, no repair), the D′ checks (a `descCt` or `pkCt` that does not open or parse is D′-invalid, then
  `dPrimeChecks` of `src/lib/proto.ts`, including the recomputation of every kept entry), accept,
  system lines from `rm`, the sweep of the old epoch's lanes, followed lanes (epoch c−1 of each member silent in c),
  and the send refusal of a frozen epoch whose claim removed a member who had not left; the lines and the refusal
  follow the current leave state and are derived again when a source is added, replaced or dropped (SPEC §6.6 steps
  5–6, §11.3 step 2, §11.9; round 11);
- the commit procedure of SPEC §6.3: blob first (continuing members' `kemPk` from the previous bundle's `pks`, never
  from the directory), EPOCH_PENDING, the monotonic + server-time wait, the re-check, the CAS loop with every outcome
  (identical occupant, undecided occupant, `t ≤ t_reg`, WRONG_ERA, network), the decide step, the switch, J delivery
  and the DELIVERED row;
- EPOCH_PENDING recovery for e ≥ 1 (keyed by bundleId);
- parking of joins that arrive before their claim is settled, and leavers / removed members following their last
  control lane;
- the old-epoch acceptance walk of §6.8 (by `t` and `rm`), with deterministic retraction: a dropped LEAVE row
  un-records its leave (round 8), and so does a claim that drops the row of a leave taken from a LEFT record, decided
  with the record's time and position (round 9); per copy, epoch and member the least source is kept and the leave
  stands while §6.8 accepts it (SPEC §6.9 "Several sources"), and the walk reads a sender's bit from `D_{j+1}` and an
  unprocessed `C_j` at its EPOCH record's position only where it removes the sender (SPEC §6.8; round 10), over
  consecutive epochs only (a skip re-add ends the walk; the claim that removed self is read at the skip EPOCH's
  position; round 11);
- leave, plus the rotation-before-send of §6.9 (skipped when frozen), and the LEFT records that go with it: writing
  them beside every HEADS entry of their epoch and in snapshots, and their use at restore (the leave parts of the M6
  `conv.ts`, `selflane.ts` and `restore.ts` rows; round 10);
- `addMembers` / `removeMember` with the leaver handling ported from `3de5f5e:src/client/engine.ts:396-438`;
- the `blocked = "pending"` / `"frozen"` and `frozen` view fields of §0.3 (round 8; `pending` only after the step-2
  wait, round 9);
- harness (round 9): the builders `commitChange`, `buildClaim`, `readableWith` and `entryOutcome` of §2.3.

**Tests.** Port, from `3de5f5e:test/engine/`, `flows.spec.ts` "add/remove/rename" and "leave", all of `epochs.spec.ts`
(19), `sending.spec.ts` (9) and `privacy.spec.ts` (3). New tests in `test/engine/claims.spec.ts`:

1. The first e-valid claim wins over a later one at k+1. Junk at `(E, 0)` is skipped with the noise warning.
2. A claim whose bundle is registered after the claim's `t` (forged with a fake BlobReg timestamp hook) is e-invalid
   for every member.
3. A MISS within SKEW is retried, not decided (the fake reports `now < t_row` once).
4. A claim written while the previous era is unsealed becomes final only after `world.sealPrevious()`. A claim placed
   in the old era's prefix before the seal wins over the new-era claim.
5. **Invalid D′ freezes everyone** (SEC-2, RC-2): mallory's e-valid claim has valid entries and garbage `descCt`; a
   later honest claim at k+1 is not used; every member is frozen with "@mallory made an invalid membership change";
   messaging in e continues. Variant (RC-2): D′ decrypts but has a wrong `prev`; mallory then sends J(e+1) of that D′
   (same EK′ and bundleId) to every member by inbox and by WELCOME; every member ignores it (the "claimed" rule, SPEC
   §6.7 step 5), stays frozen in e (`mustView(X, id).epoch` unchanged), writes no EPOCH record and gets no new
   warning.
6. **Split withholding plus invalid D′** (SEC-2, COR-3b, RC-2): entries open for alice and bob, garbage for carol, and
   D′ is invalid; all three agree on the winner (`I(e).winner` equal) and are frozen; nobody reaches e+1; carol's
   warning is the named "never delivered" text. Variant: mallory sends J(e+1) of the invalid D′ to all three; it is
   ignored by all, and nobody reaches e+1.
7. **Partial withholding freezes everyone** (SEC-4, CMP-7, SIMP3-1): mallory's claim (rm = 0, a valid-looking D′)
   gives bob's entry a dummy seal. Bob is frozen with "@mallory's membership change was never delivered to you; …";
   alice and carol recompute bob's entry, find it wrong and are frozen with "@mallory made an invalid membership
   change; …" (`I(X).frozen` = `"nokey"` for bob and `"invalid"` for the others); nobody reaches e+1; bob's "hello?"
   in e is read by alice and carol, and theirs by him. Variants: bob's entry is a fresh-randomness `seal` to bob's
   right key (bob opens it, and everyone, bob included, is frozen as invalid); bob's entry is `sealDet` to another key;
   every entry except mallory's is a dummy (withheld from all: every member shows the named text). No member posts
   anything because of the freeze, and a reload of every device re-derives the same state.
8. **Covert removal is impossible** (SEC-1, CMP-8, COR-3a, RC-2): mallory's claim gives victor a dummy entry while
   `rm` keeps him and D′ lists him. Everyone is frozen as in test 7, victor's warning names mallory and is not
   "removed you", and nobody shows a removal. Variant A: D′ also omits victor (or lists him with `rm` set): everyone
   is frozen; mallory then sends J(e+1) of that D′ to alice and bob, who ignore it; a J to victor is rejected
   (self ∉ D). Variant B: a later forged J(e = k+5) from mallory to victor is rejected (no skip, since victor's `rm`
   bit is 0).
9. **Consistent removal lines** (SEC-1, ADV3-3): bob removes victor; alice sees "@bob removed @victor" and victor sees
   "@bob removed you". Variant: mallory's claim removes victor and is D′-invalid; every member is frozen and shows
   "@mallory removed @victor"; `canSend` is false (`blocked = "frozen"`, `frozen = true`; round 8), a `sendText` in e fails
   with "a removed member could still read this conversation; start a new conversation", nothing is written to any
   lane of e, and `leave` still works.
10. **Registration between evaluations** (SEC-3, RC-1): (a) a claim's D′ lists a fresh uid U with a key mallory holds;
    alice evaluates, then `world.dir.register(U)`, then bob evaluates and carol restores: all three reach the same
    epoch. (b) **Unregistered committer**: mallory's D′ adds U (unregistered); U, as a member of e+1, writes a
    well-formed claim at `Lctl_{e+1}(E, k)`; alice evaluates it (U has no bundle), then `world.dir.register(U)`, then
    bob evaluates and carol restores; all three agree that U's claim at k is the winner (`I(e).winner` equal) and
    reach the same e+2; alice's own claim attempt at k+1 loses.
11. **Cuts** (SEC-5, COR-14): a claim with `cut_R = (0xFFFE, …)` is e-invalid; a claim with every cut at
    `(E_start, 0)` still shows R's earlier messages on every device, and R's rows after the claim are dropped and
    retracted from live views.
12. **Bundle shape** (SEC-6, COR-15, ADV3-3): claims pointing at a 12 MiB image blob (no member fetches it: rule (g)
    fails on `meta` first, READV4-3), at an 81 248-byte blob with a bad header, and at a B = 8 bundle for a 20-member
    group are e-invalid for all; a blob GET that fails twice is undecided, a send meanwhile waits 30 s and then fails
    with "the conversation is changing membership; try again in a moment" (no row is written to e), and once the fake
    recovers the claim is applied and the retried send goes to e+1. `blocked` stays `""` (`canSend` true) until the
    claim has been undecided for the step-2 wait, is `"pending"` from then until the claim is applied, and is `""`
    again after it (round 9, SPEC §11.3 step 2). Variants: a `blob/meta` that answers 429 makes
    the claim undecided, never e-invalid (READV4-4); a send whose control probe fails (`fail('before')` on the probe's
    `get`) fails with "message was not delivered …" and writes nothing (READV4-2).
13. **Early commit** (COR-1, IMP-4, CMP-1): the fake shard clock lags BlobReg by more than SKEW, so the first CAS
    returns OK with `t ≤ t_reg`; the committer posts no J and does not switch, retries at k+1, and that claim wins.
    Variant: the engine clock runs 5 s fast.
14. **Undecided occupant** (COR-2): mallory's claim at (E, 0) has an unregistered bundle and the fake returns
    `missNow < t_row`; alice's CAS at (E, 0) conflicts and alice waits instead of writing at (E, 1); mallory then
    registers late; every member agrees on the winner.
15. **Lost CAS response** (COR-11): `fail('after')` on the claim put; the retry's CONFLICT carries our own body, so the
    commit completes and dave receives J at once.
16. **J before its claim** (SEC-12, COR-8): bob leaves; alice drops leavers and re-adds bob; the publish of the
    dropping claim is lost (`wsEnabled` off for that row) and J(k+2) arrives first; bob parks it and accepts it as a
    skip once the claim is processed, with no warning. Variant: a newcomer gets J(e+1) and J(e+3) in one poll.
    **Reload after a skip** (ADV3-6, LIVE3-8): bob reloads before any HEADS records the re-add (his HEADS still names
    the epoch before his removal); the restore re-derives the removal, applies the skip EPOCH record, and bob is in
    the re-added epoch with no new warning or system line. **History below a skip** (round 11, SPEC §6.8, §7.2,
    §11.10): alice's claim C_k removes bob and carol; carol has a TEXT on her lane of k stored before C_k and one stored
    after it (`buildMessage`); live, bob shows the first and never the second; alice's next commit re-adds bob (J(k+2), a
    skip), and bob's skip EPOCH record names C_k's position; bob's device writes a snapshot in e′ = k+2
    (`advanceEra()`) and reloads; his history continues from k+2 into k and reads C_k at that position somewhere
    between the reload and the settled `markRead` (the initial history already steps into k, since k+2 has fewer than
    30 rows; round 12, V11CON-5): a body `get`, with no `blob/meta` request or blob GET of C_k's bundle, and no blob GET
    of k's bundle either, since the snapshot holds DESC(k) (SPEC §7.4; round 12); it shows carol's first TEXT but not
    the second, as live. **Post-snapshot variant** (round 12, SPEC §11.4 step 5): without `advanceEra()`, so bob's
    only snapshot was written in this era before G's epoch 1; alice's two commits that keep bob move him to k = 2
    through his own entries, C_2 removes him and carol, and alice re-adds him (a skip to 4, then a HEADS(4) row); his
    reload processes G's control lanes from the root, so it holds epochs 1 and 2 and C_2 (no EPOCH record names
    them), and his history shows carol's first TEXT of epoch 2 but not the second, as live. **D.by key check**
    (CONS3-6): a forged first contact whose D names `D.by = alice` with eve's key gives bob no copy, no system line,
    and only the noise warning "ignored a conversation key with an invalid signature"; the same holds for a skip re-add whose `D.by` key differs from bob's
    MEMBER pin. A `D.by` lookup that answers 503 parks the join instead (LIVE3-3).
17. **Frozen member with a leaver** (COR-23, CMP-17): a frozen member can still send TEXT after another member left.
18. **Sibling commits** (COR-24): two devices of alice race commits for the same e; the winner's device crashes after
    the CAS; the other device's recovery delivers J from the winner's EPOCH_PENDING.
19. **Committer crash** (old item 7): a second device of the committer delivers J from EPOCH_PENDING after
    `RESUME_AFTER` (engine option).
20. **Row beyond a hole**: covered by integrity test COR-10 (M8).
21. **Failed echo retry** (COR-26): a slow put whose probe returned MISS is retried with the same sealed body and gives
    one message, not two. Variant: a claim becomes final between the failure and "try again"; the retry probes the
    kept slot (MISS) and builds the message again in e+1. Variant (READV4-2): the failed put lands late, after two
    claims became final; the retry finds our body at the kept slot in e while the copy is in e+2, treats it as a late
    row, and builds the message again in e+2 (alice and bob show it once, from e+2).
22. **A late row in the previous epoch** (ADV3-4, LIVE3-1): alice, bob and zed; zed's last row is in e−1. Alice's claim
    C (e → e+1) lands; the realtime frame to zed is dropped. (a) zed sends a LEAVE right away: his control probe (SPEC
    §11.3 step 1) sees C, he switches first, and the LEAVE lands in e+1. (b) With zed's probe answered before C is
    stored (`beforePut` holds C until zed's `get` returned), zed's LEAVE lands in e after alice and bob switched; both
    follow zed's lane of e (`I(A).followed`), see the LEAVE, and rotate before their next text; a restore of bob from
    a HEADS at e+1 sees it too. (c) As (b) with a TEXT instead of a LEAVE: alice and bob show it. Then zed posts in
    e+1, and the followed lane is dropped after a final sweep. (d) **Stale probe** (READV4-2, RECONS4-2): zed's
    engine clock (monotonic and wall) advances by more than `(Δ + SKEW)/2` between his step-1 probe and his put (a
    slow proof of work or a frozen tab: `I(zed).clock.advance` from his `beforePutAttempt` hook, §2.2; round 8), while alice
    commits twice (e → e+1 → e+2); zed probes again before the put,
    and his TEXT lands in e+2 and is shown by alice and bob. (e) **Late put**: as (d), but the put itself is held
    (`beforePut`) until both claims are final; the answer arrives more than `Δ + SKEW` after the probe, zed's late-row
    check finds the copy in e+2, and the echo shows `failed` (a LEAVE instead is put again in e+2, not refused as "you
    left", and alice and bob rotate zed out; READV5-4). **Reload variant** (READV5-4): zed's LEAVE answer is late, and
    his engine is logged out before the repeat is put (`beforePut` holds it); his next session's restore finds the
    LEAVE record two epochs back, puts the LEAVE in e+2 (SPEC §6.9), and alice and bob rotate zed out. **Re-add
    variant** (READV6-1): after zed is rotated out, alice re-adds him (a skip join on zed's side); zed's device puts no
    new LEAVE (after catch-up and after a reload), zed can send, and alice and bob do not record him as left in the
    re-added epoch. (f) **Idle
    eras**: after `advanceEra() × 2`, alice's claim sits at `(E_c + 1, 0)`; zed's step-1 probe (every era of SPEC §6.5)
    finds it and his row lands in e+1. (g) **Rotation after a stale probe** (READV5-3): G = {alice, bob, lee}; alice's
    TEXT passes steps 1–3, then her engine clock advances by more than `(Δ + SKEW)/2` before the put; meanwhile lee
    leaves (alice receives the LEAVE, the frame to bob is dropped) and bob renames G, keeping lee (e → e+1). Alice's fresh probe accepts e+1,
    finds lee's leave carried over, commits a rotation (e+1 → e+2) and puts the TEXT in e+2; no row readable with
    `mk_{e+1}` holds the text, and lee's entry in the e+2 bundle opens for nobody (`entryOutcome`). (h) **Suspend**
    (round 7, SPEC §10.1, §11.3 step 6; rewritten in round 8 so that the wall clock is the only trigger): in zed's
    `beforePutAttempt` hook, `I(zed).clock.pauseMono()`, then `world.tick(2 h)` moves the world and every other clock
    (zed's wall clock included; sockets stay open), alice commits twice (e → e+1 → e+2) with both claims' frames to
    zed dropped (`dropPublish`) and without settling zed, then `I(zed).clock.resumeMono()`. Zed's copy is still in e
    when the fresh-probe check runs (assert it), and his monotonic clock and server-time estimate show no elapsed time,
    so only the wall clock triggers the probe. The TEXT lands in e+2 and is shown by alice and bob, and after the
    probe's response zed's estimate is current again (his next put needs no WRONG_ERA; test 15 isolates the discard
    rule).
23. **WELCOME in an older epoch after HEADS** (RC-6): bob's HEADS for his 1:1 with alice covers alice's e0 lane up to
    (E, 10); bob goes offline; alice adds bob to G with a WELCOME at (E, 11) of the 1:1's e0; alice adds carol to the
    1:1 (e1) and posts in e1. Bob restores and holds G. Live variant: bob stays online but the realtime publish of
    (E, 11) is dropped (`dropPublish`); after alice's e1 post, bob's switch to e1 sweeps alice's e0 lane, and bob holds
    G. **Parked variant** (READV4-5, RECONS4-9): the sweep finds the WELCOME but G's `blob/meta` answers 503
    (`failMeta`), so the join is parked; bob's HEADS for the 1:1 is written (timer knob) and must describe e0 with
    alice's lane before the WELCOME, not e1; bob reloads before the fake recovers, the restore processes e0 again, and
    bob holds G once `meta` answers.
24. **Expired request is not a WELCOME channel** (RC-5): alice starts a 1:1 with bob (a stranger, so a request on
    bob's side) and bob never opens it; `advanceEra × 5` expires the request (variant: 64 newer spam requests push it
    out). Alice adds bob to G: her J goes by inbox (assert no WELCOME row was written), and bob holds G. Variant: bob
    posted in the 1:1 and then left it; alice's add again goes by inbox.
25. **WELCOME racing a leave** (LIVE3-4): alice posts a WELCOME for G in her 1:1 with bob, the frame to bob is
    dropped, and bob leaves the 1:1 5 s later; bob's next catch-up still processes the WELCOME (a leaver keeps
    processing WELCOMEs until a claim drops it) and bob holds G. Mirror: bob's LEAVE is stored first but its frame to
    alice is dropped, so alice still uses the 1:1; bob holds G.
26. **Leave order** (LIVE3-9): `fail('after')` on the LEAVE put leaves no LEAVE record until the probe finds the row;
    a crash after the LEAVE row but before the record is repaired by the next restore of any device (it applies its
    own LEAVE row and writes the record); the others see the LEAVE and rotate.
27. **Honest commits never freeze** (SIMP3-1, ADV3-9): alice commits a rename while the fake directory answers 503 for
    every prefix (`failDir`); the commit needs no lookup (every `kemPk` comes from the previous bundle), everyone
    reaches e+1, and the commit made no directory request. An unknown member (no directory bundle) also gets a real
    entry and reaches e+1.
28. **No covert reader under a real handle** (READV4-1, RECONS4-1): mallory creates G with alice and a slot for bob's
    uid with bob's real `sigPk` but the `kh` of a key X that mallory holds (variant: mallory adds that slot by a
    commit). alice shows the slot as `?…` with "the public keys of @bob changed", never `@bob`, before and after a
    reload. alice then removes mallory and the slot: no entry of any later bundle opens under X or under mallory's
    key (`entryOutcome`). Control: if alice removes only mallory, the `?…` slot's entries still open under X, which is
    the documented power of SPEC §13.2 item 3.
29. **Followed lanes at restore** (RECONS4-3): alice and bob; bob writes 1 000 rows in epoch c−1, a commit moves the
    copy to c, bob posts once in c, and alice writes HEADS(c) (no followed lane for bob). alice reloads: the restore
    fetches no body of bob's lane of c−1 and follows no lane of c−1 for bob. Variant: bob stays silent in c; the
    HEADS entry lists bob's lane of c−1 with its position, and the restore fetches only the rows after it. Variant
    (RECONS4-7): a copy whose root epoch is c (alice was added at c) follows no lane.
30. **A WELCOME never moves into a later epoch of its carrier** (READV5-1): alice and bob share a 1:1 in epoch c, and
    bob has posted in c. Bob adds dave to the 1:1 (claim C1, c → c+1). (a) The realtime frame of C1 to alice is
    dropped (`dropPublish`); alice then adds bob to G {alice, carol}: her step-1 probe of the 1:1 processes C1, the
    WELCOME check of step 2 fails for c+1 (three members), nothing is written to the 1:1, and bob gets an inbox
    invite. (b) **Stale probe** (RECONS6-4, on the pattern of test 22 (d)): alice's engine clock (monotonic and wall)
    advances by more than `(Δ + SKEW)/2` between her step-1 probe and sending the WELCOME's put (her
    `beforePutAttempt` hook; round 8), while C1 is stored and becomes final in that window: the fresh probe finds c+1, nothing
    is put, and bob gets an inbox invite. (c) **Switch during the send** (READV6-4): with no clock advance, C1's frame
    is processed between alice's step 2 and a CONFLICT with a sibling device's row (her put returns to step 4): the
    fresh probe re-runs steps 1–3, nothing is put in c+1, and bob gets an inbox invite. In all three, no row readable
    with `mk_{c+1}` carries a J (`readableWith`), dave holds no copy of G, and bob holds G. Control: `beforePut` holds alice's WELCOME (built for c) until C1 is final, without
    a clock advance: the WELCOME lands in c (readable only with `mk_c`), is late, counts as delivered (no row of alice
    in c+1), and bob holds G through his followed lane of c.
31. **Others' leaves survive a reload** (READV6-2, rewritten for VADV-1/VADV-2; round 9: LEFT records carry the LEAVE
    row's time and position and are decided by §6.8 like the row, SPEC §6.8, §7.3): G = {alice, bob, lee}; lee leaves;
    alice applies the LEAVE live but sends nothing, writes HEADS (timer knob; the row carries `LEFT{e, lee, t, (E, n)}`
    of lee's LEAVE row beside the entry) and reloads. The restore takes lee's leave from the LEFT record, and alice's
    next `sendText` commits a rotation first: no row readable with the old epoch's `mk` holds the text.
    Variant: a racing claim keeps lee in e+1 (alice follows lee's lane of e); the same holds after a reload, and lee's
    own device repeats its LEAVE in e+1 once (SPEC §6.9). **Two-claim variant** (lee's engine is logged out right after
    her LEAVE is OK, so no repeat reaches xena; round 8): lee's LEAVE is in e; bob's add of xena, built before the row
    reached him, keeps lee in e+1; xena (root epoch e+1, no followed lane) adds yuri, keeping lee in e+2; alice writes
    HEADS(e+2) (its `LEFT{e+2, lee}` carries the row's `t` and NONE) and reloads: her restore holds lee as left (the
    newest LEAVE row being two epochs back), writes HEADS(e+2) again with that LEFT record, and a second reload before
    the text also holds lee as left (round 9); her next text rotates first; when lee's engine returns before that
    text, it puts its repeat in e+2, which changes nothing for alice. Xena's line for alice's rotation (round 11, SPEC
    §6.9): while lee's engine stays logged out until that rotation, xena has no source for the leave and shows
    "@alice removed @lee" where alice and bob show "keys rotated after @lee left"; when lee's repeat in e+2 reached her
    first, she shows "keys rotated after @lee left" too. **Flood variant:** G frozen in e (mallory's claim
    with a wrong kept entry); lee leaves, and 200 rows signed by lee follow the LEAVE on her lane (`buildMessage`);
    after alice's HEADS passes them, a reload fetches none of the 200 bodies and still holds lee as left.
    **Removed-copy flood variant** (round 9): mallory's claim removes alice (alice's copy stays in e, not frozen);
    mallory then leaves and puts 200 rows on her lane of e; alice's next HEADS passes them (with `LEFT{e, mallory}`),
    and a reload fetches none of them. **Snapshot variants** (round 8, SPEC §7.3: LEFT records sit beside every HEADS
    entry of their epoch): (a) alice's device holds a parked WELCOME for a new conversation H, found on bob's lane of
    G's epoch e−1 (`failMeta` on H's `blob/meta`), so its HEADS entries for G describe e−1; lee leaves G in e; a
    snapshot is written (more than 200 records, or `advanceEra()`); `meta` recovers, the J is accepted and alice
    writes HEADS(e) for G; a reload holds lee as left, and the next text in G rotates first. (b) alice's device A is in
    e+1, records lee's leave there and writes HEADS(e+1); her device B, which has not yet processed the claim that
    ended e (its frame dropped), writes HEADS(e) later; a snapshot is written; A writes HEADS(e+1) again; a reload of
    either device holds lee as left in e+1, and the next text rotates first. **Retracted-leave variants** (round 9,
    SPEC §6.8, §7.3; replace round 8's): G = {alice, bob, lee, mallory}; in each, a claim of mallory that drops lee and
    carries a wrong kept entry (D′ invalid, so G freezes) ends up dropping lee's LEAVE row R by §6.8 after alice has
    written HEADS with a LEFT record for lee:
    (a) **undecided claim**: mallory's claim C is stored before R; alice receives R while C is undecided (`failMeta`
    on C's bundle) and writes HEADS(e) with `LEFT{e, lee}` in that window (timer knob); bob receives R after C is
    final;
    (b) **claim beyond a hole** (V8ADV-1): mallory stores C* at `Lctl_e(E, 5)` with `(E, 0..4)` empty, before R
    (`buildClaim`); alice's probes see `(E, 0)` empty, she applies R and writes HEADS(e) with `LEFT{e, lee}`; then
    mallory fills `(E, 0..4)` with junk (`junkRow`), which makes C* the winner;
    (c) **pre-stored next claim** (V8ADV-1): mallory stores C_{e+1} (dropping lee) on `Lctl_{e+1}` before R, its
    labels computed from the EK_{e+1} she chose, and only after R commits the rename C_e that keeps lee; alice writes
    HEADS(e) with `LEFT{e, lee}` and, after switching to e+1, HEADS(e+1) with `LEFT{e+1, lee}` (NONE).
    In each, once the dropping claim is final and processed, alice drops the leave and shows "@mallory removed @lee",
    as bob does, and her `sendText` fails with "a removed member could still read this conversation; start a new
    conversation" (`blocked = "frozen"`): live, after a reload from the HEADS entry that carries the LEFT record (the
    restore re-decides it with the claim), and after a reload from a later entry.
    **Source-order variant** (round 10, SPEC §6.9 "Several sources", R10ADV-1/R10ADV-4): G = {alice, bob, lee,
    mallory} in e; lee's LEAVE R1 lands in e at t1; bob's add, built before R1 reached him, keeps lee, so the copy
    moves to e+1 and alice and bob follow lee's lane of e; lee's device repeats the LEAVE in e+1 as R′; mallory's
    C_{e+1} drops lee with a wrong kept entry (everyone frozen in e+1) and is stored with t1 < t(C_{e+1}) < t(R′)
    (`beforePut` holds R′ until C_{e+1} is stored). Bob applies R1 first. R1 is hidden from alice
    (`world.shard.hide(E, label(R1), "alice")`: no get or realtime frame of hers returns it) until the moment each order
    names, and then `unhide(E, label(R1), "alice")` (round 12, V11CON-1: `dropPublish` loses a publish for every
    subscriber, and alice's catch-ups would fetch R1 early). Alice runs in two orders (round 11, SPEC §6.6 step 5,
    §11.9): (i) R′ and then R1 before C_{e+1} is processed (`failMeta` on C_{e+1}'s bundle keeps it undecided): R1 is
    unhidden once she has applied R′, whose arrival made her sweep and drop lee's followed lane of e with R1 still
    hidden, and she finds R1 through the scrollback of her first `markRead` of G in the session, past the head that
    sweep recorded (SPEC §11.10); then `failMeta` is cleared; (ii) C_{e+1} first (`beforePut` holds R′ until her copy has processed C_{e+1}), so she shows
    "@mallory removed @lee" and refuses `sendText`; then R1 is unhidden, her next catch-up of lee's followed lane of e
    finds it, and she derives the line and the gate again; R′ is released after that. After settling, in both orders,
    alice and bob show "keys rotated after @lee left" and no "@mallory removed @lee", exactly one "@lee left" line (at
    R1, none at R′; SPEC §11.9), and both can `sendText` in e+1. Alice's next HEADS(e+1) row carries exactly one LEFT
    record for lee in e+1, with t1 and NONE (a carried record's position is NONE), and restores of alice from a
    HEADS(e) written before both rows and from that HEADS(e+1) give the same verdict, the same send gate and the same line for C_{e+1} ("keys
    rotated after @lee left", no removal line); the "@lee left" line at R1, which the HEADS(e+1) restore holds only
    once its history loads R1, is asserted after each restore's settled `markRead` (round 12, V11CON-6, SPEC §11.9).
    **Equal-time repeat** (round 12, V11ADV-2, SPEC §11.9): lee's engine is logged out after R1 (as in the two-claim
    variant), and R′ is built with `buildMessage` and stored by `world.shard.commit(…, {t: t1, topic})`, as if her
    device had repeated the LEAVE within R1's Δ batch; R′ then replaces the carried source as the kept source of e+1 (a
    real position sorts before NONE), and alice and bob still show exactly one "@lee left" line, at R1, whether R1 or
    R′ reaches them first.
    **Followed-lane variant** (round 10, SPEC §6.8 "The bit without `C_j`", R10ADV-2): G = {alice, bob, lee, mallory}
    in c−1; bob's rename C_{c−1} keeps everyone; lee posts nothing in c, so alice follows lee's lane of c−1, and her
    HEADS(c) lists it at position p; alice's device then writes a snapshot holding EPOCH(c) and that HEADS(c) entry
    (`advanceEra()` after the HEADS(c) row, or more than 200 self records; round 11, V10CON-1: a restore without such a
    snapshot processes C_{c−1} on its way to c and would not exercise the rule); mallory's C_c removes lee with a wrong
    kept entry, so everyone is frozen in c and texts are refused. A LEAVE of lee at p on her lane of c−1 (or, after
    `advanceEra()`, at slot 0 of the new era, where that lane continues), stored after C_c (`buildMessage`: lee's own
    device would not write it), is dropped by bob live and by alice live and after a reload from that snapshot, which
    does not process C_{c−1}: it makes no blob GET of epoch c's bundle (the one C_{c−1} names; D_c and D_{c−1} come
    from the snapshot's DESC records; round 12, V11CON-5: the initial history may still read C_{c−1} at EPOCH(c)'s
    position, which is not processing it). Both keep refusing `sendText`, and the reload writes no LEFT record for
    lee. Variant: a TEXT of lee there is shown by neither, live or after the reload.
32. **A re-added leaver comes back** (READV6-1): bob leaves G; alice rotates him out and later re-adds him (two
    commits). Bob accepts the skip, shows "@alice added you", can send, and puts no LEAVE, live and after a reload;
    alice and carol show him as a member (not left) and need no rotation before their next text.

**Acceptance.** All of `epochs`, `sending`, `privacy` and `flows` (ported from `3de5f5e:test/engine/`) and
`claims.spec.ts` are green in the `engine` project. `npm run test:e2e` is green with the M7 steps of §5 restored
(round 8). Every membership change in the tests waits `Δ + SKEW` = 1 s (`world` Δ = 1, SKEW = 0); every other
protocol delay is shortened through `EngineOptions`. The `engine` project's run time is ≤ 2× that of v1's engine
suite, measured once on the same machine from a `git worktree` of 3de5f5e (round 8).

### M8. Integrity, warnings, scale acceptance (3–4 days; e2e has run on v2 since M6b, round 8)

**Add `src/client/integrity.ts`:**

- checkpoint pin and storage (`localStorage["segv.ckpt"]`), range verification, and the rewrite and rollback warnings;
- the `ck` split-view check, deduplicated per sender;
- the row immutability map;
- `prevh` omission checks;
- receipt verification;
- `EngineState.head` = the checkpoint.

**Tests.**

- Port `sync.spec.ts` (11, from `3de5f5e:test/engine/`; mapping in §3 of this plan).
- New `test/engine/scale.spec.ts`: the O(history) acceptance tests T1–T7 (§4 of this plan).
- New `test/engine/integrity.spec.ts`:
  - the server changes a stored body, or only its `t` or class, after a client saw it → the "changed a stored entry"
    warning (SEC-14);
  - the server returns MISS for a row named by a later row's `prev` → "hiding messages";
  - an omitted middle row (COR-10): the fake hides alice's `(E, 5)` from bob only; bob still shows `(E, 6..)` and warns
    "hiding messages from @alice";
  - an invalid receipt;
  - a changed `srvKey`;
  - a returning device whose checkpoint advanced reports no rollback (replaces #38);
  - equal `q` with a different `C` → "history was rewritten" (CMP-16);
  - `q` jumping 50 000 ahead after 1 h → "history was rewritten"; a stored `at` older than 30 days skips the range
    (SEC-8);
  - split view with `ck16`: a forged reference that matches the first 8 bytes only is still detected (SEC-7).

**E2E.** `test/e2e/run.mjs` has run on v2 since M6b (§5), so M8 needs no flag and no import change; the UI shows
"checkpoint #N" (§0.4) (round 8).

**Acceptance.** The `engine` project is fully green (59 ported from 3de5f5e, the 4 obsolete ones replaced, plus the
new tests), and `npm run test:e2e` is green.

### M9. Documentation and cleanup (1 day; round 8)

v1 was deleted at 8092e98 (§0.1), so there is no cut-over and nothing of v1 is left to delete. M9 does:

**Change.**

- `git rm docs/PROTOCOL.md` (v1), then `git mv docs/PROTOCOL-v2.md docs/PROTOCOL.md`. From this commit on, each
  revision of the spec is copied verbatim to `docs/PROTOCOL.md` (by the implementing session, which owns the
  repository; header, round 10); a later copy to the old name is a mistake (revert it, do not merge it).
  `docs/STAGE1-PLAN.md` stays, under its name, as the plan of record, refreshed the same way.
- Point every reference at the new name: replace `docs/PROTOCOL-v2.md` with `docs/PROTOCOL.md` in every file that
  `git grep -l "PROTOCOL-v2" -- . ':!docs/STAGE1-PLAN.md' ':!docs/PROTOCOL.md'` lists (41 files at c993e83:
  comments in `src/`, `test/` and `wrangler.jsonc`; the comment of `migrations/0001_init.sql`, a comment-only edit that
  wrangler does not track; and the link in `README.md`). In `vite.config.ts`, the `fmt.ignorePatterns` entry
  `"docs/PROTOCOL-v2.md"` and its comment become `"docs/PROTOCOL.md"`; otherwise `vp fmt`/`vp check` reformats or
  flags the verbatim copy.
- `docs/DESIGN.md`:
  - §2 rewritten for LIS (no `segv.sh/v1/` label remains; line 56 shows `PRF("segv.sh/v1/prf")` at c993e83);
  - §3 updated with SPEC §13.2 (every weakening, verbatim in substance) and §13.3;
  - §4 future work becomes SPEC §14.
- `README.md`: link the spec as `docs/PROTOCOL.md` (line 9 at c993e83) and drop the remark that `docs/DESIGN.md` is
  v1 content until M9 (line 10). M6b already updated the status note and the engine and e2e lines (round 9).
- Stale v1 comments: `adapters/cloudflare-workers/vite.config.ts:23` (`LogDO`) and the header of
  `test/worker/api.spec.ts` ("ported … from ../api.spec.ts"), as at c993e83.
- Optionally drop the "stage 1" draft wording in the spec title (in the spec author's copy, then copied).

**Delete.** Nothing. 8092e98 removed LogDO, `d1-index.ts`, the v1 router, wire types, engine, API client, `dh.ts`, the
v1-only exports and tests, the `LOG` binding, `POW_APPEND` and the v1 D1 migrations. `src/server/types.ts` (the DO RPC
types and stub names), `src/client/engine.ts` and `src/client/api.ts` (M6's engine and API client) are v2 and stay.
No DO migration tag and no D1 migration is added: the tag `v1` and `0001_init.sql` are the baseline (§0.5).

**Acceptance** (rounds 8–9).

- The checks of the header and `npm run test:e2e` are green.
- `git grep -l "segv.sh/v1/" -- src test migrations` prints exactly `src/lib/proto.test.ts`, and every match there is
  inside one of the four tests that assert rejection (round 9: cited by name, lines at c993e83): "verifyBundle: the
  signature binds the exact bytes and the v2 label" (885, a v1 bundle signature), "verifyWrap rejects the wrong
  owner, a tampered record and other signature labels" (1239, a v1 wrap signature), "auth binding: a wrap opens only
  with the matching auth and KEM key" (1255, a v1 auth key) and "powPre = H(enc('segv.sh/v2/pow', scope, u32 window,
  digest)), distinct per scope and window" (1891, a v1 PoW prefix). `README.md` and `docs/DESIGN.md` contain no
  `segv.sh/v1/`; `docs/PROTOCOL.md` may, in its comparison with v1.
- `git grep -n -e "/api/log" -e "/api/append" -e "/api/ws" -- src test` prints only the two lines (1864 and 1867 at
  c993e83) of the `test/worker/api.spec.ts` test "other hosts: 421 on /api/v2/*; listed hosts are served", which
  assert that a non-v2 path is refused; `test/e2e/run.mjs` has none since M6b.
- `git grep -n -e "PROTOCOL-v2" -e "LogDO" -- . ':!docs/STAGE1-PLAN.md' ':!docs/PROTOCOL.md'` prints nothing.

### M10 (before M9). Links (2 days)

Link hello is a DD §12.1 client item, so it is part of stage 1. It lands before M9, so that the documentation of M9
describes it, and adds no `Engine` interface change (SPEC §11.11; round 8):

- `src/client/links.ts`: LINK records, `Tlink` subscription, hello write (CAS at the first empty `j`) and read (probe
  up to the first MISS for every era of the link's lifetime), one-shot and expiry handling.
- The engine exposes `createLink(opts?: {oneShot?: boolean}): Promise<string>` and `openLink(url): Promise<string>` as
  internal methods (reachable through `I(e)` in tests). Stage 1 has no UI and no `Engine` method for them; adding them
  later is an additive interface change (Q7).
- **Tests** (`test/engine/links.spec.ts`): a hello CASes the first empty `j` and a racing second hello takes `j+1`;
  Bob finds both by probing; a one-shot link stops after the first valid hello; an expired link (`advanceEra × 5`) is
  not probed; a junk hello row gives a noise warning and no conversation; the joined conversation works both ways.

The order is M0 … M8, M10, M9.

## 2. The engine harness (`test/engine/harness.ts`, `test/engine/fake/*`; built in M5; M6a adds the engine helpers and clocks, M6c and M7 the builders; rounds 8–10)

### 2.1 `FakeWorld` (replaces v1's `FakeServer`)

The fake is `FakeWorld` (`test/engine/fake/world.ts` and its parts in `test/engine/fake/*.ts`, re-exported by
`test/engine/harness.ts`), one object behind `fetch` and `WebSocket`. It decodes binary bodies with the **same**
`src/lib/wire.ts` codecs as the Worker and uses the commitment helpers of `src/lib/proto.ts`, so the fake cannot drift
from the wire format. Per-engine attribution (`shard.hide`, per-user rate limits and request counts) goes through
`world.transport(who)`.

| part | what it fakes | test controls |
| ---- | ------------- | ------------- |
| `clock` | Server time = `Date.now() + offsetMs`, with extra lags for the shard and the inbox (`shardLagMs`, `inboxLagMs`). Params use **Δ = 1, SKEW = 0, inboxSlot = 1**, PoW 0 everywhere, a fixed `srvKey` / `SRV_SK`, `p` computed from the users, and `kcommit`. Every response except the `101` upgrade carries `x-segv-now`. `/era/{E}` answers from the world clock alone (`sealed = now ≥ end(E) + SKEW·1000`), as the Worker does (SPEC §10.9). | `tick(ms)` (round 8): moves the world **and** every engine's monotonic and wall clocks by `ms`, fires the engine timers that fall due and keeps the sockets open; it is what `settle` uses. `advance(ms, {keepSockets?})` moves the server only (a skew against the engines' clocks); `advanceEra(n = 1, {keepSockets?})` moves the server only, to the next era start + 1 s; both close every FakeWebSocket unless `keepSockets`, so engines reconnect and see a new HELLO. Each engine's own clock is `I(e).clock` (§2.2). `shardLagMs`; `inboxLagMs`; `sealDelayMs` (default 0), with `sealPrevious()` |
| `shard` | `Map<"E:label", {t, cls, body}>`. `put` follows SPEC §9.1: OK, CONFLICT with the occupant, WRONG_ERA by `clock` (with early acceptance), BAD; FULL never. `get` returns HIT, MISS(sealed) or NO_ERA. Batches and heads are computed lazily for checkpoints. | `rows()` for attackers and `readableWith`; `commit(E, label, cls, body, {t?, topic?})` without validation (an attacker write; `t` chooses the stored time and `topic` publishes it, as at c993e83; round 12: M7 test 31's equal-time repeat uses both); `hasLabel`; `hide(E, label, forUser)` (omit a row from one engine's gets and realtime frames) and `unhide(E, label, forUser?)` (both at c993e83; round 12 names `unhide` for M7 test 31); `retime(E, label, t)` (serve a different `t`) |
| `blobreg` | Create-only `id → {t, size}` plus the high-water mark; `meta` returns MISS with `now`. | `forceT(id, t)` (forge a late registration); `missNow(fn)` (return `now < t_row` once); `failMeta(id, n)` (`blob/meta` 503 n times) |
| `blobs` | Content-addressed bytes; PUT checks `H = id`, registers, and returns `t`. GETs are `public, immutable` and carry `content-length`, like the Worker's. | `failGet(id, n)` (blob GET 503 n times; `world.blobs`, `test/engine/fake/blobs.ts`; round 10); `staleNow` (cacheable responses, i.e. blob GETs and inbox reads, carry an `x-segv-now` weeks old, as a browser cache would replay it) |
| `inbox` | Per era: rows `{rel, eid, body}`. Jitter from `inboxJitter` (default 0), `rel = max(⌊(ms + j)/1000⌋ + 1, closed_hw + 1)`, `closed = max(⌊ms/1000⌋, closed_hw)`, posts accepted until `end(E)` by the inbox clock and `ended` from `end(E) + SKEW`, batched posts with per-row results, the day cap (`dayCap`, default 2000), 409 `wrong era`, 410 for old eras. | `post(...)` as an attacker; `dayCap`; `rollDay()`; `inboxJitter(fn)`; `wrongEraOnce(reported?)` (round 10, R8-5): each call refuses the next post that passes the Worker's checks with WRONG_ERA, which the Worker answers 409 `{error: "wrong era", era: reported}`; nothing is stored or counted. `reported` defaults to the inbox clock's era, as `InboxDO.post` reports it; mid-era that is the posted era itself, which a real InboxDO never reports, so the engine then waits until `end(E) + SKEW` (SPEC §6.12 step 4). To test the immediate rebuild, pass an era the Worker accepts (M6 test 7) |
| `limits` | Optional per-route rate limits (`RL_INBOX` 10/60 s etc.) answering 429 with `retry-after`. Off by default. | `rateLimits(on)` |
| `rt` | `FakeWebSocket` bound to the world. HELLO (with `seq`) on open; SUB, UNSUB and RESUME by `seq`; ROWS delivered with `setTimeout(0)` to the subscribed sockets only; the ring with `boot`; the topic limits. | `restart()` (new boot, so the next RESUME gets GAP); `wsEnabled`; `dropPublish(pred)` |
| `dir` | `user`, `wrap` and `dirlog` with the validation of M3; prefix queries; `uid`; `wraps/{id}`. | `register(...)` and `postWrap(...)` called directly by tests (as `makeUser` does today), also between two engines' evaluations (SEC-3); `failDir(pred, n)` (prefix lookups answer 503 `{error: "directory unavailable"}` n times, after `RL_READ` and the path and query 400s and before the 409 prefix-bits check, as an isolate without a cached `P` does; an isolate with one can answer 409 first, and SPEC §10.1 orders neither, so a test of the 409 path does not arm `failDir` for that lookup; round 10, R8-6) |
| `ckpt` | `tick()` builds `C_q` from the fake heads and signs it with the test key. | `forkAt(q)` (serve a rewritten chain from q) |
| `requests` | Every request: `{method, path, status, reqBytes, resBytes, putResults[]}`. | used by the scale assertions |
| `hooks` | `beforePut(rows)`, which may await or commit other rows first (replaces `beforeAppend`); `fail(method, path) → 'before' \| 'after' \| null`; `beforeRequest(method, path)` | |

The browser globals (`localStorage`, `location`, `WebSocket`, `fetch` and an always-failing `indexedDB`) are installed
by `installBrowserGlobals()` in `test/engine/harness.ts`, as v1's harness did (`3de5f5e:test/engine/harness.ts:398-429`).

### 2.2 Lifecycle helpers

These are exported by `test/engine/harness.ts`: `freshWorldPerTest`, `newEngine`, `engineFor`, `makeUser`, `view`,
`mustView`, `chat`, `systemLines`, `waitFor`, `sleep`, `localStore`, `server()` (the current `FakeWorld`). M6a replaces
the bodies of `newEngine`, `engineFor`, `settle` and `I`, which throw "needs the v2 engine (milestone M6)" at c993e83,
and adds `conv` and `epoch`.

**`settle(...es)`** is the new definition, because `head.seq` no longer exists. It runs rounds of:

1. Await every engine's `queue` and `sendChains`.
2. `world.ckpt.tick()`. Like the CheckpointDO, it mints a new `q` only when `CKPT_PERIOD_MS` (60 s) of world clock
   have passed since the last one; a test that needs a fresh checkpoint first calls `world.tick(CKPT_PERIOD_MS)`.
   `settle` never calls `ckpt.tick({force: true})` (round 8).
3. `await I(e).catchUp()` for each engine, which includes the inbox poll.
4. Compute `stamp = world.writeCount + Σ I(e).version`, where `version` is a new engine counter, bumped on every
   applied row or record.

It stops when the stamp is unchanged for 2 consecutive rounds, every `I(e).busy === 0`, and the fake inbox holds no
row with `rel > closed` (a posted invite that is not yet visible). `busy` counts in-flight actions and scheduled
protocol timers (the commit wait, parked joins, resume timers, pending HEADS writes); periodic timers
(the 300 s sweep, the inbox poll) are not counted. When `busy > 0` only because of a timer, `settle` calls
`world.tick` up to that timer's due time instead of sleeping (round 8: `tick`, never `advance`, so that the engines'
clocks and the server move together; a commit's wait needs both). The timeout is 60 s.

**Engine options.** `newEngine(who, opts)` passes `EngineOptions` with:

- every protocol delay of SPEC §11 (rotation rank delay, `RESUME_AFTER`, the HEADS delay, the poll and catch-up
  intervals, the 30 s processing wait); tests use 0 or a few milliseconds, except where a test measures the delay;
- the transport (`fetch`, `WebSocket`) from `world.transport(who)`, so every request is attributed to its engine;
- the injectable clock (round 8): a monotonic clock, a wall clock, and the engine's timers, which run on its
  monotonic clock. Each is real time plus offsets: `world.tick(ms)` adds `ms` to every engine's offsets (and the
  world's), `I(e).clock.advance(ms, {mono?, wall?})` moves one engine's clocks (both by default), and
  `I(e).clock.pauseMono()` / `resumeMono()` hold its monotonic clock still while the wall clock and the world run on
  (SPEC §10.1, §11.3 steps 6 and 8);
- the test hook `beforePutAttempt()` (round 8), which `send.ts` awaits after the proof of work and before the
  fresh-probe check of SPEC §11.3 step 6. It models a slow proof of work or a frozen tab: M7 tests 22 (d), 22 (h) and
  30 (b) move clocks there and let other engines commit;
- `inboxWorker?: (() => Promise<Worker | null>) | null` (round 9; typed in round 10): the factory that creates the
  trial-decryption Web Worker (§0.4); absent, the default imports `inbox-worker-url.ts`; the engine tests set the
  option itself to `null` (no worker), so trial decryption runs on the same thread.

**`engineFor(u)`** unlocks, waits for `!syncing`, then settles, as v1's did (`3de5f5e:test/engine/harness.ts`; round 9).

### 2.3 Builders (rewritten; round 9: only `junkRow` exists at c993e83)

M6c adds `signEpoch`, `buildBundleFor`, `forgeJoin` and `buildMessage` (M6 tests 10, 13 and 18, `images.spec.ts`
#61); M7 adds `commitChange`, `buildClaim`, `readableWith` and `entryOutcome` (the M7 tests and the ported §3 rows that
use them).

| builder | does |
| ------- | ---- |
| `signEpoch({conv, e, members, by, prev, name, keyOf?})` | Returns `{EK, keys, D, dsig, hD}`, binary D through `src/lib/proto.ts`. Members are `(uid, sigPk, kh)`; `keyOf(uid)` overrides a member's keys, either one alone (for the fake-key cases: another `sigPk`, or the real `sigPk` with another `kemPk`), and the default is the user's real keys. |
| `buildBundleFor(epochPrev \| null, D, dsig, EK, {pks?, entryOverride?})` | Returns `{blob, id, size}` and uploads and registers it with `world`. Entries follow `rm` (derived from `epochPrev` and D); `entryOverride(i)` replaces one kept entry with a dummy, a fresh-randomness `seal`, or a `sealDet` to another key, for the withholding cases. |
| `commitChange(by, convId, ep, members, name?)` | Async. Exactly what the engine's commit does: bundle, wait `Δ + SKEW`, claim at the first empty `Lctl` slot with real cuts, J by inbox to new members. Replaces `buildChange` and is used for "rename" and the forged commits. |
| `buildClaim(by, ep, {hD, ekc, bundleId, size, cuts, k, E})` | A raw claim row, for the forged and invalid cases. |
| `buildMessage(from, convId, ep, {E, n, prev?}, partial)` | A signed lane row: TEXT, IMAGE, WELCOME, LEAVE, or with a forged `ck`. |
| `forgeJoin(toUser, J, {era?})` | An inbox invite row. Replaces `invitesFor` / `junkInvite`. |
| `junkRow(E, label?, cls?)` (`harness.ts:218`; round 8) | Replaces `junkMessageRow` / `junkInviteRow`. |
| `readableWith(mk)` | Every fake shard row that opens under `mk`, parsed. |
| `entryOutcome(blob, user, e)` | `"EK" \| "none"` for each user. Replaces `inviteRecipients`. |

`I(e)` white-box access changes:

- **Kept:** `account`, `convs` (copies), `queue`, `sendChains`, `imageCache`, `pending`, `fatal`, `generation`,
  `unlock()`, `views()`.
- **New:** `catchUp()`, `version`, `busy`, `clock` (round 8, §2.2), `timeSample` (the clock sample `{s, mid, rtt}` the
  server-time estimate uses; round 9, M6 test 15), `expected` (label → target),
  `laneHead(convId, uid)`, `followed`, `parked`, `requests`, `createLink`, `openLink`, and the epoch introspection (`keys`, `D`, `members`, `myIndex`,
  `frozen` (`"nokey" | "invalid" | null`: one frozen state, with the cause that picks the warning text), `removed`,
  `winner`, `ctlPos`, `rm`), and `members` (MEMBER records).
- **Removed:** `head`, `tags`, `syncNow`.

## 3. Per-test mapping of the 63 engine scenarios (v1 specs at `3de5f5e:test/engine/*.spec.ts`, rewritten into `test/engine/`; round 8)

Verdicts:

- **K** = keep: black-box, only the harness port changes.
- **A** = adapt: same property, new attack construct or assertion.
- **R** = the expected outcome changes because the stage-1 rules change.
- **O** = obsolete, replaced as noted.

| # | spec / test | V | stage-1 equivalent and reason |
| --- | --- | --- | --- |
| 1 | accounts: recovery wrap of attacker's AK under victim's recovery id | K | `world.dir.postWrap` accepts it (ids are public); the exact `dir/wraps/{id}` lookup plus the `auth`-bound seal keep the victim's login correct. |
| 2 | accounts: wrong recovery code refused, creates nothing | K | Replace `head.seq` with "no successful register/wrap/put request in `world.requests`". |
| 3 | accounts: passkey wrap under victim's credId (with and without userHandle) | K | Exact wrap-id lookup kept (SPEC A22). |
| 4 | accounts: registers, code once, both factors unlock | K | Handle check through the `dir/h` prefix. |
| 5 | accounts: lost register response still completes | K | `fail('after')` on `POST /api/v2/register`; the lost-response check uses the handle prefix and compares `bundleBytes`. |
| 6 | accounts: register never reached fails | K | |
| 7 | accounts: definitive rejection forgets passkey | K | |
| 8 | accounts: PRF second ceremony | K | |
| 9 | accounts: second passkey; handle filled in | K | The handle comes from `dir/uid` at unlock. |
| 10 | accounts: "remember" failing without IndexedDB | K | |
| 11 | flows: 1:1 both ways (lines, names, unread, echo) | K | J via inbox; `settle` polls the inbox. |
| 12 | flows: later device sees history; other-device rows advance counter | K | Now exercises restore (self lane CONV_JOIN, last 30) and lane-head probing; A2's send uses the probed head (or a CONFLICT with a sibling row). |
| 13 | flows: unknown handles, empty conversation | K | "unknown: @nobody" through the prefix query. |
| 14 | flows: group messages, "# " names | K | |
| 15 | flows: name sanitisation | K | |
| 16 | flows: add / remove / rename system lines | A | Rename and name removal use `commitChange(alice, …, name)` instead of `buildChange().rows`. The system-line texts are unchanged. |
| 17 | flows: leave, next sender rotates, leaver cannot read on | K | LEAVE on the own lane, and rotation before send (SPEC §6.9). Expect about 1 s per commit. |
| 18–21 | epochs: invite-only epoch from a removed member, e = 7 / 2 / 2^32−2 / 0xffffffff | A | Mallory registers a bundle for a forged D and posts a forged J through `forgeJoin` to alice and bob. Expected outcomes are unchanged: epoch 1, `canSend`, no "mallory added", warnings > 0 (bob may hold an extra ⚠ copy, as in v1, because his copy is unconfirmed), `readableWith(forged.mk) = []`, and a later add works (epoch 2). For 0xffffffff, `parseD` rejects the J, giving a noise warning. |
| 22 | epochs: a member cannot fork the group by skipping the claim slot | A | Carol sends J(e = 1, chained `prev`) to bob only, with no claim. Bob finds no fit, so `mustView(B, id).epoch` stays 0, and bob's message reaches alice. |
| 23 | epochs: legit re-add of a removed member | K | Skip rule (`rm` bit set and a dummy entry, then J at e = 2). `warnings` stays `[]`. |
| 24 | epochs: future member cannot be captured by a forged epoch | A | Planted with `forgeJoin` to dave. The rest is unchanged: 2 ⚠ copies; corroboration by bob clears the real copy's mark; the later junk copy is rejected. Still needed: the stage-1 design draft had no defence for this, and SPEC §6.7 keeps v1's copies rule. Added variants: dave posts in the forged copy before the real add, and the real add is still kept (self never confirms, COR-9); dave is offline while bob posts, and corroboration still happens at restore through request probing (SEC-17). |
| 25 | epochs: removed member posts into two old epochs | A | Mallory writes rows at her lane's next slot in e0 and e1 (after the cuts) with `buildMessage`. Chats are unchanged. The rule is now cut / `t` (SPEC §6.8). |
| 26 | epochs: old-epoch messages before the claim are shown | K | Pre-cut rows are accepted. |
| 27 | epochs: claim with a bad csig freezes membership only | **R** | The claim is not e-valid and is ignored: no removal, epoch 0, `canSend`; a noise warning "ignored an invalid membership change" instead of "can no longer change"; evaluating it makes no `blob/meta` request and no blob GET (SPEC §6.4 "Order of requests"; round 11); then `A.removeMember(mallory)` **succeeds** with its claim at `k = 1`. Junk no longer freezes (SPEC §6.10). |
| 28 | epochs: junk kind-4 row on the claim slot freezes membership | **R** | Junk at `Lctl(E, 0)`: messaging continues, and `A.removeMember(mallory)` succeeds at `k = 1`. |
| 29 | epochs: kind-3 row on the claim slot | O | Rows have no kinds in v2. Covered by #28. |
| 30 | epochs: valid claim whose invites never arrive; messaging continues | A | The v2 analogue is a key withheld from everyone: mallory commits an e-valid claim with a registered bundle whose entries are garbage. Alice, bob and victor are **frozen** (v1 semantics; the warning is v1's text with the signer named: "@mallory's membership change was never delivered to you; …"): victor's message reaches alice; `A.removeMember` throws "can no longer change". Added variant: a claim with an unregistered bundle is ignored, and nothing freezes. The partial case (which now also freezes everyone) is claims.spec #7. |
| 31 | epochs: valid claim honoured; "@bob removed you" | K | The `rm` bit set and a dummy entry (SPEC §5.4, §6.2). Alice's line "@bob removed @victor" comes from `rm`. |
| 32 | epochs: bob leaves, alice adds dave; no invite for bob | A | `entryOutcome` shows bob's entry opens for nobody, and alice's and carol's to EK. Exactly one inbox J, opened by dave only. The rest is unchanged. |
| 33 | epochs: bob leaves, alice removes carol | K | |
| 34 | epochs: a leaver who is explicitly re-added comes back | K | The re-added leaver's state is covered further by claims.spec test 32 (no repeated LEAVE, `left` cleared, SPEC §6.9). |
| 35 | epochs: a leaver not yet rotated out is re-added | K | Two commits, as in v1. |
| 36 | epochs: concurrent rotation after a leave | **R** | `beforePut` holds both control-lane CAS puts (the test computes `Lctl_0` labels from the epoch keys) and releases them together. Expect exactly **one CONFLICT** on the control lane (from `world.requests[].putResults`), one e-valid claim in the prefix, both messages delivered, epoch 1, and B unable to send. The v1 "two kind-4-first batches" assertion becomes "one creation decoy + one claim". |
| 37 | sync: > 4 MiB of junk, short pages; reaches the head | O | There are no pages. Replaced by scale test T1 (junk rows never fetched). |
| 38 | sync: no false rollback after a short page | O | Replaced by integrity test "a returning device whose checkpoint advanced reports no rollback". |
| 39 | sync: transient fetch failure in the first sync is not fatal | A | Fail the first `POST /api/v2/get` (or `GET …/dir/uid`) once. The engine retries and reaches ready, not fatal. |
| 40 | sync: rewritten history at checkpoint; warns in later sessions | A | Pre-seed `localStorage["segv.ckpt"] = {k: srvKey, q: 1, C: random, at: now}`. Expect "history was rewritten", sticky across sessions, whether the fake's latest `q` is 1 (equal-`q` rule) or larger (range rule). |
| 41 | sync: rolled-back log | A | Stored `{q: latest + 10, at: now}` gives "rolled back". |
| 42 | sync: junk invites do not evict the rewrite warning; deduplicated | A | PQ inbox decryption is silent for junk, so the noise source becomes junk rows on watched lane slots ("ignored an undecryptable message"). The critical warning stays first and noise is ≤ 5. |
| 43 | sync: noise warning shows "(×n)" | A | 120 junk rows in mallory's lane prefix give "ignored an undecryptable message (×120)": catch-up fetches the bodies of every slot up to the head (SPEC §11.6). |
| 44 | sync: split view survives a noise flood | A | Bob's row carries `ckq` = a known q with a random `ck16`, giving "split view: @bob …". The flood: junk lane rows, junk control rows, a forged J with a bad dsig, a malformed J. Assertions unchanged. |
| 45 | sync: one insider cannot flood the critical list with split views | A | 30 rows from mallory with different bad `ck` give ≤ 1 split-view line (per-sender dedupe). |
| 46 | sync: each spam invite registers at most members×8+1 tags | A | 120 spam conversations of 32 members via inbox, from a stranger. They become requests (SPEC §11.5): the account writes at most 64 REQUEST records (none that the limit would drop at once) and keeps ≤ 64 live, subscribes no topic for them, probes ≤ 2·m + 3 keys per request per catch-up, writes the joins of one poll in ≤ ⌈64 / 5⌉ = 13 self rows (5 REQUESTs of a 32-member group fit one class-3 row) with the cursor's HEADS in the last of them, and spends ≤ 1 blob GET, ≤ 1 `blob/meta` and ≤ 1 directory request per spam join. |
| 47 | sync: the window slides and exactly 8 are watched | A | After 20 sends, B's expected map holds exactly W = 8 slots for alice's lane in the current era. |
| 48 | privacy: creation batch has the same shape as a change; a message is [4] | **R** | Per `world.requests`, creation, add and remove all produce: one SGB2 PUT, one class-1 self row, exactly one class-1 put ≥ Δ + SKEW after `t_reg` (decoy versus claim), and exactly one class-1 self row at the end (the padded DELIVERED row, SPEC §6.12 step 3). Creation and add then show the batched inbox posts; remove shows none (the documented difference, SPEC §13.2 item 12). Variant (CONS3-1): a creation and an add with 9 and with 31 inbox recipients still end with exactly one class-1 self row. In the 30 s after another member's claim, the other members write no self rows. A text message is one class-0 put. |
| 49 | privacy: creation decoy has a claim's size class (30 members, long name) | A | Decoy class = claim class = 1, and the bundle size is 81248 for both creation and add. |
| 50 | privacy: invite order is shuffled | O | Entry positions are bound to the `D_{e−1}` index, only the owner can open an entry, and J's are separate rows, so order leaks nothing. Replaced by: "a removed member's key opens no entry, and every other member's key opens only its own; groups of 3 and 8 produce equal bundle sizes". |
| 51 | sending: kind-3/4 junk on the victim's next slots | A | Junk at `Lmsg(alice, E, 0..7)`. Alice's 3 sends land at n = 8..10. B's head for alice is `cnt = 11`, and the noise warning shows. |
| 52 | sending: a squat just beyond the window | A | Junk at `(E, 8)`. The 9th send gets a CONFLICT with junk, skips, and all 10 are delivered. |
| 53 | sending: a burst of 40 squats beyond the window | A | **Critical**: junk at `(E, 9..48)`. 12 sends with no error, B receives 12, and alice made ≤ 14 puts (an exists gallop, not a per-slot loop). Replaces v1's dependency on the global `logTags`. |
| 54 | sending: a send racing a removal ends "failed" | A | `beforePut` on carol's message first awaits `commitChange(alice, …, [alice, bob])`. Carol's row is stored after the claim (`t > t(C)`), so its echo is `failed` with "not delivered", A's chat is empty, carol cannot send, and `readableWith(e0.mk)` contains "hi all". |
| 55 | sending: a lost put response leaves exactly one sent message | K | `fail('after')` on `POST /api/v2/put`; the retry gets a CONFLICT with an identical body, so success. |
| 56 | sending: a put that never reached the server is failed; a retry works | K | Probe MISS gives `failed` and "not delivered". |
| 57 | sending: CONFLICT from a sibling device retries with the next counter | K | The occupant is signed by self, so it becomes the head and the device re-signs at n+1. |
| 58 | sending: a send queued before logout does not run under the next account | A | `beforePut` hang. `readableWith(mk0)` now returns parsed binary M, whose `from` is an index, so the assertion maps it through `D_0`. |
| 59 | sending: an add-member in flight across logout is not committed | A | Hold `GET /api/v2/dir/h/…` (handle resolution) instead of `/api/log`. Added variant: log out during the `Δ + SKEW` wait; no claim is written. |
| 60 | images: encrypted round trip | K | |
| 61 | images: web-4 wrong-key reference does not get cached plaintext | A | Build the IMAGE content with `buildMessage`. |
| 62 | images: upload in flight across logout | K | `/api/v2/blob`. |
| 63 | images: image never posted as the next account | K | |

**Totals: K 28, A 27, R 4, O 4.**

The obsolete and outcome-changing tests are replaced by the new specs of M6–M8:

- `restore.spec.ts`
- `claims.spec.ts`
- `integrity.spec.ts`
- `scale.spec.ts`

### 3.1 Worker spec mapping (done in M2–M4; round 8)

v1's `test/worker/log-do.spec.ts` and `api.spec.ts` (3de5f5e) were replaced by `shard-do`, `blobreg-do`, `inbox-do`,
`realtime-do`, `ckpt-do`, `directory` and the v2 `api.spec.ts`, per the M2–M4 lists; v1's outbox tests are obsolete
(there is no outbox). `helpers-unit.spec.ts` is kept (b64, `clientKey`, `logErr`, `clientTag`/`appHosts`); the `wire`
round trips are in `src/lib/wire.test.ts` (round 9).

## 4. Acceptance for the four O(history) problems (`test/engine/scale.spec.ts`)

Every test runs the same scenario twice. In the **clean** world nothing else exists. In the **noise** world the
following is added first through `world` attacker APIs:

- 50 000 random rows over eras `E_now − 3 .. E_now`;
- 2 000 registered users;
- 5 000 inbox rows in eras older than `E_now − 3`;
- 300 inbox rows for others in the current era.

| # | problem | test | pass condition |
| --- | --- | --- | --- |
| T1 | every client downloads the whole log | Alice and bob, a 1:1 with 50 messages, then alice restores on a new device and exchanges 20 more messages. | Excluding `inbox/*` and `ckpt/*` requests (directory requests included): the request count is equal between the worlds, and response bytes differ by ≤ 2%. The measured restore makes no prefix lookup and no `dirlog` read (bob's MEMBER record is in the self lane), only the own `dir/uid` lookup. No request touches a noise row (the fake counts HITs on noise labels: must be 0). Outside the measured part, every directory response holds at most `2 · users / 2^p` bundles for the `p` it asked (the noise world's handles are generated deterministically). |
| T2 | trial-scans every invite | As T1, plus two variants: (a) the day cap filled in all 4 retained eras (up to 56 000 rows, SPEC §9.3) and a returning device whose last cursor is 1 h old; (b) a freshly registered account. | Inbox requests never name an era `< E_now − 3`. Main case: inbox rows fetched in the noise world − clean world = exactly the 300 current-era rows; a second restore after the cursor was written fetches 0 of them. (a): rows fetched ≤ rows posted since the cursor. (b): rows fetched ≤ rows posted since registration. |
| T3 | receives every row over one global WebSocket | Carol and dave, in a conversation alice is not in, exchange 100 messages while alice is connected. | Alice's socket receives 0 ROWS entries whose topic is not in her SUB set; her received bytes are unaffected by carol's traffic. (`realtime-do.spec.ts` also asserts this on the real DO.) |
| T4 | replays full history on every new device or reload | Alice with one conversation holding 2 000 messages, versus the same with 4 000 messages; both with the same compacted self state (300 HEADS overwrites against 3) and a snapshot and HEADS written just before the measured restore. | A restore (unlock to `!syncing`, without `markRead`) makes the same number of requests (±1), and its bytes differ by ≤ 5%; history bodies fetched = `HISTORY_INITIAL` per lane. Without a fresh HEADS, requests ≤ `a + b · log2(rows since the last HEADS)`. With 2 000 self records and no snapshot, the restore writes a snapshot, and the next restore's self-lane probes are ≤ 2 gets. |
| T5 | (bonus) catch-up after offline | Alice offline while 10 000 unrelated rows are written. | Catch-up requests and bytes equal the clean world's. |
| T6 | restore at scale (CMP-14, IMP-10, RC-4) | Alice in 50 groups of 32 members (about 1 000 distinct co-members, in a noise world of 2 000 users), each with 40 recent messages, HEADS and snapshot current. | The restore makes fewer than 600 read requests (one `RL_READ` minute), fetches no bundle for epochs covered by DESC records, and fetches initial history for 20 copies only. **Directory:** exactly one directory request (own `dir/uid`) and no prefix lookup, so directory bytes are independent of the number of users and co-members. Variant: 10 co-members lack MEMBER records; the restore makes ≤ 10 prefix requests (≤ 1 per missing member) and the next restore makes none. |
| T7 | spam requests (SEC-13, IMP-6) | As T4, plus 500 spam joins from strangers before the snapshot. | Restore requests and bytes exceed the clean case by at most `MAX_REQUESTS × (2·32 + 3)` probe keys, with no bundle fetches and no directory requests; no topics are added. Era variant: the same after `advanceEra()`, where each request also probes control and lane slot `(E_now, 0)`, still within that bound. |

`world.requests` records `reqBytes` and `resBytes`, so the assertions are exact and deterministic. Use fixed counts,
not timing.

## 5. E2E (`test/e2e/run.mjs`; rewritten for v2 in M6b, rounds 8–9)

At c993e83 the runner is still v1 and cannot start: its first import, `await import(".../src/lib/proto.ts")` (line
22), fails under Node's type stripping, because `class Rd` in `proto.ts` declares parameter properties (round 9); it
waits for `GET /api/params` (now a 404); its generated config sets `POW_APPEND` and no `ROUTE_KEY`/`SRV_KEY`, so every
`/api/v2/*` call answers 503 (`wrangler dev` reads no `.dev.vars` for a config under `.wrangler/e2e`); and its audit
calls `P.rowHash`, `P.INV_BODY_LENS` and `P.MSG_BODY_LENS`, which `src/lib/proto.ts` no longer exports.

1. **Config** (`e2eConfig()`): `cfg.vars = {...cfg.vars, POW_REGISTER: "10", POW_WRAP: "10", POW_PUT: "8",
   POW_INBOX: "8", POW_BLOB: "8", DELTA_S: "1", SKEW_S: "0", INBOX_SLOT_S: "1", E_FIRST: String(P.era(Date.now())),
   ROUTE_KEY: P.b64u(P.random(32)), SRV_KEY: P.b64u(P.random(32))}`. The existing loop already raises every rate
   limit, `RL_INBOX` included. `startServer()` polls `GET /api/v2/params` until it answers 200.
2. **Flows, by milestone.** The steps keep their intent. Waits for "conversation appears" need ≤ 15 s (inbox slot 1 s +
   poll 2 s + commit 1 s). Assertions name their secrets (`const tGroup = …`) instead of indexing `secrets[i]`,
   because the step set changes per milestone.
   - M6b: CSP and security headers; register three accounts; 1:1 text both ways (bob opens alice's request, which
     accepts it); a group of three, named at creation as at c993e83 (`team ${sfx}`, opened by that name; round 10,
     M6b code), so the audit's team-name needle applies from M6b; reload without "remember", then passkey sign-in restores the texts; a new device by
     recovery code, add a passkey, and a message from device 2 that reaches device 1; "remember this device"; the audit
     (step 3); no page errors.
   - M6c: the image step, the image assertion of the reload step, and a new step: a 1:1 with 100 messages, reload,
     open it, and messages older than the last 30 per lane appear (the `markRead`-on-open change of §0.4).
   - M7: "removing a member cuts them off" and "leaving rotates keys on the next send", as at 8092e98 (both wait for
     "you are no longer a member", which §0.4 keeps for `removed`/`left`), and the new-device assertion of the message
     sent after the leave.
3. **Audit step** (replaces the `/api/log` audit). `run.mjs` imports `src/lib/proto.ts` and `src/lib/wire.ts` under
   Node's type stripping. Make both strippable (round 9: `proto.ts` too): explicit fields instead of the parameter
   properties of `Rd` (`constructor(private readonly b: Bytes, private readonly what: string)`, `src/lib/proto.ts`)
   and `Reader` (`constructor(private readonly b: Bytes)`, `src/lib/wire.ts`), and `import … from "./proto.ts"` in
   `wire.ts` (`allowImportingTsExtensions` permits it). Nothing else in either file is non-erasable, and `proto.ts`
   imports only `@noble/*`. Add a unit test to `src/lib/wire.test.ts` that runs `stripTypeScriptTypes` (`node:module`)
   on both files, so a later parameter property, enum or namespace fails `vp test run` instead of e2e. The audit then
   decodes pages with the shared `decodeFeed` / `decodeInboxRead`; hand-written decoders in `run.mjs` are the
   fallback.
   - Enumerate `GET /api/v2/feed/{E}/0` for every era from the run's start era to `E_now`; verify every batch's root
     (`P.mth` over `P.leafShard`) and the head chain (`P.nextHead`).
   - Require the `shard/{E}/0` head in `/api/v2/ckpt/latest` to occur in the feed's head chain (wait up to 60 s for the
     CheckpointDO's alarm, or expose a test-only tick through an env flag); the feed may hold later batches (SPEC
     §10.9). Every page is decoded with the strict `decodeFeed`, so an incomplete page is rejected (round 9: the
     browser flows never write a batch above 4 MiB, so streamed pages and truncation stay with the Worker test of the
     9 MiB page and the `wire.test.ts` truncation cases).
   - Require every row body length to be in `P.BODY_LENS`.
   - Enumerate `GET /api/v2/inbox/{E}/0`: every body is `P.INBOX_BODY_LEN` (1416 B). Enumerate `GET /api/v2/dirlog`:
     exactly 4 user entries (kind 1).
   - For every row and inbox body, check that no plaintext needle (the secrets, the team name, the handles) appears.
4. **Console errors.** Probes, CONFLICTs and per-invite `conflict`/`full` results are in-band (HTTP 200), and
   `blob/meta` misses are 404, so the existing "no page errors except 404" rule holds. Avoid 409 paths in honest flows:
   the inbox wrong era is retried silently, and the directory prefix bits refresh params first.

## 6. Risks, ranked

1. **Security: undetectable selective omission, forks and directory substitution by the operator** (SPEC §13.2
   items 2–4). This is a deliberate stage-1 weakening, and it MUST be written into `docs/DESIGN.md` §3. Mitigations in
   stage 1: receipts, `ck`, `prevh`, CONTACT and MEMBER pins, descriptor keys, the public feed and dirlog for
   auditors. Inclusion proofs and witnesses come in stage 2.
2. **Schedule: engine rewrite size.** Restore, the self lane, claims and integrity add up to about 2–3× the logic of
   v1's `engine.ts`. Mitigations: the harness first (M5), the minimal end-to-end path first (M6a–M6b) with e2e green
   from M6b on, and porting the 3de5f5e spec files one by one (round 8).
3. **Correctness of claim timing.** The `Δ + SKEW` wait, MISS decisiveness, era sealing and grace, and finality across
   eras. A bug here forks groups. Mitigations: `claims.spec.ts` items 2–4 with fake clocks; the worker tests for the
   BlobReg high-water mark and the ShardDO seal. The same holds for the derived key entries (SPEC §5.4): if two
   implementations derive `sealDet` differently, every honest commit between them freezes the conversation.
   Mitigations: the `sealDet` KAT and the node:crypto cross-check of M1, and claims.spec test 27 (honest commits never
   freeze). On the send side, a row put long after its control probe can land in an epoch every other member has
   already swept (SPEC §11.2); the fresh-probe and late-row rules (SPEC §11.3 steps 6 and 8) bound this, and
   claims.spec tests 21, 22 and 30 drive it with stalled clocks and held puts (including a monotonic clock that
   stops while the system sleeps, which only the wall clock sees: test 22 (h)). Every validity rule must also give the
   same answer in every browser: no parser or D′ check may use Unicode property classes or `normalize` (SPEC §5.1;
   M1 test 10), and every signature check uses the pinned rule of SPEC §1.1 (prime-order keys, cofactored equation;
   never WebCrypto on the client; M1 test 13).
4. **Dense prefixes, multi-device CAS and the self lane.** Duplicate application, `prev` chains across eras, copy
   numbering across devices. Mitigations: `restore.spec.ts`, idempotent record keys, CONFLICT-occupant handling in one
   shared helper used by lanes, the self lane and the control lane.
5. **Latency and UX.**
   - Every commit and creation waits at least 12 s in production (Δ = 10, SKEW = 2).
   - First contact by handle arrives in about 10–20 s.
   - Tests are slower (Δ = 1).

   Tunable through params, with a privacy cost.
6. **DoS on the global inbox (β = 0).** One attacker can hit the 2 000/day cap and delay first contact by handle, and
   adds of members without a 1:1, for everyone, for as long as it refills the cap every day (SPEC §13.2 item 11). A
   device without a cursor trial-decapsulates up to 56 000 invites. Mitigations: PoW `inbox` 18, `RL_INBOX`, batched
   posts, resumable delivery with retry (SPEC §6.12), 1:1 WELCOMEs for known contacts, the cursor in the self lane, and
   trial decryption in a Web Worker. Stage 2 adds β > 0.
7. **Single RealtimeDO.**
   - Its capacity is about 20 000 sockets and 250 000 subscriptions, sized to its 128 MB isolate (SPEC §9.4).
   - Hibernation or a deploy clears the ring, which causes GAP storms (catch-up spikes).
   - API deploys still drop sockets (no separate Worker until stage 2).

   Mitigations: jittered reconnect and the 300 s sweep cadence.
8. **D1 as the authoritative directory.** An outage blocks registration and login, where v1 had a log fallback.
   Dirlog contention under bursts. Mitigations: 16 retries with random back-off, then 503. If contention shows up in
   practice, serialise directory writes through one small DO.
9. **No working app until M6b** (round 8). From 8092e98 until M6b the build shows the placeholder's fatal screen.
   Mitigations: nothing is deployed until then, and M6 is ordered so that M6b (register, 1:1, send, receive, restore)
   comes first.
10. **Privacy against O (the social graph).** Inherent in stage 1. Documented (SPEC §13.2 item 1).
11. **Single-instance capacity** (SPEC §13.2 item 13). One ShardDO per era (10 GB, about 1 000 requests/s per
    object), one current InboxDO polled by every visible client every 10 s (about 10 000 clients at 1 000 requests/s),
    one RealtimeDO and one CheckpointDO. Mitigations: the inbox tail is edge-cached for Δin, immutable reads come from
    `caches.default`, params never reach the CheckpointDO per request, a `logErr` alert at 4 GiB per shard, and an
    emergency S = 2 for the next era (routing by `v` exists). This bounds stage 1 at roughly 10 000–25 000 active
    users; document it in `docs/DESIGN.md` §3.

## 7. Open questions (decide before or while implementing)

| # | question | plan default |
| --- | --- | --- |
| Q1 | DO migrations | Decided at 8092e98: a single tag `v1` with the five classes; later changes add new tags (round 8). |
| Q2 | Production Δ = 10 s and SKEW = 2 s give ≥ 12 s commits. Accept, or use Δ = 5 s (7 s commits, weaker time blurring)? | Δ = 10. |
| Q3 | Should creation wait `Δ + SKEW` and post a decoy, which keeps v1's creation-versus-change indistinguishability, at the price of slower creation? | Wait (SPEC §6.1). |
| Q4 | Inbox client retention of 4 eras, and a global day cap of 2 000 | As in SPEC. |
| Q5 | Implement sending J through a qualifying 1:1 (SHOULD; SPEC §6.12 step 1: the recipient has posted in the 1:1's current epoch and has not left) in M6, or defer it (receiving is a MUST)? | Implement in M6, with creation: it removes most inbox load. A 1:1 that does not qualify, also when the send finds it in a later epoch (SPEC §11.3 step 2), always falls back to the inbox. |
| Q6 | Proactive ranked rotation after a leave (MAY). It would also shorten the window in which a member added by a commit that raced the LEAVE writes texts the leaver's keys can read (SPEC §6.9) | Not implemented. |
| Q7 | Link UI and `Engine` methods (an additive interface change) | The protocol and engine support land in M10, as internal methods with tests. Adding `createLink` / `openLink` to `Engine` and a UI is a user decision after stage 1 (round 8). |
| Q8 | A persisted local cache (IndexedDB) for faster reloads | Deferred; restore is bounded anyway. |
| Q9 | Should "frozen" members get a UI hint beyond the critical warning? | Decided (round 8): `ConversationView.frozen` and `blocked` (§0.3). The composer names the reason, add/remove are hidden when frozen, and a frozen member can still leave. Both frozen warnings name the signer (the never-delivered one is v1's text with the signer added). |
| Q10 | Pending invitations after `createConversation` resolves are invisible in the UI (only a warning on failure). Add a "inviting…" hint? | No: the failure warning suffices and the UI stays minimal (round 8: a new view field would now be allowed). |
| Q11 | Run the late-row check of SPEC §11.3 step 8 after every put, not only after slow ones? It closes SPEC §13.2 item 15 (a member's own devices racing a claim; a malicious back-to-back double commit) at one more `get` per send. | No: only slow puts are checked in stage 1 (SPEC §14). It is a client-only change that can be turned on later without a wire change. |

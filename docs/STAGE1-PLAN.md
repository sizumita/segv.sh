# segv.sh stage 1 (LIS v2): implementation plan

The normative target is `stage1-spec.md`, called **SPEC** below. It becomes `docs/PROTOCOL.md` at the cut-over.
Paths are relative to the repository root. Every milestone lands with `vp check`, `vp test run` (unit + workers +
engine) and `vp build` green. Milestones M8 and M9 also need `npm run test:e2e` green.

## 0. Strategy

### 0.1 Build v2 next to v1, then cut over once

v1 and v2 share almost no wire format. A rewrite in place would leave the tree red for weeks. Instead:

- **Protocol core.** Build it in `src/lib/proto2.ts` (with `src/lib/proto2.test.ts`). It re-exports the unchanged
  encoding and primitives from `src/lib/proto.ts`: `utf8`, `fromUtf8`, `concat`, `u8`–`u64`, `lp`, `enc`, `dec`,
  `b64u`, `fromB64u`, `hex`, `equalBytes`, `trunc16`, `H`, `HKDF`, `HMAC`, `random`, `aeadSeal`, `aeadOpen`,
  `kemKeygen`, `sigPub`, `sign`, `verify`, `pad`, `unpad`, `padme`, `padmeLength`, `leadingZeroBits`, `powCheck`,
  `powSolve`, `formatRecoveryCode`, `parseRecoveryCode`, `newRecoveryCode`, `validName`, `HANDLE_RE`.
  - At the cut-over (M9), `proto2.ts` becomes `proto.ts`, and the v1-only exports and tests are deleted.
- **Server.** Build it in `src/server/v2/`. `src/entry.cloudflare-workers.ts` routes `/api/v2/*` to the v2 handler
  and leaves `/api/*` on v1 until the cut-over.
- **Client.** Build it in `src/client/v2/`. `SegvEngineV2` implements the unchanged `Engine` interface.
  `src/components/real-engine.ts` keeps importing the v1 engine until the cut-over, where one import line changes.
- **Engine tests.** Port them to `test/engine2/`, with a new `FakeWorld` harness, one spec file at a time. The v1
  `test/engine/` stays green until the cut-over, when it is deleted and `test/engine2/` is renamed to `test/engine/`.
- **Worker tests.** New specs go in `test/worker/v2/*.spec.ts`. The v1 specs are deleted at the cut-over.
- **Local data.** Wipe `.wrangler/state` and `.wrangler/e2e` before M2. There is no migration (no users).

### 0.2 Session ownership rule

Everything listed here is inside the repository. The implementing session owns it.

### 0.3 `src/client/types.ts`

**No shape changes.** Only the doc comments change, to state the new meaning:

| field | new comment |
| ----- | ----------- |
| `Phase` `"fatal"` | "unrecoverable (account check failure: account missing from the directory, or keys mismatch)" |
| `MessageView.seq` | "local application order (stable tie-breaker), not a server sequence; 0 for a local echo" |
| `MessageView.ts` | "ms; sender time clamped to the row's public time ± 5 min (SPEC §11.8)" |
| `ConversationView.messages` | "display order (SPEC §11.8); local echoes last" |
| `ConversationView.canSend` | "false once this user was removed or left; a frozen member can still send" |
| `MemberView.handle` | "handle, or `?` + 8 uid characters for a member not (or not validly, or not yet) resolved in the directory (SPEC §11.2)" |
| `EngineState.head` | "latest verified checkpoint: {seq: q, h: b64u(C_q)}" |
| `EngineState.syncing` | "restoring or catching up" |
| `EngineState.connected` | "realtime socket (/api/v2/rt) is open" |

The rest of the contract stays as it is:

- `src/components/state.ts` `initialEngineState` is unchanged (no new fields).
- `src/client/mock-engine.ts` compiles unchanged.
- Warning and error strings stay where the spec keeps them (SPEC §11.9, §6.6, §12). New strings: "@by made an invalid
  membership change; the members of this conversation can no longer change" (critical, frozen as invalid), "@by made
  an invalid membership change that excluded you; waiting for another member to re-send the key" (critical, frozen as
  excluded), "the public keys of @x changed" (critical: a pin mismatch, or a descriptor key that differs from the
  directory), "ignored an invalid membership change" (noise, e-invalid control rows), "@x has not been notified yet;
  retrying" (noise), "the directory answered fewer accounts than expected" (noise).
- `MemberView.handle` is `?` + 8 uid characters for an unknown member (SPEC §11.2), which now also covers a member
  whose key in the descriptor differs from the directory's, and members of an unopened request other than the
  inviter.
- **Semantics that change without a shape change** (document them in the doc comments of `types.ts`):
  - `createConversation` resolves after the bundle upload and the first self row (SPEC §6.1 step 5); invitations
    finish in the background (≥ Δ + SKEW later).
  - `addMembers` / `removeMember` resolve after the switch and the first delivery attempt (SPEC §6.3).
  - `markRead(convId)` is also the "conversation opened" hint: it accepts a request copy and starts scrollback once
    (SPEC §11.10–§11.11), even when `unread` is 0.
  - Links are implemented inside the engine (`createLink`, `openLink`) but are **not** added to `Engine` in stage 1
    (SPEC §11.11; M10).

### 0.4 UI

**One functional UI change is required** (in M6, so that scrollback works after a reload):

- `src/components/conversation.tsx:16-26`: today `markRead(id)` runs only `if (unread > 0 && …)`. After a reload every
  conversation has `unread = 0` (SPEC §11.8), so scrollback (SPEC §11.10) would never start and a device would show at
  most 30 rows per lane. Add a second `useVisibleTask$` that tracks `props.conv.id` and calls `markRead(id)` once each
  time the pane opens (and the page is visible), whatever `unread` is. Keep the existing task for unread changes. The
  v1 engine's `markRead` is a no-op at `unread = 0` (`engine.ts:464`), so this change is safe before the cut-over.
- `src/components/chat.tsx:27-28` shows "log #N" with `head.seq`. That number is now the checkpoint `q`. Optionally
  change the label text to "checkpoint #N" in M9; it is cosmetic.

Behaviours the UI already depends on are kept:

- `createConversation` inserts the conversation into `conversations` before resolving (`app.tsx:72` clears `active`
  otherwise). It now resolves in about one round trip plus the blob upload, not after the ≥ 12 s commit wait.

The CSP (`src/routes/plugin@csp.ts`) needs no change: `/api/v2/rt` is same-origin `ws:`/`wss:`.

### 0.5 Configuration

**`wrangler.jsonc`.** These are added in M2 and kept after the cut-over:

```jsonc
"durable_objects": { "bindings": [
  { "name": "LOG", "class_name": "LogDO" },            // removed in M9
  { "name": "SHARD", "class_name": "ShardDO" },
  { "name": "BLOBREG", "class_name": "BlobRegDO" },
  { "name": "INBOX", "class_name": "InboxDO" },
  { "name": "RT", "class_name": "RealtimeDO" },
  { "name": "CKPT", "class_name": "CheckpointDO" } ] },
"migrations": [
  { "tag": "v1", "new_sqlite_classes": ["LogDO"] },
  { "tag": "v2", "new_sqlite_classes": ["ShardDO", "BlobRegDO", "InboxDO", "RealtimeDO", "CheckpointDO"] },
  { "tag": "v3", "deleted_classes": ["LogDO"] } ],      // added in M9
"ratelimits": [ …RL_WRITE 1001, RL_BLOB 1002, RL_READ 1003,
  { "name": "RL_INBOX", "namespace_id": "1004", "simple": { "limit": 10, "period": 60 } } ],
"vars": { "POW_REGISTER": "20", "POW_WRAP": "18", "POW_PUT": "16", "POW_INBOX": "18", "POW_BLOB": "18",
          "DELTA_S": "10", "SKEW_S": "2", "INBOX_SLOT_S": "10", "E_FIRST": "<era of the first deploy>",
          "APP_HOSTS": "segv.sh,localhost" }
```

- `POW_APPEND` is removed in M9.
- **Secrets.** `ROUTE_KEY` (32 B, b64u) and `SRV_KEY` (32-byte Ed25519 seed, b64u):
  - production: `wrangler secret put`;
  - `vp dev`: `.dev.vars`;
  - when either is missing, the Worker answers 503 "server misconfigured" on `/api/v2/*`.
- **Migrations, open question Q1.** Nothing was ever deployed (the D1 id is all zeros). The plan keeps cumulative
  migrations because they are safe for both fresh and existing local state. If `wrangler deploy --dry-run` rejects
  creating and deleting LogDO in one fresh deploy, collapse to a single `v1` tag listing only the five v2 classes, and
  wipe local state.

**`test/worker/wrangler.test.jsonc`.** Mirror the bindings above, plus:

- `DELTA_S: "1"`, `SKEW_S: "0"`, `INBOX_SLOT_S: "1"`, `E_FIRST: "1"`;
- low PoW: `POW_PUT: "4"`, `POW_INBOX: "4"`;
- fixed test `ROUTE_KEY` and `SRV_KEY` values as `vars`.

**DO class exports.** Export every new class from `src/entry.cloudflare-workers.ts` and from `test/worker/entry.ts`.

**`worker-configuration.d.ts`.** Regenerate it with `wrangler types` (or hand-edit `Env`, lines 4-16) to add:

- the bindings `SHARD`, `BLOBREG`, `INBOX`, `RT`, `CKPT`, `RL_INBOX`;
- the vars `POW_PUT`, `POW_INBOX`, `DELTA_S`, `SKEW_S`, `INBOX_SLOT_S`, `E_FIRST`;
- the secrets `ROUTE_KEY`, `SRV_KEY`.

**D1.** Add `migrations/0003_v2_directory.sql` in M3 with the tables `user`, `wrap` and `dirlog` (SPEC §9.6). They sit
next to v1's `users`, `wraps` and `blobs`; the names are distinct. In M9, add `migrations/0004_drop_v1.sql` that drops
`users`, `wraps` and `blobs`. Alternatively squash everything into a fresh `0001_init.sql` and delete `0002`/`0003`.
Both are acceptable because nothing is deployed; squashing is preferred if local state is wiped anyway.

**`test/e2e/run.mjs`.** It generates its config from `wrangler.jsonc`, so new bindings carry over. Add overrides:

- `DELTA_S = "1"`, `SKEW_S = "0"`, `INBOX_SLOT_S = "1"`;
- `POW_PUT` and `POW_INBOX` low;
- the test secrets as vars;
- the raised rate limits also for `RL_INBOX`;
- `E_FIRST` = the current era.

The `/api/log` audit step is rewritten in M9 (§5.3 of this plan).

### 0.6 New file layout (target after M9)

```
src/lib/proto.ts            (was proto2.ts) v2 core: everything in SPEC §1–§8, §9 commitments, §10.2 PoW, §12 hashes
src/lib/proto.test.ts       node:crypto re-implementation + KATs (rewritten)
src/lib/wire.ts             binary codecs for /put, /get, /inbox, /feed, rt frames (shared by Worker, client, FakeWorld)
src/lib/wire.test.ts
src/server/api.ts           v2 router + handlers (was src/server/v2/api.ts)
src/server/time.ts          era(), sec(), tpub(), params from env (DELTA_S, SKEW_S, INBOX_SLOT_S)
src/server/routing.ts       kroute_E, kcommit_E, v(E,label) → 8-byte BLOB, shard index
src/server/commit.ts        leaf(), MTH(), head chain (also used by tests/auditors)
src/server/shard-do.ts      ShardDO            src/server/blobreg-do.ts  BlobRegDO
src/server/inbox-do.ts      InboxDO            src/server/realtime-do.ts RealtimeDO
src/server/ckpt-do.ts       CheckpointDO       src/server/directory.ts   D1 directory + dirlog
src/server/{http,b64,hosts,abuse,validate}.ts  kept; abuse.ts scopes {register,wrap,put,inbox,blob}; validate.ts v2 shapes
src/client/engine.ts        SegvEngineV2 (thin class wiring the modules below), getEngine()
src/client/api.ts           v2 HTTP + rt client (binary), params/clock offset, PoW
src/client/{accounts,restore,selflane,conv,claims,deliver,send,inbox,integrity,realtime,history,links}.ts   engine modules
src/client/{session,webauthn,image,types,mock-engine}.ts   kept (session aad label → segv.sh/v2/session/<uid>)
deleted: src/server/log-do.ts, src/server/d1-index.ts, src/server/types.ts (v1 wire types), src/client/dh.ts
```

The engine module split is a recommendation: it keeps each file under about 600 lines. A single `engine.ts` is also
acceptable.

## 1. Milestones

Each milestone lists the files to add, change and delete, what it reuses, its tests, and its acceptance criteria.
Every await point added on the client MUST re-check the session (`assertSession(acc, gen)`); this carries over the
engine-11 invariant.

### M0. Groundwork (½ day)

- **Add.** `docs/PROTOCOL-v2.md` (a copy of SPEC, the working reference until M9).
- **Change.** Wipe `.wrangler/state` and `.wrangler/e2e` locally. Optionally fix the stale doc text in `docs/DESIGN.md`
  §2.2 (window 32 → 8, the 256 class): it is rewritten in M9 anyway.
- **Acceptance.** Nothing else changes, and all tests stay green.

### M1. Protocol core v2: `src/lib/proto2.ts`, `src/lib/wire.ts` (2–3 days)

**Add `src/lib/proto2.ts`.** It re-exports the shared primitives (§0.1) and implements the following.

| area | functions | SPEC |
| ---- | --------- | ---- |
| time | `T0_MS`, `ERA_MS`, `era()`, `secOf()`, `tpub(ms, Δ)`, `NONE`, `posCmp()` | §3.1 |
| classes | `CLASSES = [256, 1024, 4096, 16384]`, `BODY_LENS`, `INBOX_BODY_LEN = 1416`, `clsFor(len)` | §3.2 |
| accounts | `deriveIdentity` (v2 labels, no scan key, plus `kS`/`rS`/`nS`); `makeBundle`, `parseBundle`, `verifyBundle` (v2 JSON); `checkUserKeys(sigPk, kemPk)`; `fingerprint` (v2); `pin()`; `credKem`, `recoveryKem` (v2 labels); `makeWrap`, `parseWrap`, `verifyWrap`, `openWrap`, `unwrapAK` (v2 labels, `segv.sh/v2/ak-wrap`); `PRF_INPUT = "segv.sh/v2/prf"`; `hpre()`, `upre()` | §2 |
| sealing | `seal`/`open` with info `segv.sh/v2/seal`; `dummySeal(label, ctx, n)` | §1.4 |
| epochs | `epochKeys(EK, conv, e) → {rk, mk, kc, nk, dk}`, `ekc()`, `Lmsg`, `Lctl`, `topicConv`, `Lself`, `Lsnap`, `topicSelf` | §4 |
| links | `linkKeys(s)`, `Lhello`, `topicLink`, `encodeLink`, `parseLink` | §4.3, §5.5 |
| descriptor | `encodeD`, `parseD` (all §5.1 rules: `(uid, sigPk)` members, small-order key rejection, `validName`, ≤ 1872 B), `hashD`, `signD`, `verifyD` (under D's own key for `by`), `dPrimeChecks(Dnext, De, claim)` (the D′ checks of §6.6 step 4, shared by claim processing and chained joins) | §5.1, §6.6 |
| join | `encodeJ` / `parseJ`; `makeInvite(kemPk, E, bucket, J)` → `{eid, body}`; `tryOpenInvite(kemSk, E, bucket, eid, body)` → J or null (catches decapsulation throws, SPEC §1.1); `makeHello` / `openHello` | §5.2–5.5 |
| SGB2 | `buildBundle({conv, e, D, dsig, EK, prevMembers: (kemPk \| null)[], keep: boolean[], B})` (REMOVED for `keep = false`, a dummy for a `null` kemPk (unknown member) and for padding; `descCt` padded to [2048], 2088 B); `parseBundleBlob` (strict header, `B` from the size: 11640 or 40248); `openEntry(kemSk, conv, e, i, blob)` → `EK \| "removed" \| null` (a throw → null); `openDesc(dk, conv, e, blob)` | §5.4 |
| envelope M | `encodeM` / `parseM` (62-byte header with `ck16`, types 1, 2, 8, 16, 17, 18 (content `u32 e_f`), 19 KEY_OK); `signRow` / `verifyRow` (`segv.sh/v2/msg-sig`, always under the key in D); `sealRow(mk, E, label, M, sig)` / `openRow`; `prevh(label, body)` | §3.3 |
| claims | `encodeClaim` / `parseClaim` (`137 + 6m`, with `rm`), `rmBits(De, Dnext)`, `claimShapeValid(claim, m, from, Estart, E)` (SPEC §6.4(a), (e), (f)), `bundleShapeValid(blob, size, id, m)` (§6.4(h)), `cutBefore(cut, E, n)`, `acceptOldRow(...)` (the §6.8 walk as a pure function) | §6.2, §6.4, §6.8 |
| self lane | `encodeS` / `parseS`, a record codec for every rtype (CONV_JOIN, EPOCH, EPOCH_PENDING with `t_reg`, LEAVE, CONTACT, LINK, PREFS, partial HEADS with followed lanes, CONFIRMED, DELIVERED, REQUEST, DESC, MEMBER, SNAP; unknown rtypes are skipped, known ones parsed strictly), `sealSelf` / `openSelf` (with the forced class-1 padding for EPOCH_PENDING rows), `encodeSnapshot` / `parseSnapshot`, `encryptBlob` / `decryptBlob` with the v2 labels (`segv.sh/v2/blob`, `segv.sh/v2/snapshot`) | §7, §8.1 |
| commitments | `leafShard`, `leafInbox`, `leafBlob`, `mth(leafHashes)`, `nextHead(cid, head, t, n, root)`, `ckptHd(heads)`, `ckptC(prevC, q, sec, hd)`, `ckptSigMsg`, `receiptMsg`, `dirlogRef`, `dirlogH` | §9, §12 |
| PoW | `PowScope = 'register' \| 'wrap' \| 'put' \| 'inbox' \| 'blob'`; `powDifficulty` (unit 4 KiB for put and inbox); `powPre` with `segv.sh/v2/pow` | §10.2 |
| directory | `prefixRange(p, x)` → `{lo, hi}` with arithmetic (no shifts); `clientP(P, dirSeq)` | §9.6, §10.6 |

**Add `src/lib/wire.ts`.** Encoders and decoders for:

- the put request and response, and the get request and response (SPEC §10.3–10.4);
- the inbox post (1..32 invites) and read (SPEC §10.5);
- the feed (SPEC §10.9);
- the rt frames SUB, UNSUB, RESUME (by `seq`), HELLO (with `seq`), ROWS (per-row `seq`), GAP and RESUMED (SPEC §10.8).

Every decoder is strict: exact lengths, enums, counts within limits, and no trailing bytes.

**Reuse.** The `proto.ts` encoding and primitives, unchanged. The style of `proto.test.ts` (an independent node:crypto
re-implementation, then cross-checks).

**Tests.** `src/lib/proto2.test.ts` and `src/lib/wire.test.ts`:

1. Re-implement every v2 construct with node:crypto plus noble ML-KEM only where unavoidable, and compare with proto2:
   - the label derivations;
   - `encodeM`, D and J;
   - the inbox body and SGB2 lengths: 1416, 11640, 40248; a maximal D (32 members, a 64-code-point 4-byte name) is
     1872 B and `D ‖ dsig` fits the [2048] descriptor class;
   - the entry for REMOVED versus EK;
   - claims, S and S2;
   - the commitments (an RFC 6962 MTH test vector: 1, 2, 3, 5 and 7 leaves);
   - the checkpoint chain and the dirlog chain.
2. **KATs**, fixed with deterministic randomness through an injectable RNG in test mode (as v1 does): every label,
   `epochKeys`, `Lmsg`/`Lctl`/`Lself`/`Lsnap`/`Lhello`, topics, `encodeD`, `encodeJ`, the invite body, the bundle,
   `encodeM` + sig, the claim, the self row, the snapshot, the receipt message, `ckptC`, `hpre`, `upre`, the
   fingerprint and `pin`.
3. **Tamper and bit-flip tests.** Flipping any byte of a row body, the label (AAD), `E` (AAD), `conv` or `e`
   (signature) makes the row fail to open or verify.
4. **Parser fuzzing.** Random truncations and extensions are rejected; unknown types and enums are rejected; an
   unknown self `rtype` is skipped.
5. **Era math.** Boundaries at `T0`, `T0 + ERA_MS − 1` and `T0 + ERA_MS`; `tpub` for Δ ∈ {1, 10}; `posCmp` with NONE.
6. **Class selection.** A 129-byte text lands in class 0 and a 130-byte one in class 1; 897 and 898 bytes split
   classes 1 and 2. A 12000-byte text lands in class 3. Claims for m = 1 and m = 32 land in class 1. A self row with
   an EPOCH_PENDING for `a = 0` is class 1.
7. **SGB2.** A member kept at index i opens EK; a removed member opens "removed"; a padding entry and an unknown
   member's dummy entry open for nobody; a random key returns null. `bundleShapeValid` rejects each failure
   separately: a size outside {11640, 40248}, a hash mismatch, a bad magic, version or `B`, and `B < m`.
8. **Inbox trial decryption.** The recipient opens it; another key returns null without throwing.
9. **Throwing decapsulation** (SPEC §1.1). A ciphertext whose X25519 component is a low-order point makes
   `tryOpenInvite`, `openEntry`, `openHello` and `openWrap` return null (or "does not open"), for every recipient key.
10. **Claims.** `rm` bits round-trip; `claimShapeValid` rejects a bit at or above m, the committer's own bit, and cuts
    outside `[E_start, E]`. `acceptOldRow` matches a table of cases: a low cut, a high cut, `t_R` equal to `t(C)`
    before and after the cut, a later claim that removes the sender, and a frozen reader. `dPrimeChecks` rejects each
    failure separately: `hD`, `conv`, `e`, `prev`, `by`, `dsig′` under the `D_e` key, `D′ ∩ D_e` ≠ the `rm`-kept set,
    and a continuing member whose `sigPk` changed; `parseD` rejects a small-order `sigPk` and duplicate uids.
11. **Directory prefixes.** `prefixRange` for p = 0, 1, 31 and 32 and x at both ends; `clientP` bounds by `dirSeq`.
12. **Descriptor keys.** `verifyRow` and `verifyD` take the key from D only (no directory argument exists in the
    API); a D listing a uid with a key other than the uid's bundle key still verifies rows signed by the listed key.

**Acceptance.** The unit project is green, the v1 tests are untouched, `vp check` is green, and `proto2.ts` has no DOM
or Workers APIs.

### M2. Storage Durable Objects (3–4 days)

**Add.**

- `src/server/v2/time.ts`, `routing.ts`, `commit.ts` (or import the commitments from proto2).
- `src/server/v2/shard-do.ts` (SPEC §9.1), `blobreg-do.ts` (§9.2), `inbox-do.ts` (§9.3), `realtime-do.ts` (§9.4) and
  `ckpt-do.ts` (§9.5). The CheckpointDO's dirlog head reads D1. Until M3 creates the table, it uses ZERO32 when the
  table is missing.
- Export the classes from `src/entry.cloudflare-workers.ts` and `test/worker/entry.ts`.

**Change.** `wrangler.jsonc`, `test/worker/wrangler.test.jsonc`, `worker-configuration.d.ts` (§0.5 of this plan).

**Reuse.**

- From `src/server/log-do.ts`, for `realtime-do.ts`:
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

**Tests** (`test/worker/v2/*.spec.ts`).

`shard-do.spec.ts`:

- In a CAS race of two `put` calls on the same label, the first wins and the second gets CONFLICT with the first body.
- BAD lengths. A duplicate inside one put.
- WRONG_ERA: a DO of a past era (`E_now − 1`, with the clock past `end`) and a future era.
- `MISS(sealed = 0)` before the seal alarm and `MISS(sealed = 1)` after `runDurableObjectAlarm`. A put after the seal
  gets WRONG_ERA.
- Batch close: the head chain recomputed with `proto2.nextHead` over `feed()` output matches `head()`. This also holds
  after `evictDurableObject`, with nothing lost.
- `feed` pagination never splits a batch.
- With a clock stepping back, `t` never decreases (`last_t`).
- Close a batch through the alarm, step the clock back by SKEW, and put: the row gets `t = closed_t + Δ`, `closeBatch`
  never sees a duplicate `t`, and the head chain recomputes from `feed()` (IMP-7).
- Early acceptance: with the clock at `start(E) − SKEW·1000 + 1`, `shard/E` accepts with `t = sec(start(E))`; at
  `start(E) − SKEW·1000 − 1` it answers WRONG_ERA. With two DOs whose clocks differ by SKEW, a write at the boundary is
  accepted by at least one of them.
- The DO reads `(E, i)` from `ctx.id.name`; a constructor wake with a pending batch alarm keeps the earlier alarm.

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
- `ended` is persisted at `end(E) + SKEW`; posts after it get WRONG_ERA; the final `closed` is the maximum `rel`.
- A post of 32 invites returns 32 results; the day cap turns the rows past the cap into `full` while earlier rows
  succeed.
- Whole rel groups per page. The eid-idempotent retry. `conflict` on a reused eid. WRONG_ERA. Slot commitments.

`realtime-do.spec.ts`:

- HELLO on connect. SUB, then a publish to two topics: the socket receives only its topic.
- UNSUB. RESUME with the current boot replays ring rows newer than `since` and sends RESUMED. RESUME with a stale boot,
  or `since` older than the ring, gets GAP.
- RESUME by `seq`: two rows published in the same millisecond are both replayed; a RESUME answered with GAP still
  installs its topics.
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
- A failing component keeps its previous head.
- The blob registry head changes in checkpoints at most once per hour, even when blobs are registered every minute.
- The alarm is armed from the constructor; calling `ensure()` repeatedly makes no extra writes.

**Acceptance.** All new worker specs are green, the v1 specs are green, and the DO classes deploy in `vp build`.

### M3. D1 directory (2 days)

**Add.**

- `migrations/0003_v2_directory.sql`.
- `src/server/v2/directory.ts`:
  - `register(env, bundle, sig, wraps)` and `addWrap(env, record, sig)`, using one D1 `batch()` with explicit dirlog
    seqs (plus the `dirmeta.users` increment) and up to 16 optimistic retries with random back-off;
  - error mapping: `user.handle` or `user.uid` → 409, `dirlog.seq` → retry, anything else → 503;
  - `byPrefix(kind, p, x, after)` with `BETWEEN lo AND hi` from `proto2.prefixRange` (never shifts), `byUid(uid)`,
    `wrapsById(id, uid?)` (≤ 64 by dirseq), `dirlog(after, limit)`, `currentP()` (cached 60 s from
    `dirmeta.users`, never `count(*)`).
- `src/server/v2/validate.ts`: `checkBundleShapeV2` and `checkRecordShapeV2`, adapting the canonical-JSON checks of
  `src/server/validate.ts`.

**Reuse.** `validate.ts` (`canonical`, `MAX_SIGNED_TEXT`, the signature helpers) and `http.ts` (`ed25519Verify`).

**Tests** (`test/worker/v2/directory.spec.ts`):

- Register is atomic (user + wraps + dirlog).
- 409 on a taken handle or uid, and nothing is written.
- 400 cases ported from `api.spec.ts` "POST /api/register" (bad signature, foreign wrap, malformed bodies, 413).
- `addWrap`: 404 for an unknown uid, 400 for a bad signature, the 64-per-uid cap, and 409 for a duplicate `(uid, id)`.
- Prefix queries: any `p ≤ P + 1` is accepted (409 with `P` above), p = 0, 1 and 32 return exactly the matching rows,
  the query plan uses `user_hpre` (`EXPLAIN QUERY PLAN`), paging with `after`, and verification of the returned
  bundles.
- `wrapsById` is oldest first, filters by `uid`, and returns an empty list for unknown ids.
- 8 concurrent registrations all succeed, and the dirlog chain recomputes from `dirlogH` without gaps;
  `dirmeta.users` equals the number of users.
- A failing D1 (a proxy swapped in `env.DB`, as in `log-do.spec.ts`) gives 503.

**Acceptance.** Green.

### M4. HTTP and WebSocket API v2 (3 days)

**Add `src/server/v2/api.ts`**, with `handleApiV2(request, env, ctx, url)` and these routes:

| route | notes |
| ----- | ----- |
| every route | `x-segv-now` on every response, stamped in `finalize` on the response actually returned (after any `caches.default` lookup), and deleted from the copy given to `cache.put` (SPEC §9.7, §10.1); the era bounds of SPEC §9.7 before any DO call; `caches.default` before the rate limiter for immutable responses and the inbox tail. |
| `GET /api/v2/params` | Calls `CKPT.ensure()` at most once per isolate (a module-level flag), never per request (the DO also arms itself in its constructor). |
| `GET /api/v2/era/{E}` | No `kroute` (SPEC §10.9). |
| `POST /api/v2/put` | Body ≤ 263 345 B. Grouped ShardDO RPCs (`getByName`), receipts signed with `SRV_KEY` (WebCrypto Ed25519 or noble), and `waitUntil(RT.publish(okRowsWithTopic))` with one retry. |
| `POST /api/v2/get` | Grouped RPCs, the 4 MiB body budget, then SKIPPED. |
| `POST /api/v2/inbox`, `GET /api/v2/inbox/{E}/{bucket}` | Posts of 1..32 invites with per-row results; 410 for `E < E_now − 3`; `public, max-age=Δin` for the current era (served from `caches.default`); immutable only after the InboxDO reports `ended`. |
| `PUT /api/v2/blob/{id}`, `GET /api/v2/blob/{id}`, `GET /api/v2/blob/{id}/meta` | Blob GETs served from `caches.default` when present. |
| `GET /api/v2/rt` | |
| `GET /api/v2/ckpt/latest`, `/ckpt/{q}`, `/ckpt/range` | |
| `GET /api/v2/feed/{E}/{i}` | |
| directory routes | §10.6 |

**Change.**

- `src/entry.cloudflare-workers.ts` (and `test/worker/entry.ts`): `/api/v2/` goes to `handleApiV2`, and everything
  else under `/api/` goes to `handleApi` (v1) until M9.
- `src/server/abuse.ts`: `PowScope` from proto2, and the `POW_DEFAULTS`/`POW_VARS` entries for `put` and `inbox`.
  Keep `append` until M9.
- `routeLabel`: v2 path labels that redact ids, handles, prefixes and eras.

**Reuse from `src/server/api.ts`:**

- `putBlob`/`getBlob`, almost verbatim (streaming R2 put with `sha256`, the header set). Insert `BLOBREG.meta()` before
  the R2 head check and `BLOBREG.register()` after the put. Delete `recordBlob`.
- `ws()` becomes `rt()`: the Origin check, the opaque client tag (the key now lives in RealtimeDO `wsTagKey`), and the
  minimal forwarded request.
- `methods`, `HttpError` handling, `finalize`, `readBody`, `exactKeys`, `intParam`, `rl()`, `rateLimit`, `checkPow`.

**Tests** (`test/worker/v2/api.spec.ts`; port `test/worker/api.spec.ts` section by section):

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
| (new) server time | every v2 response carries `x-segv-now`; a blob GET served twice (the second from `caches.default`, where the runtime has it) carries a fresh value the second time, and the entry stored in `caches.default` has no `x-segv-now` (inspect it with `caches.default.match` in the test) |
| (new) params | 100 params requests make at most one `ensure()` call |

Also add `helpers.ts` v2 helpers: `putRows`, `getKeys`, `makeAccountV2`, `registerOkV2`, `openRt`, and the binary
codecs from `src/lib/wire.ts`.

**Acceptance.** v1 and v2 worker specs are green. `curl` against `vp dev` shows the v2 routes working.

### M5. FakeWorld engine harness (2 days)

**Add `test/engine2/harness.ts`**, described in §2.1 of this plan, and `test/engine2/harness.spec.ts`, which
self-tests the fake against the same `src/lib/wire.ts` codecs and the semantics of SPEC §9–10:

- CAS and CONFLICT;
- WRONG_ERA after `world.advanceEra()`, and early acceptance within SKEW;
- sealing;
- the inbox closed slot, `rel = ⌊(ms + j)/D⌋ + 1`, `closed_hw`, batched posts and per-row `full`;
- blob meta high-water;
- rt RESUME by `seq` and GAP;
- the rate-limit knob (429 with `retry-after`);
- `x-segv-now` on every response, with `cache-control` as the Worker sets it, and the `staleNow` knob (§2.1);
- separate clocks for the shard and BlobReg (`world.shardLagMs`).

**Change `vite.config.ts`.** Add an `engine2` test project (same settings as `engine`, `include:
["test/engine2/**/*.spec.ts"]`). M9 removes `engine` and renames this one.

**Acceptance.** `harness.spec.ts` is green, and the engine project is untouched.

### M6. Engine v2: accounts, restore, 1:1 and group messaging, images (5–7 days)

**Add `src/client/v2/`**, implementing SPEC §11:

| file | contents |
| ---- | -------- |
| `api.ts` | Binary put, get, inbox, feed and rt clients; JSON params, directory and ckpt. Params cache (5 min) and `clockOffset`, updated from `x-segv-now` only on `no-store` responses (SPEC §10.1); `serverNowMs()`. `postPow` reused from `src/client/api.ts` with scopes `put`/`inbox`. `ApiError` kept. |
| `realtime.ts` | The socket with SUB, UNSUB and RESUME, the topic set, backoff + jitter, ping every 30 s; emits rows, GAP and connection state. |
| `accounts.ts` | register, login, recovery, addPasskey, `unwrapFrom`. Ported from `engine.ts:180-300` and `497-523`, with v2 lookups: the handle check through `dir/h` plus local filtering; the lost-response check by comparing the handle-prefix result with our bundle. |
| `selflane.ts` | Record fold (including the CONFIRMED check on CONV_JOIN and the REQUEST bound), CAS writes with batching, no sibling wait, the durability order of SPEC §7.3, snapshot write and read (original record order), partial HEADS. |
| `restore.ts` | SPEC §11.4. |
| `conv.ts` | Copies, epochs, D from DESC records or the bundle (signatures always under the keys in D), unknown members and MEMBER records (handles only), J acceptance (§6.7 incl. parking, the D′ checks for chained joins, the `D.by` key check for skip and first contact, copies, ⚠, confirmed without self), lanes with dense prefixes, processed positions, followed lanes (`run(s)`, `f(s)`, SPEC §11.2), the sweep of old-epoch lanes before they leave the expected-label map, the §6.8 acceptance walk, system lines, views. |
| `deliver.ts` | The J delivery queue of SPEC §6.12 (WELCOME only in a 1:1 where the recipient has posted in the current epoch and has not left, otherwise batched inbox; DELIVERED records, retry, resume per §6.11). |
| `send.ts` | SPEC §11.3, including CONFLICT handling and junk galloping. |
| `inbox.ts` | Poll with the era clamp and per-era `after` (SPEC §11.5), trial decryption in a Web Worker, parked joins, request copies and their transitions. |
| `history.ts` | Initial history for the 20 most recent copies, scrollback to 500 on the first `markRead` per copy, era-crossing probes (SPEC §11.10). |
| `engine.ts` | `SegvEngineV2 implements Engine`: state, emit throttling, warnings (critical and noise), `logout`, the generation guards. |

M6 implements **creation** (SPEC §6.1: blob first, then CONV_JOIN + EPOCH_PENDING(e = 0) in one class-1 self row,
the wait, the decoy, J via a 1:1 WELCOME or batched inbox invites, DELIVERED records) and the J delivery queue with
retry and resume (§6.11–§6.12), but not yet claims. It also implements:

- the clock offset from `x-segv-now` on every response (`api.ts`), and the monotonic commit wait;
- the engine options object (`EngineOptions`, test-only) for every protocol delay of SPEC §11 and an injectable
  clock;
- restore by processed positions (HEADS, trusted), DESC records, `P0 = 2` probes, bodies from the processed position to
  the head in **every epoch since the HEADS epoch** (SPEC §11.4), MEMBER records instead of directory lookups for
  known members, initial history for the 20 most recent copies, and 429 back-off;
- request copies (REQUEST records, cheap probing, no subscription, the transitions of SPEC §11.5);
- CONTACT and MEMBER records in the HEADS row (a request's `D.by` MEMBER in the REQUEST's row), HEADS at most every
  30 minutes and right after registration, and the durability order of SPEC §7.3;
- `markRead` as the open hint (scrollback once, request acceptance) and the UI change of §0.4 of this plan;
- trial decryption in a Web Worker (with a same-thread fallback for tests).

**Reuse.**

- From `src/client/engine.ts`: `authFlow`, `remember`, `assertSession`, `warn`/`die`/`patch`/`scheduleEmit`/`emitNow`,
  `views()`, `cleanName`, `resolveHandles` (now asynchronous through prefixes), `addEcho`/`markEcho`, the
  `sendChains` serialisation, `loadImage` + `imageCache`, and the image path of `sendImage`.
- Unchanged: `src/client/image.ts`, `webauthn.ts`, `session.ts` (change the aad label to `segv.sh/v2/session/<uid>`).
- Delete in M9: `src/client/dh.ts` (the scan key is gone).

**Tests.** Port these spec files to `test/engine2/` (mapping in §3 of this plan): `accounts.spec.ts` (10),
`images.spec.ts` (4), and from `flows.spec.ts` the tests "1:1 both ways", "later device", "unknown handles",
"group # names" and "name sanitisation" (5). New tests in `test/engine2/restore.spec.ts`:

1. A reload restores conversations from the self lane without a snapshot, then a snapshot is written and the next
   restore uses it.
2. Two devices write self records concurrently: both are applied once, and copy numbering is equal on both, also when
   one restores from a snapshot and the other from the lane (COR-25).
3. An era rollover during a session (`world.advanceEra()`): sends go to `(E+1, 0)` with `prev` pointing into E, and the
   receivers follow. Two devices write `(E, 6)` and `(E+1, 0)` of one lane around the boundary: restore and scrollback
   show both (COR-21).
4. A restore after `advanceEra() × 3` with idle lanes probes one key per idle era, and a catch-up 10 eras later probes
   at most `W + 1` keys per idle lane (CMP-15).
5. `createConversation` resolves with the conversation present in `conversations`, before the commit wait ends.
6. **Creation crash** (COR-6, IMP-3, CMP-2): the creator logs out during the Δ + SKEW wait; a second device of the
   creator delivers J after `RESUME_AFTER` (knob), and the invitee holds the conversation. A creator whose engine is
   aborted before the PUT leaves no copy.
7. **Delivery under limits** (COR-7, IMP-2, CMP-3): with the FakeWorld rate limiter on (10 inbox posts per 60 s) and the
   day cap at 5, a 32-member creation with strangers sends one batched post; the rows past the cap retry after the
   fake day rolls over, with the "has not been notified yet" warning; every invitee joins.
8. **WELCOME beyond the window** (SEC-11, COR-5): dave has posted in his 1:1 with alice (so it qualifies, SPEC §6.12)
   and goes offline; alice adds him to G (WELCOME in their 1:1) and then sends 40 texts in the 1:1; dave unlocks and
   holds G. Variant: dave never posted in the 1:1, so alice's J goes by inbox, and dave still holds G.
9. **Inbox cursor** (CMP-4, COR-19): a device that polled 1 h ago restores and fetches only the inbox rows since; a
   join whose CONV_JOIN write fails is not passed by the persisted cursor.
10. **Requests** (SEC-13, SEC-17, CMP-5, COR-16, CMP-12): a stranger's group with carol offline; alice and bob post;
    carol restores with the realtime fake disabled and sees both; opening the copy (`markRead`) accepts it. 100 spam
    joins cost ≤ 1 blob GET and ≤ 1 directory request each, keep ≤ 64 REQUESTs, add no topics, and leave the next
    restore's requests within the budget, with no directory request for them (each REQUEST's row carries the MEMBER
    of its `D.by`). The request's other members show as `?…` until carol opens it.
11. **HEADS splitting** (CMP-13): an account with 200 copies writes HEADS across several rows and restores from it.
12. **Scrollback after reload** (IMP-1, CMP-6): a reloaded engine calls `markRead` on a 1:1 with 100 messages and
    shows more than 60.
13. **Unknown members** (SEC-3, RC-1): a conversation that lists an unregistered uid U (with a key mallory holds) is
    joined; U shows as `?…`, and U's rows verify under the key in D and are shown at once, under `?…`. After
    `world.dir.register(U)` with that key, the next restore shows U's handle and writes a MEMBER. Variant: D lists
    bob's uid with mallory's key; alice shows that member as `?…` (never `@bob`) and raises "the public keys of @bob
    changed", while bob himself rejects the join with a noise warning (D does not list him with his own key).
14. **MEMBER records** (RC-4): alice is in 5 groups with 30 distinct co-members (all in different prefixes at the test
    `p`); after a snapshot, a reload makes exactly one directory request (`dir/uid` for herself), no prefix lookup and
    no `dirlog` read. Variant: the HEADS row carrying the MEMBER records was never written (crash), so the first reload
    makes ≤ 30 prefix requests, writes the MEMBERs, and the second reload makes none.
15. **Stale server time** (RC-9): with FakeWorld `staleNow` on, blob GETs and inbox reads (both `public`) carry an
    `x-segv-now` three weeks old. After loading an image and polling the inbox, the engine's server-time estimate is
    unchanged (within the test clock's resolution), the next send picks the current era without a WRONG_ERA, and PoW
    windows are accepted.

**Acceptance.** The listed specs are green in `engine2`, and the v1 engine specs are still green.

### M7. Membership: control lane, claims, cuts, leave, copies (5–7 days)

**Add / extend `src/client/v2/claims.ts`:**

- control-lane probing and dense prefixes;
- three-valued e-validity (a)–(h): `rm` and cut bounds, the bundle fetch and shape, the BlobReg MISS decisiveness, and
  undecided results for network errors;
- the winner (every earlier slot decided) and finality across eras (sealed observations or own HEADS);
- `processWinningClaim`: `rm`-based removal, the three freezes (withheld, excluded, invalid; no skipping), the D′
  checks (`proto2.dPrimeChecks`, also used for chained joins), accept, system lines from `rm`, the sweep of the old
  epoch's lanes, followed lanes (`f(s)`), NEED_KEY with `e_f` on every lane of the own run, KEY_OK after a freeze ends,
  and re-delivery (ranks 0–2 by recent activity, the KEY_OK / later-row hold-back, DELIVERED records, no lane
  position recorded past a pending re-delivery);
- the commit procedure of SPEC §6.3: blob first, EPOCH_PENDING, the monotonic + server-time wait, the re-check, the CAS
  loop with every outcome (identical occupant, undecided occupant, `t ≤ t_reg`, WRONG_ERA, network), the decide step,
  the switch, J delivery and DELIVERED records;
- EPOCH_PENDING recovery for e ≥ 1 (keyed by bundleId);
- parking of joins that arrive before their claim is settled, and leavers / removed members following their last
  control lane;
- the old-epoch acceptance walk of §6.8 (by `t` and `rm`), with deterministic retraction;
- leave, plus the rotation-before-send of §6.9 (skipped when frozen);
- `addMembers` / `removeMember` with the leaver handling ported from `engine.ts:396-438`.

**Tests.** Port `flows.spec.ts` "add/remove/rename" and "leave", all of `epochs.spec.ts` (19), `sending.spec.ts` (9)
and `privacy.spec.ts` (3). New tests in `test/engine2/claims.spec.ts`:

1. The first e-valid claim wins over a later one at k+1. Junk at `(E, 0)` is skipped with the noise warning.
2. A claim whose bundle is registered after the claim's `t` (forged with a fake BlobReg timestamp hook) is e-invalid
   for every member.
3. A MISS within SKEW is retried, not decided (the fake reports `now < t_row` once).
4. A claim written while the previous era is unsealed becomes final only after `world.sealPrevious()`. A claim placed
   in the old era's prefix before the seal wins over the new-era claim.
5. **Invalid D′ freezes everyone** (SEC-2, RC-2): mallory's e-valid claim has valid entries and garbage `descCt`; a
   later honest claim at k+1 is not used; every member is frozen with "@mallory made an invalid membership change";
   messaging in e continues. Variant (RC-2): D′ decrypts but has a wrong `prev`; mallory then sends J(e+1) of that D′
   (same EK′ and bundleId) to every member by inbox and by WELCOME; every member stays frozen as invalid in e
   (`mustView(X, id).epoch` unchanged) and writes no EPOCH record.
6. **Split withholding plus invalid D′** (SEC-2, COR-3b, RC-2): entries open for alice and bob, garbage for carol, and
   D′ is invalid; all three agree on the winner (`I(e).winner` equal) and are frozen; nobody reaches e+1. Variant:
   mallory sends J(e+1) of the invalid D′ to all three; alice and bob stay frozen, carol switches from withheld to
   invalid (warning text changes), and nobody reaches e+1.
7. **Partial withholding** (SEC-4, COR-4, CMP-7, RC-8): mallory withholds bob's entry only. Bob freezes and posts
   NEED_KEY (content `e`) without sending a TEXT; alice (who posted last) re-delivers (rank 0) and writes a DELIVERED
   record; bob joins e+1 by the chained rule and posts KEY_OK; carol (rank 1) sends nothing. Variants: alice reloads
   before bob's NEED_KEY, and 15 fake minutes pass first; bob's "hello?" in e is shown to alice and carol in both.
   **Re-delivery bounds** (RC-8): in a 6-member group with bob offline after posting NEED_KEY, with two devices per
   member and a reload of every device in between, at most 3 J copies reach the fake inbox or WELCOME slots (ranks 0–2,
   one per account), the members with the oldest rows send none, and none is sent after bob's KEY_OK.
8. **Covert removal is impossible** (SEC-1, CMP-8, COR-3a, RC-2, RC-7): mallory's claim seals REMOVED to victor while
   `rm` keeps him and D′ lists him. Victor is frozen as **excluded** (`I(V).frozen = "excluded"`), with the critical
   warning naming mallory, not "removed you"; alice and bob move to e+1 with victor listed and show no removal; victor
   posts NEED_KEY; alice re-delivers; victor reaches e+1, posts KEY_OK, and his next message is read by alice and bob.
   Variant A: D′ also omits victor (or lists him with `rm` set): everyone is frozen as invalid; mallory then sends
   J(e+1) of that D′ to alice and bob, and both stay frozen in e; a J to victor is rejected (self ∉ D). Variant B: a
   later forged J(e = k+5) from mallory to victor is rejected (no skip, since victor's `rm` bit is 0).
9. **Consistent removal lines** (SEC-1): bob removes victor; alice sees "@bob removed @victor", victor sees "@bob
   removed you", and a frozen member also sees "@bob removed @victor".
10. **Registration between evaluations** (SEC-3, RC-1): (a) a claim's D′ lists a fresh uid U with a key mallory holds;
    alice evaluates, then `world.dir.register(U)`, then bob evaluates and carol restores: all three reach the same
    epoch. (b) **Unregistered committer**: mallory's D′ adds U (unregistered); U, as a member of e+1, writes a
    well-formed claim at `Lctl_{e+1}(E, k)`; alice evaluates it (U has no bundle), then `world.dir.register(U)`, then
    bob evaluates and carol restores; all three agree that U's claim at k is the winner (`I(e).winner` equal) and
    reach the same e+2; alice's own claim attempt at k+1 loses.
11. **Cuts** (SEC-5, COR-14): a claim with `cut_R = (0xFFFE, …)` is e-invalid; a claim with every cut at
    `(E_start, 0)` still shows R's earlier messages on every device, triggers no re-delivery, and R's rows after the
    claim are dropped and retracted from live views.
12. **Bundle shape** (SEC-6, COR-15): claims pointing at a 12 MiB image blob, at a 40 248-byte blob with a bad header,
    and at a B = 8 bundle for a 20-member group are e-invalid for all; a blob GET that fails twice is undecided, sends go
    to e after 30 s, and the claim is applied once the fake recovers.
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
17. **Frozen member with a leaver** (COR-23, CMP-17): a frozen member can still send TEXT after another member left.
18. **Sibling commits** (COR-24): two devices of alice race commits for the same e; the winner's device crashes after
    the CAS; the other device's recovery delivers J from the winner's EPOCH_PENDING.
19. **Committer crash** (old item 7): a second device of the committer delivers J from EPOCH_PENDING after
    `RESUME_AFTER` (engine option).
20. **Row beyond a hole**: covered by integrity test COR-10 (M8).
21. **Failed echo retry** (COR-26): a slow put whose probe returned MISS is retried with the same sealed body and gives
    one message, not two.
22. **Lurker frozen late** (RC-3): alice, bob, mallory and sam; sam never posts. Two renames by alice (e0 → e1 → e2);
    alice's followed lane for sam stays at e0 (`I(A).followed`). Mallory commits e2 → e3 and withholds sam's entry;
    alice then posts in e3 (so she is rank 0). Sam posts NEED_KEY(e_f = 2) on his lanes of e0, e1 and e2; alice sees
    the e0 copy, moves sam's followed lane to e2, re-delivers J(3), and sam reaches e3 and posts KEY_OK. Sam's "hello?" posted in e2 while frozen is shown to alice
    and bob. Variant: bob restores before sam's NEED_KEY (no HEADS since e0), computes the same followed lane, and
    sees the NEED_KEY too.
23. **WELCOME in an older epoch after HEADS** (RC-6): bob's HEADS for his 1:1 with alice covers alice's e0 lane up to
    (E, 10); bob goes offline; alice adds bob to G with a WELCOME at (E, 11) of the 1:1's e0; alice adds carol to the
    1:1 (e1) and posts in e1. Bob restores and holds G. Live variant: bob stays online but the realtime publish of
    (E, 11) is dropped (`dropPublish`); after alice's e1 post, bob's switch to e1 sweeps alice's e0 lane, and bob holds
    G.
24. **Expired request is not a WELCOME channel** (RC-5): alice starts a 1:1 with bob (a stranger, so a request on
    bob's side) and bob never opens it; `advanceEra × 5` expires the request (variant: 64 newer spam requests push it
    out). Alice adds bob to G: her J goes by inbox (assert no WELCOME row was written), and bob holds G. Variant: bob
    posted in the 1:1 and then left it; alice's add again goes by inbox.

**Acceptance.** All of `epochs`, `sending`, `privacy` and `flows` are green in `engine2`. Every membership change in
the tests waits `Δ + SKEW` = 1 s (`world` Δ = 1, SKEW = 0); every other protocol delay is shortened through
`EngineOptions`. Total engine2 run time is ≤ 2× the v1 engine suite.

### M8. Integrity, warnings, scale acceptance, e2e on v2 (3–4 days)

**Add `src/client/v2/integrity.ts`:**

- checkpoint pin and storage (`localStorage["segv.ckpt"]`), range verification, and the rewrite and rollback warnings;
- the `ck` split-view check, deduplicated per sender;
- the row immutability map;
- `prevh` omission checks;
- receipt verification;
- `EngineState.head` = the checkpoint.

**Tests.**

- Port `sync.spec.ts` (11, mapping in §3 of this plan).
- New `test/engine2/scale.spec.ts`: the O(history) acceptance tests T1–T7 (§4 of this plan).
- New `test/engine2/integrity.spec.ts`:
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

**E2E.** Temporarily point `src/components/real-engine.ts` at the v2 engine behind a build flag (`VITE_SEGV_V2=1`),
update `test/e2e/run.mjs` (§0.5, §5.3 of this plan), and run the e2e suite with the flag.

**E2E addition.** A 1:1 with 100 messages; reload; open it; messages older than the last 30 per lane appear (IMP-1,
CMP-6).

**Acceptance.** `engine2` is fully green (59 ported, the 4 obsolete ones replaced, plus the new tests). The e2e suite
is green with v2.

### M9. Cut-over and deletion (1–2 days)

**Change.**

- `src/components/real-engine.ts` imports the v2 engine unconditionally (the flag is removed).
- Rename `src/lib/proto2.ts` → `src/lib/proto.ts`, `src/server/v2/*` → `src/server/*`, `src/client/v2/*` →
  `src/client/*`, `test/engine2` → `test/engine`, and `test/worker/v2/*` → `test/worker/*`.
- `vite.config.ts`: drop the old engine project.
- Remove the `LOG` binding and `POW_APPEND` from `wrangler.jsonc` and `test/worker/wrangler.test.jsonc`, and add
  migration tag `v3` `deleted_classes: ["LogDO"]` (or collapse, per Q1).
- `migrations/0004_drop_v1.sql`, or a squash.
- `docs/PROTOCOL.md` ← SPEC (drop the "stage 1" draft wording in the title only if desired).
- `docs/DESIGN.md`:
  - §2 rewritten for LIS;
  - §3 updated with SPEC §13.2 (every weakening, verbatim in substance) and §13.3;
  - §4 future work becomes SPEC §14.
- `README` if it mentions `/api/log`.

**Delete.**

- Server: `src/server/log-do.ts`, `src/server/d1-index.ts`, `src/server/types.ts` (v1 wire types), the v1 handlers in
  `src/server/api.ts`, the v1-only parts of `src/server/validate.ts` (`checkAppendRows`, `userBody`, `wrapBody`).
- Client: `src/client/dh.ts`, the v1 `src/client/engine.ts` and `src/client/api.ts`.
- Protocol: the v1-only exports of `proto.ts`:
  - `msgTag`, `claimTag`, `makeInvite`, `inviteViewKey`, `openInvite`;
  - `makeClaim`, `openClaim`, `verifyClaimSig`;
  - `Payload`, `makeMessage`, `openMessage`, `verifyMessageSig`, `validPayload`;
  - `MSG_CLASSES`, `INV_CLASSES`, `*_BODY_LENS`;
  - `rowHash`, `ZERO32` (if unused), `userTag`, `wrapTag`;
  - the v1 descriptor JSON functions.
- Tests: `test/worker/log-do.spec.ts`, `test/worker/api.spec.ts` (v1), the v1 helpers, and `test/engine/` (v1).

**Acceptance.**

- `vp check`, `vp test run` (unit + workers + engine), `vp build` and `npm run test:e2e` are all green.
- `grep -r "segv.sh/v1/" src test` returns nothing.
- `grep -r "/api/log\|/api/append\|/api/ws" src test` returns nothing.

### M10 (before M9). Links (2 days)

Link hello is a DD §12.1 client item, so it is part of stage 1. It lands **before** the cut-over, without an `Engine`
interface change (SPEC §11.11):

- `src/client/v2/links.ts`: LINK records, `Tlink` subscription, hello write (CAS at the first empty `j`) and read
  (probe up to the first MISS for every era of the link's lifetime), one-shot and expiry handling.
- The engine exposes `createLink(opts?: {oneShot?: boolean}): Promise<string>` and `openLink(url): Promise<string>` as
  internal methods (reachable through `I(e)` in tests). No UI and no `Engine` method in stage 1; adding them later is
  an additive interface change (Q7).
- **Tests** (`test/engine2/links.spec.ts`): a hello CASes the first empty `j` and a racing second hello takes `j+1`;
  Bob finds both by probing; a one-shot link stops after the first valid hello; an expired link (`advanceEra × 5`) is
  not probed; a junk hello row gives a noise warning and no conversation; the joined conversation works both ways.

The order is M0 … M8, M10, M9.

## 2. Porting `test/engine/harness.ts` to stage 1

### 2.1 `FakeWorld` (replaces `FakeServer`)

The fake is one object behind `fetch` and `WebSocket` (`test/engine2/harness.ts`). It decodes binary bodies with the
**same** `src/lib/wire.ts` codecs as the Worker and uses the proto2 commitment helpers, so the fake cannot drift from
the wire format.

| part | what it fakes | test controls |
| ---- | ------------- | ------------- |
| `clock` | Server time = `Date.now() + offsetMs`, with an extra lag for the shard (`shardLagMs`). Params use **Δ = 1, SKEW = 0, inboxSlot = 1**, PoW 0 everywhere, a fixed `srvKey` / `SRV_SK`, `p` computed from the users, and `kcommit`. Every response carries `x-segv-now`. | `advance(ms)`; `advanceEra(n = 1)` (moves `offsetMs` to the next era start + 1 s); both close every FakeWebSocket, so engines reconnect and see a new HELLO; `shardLagMs`; `sealDelayMs` (default 0), with `sealPrevious()` |
| `shard` | `Map<"E:label", {t, cls, body}>`. `put` follows SPEC §9.1: OK, CONFLICT with the occupant, WRONG_ERA by `clock` (with early acceptance), BAD; FULL never. `get` returns HIT, MISS(sealed) or NO_ERA. Batches and heads are computed lazily for checkpoints. | `rows()` for attackers and `readableWith`; `commit(E, label, cls, body)` without validation (an attacker write); `hasLabel`; `hide(E, label, forUser)` (omit a row for one engine); `retime(E, label, t)` (serve a different `t`) |
| `blobreg` | Create-only `id → {t, size}` plus the high-water mark; `meta` returns MISS with `now`. | `forceT(id, t)` (forge a late registration); `missNow(fn)` (return `now < t_row` once); `failGet(id, n)` (blob GET 503 n times) |
| `blobs` | Content-addressed bytes; PUT checks `H = id`, registers, and returns `t`. GETs are `public, immutable`, like the Worker's. | `staleNow` (cacheable responses, i.e. blob GETs and inbox reads, carry an `x-segv-now` weeks old, as a browser cache would replay it) |
| `inbox` | Per era: rows `{rel, eid, body}`. Jitter 0, `rel = ⌊ms/1000⌋ + 1`, `closed = max(⌊ms/1000⌋, closed_hw)`, batched posts with per-row results, the day cap (`dayCap`, default 2000), 410 for old eras. | `post(...)` as an attacker; `dayCap`; `rollDay()` |
| `limits` | Optional per-route rate limits (`RL_INBOX` 10/60 s etc.) answering 429 with `retry-after`. Off by default. | `rateLimits(on)` |
| `rt` | `FakeWebSocket` bound to the world. HELLO (with `seq`) on open; SUB, UNSUB and RESUME by `seq`; ROWS delivered with `setTimeout(0)` to the subscribed sockets only; the ring with `boot`; the topic limits. | `restart()` (new boot, so the next RESUME gets GAP); `wsEnabled`; `dropPublish(pred)` |
| `dir` | `user`, `wrap` and `dirlog` with the validation of M3; prefix queries; `uid`; `wraps/{id}`. | `register(...)` and `postWrap(...)` called directly by tests (as `makeUser` does today), also between two engines' evaluations (SEC-3) |
| `ckpt` | `tick()` builds `C_q` from the fake heads and signs it with the test key. | `forkAt(q)` (serve a rewritten chain from q) |
| `requests` | Every request: `{method, path, status, reqBytes, resBytes, putResults[]}`. | used by the scale assertions |
| `hooks` | `beforePut(rows)`, which may await or commit other rows first (replaces `beforeAppend`); `fail(method, path) → 'before' \| 'after' \| null`; `beforeRequest(method, path)` | |

The browser globals stay as in v1 (`harness.ts:398-429`): a `localStorage` map, `location`, `WebSocket`, `fetch`, and an
always-failing `indexedDB`.

### 2.2 Lifecycle helpers

These keep their names and signatures: `freshWorldPerTest`, `newEngine`, `engineFor`, `makeUser`, `view`, `mustView`,
`chat`, `systemLines`, `conv`, `epoch`, `waitFor`, `sleep`, `localStore`, `server()`. `server()` now returns the
`FakeWorld`.

**`settle(...es)`** is the new definition, because `head.seq` no longer exists. It runs rounds of:

1. Await every engine's `queue` and `sendChains`.
2. `world.ckpt.tick()`.
3. `await I(e).catchUp()` for each engine, which includes the inbox poll.
4. Compute `stamp = world.writeCount + Σ I(e).version`, where `version` is a new engine counter, bumped on every
   applied row or record.

It stops when the stamp is unchanged for 2 consecutive rounds, every `I(e).busy === 0`, and the fake inbox holds no
row with `rel > closed` (a posted invite that is not yet visible). `busy` counts in-flight actions and scheduled
protocol timers (the commit wait, parked joins, re-delivery and resume timers, pending HEADS writes); periodic timers
(the 300 s sweep, the inbox poll) are not counted. When `busy > 0` only because of a timer, `settle` advances the fake
clock to that timer instead of sleeping. The timeout is 60 s.

**Engine options.** `newEngine(..., opts)` passes `EngineOptions` with every protocol delay of SPEC §11 (re-delivery
rank delay and jitter, rotation rank delay, `RESUME_AFTER`, the HEADS delay, the poll and catch-up intervals, the 30 s
processing wait) and the injectable clock. Tests use 0 or a few milliseconds, except where a test measures the delay
itself.

**`engineFor(u)`** unlocks, waits for `!syncing`, then settles (as today).

### 2.3 Builders (rewritten)

| builder | does |
| ------- | ---- |
| `signEpoch({conv, e, members, by, prev, name, keyOf?})` | Returns `{EK, keys, D, dsig, hD}`, binary D through proto2. Members are `(uid, sigPk)`; `keyOf(uid)` overrides a key (for the fake-key cases), and the default is the user's real key. |
| `buildBundleFor(epochPrev \| null, D, dsig, EK, keepMap)` | Returns `{blob, id, size}` and uploads and registers it with `world`. |
| `commitChange(by, convId, ep, members, name?)` | Async. Exactly what the engine's commit does: bundle, wait `Δ + SKEW`, claim at the first empty `Lctl` slot with real cuts, J by inbox to new members. Replaces `buildChange` and is used for "rename" and the forged commits. |
| `buildClaim(by, ep, {hD, ekc, bundleId, size, cuts, k, E})` | A raw claim row, for the forged and invalid cases. |
| `buildMessage(from, convId, ep, {E, n, prev?}, partial)` | A signed lane row: TEXT, IMAGE, WELCOME, LEAVE, NEED_KEY(`e_f`), KEY_OK, or with a forged `ck`. |
| `forgeJoin(toUser, J, {era?})` | An inbox invite row. Replaces `invitesFor` / `junkInvite`. |
| `junkRow(label, cls)` | Replaces `junkMessageRow` / `junkInviteRow`. |
| `readableWith(mk)` | Every fake shard row that opens under `mk`, parsed. |
| `entryOutcome(blob, user, e)` | `"EK" \| "removed" \| "none"` for each user. Replaces `inviteRecipients`. |

`I(e)` white-box access changes:

- **Kept:** `account`, `convs` (copies), `queue`, `sendChains`, `imageCache`, `pending`, `fatal`, `generation`,
  `unlock()`, `views()`.
- **New:** `catchUp()`, `version`, `busy`, `expected` (label → target), `laneHead(convId, uid)`, `followed`,
  `parked`, `requests`, `createLink`, `openLink`, and the epoch introspection (`keys`, `D`, `members`, `myIndex`,
  `frozen` (`"withheld" | "excluded" | "invalid" | null`), `removed`, `winner`, `ctlPos`, `rm`), `members`
  (MEMBER records) and `redeliveries` (scheduled and sent).
- **Removed:** `head`, `tags`, `syncNow`.

## 3. Per-test mapping of the 63 engine scenarios

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
| 23 | epochs: legit re-add of a removed member | K | Skip rule (REMOVED entry, then J at e = 2). `warnings` stays `[]`. |
| 24 | epochs: future member cannot be captured by a forged epoch | A | Planted with `forgeJoin` to dave. The rest is unchanged: 2 ⚠ copies; corroboration by bob clears the real copy's mark; the later junk copy is rejected. Still needed: the stage-1 design draft had no defence for this, and SPEC §6.7 keeps v1's copies rule. Added variants: dave posts in the forged copy before the real add, and the real add is still kept (self never confirms, COR-9); dave is offline while bob posts, and corroboration still happens at restore through request probing (SEC-17). |
| 25 | epochs: removed member posts into two old epochs | A | Mallory writes rows at her lane's next slot in e0 and e1 (after the cuts) with `buildMessage`. Chats are unchanged. The rule is now cut / `t` (SPEC §6.8). |
| 26 | epochs: old-epoch messages before the claim are shown | K | Pre-cut rows are accepted. |
| 27 | epochs: claim with a bad csig freezes membership only | **R** | The claim is not e-valid and is ignored: no removal, epoch 0, `canSend`; a noise warning "ignored an invalid membership change" instead of "can no longer change"; then `A.removeMember(mallory)` **succeeds** with its claim at `k = 1`. Junk no longer freezes (SPEC §6.10). |
| 28 | epochs: junk kind-4 row on the claim slot freezes membership | **R** | Junk at `Lctl(E, 0)`: messaging continues, and `A.removeMember(mallory)` succeeds at `k = 1`. |
| 29 | epochs: kind-3 row on the claim slot | O | Rows have no kinds in v2. Covered by #28. |
| 30 | epochs: valid claim whose invites never arrive; messaging continues | A | The v2 analogue is a key withheld from everyone: mallory commits an e-valid claim with a registered bundle whose entries are garbage. Alice, bob and victor are **frozen** (v1 semantics, the v1 warning text): victor's message reaches alice; `A.removeMember` throws "can no longer change"; nobody re-delivers, since nobody reached e+1. Added variant: a claim with an unregistered bundle is ignored, and nothing freezes. The partial case is claims.spec #7. |
| 31 | epochs: valid claim honoured; "@bob removed you" | K | REMOVED entry with the `rm` bit set (SPEC §5.4, §6.2). Alice's line "@bob removed @victor" comes from `rm`. |
| 32 | epochs: bob leaves, alice adds dave; no invite for bob | A | `entryOutcome` shows bob's entry opens to "removed", and alice's and carol's to EK. Exactly one inbox J, opened by dave only. The rest is unchanged. |
| 33 | epochs: bob leaves, alice removes carol | K | |
| 34 | epochs: a leaver who is explicitly re-added comes back | K | |
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
| 46 | sync: each spam invite registers at most members×8+1 tags | A | 120 spam conversations of 32 members via inbox, from a stranger. They become requests (SPEC §11.5): the account keeps ≤ 64 REQUEST records, subscribes no topic for them, probes ≤ m + 2 keys per request per catch-up, writes the joins in ≤ 3 self rows, and spends ≤ 1 blob GET and ≤ 1 directory request per spam join. |
| 47 | sync: the window slides and exactly 8 are watched | A | After 20 sends, B's expected map holds exactly W = 8 slots for alice's lane in the current era. |
| 48 | privacy: creation batch has the same shape as a change; a message is [4] | **R** | Per `world.requests`, creation, add and remove all produce: one SGB2 PUT, one class-1 self row, exactly one class-1 put ≥ Δ + SKEW after `t_reg` (decoy versus claim), and one class-0 self row at the end. Creation and add then show the batched inbox posts; remove shows none (the documented difference, SPEC §13.2 item 12). In the 30 s after another member's claim, the other members write no self rows. A text message is one class-0 put. |
| 49 | privacy: creation decoy has a claim's size class (30 members, long name) | A | Decoy class = claim class = 1, and the bundle size is 40248 for both creation and add. |
| 50 | privacy: invite order is shuffled | O | Entry positions are bound to the `D_{e−1}` index, only the owner can open an entry, and J's are separate rows, so order leaks nothing. Replaced by: "a removed member's key opens only its own entry (REMOVED); groups of 3 and 8 produce equal bundle sizes". |
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

### 3.1 Worker spec mapping

| current | stage 1 |
| ------- | ------- |
| `test/worker/log-do.spec.ts`: tag race, handle/uid uniqueness, RPC validation | `shard-do.spec.ts` (CAS race, BAD), `directory.spec.ts` (uniqueness, concurrency) |
| log-do: eviction with hibernated sockets | `realtime-do.spec.ts` |
| log-do: D1 outage and hang, outbox alarm | **obsolete** (no outbox). Replaced by `directory.spec.ts` "D1 failure → 503" and the CheckpointDO "failing component keeps its head". |
| `api.spec.ts`, every section | `test/worker/v2/api.spec.ts`, per the M4 table |
| `helpers-unit.spec.ts` | Kept unchanged (b64, `clientKey`, `logErr`, `clientTag`, `appHosts`), plus `wire` round trips. |

## 4. Acceptance for the four O(history) problems (`test/engine2/scale.spec.ts`)

Every test runs the same scenario twice. In the **clean** world nothing else exists. In the **noise** world the
following is added first through `world` attacker APIs:

- 50 000 random rows over eras `E_now − 3 .. E_now`;
- 2 000 registered users;
- 5 000 inbox rows in eras older than `E_now − 3`;
- 300 inbox rows for others in the current era.

| # | problem | test | pass condition |
| --- | --- | --- | --- |
| T1 | every client downloads the whole log | Alice and bob, a 1:1 with 50 messages, then alice restores on a new device and exchanges 20 more messages. | Excluding `inbox/*` and `ckpt/*` requests (directory requests included): the request count is equal between the worlds, and response bytes differ by ≤ 2%. The measured restore makes no prefix lookup and no `dirlog` read (bob's MEMBER record is in the self lane), only the own `dir/uid` lookup. No request touches a noise row (the fake counts HITs on noise labels: must be 0). Outside the measured part, every directory response holds at most `2 · users / 2^p` bundles for the `p` it asked (the noise world's handles are generated deterministically). |
| T2 | trial-scans every invite | As T1, plus two variants: (a) the day cap filled in all 4 retained eras (56 000 rows) and a returning device whose last cursor is 1 h old; (b) a freshly registered account. | Inbox requests never name an era `< E_now − 3`. Main case: inbox rows fetched in the noise world − clean world = exactly the 300 current-era rows; a second restore after the cursor was written fetches 0 of them. (a): rows fetched ≤ rows posted since the cursor. (b): rows fetched ≤ rows posted since registration. |
| T3 | receives every row over one global WebSocket | Carol and dave, in a conversation alice is not in, exchange 100 messages while alice is connected. | Alice's socket receives 0 ROWS entries whose topic is not in her SUB set; her received bytes are unaffected by carol's traffic. (`realtime-do.spec.ts` also asserts this on the real DO.) |
| T4 | replays full history on every new device or reload | Alice with one conversation holding 2 000 messages, versus the same with 4 000 messages; both with the same compacted self state (300 HEADS overwrites against 3) and a snapshot and HEADS written just before the measured restore. | A restore (unlock to `!syncing`, without `markRead`) makes the same number of requests (±1), and its bytes differ by ≤ 5%; history bodies fetched = `HISTORY_INITIAL` per lane. Without a fresh HEADS, requests ≤ `a + b · log2(rows since the last HEADS)`. With 2 000 self records and no snapshot, the restore writes a snapshot, and the next restore's self-lane probes are ≤ 2 gets. |
| T5 | (bonus) catch-up after offline | Alice offline while 10 000 unrelated rows are written. | Catch-up requests and bytes equal the clean world's. |
| T6 | restore at scale (CMP-14, IMP-10, RC-4) | Alice in 50 groups of 32 members (about 1 000 distinct co-members, in a noise world of 2 000 users), each with 40 recent messages, HEADS and snapshot current. | The restore makes fewer than 600 read requests (one `RL_READ` minute), fetches no bundle for epochs covered by DESC records, and fetches initial history for 20 copies only. **Directory:** exactly one directory request (own `dir/uid`) and no prefix lookup, so directory bytes are independent of the number of users and co-members. Variant: 10 co-members lack MEMBER records; the restore makes ≤ 10 prefix requests (≤ 1 per missing member) and the next restore makes none. |
| T7 | spam requests (SEC-13, IMP-6) | As T4, plus 500 spam joins from strangers before the snapshot. | Restore requests and bytes exceed the clean case by at most `MAX_REQUESTS × (32 + 2)` probe keys, with no bundle fetches and no directory requests; no topics are added. |

`world.requests` records `reqBytes` and `resBytes`, so the assertions are exact and deterministic. Use fixed counts,
not timing.

## 5. E2E (`test/e2e/run.mjs`)

1. **Config.** The overrides of §0.5 of this plan.
2. **Flows.** The existing flows (register, login, 1:1, group, image, second device, remember) are unchanged in
   intent. Waits for "conversation appears" need ≤ 15 s (inbox slot 1 s + poll 2 s + commit 1 s). New step: a 1:1 with
   100 messages, reload, open it, and messages older than the last 30 per lane appear (the `markRead`-on-open UI change
   of §0.4).
3. **Audit step, rewritten.** Enumerate `GET /api/v2/feed/{E}/0` for every era from the run's start era to `E_now`:
   - verify every batch's root (proto `mth` of `leafShard`) and the head chain;
   - require the last head to equal the `shard/{E}/0` head in `/api/v2/ckpt/latest` (after a `ckpt` tick, or wait 60 s,
     or expose a test-only tick through an env flag);
   - require every row body length in `BODY_LENS`.

   Enumerate `GET /api/v2/inbox/{E}/0`: every body is 1416 B. Enumerate `GET /api/v2/dirlog`: exactly 4 user entries.

   For every row and inbox body, check that no plaintext needle (the secrets, the team name, the handles) appears.
4. **Console errors.** Probes, CONFLICTs and per-invite `conflict`/`full` results are in-band (HTTP 200), and
   `blob/meta` misses are 404, so the existing "no page errors except 404" rule holds. Avoid 409 paths in honest flows:
   the inbox wrong era is retried silently, and the directory prefix bits refresh params first.

## 6. Risks, ranked

1. **Security: undetectable selective omission, forks and directory substitution by the operator** (SPEC §13.2
   items 2–4). This is a deliberate stage-1 weakening, and it MUST be written into `docs/DESIGN.md` §3. Mitigations in
   stage 1: receipts, `ck`, `prevh`, CONTACT and MEMBER pins, descriptor keys, the public feed and dirlog for
   auditors. Inclusion proofs and witnesses come in stage 2.
2. **Schedule: engine rewrite size.** Restore, the self lane, claims and integrity add up to about 2–3× the logic of
   `engine.ts`. Mitigations: the parallel `engine2` path, the harness first (M5), and porting spec files one by one.
3. **Correctness of claim timing.** The `Δ + SKEW` wait, MISS decisiveness, era sealing and grace, and finality across
   eras. A bug here forks groups. Mitigations: `claims.spec.ts` items 2–4 with fake clocks; the worker tests for the
   BlobReg high-water mark and the ShardDO seal.
4. **Dense prefixes, multi-device CAS and the self lane.** Duplicate application, `prev` chains across eras, copy
   numbering across devices. Mitigations: `restore.spec.ts`, idempotent record keys, CONFLICT-occupant handling in one
   shared helper used by lanes, the self lane and the control lane.
5. **Latency and UX.**
   - Every commit and creation waits at least 12 s in production (Δ = 10, SKEW = 2).
   - First contact by handle arrives in about 10–20 s.
   - Tests are slower (Δ = 1).

   Tunable through params, with a privacy cost.
6. **DoS on the global inbox (β = 0).** One attacker can hit the 2 000/day cap and delay first contact by handle, and
   adds of members without a 1:1, for everyone (SPEC §13.2 item 11). A device without a cursor trial-decapsulates up to
   56 000 invites. Mitigations: PoW `inbox` 18, `RL_INBOX`, batched posts, resumable delivery with retry (SPEC §6.12),
   1:1 WELCOMEs for known contacts, the cursor in the self lane, and trial decryption in a Web Worker. Stage 2 adds
   β > 0.
7. **Single RealtimeDO.**
   - Its capacity is about 20 000 sockets and 250 000 subscriptions, sized to its 128 MB isolate (SPEC §9.4).
   - Hibernation or a deploy clears the ring, which causes GAP storms (catch-up spikes).
   - API deploys still drop sockets (no separate Worker until stage 2).

   Mitigations: jittered reconnect and the 300 s sweep cadence.
8. **D1 as the authoritative directory.** An outage blocks registration and login, where v1 had a log fallback.
   Dirlog contention under bursts. Mitigations: 16 retries with random back-off, then 503. If contention shows up in
   practice, serialise directory writes through one small DO.
9. **Durable Object migration tags** for a fresh deploy (Q1).
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
| Q1 | Cumulative DO migrations versus collapsing to a single tag | Cumulative; collapse if `wrangler deploy --dry-run` fails. |
| Q2 | Production Δ = 10 s and SKEW = 2 s give ≥ 12 s commits. Accept, or use Δ = 5 s (7 s commits, weaker time blurring)? | Δ = 10. |
| Q3 | Should creation wait `Δ + SKEW` and post a decoy, which keeps v1's creation-versus-change indistinguishability, at the price of slower creation? | Wait (SPEC §6.1). |
| Q4 | Inbox client retention of 4 eras, and a global day cap of 2 000 | As in SPEC. |
| Q5 | Implement sending J through a qualifying 1:1 (SHOULD; SPEC §6.12 step 1: the recipient has posted in the 1:1's current epoch and has not left) in M6, or defer it (receiving is a MUST)? | Implement in M6, with creation: it removes most inbox load. A 1:1 that does not qualify always falls back to the inbox. |
| Q6 | Proactive ranked rotation after a leave (MAY) | Not implemented. |
| Q7 | Link UI and `Engine` methods (an additive interface change) | The protocol and engine support land in M10, before the cut-over, as internal methods with tests. Adding `createLink` / `openLink` to `Engine` and a UI is a user decision, after the cut-over. |
| Q8 | A persisted local cache (IndexedDB) for faster reloads | Deferred; restore is bounded anyway. |
| Q9 | Should "frozen" members get a UI hint beyond the critical warning? | No UI change. The withheld-key warning text is kept from v1; the invalid-claim and excluded warnings name the signer. |
| Q10 | Pending invitations after `createConversation` resolves are invisible in the UI (only a warning on failure). Add a "inviting…" hint? | No (it needs a new view field). |

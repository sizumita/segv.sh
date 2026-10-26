# segv.sh protocol v1

Normative spec for the MVP. Every implementation (client crypto core, client engine,
Worker, tests) MUST follow it byte-for-byte. Rationale lives in `docs/DESIGN.md`.

## 0. Model

- The server is a **public, append-only, hash-chained log** (D1) with a single sequencer
  (Durable Object `LogDO`) and a content-addressed blob store (R2). Everything it stores is
  world-readable. It has no sessions and never sees a secret.
- A client downloads **every** log row since its cursor (no per-recipient queries), verifies the
  hash chain, and recognises "rows for me" locally (trial decryption / tag lookup).
- Writes are anonymous. Abuse control = proof-of-work + per-IP rate limiting (never stored in the log).

## 1. Primitives & encoding

| name                       | definition                                                                                                                 |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `H(x)`                     | SHA-256                                                                                                                    |
| `HKDF(ikm, salt, info, L)` | HKDF-SHA-256 (`@noble/hashes/hkdf.js`)                                                                                     |
| `HMAC(k, m)`               | HMAC-SHA-256                                                                                                               |
| `AEAD`                     | XChaCha20-Poly1305 (`@noble/ciphers/chacha.js` `xchacha20poly1305`), 24-byte **random** nonce, 16-byte tag                 |
| `KEM`                      | X-Wing = `ml_kem768_x25519` from `@noble/post-quantum/hybrid.js`. `keygen(seed32)`; pk 1216 B, sk 32 B, ct 1120 B, ss 32 B |
| `SIG`                      | Ed25519 (`@noble/curves/ed25519.js`), sk = 32-byte seed                                                                    |
| `DH`                       | X25519 (`@noble/curves/ed25519.js` `x25519`)                                                                               |

Encoding helpers (all integers big-endian):

- `u8, u16, u32, u64` — fixed-width unsigned.
- `utf8(s)` — UTF-8 bytes.
- `lp(b) = u32(len(b)) || b`
- `enc(a, b, ...) = lp(a) || lp(b) || ...` — string arguments are `utf8`-encoded first.
- `b64u` — base64url **without** padding. All binary values in JSON use `b64u`.
- `trunc16(x)` — first 16 bytes.

**Signed JSON rule:** a signed JSON object is transmitted as the exact UTF-8 text the signer produced
(`*Bytes` below). Verifiers verify over those exact bytes and only then `JSON.parse`. Nobody ever
re-serialises signed JSON.

All labels are ASCII strings with prefix `segv.sh/v1/`.

## 2. Accounts

### 2.1 Account key and identity keys

`AK` = 32 random bytes. It is the root of every secret of the account.

```
sigSk   = HKDF(AK, "", "segv.sh/v1/id/ed25519", 32); sigPk = Ed25519.pub(sigSk)
kemSeed = HKDF(AK, "", "segv.sh/v1/id/xwing",   32); (kemPk, kemSk) = XWing.keygen(kemSeed)
scanSk  = HKDF(AK, "", "segv.sh/v1/id/scan",    32); scanPk = X25519.pub(scanSk)
```

`uid` = 16 random bytes (public). `handle` matches `^[a-z0-9_]{3,20}$` (lowercase), unique.

### 2.2 Bundle (public identity)

```
bundleBytes = utf8(JSON.stringify({v:1, uid:b64u(uid), handle, sig:b64u(sigPk),
                                   kem:b64u(kemPk), scan:b64u(scanPk), ts:<ms>}))
bundleSig   = SIG.sign(enc("segv.sh/v1/bundle", bundleBytes), sigSk)
```

Fingerprint (shown to users, compared out of band):
`fp = H(enc("segv.sh/v1/fp", uid, sigPk, kemPk, scanPk))`; display = 6 groups of 5 decimal digits,
group k = `(u40 of fp[5k..5k+5]) mod 100000`, zero-padded.

### 2.3 Sealing (KEM-DEM, used for key wraps)

```
seal(pk, label, ctx, pt):
  (kct, ss) = KEM.encap(pk)
  k     = HKDF(ss, H(kct), enc("segv.sh/v1/seal", label, ctx), 32)
  nonce = random(24)
  return kct || nonce || AEAD(k, nonce).encrypt(pt, aad = enc(label, ctx))
open(sk, label, ctx, out): inverse; throws on failure.
```

### 2.4 Passkey wraps (WebAuthn PRF)

- PRF input: `prf.eval.first = utf8("segv.sh/v1/prf")` (the browser hashes it with the WebAuthn PRF prefix).
- `prf` = 32-byte PRF output. Never leaves the client; never stored.
- Credential unlock key: `credSeed = HKDF(prf, credId, "segv.sh/v1/cred/xwing", 32)`;
  `(credKemPk, credKemSk) = XWing.keygen(credSeed)`; `credAuth = HKDF(prf, credId, "segv.sh/v1/cred/auth", 32)`.
- Recovery code: `code` = 20 random bytes, shown once as Crockford base32 (32 chars, 8 groups of 4).
  `recSeed = HKDF(code, "", "segv.sh/v1/recovery/xwing", 32)`; `recAuth = HKDF(code, "", "segv.sh/v1/recovery/auth", 32)`;
  `recId = HKDF(code, "", "segv.sh/v1/recovery/id", 16)`.
- `auth` is mixed into every wrap. The KEM public key and the id are public, so without it anyone could file a wrap
  of _their own_ AK under someone else's id that opens with the victim's secret (and sign them into the attacker's
  account). With it, only a holder of the PRF output / recovery code can produce a wrap that opens.

Wrap record (one per passkey and one for the recovery code; several per id are allowed):

```
recordBytes = utf8(JSON.stringify({v:1, uid:b64u(uid), kind:"passkey"|"recovery",
                                   id:b64u(credId | recId), kem:b64u(credKemPk | recKemPk),
                                   wrap:b64u(seal(kemPk_of_this_record, "ak-wrap", enc(uid, id, auth), AK)),
                                   ts:<ms>}))
recordSig = SIG.sign(enc("segv.sh/v1/wrap", recordBytes), sigSk)
```

Unlock: obtain `prf` (or `code`) → derive the KEM sk and `auth` → `open` → `AK` → re-derive `sigPk`, check the
record's signature under it, and (after sync) that it equals the bundle's `sig` (key check). If wraps of more than
one uid open, refuse. A failed unlock MUST NOT create new keys.

### 2.5 Registration and login (client flow)

Register: generate `AK`, `uid` → bundle → `navigator.credentials.create` (rp.id = page hostname,
user.id = uid, `residentKey:"required"`, `userVerification:"required"`, algs [-8,-7,-257],
`extensions.prf.eval.first`). If `getClientExtensionResults().prf.results.first` is absent, immediately
`get()` with `allowCredentials:[credId]` and the same PRF input. No PRF → abort (passkey unsupported).
Build passkey wrap + recovery wrap → `POST /api/register` → show recovery code once.

Login: `get()` discoverable (`allowCredentials: []`), UV required, `prf.eval.first`. `rawId` = credId,
`userHandle` = uid. Fetch wraps for credId (filtered by `?uid=`), unlock as above.

Lost registration response: if `POST /api/register` fails without an HTTP 4xx (network error / 5xx), the client looks up
`GET /api/users/:handle`; if the returned bundle is exactly its own, the registration landed and it continues (shows
the recovery code). Only a definitive rejection (4xx) discards the new passkey.

The server never sees any WebAuthn data. "Logging in" is local key unlock.

## 3. Conversations (1:1 and groups use the same protocol)

### 3.1 Epochs

A conversation has a secret id `conv` (16 random bytes, never public) and epochs `e = 0,1,2,…`.
Each epoch has a fresh random `EK` (32 B) and a descriptor:

```
DBytes = utf8(JSON.stringify({v:1, conv:b64u(conv), e, members:[b64u(uid), ...],  // index = position
                              prev: b64u(H(prevDBytes)) | null, by: b64u(committerUid),
                              ts:<ms>, name?: string /* ≤ 64 chars */}))
rk   = HKDF(EK, conv, enc("segv.sh/v1/ep/route",  u32(e)), 32)
mk   = HKDF(EK, conv, enc("segv.sh/v1/ep/msg",    u32(e)), 32)
kc   = HKDF(EK, conv, enc("segv.sh/v1/ep/commit", u32(e)), 32)
dsig = SIG.sign(enc("segv.sh/v1/epoch", DBytes, kc), committerSigSk)
msgTag(i, n) = trunc16(HMAC(rk, utf8("m") || u16(i) || u32(n)))   // i = member index, n = sender counter from 0
claimTag     = trunc16(HMAC(rk, utf8("c")))                       // slot for "the next epoch"
```

Rules: members has no duplicates, 1 ≤ len ≤ 32, `by ∈ members`. e = 0 ⇔ `prev = null`. `name`, when present,
is 1–64 Unicode code points with at least one letter, number, punctuation or symbol; it contains no control (`\p{Cc}`),
format (`\p{Cf}`: zero-width, bidi, tags) or lone-surrogate (`\p{Cs}`) characters, no U+061C, U+2028, U+2029 or
blank-looking fillers (U+115F, U+1160, U+3164, U+FFA0, U+2800); and after NFKC normalisation and trimming leading
whitespace it does not start with `@` (it would pass for a 1:1 with that handle). Clients display chosen names with
a `#` prefix.

### 3.2 Invites (key delivery; also used for every rekey)

For each member `m` of the new epoch (including the committer — this is how the committer's other
devices learn it):

```
P = enc(DBytes, EK, dsig)
(ephSk, eph) = X25519 keypair (fresh)
s     = X25519(ephSk, m.scanPk)
vk    = HKDF(s, eph || m.scanPk, "segv.sh/v1/inv/view", 32)
check = trunc16(HMAC(vk, utf8("check")))
(kct, ss) = KEM.encap(m.kemPk)
k     = HKDF(ss || vk, H(kct), "segv.sh/v1/inv/key", 32)
nonce = random(24)
row   = { kind: 3, tag: check,
          body: eph || kct || nonce || AEAD(k, nonce).encrypt(pad(P, [2048]),
                                                         aad = enc("segv.sh/v1/inv", eph, check)) }
```

Scanning: for every kind-3 row, `s = X25519(scanSk, eph)`, recompute `check`; on match decapsulate and
open. Errors (bad point, AEAD failure) ⇒ ignore the row. Confidentiality is hybrid (X-Wing ⊕ X25519);
recipient detectability is classical only (documented trade-off).

The invites of one epoch are appended in **random order** (the descriptor order must not leak through the batch).

### 3.3 Accepting an epoch

On a decrypted invite `(DBytes, EK, dsig)`:

1. parse D; check field shapes; `e < 2^32-1` (the last epoch could have no successor); `kc` from EK; verify `dsig`
   with `by`'s bundle `sigPk`; `by ∈ members`; self ∈ members; every member is a registered user.
2. Duplicate invites for an accepted (conv, e) are ignored (a _different_ descriptor for an accepted (conv, e) ⇒
   security warning).
3. If the client already holds the conversation, let `k` be its current epoch:
   - `e == k+1`: require `prev == H(D_k)`, `by ∈ members(k)`, and a **valid claim** (§3.4) in slot `claimTag(k)`
     whose `(DBytes, dsig)` are exactly these. Otherwise reject.
   - `e > k+1`: accept on the signature alone **only** if epoch `k` has a valid claim that excludes self (self was
     removed and is now added back). Otherwise reject: a conversation never skips epochs for its members.
   - anything else: reject.
4. If the client does not hold the conversation (first contact, possibly added at `e > 0`): accept on the signature
   alone. (A newly added member cannot verify the history before it; it trusts the inviter's member list.)
5. If the client holds copies of the conversation and the invite fits none of them (rule 3): if any copy is
   **corroborated** — a member other than the one who added us (`by` of the first epoch we accepted) has posted a
   valid message or claim in it, or we created it — reject. Otherwise keep the invite as a **separate copy** of the
   conversation and raise a security warning: a newcomer cannot tell a genuine add from a fake epoch planted earlier
   by a removed member, so neither may silently win. Clients mark uncorroborated copies (`⚠`).
6. Leaves recorded in epoch `k` (§3.5) whose senders are still listed in `e` carry over into `e`.
7. If `name` differs from the previous epoch's, clients show who renamed the conversation.
8. If the claim slot of a newly accepted epoch is already used in the log, the epoch is frozen from the start.

### 3.4 Claims (who owns the next epoch)

To create epoch `e+1` from `e` (add / remove members, or rotate after someone left), the committer
appends **one atomic batch**: a claim row + one invite per member of `e+1` (random order).

```
csig = SIG.sign(enc("segv.sh/v1/claim-sig", claimTag(e), D_{e+1}Bytes, dsig_{e+1}), committerSigSk)
C    = enc(D_{e+1}Bytes, dsig_{e+1}, csig)
row  = { kind: 4, tag: claimTag(e),
         body: nonce || AEAD(mk_e, nonce).encrypt(pad(C, [1024,4096,16384]), aad = enc("segv.sh/v1/claim", claimTag(e))) }
```

`dsig` binds the descriptor to the new EK (only members of `e+1` can check it); `csig` lets **every** member of `e`
check who made the change. A claim is **valid** iff it decrypts, `D` parses, `conv` matches, `D.e == e+1`,
`D.prev == H(D_e)`, `D.by ∈ members(e)` and `csig` verifies under `D.by`'s key. Only a valid claim moves the
conversation on (and only a valid claim that excludes self means "you were removed").

Any row of any kind on a watched claim slot that is not a valid claim **burns** the slot (`UNIQUE(tag)`): the
conversation's membership can no longer change, but messaging in epoch `e` continues ("frozen"). Likewise, a valid
claim that lists us but whose batch completes (the client reaches the head, or 40 rows pass) without an invite we can
open is treated as never delivered: the epoch is frozen and a security warning is shown.

`UNIQUE(tag)` in the log makes the first claim win; a losing batch is rejected as a whole (HTTP 409).
The loser re-syncs and retries on top of the winner (an automatic rotation simply retries its send).

New conversations start with a **decoy** kind-4 row (random 16-byte tag, random body in the size class a claim for
the same descriptor would have) followed by the invites, so creations have the same `[4, 3×N]` shape as membership
changes. Receivers ignore it
(nobody watches its tag).

The committer must be a member of `e+1` (you cannot remove yourself — use `leave`). Any member may add
or remove others (MVP policy). Add and remove drop members who have left; a leaver comes back only when explicitly added.

### 3.5 Messages

```
payloadBytes = utf8(JSON.stringify({v:1, t:"text"|"image"|"leave", conv:b64u, e, from:b64u(uid), n,
                                    ts:<ms>, text?, img?:{id, k, mime, w, h},
                                    head:{seq, h:b64u}}))       // sender's latest verified log head
tag  = msgTag(i_sender, n)
psig = SIG.sign(enc("segv.sh/v1/msg-sig", tag, payloadBytes), senderSigSk)
M    = enc(payloadBytes, psig)
row  = { kind: 4, tag, body: nonce || AEAD(mk, nonce).encrypt(pad(M, [1024,4096,16384]),
                                                           aad = enc("segv.sh/v1/msg", tag)) }
```

Receiver: tag lookup → `(conv, e, i, n)` → decrypt → verify `psig` with `members[i]`'s bundle; require
`from == members[i]`, `n`, `conv`, `e` to match. Check `head`: if the receiver has the hash for
`head.seq` and it differs ⇒ **split-view warning**.

Sender counter: `n = 1 + max(n whose slot is used for my index in this epoch)` (0 if none; own rows from other
devices count). Receivers watch a window of `W = 8` upcoming counters per (conv, e, i), extended as the member sends.
**Any** row of any kind that lands on a watched message tag uses that slot, and a slot whose tag is already in the
log when the window reaches it is used too: the counter advances past them even if the rows are junk (so an insider
squatting slots, inside or beyond the window, cannot mute a sender). On 409 the sender re-syncs and retries (fresh
encryption) with the next free counter. A send whose row was appended but is not accepted by the sender's own client
after the next sync (e.g. it raced a removal) is reported as not delivered.

Acceptance after rotation: a message in epoch `e` at seq `s` is accepted only if, for every valid claim on the chain
`e, e+1, …` whose seq is below `s`, `from` is a member of the epoch that claim created (i.e. the sender was a member
of the epoch that was current when the row landed).

`leave`: a member posts `t:"leave"`. It is recorded in epoch `e` and in every later epoch that still lists the
leaver. The next remaining member to send first rotates to an epoch without the leavers (if the slot is frozen, they
just send).

### 3.6 Images (R2)

Client re-encodes the image through a canvas (strips EXIF), longest side ≤ 2048 px, `image/webp`
(fallback `image/jpeg`; receivers accept only these two types), ≤ 8 MiB.

```
key = random(32); nonce = random(24)
blob = nonce || AEAD(key, nonce).encrypt(padme(bytes), aad = utf8("segv.sh/v1/blob"))
id   = b64u(H(blob))                       // content address, verified by server and client
```

`PUT /api/blob/:id`; the message payload carries `img: {id, k: b64u(key), mime, w, h}`.

### 3.7 Padding

`pad(x, classes)`: `x || 0x80 || 0x00…` up to the smallest class `≥ len(x)+1`; error if none.
`unpad`: strip trailing `0x00`, require and strip one `0x80`.
`padme(x)`: same marker scheme, target length = Padmé(len(x)+1):
`E = floor(log2 L); S = floor(log2 E) + 1; z = E - S; result = ceil(L / 2^z) · 2^z` (L ≥ 2; use arithmetic, not
32-bit bitwise operators).

## 4. The log

### 4.1 Rows

| kind | meaning           | tag (16 B, UNIQUE)                                    | body                                            |
| ---- | ----------------- | ----------------------------------------------------- | ----------------------------------------------- |
| 1    | user registration | `trunc16(H(enc("segv.sh/v1/tag/user", uid)))`         | `utf8(JSON {bundle: <bundle text>, sig: b64u})` |
| 2    | key wrap          | `trunc16(H(enc("segv.sh/v1/tag/wrap", recordBytes)))` | `utf8(JSON {record: <record text>, sig: b64u})` |
| 3    | invite            | `check`                                               | see 3.2                                         |
| 4    | message or claim  | `msgTag` / `claimTag`                                 | see 3.4 / 3.5                                   |

`ts` = server time in ms, floored to the second.

Hash chain: `h_0 = 32 zero bytes`; `h_seq = H(enc("segv.sh/v1/log", h_{seq-1}, u64(seq), u8(kind), tag, body, u64(ts)))`.
`seq` starts at 1, no gaps. Clients verify the chain for every row they download and refuse to
continue on mismatch.

### 4.2 Server-side validation

- kind 1: bundle parses and is canonical JSON (exact key order, no extra keys), field sizes exact, handle regex,
  `bundleSig` valid, keys usable (`checkUserKeys`: signing key not small-order, scan key not low-order, X-Wing key
  encapsulates), uid & handle unused, tag recomputed.
- kind 2: record parses, `uid` registered (or registered in the same batch), `recordSig` valid under
  that uid's `sigPk`, kem 1216 B, wrap 1192 B (1120+24+32+16), id 1..1023 B (WebAuthn maximum), tag recomputed.
- kind 3: body length 32+1120+24+2048+16 = 3240; tag 16 B.
- kind 4: body length 24 + (1024|4096|16384) + 16; tag 16 B. (No real payload fits 256 B, so there is no 256 class:
  the rare rows that would fit, e.g. `leave`, would otherwise stand out.)
- Batch ≤ 40 rows with distinct tags and **at most one kind-4 row** (a message, or a claim/decoy followed by invites).
  A batch is atomic (one SQLite transaction in `LogDO`).

### 4.3 Proof of work

```
window = floor(serverNowMs / 600000)
pre    = H(enc("segv.sh/v1/pow", utf8(scope), u32(window), H(requestBodyBytes)))
valid  ⇔ leadingZeroBits(H(pre || u64(nonce))) ≥ difficulty(scope)
header  x-segv-pow: "<window>.<nonce>"
```

Server accepts `window ∈ {current, current-1}`. Scopes / base difficulty: `register` 20,
`wrap` 18, `append` 16, `blob` 18 (from `GET /api/params`). The required difficulty grows with what the request makes
everyone store: `powDifficulty(scope, base, bytes)` = `base + ceil(log2(bytes / unit))` when `bytes > unit`, with
`unit` = 4 KiB of request body for `append` and 1 MiB of blob for `blob` (register / wrap: `base`). Clients refuse
base difficulties above 26.

## 5. HTTP API

All JSON; binary fields `b64u`.

| method & path                                     | body / response                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /api/params`                                 | `{now, window, pow:{register,wrap,append,blob}, limits:{batch, blobMax}}`                                                                                                                                                                                                                                                |
| `POST /api/register` (pow `register`)             | `{bundle, sig, wraps:[{record, sig}]}` → `{seq}`; 409 if uid/handle taken                                                                                                                                                                                                                                                |
| `POST /api/wraps` (pow `wrap`)                    | `{record, sig}` → `{seq}`                                                                                                                                                                                                                                                                                                |
| `POST /api/append` (pow `append`)                 | `{rows:[{kind:3                                                                                                                                                                                                                                                                                                          | 4, tag, body}]}`→`{seqs:[...]}`; 409 on tag conflict |
| `GET /api/log?after=<seq>&limit=<≤1000>`          | `{rows:[{seq, kind, tag, body, ts, h}], head:{seq, h}}`. A page may hold fewer than `limit` rows (≈ 4 MiB body budget): clients keep paging until `rows` is empty or the last row's seq ≥ `head.seq` — never treat a short page as the end. Pages that end below the head are immutable and may be cached                |
| `GET /api/users/:handle`                          | `{uid, handle, bundle, sig, seq}` (convenience; clients still verify)                                                                                                                                                                                                                                                    |
| `GET /api/wraps/:id[?uid=<b64u>]`                 | `{wraps:[{seq, uid, record, sig}]}` (≤ 64, oldest first; `uid` filters — ids are public, so anyone can file wraps under someone else's id)                                                                                                                                                                               |
| `PUT /api/blob/:id` (pow `blob`, body = raw blob) | 201; id must equal `b64u(H(body))`; ≤ 12 MiB                                                                                                                                                                                                                                                                             |
| `GET /api/blob/:id`                               | raw blob, `cache-control: public, max-age=31536000, immutable`                                                                                                                                                                                                                                                           |
| `GET /api/ws` (WebSocket)                         | server → client `{type:"rows", rows:[...]}` for every append (all rows, to everyone). Client → server: only `"ping"` (answered `"pong"`); anything else closes the socket. Cross-origin upgrades are refused; sockets are capped per client and globally and closed after about an hour (clients reconnect and backfill) |

Clients that see a seq gap on the socket backfill with `GET /api/log`. Every response is `nosniff`, `no-referrer`
and (on https) HSTS; the Worker serves only the hosts in `APP_HOSTS` (others are redirected), so passkeys are only
ever created for the production RP ID.

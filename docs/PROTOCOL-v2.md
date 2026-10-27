# segv.sh protocol v2 (stage 1)

This is the normative spec. It replaces protocol v1. Every implementation (the client crypto core `src/lib/proto.ts`, the
client engine, the Worker and the tests) MUST follow it byte for byte. The rationale lives in `docs/DESIGN.md`.
"Stage 1" is the first build stage of the Label-Indexed Store (LIS). The identifier of the protocol is `segv.sh/v2/` in
every stage, and §14 lists what later stages add. v1 wire formats are removed: a v2 implementation does not read,
write or serve them, and there is no migration (no v1 data exists).

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

**Implementation vocabulary** (round 10). These are implementation-defined and not part of the protocol: the names of
functions, constants and types that the plan, the delta, `answers.md`, the appendices and the tests use (for example
`dPrimeChecks`, `checkPks`, `checkJoinBundle`, `processClaim`, `acceptOldRow`, `rekeyRoot`, `validKemPk`, `pksAt`,
`SGB2_PKCT_AT`, `logErr`); the failure codes or reasons such helpers return; the order in which a client evaluates
checks whose order this spec does not state (§6.6 step 4, "Check order"); and the text, keys and format of log lines
(§9.7). What is normative is the bytes written, served and accepted; the labels; the verdicts (valid, e-valid,
undecided, D′-invalid, frozen, removed, dropped, parked); the warning and system-line texts; the requests a client
makes; and the server's status codes and headers, and its bodies as this spec defines them (binary layouts, JSON keys
and the error strings it names; any other error text is diagnostic). No implementation-defined item may change any of
these. Unit tests MAY assert failure codes as diagnostics of one implementation; engine tests assert verdicts and
texts.

## 0. Model

### 0.1 What the server is

- The server stores **public** data only. Anyone may read every stored byte, forever, and it never sees a secret.
  It has no sessions. Writes are anonymous. Abuse control is proof of work plus per-IP rate limits, and no address is
  stored.
- Conversation data is stored as **rows** `(E, label) → (t, cls, body)`:
  - `E` is the **era**, one week (§3.1).
  - `label` is 16 bytes. Only the parties that the row is meant for can compute it (a PRF output).
  - `t` is the public time, rounded to `Δ` seconds.
  - `cls` is the size class, and `body` is the fixed-length ciphertext.

  Rows are create-only: the first write of `(E, label)` wins and is never changed. Nothing else is stored about a
  row: no sender, recipient, conversation, epoch, counter, arrival order or address.
- Clients find the rows meant for them by **computing the labels they expect and looking them up by key**. They also
  receive new rows over a WebSocket topic that they subscribe to (topics are never stored). No client downloads or
  scans data that is not addressed to it, with one exception: first-contact invites in the global inbox (β = 0,
  §5.3).
- Server components:
  - one **ShardDO** per era (stage 1: one shard, S = 1);
  - one **InboxDO** per era;
  - one **BlobRegDO**, which registers R2 blobs and their registration time;
  - one **RealtimeDO**, which holds the WebSocket connections and the live feed;
  - one **CheckpointDO**, which signs the heads of the public data every 60 s;
  - the **directory** in D1 (accounts and key wraps);
  - R2 for blobs.

### 0.2 Adversaries

| name | capability |
| ---- | ---------- |
| **P** | Public reader. Reads and archives everything stored, forever, and may later own a quantum computer. **P\*** = P plus active use of every public API (including the WebSocket). |
| **O** | The operator / platform. Sees every request when it happens (IP, path, timing, WebSocket topics), can run arbitrary server code, and can delay, omit or reorder responses. Cannot break the cryptography. |
| **M** | A member of a conversation, possibly malicious. M holds the epoch keys of the epochs it belongs to, and may write any row an outsider can write plus rows under labels it can compute. |

### 0.3 Guarantees in stage 1

1. **Confidentiality.** Message text, images, conversation names and member lists are confidential against everyone
   who holds none of: a member's passkey PRF output, recovery code or AK, or the epoch key. This holds against a
   quantum P: every key is delivered with X-Wing, and everything else is 256-bit symmetric.
2. **Unlinkability against P.** Rows carry no sender, recipient, conversation, epoch or counter. Labels are
   independent PRF outputs. P learns the era, `t` (Δ-rounded), the size class of each row, inbox counts per slot, the
   public directory, and, once per hour, whether any blob was registered (§9.5). §13.1 lists the timing patterns.
3. **Recipient anonymity of invites against P, including a quantum P.** Inbox invites are found by X-Wing trial
   decapsulation, so no detection tag exists. In v1 this held against a classical P only.
4. **Authenticity among members.** Every conversation row is signed with Ed25519 by its sender inside the AEAD.
   Replays into another slot, era, epoch or conversation fail, because the AAD and the signature bind `E`, `label`,
   `conv` and `e`.
5. **Forward exclusion.** Members removed from a conversation cannot read later epochs and do not learn who was
   added: the new descriptor is encrypted under the new epoch key (§5.4). The claim's public `rm` bits (§6.2) tell
   every member of the old epoch, removed ones included, which old members were dropped, so a removed member learns
   which old members stay. v1 revealed the whole new member list to removed members.
6. **Membership liveness against members.** Junk, unsigned and e-invalid rows never freeze membership changes (§6).
   A member who signs an e-valid claim can still stop membership changes, and is named for it:
   - if it publishes an invalid new descriptor, or a key entry that is wrong for any continuing member (withholding
     the new key from some members or from all of them), membership freezes for the **whole** conversation. Every
     kept entry is derived from the new epoch key, so every member who obtains that key recomputes every kept entry
     and reaches the same verdict as the members whose entry failed (§5.4, §6.6): no member is ever left behind in an
     older epoch. v1 froze only the members whose invite was missing (§13.2 item 14);
   - messaging in the old epoch continues, as in v1, unless the freezing claim removed a member who had not left.
     That member still holds the old epoch's keys, so stage 1 refuses texts and images there (§11.3), where v1 let the
     frozen members keep writing to it.

   Validity never depends on the directory: every descriptor carries each member's signing key and a hash of its KEM
   key (§5.1).

   A malicious member can also spam.
7. **Portability.** Any device can restore every conversation and its full history with a passkey or the recovery
   code alone. The cost depends on the number of conversations and members, on the epochs since the last snapshot,
   and on the activity since the account last recorded its processed positions (HEADS, §7.3). It does not depend on
   the length of the history (§11.4).
8. **Detection (partial) of server misbehaviour:**
   - row immutability (body, `t` and class) is checked whenever a row is seen twice;
   - per-lane omission is detected through the `prev` / `prevh` chain, including rows beyond a hole (§12.2);
   - signed receipts prove that a write was accepted;
   - a signed checkpoint chain, persisted locally, detects rewrites and rollbacks;
   - checkpoint references inside messages (`ck`, 16 bytes) detect checkpoint forks between members (§12).

### 0.4 Non-guarantees

These hold in stage 1. §13 has the full leakage table and the explicit list of weakenings compared with v1.

- O sees the social graph: each WebSocket topic set, each point lookup, each writer IP, and a prefix of every
  directory lookup. Hiding this needs OHTTP / PIR (stage 2/3).
- O can selectively omit rows, or give different members different answers (including about blob registration and
  the directory), without clients being able to prove it in stage 1. There are no inclusion proofs and no witnesses
  (§12.6).
- No forward secrecy if a passkey PRF output, recovery code or AK leaks. No post-compromise security within an epoch.
- No deniability among members. No deletion: the archive is public. No censorship resistance.
- Not defended against: malicious served JavaScript; a malicious member who signs an unusable claim (freezing
  membership for the whole conversation, attributably, and messaging too when the claim removes someone) or spams;
  anyone who fills the global inbox day cap (§9.3), which delays first contact and inbox deliveries for everyone, for
  as long as it keeps refilling the cap every day; and directory key substitution by O (detected only by fingerprint
  comparison, TOFU pins (CONTACT, MEMBER) and disagreement with the keys in descriptors).

## 1. Primitives and encoding

### 1.1 Primitives

| name | definition |
| ---- | ---------- |
| `H(x)` | SHA-256 |
| `HKDF(ikm, salt, info, L)` | HKDF-SHA-256. `L` = 32 unless stated. |
| `HMAC(k, m)` | HMAC-SHA-256 |
| `AEAD` | XChaCha20-Poly1305 with a 24-byte **random** nonce and a 16-byte tag. `aeadSeal(k, pt, aad) = nonce ‖ ct ‖ tag`. `aeadOpen` is its inverse and throws on any failure. |
| `KEM` | X-Wing (`ml_kem768_x25519`, `@noble/post-quantum/hybrid.js`). `keygen(seed32)`; pk is 1216 B, sk 32 B, ciphertext 1120 B and shared secret 32 B. Decapsulating a ciphertext made for another key returns an unrelated secret (implicit rejection). Decapsulation **may throw** on a malformed ciphertext, for example a low-order X25519 component; whether it throws does not depend on the recipient's key. Every caller (inbox scan, SGB2 entries, hellos, wraps) MUST catch the throw and treat it as "does not open". |
| `SIG` | Ed25519 (RFC 8032 PureEdDSA, no context) with a 32-byte seed as sk. **Keys.** `validSigPk(A)` holds iff A is 32 bytes, decodes canonically (`y < p`; if `x = 0` the sign bit is 0), is not of small order (`[8]A ≠ O`), and lies in the prime-order subgroup (`[L]A = O`). Implementations MAY cache the result per key. **Verification.** `SIG.verify(A, M, sig)` is true iff all of these hold: `validSigPk(A)`; `len(sig) = 64`; `R = sig[0..32]` decodes canonically by the same rule (R may have any order); `S = sig[32..64]`, read little-endian, satisfies `S < L`; and, with `k = SHA-512(sig[0..32] ‖ A ‖ M) mod L` over the exact bytes, the **cofactored** equation `[8]([S]B − R − [k]A) = O` holds. This is `@noble/curves` 2.4.0 `ed25519.verify(sig, M, A, {zip215: false})` plus the subgroup check of A. Every decision that clients must reproduce identically (rows, claims, `dsig`, bundles, wraps, receipts, checkpoints) MUST use exactly this rule; a cofactorless verifier (such as WebCrypto Ed25519) MUST NOT be used for them. The Worker MAY use WebCrypto for the directory signatures it checks (§10.6): it also runs `checkUserKeys`, and clients re-verify every bundle and wrap with this rule. |
| `random(n)` | n bytes from a CSPRNG |

### 1.2 Encoding

All integers are unsigned and big-endian.

| notation | meaning |
| -------- | ------- |
| `u8, u16, u32, u64` | Fixed width. Encoders MUST reject values out of range (no truncation). |
| `utf8(s)` | UTF-8 bytes. Decoders MUST reject invalid UTF-8: valid means well-formed per RFC 3629, as WHATWG `TextDecoder("utf-8", {fatal: true})` decides (no overlong forms, no surrogate code points, nothing above U+10FFFF). U+0000, noncharacters and a leading U+FEFF are valid and kept: decoders MUST NOT strip a leading U+FEFF (a BOM), so `ignoreBOM: true`. Code points are counted on that decoded text, a leading U+FEFF included. |
| `a ‖ b` | Raw concatenation. |
| `lp(b) = u32(len(b)) ‖ b` | Length-prefixed bytes. |
| `enc(a, b, …) = lp(a) ‖ lp(b) ‖ …` | A string argument is `utf8`-encoded first. An integer argument written `u16 x` (etc.) is its fixed-width encoding, so `enc("L", u16 5) = 00000001 4C 00000002 0005`. A list argument `[x, y, …]` contributes one `lp` per element, in order. |
| `dec(b, k)` | Inverse of `enc` for exactly k fields. Fails on missing or trailing bytes. |
| `t16(x)` | The first 16 bytes of x. `t8(x)` is the first 8 bytes. |
| `b64u` | base64url **without** padding, **canonical**: decoders reject padding, characters outside the alphabet, and non-zero leftover bits. Every binary value inside JSON is `b64u`. |
| `ZERO16`, `ZERO32` | 16 or 32 zero bytes. |

Fixed binary layouts are written `field | field | …`. `x[n]` is exactly n bytes. Every parser MUST reject trailing
bytes, short input, and out-of-range enums. All labels (HKDF info, HMAC and AEAD domain strings, signature contexts)
are ASCII strings starting with `segv.sh/v2/`.

**Time and sequence fields.** These `u64` fields hold values ≤ 2^53 − 1, and encoders and parsers MUST reject larger
values: `ts` of D (§5.1), M (§3.3), S (§7.1) and S2 (§7.4), `lastTs` of a HEADS entry (§7.2), and in realtime frames
(§10.8) `now_ms` and `seq` of HELLO, `seq` of ROWS and `since_seq` of RESUME and GAP. The routing value of §4.4 is
not affected; the PoW nonce has the same bound, set in §10.2 (round 8).

**Signed JSON rule** (directory only). A signed JSON object is sent as the exact UTF-8 text its signer produced.
Verifiers MUST verify the signature over exactly those bytes, and nobody re-serialises signed JSON. Before verifying,
a verifier MAY parse the object strictly (exact key order, field shapes, and at the server canonical form) only to find
the verifying key: a bundle's own `sig` (which must pass `validSigPk`, §1.1), a wrap record's `uid` (to find the
registered bundle that signs it), or at unlock the `wrap` that yields the AK whose re-derived `sigPk` verifies the
record (§2.4). No field of the object is used, stored, displayed or compared for any other purpose until the signature
has verified. The server additionally requires canonical form: the keys appear in the order the spec lists, there are
no extra keys, and `JSON.stringify(JSON.parse(text))` equals `text`.

### 1.3 Padding

- `pad(x, classes)` returns `x ‖ 0x80 ‖ 0x00…`, extended to the smallest class `c` with `c ≥ len(x) + 1`. It is an
  error if no class fits.
- `unpad(y)` strips trailing `0x00` bytes, then requires one `0x80` and strips it.
- `padme(x)` uses the same marker. The target length is `Padmé(len(x) + 1)`:
  `L ≥ 2: E = ⌊log2 L⌋, S = ⌊log2 E⌋ + 1, z = E − S, result = ⌈L / 2^z⌉ · 2^z`. Implementations MUST use arithmetic
  here, not 32-bit bitwise operators.

### 1.4 Sealing (KEM-DEM)

```
seal(pk, label, ctx, pt):
  (kct, ss) = KEM.encap(pk)
  k = HKDF(ss, H(kct), enc("segv.sh/v2/seal", label, ctx), 32)
  return kct ‖ aeadSeal(k, pt, aad = enc(label, ctx))          // len = 1120 + 24 + len(pt) + 16
open(sk, label, ctx, box): the inverse. Throws on failure.
```

A **dummy seal** of length `n` is `seal(pkD, label, ctx, random(n))`, where `pkD` comes from `KEM.keygen(random(32))`
and is discarded. Nobody can tell it from a real seal.

## 2. Accounts and the directory

Changes from v1 §2:

- Every label moves to `segv.sh/v2/`, including the PRF input.
- The bundle drops the X25519 scan key: invite detection is now PQ trial decryption (§5.3).
- Bundles and wraps live in the D1 **directory** (§9.6). They are no longer log rows.
- Lookups by other users go through k-anonymous prefix queries. A client looks a co-member up once and keeps the result
  in a MEMBER self record (§7.2), so restores do not repeat the lookups (except for a uid that has no directory
  bundle, §7.3).
- Descriptors carry each member's `sigPk` and a hash of its `kemPk` (§5.1), and key bundles carry the `kemPk`s
  themselves (§5.4). The directory supplies handles, and the keys of a user only when that user is resolved by handle
  (creation, add) or, for a link, by uid (§5.5). It never decides whether a row, claim or descriptor is valid; its
  `sigPk` is used only for the `D.by` key check of first-contact and skip joins (§6.7).

The following are unchanged: AK as the root of every secret, per-passkey and recovery wraps, the `auth` mix-in, the
strict signature checks, the lost-response handling, and "refuse if two accounts open".

### 2.1 Account key and identity keys

`AK` = 32 random bytes. It never leaves the client, except wrapped (§2.4).

```
sigSk   = HKDF(AK, "", "segv.sh/v2/id/ed25519", 32);  sigPk = Ed25519.pub(sigSk)
kemSeed = HKDF(AK, "", "segv.sh/v2/id/xwing",   32);  (kemPk, kemSk) = KEM.keygen(kemSeed)
kS = HKDF(AK, "", "segv.sh/v2/self/aead",   32)       // self lane (§4.1)
rS = HKDF(AK, "", "segv.sh/v2/self/route",  32)
nS = HKDF(AK, "", "segv.sh/v2/self/notify", 32)
```

- `uid` = 16 random bytes, public.
- `handle` matches `^[a-z0-9_]{3,20}$` and is unique.
- `checkUserKeys(sigPk, kemPk)`: `validSigPk(sigPk)` (§1.1: canonical, not of small order, in the prime-order
  subgroup), and `KEM.encap(kemPk)` succeeds. Whether an X-Wing encapsulation succeeds depends only on the key, never
  on its randomness (the ML-KEM modulus check and the X25519 all-zero check reject the same keys for every
  randomness). The server runs it at registration, and clients run it on every bundle they use.

### 2.2 Bundle (public identity)

```
bundleBytes = utf8(JSON.stringify({v:2, uid:b64u(uid), handle, sig:b64u(sigPk), kem:b64u(kemPk), ts:<ms>}))
bundleSig   = SIG.sign(enc("segv.sh/v2/bundle", bundleBytes), sigSk)
```

- `ts` is the signer's clock in Unix ms: a JSON integer in 0..2^53 − 1 (canonical, §1.2). It is informational. The
  server MUST NOT compare it with its own clock, and no client or server decision depends on it. The time the
  directory keeps is `reg_era` = era(server time at registration) (§9.6). The same holds for `ts` of `recordBytes`
  (§2.4).
- Fingerprint: `fp = H(enc("segv.sh/v2/fp", uid, sigPk, kemPk))`. It is displayed as 6 groups of 5 decimal digits;
  group k = `(u40 of fp[5k..5k+5]) mod 100000`, zero-padded.
- Pin: `pin(u) = H(enc("segv.sh/v2/pin", bundleBytes, bundleSig))`. This is the TOFU value stored in CONTACT records
  (§7.2).

### 2.3 Unlock secrets

- PRF input: `prf.eval.first = utf8("segv.sh/v2/prf")`. The browser applies the WebAuthn PRF prefix. `prf` is 32
  bytes and never leaves the client.
- Passkey unlock key:

  ```
  credSeed = HKDF(prf, credId, "segv.sh/v2/cred/xwing", 32); (credPk, credSk) = KEM.keygen(credSeed)
  credAuth = HKDF(prf, credId, "segv.sh/v2/cred/auth", 32)
  ```

- Recovery code: `code` = 20 random bytes, shown once as Crockford base32 (32 characters in 8 groups of 4; the parser
  accepts `O→0`, `I/L→1`, any case, spaces and hyphens).

  ```
  recSeed = HKDF(code, "", "segv.sh/v2/recovery/xwing", 32); (recPk, recSk) = KEM.keygen(recSeed)
  recAuth = HKDF(code, "", "segv.sh/v2/recovery/auth", 32)
  recId   = HKDF(code, "", "segv.sh/v2/recovery/id", 16)
  ```

### 2.4 Wrap records

There is one record per passkey and one for the recovery code. Several records may share an id: ids are public, so
anyone can file a record under someone else's id with their own uid.

```
wrap        = seal(pkU, "segv.sh/v2/ak-wrap", enc(uid, id, auth), AK)         // 1192 B; pkU/auth = credPk/credAuth or recPk/recAuth
recordBytes = utf8(JSON.stringify({v:2, uid:b64u(uid), kind:"passkey"|"recovery", id:b64u(id),
                                   kem:b64u(pkU), wrap:b64u(wrap), ts:<ms>}))
recordSig   = SIG.sign(enc("segv.sh/v2/wrap", recordBytes), sigSk)
```

The rules for each field:

- `id` is `credId` (1..1023 bytes) or `recId` (16 bytes).
- `kem` is 1216 bytes.
- `wrap` is 1192 bytes.
- `ts` is the signer's clock, informational and never compared with server time (§2.2).
- The server accepts a record only if `recordSig` verifies under the `sigPk` of the bundle registered for `uid`. So
  nobody can file a record for someone else's uid.
- `auth` is what stops anyone from filing a wrap of *their own* AK that opens with the victim's secret.

**Unlock** (`unwrapFrom`):

1. Take the records for `id` (and `uid` if known) with the right `kind`.
2. For each one, `AK = open(skU, "segv.sh/v2/ak-wrap", enc(uid, id, auth), wrap)`. Skip records that fail.
3. Require `len(AK) = 32`, re-derive `sigPk` and require `recordSig` to verify under it.
4. If records of more than one uid open, refuse.
5. After the unlock, the client fetches its own bundle (§11.1). If its `sig` or `kem` differs from the derived keys,
   or the uid is not registered, the session is **fatal**.

A failed unlock MUST NOT create keys or write anything.

### 2.5 Registration, login, adding a passkey

**Register**:

1. Normalise the handle (trim, lowercase, strip one leading `@`).
2. Check that it is free with a handle-prefix query (§10.6), filtering locally.
3. Generate `AK` and `uid`, then build the bundle.
4. Call `navigator.credentials.create` with:
   - `rp.id` = the page hostname, `user.id = uid`;
   - `residentKey: "required"`, `userVerification: "required"`;
   - algorithms [-8, -7, -257];
   - `extensions.prf.eval.first` = PRF input.
5. If no PRF result came back, run `get()` immediately with `allowCredentials: [credId]`. If there is still no PRF,
   forget the credential and abort.
6. Build the passkey and recovery records and `POST /api/v2/register`.
7. On a 4xx: forget the credential (409 means "taken").
8. On a network error or 5xx: query the handle prefix. The registration landed only if the directory returns exactly
   this `bundleBytes` for the handle. Otherwise fail, and forget the credential only if another bundle holds the
   handle.
9. Show the recovery code once.

**Login**:

1. Call discoverable `get()` (empty `allowCredentials`, UV required, PRF).
2. `rawId` = credId, and `userHandle` = uid if present.
3. `GET /api/v2/dir/wraps/{credId}[?uid=]`, then unlock.

**Recovery login**: `GET /api/v2/dir/wraps/{recId}` (no uid), then unlock.

**Add passkey** (signed in): create a credential bound to the same uid, then `POST /api/v2/wraps`.

The server never sees WebAuthn data.

**Directory lookups of other users** use prefixes:

- `hpre(handle) = u32(H(enc("segv.sh/v2/dir/handle", handle))[0..4])`
- `upre(uid) = u32(H(enc("segv.sh/v2/dir/uid", uid))[0..4])`

A query names only the top `p` bits (§10.6), so O learns one of about 64–128 accounts (all accounts while there are
fewer than 64). The client bounds `p` by the
public dirlog size, so a server that overstates its user count cannot make lookups exact without inflating the
audited dirlog. This is still more than v1 revealed: v1 clients resolved handles locally from the full directory
(§13.2 item 10). Two lookups are exact, and both match v1: a client's own bundle by uid (it already reveals its uid
when it unlocks), and wrap records by id.

## 3. Clock, eras, classes, envelopes

### 3.1 Clock and eras

```
T0        = 2026-01-05T19:00:00Z  (= 1767639600000 ms)        Monday 19:00 UTC = Tuesday 04:00 JST
ERA_MS    = 604 800 000                                      one week
era(ms)   = ⌊(ms − T0) / ERA_MS⌋                              u16; start(E) = T0 + E·ERA_MS; end(E) = start(E+1)
sec(ms)   = ⌊(ms − T0) / 1000⌋                                u32 seconds since T0
tpub(ms)  = ⌊sec(ms) / Δ⌋ · Δ                                 the only time ever stored with a row
```

- `Δ` (seconds, 1 ≤ Δ ≤ 3600), `SKEW` (seconds, 0 ≤ SKEW ≤ 60; the bound on clock differences between server
  components) and `Δin` (`INBOX_SLOT`, seconds, 1 ≤ Δin ≤ 3600, §9.3) are deployment parameters reported by
  `/api/v2/params`. `E_FIRST` (§9.7) is in 0..0xFFFE.
- **Δ MUST divide `ERA_MS/1000 = 604 800`.** Then `sec(start(E))` is a multiple of Δ for every E, so every stored `t`
  (§9.1, §9.2) is a multiple of Δ, and `now ≥ t` implies `tpub(now) ≥ t`, which §6.4(g) needs for a MISS to be final.
- **Δ and Δin are constants of a deployment.** They MUST NOT change once any v2 Durable Object has stored data:
  BlobReg spans eras and §6.4(g) compares its times with shard times, and clients apply the inbox rule of §11.5 with
  the current Δin to past eras. Changing either needs a new deployment with empty v2 storage. `SKEW` MUST NOT change
  within an era. Durable Objects MAY pin Δ and Δin at their first write as a defence against operator error (ShardDO
  and BlobRegDO meta `'delta'`, InboxDO meta `'slot'`, §9.1–§9.3); an object whose pin differs from the deployment
  value MUST keep using the pin and SHOULD log the mismatch once per instance (one log line, §9.7; every pinning
  object, the ShardDO included). Pins do not make a change safe.
  `/api/v2/params` and `/api/v2/era/{E}` report the deployment values.
- A Worker whose configured Δ does not divide 604 800, or whose deployment parameters include one that is present but
  not a decimal in its range, MUST answer every `/api/v2/*` request with 503 `{error: "server misconfigured"}`, without
  any DO or D1 call. Clients MUST treat a params response whose `delta`, `skew` or `inboxSlot` breaks these bounds as a
  failed params request, and retry it with back-off.
- Production values are `Δ = 10` and `SKEW = 2`. Tests MAY use `Δ = 1` and `SKEW = 0`.
- Era 0xFFFF is reserved and means "none".
- **Lifetime.** `sec(ms)` is defined only for `T0 ≤ ms < T0 + 2^32·1000` (until 2162-02-12T01:28:16Z). The last era all
  of whose seconds fit in u32 is `E_LAST = 7100`, with `end(7100)` = 2162-02-08T19:00:00Z. Wire fields that carry an
  era accept 0..0xFFFE (0xFFFF is NONE), but no era above `E_LAST` is ever current. A component whose clock is outside
  `[T0, end(E_LAST))` is misconfigured, and the server MAY answer every request that depends on the time with a 5xx.
  Widening `sec` is a later stage's concern.
- **The server's components are the time authority.** Each Durable Object uses its own `Date.now()`. Clients estimate
  server time from the best recent server time sample (§10.1): the `x-segv-now` header of a `no-store` API response
  (never of a cacheable response, which may come from a cache with a stale header), `now` in `/api/v2/params`, or the
  realtime HELLO. Clients use it to pick `E` and to time waits (§6.3, §11.3, §11.5), and never trust it alone: a
  claim's e-validity is checked from server answers (§6.4), and the elapsed-time checks that guard a put (§11.3 steps 6
  and 8) also read the local monotonic and wall clocks.
- A position on a lane is a pair `(E, n)`, ordered lexicographically. **NONE** = `(0xFFFF, 0xFFFFFFFF)` sorts before
  every real position.
- A **position field** is `(Eprev, nprev)` of M and S, `(claimE, claimK)` of EPOCH, `(E, n)` of LEFT (round 9), or
  `(Eh, nh)` of SNAP and S2. If its E is 0xFFFF it MUST be exactly NONE: parsers reject `(0xFFFF, n)` with
  `n ≠ 0xFFFFFFFF`, and encoders refuse it. A position with `E ≠ 0xFFFF` may have any n. The `(E, cnt)` pairs are not
  position fields and have no parse-time range rule: the claim cuts (§6.2) and, in HEADS, `(ctlE, ctlCnt)`, the lane
  and followed-lane positions, and the inbox cursor `(Ein, relIn)`. §6.4(f) bounds the cuts.

### 3.2 Size classes

```
CLASSES   = [256, 1024, 4096, 16384]            cls = index 0..3; row body length = CLASSES[cls] + 40
```

| cls | plaintext | body | typical content |
| --- | --------- | ---- | --------------- |
| 0 | 256 | 296 | text ≤ 129 B, image reference, leave, welcome, most self rows, snapshot pointers |
| 1 | 1024 | 1064 | text ≤ 897 B, claims, decoys, self rows with EPOCH_PENDING or DELIVERED |
| 2 | 4096 | 4136 | text ≤ 3969 B, link hellos, large self rows |
| 3 | 16384 | 16424 | text ≤ 12000 B (the client limit), very large self rows |

Every row in a shard, whatever its content (message, claim, decoy, self record, snapshot pointer, hello), uses these
classes. P cannot tell them apart except by class.

| other object | length |
| ------------ | ------ |
| inbox invite body | 1120 + 24 + 256 + 16 = **1416** |
| SGB2 key bundle blob | 16 + 4136 + (B·1216 + 40) + B·1192 = 4192 + 2408·B, with B ∈ {8, 32}: **23456** or **81248** |
| key wrap / SGB2 entry | 1192 |
| image or snapshot blob | 24 + padme(len+1) + 16 (≤ 12 MiB) |

### 3.3 Conversation row envelope (M)

Every row on a conversation lane or control lane uses this envelope, encrypted under `mk_e` of its epoch:

```
M = u8 ver(=2) | u8 type | u16 from | u16 lane | u32 n | u16 Eprev | u32 nprev | prevh[16]
    | u64 ts | u32 ckq | ck16[16] | u16 len | content[len]                     (62-byte header)
sig  = SIG.sign(enc("segv.sh/v2/msg-sig", conv, u32 e, u16 E, label, M), sk_from)
body = aeadSeal(mk_e, pad(M ‖ sig, CLASSES), aad = enc("segv.sh/v2/msg", u16 E, label))
```

| field | meaning |
| ----- | ------- |
| `type` | 1 TEXT, 2 IMAGE, 8 WELCOME, 16 CLAIM, 17 LEAVE. Every other value is invalid. |
| `from` | The sender's index in `D_e` (§5.1). |
| `lane` | For lane rows (types 1, 2, 8, 17): equal to `from` (stage 1: one lane per member). For CLAIM: `0xFFFF`. |
| `n` | The slot within era `E`: the lane counter, or `k` for CLAIM. |
| `Eprev, nprev, prevh` | Lane rows only: the position of the sender's previous **valid** row on this lane in this epoch, and `prevh = t16(H(enc("segv.sh/v2/prev", label_prev, body_prev)))`, where `body_prev` is that row's stored body. For the first row of the lane in the epoch, and for every CLAIM: NONE and `ZERO16`. |
| `ts` | The sender's clock in ms (display only, §11.8). |
| `ckq, ck16` | The sender's latest verified checkpoint: `q` and `t16(C_q)`. `(0, 00…)` if it has none (§12.3, §12.4). |

**Parse rules** (normative; they decide "the envelope parses" in §6.4(a)). A body *does not decrypt* if its length is
not a class body length (§3.2) or `aeadOpen` fails. Otherwise the row is *malformed*, and is not accepted, unless all
of these hold:

1. `unpad` (§1.3) succeeds. The result x has `len(x) ≥ 62 + 64`; `M` = x without its last 64 bytes, and `sig` = the
   last 64 bytes.
2. `ver = 2` and `type ∈ {1, 2, 8, 16, 17}`.
3. `from < 32`.
4. `type = 16` (CLAIM): `lane = 0xFFFF` and `(Eprev, nprev)` = NONE. Every other type: `lane = from`.
5. `(Eprev, nprev)` obeys the position rule (§3.1).
6. If `(Eprev, nprev)` is NONE, `prevh = ZERO16`.
7. `ts ≤ 2^53 − 1` (§1.2).
8. If `ckq = 0`, `ck16 = ZERO16` (checkpoints start at q = 1, §9.5).
9. `len(M) = 62 + len`.
10. The content rule of the type holds (below). A CLAIM's content has `1 ≤ m ≤ 32` and exactly `137 + 6m` bytes
    (§6.2).

Nothing else is a parse rule: `n`, `prevh` when prev is not NONE, `ck16` when `ckq > 0`, and the order of prev relative
to `(E, n)` are checked by §12.2 and §12.4 only. The parse needs no epoch context.

A receiver accepts a row only if it parses and all of these hold:

- `from < |D_e|`;
- the label recomputes: `Lmsg_e(from, E, n)` for lane rows, or `Lctl_e(E, n)` for a CLAIM;
- a CLAIM has `m = |D_e|`;
- `sig` verifies (§1.1) under `D_e.members[from].sigPk`, the key carried in the descriptor (§5.1), never a directory
  key.

A row that decrypts but fails any of these "fails another rule" (§6.4 Outcomes): on a lane it is junk, and on the
control lane it is not e-valid. A row that is not accepted still occupies its slot (§4.2).

Content rules:

- **TEXT (1)**: 1..12000 bytes of valid UTF-8.
- **IMAGE (2)**: `id[32] | k[32] | u8 mime | u16 w | u16 h` (69 B), with `mime` 1 = image/webp or 2 = image/jpeg and
  `1 ≤ w, h ≤ 8192`.
- **WELCOME (8)**: a join payload `J` (§5.2), 90 B.
- **CLAIM (16)**: see §6.2.
- **LEAVE (17)**: `len = 0`.

## 4. Derivations

### 4.1 Self lane (per account; shared by all devices of the account)

```
Lself(E, n) = t16(HMAC(rS, enc("segv.sh/v2/lab/self", u16 E, u32 n)))     device-state records (§7)
Lsnap(E, j) = t16(HMAC(rS, enc("segv.sh/v2/lab/snap", u16 E, u32 j)))     snapshot pointers (§7.4)
Tself       = t16(HMAC(nS, utf8("segv.sh/v2/topic/self")))                 realtime topic
```

### 4.2 Conversation epochs

A conversation has a secret id `conv` (16 random bytes) that is never public, and epochs `e = 0, 1, …`. Each epoch has
a fresh random `EK` (32 B).

```
rk_e  = HKDF(EK_e, conv, enc("segv.sh/v2/ep/route",  u32 e), 32)
mk_e  = HKDF(EK_e, conv, enc("segv.sh/v2/ep/msg",    u32 e), 32)
kc_e  = HKDF(EK_e, conv, enc("segv.sh/v2/ep/commit", u32 e), 32)
nk_e  = HKDF(EK_e, conv, enc("segv.sh/v2/ep/notify", u32 e), 32)
dk_e  = HKDF(EK_e, conv, enc("segv.sh/v2/ep/desc",   u32 e), 32)
ekc_e = H(enc("segv.sh/v2/ekc", conv, u32 e, EK_e))

Lmsg_e(ℓ, E, n) = t16(HMAC(rk_e, enc("segv.sh/v2/lab/msg", u16 ℓ, u16 E, u32 n)))   member lane ℓ = index in D_e
Lctl_e(E, k)    = t16(HMAC(rk_e, enc("segv.sh/v2/lab/ctl", u16 E, u32 k)))          control lane (claims)
T_e             = t16(HMAC(nk_e, utf8("segv.sh/v2/topic/conv")))                     realtime topic of epoch e
```

- **Lanes.** In stage 1 there is one lane per member, `L_e = |D_e| ≤ 32`, and lane `ℓ` belongs to
  `D_e.members[ℓ]`. Only that member's devices write it, and they share the counter (§11.7).
- **Counters.** `n` (and `k`) restart at 0 in every era.
- **Dense prefixes.** Slots fill densely within an era: honest writers always write the first empty slot. The **dense
  prefix** of a lane in era `E` is the slots `(E, 0..h−1)` up to and including the last one before the first empty slot
  `(E, h)`. Writers and the control lane use only the dense prefix. Any row of any content inside the prefix
  *occupies* its slot, junk included. Junk beyond a hole is ignored. A validly signed lane row beyond a hole is evidence
  that the server omitted the hole: receivers accept it through its `prev` chain and warn (§12.2).
- **Lane head.** The lane head is the last slot of the dense prefix of the latest era that has one, or NONE.
- **Epoch start.** `E_start(e)` = `era(t_reg)` of the SGB2 bundle that defines epoch e (§5.4, §8.2). No row of epoch
  e is in an earlier era (§6.1 and §6.3 write nothing for e before `t_reg` is known), so clients never probe earlier
  eras.

### 4.3 Links (out-of-band first contact)

```
link     = "https://<host>/i#" + b64u(u8 2 ‖ s[16] ‖ uid_inviter[16])     the fragment never reaches the server
kL = HKDF(s, "", "segv.sh/v2/link/route", 32);  mL = HKDF(s, "", "segv.sh/v2/link/aead", 32)
nL = HKDF(s, "", "segv.sh/v2/link/notify", 32)
Lhello(E, j) = t16(HMAC(kL, enc("segv.sh/v2/lab/hello", u16 E, u32 j)))
Tlink        = t16(HMAC(nL, utf8("segv.sh/v2/topic/link")))
```

### 4.4 Server routing

These derivations are the server's only (§9.1).

```
kroute_E = HMAC(ROUTE_KEY, enc("segv.sh/v2/route", u16 E))                ROUTE_KEY: 32-byte Worker secret
kcommit_E = H(enc("segv.sh/v2/kroute", kroute_E))                         published in params / era info
v(E, label) = u64(HMAC(kroute_E, label)[0..8]) >> 1                       63-bit routing value; stored as 8-byte big-endian
shard(E, label) = v >> (63 − s_E)                                         stage 1: s_E = 0 ⇒ shard 0
```

## 5. Descriptors, joins and key bundles

### 5.1 Descriptor D (binary)

```
D = u8 ver(=2) | conv[16] | u32 e | prev[32] | by[16] | u64 ts | u8 m | (uid[16] | sigPk[32] | kh[32]) × m
    | u16 nlen | name[nlen]
kh   = H(enc("segv.sh/v2/kh", kemPk))                                    the member's X-Wing key, by hash
dsig = SIG.sign(enc("segv.sh/v2/epoch", D, kc_e), sk_by)                 verified under D's own sigPk of `by`
```

The rules:

- `1 ≤ m ≤ 32`, and the uids are distinct.
- Every `sigPk` passes `validSigPk` (§1.1; the `sigPk` half of `checkUserKeys`). A descriptor with a non-canonical,
  small-order or mixed-order `sigPk` does not parse.
- `by` is one of the uids.
- `e < 2^32 − 1`: the last epoch could have no successor, so it is never created or accepted.
- `e = 0 ⇔ prev = ZERO32`. Otherwise `prev = H(D_{e−1})`.
- `ts ≤ 2^53 − 1`.
- `nlen ≤ 256`. `nlen = 0` means no name. Otherwise `name` is valid UTF-8 of 1–64 code points, counted as §1.2 says
  (a leading U+FEFF is kept and counts). These are the only rules a parser applies to the name.
- Nothing follows `name`. The maximum length is 78 + 80·32 + 2 + 256 = 2896 B.

`members[i] = (uid, sigPk, kh)` is member index `i`, which is also lane `i`. Clients display chosen names with a `#`
prefix. `H(D)` is SHA-256 over these exact bytes.

**`validName`** is a rule for building and displaying names, never for parsing:

- 1–64 code points, at least one of them `\p{L}\p{N}\p{P}\p{S}`;
- none of `\p{Cc}\p{Cf}\p{Cs}` or U+061C, U+2028, U+2029, U+115F, U+1160, U+3164, U+FFA0, U+2800;
- after NFKC and trimming leading whitespace, it does not start with `@`.

A creator or committer writes a new name only if it satisfies `validName` (§6.1, §6.3); a name carried over is copied
byte for byte. A reader displays a name only if it satisfies the reader's own `validName`; otherwise the conversation
is shown as unnamed (its other members are listed), and §11.9 treats the name as absent. The character classes and
NFKC depend on the Unicode version of the reader's JavaScript engine, so two readers may display a name differently,
but no validity decision (a descriptor, a join, the D′ checks of §6.6, a self record) depends on them.

**Keys in D.** Every signature of a member of epoch e (lane rows, claims, `dsig` of `D_{e+1}`) is verified under the
`sigPk` that `D_e` lists for it, and every key entry of the bundle that defines an epoch is sealed to the `kemPk` whose
hash `kh` the descriptors list (§5.4). The directory is never consulted for validity, so a later registration, or a
directory answer that differs between readers, cannot change any member's decision. Where the keys come from:

- the creator (§6.1) and a committer adding members (§6.3) copy each new member's `sigPk` and `kh` (and its `kemPk`,
  into the bundle) from that member's verified directory bundle;
- a committer copies every continuing member's `(uid, sigPk, kh)` from `D_e` unchanged, and its `kemPk` from the
  bundle of e, and §6.6 requires it;
- a recipient accepts a first-contact or skip join only if D's `sigPk` for `D.by` equals the `sigPk` of `D.by`'s
  verified directory bundle (§6.7), and any join only if D lists self with self's own `sigPk` and `kh`.

The directory supplies handles, and keys only for users resolved by handle (§6.1, §6.3) or, for a link, by uid
(§5.5). A member whose directory bundle is missing, fails `checkUserKeys`, has a `sigPk` different from the one in D,
or has a `kemPk` whose hash `H(enc("segv.sh/v2/kh", kemPk))` differs from the `kh` in D is shown as an unknown member
(§11.2); its rows still verify under the key in D, and its key entries are sealed to the `kemPk` the bundles carry.
So a descriptor cannot show a real user's handle for a slot whose key entries go to someone else's key.

### 5.2 Join payload J

J delivers an epoch to a member who does not get it through a claim: a creator's invitees, members added by a change,
and re-added members.

```
J = u8 ver(=2) | u8 type(=1) | conv[16] | u32 e | EK[32] | bundleId[32] | u32 bundleSize       (90 B)
```

J reaches its recipient by one of:

- an **inbox invite** (§5.3);
- a **WELCOME** row (type 8) in a conversation the sender and recipient both hold. Stage 1 senders SHOULD use a
  1:1 conversation that qualifies under §6.12 step 1 (the recipient provably holds and processes it) when one exists,
  and MUST NOT use any other conversation. The row is written only in an epoch of that 1:1 that still qualifies when
  the row is built (§11.3 step 2). Receivers MUST accept a WELCOME in any conversation, from any verified
  member, whenever they process the row: live, at catch-up, at restore (every row after the processed position, in
  every epoch since HEADS, §11.4) and in scrollback.
- a **link hello** (§5.5).

J itself is not signed. Authenticity comes from `dsig` over the descriptor stored in the bundle (§6.7).

### 5.3 Inbox invite (stage 1: β = 0, one bucket `0`)

```
eid = random(16); bucket = 0
(kct, ss) = KEM.encap(kemPk_recipient)
k    = HKDF(ss, H(kct), enc("segv.sh/v2/inv", u16 E, u32 bucket, eid), 32)
body = kct ‖ aeadSeal(k, pad(J, [256]), aad = enc("segv.sh/v2/inv", u16 E, u32 bucket, eid))       (1416 B)
```

`E` is the era of the InboxDO that accepts the row (the current era).

**Scanning.** For every inbox row the client fetches (§11.5):

1. `ss' = KEM.decap(kct, kemSk)`. A throw (§1.1) means "not for me".
2. Derive `k`, then `aeadOpen`. A failure means "not for me" and is **silent**: it is the normal case, and a junk
   invite addressed to me is indistinguishable from one addressed to someone else.
3. `unpad`, then parse J (`ver = 2`, `type = 1`, exactly 90 B). A J that is malformed but decrypted correctly gives a
   noise warning.

### 5.4 SGB2 key bundle (blob)

Every epoch, including e = 0, is defined by one bundle blob. The blob carries the encrypted descriptor, the encrypted
`kemPk` of every member, and one key wrap per index of the previous epoch.

```
blob = "SGB2" | u8 ver(=1) | u8 B | 00[10]                                        16-byte header
       | descCt                                                                    4136 B
       | pkCt                                                                      B·1216 + 40 B
       | entry_0 | … | entry_{B−1}                                                 B × 1192 B
descCt  = aeadSeal(dk_e, pad(D_e ‖ dsig_e, [4096]), aad = enc("segv.sh/v2/desc", conv, u32 e))     D ‖ dsig ≤ 2960 B
pks_e   = kemPk_0 ‖ … ‖ kemPk_{|D_e|−1} ‖ 00…           the kemPk of D_e.members[j] in D order, zero-filled to B·1216 B
pkCt    = aeadSeal(dk_e, pks_e, aad = enc("segv.sh/v2/pks", conv, u32 e))
entry_i = sealDet(pks_e[j], enc(conv, u32 e, u16 i), i)   for a kept X_i, where j is X_i's index in D_e;
          otherwise a dummy seal (§1.4) of a 32-byte value
bundleId = H(blob) (raw 32 B; the blob id is b64u(bundleId)); bundleSize = len(blob)
```

The 10 bytes after B are reserved and MUST be zero. A reader treats a non-zero byte there as a header mismatch.

**Derived entries.** A kept member's entry is a seal whose randomness comes from `EK_e`:

```
rr_e = HKDF(EK_e, conv, enc("segv.sh/v2/ep/rekey", u32 e), 32)
sealDet(pk, ctx, i):
  ρ        = HKDF(rr_e, "", enc("segv.sh/v2/rekey-rnd", u16 i), 88)
  (kct,ss) = KEM.encap(pk, ρ[0..64])                    X-Wing EncapsulateDerand: ρ[0..32] ML-KEM coins,
                                                         ρ[32..64] the X25519 ephemeral key (noble: encapsulate(pk, rnd))
  k        = HKDF(ss, H(kct), enc("segv.sh/v2/seal", "segv.sh/v2/rekey", ctx), 32)
  return kct ‖ ρ[64..88] ‖ ct ‖ tag                       XChaCha20-Poly1305 of EK_e under k, nonce ρ[64..88],
                                                         aad = enc("segv.sh/v2/rekey", ctx); 1192 B
```

The layout is exactly that of `seal(pk, "segv.sh/v2/rekey", ctx, EK_e)` (§1.4), so `open` opens it unchanged. `ρ` is a
PRF output under the 256-bit `EK_e`, which only the members of e hold. To everyone else an entry is distributed like
a seal with fresh randomness (the Fujisaki–Okamoto derandomization pattern, in the random-oracle model for HKDF).
Every member who holds `EK_e` can therefore recompute every kept entry byte for byte from `pks_e`, and §6.6 requires
it: a wrong kept entry (a withheld key, a seal to another key, fresh randomness) is seen by every member who obtains
`EK_e`, not only by its owner.

- **B.** B = 8 if `max(|D_prev|, |D_e|) ≤ 8`, otherwise B = 32. For e = 0, B = 8 if `|D_0| ≤ 8`, otherwise 32.
- **pks.** `kemPk_j` passes the `kemPk` half of `checkUserKeys`, and `kh` of `D_e.members[j]` is its hash (§5.1). A
  committer copies a continuing member's `kemPk` from `pks_{e−1}` (the bundle of e−1), never from the directory. A
  new member's `kemPk`, and for e = 0 every member's, comes from its verified directory bundle (the bundle passes
  `checkUserKeys`, its `sigPk` is the one put in D, and it agrees with the MEMBER and CONTACT pins, §7.3); the
  creator's or committer's own comes from its identity.
- **Entries for e > 0.** For `i < |D_{e−1}|`, `X_i = D_{e−1}.members[i]`. If `X_i ∈ D_e` (its `rm` bit is 0), the
  entry is `sealDet` to its `kemPk` in `pks_e`. Otherwise (the member was removed, or left and was dropped) the entry
  is a dummy seal, and X_i learns its removal from `rm`. Every `i ≥ |D_{e−1}|` is a dummy seal.
- **Entries for e = 0.** Every entry is a dummy. All members receive J.
- **New members** (in `D_e` but not in `D_{e−1}`) have no entry. They receive J.
- **Removal is public to the old epoch.** The claim that points at the bundle carries `rm` (§6.2), so every member of
  `D_{e−1}` sees who is dropped. Nobody reads a dropped member's entry (§6.6 step 3).
- **What the layout hides.**
  - P cannot list bundles (§8.2). Anyone who learns a bundle id learns only B.
  - Members of e can recompute the other members' entries, which gives them only `EK_e`, which they hold. Members of
    e−1 who are not in e cannot open or recompute any entry.
  - A removed member learns that it was removed and, from `rm`, which old members stay. It cannot read `D_e` or
    `pks_e`, so it does not learn who was added or the new name.

### 5.5 Link hello

Bob (the link owner) creates `s`, writes a LINK record (§7.2), subscribes to `Tlink`, and shares the link. Links are
valid for at most 4 eras.

Alice opens the link:

1. Fetch Bob's bundle by uid prefix (§10.6), verify it, and run `checkUserKeys`. This resolves Bob for §6.1 step 1:
   his `sigPk`, `kh` and `kemPk` come from this bundle.
2. Create the conversation as in §6.1, but deliver J to Bob as a hello row instead of an inbox invite:

   ```
   inner = seal(kemPk_Bob, "segv.sh/v2/hello", enc(H(s)), J)                        1250 B
   body  = aeadSeal(mL, pad(inner, CLASSES), aad = enc("segv.sh/v2/hello", u16 E, label))   cls 2 (4136 B)
   ```

   The row is put at `label = Lhello(E_now, j)` for the first empty `j`, with topic `Tlink`.

Bob's side:

- Bob receives the row on `Tlink`, or probes `Lhello(E, j..)` up to the first MISS for every era E of the link's
  lifetime.
- He opens both layers and accepts J as a first contact (§6.7).
- One-shot links stop listening after the first valid hello.

The inner seal exists because every holder of the link knows `mL`. P sees one ordinary class-2 row. A link holder
learns only how many hellos there are and when.

## 6. Epoch changes

### 6.1 Creating a conversation (epoch 0)

The creator C:

1. Resolve the other members' handles (§10.6) and verify their bundles. Require `2 ≤ m ≤ 32`.
2. Build `conv = random(16)`, `EK_0`, and `D_0`:
   - `members = [(C, sigPk_C, kh_C), …others]`, each other member with the `sigPk` and `kh` of its verified bundle;
     `prev = ZERO32`, `by = C`;
   - the name, if any, is cleaned by the client and then must satisfy `validName` (§5.1).
3. Compute `dsig_0` and build the SGB2 blob (`pks_0` from the same bundles; all entries dummy).
4. `PUT /api/v2/blob/{id}`. The response carries `t_reg`. A crash before this step completes leaves at most an unused
   blob.
5. Write one self row holding CONV_JOIN (`via = created`) and EPOCH_PENDING (`e = 0`, `t_reg`,
   `uids = D_0 \ {C}`), padded to class 1 (§7.1). CONTACT and MEMBER records for the resolved users go into the next
   HEADS row (§7.3), so their number does not change the class of this row. From here on
   the conversation exists for every device of the account: `createConversation` resolves, with the copy in
   `conversations`. Steps 6–9 continue in the background.
6. Wait for the commit time (§6.3 step 5).
7. Put one **decoy row**: a random 16-byte label in the current era, `cls = 1`, and a body of 1064 random bytes, with no
   topic.
8. Deliver J to every other member (§6.12).
9. Write the DELIVERED row (§6.12 step 3).

The creator's sends in the new conversation are queued locally (the echo shows `sending`) until step 7 has completed.
So no row of the new conversation precedes the decoy, and every row of epoch 0 lies in an era ≥ `era(t_reg)` =
`E_start(0)`. If the session ends during steps 6–9, any device of the account finishes them (§6.11).

Steps 4–9 give a creation the same shape as a membership change (§6.3): a blob registration, a class-1 self row, one
class-1 row at least Δ+SKEW after the registration, then J deliveries and a class-1 self row. Nobody reads the decoy.
§13.1 lists what still differs. Members learn `E_start(0)` from the blob's `t_reg`.

### 6.2 Claim content (type 16 on the control lane)

```
content = prevD[32] | hD[32] | ekc[32] | bundleId[32] | u32 bundleSize | u32 rm | u8 m | cut[6] × m     (137 + 6m B)
cut_ℓ   = u16 E_ℓ | u32 cnt_ℓ
```

| field | value |
| ----- | ----- |
| `prevD` | `H(D_e)` |
| `hD` | `H(D_{e+1})` |
| `ekc` | `ekc_{e+1}` |
| `bundleId`, `bundleSize` | identify the SGB2 blob of e+1 |
| `rm` | Bit i (value `2^i`) is 1 iff `D_e.members[i]` is not in `D_{e+1}`: it was removed, or it had left and is dropped. Bits at or above `m` are 0, and the committer's own bit is 0. |
| `m` | `|D_e|` |
| `cut_ℓ` | The committer's observed dense prefix of lane ℓ at commit time: `(E, cnt)` = the era of the lane head and the length of that era's dense prefix. For an empty lane: `(E_start(e), 0)`. Cuts only decide rows stored in the same Δ batch as the claim (§6.8). |

`rm` is readable by every member of `D_e`, removed ones included. It makes removal a public, signed fact of the old
epoch, as v1's claim descriptor did, while who was *added* stays hidden in `D_{e+1}`.

A lane row `(E', n')` of epoch e is **before the cut** of lane ℓ iff `E' < E_ℓ`, or `E' = E_ℓ` and `n' < cnt_ℓ`.

The claim is an envelope M with:

- `type = 16`, `from` = the committer's index in `D_e`, `lane = 0xFFFF`, `n = k`;
- prev fields NONE / `ZERO16`, and `ts` set;
- `ck` set;
- `sig` (= csig) under the committer's key.

It is put at `Lctl_e(E, k)` with topic `T_e`. A claim is always cls 1: it takes between `62 + 143 + 64 + 1 = 270` B
(m = 1) and `62 + 329 + 64 + 1 = 456` B (m = 32).

### 6.3 Committing epoch e+1 (add, remove, rotate after a leave, rename)

The committer C is a member of `D_e` who has not left, has not been removed, and is not frozen in e.

1. **Catch up the control lane of e** (§6.5) until every slot of its prefix is decided. If an e-valid claim exists,
   abort with a conflict: follow it (§6.6) and retry on top of it if appropriate.
2. **Build the new epoch.** `EK' = random(32)`, then `D' = D_{e+1}`:
   - `prev = H(D_e)`, `by = C`, `C ∈ D'`;
   - every continuing member keeps its `(uid, sigPk, kh)` from `D_e`; every added member gets the `sigPk` and `kh` of
     its verified directory bundle (resolved by handle);
   - `|D'| ≤ 32`, and `e+1 < 2^32 − 1`;
   - the name is carried over byte for byte unless the commit renames; a new name must satisfy `validName` (§5.1).

   Then compute `dsig'`, `rm`, and the SGB2 blob (§5.4). Continuing members' `kemPk` come from `pks_e` in the bundle of
   e (fetched once if the device does not hold it); added members' from the bundles resolved by handle. A commit never
   looks a continuing member up in the directory, so a directory failure cannot produce a wrong entry.
3. **`PUT /api/v2/blob/{id}`.** The response is `{t: t_reg}`. An idempotent re-upload returns the original `t_reg`.
4. **Write EPOCH_PENDING** (§7.2) in a self row padded to class 1: conv, root, e+1, EK', bundleId, bundleSize, `t_reg`,
   and the uids that will need J (`D' \ D_e`, possibly none).
5. **Wait for the commit time.** Wait until both of these hold:
   - at least `(Δ + SKEW)·1000` ms of monotonic local time (`performance.now()`) have passed since the PUT response
     arrived;
   - the estimated server time (§3.1) satisfies `sec ≥ t_reg + Δ + SKEW`.

   BlobReg's clock normally read at least `t_reg` when it registered the blob, and the ShardDO clock lags it by at most
   SKEW, so the claim lands in a later Δ batch than the registration. Step 7 checks this from server answers alone: a
   wrong local clock costs a retry, never a fork.
6. **Catch up again.** Probe the control lane again (step 1) and every lane head of e. Compute the cuts from the
   observed lane heads.
7. **CAS the claim** at `Lctl_e(E_now, k)`, where `k` is the first empty slot of that era's dense prefix. At most 8
   attempts, counting WRONG_ERA and the retries below. Handle the result:
   - **OK(t).** If `t ≤ t_reg`, the claim is not e-valid (§6.4(g)): C treats `(E, k)` as an occupied, ignored slot,
     repeats step 5 from now, and continues at step 6. Otherwise C's claim is at `(E, k)`: go to step 8.
   - **CONFLICT(occupant).** If the occupant's body equals the sent body, treat it as OK with the occupant's `t` (a lost
     response). Otherwise evaluate the occupant (§6.4):
     - e-valid: C's commit lost. Abort with a conflict and process the winner (§6.6);
     - undecided: wait as §6.4 says and evaluate again. C never writes past an undecided slot;
     - not e-valid: continue at `k+1`, and gallop with an exists probe to the next empty slot.
   - **WRONG_ERA(E').** Recompute with `E = E'` and the first empty slot there. If `E'` was already tried for this
     commit, first wait until the estimated server time is past `end(min(E, E')) + SKEW`.
   - **FULL, a network error or a 5xx.** Probe the slot with `get` (body). Our body: as OK. Another body: as CONFLICT.
     A MISS: retry the CAS at the same slot.
8. **Decide.** Make every earlier slot of the control lane (in this era and in earlier eras) decided, and wait for
   finality (§6.5). If an earlier slot is e-valid, C's claim lost: abort and process the winner. Otherwise C's claim is
   the final winner.
9. **Switch to e+1** (§6.6). C's own entry opens like everyone else's.
10. **Deliver J** for e+1 to the uids of EPOCH_PENDING (§6.12), then write the DELIVERED row (§6.12 step 3).

The call (`addMembers`, `removeMember`, or a rotation before a send) resolves after step 9 and the first delivery
attempt of step 10. Deliveries that failed keep retrying in the background (§6.12).

Every await point MUST re-check that the session (account and generation) is unchanged. After an abort, C writes
nothing more for this commit, and the registered blob is simply never claimed. Whenever any device of C's account
learns that one of its own claims is the final winner, even after an abort or a crash, it completes steps 9–10
(§6.11).

### 6.4 e-validity

A row at `Lctl_e(E, k)` is **e-valid**, **not e-valid** or **undecided**. Every member of `D_e` evaluates the rules
below from public facts plus `mk_e`. As long as the server answers consistently, every member gets the same result.
The row is e-valid iff all of these hold:

- **(a)** It decrypts under `mk_e` with AAD `enc("segv.sh/v2/msg", u16 E, label)`, the envelope parses (every parse
  rule of §3.3) with `type = 16`, `lane = 0xFFFF` and `n = k`, the content has exactly `137 + 6·|D_e|` bytes, and
  `m = |D_e|`.
- **(b)** `from < |D_e|`. Stage 1 policy: any member may commit.
- **(c)** `sig` verifies under `D_e.members[from].sigPk`, the key listed in `D_e` (§5.1). Whether the committer is
  registered in the directory, now or later, plays no part.
- **(d)** `prevD = H(D_e)`.
- **(e)** `rm` has no bit at or above `m`, and bit `from` of `rm` is 0.
- **(f)** Every cut satisfies `E_start(e) ≤ E_ℓ ≤ E`. A reader that does not hold `t_reg` of e's own bundle (§4.2)
  learns it once with `GET /api/v2/blob/{id}/meta` (§11.4); until it has the answer, the row is undecided.
- **(g)** `bundleSize ∈ {23456, 81248}`, and BlobReg has `bundleId` registered with `size = bundleSize` and
  `t_reg < t_row`. Readers evaluate (g) before (h), so a claim that names a larger blob costs no blob download.
  `t_row` is the stored time of the claim row, taken from a `get` HIT or a CONFLICT, never from a realtime frame alone
  (§12.1). Evaluate with `GET /api/v2/blob/{id}/meta`:
  - **HIT** `{t, size}`: decide by the rule. Registrations are create-only and never change.
  - **MISS** `{now}`, where `now` is BlobReg's clock in seconds since T0:
    - If `now ≥ t_row`, (g) fails for good: any later registration gets `t_reg ≥ tpub(now) ≥ t_row` (`t_row` is a
      multiple of Δ, §3.1).
    - If `now < t_row` (only possible within SKEW of a batch boundary), (g) is undecided: retry after `t_row − now`
      seconds.
- **(h)** The blob, fetched with `GET /api/v2/blob/{id}`, hashes to `bundleId`, is `bundleSize` bytes long, and has the
  header `"SGB2"`, ver 1, `B ∈ {8, 32}` with `bundleSize = 4192 + 2408·B`, and 10 zero bytes (§5.4), and
  `B ≥ |D_e|`.

**Order of requests** (rounds 11–12). The **local rules** are (a)–(e), the `bundleSize` clause of (g), and
`B ≥ |D_e|` of (h), where `B = (bundleSize − 4192) / 2408` follows from `bundleSize`; (f) is local too when the reader
holds `t_reg` of e's own bundle. A reader makes no `blob/meta` request and no blob fetch for a row before its local
rules have passed; then it makes (f)'s `meta` request if it needs one, (g)'s `meta` request only after (f) has passed,
and (h)'s blob fetch only after (g) has passed. The `get` that supplies the row's body, or its `t_row` for (g) when the
row arrived in a realtime frame (§6.4(g), §11.6), is not ordered by this paragraph (round 12). So a row that fails a
local rule costs no `blob/meta` request and no blob fetch, and every reader that holds the same facts makes the same
such requests for it. The order among the local rules is free (preamble).

Outcomes:

- If any of (a)–(f) fails, or (g) or (h) fails definitively, the row is **not e-valid**. It is ignored: it still
  occupies its slot and is part of the dense prefix. A row that does not decrypt gives the noise warning "ignored an
  undecryptable message". A row that decrypts but fails another rule gives the noise warning "ignored an invalid
  membership change".
- A network error, a timeout, a 429, a 5xx, a 404 for a blob whose registration was seen, or a MISS with `now < t_row`
  makes the row **undecided**. The reader retries with backoff (1 s, doubling to 60 s; after a 429, no sooner than its
  `retry-after`).

### 6.5 Winner and finality

The control lane of epoch e is the sequence of slots `(E, k)` for `E ≥ E_start(e)`, in lexicographic order. Only
slots inside each era's dense prefix count.

- **Winner.** The winner is the first e-valid row in that order, provided every earlier slot is decided not e-valid.
  While an earlier slot is undecided there is no winner yet. Nothing a reader learns later (its own entry, `D'`)
  changes the winner, so every member of e agrees on it.
- **Finality.** A claim at `(E, k)` is **final** iff it is inside the dense prefix of era E (so every `(E, j < k)` is
  filled), and for every era E' with `E_start(e) ≤ E' < E`, the reader has observed the first empty slot of E''s
  prefix as `MISS(sealed = 1)`, or holds a HEADS record of its own account that covers E' (§7.2). A sealed era can
  never gain rows (§9.1).
- **Probing.** A client keeps, per epoch, the control position `(E_c, cnt_c)` it has observed. It probes
  `(E_c, cnt_c .. cnt_c+1)` and `(E', 0)` for each `E' ∈ (E_c, E_now]`, and gallops when every probe hits. An era
  `E' < E_now` observed `MISS(sealed = 1)` at `(E', 0)` is never probed again.
- Honest committers always CAS the first empty slot, so they never leave holes. A writer who leaves a hole only hides
  its own later rows until someone fills the hole, and the filler comes earlier in order.

### 6.6 Processing the winning claim

Every member X of `D_e` (index i), including members who left or will be removed, processes the final winning claim C
of e, made by `by = D_e.members[from]`:

1. The bundle was fetched for rule (h). Let `r` = bit i of `rm`.
2. Open `entry_i`: `V = open(kemSk, "segv.sh/v2/rekey", enc(conv, u32 e+1, u16 i), entry_i)`. A throw, an AEAD
   failure or `len(V) ≠ 32` means the entry does not open.
3. **If `r = 1`, X was removed** (or, having left, dropped). Whatever V is:
   - X sets the copy to removed (`canSend = false`) and shows "@by removed you", unless X has left.
   - X stops following new epochs. It keeps its old epochs for history.
4. **If `r = 0`**, X must get `EK'`:
   - The entry does not open, or `ekc_{e+1}(V) ≠ ekc`: X is **frozen** with the critical warning "@by's membership
     change was never delivered to you; the members of this conversation can no longer change". X cannot read `D'`
     and needs no more: its entry is not `sealDet` to the key whose hash `D_e` lists for it, so every member who
     obtains `EK'` finds one of the D′ checks below failing, and no member of e moves to e+1.
   - Otherwise `EK' = V`. Decrypt `descCt` with `dk_{e+1}(EK')`, unpad, and parse `D'` (it is self-delimiting; the
     last 64 bytes are `dsig'`). Decrypt `pkCt` with `dk_{e+1}(EK')` (aad `enc("segv.sh/v2/pks", conv, u32 e+1)`) to
     `pks'`. **The D′ checks** (against `D_e`, C and the bundle) are all of:
     - `descCt` and `pkCt` open under `dk_{e+1}(EK')`, and `D' ‖ dsig'` unpads and parses (every rule of §5.1, none
       of which depends on the reader's Unicode tables); a failure here is a failed check like any other, never an
       error that leaves the claim unprocessed;
     - `H(D') = hD`;
     - `D'.conv = conv`, `D'.e = e+1`, `D'.prev = H(D_e)`;
     - `D'.by = D_e.members[from].uid`;
     - `dsig'` verifies with `kc_{e+1}` under `D_e.members[from].sigPk` (the committer's key in `D_e`);
     - the old members in `D'` are exactly those with `rm` bit 0: `D' ∩ D_e = {D_e.members[j] : bit j of rm = 0}` (as
       sets of uids). In particular X ∈ D';
     - every continuing member has the same `sigPk` and `kh` in `D'` as in `D_e`;
     - `|D'| ≤ B`, `pks'` is `B·1216` bytes and zero after slot `|D'| − 1`, and for every `j < |D'|`,
       `H(enc("segv.sh/v2/kh", pks'[j])) = D'.members[j].kh` and `pks'[j]` passes the `kemPk` half of `checkUserKeys`
       (for a kept member, the `sealDet` recomputation below performs that encapsulation, and whether it succeeds does
       not depend on its randomness, §2.1, so a checker MAY skip the separate one, and a throw of that recomputation
       is then a failure of this check: at most 32 encapsulations in all; round 10);
     - **every kept entry recomputes**: for every `i < |D_e|` whose `rm` bit is 0, `entry_i` equals
       `sealDet(pks'[j], enc(conv, u32 e+1, u16 i), i)` under `EK'` byte for byte, where j is the index of
       `D_e.members[i]` in `D'` (§5.4). X's own entry is included.

     If a check fails, the claim is **D′-invalid** and X is **frozen** with the critical warning "@by made an invalid
     membership change; the members of this conversation can no longer change". Every member who obtains `EK'` sees
     the same `D'` and `pks'` (bound by `hD`, `ekc` and `bundleId`) and runs the same checks on data it already holds.
     A member whose entry does not open has an entry that fails the last check: a continuing member's `kh` is the hash
     of the key it verified when it joined (§6.7) and that every later D′ check carried forward, and `sealDet` to that
     key always opens. So either every member of `D_e ∩ D'` accepts e+1 or none does, and no join moves a member into
     e+1 later (§6.7 step 5): membership is frozen for the whole conversation, as v1's never-delivered state and
     burned slot were, but the signer is known.

     **Check order** (round 10). The D′ checks are one conjunction over data the member already holds: the claim is
     D′-invalid iff at least one of them fails, whichever it is. A checker MAY evaluate them in any order and MAY stop
     at the first failure (for example, it may compare `H(D')` with `hD` before parsing D′). Every check MUST be
     total: for any bytes a committer or the server can supply it passes or fails, and it never throws past the
     checker, waits or makes a request. The same holds for the local checks of §6.7 steps 1–2 on a fetched blob. This
     paragraph changes no order that this spec states explicitly, such as the `rm` bit before the entry (step 3: a
     removed member is removed whatever its entry holds), the own entry before the D′ checks (this step: it selects
     the warning), the order of e-validity's requests (§6.4: the local rules first, among them the `bundleSize`
     clause of (g) and `B ≥ |D_e|` of (h), then (f), (g) and (h); rounds 11–12),
     `bundleSize`, then `meta`, then the blob (§6.7 step 1), and the server's order of checks (§10.1).
   - Otherwise X **accepts e+1**:
     - members `D'`; leaves carry over (§6.9); system lines (§11.9);
     - X subscribes to `T_{e+1}`. It keeps following the lane of e of every continuing member who has not yet posted
       in e+1, and sweeps every other lane of e, and the lanes of e−1 it still followed, to their heads before they
       leave the expected-label map (§11.2);
     - X starts sending in e+1.

     X writes no self record for this epoch: restore re-derives it from the control lane, and snapshots carry it
     (§7.3).
5. **System lines from `rm`.** Every member of e that processes C, frozen or not, shows "`who(by)` removed `who(x)`,
   …" for the members whose `rm` bit is 1 and who had not left, and "keys rotated after `who(l)`, … left" for dropped
   leavers (§11.9). A removed member shows only "@by removed you". Who had left is the member's current leave state
   in e (§6.9), not the state when C was processed: when a source of a leave in e is added, replaced or dropped later
   (a sweep, scrollback, a late frame, or §6.8 on a new final winner), the two lines are derived again, so the same rows
   give the same lines in every order of arrival (round 11). A reload holds fewer rows: the leave state of its HEADS
   epoch and of later epochs comes from the LEFT records and the lanes it processes (§11.4 step 5), as live, but that of
   an older epoch only from the rows that the initial history and scrollback load (§11.4 step 6, §11.10). So until
   they load a leave's source, a claim below the HEADS epoch can show a removal where the live view showed "keys
   rotated" (round 12). The gate of step 6 depends only on the current epoch, so a reload keeps it.
6. **Frozen.** There is one frozen state; the two warnings above differ only in what X could see. A frozen member:
   - stays in epoch e, keeps receiving there, and applies the cut rule through `rm` (§6.8);
   - keeps sending there (`canSend = true`), unless `rm` of C has a bit for a member who had not left (by the current
     leave state, step 5; round 11). That member was told it was removed but still holds e's keys, so texts and images
     in e are refused (§11.3);
   - refuses its own membership changes with "the members of this conversation can no longer change; start a new
     conversation" (its control lane of e has a winner it cannot follow).

   A freeze is permanent, as in v1: the members start a new conversation to change membership. It needs no self
   record, because every device re-derives it from the control lane and the bundle (§11.4).

While the current epoch has an undecided control slot before any winner, or a winner that is not yet final or
processed, sends wait at most 30 s and then fail, as in v1 (§11.3). Commits wait until the control lane is settled.

### 6.7 Accepting a join (J from inbox, WELCOME or hello)

1. Check the bundle, in this order, so that a J naming a large blob costs no download:
   - `J.bundleSize ∈ {23456, 81248}`;
   - its registration (`GET /api/v2/blob/{id}/meta`, whose `t` is `t_reg` and gives `E_start(e)`, §4.2) is a HIT with
     `size = J.bundleSize`;
   - only then fetch the blob `bundleId`, aborting a response whose `Content-Length` is present and not
     `J.bundleSize` (a size mismatch), or whose body grows past `J.bundleSize` (without a `Content-Length`, read at
     most `J.bundleSize + 1` bytes); check the hash, the length and the header (`"SGB2"`, ver 1, B matching the size,
     10 zero bytes).

   A size, hash or header mismatch, or a `meta` MISS, gives a noise warning and stops. A network error, a timeout, a
   429 or a 5xx on either request, or a blob 404 while `meta` answers HIT, **parks** the join as step 4 says, retried
   with backoff (1 s, doubling to 60 s): a transient failure never drops a join.
2. Decrypt `descCt` with `dk_e(EK)` and parse `D`, and decrypt `pkCt` with `dk_e(EK)` to `pks`. Check all of:
   - `D.conv = J.conv` and `D.e = J.e < 2^32 − 1`;
   - `dsig` verifies with `kc_e(EK)` under D's own `sigPk` for `D.by`;
   - `|D| ≤ B`, `pks` is `B·1216` bytes and zero after slot `|D| − 1`, and every `pks[j]` hashes to
     `D.members[j].kh` and passes the `kemPk` half of `checkUserKeys` (so every later commit can seal to every member);
   - self ∈ D, listed with self's own `sigPk` and `kh`.

   Registration of the other members is not part of validity: a member whose bundle is missing, fails
   `checkUserKeys` or disagrees with D (another `sigPk`, or a `kemPk` that does not hash to D's `kh`) is shown as an
   unknown member (§11.2). If any check fails, give a noise warning and stop. Whether D's key for `D.by` is the
   directory's is checked in steps 5–6, only where it matters (skip and first contact).
3. **Duplicate.** If any copy already holds `(conv, e)` with the same `H(D)`, ignore the join.
4. **Settle the held copies.** For each held copy of `conv`, catch up the control lane of its current epoch k until
   either the winner is final and processed, or every slot is decided not e-valid and the current era has been
   probed. If a slot is still undecided or a winner not yet final, **park** the join: keep it, re-evaluate it after the
   next catch-up, and keep the inbox cursor (for a WELCOME, the lane's processed position, and the carrier copy's
   HEADS entry at that lane's epoch) before it (§7.3, §11.5). A
   removed member or a leaver keeps following the control lane of its last epoch until such a winner is final and
   processed.
5. **Fit.** For each held copy, with current epoch k:
   - **Claimed.** `e = k + 1` and the final winning claim C of k names `hD = H(D)`: ignore the join. The copy has
     processed C (step 4), so it either holds e already (step 3) or is frozen by C, and a J never overrides the
     verdict of the claim (§6.6).
   - **Skip.** `e > k + 1`, and the final winning claim of k has bit self of `rm` = 1 (self was removed or dropped by a
     public, signed claim). Accept it on the signature alone (a re-add), provided D's `sigPk` for `D.by` equals the
     `sigPk` of `D.by`'s verified directory bundle (from a MEMBER record, or fetched by prefix, §10.6) and agrees with
     any CONTACT or MEMBER pin. If this **`D.by` key check** fails, drop the join with the noise warning "ignored a
     conversation key with an invalid signature" (anyone can send such a join, §12.7). A lookup that fails
     transiently parks the join (step 1). An accepted skip ends a leave of the copy (§6.9).
   - Otherwise it does not fit this copy. A held conversation never skips epochs.
6. **No fit.**
   - If the client holds no copy: this is a first contact. Accept it on the signature alone as a new copy whose root
     is `H(D)`, after the same `D.by` key check as a skip (a failure drops the join with the same noise warning, and no
     copy is created). A newly added member cannot verify the history before it. The copy is a **request** (§11.5)
     unless `D.by` is a contact (§7.3). For an accepted join or a created request, the first verification of `D.by`'s
     bundle writes a MEMBER record from it (§7.3); a dropped join writes nothing.
   - If any held copy is **confirmed**, reject the join with the critical warning "ignored a conversation key that does
     not match the conversation history".

     A copy is confirmed when either holds:
     - a member other than its `rootBy` **and other than self** has posted a valid row in it, or a final e-valid
       claim by such a member exists in it;
     - self created it.
   - Otherwise keep the join as a **separate copy** (a request or not, by the same rule, after the same `D.by` key
     check as a first contact) and raise the critical warning "@x sent you a second, different copy of a conversation
     you were added to; both are shown marked ⚠ — only one can be genuine". Copies that are not confirmed are shown
     with "⚠ " when more than one copy exists.
7. On acceptance, write CONV_JOIN or REQUEST (a new copy) or EPOCH (a skip, flag bit1, naming the position of the
   claim of k that removed self, §7.2; round 11) to the self lane at once (§7.3). For an accepted copy, subscribe to
   `T_e` and probe the control lane and the lanes from `E_start(e)`. A request is probed as §11.5 says.

### 6.8 Old-epoch acceptance (cuts and claim times)

A receiver accepts a valid lane row R of epoch e from `s = D_e.members[i]` at `(E', n')`, with stored time `t_R`,
iff this walk accepts it. For `j = e, e+1, …`, while s is a member of `D_j` at index `i_j` (`i_e = i`) and the
receiver holds `D_{j+1}` or the final winning claim `C_j` of epoch j (with stored time `t_j`; round 10). The epochs are
consecutive: an epoch that the receiver reached by a skip (§6.7 step 5) is not `D_{j+1}` of the epoch it was removed
from, and never continues the walk (round 11).

- If bit `i_j` of `rm(C_j)` is 0, s continues into `D_{j+1}`. If the receiver holds `D_{j+1}`, continue with `j + 1`;
  otherwise (a frozen receiver, or one removed or dropped at j+1) stop and accept.
- If the bit is 1 (s was removed or dropped at j+1), accept iff `t_R < t_j`, or `j = e`, `t_R = t_j` and R is before the
  cut of lane i in `C_e`. Stop.

If the walk ends without a removal, accept.

**The bit without `C_j`** (rounds 10–12). A receiver that holds `D_{j+1}` accepted it through `C_j`, whose `rm` has
bit 0 exactly for the members of `D_j` that `D_{j+1}` lists (§6.6 step 4). It therefore reads s's bit from `D_{j+1}`,
and needs `C_j` itself only at a step whose bit is 1 (for `t_j`, and for the cut when `j = e`). A receiver that was
removed or dropped at j+1 holds no `D_{j+1}` and needs `C_j` at step j (round 11). A receiver that needs `C_j` but did
not process it (a restore that started at a later HEADS epoch with that epoch's key from a snapshot's EPOCH record,
§11.4 step 5, or scrollback, §11.10) reads `C_j` from the position that the EPOCH record of the copy's next held epoch
names: the record for j+1, or, when self was removed or dropped at j+1, the record of the skip re-add that followed
(§7.2; round 11). A snapshot holds an EPOCH record for every held epoch above the root (§7.4), and a restore
re-derives every held epoch that no record gives by processing the claim before it (§7.3, §11.4 step 5; round 12), so
it holds every held epoch and those claims. The copy's previous held epoch below an epoch is the highest held epoch
below it (e−1, or the epoch k self was removed from below a skip re-add). The read is a body `get`, opened with
`mk_j`, whose stored `t`, `rm` and cuts the receiver uses without evaluating the claim again (the record is the
account's own). It retries a transient failure, and the row is not shown before it is decided. A receiver never
accepts a row because it lacks `C_j`.

- A committer cannot erase a removed member's earlier rows with a low cut: rows with `t_R < t(C)` are always
  accepted. It cannot let a removed member keep posting with a high cut either: rows with `t_R > t(C)` are always
  dropped. The cut only decides rows in the claim's own Δ batch.
- A member removed at e+1 cannot post into e after the claim, nor into any earlier epoch after a later claim that
  removed it. Equal times count as "after" for later claims, which is the safe side.
- Valid rows of members who are still listed are shown even if they land late.
- Every device applies the rule to the same stored `t` and the same public `rm` (from `C_j`, or from `D_{j+1}` as
  above), so live, restored and frozen views agree: a freeze stops every continuing member of e at e (§6.6), so frozen
  members hold the same claims as the others. Decisions are recomputed when the receiver learns a new final winner: a
  row that is now dropped is removed from the view and from `unread`. Dropped rows give no warning, and §11.3 step 7
  marks one's own echo `failed`. A leave stands in an epoch only while this walk accepts the source the receiver keeps
  for it there (§6.9: the least of the leaver's LEAVE rows in that epoch and the leaves carried into it). When that
  source is dropped, the leave is un-recorded in that epoch, and no other source can keep it: along the same walk a
  source with a smaller key is accepted whenever one with a larger key is (rounds 8 and 10).
- A LEFT record (§7.2) carries the stored time of its LEAVE row and, when it names the row's own epoch, the row's
  position. A leave taken from one (§11.4 step 5) is decided by this walk exactly as the row would be: the walk starts
  at the record's epoch, and the equal-time cut applies only to a record that carries a position (a carried record's
  position is NONE, which is never before a cut). So a claim that drops the row un-records the leave on a restored
  device too (round 9). Every device keeps the least source per epoch and member, whatever the order in which it
  learned the sources, and its LEFT record names that source (§6.9, §7.3), so live and restored views agree whenever
  the record was written (round 10).

### 6.9 Leave and remove

- **Leave.** The leaver posts a LEAVE row (type 17) on its own lane of the current epoch (§11.3) and, only after the
  put returned OK (or a probe found its own body), writes a LEAVE self record. A device that applies a LEAVE row of
  its own account for which no LEAVE record exists writes the record, so a crash between the two writes is repaired by
  any device, and a record never exists without its row. The leaver stops sending, shows "you left the conversation"
  once, and sets `canSend = false`. It keeps following the control lane of its current epoch (a claim that keeps it
  moves it to the next epoch like any member, §6.6) until a final winner drops it (§6.7 step 4). Until then it also
  keeps processing the copy's lanes for WELCOME rows only (it shows nothing else), and sweeps them once more when the
  dropping winner is final (§11.2), so a WELCOME written before the sender learned of the leave, or before the leave
  itself, is not lost. Senders still never choose a copy in which they have seen the recipient's LEAVE as a WELCOME
  channel (§6.12). Receivers record the leave in e and in the consecutive later epochs e+1, e+2, … that they hold, up
  to the first that does not list the leaver; so a leaver who is dropped and later re-added is not recorded as left in
  the epochs of the re-add. Each epoch in which a receiver records the leave gets a LEFT record with the row's stored
  time and, for the row's own epoch, its position (NONE for an epoch the leave was carried into; §7.3), so a reload
  does not forget the leave and decides it by §6.8 as it would decide the row (rounds 9 and 10).
- **Several sources** (round 10). A member can be recorded as left in one epoch k from several **sources**: each of
  its LEAVE rows in k (with the row's stored time and position), and each leave carried into k from an earlier epoch
  (with that row's stored time and NONE), for example the leaver's own repeat (below) in an epoch into which a racing
  claim carried its first leave. A source's **key** is `(t, position)`, compared by t, then by position, where NONE
  counts as after every real position (unlike the order of §3.1). Per copy, epoch and member, the receiver keeps only
  the source with the least key, whatever the order in which it learned the sources: a source with a smaller key
  replaces the kept one (the receiver writes its LEFT record, §7.3), and one with an equal or larger key changes
  nothing. The leave stands in k iff §6.8 accepts the kept source; because a smaller key is accepted whenever a larger
  one is (§6.8), the kept source is accepted whenever any source is, and every device that holds the same rows reaches
  the same verdict. The "@x left" line belongs to one LEAVE row per leave: a kept source that §6.8 accepts, in an
  epoch into which no leave of x was carried (§11.9; round 12). A claim's removed and rotated lines follow the leave
  state (§6.6 step 5), so they too depend on the rows held, not on the order in which they arrived (round 11).
- **The leaver's own state.** A copy's leave is **current** while the copy has a LEAVE record and no skip re-add
  followed it: an EPOCH record with flag bit1 (§6.7 step 5) for an epoch above the latest LEAVE record's epoch ends the
  leave. The latest LEAVE record is the one with the highest e, whatever the order of the records (§7.3). While the
  leave is current the copy is `left` (§11.2; sends are refused, §11.3 step 2). A skip re-add clears `left`, live and
  at restore (§11.4).
- **Repeating a LEAVE.** The others see a LEAVE row only if it lies in their current epoch, or in the previous one
  while they follow the leaver's lane there (§11.2). So whenever a leaver's copy is in an epoch c that still lists self
  (self was not removed or dropped), its leave is current, and its latest LEAVE record names an epoch `e_L < c`, a
  device of the account puts a LEAVE in c. Devices check this after every catch-up and restore, and in §11.3 step 8,
  also in a frozen copy (the freeze itself posts nothing, §11.4 step 5). The put runs §11.3 steps 1 and 2 (without the
  "you left" refusal), then steps 4–8, and writes its own LEAVE record after its OK. This is how a late LEAVE (§11.3
  step 8) is repeated, also by another device or after a reload. The rule does not test whether the others still
  follow self's lane of c − 1 (a restore cannot see self's rows before its HEADS positions); an unneeded repeat costs
  one row, and a duplicate LEAVE is harmless.
- **Rotation after a leave.** A remaining member MUST commit an epoch without the leavers (§6.3) before sending a TEXT
  or IMAGE in an epoch that lists a member who has left, unless it is frozen in that epoch or the epoch is
  `2^32 − 2` (§11.3). Clients MAY rotate proactively: the remaining member of rank r (by index among non-leavers) waits
  `r × 30 s + random(0..10 s)` after seeing the leave, and aborts if a claim appears first. A member added by a commit
  that raced the LEAVE (its committer built `D′` before the row reached it, so `D′` still lists the leaver) holds no
  epoch of that row and does not see it. It records the leave only when the leaver's device repeats it in an epoch
  the new member holds (above). Until then, a claim that drops the leaver (a member who saw the leave rotating) is a
  removal to it: it shows "`who(by)` removed `who(x)`" where the members who saw the leave show "keys rotated after
  `who(x)` left", and if that claim froze the conversation it refuses texts there while they may still send (§6.6
  steps 5–6). Members that hold different rows can thus show different lines and gates (round 11). Its texts sent
  before the leaver is dropped are readable with the leaver's keys, although the leaver's own client shows none of
  them.
- **Add.** An add commit drops every member who has left. Re-adding a leaver who is still listed takes two commits:
  first drop the leavers, then add.
- **Remove.** A remove commit drops the removed member and every leaver. A member cannot remove itself (it must leave).
- **What a removed member learns.** That a claim removed it, which other old members were dropped (`rm`), the cuts,
  and the bundle size bucket. It does not learn who was added, the new name, `T_{e+1}` or `rk_{e+1}`.

### 6.10 What can no longer freeze (reconciliation with v1)

v1 had one claim slot per epoch, and the first row of any kind won it:

- an invalid row or junk on the slot froze membership forever, while messaging continued;
- a valid claim whose invites never arrived also froze the epoch.

Stage 1 has a multi-slot control lane and chooses the first e-valid claim, where e-validity uses only facts every
member of e shares and requires the key bundle to be registered before the claim (rule (g)). As a result:

| v1 cause | stage 1 outcome |
| -------- | --------------- |
| Junk or a non-claim row on the slot | Ignored (noise warning). It occupies one slot, and the next committer uses `k+1`. Nothing freezes. |
| Claim with a bad csig, a wrong `prevD`, bad `rm` or cuts, or a malformed bundle | Not e-valid, so ignored. Nothing freezes. The csig is checked against the committer's key in `D_e`, so whether the committer is registered (now or later) cannot change the result. |
| Claim whose bundle is missing or late | Permanently e-invalid by (g), so ignored by everyone. Nothing freezes. Registered bundles always have their R2 object (§8.2). |
| e-valid claim with an invalid `D'` (a `descCt` or `pkCt` that does not open or parse, bad `hD`, `dsig'` or `prev`, old members that disagree with `rm`, a continuing member's key changed, or a bad `pks'`) | **Membership freezes for the whole conversation, as in v1**. Messaging in e continues unless the claim removed a member who had not left (§6.6 step 6). The difference: csig is valid, so the warning names the signer. A J for that `D'` sent afterwards is ignored (§6.7 step 5), so the committer cannot move chosen members into the invalid epoch. |
| e-valid claim whose key entry is wrong for any continuing member (the key withheld from some members or from all, or an entry sealed to another key or with fresh randomness) | The same: every member who obtains `EK'` recomputes every kept entry and finds `D'` invalid, and the members whose entry fails are frozen too (§6.6 step 4), so **everyone** is frozen in e, attributably. v1 froze only the members whose invite was missing (§13.2 item 14). A member cannot be removed covertly or left behind. |
| A new member's J that never arrives | The committer's devices keep retrying the delivery (§6.12). If it still never arrives, the new member does not join, and the others continue, as in v1. |

**What still freezes or stops:**

- a conversation whose winning claim's signer made it unusable (invalid `D'`, or a wrong key entry for any continuing
  member), and its messaging too when that claim removed a member who had not left;
- a member whose `rm` bit is 1 is removed, by design;
- a conversation at `e = 2^32 − 2` cannot change;
- a member who keeps filling control slots with junk delays committers by one probe per junk row, which costs it PoW
  for every row.

**What still progresses:** messaging in every case except the frozen-with-a-removal case above. Membership changes
in every case except the frozen and final-epoch cases above.

**Why this is safe.** Who wins depends only on facts that every member of e evaluates identically:

- the rows' existence and stored `t`;
- the content readable with `mk_e`, including `rm` and the cuts;
- signatures, verified under the keys that `D_e` lists (§5.1);
- create-only blob registrations and the blob bytes (bound by `bundleId`);
- the sealing of past eras.

Nothing a member learns only from its own entry or from `D'` changes the winner, and the directory never enters
validity: an unregistered member who commits, and registers between two members' evaluations, gets the same verdict
from both. Whether `D'` is valid is the same for everyone who can open it (no D′ check uses the reader's Unicode
tables, §5.1), a member who cannot open its entry always has an entry that makes `D'` invalid for the others, and a
join never overrides a claim, so no member enters an epoch that the others rejected. So two members of e follow different epochs e+1 only if the server lies to
one of them (§0.4, §12.6).

### 6.11 Multi-device and crash recovery

- **Other devices of the committer.** They learn e+1 like any member: the committer's own entry in the bundle is a
  real wrap, because C ∈ D_e ∩ D'.
- **Unfinished deliveries.** On restore and on every catch-up, a device checks each EPOCH_PENDING record
  `(conv, root, e, bundleId)` of its account that still has uids not covered by DELIVERED records:
  - for `e = 0`, the creation is established if the account holds the CONV_JOIN `(conv, root)`;
  - for `e ≥ 1`, it is established if `bundleId` is the final winning claim of `e − 1`. If the final winner is another
    claim, the record is dead: it is ignored and dropped from snapshots.

  If the record is established, and either this device wrote it in this session or its self row's stored `t` is more
  than `RESUME_AFTER` = 10 minutes old, the device delivers J to the remaining uids (§6.12). Receivers ignore duplicate
  J. A creation resumed this way skips the decoy.
- **A created copy without a bundle.** If the bundle named by a CONV_JOIN with `via = created` is definitively
  unregistered (a decided MISS), the copy is dropped with a noise warning.
- **AK rotation.** AK rotation and bundle versioning are **deferred** (§14). In stage 1 an account's keys never change.

### 6.12 Delivering J

J is delivered for a creation and a commit in the same way:

1. A recipient R gets a WELCOME row (§11.3) in a 1:1 copy only if the recipient provably holds that copy and
   processes its lanes. All of these must hold for self's accepted copy, both when the channel is chosen and, in
   §11.3 step 2, for the epoch the row is about to be built in:
   - its current epoch c lists exactly self and R, and self is not frozen in c;
   - self has not left this copy (its leave is not current, §6.9) and was not removed from it;
   - self has seen a valid row of R in epoch c (R can only post in an epoch it holds, and posting turns a request copy
     into an accepted one, §11.5, which is never dropped, §7.3);
   - R has not left (no LEAVE of R seen in c or an earlier epoch of the copy; a leaver processes WELCOMEs only until a
     claim drops it, §6.9).

   A 1:1 that R has never posted in (for example one that is still a request on R's side, which R may drop after 4
   eras or when 64 newer requests push it out, §7.3) does not qualify. The check is repeated in §11.3 step 2 because
   the send may move the 1:1 to a later epoch (a claim found by its control probe), and that epoch may list a member
   who must not learn J. If the epoch the row would be built in no longer qualifies, nothing is written to the 1:1, and
   R gets an inbox invite instead (step 2).
2. Every other recipient (including one whose WELCOME step 1 withdrew) gets an inbox invite, sealed to its `kemPk` in
   `pks` of the new epoch's bundle (§5.4), so a device that resumes the delivery (§6.11) needs no directory lookup.
   Invites are posted in random order, batched up to 32 per `POST /api/v2/inbox` (§10.5).
3. For a creation or a commit, once every recipient has had its first attempt (steps 1–2), the device writes **one**
   self row holding the DELIVERED record (§7.2) of the recipients that succeeded, with `a = 0` if none did; a commit
   without recipients writes it with `a = 0` after switching. A row with a DELIVERED record is padded like an
   EPOCH_PENDING row (§7.1), so it is class 1 for any number of recipients. Every creation and commit therefore ends
   with exactly one class-1 self row. A recipient that succeeds on a later retry is recorded in a further such row.
4. On 429 (rate limit), a per-row FULL (the day cap), a network error, a 5xx, a WELCOME that §11.3 refuses (a
   pending claim, or a failed control probe; every other refusal of a WELCOME gives an inbox invite, §11.3 step 2), or
   a late WELCOME that §11.3 step 8 does not count as delivered, the uids stay pending. On 409 `{error: "wrong era", era}`, the device rebuilds those invites for
   the returned era (fresh `eid`, AAD with the new `E`) and retries at once; if that era was already tried for this
   batch, it first waits until the estimated server time is past `end(min(E, E')) + SKEW`, as §11.3 step 6 does. The
   device retries with backoff, honouring `retry-after` (10 s, doubling to 10 minutes), and raises once per recipient
   the noise warning "@x has not been notified yet; retrying". Only an OK (or an idempotent same-body result) counts as
   delivered. Pending deliveries survive reloads and logouts through EPOCH_PENDING (§6.11).

## 7. Self lane and snapshots

The self lane is the account's encrypted, append-only device-state log. A new device (or a reload) rebuilds the list of
conversations and epoch keys from it without scanning invites.

### 7.1 Self row envelope

```
S    = u8 ver(=2) | u16 Eprev | u32 nprev | prevh[16] | u64 ts | u8 count | record × count      (32-byte header)
record = u8 rtype | u16 len | content[len]
body = aeadSeal(kS, pad(S, CLASSES), aad = enc("segv.sh/v2/self", u16 E, label))
```

- Self rows are put at `Lself(E, n)` (dense per era) with topic `Tself`. Snapshot pointers are put at `Lsnap(E, j)`
  without a topic (§7.4).
- `Eprev`, `nprev` and `prevh` point to the previous self row on `Lself` (written by any device), using the same
  `prevh` formula as §3.3. The first row of the account uses NONE / `ZERO16`. Snapshot pointer rows at `Lsnap` carry
  NONE / `ZERO16` and are not part of this chain.
- `1 ≤ count ≤ 255`.
- A writer SHOULD batch the records it produces in one burst (for example all joins found by one inbox poll) into one
  row, up to cls 3. This keeps self-lane writes from being amplified by spam.
- A self row that carries EPOCH_PENDING or DELIVERED is padded with `pad(S, [1024, 4096, 16384])`, so it is class 1
  even when it would fit class 0. Creations and commits of any size then write the same classes (§13.1).
- Self rows are not signed: `kS` is known only to the account.

**Parse rules** (normative).

- S is malformed unless: `ver = 2`; `(Eprev, nprev)` obeys the position rule (§3.1), and NONE comes with
  `prevh = ZERO16`; `ts ≤ 2^53 − 1`; `1 ≤ count ≤ 255`; and exactly `count` records follow, each
  `u8 rtype | u16 len | content[len]`, with nothing after the last one.
- A record with an unknown `rtype` is skipped by its `len` (forward compatibility).
- A known record's content has exactly the length its layout gives and obeys its row in §7.2: CONV_JOIN and REQUEST
  `via ∈ 1..5`; EPOCH `e ≥ 1`, only flag bit1 allowed, `(claimE, claimK)` a position; LINK only flag bits 0–1; PREFS
  `len ≥ 1`; the counts of §7.2; DESC and REQUEST `224 ≤ dlen ≤ 2960`; MEMBER's handle; LEFT's `(E, n)` a position
  (round 9); SNAP's `(Eh, nh)` a position.
- A row at `Lself` MUST NOT hold a SNAP. A row at `Lsnap` MUST hold exactly one known record, a SNAP. Writers write
  `count = 1` and prev fields NONE / `ZERO16` there; readers do not use a pointer row's prev fields.
- S2 (§7.4) is malformed unless, after removing the padmé padding, it is `"SGS2"`, `ver = 1`, `(Eh, nh)` a position,
  `ts ≤ 2^53 − 1`, then `count` records (any u32; 0 is allowed) as above, none of them a SNAP, with nothing after
  them.
- A self row or S2 that breaks any of these rules is **rejected as a whole**: none of its records are applied. A
  rejected self row still occupies its slot (§4.2).

### 7.2 Record types

`root` identifies a conversation **copy**: `root = H(D)` of the first epoch the account accepted in that copy (§6.7).

| rtype | name | content |
| ----- | ---- | ------- |
| 0x01 | CONV_JOIN | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | rootBy[16] | u8 via` (137 B). An accepted copy. `via`: 1 = created, 2 = inbox, 3 = welcome, 4 = hello, 5 = request accepted. |
| 0x02 | EPOCH | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u16 claimE | u32 claimK | u8 flags` (127 B). Epoch e ≥ 1 of this copy. `(claimE, claimK)` is the position of the final winning claim that ended the copy's previous held epoch: the claim on `Lctl_{e−1}`, or, for a skip re-add, the claim on `Lctl_k` that removed or dropped self from the epoch k the copy held before (§6.7 step 5; round 11, was NONE), so every held epoch above the root names the claim that a walk below it needs (§6.8). The record does not name k: it is the highest held epoch below e, and a restore holds every held epoch (§11.4 step 5; round 12). `flags`: bit1 = accepted by a skip join (0 for an epoch derived from the account's own bundle entry). Every other bit, bit0 included, is 0. |
| 0x03 | EPOCH_PENDING | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u32 t_reg | u8 a | uid[16] × a` (125 + 16a B). Creation (e = 0) or commit intent: the uids that need J. |
| 0x04 | LEAVE | `conv[16] | root[32] | u32 e` (52 B) |
| 0x05 | CONTACT | `uid[16] | pin[32]` (48 B). TOFU pin of the bundle (§2.2). |
| 0x06 | LINK | `s[16] | u16 Ecreated | u16 Eexpires | u8 flags` (21 B). bit0 = one-shot, bit1 = revoked. |
| 0x07 | PREFS | `u8 key | value[len−1]`. No keys are defined in stage 1. The latest value per key wins. |
| 0x08 | HEADS | `u16 Ein | u32 relIn | u16 c | entry × c`, with `entry = conv[16] | root[32] | u32 e | u64 lastTs | u16 ctlE | u32 ctlCnt | u8 m | (u16 E | u32 cnt) × m | u8 f | (u32 ef | u16 ℓ | u16 E | u32 cnt) × f` (68 + 6m + 12f B per entry). Processed positions (§7.3). `c = 0` records only the inbox cursor. |
| 0x09 | CONFIRMED | `conv[16] | root[32]`. The copy is corroborated (§6.7). |
| 0x0A | DELIVERED | `conv[16] | root[32] | u32 e | bundleId[32] | u8 a | uid[16] × a` (85 + 16a B). These uids have been sent J for that EPOCH_PENDING (§6.12 step 3). Its row is padded to class ≥ 1 (§7.1). |
| 0x0B | REQUEST | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u32 t_reg | rootBy[16] | u8 via | u16 dlen | desc[dlen]` (143 + dlen B), where `desc = D ‖ dsig` of epoch e. A request copy (§11.5). |
| 0x0C | DESC | `conv[16] | root[32] | u32 e | u16 dlen | desc[dlen]` (54 + dlen B, `dlen ≤ 2960`), `desc = D ‖ dsig`. The descriptor of epoch e of the copy, so a restore needs no bundle fetch for it. |
| 0x0D | MEMBER | `uid[16] | sigPk[32] | kh[32] | pin[32] | u8 hlen | handle[hlen]` (113 + hlen B). `handle` matches `^[a-z0-9_]{3,20}$` (§2.1), so `3 ≤ hlen ≤ 20` and the handle is ASCII; any other handle makes the record malformed. A co-member's directory bundle as self verified it: its `sigPk`, `kh = H(enc("segv.sh/v2/kh", kemPk))` of its `kemPk` (§5.1), and `pin` (§2.2), so restores need no directory lookup for that member (§11.4). |
| 0x0E | LEFT | `conv[16] | root[32] | u32 e | uid[16] | u32 t | u16 E | u32 n` (78 B; round 9). Another member's leave as self recorded it: `uid` is recorded as left in epoch e of the copy (§6.9). `t` is the stored time of the LEAVE row R of the leave's kept source (§6.9; round 10), and `(E, n)`, a position field (§3.1), is R's position when e is R's own epoch, or NONE when the leave was carried into e from an earlier epoch. Written as §7.3 says, so a restore does not need R and decides the leave as R would be decided (§6.8). |
| 0x20 | SNAP | `blobId[32] | key[32] | u32 size | u16 Eh | u32 nh` (74 B). Allowed only in rows at `Lsnap`. |

**Counts.**

- EPOCH_PENDING and DELIVERED: `a ≤ 32` (honest writers write at most 31; `a = 0` is valid). The uids form a set; a
  repeated uid is not a parse error.
- HEADS entry: `1 ≤ m ≤ 32` and `f ≤ 32`. `c` may be any u16 (`c = 0` records only the cursor).
- A record that breaks a count rule is malformed (§7.1).
- When a reader uses a HEADS entry for epoch e of a copy, it MUST ignore the entry (the copy restores as if it had no
  HEADS entry, §11.4 step 5) if `m ≠ |D_e|`, or if two followed lanes with `ef = e − 1` name the same ℓ, or one of
  them names `ℓ ≥ |D_{e−1}|`. Followed lanes with `ef ≠ e − 1` are ignored one at a time (below). For a copy that does
  not hold epoch e−1 (e is its root epoch, or it reached e by a skip, §11.2), the reader MUST ignore every followed-lane
  entry and use the rest of the entry; the two ℓ checks then do not apply.

**`desc` of DESC and REQUEST.** The record parser checks only `224 ≤ dlen ≤ 2960`. Before using `desc`, the consumer
MUST split it (D = all but the last 64 bytes, `dsig` = the last 64), parse D with every rule of §5.1, check
`D.conv = conv` and `D.e = e`, check that `dsig` verifies with `kc_e` under D's own `sigPk` for `D.by` (`kc_e` from
the epoch key the account holds for `(conv, root, e)`; for a REQUEST, from the record's own EK), and check
`H(D) = root` when e is the copy's first epoch (the e of its CONV_JOIN or REQUEST; always so for a REQUEST). A DESC
that fails is ignored as if absent, and D of that epoch then comes from the bundle (§11.4 step 5). A REQUEST that
fails is ignored as if absent: no request copy is created from it, it does not count toward the 64 live requests, and
a later REQUEST for the same `(conv, root)` can win. Neither failure shows a warning. Honest records always pass.

**HEADS positions.** A HEADS entry describes epoch e of the copy as processed by the writing device:

- `(ctlE, ctlCnt)`: every era of the control lane before `ctlE` was observed sealed, and every slot before
  `(ctlE, ctlCnt)` was decided not e-valid;
- `(E, cnt)` for lane ℓ (one per member of `D_e`): every row of lane ℓ before `(E, cnt)` was fetched and processed
  (joins and leaves included; the leaves of others recorded in e are carried by LEFT records, §7.3);
- the `f` followed lanes (§11.2), each with its processed position (same rule). `ef` is always `e − 1` (the field stays
  in the layout); a reader ignores a followed-lane entry with another `ef`. The list is complete: at restore, the
  followed lanes of epoch e are exactly those listed (§11.4);
- `lastTs`: the copy's `lastTs` (§11.8), used to rank copies for the initial history (§11.4).

A recorded position (here, in a snapshot's `(Eh, nh)`, or as a processed position) never lies in an era E′ while the
same lane has rows in an earlier era E whose dense-prefix end the device has not observed as `MISS(sealed = 1)`.
Around an era boundary both shards accept writes for up to SKEW (§9.1), so a lane can still gain a row in E after it
has one in E′; §6.5 applies the same rule to the control lane.

`(Ein, relIn)` is the inbox cursor: every invite at or before it was processed, and no parked join lies before it
(§11.5). Only the account can write self rows, so a device trusts these positions as starting points and, for the eras
they cover, for finality (§6.5).

### 7.3 Semantics

**State.** The state is the fold of the records in self-lane order: by `(E, n)`, and within a row by record order. The
records are idempotent:

| record | key | rule |
| ------ | --- | ---- |
| CONV_JOIN | `(conv, root)` | the first one wins; it supersedes a REQUEST with the same key. A CONV_JOIN for a `conv` that already holds a different copy with a CONFIRMED record is dropped with the critical warning of §6.7 step 6. |
| REQUEST | `(conv, root)` | the first one wins. At most 64 are live: older ones (by self-lane order) are dropped, and so is a REQUEST whose row's stored `t` is more than 4 eras old. |
| EPOCH | `(conv, root, e)` | the first one wins; flags are OR-ed |
| EPOCH_PENDING | `(conv, root, e, bundleId)` | every record is kept |
| DELIVERED | `(conv, root, e, bundleId)` | the uids are united |
| DESC | `(conv, root, e)` | the first one wins |
| MEMBER | `uid` | the first one wins (see the pin check below) |
| LEAVE | `(conv, root, e)` | every record is kept; the copy's *latest* LEAVE record is the one with the highest e (§6.9) |
| LEFT | `(conv, root, e, uid)` | the record with the least `(t, (E, n))` wins, NONE counting as after every real position (the key of §6.9), so identical records count once and the fold holds at most one record per key; it stands for its LEAVE row and is decided by §6.8 (rounds 9–10) |
| CONTACT | `uid` | the first one wins (see the pin check below) |
| LINK | `s` | |
| CONFIRMED | `(conv, root)` | |
| HEADS | per `(conv, root)` | the latest entry wins; `(Ein, relIn)` takes the maximum. A record may hold any subset of copies. |

**Contacts.** A CONTACT is written for every user that self resolves by handle (creation, add), and for `D.by` of a
copy when self first posts in it or opens it (§11.5). An incoming join never creates a contact. A second CONTACT for the
same uid with a different pin, or a directory bundle whose pin differs from the pinned one, raises the critical warning
"the public keys of @x changed".

**Members.** A MEMBER is written the first time self verifies (§10.6) the directory bundle of a uid that appears in a
D it holds (as an accepted copy's member, or as `D.by` of a request), whatever keys that D lists for it: it is the
TOFU pin of the directory's keys for that uid, as CONTACT is (keys never change in stage 1, §6.11). A CONTACT for a
resolved handle comes with a MEMBER. The same pin rule applies: a second MEMBER, a CONTACT or a later directory bundle
with a different pin for the same uid raises "the public keys of @x changed". A member of a D whose `sigPk` or `kh`
differs from its MEMBER's is shown as an unknown member (§11.2), and raises the same warning; deciding this needs no
lookup. Only a uid that has no verified directory bundle has no MEMBER; it is looked up again at the next restore. A
request's `D.by` always has one (the `D.by` key check of §6.7 needs its bundle), so requests cost no directory lookup
at restore (§11.5). MEMBER records exist so that restores need no directory lookups (§11.4); they never affect
validity.

**Copy keys.** The local view key of a copy is `b64u(conv)` for the copy whose CONV_JOIN or REQUEST comes first.
Later copies get `b64u(conv) + "~" + i` (i = 1, 2, … in that order). Snapshots keep the original self-lane order of
these records (§7.4), so every device numbers copies the same way.

**When to write.**

- A device writes a record when it causes the event: a creation (CONV_JOIN and EPOCH_PENDING in one row), a commit
  (EPOCH_PENDING, later DELIVERED), an accepted join (CONV_JOIN, REQUEST or EPOCH), a leave, a corroboration
  (CONFIRMED, written before any CONV_JOIN in the same row), or an accepted request (CONV_JOIN with `via = 5`). New
  CONTACT and MEMBER records ride in the next HEADS row, and LEFT records in every HEADS row or snapshot that holds an
  entry for their epoch (below; round 8); the device uses them locally at once. The MEMBER for a request's `D.by` rides
  in the REQUEST's row.
- **Others' leaves.** For every member uid that the device records as left in epoch e of a copy (§6.9: by applying its
  LEAVE row R, by carrying the leave into a later epoch, or at restore from a LEFT record, §11.4 step 5), it writes
  `LEFT{conv, root, e, uid, t, E, n}` for the source it keeps for uid in e (§6.9; round 10), where `t` is that
  source's LEAVE row R's stored time and `(E, n)` is R's position when e is R's own epoch, or NONE when the leave was
  carried into e (round 9). When a source with a smaller key replaces the kept one, the device writes the new source's
  record (round 10). A LEFT record stands for R: a leave taken from it is decided by §6.8 as R would be, so a claim
  that drops R un-records the leave on a live and on a restored device alike, however long before that claim the
  record was written (round 9). Every HEADS entry for epoch e, in a self row or a snapshot, MUST be accompanied **in the
  same row or snapshot** by a LEFT record naming the kept source of every member that the device writing the row or
  snapshot records as left in e (rounds 8 and 10; an earlier row does not count, because a snapshot may have compacted
  it away). Whichever HEADS entry a restore uses thus has the LEFT records of its epoch beside it, whatever snapshots or
  sibling rows came between, and lane positions may pass the LEAVE rows.
- Epochs accepted through the account's own bundle entry are **not** written as self rows: restore re-derives them from
  the control lane (§11.4), and snapshots carry them. So no self row follows a claim observed from another member
  (§13.1).
- Records are written at once, without waiting for siblings. Duplicates from sibling devices are harmless.
- **Durability order.** The joins found by one inbox poll are written, in order, in as few self rows as fit cls 3
  (a 32-member REQUEST is about 2.9 KB, so a row holds 5 of them), and the HEADS record (`c = 0`) that moves the cursor
  past them goes in the last of these rows, written only after every earlier one is CAS OK. A REQUEST that the
  64-request limit would drop at once is not written. No HEADS record or snapshot records an inbox cursor or a lane
  position past a join, an own leave or a J that is not yet durably recorded (CAS OK) or is parked (§6.7). Others'
  leaves are made durable by their LEFT records (above). While a J found on a lane of epoch e′ of a copy is parked,
  every HEADS entry written for that copy (in a self row or a snapshot) describes epoch e′, or epoch e′ + 1 with that
  lane among its followed lanes, and holds that lane's position before the J, even after the copy has moved on:
  restore processes lanes only from the HEADS epoch on (§11.4). A failed write is retried before the cursor advances.
- **HEADS** is written in every snapshot; as a self row at most every 30 minutes (after a random delay of up to 5
  minutes), when processed positions advanced or new CONTACT, MEMBER or LEFT records wait; and once right after
  registration, with the cursor at the current inbox slot. A writer splits HEADS over several records and rows so that
  each row fits cls 3, keeping each entry in the same row as the LEFT records of its epoch (above; round 8).
- Writes use CAS at the first empty slot of era `max(E_now, the era of the self-lane head)`, never below the head's
  era. On CONFLICT the device applies the occupant (if it opens under `kS`) and retries at `n+1`. On WRONG_ERA it
  writes at `(E', 0)`.

### 7.4 Snapshots

A snapshot compacts the self lane into one blob:

```
S2   = "SGS2" | u8 ver(=1) | u16 Eh | u32 nh | u64 ts | u32 count | record × count       (records as in §7.1)
blob = aeadSeal(skey, padme(S2), aad = utf8("segv.sh/v2/snapshot")); skey = random(32); id = b64u(H(blob))
```

- `(Eh, nh)` is the last self-lane position whose effects are included, or NONE. It obeys the era rule of §7.2: it
  never lies in an era E′ before the end of the self lane's dense prefix in the previous era with rows was observed
  `MISS(sealed = 1)`.
- The records are the compacted state, with CONV_JOIN and REQUEST records in their original self-lane order:
  - per accepted copy: its CONV_JOIN, an EPOCH for every held epoch **above the copy's root epoch** (the CONV_JOIN
    carries the root epoch's key, and EPOCH requires `e ≥ 1`, §7.1), a DESC for the current epoch and for the copy's
    previous held epoch, if any (e−1, whose lanes may be followed, §11.2, or, below a skip re-add, the epoch k self was
    removed from; either one's history may be loaded at restore, §11.4 step 6; round 12), every EPOCH_PENDING that
    is neither dead nor complete (every listed uid covered) with its DELIVERED records, its LEAVE record with the
    highest e (if any), CONFIRMED, the latest HEADS entry, and the LEFT records naming that entry's epoch: for each
    member that the fold or the snapshot's writer records as left in that epoch, exactly one, the least of the fold's record (the row that held the entry held one,
    §7.3) and the writer's kept source (§6.9), as §7.3 requires (rounds 8–10: a snapshot holds at most one LEFT record
    per member, so repeated HEADS rows and snapshots never pile up copies). Every held epoch above the root was
    reached either through the account's own bundle entry, whose EPOCH has flags 0 and `(claimE, claimK)` = the
    position of the winning claim the device processed, or through a skip join, whose EPOCH has flag bit1 and the
    position of the claim that removed or dropped self from the previous held epoch (§7.2; round 11). A complete or
    dead EPOCH_PENDING and its DELIVERED records are dropped: nothing reads them, and the EPOCH or CONV_JOIN record
    already carries the epoch key;
  - the live REQUESTs (at most 64);
  - every CONTACT;
  - the MEMBER record, where one exists, of every uid listed in a D carried by a DESC or a live REQUEST, or held as a
    CONTACT (other MEMBER records are dropped, and looked up again if ever needed);
  - every LINK that has not expired;
  - the latest PREFS per key;
  - a HEADS record with the inbox cursor.
- **Pointer.** A self row whose only record is `SNAP{blobId, skey, size, Eh, nh}`, with prev fields NONE / `ZERO16`
  (§7.1), is put at `Lsnap(E_now, j)`, where `j` is the first empty slot. Slots are dense per era, and the first writer
  of a slot wins.
- **When to write.** A device SHOULD write a snapshot when it is online and either holds no snapshot pointer in the
  current era, or has applied more than 200 self records since the latest snapshot.

## 8. Blobs and images

### 8.1 Image blobs

The client re-encodes an image through a canvas:

- this strips EXIF and location;
- the longest side is ≤ 2048 px;
- the format is `image/webp`, with `image/jpeg` as fallback;
- the result is ≤ 8 MiB.

```
key = random(32)
blob = aeadSeal(key, padme(bytes), aad = utf8("segv.sh/v2/blob")); id = b64u(H(blob))      ≤ BLOB_MAX = 12 MiB
```

- The IMAGE content (§3.3) carries `id`, `key`, the mime code, `w` and `h`.
- Receivers check `H(blob) = id` before decrypting, and accept only the two mime types.
- A decrypted image is cached by `(id, key)`, never by `id` alone.

### 8.2 BlobReg semantics (create-only, with registration time)

Every blob uploaded with `PUT /api/v2/blob/{id}` is stored in R2 under `b/{id}` and then **registered** in BlobRegDO
as `(id, size, t_reg)`, where `t_reg = tpub(BlobReg clock at the first registration)`.

- **Create-only.** The first registration of an id wins forever. Later uploads of the same content return the
  original `t_reg` and never change it.
- **Order.** The server registers only after R2 has stored the object and verified its SHA-256 against the id. A
  registered id therefore always has its object.
- **Recovery after a crash.** If the server crashed between storing and registering, re-uploading the blob registers
  it.
- **Who can see it.** `t_reg` and `size` are readable by anyone who knows the id (`GET …/meta`). There is no
  enumeration API in stage 1, so P cannot list blob ids: they appear only inside encrypted rows and inside key bundles
  that are referenced by encrypted claims. The registry's head enters the public checkpoints at most once per hour
  (§9.5), so P learns at most, per hour, whether any blob (image, snapshot or bundle) was registered.
- **Same mechanism for every blob.** SGB2 bundles, snapshots and images all use it. Only SGB2 bundles rely on `t_reg`
  (§6.4(g)).

## 9. Server components

**Batch commitments.** These are shared by every component that commits to its public rows:

```
leaf(data)  = H(0x00 ‖ data)
MTH(leaves) = RFC 6962 Merkle tree hash over the leaf hashes in the stated order; node = H(0x01 ‖ left ‖ right);
              MTH of one leaf = that leaf hash (batches are never empty)
head'       = H(enc("segv.sh/v2/head", cid, head, u32 t, u32 n, root))         head of the first batch: head = ZERO32
```

`cid` is the component id string:

| component | cid |
| --------- | --- |
| shard | `"shard/{E}/{i}"` |
| inbox | `"inbox/{E}/{g}"` |
| blob registry | `"blobreg"` |
| directory log | `"dirlog"` (a separate chain, §9.6) |

In every cid, numbers are decimal without padding.

**Identity and alarms (every per-era DO).** The Worker reaches a per-era DO with `getByName("shard/v2/{E}/{i}")` (or
`"inbox/v2/{E}/{g}"`). The DO derives `(E, i)` from `ctx.id.name`, which is available inside the object for ids
created by name. Every RPC also carries `E` and `i`; a mismatch is a programming error and throws. The constructor runs
`blockConcurrencyWhile`: if the era has not ended (the object's state is not sealed (ShardDO) or `ended` is not set
(InboxDO), and `now < end(E) + SKEW·1000`), it sets the alarm to `min(getAlarm(), due)`, where `due` is the earliest
of the seal time and an open batch's close time. A DO of an era that has already ended arms nothing; it seals
synchronously in `prepare()`. Every write that opens a batch arms `min(current alarm, batch due)` in the same
synchronous block as the commit. An alarm handler that still has work due re-arms at `max(due, now + 1000)` ms; it
never arms a time in the past, so an early alarm or a clock that steps back cannot make it fire in a loop.

### 9.1 ShardDO (`shard/v2/{E}/{i}`, SQLite; stage 1 has one per era, i = 0)

```sql
CREATE TABLE meta  (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
  -- 'state' 'open'|'sealed' | 'last_t' u32 | 'open_t' u32 (absent = no open batch)
  -- 'closed_t' u32 (t of the newest closed batch; absent = none) | 'head' 32 B (ZERO32 initially)
  -- 'delta' u16 (Δ, pinned by the first put that inserts a row; the deployment Δ applies until then; §3.1)
CREATE TABLE row   (id INTEGER PRIMARY KEY,
                    v BLOB NOT NULL CHECK (length(v) = 8), label BLOB NOT NULL CHECK (length(label) = 16),
                    t INTEGER NOT NULL, cls INTEGER NOT NULL CHECK (cls BETWEEN 0 AND 3),
                    bh BLOB NOT NULL CHECK (length(bh) = 32), body BLOB NOT NULL,
                    UNIQUE (v, label));
CREATE INDEX row_t ON row (t, label);            -- batch recomputation + public feed (no arrival order is exposed)
CREATE TABLE batch (t INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
```

Bodies (296–16 424 B) live in a rowid table: SQLite advises against WITHOUT ROWID for rows this large. The rowid is
internal and never exposed; feed and batches order by `(t, label)`. `bh` MUST equal `H(body)`. It is written with the
row and is internal (no RPC returns it); it exists so that closing a batch never reads, hashes or holds a body.

**Era state.**

- `now` = `Date.now()`, and `s = sec(now)`.
- `prepare()` runs first in every RPC: if `now ≥ end(E) + SKEW·1000` and the state is open, close the open batch and
  persist `state = sealed`, in one transaction.
- The seal alarm, due at `end(E) + SKEW·1000`, does the same.
- `MISS(sealed = 1)` is returned only once `state = sealed` is persisted.
- **Accept window.** Writes are accepted while `start(E) − SKEW·1000 ≤ now < end(E)`. Opening SKEW early means two
  shards whose clocks differ by at most SKEW never both refuse a write at an era boundary.

**Batches.**

- `closeBatch(t0)` requires `t0 > closed_t`. It reads `SELECT label, cls, bh FROM row WHERE t = t0 ORDER BY label`.
  Each leaf is `leaf(enc("segv.sh/v2/leaf", u16 E, label, u32 t0, u8 cls, bh))`, which is the leaf with `H(body)`. It
  computes `root` and `head'`, inserts the batch row, sets `head = head'` and `closed_t = t0`, and deletes `open_t`.
- An alarm is due at `T0 + (open_t + Δ)·1000 + 1000` while a batch is open. When it fires, close the batch if
  `tpub(now) > open_t`. Seal alarms and batch alarms share the one DO alarm: always arm the earliest that is due.
- **Batch size.** A batch holds every row put during its Δ window. Stage 1 sets no bound on the rows or bytes of a
  batch: the shard's request rate (`RL_WRITE`, the PoW of `put`, about 1 000 requests/s per DO) and FULL bound it.
  Closing a batch costs O(n) reads of `(label, cls, bh)`, and the feed streams batches of any size, charging one
  `RL_READ` token per started 4 MiB of the page's batches (without the page header), at least 1 and at most 64 (§10.9;
  rounds 8, 11 and 12).

**`put(E, i, rows: {v, label, cls, body}[])`** returns one result per row.

1. It first computes `bh = H(body)` for every row whose body length matches its class. It MAY await here (for example
   for native SHA-256).
2. Only then does it read `now` and run the rest synchronously inside `transactionSync`, with no await, so the CAS
   and the assignment of `t` are atomic:

```
prepare()
if state = sealed or now ≥ end(E) or now < start(E) − SKEW·1000:   every row → WRONG_ERA(era(now))
if storage.sql.databaseSize > 8 GiB:                                every row → FULL         (stage 1: no splitting)
t = max(tpub(now), last_t, sec(start(E)), closed_t + Δ if closed_t exists)
if open_t exists and t > open_t: closeBatch(open_t)
for each row (in order):
  if len(body) ≠ CLASSES[cls] + 40 or len(label) ≠ 16 or len(v) ≠ 8:  BAD
  o = SELECT t, cls, body FROM row WHERE v = ? AND label = ?
  if o:  CONFLICT(o.t, o.cls, o.body)
  else:  INSERT row (v, label, t, cls, bh, body); open_t = t; last_t = t; OK(t)
arm alarm if needed
```

`t` never decreases and never falls into a closed batch, even if the clock steps back (a restart on another host).
Rows inside one put are independent: there is no atomicity across rows. A duplicate label inside the same put returns
CONFLICT with the first copy.

**`get(E, i, keys: {v, label, mode}[])`** calls `prepare()` and then, for each key:

- if the row exists: `HIT(t, cls, body if mode = 0)`;
- otherwise `MISS(sealed = state = sealed ? 1 : 0)`.

The Worker enforces the response budget (§10.4).

**`head(E, i)`** calls `prepare()`, closes the open batch if `tpub(now) > open_t`, and returns
`{head, t_last, sealed, size}`, where `t_last` is `closed_t` or 0 and `size` is `databaseSize`.

**Feed RPCs** (internal; the HTTP page is §10.9). Both call `prepare()` and only read: they never close an open batch,
even a due one (the batch alarm, `head()`, a later `put` or sealing does), and the open batch is never readable. No
result carries more than the caller's `budget` of row bytes, because Workers RPC values are limited to 32 MiB.

- `feedBatches(E, i, after_t, budget)` returns the closed batches with `t > after_t`, ascending, each with its §10.9
  encoded size `72 + Σ(17 + len(body))`, computed without reading bodies. It stops before the first batch that would
  push the total past `budget`, but returns at least one batch when one exists, and also returns `more` (another
  closed batch follows) and `sealed`. When the total is ≤ `budget`, every batch carries its rows ordered by label.
- `feedRows(E, i, t, after_label, budget)` returns the rows of the closed batch `t` with `label > after_label`, ordered
  by label. It stops before the first row that would push the result past `budget`, but returns at least one row
  while any is left, plus `done`. It refuses a `t` that is not a closed batch.

This is the public enumeration of the database.

**Retention and capacity.** Old era DOs are kept and stay readable. Paging into R2 and deletion come in stage 2. A DO
stores at most 10 GB, and one object handles about 1 000 requests/s, so a single shard per era bounds stage 1 (§13.2
item 13). The CheckpointDO logs (§9.7) when a shard's `size` passes 4 GiB. The emergency path is S = 2 by
parameter for the next era, since routing by `v` already exists (stage-2 work).

### 9.2 BlobRegDO (`blobreg/v2`, SQLite, one instance)

```sql
CREATE TABLE meta  (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;   -- 'last_t', 'open_t', 'closed_t', 'head', 'hw',
                                                                          -- 'delta' (u16 Δ, pinned by the first write:
                                                                          -- a registration or a 'hw' raise; §3.1)
CREATE TABLE blob  (id BLOB PRIMARY KEY CHECK (length(id) = 32), size INTEGER NOT NULL, t INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX blob_t ON blob (t);
CREATE TABLE batch (t INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
```

**`register(id, size)`** returns `{t, size, created}`:

- If the row exists, return it with `created = false`.
- Otherwise `t = max(tpub(now), last_t, tpub(hw), closed_t + Δ if closed_t exists)`. Insert `(id, size, t)`, maintain
  the open batch exactly as the ShardDO does (including `closed_t`), and return `created = true`.

**`meta(id)`** returns `{t, size}` if the row exists. Otherwise it returns `MISS{now: sec(now)}` and first raises the
high-water mark: if `⌊sec(now)/Δ⌋ > ⌊hw/Δ⌋`, persist `hw = sec(now)`. This is at most one write per Δ. It guarantees
that every later registration gets `t ≥ tpub(every now ever reported)`, even if the clock steps back, which is what
makes §6.4(g) final.

**Batches.** Each leaf is `leaf(enc("segv.sh/v2/leaf/blob", H(id), u32 size, u32 t))`, ordered by `H(id)`.

**`head()`** works as for the shard. There is no enumeration RPC.

### 9.3 InboxDO (`inbox/v2/{E}/{g}`, SQLite; stage 1: β = 0, g = 0, bucket 0)

```sql
CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;     -- 'head', 'closed_hw', 'ended',
  -- 'slot' (Δin in seconds, pinned by the first write: a post that inserts a row, or the first persisted closed_hw;
  -- every rel and closed_hw is in units of it; §3.1)
CREATE TABLE inv  (id INTEGER PRIMARY KEY, bucket INTEGER NOT NULL, rel INTEGER NOT NULL,
                   eid BLOB NOT NULL CHECK (length(eid) = 16), body BLOB NOT NULL CHECK (length(body) = 1416),
                   UNIQUE (bucket, eid));
CREATE INDEX inv_rel ON inv (bucket, rel, eid);
CREATE TABLE cnt  (bucket INTEGER NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (bucket, day)) WITHOUT ROWID;
CREATE TABLE slot (rel INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
```

The slot clock uses milliseconds since T0 and `Δin` = `INBOX_SLOT` seconds (a deployment parameter; production 10,
tests 1). Let `D = Δin·1000` and `ms = now − T0`. D is computed from the pinned `'slot'` once it exists; a deployment
Δin that differs from it is an operator error (§3.1), logged once per instance and otherwise ignored.

```
closed  = max(⌊ms / D⌋, closed_hw)                     reported to readers; every row with rel ≤ closed is final
rel     = max(⌊(ms + j) / D⌋ + 1, closed_hw + 1)        j uniform in [0, D), drawn per row and never stored
```

- `closed_hw` is the largest `closed` ever used. Every operation that reports `closed` or commits slots up to it
  (`read`, `head`) MUST, when `closed > closed_hw`, persist `closed_hw = closed` before answering, in the same
  transaction as the slot rows it commits (at most one write per slot). So `rel > closed_hw` and `rel > ⌊ms/D⌋` always
  hold: a new row never lands in a slot that a reader has passed or that is already committed, even after a clock step
  back.
- **Era end.** Posts are accepted while `start(E) − SKEW·1000 ≤ now < end(E)` and `ended` is not set. Once
  `now ≥ end(E) + SKEW·1000`, `prepare()` (or the alarm) persists `ended = 1`. From then on `closed = max(R, closed_hw)`,
  where R is the largest `rel` of the era's rows (0 when it has none). Every row then has `rel ≤ closed` (all rows are
  final), and `closed` is constant (no post is accepted and `closed_hw` is no longer raised). Only then may the Worker
  mark responses immutable (§10.5).
- **Monotonic.** `closed` MUST never decrease: every `read` and `head` reports a `closed` that is ≥ every `closed`
  reported before, before and after `ended`.

**`post(E, bucket, rows: {eid, body}[])`** (1..32 rows) returns one result per row:

- If posts are not accepted (above), the whole call returns `WRONG_ERA(era(now))`.
- If `(bucket, eid)` exists with the same body, the row's result is its `rel` (an idempotent retry). With another body:
  `CONFLICT`.
- If `cnt(bucket, d) ≥ INBOX_DAY_CAP` (2000): `FULL`, where `d = max(⌊sec(now)/86400⌋, 7·E)`. The day
  `7·E = sec(start(E))/86400` is the era's first day, so a post accepted in the SKEW window before `start(E)` counts
  against that day.
- Otherwise insert, increment `cnt`, and return `OK(rel)`.

**`read(bucket, after, limit)`** returns `{closed, rows}`:

- `closed` as above.
- `rows` are those with `after < rel ≤ closed`, ordered by `(rel, eid)`.
- Whole `rel` groups are always returned. Once at least `limit` rows have been returned, the read stops before the
  next group, and `more = 1`.

**Slot commitments.** Before `read` and `head` answer, in the transaction that persists `closed_hw`, close every slot
with `rel ≤ closed` that has rows and no `slot` row yet. Each leaf is
`leaf(enc("segv.sh/v2/leaf/inbox", u16 E, u32 bucket, u32 rel, eid, H(body)))`, ordered by `(eid, bucket)` (bucket
breaks ties only in stage 2), and the chain uses `t = rel`.

**`head(E, g)`** settles as `read` does (persisting `closed_hw` and committing slots) and returns
`{head, t_last, ended}`: `t_last` is the `rel` of the newest slot row (0 when there is none), and `ended` says whether
`ended` is persisted.

**Retention.** Clients never read inbox eras older than `E_now − 3`, and the Worker answers 410 for them. The rows are
still stored (and committed).

**Size under attack.** The day cap bounds an era to 14 000 rows: 7 days of 2 000, the SKEW early window included
(about 19.8 MB of bodies). The 4 retained eras hold at most 56 000 rows (about 79.3 MB, 56 000 X-Wing
decapsulations). Only a device with no inbox cursor reads that much (§11.5).

### 9.4 RealtimeDO (`rt/v2/0`, SQLite meta only, hibernatable WebSockets, one instance)

**State.**

- Storage: a `meta` table holding `ws-tag-key`, 32 random bytes that key the opaque per-client tag.
- Per socket:
  - tags `[clientTag, "h:" + ⌊acceptMs / 3 600 000⌋]`;
  - the attachment `{t: acceptMs, topics: Uint8Array(16·n), win, frames, changes}` with at most 256 topics (4 KiB;
    attachments may hold up to 16 KiB).
- In memory:
  - `boot` = 8 random bytes chosen at construction, and `seq`, a u64 counter of published rows that starts at 0 per
    boot;
  - the index from an 8-byte topic prefix to sockets (the full 16 bytes are compared on delivery), rebuilt lazily from
    the attachments after a wake, and the total number of (topic, socket) pairs;
  - a **ring** of published rows, `(seq, topic, E, label, t, cls, body)`, keeping the last 10 minutes, at most 8192
    rows and at most 16 MiB, counting each row as `47 + len(body)` bytes (its ROWS encoding).

**Limits.**

- 8 sockets per client tag, and 20 000 sockets in total. Both are counted with `getWebSockets(tag)` and
  `getWebSockets()`, without deserialising attachments. Only sockets in state OPEN count (closing or closed sockets do
  not).
- 256 topics per socket, and 250 000 (topic, socket) pairs in total.
- Per socket, at most 30 SUB/UNSUB frames and 2 048 topic changes per minute (counted in the attachment, with `win` =
  the current minute `⌊now/60 000⌋`). A topic change is each topic a SUB or UNSUB frame carries (its `n`; duplicates
  and no-op changes count). RESUME counts toward neither (it is allowed once per socket); its topic set, after removing
  duplicates, counts toward the 256-topic cap and the 250 000-pair budget like a SUB. A frame is checked in this order:
  the rate (close 1008), topics per socket (1008), the pair budget (1013).
- A RESUME replays at most 2 MiB of rows; above that it gets GAP (§10.8).
- Frames up to 8 KiB.

With these limits the index (about 120 B per pair), the ring and the attachments stay well under the 128 MB memory of an
isolate.

**`fetch(upgrade)`** (from the Worker only):

1. Take the client tag from `x-segv-client` if it matches `^[0-9a-f]{32}$` (the Worker sends lowercase hex), else
   "none".
2. Refuse if the client already has 8 live sockets: 429, `retry-after: 60`.
3. Refuse if there are 20 000 live sockets in total, or if accepting fails: 503, `retry-after: 60`.
4. Otherwise accept with the tags, set the attachment, send HELLO, and return 101.

Sockets older than 1 h are closed with 4000. Whenever sockets are counted or sent to, every socket under an hour tag
older than the previous hour is closed, and a socket's exact age is checked before sending to it. Clients reconnect and
RESUME.

**`webSocketMessage`:**

- Text `"ping"` is answered `"pong"` (auto-response).
- Binary SUB, UNSUB and RESUME are handled as in §10.8.
- Anything else closes the socket with 1008: another text, a malformed binary frame, more than 256 topics on the
  socket, a frame over 8 KiB, a second RESUME, or a control-frame rate above the limits.
- A SUB that would push the total above 250 000 pairs closes the socket with 1013 (try again later).

**`publish(rows)`** (RPC from the Worker):

1. Give each row the next `seq` and append it to the ring.
2. For each socket subscribed to a row's topic, send one ROWS frame with the matching rows.
3. Drop sockets that fail to receive.

**Durability.** Nothing about topics or rows is persisted. After a restart, `boot` changes, so a RESUME gets GAP. A
hibernatable DO is also evicted after a short time without events (an auto-answered `ping` is not an event): its
in-memory state, the ring and `boot` included, is reset, and the constructor runs again on the next event. The
10-minute window is therefore an upper bound, reached only while the DO stays resident; at low traffic most RESUMEs
after a reconnect get GAP, which costs a catch-up (§11.6), never a lost row.

### 9.5 CheckpointDO (`ckpt/v2`, SQLite, one instance)

```sql
CREATE TABLE cp   (q INTEGER PRIMARY KEY, sec INTEGER NOT NULL, hd BLOB NOT NULL, heads BLOB NOT NULL,
                   C BLOB NOT NULL, sig BLOB NOT NULL);
CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;   -- 'final:<cid>', 'blobreg:hour', 'blobreg:head'
```

An alarm runs every 60 s and is re-armed in the same commit. When no alarm is set, the constructor (inside
`blockConcurrencyWhile`) and `ensure()` arm it at `now + 60 000` ms; `ensure()` writes nothing otherwise. The first
checkpoint is therefore made about 60 s after the object first runs, and `/ckpt/latest` answers 404 until then. The
Worker calls the DO's `ensure()` at most once per isolate (a module-level flag), never per request.

**Collecting heads.**

- Collect `(cid, head)` from:
  - `shard/{E_now}/0` and `inbox/{E_now}/0`;
  - `shard/{E_now−1}/0` and `inbox/{E_now−1}/0`, when `E_now − 1 ≥ max(E_FIRST, 0)`, until the component reports
    `sealed` (shard) or `ended` (inbox) and that final head has appeared once; then `final:<cid>` is persisted in the
    same transaction as that checkpoint (alone when `hd` is unchanged) and the cid is no longer collected. Eras before
    `E_now − 1` are never collected: if no checkpoint succeeds between `end(E) + SKEW·1000` and `end(E+1)`, era E's
    final head never appears (accepted in stage 1);
  - `blobreg`, **at most once per hour**: with `hour = ⌊now / 3 600 000⌋` (Unix ms, so UTC hours), the first alarm
    whose `hour` exceeds the stored `blobreg:hour` reads the registry head; on success it persists
    `blobreg:hour = hour` and `blobreg:head` in the same transaction as the checkpoint (alone when `hd` is unchanged).
    A failed read changes nothing, so the next alarm retries within the same hour. Every other checkpoint reuses
    `blobreg:head` (before any successful read, the previous checkpoint's head, else blobreg is left out). P therefore
    learns at most, per hour, whether any blob was registered;
  - `dirlog`, read from D1 (`SELECT seq, h FROM dirlog ORDER BY seq DESC LIMIT 1`), or ZERO32 while the dirlog is
    empty (a table that does not exist yet counts as empty); any other D1 error is a failure.
- Each component call has 10 s to answer. A component that fails (an error or no answer in time) keeps its head from
  the previous checkpoint's list; one that has no head there (it has never answered) is left out of the list, never
  listed as ZERO32. A failing component never delays or blocks the checkpoint.
- A component with no closed batch (shard) or slot (inbox) reports `head = ZERO32` and is listed with it, in the
  current and the previous era alike.
- A previous-era component's final head (its head once it reports `sealed` or `ended`) has *appeared* once it is in
  the list of a checkpoint: the one built from this collection, or, when `hd` equals the previous `hd` and no
  checkpoint is made, checkpoint q−1, whose list is identical.
- Sort the list by cid (byte order).
- Log (§9.7) when a shard reports `size` above 4 GiB.

**Building and signing.**

```
hd  = H(enc("segv.sh/v2/ckpt/heads", [cid_1, head_1, cid_2, head_2, …]))
C_q = H(enc("segv.sh/v2/ckpt", C_{q−1}, u32 q, u32 sec, hd))            C_0 = ZERO32, q starts at 1
sig = SIG.sign(enc("segv.sh/v2/ckpt-sig", u32 q, C_q), SRV_SK)
```

where `sec = max(sec(now), sec_{q−1})` (`sec_0 = 0`): checkpoint times never decrease, even when the clock steps back.
If `hd` equals the previous `hd`, no new checkpoint is made, so `q` grows at most once per 60 s. `heads` stores the
encoded list for audit.

**Server key.** `SRV_SK` is a 32-byte Ed25519 seed held as a Worker secret. Its public key, `srvKey`, is in params.
The same key signs receipts (§10.3).

### 9.6 Directory (D1)

```sql
CREATE TABLE user (
  uid TEXT PRIMARY KEY,            -- b64u(16 B)
  upre INTEGER NOT NULL,           -- u32, §2.5
  handle TEXT NOT NULL UNIQUE,
  hpre INTEGER NOT NULL,           -- u32
  bundle TEXT NOT NULL, sig TEXT NOT NULL,   -- exact signed text, b64u signature
  reg_era INTEGER NOT NULL,        -- era(server time) at registration
  dirseq INTEGER NOT NULL
);
CREATE INDEX user_upre ON user (upre);
CREATE INDEX user_hpre ON user (hpre);
CREATE TABLE wrap (
  uid TEXT NOT NULL, id TEXT NOT NULL,       -- b64u
  record TEXT NOT NULL, sig TEXT NOT NULL, dirseq INTEGER NOT NULL,
  PRIMARY KEY (uid, id)
);
CREATE INDEX wrap_id ON wrap (id, dirseq);
CREATE TABLE dirlog (seq INTEGER PRIMARY KEY, kind INTEGER NOT NULL, ref TEXT NOT NULL, h TEXT NOT NULL);
CREATE TABLE dirmeta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);   -- 'users': the number of user rows
INSERT INTO dirmeta (k, v) VALUES ('users', 0);                  -- in the same migration: the UPDATE below needs the row
```

**The dirlog chain.**

```
ref_user = H(enc("segv.sh/v2/dir/user", bundleBytes, bundleSig))
ref_wrap = H(enc("segv.sh/v2/dir/wrap", recordBytes, recordSig))
h_seq    = H(enc("segv.sh/v2/dirlog", h_{seq−1}, u64 seq, u8 kind, ref))       h_0 = ZERO32; kind 1 = user, 2 = wrap
```

Each `ref` and `h` is stored as b64u text, and `dirseq` = the dirlog `seq` of the row.

**Writes.**

1. Read the dirlog head.
2. Compute the new entries.
3. Run one D1 `batch()`, which is atomic: `INSERT user`, `INSERT wrap…`, `INSERT dirlog…` with explicit seqs, and, for
   a registration, `UPDATE dirmeta SET v = v + 1 WHERE k = 'users'`.
4. Handle failures:
   - a `UNIQUE` failure on `dirlog.seq` (a concurrent writer) means: wait a random 5–50 ms times the attempt number,
     re-read the head and retry, up to 16 attempts, then answer 503;
   - a failure on `user.handle` or `user.uid` means 409;
   - a failure on `wrap (uid, id)` means 409.

At most 64 wraps per uid (400 beyond that). D1 is authoritative: there is no outbox and no log fallback. If D1 is
unavailable, directory writes and directory reads (register, wraps, prefix, uid and wraps lookups, dirlog) answer 503
`{error: "directory unavailable"}`. The one exception is `p` in `/api/v2/params` (§10.9), which MUST NOT fail or wait
because of D1. `users` (and so `P`) is read from `dirmeta` and cached per isolate for at most 60 s while D1 answers.
While the `dirmeta` read fails, params reports the `P` of that isolate's last successful read, or 0 when there is none;
the failure is logged, and after a failed read the isolate MUST NOT query `dirmeta` again for 5 s. A prefix lookup
uses the same cached value and answers 503 while the isolate has none; it never treats the count as 0. `dirmeta.users`
never decreases, so a cached or stale `P` is never above the current one.

**Prefix reads.** A lookup of the top `p` bits equal to `x` returns exactly the rows with `lo ≤ hpre ≤ hi` (or `upre`),
and with `uid > after` when `after` is given, ordered by `uid` (the stored b64u text, §10.6), at most 256 per page. The
server reads up to 257 rows; the extra row decides `more`. `lo = x · 2^(32−p)` and `hi = lo + 2^(32−p) − 1`, computed
with arithmetic, never with 32-bit shifts (`1 << 32` is 1 in JavaScript). `p = 0` covers the whole table. The server
MUST accept every `p` with `0 ≤ p ≤ min(32, P + 1)`; stage 1 has no lower bound on `p`. The spec fixes the result, not
the query plan. The server SHOULD bound the rows one page reads: it reads the range through the `hpre`/`upre` index
when `users / 2^p ≤ 257 · 2^p`, and otherwise walks the `uid` primary key in order and filters by the prefix (for
SQLite: `+hpre BETWEEN …`, which keeps the planner off the prefix index). No page then reads more than about
`√(257 · users)` rows, and a `p = 0` page reads about 257. The user count `P` is derived from `dirmeta.users`, never
from `count(*)`.

### 9.7 Hardening (all endpoints)

These carry over from v1:

- `APP_HOSTS` host pinning: other hosts get 421 on `/api/*` and a 308 to the canonical host on pages. A 421 on
  `/api/v2/*` carries `x-segv-now`, `nosniff`, `no-referrer`, and HSTS on https, like every other v2 response;
- HSTS on https; `nosniff` and `no-referrer` on every response, except the `101` WebSocket upgrade, whose headers are
  immutable and which the Worker passes on unchanged (§10.1), as v1's `finalize` does;
- `workers_dev: false` and `preview_urls: false`;
- Workers invocation logs disabled;
- **Logs** (round 10): `console.error` lines carry no request bodies, client addresses or headers, uids, handles,
  labels, eids, topics, blob ids or credential ids, and error messages, which may quote such values, are redacted
  before they are logged (this implementation's `logErr`); public values (deployment parameters, the era of the
  object that logs, a route label without path parameters, counts and sizes) may appear. Their text, keys and format
  are implementation-defined (preamble);
- an `HttpError` cancels any request body that was not read;
- a rate limiter error fails closed with 503;
- request bodies are capped by both the declared and the actual length: above the endpoint cap → 413, and an actual
  length that differs from Content-Length → 400 (blob PUT: §10.7).

New in stage 1:

- **Era bounds before any DO.** The Worker checks `E` with its own clock before it routes a request, so nobody can
  instantiate (and arm alarms in) arbitrary era objects. With `lo = era(now − SKEW·1000)` and
  `hi = era(now + SKEW·1000)`:
  - put rows and inbox posts need `lo ≤ E ≤ hi`, else WRONG_ERA (put) or 409 (inbox), without a DO call;
  - get, feed, era and inbox reads with `E > hi` get NO_ERA (get) or 400/404, and with `E < E_FIRST` (a deployment
    parameter: the era of the first deploy) get `MISS(sealed = 1)` (get) or 404, without a DO call. An inbox read with
    `E < E_now − 3` gets 410 first (§10.5).
- **Cache before limits.** Immutable responses (blob GETs, ended inbox eras, `/ckpt/{q}`, immutable feed pages whose
  batches fit the 4 MiB page budget) and the short-lived inbox tail (§10.5) are served from `caches.default` when
  present, before the rate limiter. The Worker strips `x-segv-now` before `cache.put` and stamps a fresh `x-segv-now`
  on the response it returns, after the cache lookup (§10.1). A feed page streamed because its one batch exceeds
  4 MiB (§10.9) is not stored in `caches.default` (copying the stream would buffer the whole batch); it is sent
  without Content-Length and with the same `cache-control` as any other page, and costs one `RL_READ` token per
  started 4 MiB of the page's batches (without the page header), at most 64 (§10.9; rounds 8 and 11).

The Worker passes Durable Objects only what they need. Client addresses and headers never reach a DO; the RealtimeDO
gets the opaque client tag only.

## 10. HTTP and WebSocket API

### 10.1 General

- **Paths.** Every endpoint is under `/api/v2/`. Any other `/api/*` path returns 404. A wrong method returns 405 with
  `allow`.
- **Bodies.**
  - Binary bodies use `content-type: application/octet-stream` and the layouts below.
  - JSON bodies are UTF-8 objects with exactly the listed keys.
  - Every response that is not 2xx is JSON `{error: string, …}`.
  - Responses are `cache-control: no-store` unless stated otherwise.
- **Server time.** Every `/api/v2/*` response carries `x-segv-now: <server ms>`. This covers successes and errors
  alike: the 421 of host pinning (§9.7), the 503 `server misconfigured`, the router's 404 and 405, and every non-101
  answer of `/api/v2/rt` (426, 403, 429, 503). The header is set on the response object the Worker returns, after any
  `caches.default` lookup, and is never stored in `caches.default` (§9.7). The one exception is the `101` WebSocket
  upgrade of `/api/v2/rt`, which the RealtimeDO returns with immutable headers; the Worker passes it on unchanged, and
  HELLO carries the server time instead (§10.8). `x-segv-now` (and params `now`) is the Worker's `Date.now()` taken
  when it starts handling the request, before any cache lookup or DO call: the same value it uses for era bounds and
  the PoW window. Clients take clock samples **only from responses whose `cache-control` is `no-store`**, and from
  HELLO: a `public` response (blob GETs, `/ckpt/{q}`, inbox reads, immutable feed pages) may be replayed by the
  browser's HTTP cache with the header it was first stored with, possibly weeks old. A sample is `(s, mid, rtt)`: `s`
  is the server time; `rtt` is the client's monotonic time from just before sending the request to receiving the
  response headers (for HELLO, from the upgrade request to the HELLO frame); `mid` is the monotonic midpoint. It
  estimates server time as `s + (mono_now − mid)`. When a sample arrives, the client SHOULD discard every older sample
  whose estimate at the new sample's `mid` differs from the new `s` by more than `(rtt_old + rtt_new)/2 + SKEW + 1 s`:
  the monotonic clock stopped in between (a browser's `performance.now()` commonly stops while the system sleeps) or a
  clock stepped, and the newer answer wins. Among the remaining samples taken in the last 10 minutes (monotonic), a
  client SHOULD use the one with the smallest `rtt`, and the newest among equal ones; a sample with `rtt > 2 s` SHOULD
  be used only when no sample with `rtt ≤ 2 s` was taken in the last 10 minutes; with no sample younger than 10
  minutes, the client uses the newest one. The estimate never reads the wall clock (`Date.now()`), which the user or
  the system may set; only the elapsed-time checks of §11.3 steps 6 and 8 read it. Every API call a client makes
  regularly (`get`, `put`, params, `blob/meta`, directory, `ckpt/latest`) is `no-store`, so the estimate of §3.1 never
  goes stale.
- **Hardening.** §9.7 applies to every response (the `101` upgrade only through its exemption), including the era
  bounds and the cache-before-limits rule.

**Status codes:**

| code | meaning |
| ---- | ------- |
| 200 / 201 | success (put and get carry per-row status inside a 200) |
| 400 | malformed request (bad layout, length, encoding, class, count, id or handle) |
| 403 | missing, malformed, stale or insufficient proof of work |
| 404 | unknown path, user, uid, blob, era or checkpoint |
| 405 | wrong method |
| 409 | conflict: handle or uid taken, duplicate wrap, inbox wrong era (`{error, era}`), directory prefix bits out of range (`{error, p}`) |
| 410 | inbox era older than `E_now − 3` |
| 411 / 413 | blob without Content-Length / too large; body over the endpoint cap |
| 421 | host not in `APP_HOSTS` |
| 426 | `/api/v2/rt` without an upgrade |
| 429 | rate limited, or too many sockets from this client (`retry-after`) |
| 503 | rate limiter or D1 unavailable, global socket cap, server misconfigured (missing secrets, invalid parameters), a failed Durable Object call on put or get (`retry-after: 5`) |
| 500 | internal error (other routes MAY answer 500, or 503 `{error: "storage unavailable"}`, for a failed Durable Object or R2 call; clients treat every 5xx alike; round 10) |

**Order of checks.** The Worker answers with the first check that fails, in this order:

1. host pinning: 421 (§9.7);
2. server configuration (secrets, deployment parameters, §3.1): 503 `{error: "server misconfigured"}`, without any DO
   or D1 call;
3. path: 404 when no route matches; method: 405 with `allow`; for `/api/v2/rt`: 426 without an upgrade, 403 for a
   foreign Origin;
4. for the cacheable GETs (blob, inbox read, feed page, `/ckpt/{q}`): the path, query and era-bound checks that need
   no storage (§9.7, §10.5, §10.9), then the `caches.default` lookup; a hit is returned here;
5. the rate limit: 429 with `retry-after`, or 503 when the limiter fails;
6. for requests with a body, the declared length before any byte is read. Blob PUT: missing → 411, above 12 MiB →
   413, below 41 B → 400. Other endpoints: above the endpoint cap → 413. A malformed Content-Length → 400. Then, while
   the body is read: more bytes than the cap → 413, and a length that differs from the declared one → 400 (blob PUT:
   §10.7);
7. proof of work: 403;
8. strict parse of the binary layout or JSON body: 400;
9. the endpoint's own rules (era bounds per row or key, bucket, directory rules, DO and D1 answers).

For endpoints whose PoW digest is `H(body)`, step 6 reads the whole body before step 7. A blob PUT reads its body only
while streaming it into R2, after its PoW and its registry check (§10.7). Where this list does not order two checks
(for example two parameter checks, or a parameter check of a non-cacheable GET against the rate limit), either answer
conforms. Example: a put with Content-Length 263 346 gets 413 without a PoW check. Within step 9, a check that needs
stored state and the 5xx of a failed D1, Durable Object or R2 call are not ordered against each other either: during a
D1 failure, an isolate that holds a cached `P` (§9.6) answers 409 for a prefix lookup whose `p` is out of range, and
one without answers 503; both conform, and a client that gets 409 and then 503 on its one retry fails the lookup as
transient (§10.6; round 10).

### 10.2 Proof of work and rate limits

```
window = ⌊serverNowMs / 600000⌋
pre    = H(enc("segv.sh/v2/pow", scope, u32 window, digest))
valid  ⇔ leadingZeroBits(H(pre ‖ u64 nonce)) ≥ powDifficulty(scope, base, bytes)
header   x-segv-pow: "<window>.<nonce>"      (^\d{1,12}\.\d{1,16}$; window ∈ {current, current−1}; nonce ≤ 2^53 − 1)
powDifficulty(scope, base, bytes) = base + ⌈log2(bytes / unit)⌉ if bytes > unit else base
```

| scope | digest | bytes | unit | default base (env var) |
| ----- | ------ | ----- | ---- | ---------------------- |
| `register` | H(body) | len(body) | — (always base) | 20 (`POW_REGISTER`) |
| `wrap` | H(body) | len(body) | — | 18 (`POW_WRAP`) |
| `put` | H(body) | len(body) | 4096 | 16 (`POW_PUT`) |
| `inbox` | H(body) | len(body) | 4096 | 18 (`POW_INBOX`) |
| `blob` | raw 32-byte id | Content-Length | 1 MiB | 18 (`POW_BLOB`) |

Overrides must match `^\d{1,2}$` and be ≤ 64. Clients refuse a base above 26. On 403 a client retries once with fresh
params. The nonce is the decimal value of the `u64` that is hashed; the server answers 403 "malformed proof of work"
for a nonce above 2^53 − 1 (round 8). Clients search nonces upward within that bound, both halves of the `u64`
included, so the search is bounded by time only (round 9). A proof is accepted only while its window is the current
or the previous one, 10 to 20 minutes (round 10): a client searches with the window that is current by its estimated
server time, and when that window stops being current before a nonce is found, it MUST restart the search with the
new window (a new `pre`), so it never sends a proof that is already stale. Restarting loses nothing, because every
nonce is an independent trial. The expected work is `2^difficulty` hashes: at the highest base a client accepts (26), a
full put (33 bits) expects about 8.6·10^9 hashes, over an hour in a browser tab, and a deployment that raises the base
that far accepts that cost.

**Per-IP rate limits.** The key is the IPv4 address or the IPv6 /64 (an IPv4-mapped address counts as IPv4). Keys are
never stored.

| binding | limit | endpoints |
| ------- | ----- | --------- |
| `RL_WRITE` | 60 / 60 s | register, wraps, put |
| `RL_INBOX` | 10 / 60 s | inbox post (one token per POST of up to 32 invites) |
| `RL_BLOB` | 20 / 60 s | blob PUT |
| `RL_READ` | 600 / 60 s | get, inbox read, directory reads, dirlog, blob GET and meta, ckpt, feed (one token per started 4 MiB of the page's batches, without the page header, at least 1 and at most 64, §10.9; rounds 8, 11 and 12), era, rt upgrade |

`/api/v2/params` is not rate limited (§9.5: it never reaches the CheckpointDO per request). Responses served from
`caches.default` (§9.7) are not counted.

### 10.3 `POST /api/v2/put` (binary; PoW `put`; `RL_WRITE`; body ≤ 263 345 B)

```
request  = u8 count (1..16) | row × count
row      = u16 E | label[16] | u8 cls (0..3) | topic[16] | body[CLASSES[cls] + 40]        topic = ZERO16 ⇒ no realtime publish
response = u8 count | result × count                                                  same order as the request
result   = u8 0 (OK)        | u32 t | receipt[64]
         | u8 1 (CONFLICT)  | u32 t | u8 cls | body[CLASSES[cls] + 40]                the occupying row
         | u8 2 (WRONG_ERA) | u16 E_current
         | u8 3 (FULL)
         | u8 5 (BAD)
receipt  = SIG.sign(enc("segv.sh/v2/receipt", u16 E, label, H(body), u32 t), SRV_SK)
```

Status 4 (MOVED) is reserved for stage 2. The body cap is exactly the largest valid request,
`1 + 16 × (2 + 16 + 1 + 16 + 16 424) = 263 345` B; params report it as `limits.putBytes`.

The Worker:

1. Checks the host, the rate limit, and the size.
2. Checks the PoW.
3. Parses the request strictly (400 on any layout error).
4. Computes `v(E, label)` and `shard`, groups rows by `(E, shard)`, and calls each ShardDO's `put`. If any of these
   calls throws (a DO error, an overloaded or reset object, a failed RPC), the Worker MUST answer **503**
   `{error: "storage unavailable"}` with `retry-after: 5` for the whole request: no per-row results, no receipts, and
   nothing published, even for groups that answered. Rows of any group (the failing one included) may nevertheless be
   stored. A client MUST treat this 503, like any 5xx, network error or timeout, as "outcome unknown" and resolve each
   row by probing its slot (§11.3 step 6); a HIT with its own body is its own write.
5. Signs a receipt for every OK.
6. Publishes OK rows that carry a topic to the RealtimeDO through `ctx.waitUntil` (one `publish` call, at most one
   retry). Publishing never delays or changes the response.

Clients MUST verify receipts against the pinned `srvKey` and keep the receipts of their own rows for the session.

### 10.4 `POST /api/v2/get` (binary; `RL_READ`; body ≤ 8 KiB)

```
request  = u16 count (1..256) | key × count
key      = u16 E | label[16] | u8 mode (0 = body, 1 = exists)
response = u16 count | status × count
status   = u8 0 (HIT)     | u32 t | u8 cls | [body[CLASSES[cls] + 40] if mode = 0]
         | u8 1 (MISS)    | u8 sealed (0|1)
         | u8 2 (SKIPPED)                                       response budget (4 MiB of bodies) reached: ask again
         | u8 3 (NO_ERA)                                        E > era(server now + SKEW)
```

The Worker groups keys by `(E, shard)` for the DO calls and answers in request order. Keys with `E < E_FIRST` get
`MISS(sealed = 1)` and keys with `E > era(now + SKEW)` get NO_ERA, both without a DO call (§9.7).
`MISS(sealed = 1)` is final: era E can no longer gain that row. If any ShardDO `get` call throws, the Worker answers
503 `{error: "storage unavailable"}` with `retry-after: 5` for the whole request.

**Response budget.** The Worker MUST then walk the keys in request order with a budget of 4 194 304 bytes (4 MiB) of
HIT bodies:

- an exists-mode key (`mode = 1`) is answered with its status and costs nothing; it is never SKIPPED;
- a body-mode key (`mode = 0`) is answered with its status while no key has been skipped. A HIT costs its body length
  and is returned only if that length is ≤ the remaining budget (a total equal to the budget fits);
- the first body-mode HIT whose body exceeds the remaining budget, and every later body-mode key whatever its status
  would have been (HIT, MISS, NO_ERA), is answered SKIPPED (2).

The answered body-mode keys are therefore always a prefix of the request's body-mode keys, and the returned bodies
never total more than 4 MiB. The first body-mode HIT always fits, so every response makes progress; with at most 256
keys only a request of 256 class-3 body HITs reaches the budget (255 × 16 424 = 4 188 120 B fit, and the 256th is
SKIPPED). SKIPPED carries no information about the key: a client MUST NOT draw any conclusion from it (in particular
it never ends a dense prefix) and MUST ask for the key again in a later request.

### 10.5 Inbox

`POST /api/v2/inbox` (binary; PoW `inbox`, priced by the body length; `RL_INBOX`, one token per request; body =
exactly `7 + 1432·count` B, at most 45 831 B):

```
request  = u16 E | u32 bucket | u8 count (1..32) | (eid[16] | body[1416]) × count
response = 200, JSON {"results": [{"rel": <u32>} | {"error": "conflict"} | {"error": "full"}, …]}     same order
```

One request carries the invites of one delivery burst (§6.12), so a 32-member creation needs one request, not 31.
Errors:

- 400: `bucket ≠ 0` in stage 1, a bad count, or a bad length.
- 409: `{error: "wrong era", era}` when E is not accepted (§9.3, §9.7).
- Per row: `conflict` (the eid is taken with another body) and `full` (the day cap).

`GET /api/v2/inbox/{E}/{bucket}?after=<rel>&limit=<1..1024, default 1024>` (binary; `RL_READ`):

```
response = u32 closed | u8 more | u32 count | (u32 rel | eid[16] | body[1416]) × count      ascending (rel, eid)
```

The server returns rows strictly ascending by `(rel, eid)` (eid compared bytewise), every row with
`after < rel ≤ closed`, whole `rel` groups (§9.3), and at least one row when `more = 1`. A client decoder MUST reject a
response whose `rel` values decrease, and treats it as a failed read (retry later, like a 5xx); it need not check the
`eid` order, which no decision uses. The engine ignores rows with `rel ≤ after` or `rel > closed` (duplicates are
harmless, §6.7 step 3). With `more = 1`, the next page uses `after` = the `rel` of the last row, and a `more = 1` page
that holds no row with `rel > after` is a failed read.

Errors, checked in this order before any cache lookup, rate limit or DO call (`E_now = era(Worker now)`):

1. 400 for a path whose E is above 0xFFFE or whose bucket is not a u32;
2. 400 for `bucket ≠ 0`;
3. 400 for `E > era(now + SKEW)`;
4. 410 for `E < E_now − 3`, also when E is below `E_FIRST`;
5. 404 for `E_now − 3 ≤ E < E_FIRST`;
6. 400 for an `after` that is not a decimal u32, or a `limit` outside 1..1024.

Clients never read eras below `E_FIRST`: their cursor starts at `max(regEra, E_now − 3)`, and `regEra ≥ E_FIRST`.

Cache rules:

- A 200 response for an era whose InboxDO has persisted `ended` (§9.3) and that has `more = 0` is immutable
  (`public, max-age=31536000, immutable`).
- Every other 200 response is `public, max-age=Δin`: the current era, a past era whose InboxDO has not yet persisted
  `ended` (normally the SKEW seconds after `end(E)`), and any response with `more = 1`.
- The Worker serves every inbox read from `caches.default` when present, before the rate limiter (§9.7). Entries are
  keyed by the canonical `(E, bucket, after, limit)` (an absent `after` is 0 and an absent `limit` is 1024), and each
  200 response is stored with its own `cache-control`. Every row up to the reported `closed` is final, so a response
  at most Δin old is still correct; most clients poll with the same `after` (the last `closed`), and §11.5 step 3's
  `2·Δin` margin covers the cache age.

### 10.6 Directory (JSON)

**`POST /api/v2/register`** (PoW `register`; `RL_WRITE`; body ≤ 64 KiB):

- Body `{"bundle": text, "sig": b64u, "wraps": [{"record": text, "sig": b64u}, …1..4]}`.
- The server checks the canonical bundle, the field sizes, the handle regex, `bundleSig`, and `checkUserKeys`. For
  every record it checks canonical form, sizes, `uid` equal to the bundle's, `recordSig` under the bundle key, and
  that ids are distinct (compared as decoded bytes).
- Every failed check is 400: shape, size, canonical form, handle, `bundleSig`, `checkUserKeys`, a record `uid` that
  differs from the bundle's, a repeated id, a bad `recordSig`, and 0 or more than 4 wraps. 409 is only for a handle or
  uid that is already registered.
- It writes the user, the wraps and the dirlog entries atomically (§9.6).
- On success: 200 `{"dirseq": n}`, where n is the dirlog seq of the user entry (kind 1), i.e. the user's `dirseq` in
  lookups; its wrap entries take the following seqs n+1 … n+w in request order.

**`POST /api/v2/wraps`** (PoW `wrap`; `RL_WRITE`; body ≤ 16 KiB):

- Body `{"record": text, "sig": b64u}`.
- The server checks, in this order: body and record shape, size and canonical form (400); unknown uid (404);
  `recordSig` under the uid's registered bundle key (400); the cap of 64 records per uid, counted in the same D1
  snapshot as the dirlog head (400 when the uid already has 64); then the insert, where a duplicate `(uid, id)` is 409.
  A request that is both over the cap and a duplicate therefore answers 400.
- On success: 200 `{"dirseq": n}`, the seq of the wrap's dirlog entry.
- A client MUST NOT take a 400 or a 409 as proof that its record is stored. After a network error, a timeout or a
  5xx, it looks up `GET /api/v2/dir/wraps/{id}?uid=<its uid>`, and the add succeeded if and only if its exact record
  text is listed.

**User lookups.** `GET /api/v2/dir/h/{p}/{x}` and `GET /api/v2/dir/u/{p}/{x}`:

- `p` is the number of prefix bits (decimal, 0..32) and `x` the prefix value (decimal, `0 ≤ x < 2^p`).
- The server accepts `p ∈ [0, min(32, P+1)]`, where `P = max(0, ⌊log2(users / 32)⌋)` is reported in params and
  `users` is `dirmeta.users`. Otherwise it answers 409 `{error, p: P}`.
- The Worker MAY cache `dirmeta.users`, and so `P`, per isolate for at most 60 s (§9.6). A cached `P` is never above
  the current one, and since the client uses `p ≤ P* − 1` with `P*` never above the current `P` (below) while the
  server accepts `p ≤ P + 1`, lookups survive growth of up to a factor 4 in users within the cache lifetime. A client
  that receives 409 `{error, p: P′}` MUST recompute `p` with `min(P*, P′)` in place of `P*` (not raised again by the
  `dirSeq` bound) and retry once; it never raises `p` because of a 409. If the retry also fails, the lookup fails like
  a transient failure (it never makes a user unknown).
- Rows are those whose `hpre` (or `upre`) has the top p bits equal to x (a `BETWEEN` range, §9.6). They are ordered by
  the stored b64u `uid` text, compared bytewise (SQLite BINARY collation; this is not the order of the raw uid bytes).
  A page holds at most 256 users: the server reads up to 257 rows and returns the first 256, and `more = true` if and
  only if a 257th row exists, so a page with `more = true` holds exactly 256 users. The next page passes
  `?after=<uid of the last user returned>`, which must be a canonical b64u 16-byte uid (else 400), and returns users
  with `uid > after` in the same order.
- **Client choice of p.** The client MUST use `p = max(0, min(P* − 1, ⌊log2(dirSeq / 64)⌋, 16))` with
  `P* = max(P, ⌊log2(dirSeq / 2080)⌋)`, where `P` is the params value and `dirSeq` is the dirlog head `seq` (read once
  per session, before its first prefix lookup, from `/api/v2/dirlog`; every account adds at least two dirlog entries).
  The second term of `P*` counts only when `dirSeq ≥ 2080`. Every account adds at most 65 dirlog entries (one user
  entry and at most 64 wraps), so the true `P` is at least `⌊log2(dirSeq / 2080)⌋`: `P*` is never above the current
  `P`, and a `P` of 0 (or a stale `P`) reported during a D1 outage (§9.6) widens lookups at most down to that bound.
  An operator that inflates `P` to make lookups exact must also inflate the public, audited dirlog. A client whose
  params `P` is below `⌊log2(dirSeq / 2080)⌋` MAY re-read params first (at most once per 60 s), because the bound is
  usually a few bits below the true `P`. If a page for `p ≥ 1` returns fewer than 8 users, the client gives the noise
  warning "the directory answered fewer accounts than expected". Clients cache prefix responses for the session.
- **When clients look up.** A prefix response holds `users / 2^p` bundles (about 64–128, each about 1.9 KB, so
  120–240 KB). Clients therefore look a user up only to resolve a handle (creation, add; this also gives the new
  member's `kemPk`), to resolve a link owner by uid (§5.5), and to verify a co-member or a joiner's `D.by` the first
  time (then a MEMBER record is written, §7.3). Commits and J deliveries take every other `kemPk` from the bundles
  (§5.4, §6.12).
  Restores and catch-ups use MEMBER records and make no lookup for known members (§11.4).
- Response: `{"p": p, "users": [{"uid", "handle", "bundle", "sig", "regEra", "dirseq"}], "more": bool}`.
- Clients MUST verify every bundle they use (`verifyBundle`, `checkUserKeys`, `uid` and `handle` match), filter
  locally, and compare with their CONTACT and MEMBER pins (§7.3).
- **Transient failures.** Only a complete answer (every page fetched, the last with `more = false`) that lacks the
  handle or uid means "no such user". A network error, a timeout, a 429, a 5xx or a page sequence that does not
  complete is retried, or fails the operation with that error; it never makes a handle unknown (§6.1 step 1, §6.3)
  or a member unknown (§11.2), and a join that needs the lookup is parked (§6.7).

**`GET /api/v2/dir/uid/{uid}`** is the exact lookup of one user. Clients use it only for their own account.
Response: `{"user": {…} }`, or 404.

**`GET /api/v2/dir/wraps/{id}[?uid=<b64u>]`** returns `{"wraps": [{"uid", "record", "sig", "dirseq"}]}`:

- at most 64 records, oldest (lowest dirseq) first;
- `id` is 1..1023 bytes and `uid` 16 bytes;
- an unknown id returns an empty list (status 200).

**`GET /api/v2/dirlog?after=<seq>&limit=<1..1000>`** returns `{"entries": [{"seq", "kind", "ref", "h"}],
"head": {"seq", "h"}}`. It is the public audit log of the directory. `after` defaults to 0 and `limit` to 1000; a
value out of range → 400. While the dirlog is empty, `head` is `{"seq": 0, "h": b64u(ZERO32)}`.

### 10.7 Blobs

**`PUT /api/v2/blob/{id}`** (`id` = 43 b64u characters for 32 bytes; PoW `blob`; `RL_BLOB`):

- The Worker checks, in this order (§10.1): the rate limit; Content-Length (411 without it, 400 when malformed, 413
  over 12 MiB, 400 below 41 bytes); the PoW, priced by the declared Content-Length.
- If BlobReg already has the id, respond `201 {"id", "size", "t"}` with the registered values, without reading the
  body (the Worker cancels it).
- Otherwise, if R2 already holds `b/{id}` with a stored SHA-256 equal to the id (an earlier upload was stored but never
  registered, e.g. after a crash between the two steps), the Worker MUST NOT read the body (it cancels it), MUST skip
  step 1, and MUST call `BlobReg.register(id, size)` with the stored object's size, never the declared Content-Length.
  It then answers as in step 3.
- Otherwise:
  1. Stream the body into R2 `b/{id}` through a fixed-length stream with `sha256 = id`. A mismatch → 400. In a
     concurrent put, the upload counts only if the stored digest equals the id. A body shorter than Content-Length
     gets 400, and a longer one 413, both `{error: "body length does not match content-length"}`; a client that
     disconnects mid-upload gets 400 `{error: "request body was not received"}`. Nothing is registered in these cases.
  2. `BlobReg.register(id, size)`.
  3. Respond `201 {"id", "size", "t"}`, where `t` is `t_reg` in seconds since T0.

**`GET /api/v2/blob/{id}`** returns the raw bytes (served from `caches.default` when present, §9.7):

- headers: `cache-control: public, max-age=31536000, immutable`, `etag`, `content-disposition: attachment`,
  `content-security-policy: default-src 'none'; sandbox`, `cross-origin-resource-policy: same-origin`;
- `If-None-Match` is honoured with 304 when it is valid RFC 9110 syntax (`*` or a list of entity-tags). A malformed
  value is ignored, and the GET is answered as unconditional (200). A response from `caches.default` MAY answer 200
  where a 304 would be allowed. Other conditional headers are ignored;
- 404 if the blob is absent.

Range requests are not supported in stage 1.

**`GET /api/v2/blob/{id}/meta`** returns `200 {"t", "size"}`, or `404 {"error": "unregistered", "now": <sec>}`. This
is the MISS of §6.4(g). It is `no-store`.

### 10.8 Realtime: `GET /api/v2/rt` (WebSocket; `RL_READ`)

The upgrade is refused:

- with 426 when there is no upgrade header;
- with 403 when an `Origin` header is present and its host differs from the request host.

The Worker forwards only `{upgrade, x-segv-client: hex(HMAC(wsTagKey, "ws|" + clientKey))[0..32]}` to the RealtimeDO.

**Client → server.** Each binary frame is ≤ 8 KiB.

```
"ping" (text)                                                     → "pong"
SUB     = 0x01 | u16 n (1..256) | topic[16] × n                   add topics (the socket's total must stay ≤ 256)
UNSUB   = 0x02 | u16 n (1..256) | topic[16] × n                   remove topics
RESUME  = 0x03 | boot[8] | u64 since_seq | u16 n (0..256) | topic[16] × n
```

RESUME is allowed only as the first binary frame. It replaces the topic set.

**Server → client** (binary):

```
HELLO   = 0x80 | boot[8] | u64 now_ms | u64 seq                   sent right after accept (now_ms = Unix ms; seq = last assigned)
ROWS    = 0x81 | u16 n (1..65535) | (u64 seq | topic[16] | u16 E | label[16] | u32 t | u8 cls | body[CLASSES[cls]+40]) × n
GAP     = 0x82 | u64 since_seq                                    rows published after since_seq may have been missed
RESUMED = 0x83                                                    the replay for RESUME is complete
```

The server MUST NOT send a ROWS frame with `n = 0`; a client treats one as unparseable (close and reconnect, as for
any frame it cannot parse). A ROWS frame holds rows in ascending `seq`. The server starts a new frame before a row
that would push the frame's rows above 512 KiB, counting each row as `47 + len(body)` bytes (its encoding); one row
(at most 16 471 B) always fits. A publish is one put of at most 16 rows, so it always fits one frame.

**RESUME.** The server replays only if all of these hold:

- `boot` equals the server's boot;
- `since_seq ≤` the last assigned `seq`;
- the ring still holds every row with `seq > since_seq`;
- the rows to replay (those with `seq > since_seq` whose topic is in the RESUME's set) take at most 2 MiB
  (2 097 152 B), counting `47 + len(body)` per row.

It then sends them in ascending `seq` as ROWS frames (none when `since_seq` equals the last assigned `seq`), then
RESUMED. Otherwise it sends `GAP(since_seq)` and no row. In both cases the RESUME's topic set is installed. Sequence
numbers are per boot and strictly increasing, so rows published in the same millisecond are never skipped. A GAP only
costs a catch-up (§11.6), never a lost row.

**Client behaviour.**

- Keep the highest `seq` received, or HELLO's `seq`.
- Subscribe to at most 256 topics per socket and use at most 2 sockets per tab, in priority order: `Tself`, the
  current epochs of accepted copies by recent activity, followed old epochs (§11.2), then links. Request copies are
  never subscribed (§11.5). Copies beyond the budget are covered by catch-up (§11.6).
- On reconnect, send RESUME, and SUB any further topics.
- After GAP, run catch-up (§11.6). After a SUB of a topic that was not subscribed before, run a one-shot probe of that
  topic's expected slots, since rows published before the SUB are not replayed.
- Reconnect with backoff of 1 s, doubling to 30 s, with jitter; ping every 30 s. After a close with 1008 or 1013, wait
  at least 60 s and do not resend the same frame or topic set; never send a frame or topic set above the limits.
- On any frame the client cannot parse, close and reconnect.

### 10.9 Params, eras, checkpoints, feed

**`GET /api/v2/params`** (JSON, `no-store`):

```json
{"v":2, "now":<ms>, "T0":1767639600000, "eraMs":604800000, "era":<E_now>, "delta":Δ, "skew":SKEW,
 "inboxSlot":Δin, "inboxRetention":4, "inboxDayCap":2000, "inboxBatch":32, "shards":1, "p":P, "efirst":E_FIRST,
 "kcommit":"<b64u kcommit_E_now>", "srvKey":"<b64u Ed25519 pk>",
 "pow":{"register":20,"wrap":18,"put":16,"inbox":18,"blob":18},
 "limits":{"putRows":16,"putBytes":263345,"getKeys":256,"topics":256,"blobMax":12582912,"textMax":12000}}
```

`p` is `P` as §9.6 says; during a D1 outage it may be a stale value or 0, and params never fails because of D1.
Clients bound it from below by the dirlog size (`P*`, §10.6).

**`GET /api/v2/era/{E}`** (JSON; `RL_READ`) returns `{"era": E, "start": start(E), "end": end(E), "delta": Δ,
"shards": 1, "kcommit": b64u(kcommit_E), "sealed": bool}`. `start` and `end` (§3.1) are Unix milliseconds, the unit of
params `T0` and `now`; `delta` is in seconds. The Worker answers it alone and MUST NOT address any Durable Object for
it. `E > era(now + SKEW·1000)` or `E < E_FIRST` → 404 (§9.7); a malformed E → 400. `sealed = (now ≥ end(E) +
SKEW·1000)` by the Worker's clock: by the SKEW bound no component of era E accepts a write from then on, so every field
is final, and a response with `sealed = true` is `public, max-age=31536000, immutable`; any other is `no-store`.
`sealed` is informational: it does not mean that the ShardDO has persisted `state = sealed`, and clients MUST NOT use
it as the finality of a key (only `MISS(sealed = 1)`, §10.4, is). Publishing `kroute_E` for sealed eras belongs to
stage 2 (paging, §14) and is not part of stage 1.

**`GET /api/v2/ckpt/latest`** returns `{"q", "sec", "hd", "C", "sig", "heads": [{"cid", "head"}]}` (binary fields in
b64u). 404 when there is none yet.

**`GET /api/v2/ckpt/{q}`** has the same shape. It is immutable (`public, max-age=31536000, immutable`).

**`GET /api/v2/ckpt/range?after=<q>&limit=<1..1440>`** returns
`{"from": {"q": after, "C": b64u(C_after)}, "entries": [{"q", "sec", "hd"}], "latest": {"q", "C", "sig"}}`.

- Entries have `q > after`, in ascending order.
- The client recomputes `C` forward from `from.C`.
- When the last entry is `latest`, the result MUST equal `latest.C`. Otherwise the client pages on.
- `after` defaults to 0 (`from.C` = C_0 = ZERO32) and `limit` to 1440; a value that is not decimal or is out of range
  → 400.
- While no checkpoint exists, or when `after > latest.q` → 404 `{error}`. `after = latest.q` → 200 with
  `entries: []`; the client then requires `from.C = latest.C`.
- `latest` is the latest checkpoint at the time the range is served (it may be newer than an earlier `/ckpt/latest`);
  the client verifies its `sig` before using it.

**`GET /api/v2/feed/{E}/{i}?after=<t>`** (binary; `RL_READ`) is the public enumeration of a shard's closed batches:

```
response = u8 more | u32 nb | batch × nb
batch    = u32 t | u32 n | root[32] | head[32] | (label[16] | u8 cls | body[CLASSES[cls]+40]) × n     rows ordered by label
```

A page holds the closed batches with `t > after`, ascending: whole batches while the sum of their encodings stays
≤ 4 MiB (4 194 304 B), and always at least one when one exists. An empty page is `more = 0, nb = 0`. `more = 1` iff
another closed batch follows the page. Batches are never split, so a page whose first batch alone exceeds 4 MiB holds
only that batch and is as large as it; the Worker streams such a page, pulling the batch's rows from the DO in
label-ordered chunks of at most 4 MiB (§9.1), and does not store it in `caches.default` (§9.7). A feed request that
is not answered from `caches.default` MUST take `min(⌈bytes / 4 194 304⌉, 64)` `RL_READ` tokens (at least 1), where
`bytes` is the sum of the encodings of the page's batches, without the 5-byte page header (round 8). So every page that
is not streamed (its batches fit the 4 MiB budget; the empty page included) takes one token, and a streamed page of
one batch of b bytes takes `min(⌈b / 4 194 304⌉, 64)` (round 10). The Worker takes the first token in step 5 of §10.1
and the others after `feedBatches` returned the batch sizes, before it sends the first byte, and answers 429 with
`retry-after` if one is refused. So up to 256 MiB of batches no request makes the shard read more than 4 MiB of rows
per token, the rate of an uncached tail page. The cap keeps every page readable by one address within one `RL_READ`
window, with room to spare for an address that other readers share and for a limiter that counts approximately; a
deployment MUST keep its `RL_READ` limit per window (600, §10.2) above 64 (rounds 8 and 10). Above 256 MiB a token
buys `bytes / 64` of shard reads. Such a batch needs about 1 021 maximal puts (263 056 B of feed encoding each) within
one Δ, and every further 4 MiB per token about 1 021 more; at the production Δ = 10 the shard's ~1 000 requests/s
(§9.1) bound a batch near 2.5 GB, so a token buys at most about 10 times the tail-page rate, and only after a flood
that took the shard's whole write capacity for a Δ (round 10). Page composition is
deterministic for a given `after`. A page whose `more = 1`, or any page of a sealed era, is immutable; the tail page is
`no-store`. If a streamed page fails part-way, the response ends abnormally: it is truncated, never altered. Feed
readers MUST reject a page whose bytes end before its `nb` batches and their `n` rows are complete, and fetch it again.

Rows of a batch are strictly ascending by label (bytewise). A feed consumer recomputes each batch's `root` over the rows
in the order received, and `head` from the previous batch, so misordered rows fail that check and decoders need not
check the order. Every head in a checkpoint was obtained through `head()`, which closes a due batch first, so its batch
is already in the feed; the feed may hold later batches. Auditors check that each checkpointed `shard/{E}/{i}` head
occurs in the feed's head chain (not that it is the last head). Clients never use the feed. It exists so that the
database stays public and mirrors and auditors can verify batch roots and the head chain against checkpoints.

## 11. Client algorithms

Constants: `W = 8` (lane lookahead and gallop chunk), `P0 = 2` (probe depth of an idle lane), `SEND_ATTEMPTS = 8`,
`HISTORY_INITIAL = 30` rows per lane, `HISTORY_COPIES = 20`, `VIEW_MESSAGES = 500`, `MAX_TEXT_BYTES = 12000`,
`MAX_REQUESTS = 64`, `RESUME_AFTER = 10 min`.

Every protocol delay (the rotation rank delay, `RESUME_AFTER`, the HEADS delay, the poll and catch-up intervals, the
processing wait of §11.3) is a named engine option, so tests can shorten it. Waits on server
time (§6.3 step 5) use the injectable clock.

### 11.1 Unlock

1. Unlock AK (§2.4).
2. `GET /api/v2/dir/uid/{uid}`:
   - If the account is absent, the session is **fatal**: "your account was not found in the directory of this
     server".
   - If the bundle does not verify, or its `sig` or `kem` differs from the derived keys, the session is **fatal**:
     "the public keys registered for your account do not match your passkey's keys".
   - Otherwise take `handle` and `regEra` from the response.
3. Load and verify checkpoints (§12.3).
4. Restore (§11.4), open the realtime socket, and start the inbox poll.

After `register`, the client writes its first self row: a HEADS record (`c = 0`) whose cursor is the current inbox
slot, so its first restore does not scan the inbox from the start of the era.

### 11.2 Per-copy state

| item | contents |
| ---- | -------- |
| identity | `(conv, root)`, `rootBy`, `confirmed`, `request` |
| epochs `e → {EK, keys, D, H(D), bundleId, E_start, …}` | For each lane ℓ: the dense-prefix position, the processed position, the last valid row (for `prev`/`prevh`), and the rows seen. For the control lane: the position `(E_c, cnt_c)`, the evaluated rows and their e-validity (valid, not valid, undecided), the winning claim with its finality and processing state, and the sealed eras observed. Also the set of members who left in e, each with its kept source (§6.9): the stored time of the LEAVE row it comes from and, when e is that row's epoch, the row's position (NONE for a leave carried into e), kept in LEFT records (§7.3; rounds 8–10). |
| current epoch | `removed`, `left` (the copy's leave is current; a skip re-add clears it, §6.9), `frozen` (with its cause, for the warning text: own entry not opened, or `D'` invalid; §6.6 steps 4 and 6) |
| followed lanes | the lane of epoch c−1 of each member silent in c (below) |
| messages | message list, `unread`, `lastTs` |

**Unknown members.** A member of a D whose uid has no directory bundle, whose bundle fails `checkUserKeys`, or whose
bundle (or MEMBER record) disagrees with D is an **unknown member**: the bundle's `sigPk` differs from the `sigPk` in
D, or the hash `H(enc("segv.sh/v2/kh", kemPk))` of its `kemPk` (the MEMBER record's `kh`) differs from the `kh` in D.
It is shown with the handle `?` + the first 8 b64u characters of its uid. Its rows verify under the key in D like any
member's (§5.1), so they are shown, under that name. Being unknown affects only the display: its key entries are
sealed to the `kemPk` the bundles carry (§5.4), never to a directory key. A key that differs from the directory's
raises the critical warning "the public keys of @x changed" (either the descriptor's author or the directory lied, and
the handle is not shown for a slot whose keys do not belong to it). A disagreeing bundle is pinned in a MEMBER record
like any other (§7.3), so later restores compare D with that record and make no lookup; only a missing bundle is
looked up again on the next restore, and a lookup that fails transiently never makes a member unknown (§10.6).
Members of a request copy other than `D.by` are shown the same way until the copy is opened or accepted (§11.5).

**Followed lanes.** In the copy's current epoch c, if the copy holds epoch c−1, the client also follows, for each
member s of both `D_c` and `D_{c−1}` other than self of whom no valid row in c has been seen, s's lane of epoch c−1.
A copy that does not hold c−1 (its root epoch is c, or it reached c by a skip, §6.7 step 5) follows no lane. That lane
leaves when a valid row of s in c is seen, or when the copy switches past c (the lanes of c then become the
candidates). There is at most one followed lane per member, always in c−1. A restore takes the followed lanes of its
HEADS epoch from the HEADS entry (§11.4).

**Why one epoch back is enough.** An honest member sends a put into epoch e only within `(Δ + SKEW)/2` seconds after
the answer to a probe of e's control lane (§11.3 steps 1 and 6) that found no pending claim there and no winner other
than one that froze e (§11.3 step 2), and every member of e reaches the same verdict on the winner (§6.5, §6.6). So
its row lands in e after the others switched to e+1 only if the claim is stored between that probe and the row, and
the others still follow its lane of e until it posts in e+1. They sweep and drop that lane only after a second claim
is final, and an honest second committer registers its bundle only after the first claim is final and then waits at
least Δ + SKEW (§6.3), so the second claim is stored at least Δ + SKEW after the probe was answered. The row is
therefore seen whenever its put is answered less than Δ + SKEW after the probe was sent; a later answer makes the row
late, and its sender checks it again (§11.3 step 8).

**Sweeping.** Before any lane of an older epoch leaves the expected-label map (when the copy switches epochs, or a
followed lane is dropped), the client processes it from its processed position to its dense-prefix head, probed at
that moment, after the winner that ended the epoch is final. So a WELCOME or LEAVE posted in an older epoch before it
leaves the map is never skipped. Two gaps remain, and scrollback finds their rows (§11.10, §13.2 item 15): a row that
a member writes into an older epoch after it already wrote in a newer one, which only two of its own devices racing a
claim can do; and an honest row raced by a malicious member who registers the next bundle in advance and commits two
claims back to back.

The client also keeps:

- the **expected-label map**, `label → (copy, e, kind, ℓ|ctl, E, n)`, covering:
  - for each lane of the current epoch and each followed lane: the next `W` slots in the head's era, and slot 0 of
    `E_now` if that is later. An era between them is probed only at slot 0, and never again once that slot is
    `MISS(sealed = 1)`. When the head moved into a later era while the lane's dense prefix in the previous era with
    rows has not yet been observed sealed, the slot after that prefix also stays in the map until it returns
    `MISS(sealed = 1)` (or a HIT, which extends the prefix): a sibling device may still write there for up to SKEW
    (§7.2). The same applies to the self lane;
  - the next 2 control slots of every epoch whose winner is not yet final and processed;
- the self-lane and inbox cursors, and the processed positions of every lane.

### 11.3 Send (TEXT / IMAGE / LEAVE / WELCOME)

Sends are serialized per conversation. The UI echo appears at once, with status `sending` (none for LEAVE and
WELCOME).

1. Re-check the session. Probe the control lane of the current epoch e as §6.5 says (its next 2 slots, and slot 0 of
   every later era up to `E_now`), in one `get`, whatever the realtime state, and process what it finds (§6.4–§6.6);
   if that switches the copy to a later epoch, repeat this step for it. This costs one `get` per send, as v1's sync
   before every send did, and keeps a send from landing in e after a claim whose realtime frame was lost (§11.2). If
   the `get` fails (a network error, a timeout, a 429 or a 5xx), nothing is put: the echo becomes `failed` with the
   error "message was not delivered (membership changed or the request failed); try again", and its retry is a new
   send (a LEAVE fails with the same error; a WELCOME's uid stays pending, §6.12 step 4).
2. If the control lane of the current epoch has an undecided slot before any winner, or a winner that is not yet final
   or processed, wait for it, at most 30 s. (Slots after a processed final winner, as in a frozen epoch, never block.)
   Then:
   - if the user was removed: fail with "you are no longer a member of this conversation" (not for a WELCOME, last
     bullet);
   - if the user has left: fail with "you left this conversation" (except a LEAVE repeated by §6.9, and not for a
     WELCOME, last bullet);
   - if the wait timed out: fail with "the conversation is changing membership; try again in a moment" (the v1 text).
     Writing into e now could reach a member that the pending claim removes;
   - if self is frozen in e, the winning claim of e has an `rm` bit for a member who had not left (by the leave state
     when this check runs, §6.6 step 5; round 11), and the type is TEXT or IMAGE: fail with "a removed member could
     still read this conversation; start a new conversation" (§6.6 step 6);
   - if the type is WELCOME and the current epoch (the one the row would be built in) does not meet every condition of
     §6.12 step 1 (a copy that self left or was removed from never does): put nothing; the recipient gets an inbox
     invite instead (§6.12 steps 1–2). A WELCOME is thus never written in an epoch that lists anyone but self and its
     recipient.

   Otherwise a frozen member sends normally in e. The view's `canSend` is false whenever this step would fail for a
   TEXT, and follows the leave state as it changes (round 11). For an undecided slot, or a winner not yet final or
   processed, the view cannot know whether a wait would time out, so `canSend` turns false only once the slot or
   winner has stayed so for 30 s, until it is settled; a send made before then waits here (round 9).

   **The send's epoch.** The epoch this step last checked is the send's epoch e. Steps 4–8 build, put and judge the row
   in e, also when the copy has meanwhile switched to a later epoch through §11.6 or a catch-up; only a re-run of steps
   1–3 (step 6) sets a new e.
3. If the epoch lists a member who has left (other than self) and the type is TEXT or IMAGE, commit a rotation (§6.3),
   unless self is frozen in e or `e = 2^32 − 2`. On a conflict, follow the winner. Then restart at step 1. If the
   commit fails with "can no longer change" (self is now frozen), restart at step 1 too: step 2 decides whether e
   still takes the send.
4. Pick the slot:
   - `(E, n)`: let `E* = max(E_now, the era of the lane head)`, so a slot is never picked below the head's era (a clock
     estimate that steps back across an era boundary); if the lane head is in `E*`, then `n = head.n + 1`, otherwise
     `(E*, 0)`;
   - `prev` = the sender's last valid row on its lane in epoch e.
5. Build M, sign it, pad it (a text over 12000 bytes fails with "message is too long"), and encrypt it.
6. Put with topic `T_e` and handle the result. Every attempt, WRONG_ERA included, counts against `SEND_ATTEMPTS`, except
   the junk skipping below.
   - **Fresh probe.** Immediately before each put attempt is sent (the first one, every one after a return to step 4,
     and the re-put of a failed echo), after its proof of work: if more than `(Δ + SKEW)/2` seconds have passed, by the
     monotonic clock, by the wall clock (`Date.now()`) or by the estimated server time (§3.1, §10.1), since the answer
     to the latest step-1 probe arrived (a browser's monotonic clock may stop while the system sleeps; the wall clock
     does not, and a wall clock that steps back counts as no time passed), or
     if the copy is no longer in the send's epoch e, run steps 1–3 again first (so the refusals of step 2, including
     the WELCOME check, and a rotation that §6.9 now requires apply to the epoch the row will go to); if that re-run
     leaves the copy in a later epoch, go back to step 4 and build the row for that epoch (a new signature and proof
     of work). A slow proof of work, a frozen tab or a WRONG_ERA wait thus costs one more `get`, never a row in an
     epoch the others have left (§11.2).
   - **OK**: verify the receipt, apply the row locally (the echo becomes `sent`, unless the row is late, step 8), and
     update the lane head.
   - **CONFLICT(o)**:
     - if `o.body` is exactly what was sent: success (a lost response was retried);
     - else if `o` opens under `mk_e` and is a valid row of this lane signed by self (a sibling device): apply it as a
       row, advance, and go to step 4;
     - else (junk): the slot is occupied. Probe with exists `(E, n+1..n+64)`, jump to the first MISS, and go to
       step 4. Junk skipping does not count against `SEND_ATTEMPTS`.
   - **WRONG_ERA(E')**: go to step 4 with `E_now = E'`. If `E'` was already tried for this message, first wait until
     the estimated server time is past `end(min(E, E')) + SKEW`.
   - **FULL, a network error or a 5xx**: probe the slot with `get` (body), up to 3 times with backoff.
     - If the stored body is ours: success.
     - If there is another body: treat it as CONFLICT.
     - If it is a MISS: the echo becomes `failed`, with the error "message was not delivered (membership changed or
       the request failed); try again". The client keeps the sealed body and its slot.
     - If every probe fails: the echo becomes `failed` with the same error, and the client keeps the body.
   - Any other 4xx: the echo becomes `failed`, with the server's error.
7. After success, if the cut rule (§6.8) later drops this row because a final winning claim removed the sender, mark the
   echo `failed`, with the same "not delivered" error.
8. **Late rows.** A row is *late* when the answer to its put (or to the probe that found its body) arrived `Δ + SKEW`
   seconds or more after its latest step-1 probe was sent, by the monotonic clock, the wall clock or the estimated
   server time (as in step 6), or
   when the retry of a failed echo finds it after the copy left its epoch. The others may have swept its lane before
   it landed (§11.2). After a late row in epoch e, its echo stays `sending`, and step 1 runs again and waits as step 2
   does. The row counts as delivered only if the copy is then still in e, or in e+1 with no valid row of self in e+1
   (so the others still follow self's lane of e). Otherwise, or if the probe fails or the wait times out: a TEXT or
   IMAGE echo becomes `failed` with the same "not delivered" error, and its retry builds the message again in the
   current epoch; a LEAVE is put again in the current epoch by the rule of §6.9 (its record for the late row stays,
   since that row exists); a WELCOME's uid stays pending (§6.12 step 4). A member that did see the late row then sees
   the message twice.

**Retry of a failed echo.** "Try again" first runs steps 1–3. While the copy is still in the body's epoch, it re-puts
the kept sealed body at its original slot (after the fresh-probe check of step 6): OK, or a CONFLICT with an identical
body, is success. If the copy has moved to a later epoch, it only probes the kept slot, and a HIT with our body is a
late row (step 8). Another occupant, a MISS after an epoch change, a WRONG_ERA, or a late row that step 8 does not
count as delivered makes the client build the message again at a new slot. A message is therefore delivered twice
only when a late row that some member saw is built again (step 8).

### 11.4 New device / reload (restore)

Every unlock restores. There is no persisted local cache in stage 1.

1. Directory and checkpoints: §11.1.
2. **Snapshot pointer.** Probe `Lsnap(E_now, 0..15)` and `Lsnap(E_now−1, 0..15)` (body mode).
   - Take the highest `(E, j)` inside a dense prefix. If all 16 slots of an era hit, gallop.
   - If neither era has one, probe `Lsnap(E, 0)` for `E = E_now−2` down to `regEra`, and stop at the first hit.
3. If there is a snapshot: fetch the blob, check its hash, decrypt, parse `S2`, and apply its records. The self
   position is `(Eh, nh)`. The client tries the pointers it found from the highest `(E, j)` down, continuing the
   step-2 search into earlier eras, and uses the first pointer that opens and parses as a pointer row (§7.1) and whose
   blob is a HIT, hashes to `blobId`, decrypts with `skey` and parses as S2. A transient error (network error,
   timeout, 429, 5xx) is retried with backoff, never skipped. When no pointer qualifies, restore runs without a
   snapshot, from `(regEra, 0)`; old era DOs stay readable in stage 1 (§9.1), so the result is the same.
4. **Self delta.** Probe `Lself` densely from the position after `(Eh, nh)` (or from `(regEra, 0)` without a
   snapshot):
   - `W` slots of the current era, and `(E', 0..W−1)` for each later era up to `E_now`;
   - gallop when all hit;
   - apply the records in order.

   An idle era costs one probe key.
5. **Per accepted copy.**
   - Epoch keys come from the records (CONV_JOIN, EPOCH, EPOCH_PENDING). `D` of an epoch comes from a DESC record, or,
     only when there is none, from its bundle. Signatures need no directory (§5.1). Members' handles come from MEMBER
     records (§7.2); only members of a held D that have none are looked up by prefix, batched per prefix and cached
     for the session, and the result is written as a MEMBER record. Restore never fetches `kemPk`.
   - **Control lane.** The restore holds every held epoch of the copy (round 12). It starts at the copy's highest epoch
     whose key a snapshot record gives (its root epoch when there is none), or at the HEADS epoch when that is lower
     (the root epoch for a copy without a HEADS entry, as for its lanes below), and probes and processes the claims of
     each epoch it reaches as in §6.4–§6.6: the HEADS epoch from its HEADS position (trusted, §7.2), every other from
     `(E_start, 0)`. So it re-derives every held epoch that no record gives (one reached through the account's own
     entry after the snapshot, or any without a snapshot, §7.3), those below a skip re-add included, and holds the
     claim that ended each held epoch below the current one (processed, or named by an EPOCH record, §6.8). Each new
     epoch costs one bundle fetch, the rule-(g) `blob/meta` request and at most 32 entry recomputations (§6.6 step 4). `E_start` of an epoch (§4.2) comes from the `meta` answer that
     accepted it, from an EPOCH_PENDING or REQUEST record, or else from one `GET /api/v2/blob/{id}/meta`, made only when
     a claim of that epoch must be evaluated (§6.4(f)) or its lanes probed from the start.
   - **Skip re-adds.** When the control lane of epoch k shows self removed (`rm` bit 1) and the self lane holds an
     EPOCH record with flag bit1 for a later epoch of this copy, the copy continues at the earliest such epoch, exactly
     as the live skip join did (§6.7 step 5), without a new system line or warning. A skip above the latest LEAVE
     record's epoch ends the copy's leave and clears `left` (§6.9).
   - **Lanes.** For **every epoch** of the copy from the epoch of its HEADS entry (or from the copy's root epoch when it
     has no HEADS entry) up to the current epoch, and for each lane of that epoch, from its processed position in HEADS
     (or from the epoch's start): probe `P0` slots, gallop with `W` on hits to find the head, then fetch the bodies of
     every slot from the processed position to the head and process them (§6.8): WELCOMEs and LEAVEs take effect. The
     lanes of an epoch are processed before the switch past it, exactly as the sweep of a live client (§11.2), so the
     followed lanes (epoch c−1 of each member silent in c) come out the same. For the HEADS epoch itself, the followed
     lanes are exactly those its HEADS entry lists, processed from their recorded positions; every other member of
     both `D_c` and `D_{c−1}` counts as having a valid row in that epoch, as it had for the device that wrote the entry
     (rows before the recorded positions are not fetched again, so this restore cannot see them itself). The senders of
     the followed lanes' rows are listed in `D_c`, so §6.8 decides those rows with s's bit in `C_{c−1}` read from
     `D_c` (0), continuing at c, without `C_{c−1}`; a row stored after a claim of c (or later) that removed its sender
     is dropped as it is live (round 10). A restore that took `EK_c` from a snapshot's EPOCH record never processes
     `C_{c−1}`; one that re-derived c (without a snapshot, or for an epoch reached after it) processed it on its way to
     c (Control lane, above), and decides those rows the same way (rounds 11–12). A HEADS entry that §7.2 says to
     ignore counts as absent. The members recorded as left in the HEADS epoch are those its LEFT records name (§7.3:
     per member the record with the least key), each decided by §6.8 with the record's time and position, as its
     LEAVE row would be, when a claim of that epoch or a later one is processed (round 9); a LEAVE found here is
     applied as a live one is (§6.9: it replaces the kept source only when its key is smaller; round 10), and the
     switch to a later epoch carries the leaves over (§6.6 step 4). Rows applied during restore never count as unread.
   - **Frozen copies** re-derive their freeze from the control lane and the bundle (§6.6). The freeze itself posts
     nothing (LEAVEs that §6.9 repeats are still put).
   - **Unfinished deliveries** (§6.11), and LEAVEs that §6.9 repeats.
6. **Initial history.** For the `HISTORY_COPIES` copies with the newest `lastTs` (from HEADS), also fetch the last
   `HISTORY_INITIAL` slots of each lane of the current epoch (body mode), and, if the epoch has fewer than 30 rows,
   rows of the copy's previous held epoch (the highest held epoch below it, step 5 and §11.10: e−1, or the epoch self
   was removed from before a skip re-add; none below the root epoch; rounds 11–12) up to the time of the claim that
   ended it (its lane heads found as §11.10 says for an epoch this session never swept, never from the claim's cuts;
   that claim read at the position the current epoch's EPOCH record names when the restore did not process it, §6.8;
   rounds 10–11). These rows are processed as §11.10 says for rows found by scrollback (round 12). Other copies load
   their history when they are opened (§11.10).
   Build the views, ordered by §11.8.
7. **Inbox.** Read from the HEADS cursor (§11.5).
8. **Requests** (§11.5): probe each live REQUEST copy once.
9. **Subscribe** (§10.8): `Tself`, `T_e` of each accepted copy's current epoch, the topics of followed lanes, and
   `Tlink` of each live link.
10. If more than 200 self records were applied since the snapshot, or there is no snapshot in `E_now`, write a
    snapshot (§7.4). Write HEADS when positions advanced (§7.3).

Requests are paced to `RL_READ`: on 429 the client waits for `retry-after` and continues where it stopped.

**Cost.** In keys, rows and bytes, a restore costs:

- `copies × (members × P0 + 2)` probe keys, plus `members × P0` keys per epoch changed since HEADS, plus up to one
  followed lane per member, plus a gallop per lane that moved;
- one bundle (23–81 KB) per epoch that the restore re-derives (step 5) or whose D it needs and has no DESC record for,
  which in practice means the epochs since the snapshot (every held epoch without one; a snapshot's DESC records cover
  its current and previous held epochs, §7.4; round 12);
- one claim row (in a batched `get`) per older epoch whose ending claim the initial history or a removed sender's row
  needs and the restore did not process (§6.8; round 10);
- per epoch re-derived (changed since HEADS, or since the snapshot, step 5; round 12), up to two `blob/meta` requests
  (rule (g), and `E_start` when no record holds it) and at most 32 X-Wing encapsulations (the entry recomputations
  and the key checks of added members, §6.6 step 4, a few ms each);
- the rows written since the account's last HEADS, in bodies, in every epoch since HEADS;
- `HISTORY_COPIES × lanes × HISTORY_INITIAL` rows of initial history;
- `MAX_REQUESTS × (2 · members + 3)` keys for requests (§11.5);
- the inbox rows since the cursor (at most about 30 minutes of inbox when HEADS is current);
- **directory:** the exact own-uid lookup, plus one prefix response (about 64–128 bundles, 120–240 KB) per distinct
  co-member that has no MEMBER record. With a current snapshot or HEADS that is none, except for listed uids that are
  not registered (§7.3; a member whose keys disagree with D has a MEMBER record and costs nothing), so the directory
  bytes of a restore do not grow with the directory or with the number of co-members.

It does not depend on the number of messages ever sent. As an example, 100 copies of 8 members are about 1 800 probe
keys (8 `get` requests) plus at most 4 800 history rows (about 1.4 MB at class 0), plus about 3 KB for the own bundle.

### 11.5 Inbox poll and requests

The client polls every `max(inboxSlot, 2)` seconds while the page is visible, on reconnect, and after unlock.

1. Let `(Ec, rc)` be the cursor. For each era E from `max(Ec, E_now − 3)` to `era(server now)` (from params or
   `x-segv-now`): `GET …/inbox/{E}/0?after=a` until `more = 0`, with `a = rc` for `E = Ec` and `a = 0` for every later
   era. A 410 moves the cursor to `(E_now − 3, 0)`. Without a cursor, start at `(max(regEra, E_now − 3), 0)`.
2. Trial-decrypt each row (§5.3), in chunks in a Web Worker, so the page stays responsive. A decapsulation that throws
   means "not for me". Process each J (§6.7). Joins found in one poll are processed one after the other, with the
   held copy caught up between them.
3. The cursor becomes `(E, closed)` of the last era read, but never passes a parked join (§6.7 step 4), and never
   leaves an era E before E is **complete**: a read of E returned `more = 0` and was issued at an estimated server time
   of at least `end(E) + (2·SKEW + 2·Δin)·1000`. Until then InboxDO E may still hold rows with `rel` above the `closed`
   it reported (posts are accepted until `end(E)` by its own clock, with up to Δin of jitter, and the tail may come
   from a cache up to Δin old, §10.5), so the cursor stays at `(E, closed of E)` and each poll reads E from there and
   every later era from `after = 0`. Joins found again in a later era are duplicates (§6.7 step 3). Joins and the new
   cursor are written as §7.3 says.

**Requests.** A copy created by a first-contact join whose `D.by` is not a contact (§7.3) is a **request**:

- It is recorded as a REQUEST self record, which carries `D`, so a restore needs no bundle fetch for it. At most
  `MAX_REQUESTS` are live (§7.3).
- At acceptance only `D.by`'s bundle (its `sigPk` against D, §6.7) and `dsig` are verified, and a MEMBER for `D.by` is
  written with the REQUEST from that bundle (§7.3), so `D.by` is never looked up at restore. Other members' rows
  verify under the keys in D; their bundles are fetched (for handles) only when the copy is opened or accepted, and
  until then they are shown as `?…` (§11.2).
- It is not subscribed. On restore and at every catch-up it is probed with at most `2 · members + 3` keys: the next 2
  control slots, plus control `(E_now, 0)` if that era is later (§6.5); and per lane the slot after the lane's known
  head (from HEADS, which covers requests too), or `(E_start, 0)` when none is known, plus `(E_now, 0)` if that era is
  later. Hits are galloped, fetched and processed, so a member who has not posted yet still sees the others' rows
  after a restore, and corroboration does not depend on realtime.
- It becomes an accepted copy (a CONV_JOIN with `via = 5`, plus CONTACT for `D.by`) when the user opens it
  (`markRead`), when self posts in it, when `D.by` becomes a contact, or when a valid row from a member other than
  `rootBy` and self is seen (which also writes CONFIRMED). On that transition the client processes every lane from
  `E_start` in body mode, looks up the members that have no MEMBER record, then treats the copy like any other.

This bounds what an inbox spammer costs a victim: one `blob/meta` request and at most one bundle fetch of at most
81 248 bytes (§6.7 step 1), at most 32 key checks (§6.7 step 2) and at most one directory lookup per join (none when
`D.by` already has a MEMBER record), at most
`MAX_REQUESTS × (2 · members + 3)` keys per catch-up, no directory lookups at restore, and no topics.

### 11.6 Realtime receive and catch-up

**On a ROWS frame**, for each row, look up its topic:

- **`Tself`**: decrypt under `kS`, apply in self-lane order, and fill holes by probing.
- **`T_e`**:
  1. If the label is in the expected-label map, use that position.
  2. Otherwise decrypt with `mk_e`. Parse M and recompute the label from `(type, lane, E, n)`. If it does not match,
     drop the row: it is junk on a known topic.
  3. If a lane row's position is beyond the lane's dense prefix + 1, fetch the missing slots first (§12.2).
  4. Then process the row (§3.3, §6.8). A realtime `t` is used for display and ordering; e-validity uses the `t` of a
     `get` (§6.4(g)).
- **`Tlink`**: open the hello (§5.5).
- **An unknown topic**: ignore it.

Rows on a slot in the expected map that fail decryption occupy the slot: the client gives the noise warning "ignored
an undecryptable message" and advances.

**Catch-up** runs:

- after GAP;
- after a (re)connect without RESUMED;
- every 300 s while connected;
- every 10 s while disconnected;
- before the first send in a conversation after 30 s without realtime;
- once after each SUB of a new topic (for that topic's slots).

It is one batched `get` over the expected-label map: `P0` slots per lane in body mode, the control slots, requests'
keys, and `W` self-lane slots. The client gallops in exists mode on full hits, then fetches the bodies of every slot
from the processed position to the head. When a catch-up makes a copy switch epochs, the old epoch's lanes that do
not stay followed are swept to their heads first (§11.2). Then it polls the inbox, resumes unfinished deliveries
(§6.11) and repeats LEAVEs as §6.9 says. On 429 it backs off as `retry-after` says.

### 11.7 Multi-device

- Devices of one account share every counter through CAS. They do not coordinate in any other way:
  - a CONFLICT whose occupant is a valid row signed by self (lanes) or opens under `kS` (self lane) is applied and
    treated as the new head;
  - an identical body means our own lost write.
- Sibling devices subscribe to the same topics, so they see each other's sends in real time.
- A committer's other devices learn new epochs through their own bundle entries, and finish its deliveries (§6.11).
- Two devices may write `(E, n)` and `(E+1, 0)` of one lane (or of the self lane) around an era boundary, in either
  order. Readers find both: they keep the end of E's dense prefix in the expected-label map until it is observed
  sealed (§11.2), record no position in E+1 before that (§7.2), and scrollback probes each era's dense-prefix end
  (§11.10, §12.2). A single device never writes below its lane head's era (§7.3, §11.3 step 4).

### 11.8 Order, timestamps, unread

- **Timestamps.** Shown times are the sender's `ts`, clamped to `[T0 + t·1000 − 300 000, T0 + (t+Δ)·1000 + 300 000]`,
  where `t` is the row's stored time.
- **Order.** A conversation's messages are ordered by `(clamped ts, epoch, E, lane, n)`.
  - Local echoes come last until applied.
  - System lines take the clamped `ts` of the claim, join or LEAVE row that caused them.
  - There is no server total order, so concurrent messages from different senders may appear in different orders on
    different devices.
- **`lastTs`** is the maximum clamped `ts` of the copy's rows and system lines.
- **`unread`** counts TEXT and IMAGE rows not signed by self (and epochs committed by others) applied after restore
  finished, while `live`. It is not persisted. `markRead` resets it. A row applied during restore, a row from a sibling
  device, and a row later dropped by §6.8 never count.
- **`MessageView.seq`** is a local, increasing application counter used as a stable tie-breaker. It is not a server
  sequence.

### 11.9 System lines (exact text)

These strings are kept from v1. `who(u)` is "you" for self and `@handle` otherwise.

| event | system line |
| ----- | ----------- |
| join at e = 0 | "`who(by)` started the conversation" |
| join at e > 0, or a skip re-add | "`who(by)` added you" |
| accepted e+1, members added | "`who(by)` added `who(a)`, …" |
| a claim with `rm` bits for members who had not left (shown by every member of e, frozen ones included) | "`who(by)` removed `who(r)`, …" |
| a claim that drops only leavers | "keys rotated after `who(l)`, … left" |
| accepted e+1, no membership change | "`who(by)` rotated the conversation keys" |
| accepted e+1, renamed | "`who(by)` renamed the conversation to “name”" |
| accepted e+1, name removed | "`who(by)` removed the conversation name" |
| removed (`rm` bit set for self) | "`@by` removed you" (not shown for a self-leaver) |
| frozen | the critical warning of §6.6, no system line |
| leave | "you left the conversation" (own, once) or "`@x` left" |

The rename lines compare the names as displayed (§5.1): a name that fails the reader's `validName` counts as no name.

Lines that depend on others' leaves are derived from the leave state (§6.9), not latched when an event is processed
(round 11). A LEAVE row R of x in epoch k shows "`@x` left" while it is the kept source of x's leave in k, §6.8
accepts it, and x is not recorded as left in k−1 (a leave carried into k shows its line at its source in an earlier
epoch), so one leave shows one line. R loses its line when a source with a smaller key replaces it, when §6.8 drops it,
or when x becomes recorded as left in k−1 (round 12). A claim's "removed" and "keys rotated" lines are derived again
whenever the leave state of its epoch changes (§6.6 step 5). The same rows thus give the same lines, whatever the order
in which they arrived.

After a reload the device holds fewer rows (§6.6 step 5): a LEAVE row before the HEADS positions shows its line only
once the initial history or scrollback loads it (§11.4 step 6, §11.10), and the leave state of an epoch below the HEADS
epoch is rebuilt only from the rows they load. Until they load a leave's source, its "@x left" line is missing and a
claim below the HEADS epoch can show a removal where the live view showed "keys rotated". A claim that history reads
without processing it (§6.8) shows its lines as a processed claim would (round 12).

### 11.10 Scrollback

When a conversation is opened (`markRead`, which the UI calls every time it opens a conversation pane), the client
loads older rows until the view holds `VIEW_MESSAGES` messages or the history is exhausted. This runs once per copy
and session; later calls are no-ops.

- For each lane, probe `(E, n−32..n−1)`.
- At `n = 0`, move to the previous era that has rows: follow `prev` of the oldest loaded valid row, and also probe the
  dense-prefix end of each earlier era down to `prev`'s era, so rows that are not on the `prev` chain (a sibling's row
  written across an era boundary) are found too.
- Below the first row of an epoch, continue in the copy's previous held epoch, the highest held epoch below it, using
  its keys from the self lane or the restore (§11.4 step 5) and its DESC, or its bundle, for its D: e−1, or, below an
  epoch reached by a skip re-add, the epoch k that self was removed from; the history ends below the copy's root epoch
  (rounds 11–12). On entering a lane of an older epoch e, which the winning claim C ended, first find the lane's head (a session that did not process C reads it at the position that
  the EPOCH record of the next held epoch names: e+1, or the skip epoch for k; §6.8; rounds 10–11):
  - for an epoch this session swept, probe the `W` slots after the head the sweep recorded (galloping on hits), and
    slot 0 of every later era up to the era after C's era (at most `E_now`), galloping on hits;
  - for an epoch this session never swept (one before the HEADS epoch of the restore), probe slot 0 of every era from
    `E_start(e)` to the era after C's era (at most `E_now`), and gallop on hits to each era's dense-prefix end.

  The cuts in C are never a starting point: the committer chooses them, and §6.4(f) bounds only their era. So a row
  that landed after the sweep (§11.2) is found too, also when its writer started a new era for it (§11.3 step 4), and
  a malicious cut can neither hide a lane nor make the walk unbounded. An idle era costs one key, as for a live lane
  (§11.2). A row that its sender counts as delivered was put less than `Δ + SKEW` after a control probe that did not
  yet see C (§11.3 steps 6 and 8), so it lies no later than the era after C's. The backward walk above (probing
  `(E, n−32..n−1)` and the earlier eras) then starts from the heads found.

Rows found by scrollback are processed like any other (a WELCOME that lies before the processed position was already
processed and is not applied twice; a LEAVE is applied as §6.9 says: it records a leave the local state lacks, and
replaces the kept source only when its key is smaller; round 10). Older rows are never counted as unread.

### 11.11 Engine operations

| Engine call | protocol |
| ----------- | -------- |
| `register`, `login`, `loginWithRecovery`, `addPasskey`, `logout` | §2.5. `logout` bumps the generation, closes the socket and stops polls and background deliveries, clears the remembered session, revokes image URLs, and drops all state. Another device or the next session finishes pending deliveries (§6.11). |
| `createConversation(handles, name)` | §6.1, by handle. It resolves after step 5, with the new copy in `conversations`; steps 6–9 run in the background. |
| `sendText` / `sendImage` / `leave` | §11.3. An image is uploaded first (§8.1); the echo shows a local preview. |
| `addMembers` | Drop leavers (a separate commit first if a requested user is a listed leaver), then §6.3 with the added uids. Resolves after the switch and the first delivery attempt. |
| `removeMember` | §6.3 without that uid and without leavers. Removing self is refused ("use “leave” to leave a conversation"). |
| `markRead(convId)` | Resets `unread`, accepts a request copy, and starts scrollback once (§11.10). |
| `loadImage` | §8.1, cached by `id.k`. |

Links (§4.3, §5.5) are implemented in the engine as internal operations (`createLink`, `openLink`), together with the
LINK record, `Tlink` subscriptions and hello probing. They are not on the `Engine` interface in stage 1, because the
link-sharing UI is deferred (§14).

## 12. Integrity (replacing the v1 global hash chain)

### 12.1 Row immutability

A client remembers, for the session, `(H(body), t, cls)` of every row it has fetched, received or written.

If the server later returns a different body, `t` or class for the same `(E, label)`, through HIT (body or exists mode),
CONFLICT, ROWS or RESUME replay, the client raises the critical warning "the server changed a stored entry: history
was rewritten". Decisions that depend on `t` (e-validity, §6.4(g); old-epoch acceptance, §6.8) use the `t` of a `get`
HIT or a CONFLICT, so a realtime frame cannot change them on its own.

### 12.2 Lane omission (`prev` / `prevh`)

Honest writers never leave holes in their own lane, so a validly signed lane row is evidence about the rows before it.

- **Rows beyond a hole.** A lane row beyond the known dense prefix whose label recomputes and whose signature verifies
  under the lane owner's key is not ignored. The client walks its `prev` chain back to the known prefix, fetching each
  named slot:
  - a HIT whose `prevh` matches continues the walk;
  - **MISS(sealed = 1)**, or a MISS in an era whose shard answered for later slots: critical warning "the server is
    hiding messages from @x";
  - **a different body** (the `prevh` mismatch): critical warning "the server is showing different messages from @x
    to different members".

  The row and every row chained to it are then accepted (subject to §6.8). Empty slots that are not on the chain
  (junk-free holes) do not matter. Junk beyond a hole stays ignored.
- **Every row.** When a valid lane row names `prev = (Eprev, nprev)`, the client checks that it holds the row there and
  that `prevh` matches, whatever the position of that slot relative to the known prefix (fetching it if needed, with
  the outcomes above).

The warnings are deduplicated per sender.

### 12.3 Checkpoints (rewrite and rollback, persisted)

The client stores `localStorage["segv.ckpt"] = {"k": srvKey, "q": q, "C": b64u(C_q), "at": <client ms>}`, one per
browser, like v1. `at` is the client's clock when the entry was stored. On every catch-up:

1. Fetch `/ckpt/latest` and verify `sig` under the pinned key. On first use, pin params' `srvKey`. A different
   `srvKey` raises the critical warning "the server's signing key changed".
2. If `latest.q < stored q`: critical warning "the server's log is shorter than what this device verified before
   (#stored > #latest): it was rolled back". The stored value is kept, so later sessions warn again.
3. If `latest.q = stored q`: require `latest.C = stored C`. Otherwise raise the critical warning "the server's log
   differs from what this device verified before at checkpoint #q: history was rewritten", keep the stored value and
   never advance it again.
4. If `latest.q > stored q`:
   - A checkpoint is made at most once per 60 s (§9.5). If `latest.q − stored q > (now − at)/60 000 + 60`, raise the
     "history was rewritten" warning and do not advance.
   - Only if `now − at > 30 days` MAY the client skip the range and store `latest`. It loses rollback detection across
     that gap. `q` alone never justifies a skip, since the operator mints it.
   - Otherwise fetch `/ckpt/range?after=stored q` (paging), recompute the chain, and require `from.C = stored C` and
     that the chain ends at `latest.C`. On a mismatch, raise the "history was rewritten" warning; the stored value is
     kept and never advanced again. Otherwise store `latest` with `at = now`.
5. Keep a session map `q → C_q` of the verified entries of the last 2 hours.

`EngineState.head` is `{seq: latest verified q, h: b64u(C_q)}`.

### 12.4 Split view (`ck`)

Rows carry `ck16 = t16(C_ckq)`. Sixteen bytes make a fork with matching references cost the operator about 2^64 work
per checkpoint, where v1's comparison used the full 32-byte head; 8 bytes would allow a 2^32 birthday grind.

For a valid row with `ckq > 0`:

- If `ckq` is in the client's session map and `t16(C_ckq) ≠ ck16`: critical warning "split view: @x saw a different
  log than this device — the server may be lying to one of you". Deduplicated per sender.
- If `ckq > latest`: fetch the range first.
- If `ckq` is older than the map: skip the check. Rows loaded at restore or by scrollback that are more than 2 hours
  old are therefore never compared (§13.2 item 2).

### 12.5 Receipts

OK results carry `receipt = Sign(SRV_SK, enc("segv.sh/v2/receipt", u16 E, label, H(body), u32 t))`. A client MUST
verify it. An invalid receipt raises the critical warning "the server returned an invalid receipt".

Receipts let a writer prove to third parties that the operator accepted a row, at a given `t`, that it later omits.
Stage 1 defines no client UI for them.

### 12.6 Not detected in stage 1 (see §13.2)

The checkpoint chain commits to shard batch heads, inbox slots, blob registrations (hourly) and the directory log. But
clients verify **no inclusion proofs**, so:

- O can omit rows from some clients;
- O can answer `blob/meta` (rule (g)) or a directory lookup differently to different clients, without forking the
  checkpoint chain.

Only `prev` / `prevh` (within a lane), row immutability, receipts, CONTACT and MEMBER pins, descriptor keys and
fingerprints expose this. Mirrors and auditors that download the feed and the dirlog can check the commitments.

### 12.7 Fatal conditions

The engine enters phase `fatal` only for an account check failure (§11.1). Every integrity finding above is a sticky
critical warning, and messaging continues.

Noise warnings (anything an outsider or a member can trigger at will) are deduplicated as "text (×n)", and at most 5
are kept. Critical warnings are kept until sign-out.

## 13. Leakage

### 13.1 Leakage table (stage 1)

| linkage | P / P\* (public archive, public API) | O (operator, direct TLS) | M (member) |
| ------- | ------------------------------------ | ------------------------ | ---------- |
| message ↔ sender | None: no sender column, the signature is inside the AEAD, writes are anonymous. Only Δ-rounded `t` and the class. | The writer's IP for every put, which with an IP-to-account match (unlock, own-bundle lookup) gives the account. | Verifiable, not deniable. |
| message ↔ recipients | None for rows. Inbox invite: one of all users (β = 0), even against a quantum P. | Exactly, through the socket's topic set and the labels each client fetches. | The member list. |
| message ↔ message (same conversation) | No identifiers. Rows in the same Δ batch and rare classes are visible. With S = 1 and low traffic, timing correlation is strong. | Exactly: same topic, same IP. | Everything. |
| user ↔ conversation | None. The directory reveals that the account exists and when it registered (the client's `ts`, and the minute through the dirlog head in checkpoints). | The topic set and fetch pattern per socket / IP, linked to the uid at unlock. | Co-members of shared conversations. |
| user ↔ user | None. Global inbox counts per slot are public. | The whole social graph, including a p-bit prefix of every handle and co-member lookup (§13.2 item 10). | Co-members only. |
| activity of a user | Directory events (registration, wrap additions); the size of the global inbox; self rows (one after each own creation, commit, join or leave, and at most one HEADS row per 30 minutes while active), which P cannot tell from other rows except by timing. Per-user send volume is not visible. | Per-IP read and write volume and times; online time; topic sets. | Send times in shared conversations. |
| activity of a conversation | Not directly: rows have uniform labels. | Exact per-topic volume and times. | Everything. After removal: only that a claim happened, its `rm` bits and its cuts. |
| membership changes and creations | Both show the same row pattern: a class-1 self row, one class-1 row at least Δ+SKEW later (claim or decoy, which P cannot tell from a medium text), then J deliveries and one class-1 self row (DELIVERED, padded for any number of recipients, §6.12); at most hourly, that some blob was registered. Members who receive J by inbox add that many inbox rows within seconds, while a removal or rotation adds none, so P can tell "someone was invited by inbox" from "nobody was" (§13.2 item 12). Not the member count, not who. No self rows follow a claim observed by other members, and a freeze writes nothing. | Which IPs fetch the bundle blob, so the members. | The members of e+1 see D′. Every member of e, removed ones included, sees `rm` (who of the old members was dropped). |
| content | The size class only. Safe against a quantum P. | Same, plus blob fetches per IP (image recipients). | Everything in epochs held. |
| directory | handle ↔ uid ↔ keys, registration time, every wrap (credential ids, recovery ids). | The same, plus a p-bit prefix of every lookup, and the exact wrap id and own uid at every login. | — |

Never stored anywhere: topics, subscriptions, IPs, RESUME rings, rate-limit keys, arrival order inside a Δ batch, and
inbox jitter.

### 13.2 Properties of v1 (v1's docs/DESIGN.md §3, at 3de5f5e) that stage 1 weakens

Each item is a deliberate trade-off that stage 2 or 3 addresses. None is silent.

1. **Read privacy against the operator (O).** In v1 every client downloaded every row, and the WebSocket broadcast
   everything to everyone, so O could not tell which client reads which conversation. Stage 1 serves only the rows
   each client asks for (topics and point lookups), so O learns the social graph and per-conversation activity. This
   is inherent in removing O(global) downloads. The fixes come later: OHTTP and tokens in stage 2, PIR and cover
   subscriptions in stage 3.
2. **Tamper and omission evidence.** v1 clients verified a single global hash chain covering every row they
   processed:
   - a skipped seq or a broken chain was **fatal**;
   - `payload.head` exposed any fork between two members who talk.

   In stage 1 there is no global order, and clients verify no inclusion proofs. Detection is reduced to:
   - row immutability (body, `t`, class);
   - the lane `prev` / `prevh` chain;
   - the checkpoint chain persisted per browser (rewrite and rollback of the signed chain itself);
   - `ck16` comparison between members (forks of the checkpoint chain), only for rows whose checkpoint is less than
     2 hours older than the reader's session map: history loaded at restore or by scrollback is not split-view checked;
   - receipts.

   Selective omission, or showing a row to some members only, is undetectable when it does not break a `prev` /
   `prevh` chain. Integrity failures are no longer fatal; they are sticky critical warnings. Inclusion proofs and
   witnesses come in stage 2.
3. **Directory integrity.** In v1, bundles were log rows, every client built its own handle→uid map (the first
   registration of a handle won), and any key substitution forked the log. In stage 1 the directory is server-answered
   D1. The dirlog chain is committed in checkpoints, but clients do not verify inclusion. O can substitute a bundle
   for one client. Defences: fingerprints, CONTACT and MEMBER pins (§7.3), and the keys every descriptor carries
   (§5.1): a directory answer that disagrees with the key a shared conversation lists raises "the public keys of @x
   changed". The pins keep the first verified answer for a uid, whatever a descriptor lists, so a substitution made
   at that moment keeps being reported in every later session instead of disappearing silently. Conversely, v1
   rejected a conversation that listed an unregistered uid ("ignored a conversation with unknown members"), and keys
   always came from the log. Stage 1 accepts such a conversation and takes members' keys
   from the signed descriptor, so validity never depends on the directory (§6.10); a member whose uid is not
   registered, or whose `sigPk` or `kh` in D is not the directory's, is shown as an unknown member `?…` with that
   warning, never under a handle (§11.2, §7.3: MEMBER records keep both keys). A creator or committer can therefore
   list a fake signing or KEM key for a real uid, but cannot make that slot appear under the user's handle, so nobody
   mistakes a reader it controls for that user. Key entries go to the key the descriptors list (§5.4), so such an
   unknown member keeps receiving the epoch keys through whoever holds that key until the members remove it. That is
   the power any member already has by adding a sockpuppet account, except that the member is shown as `?…` instead
   of a handle.
4. **Claim validity depends on server answers.** Rules (g) and (h) use BlobReg and blob answers. A lying operator can
   make members of one conversation disagree about a claim (a fork), with the same power and detectability as item 2.
   Directory answers no longer affect validity: signatures are checked under the keys in descriptors (§5.1, §6.6).
5. **Invite retention.** v1 kept every invite discoverable forever. Stage 1 clients read only the last 4 inbox eras
   (about 4 weeks). A first-contact invite that none of the recipient's devices picks up within that window is lost,
   and the inviter must re-invite. An account keeps at most 64 unopened requests (§11.5), so a spammer can push out a
   genuine request from a stranger before the user opens it. Conversations that were joined are recorded in the self
   lane and never lost.
6. **Latency.**
   - Every membership change and every creation waits at least `Δ + SKEW` (12 s in production) before it becomes
     visible to others, and the creator's first messages wait for it too.
   - First contact by handle arrives within about `inboxSlot` plus the poll interval.
   - The first message after a leave waits for the rotation.
   - Every send costs one more `get` (the control-lane probe of §11.3 step 1), as v1's sync before every send did, and
     another when preparing the put (a slow proof of work, a frozen tab) or its answer takes long (§11.3 steps 6
     and 8).
7. **Ordering.** v1 showed a server total order (seq). Stage 1 orders by clamped sender time, so concurrent messages
   may be ordered differently on different devices. A row shown live can be withdrawn when a claim that removed its
   sender becomes known (§6.8).
8. **History on a fresh device.** v1 replayed everything (all history available at once, at O(global) cost). Stage 1
   shows the last 30 rows per lane of the 20 most recently active conversations at once, and loads up to 500 per
   conversation when it is opened. Older history stays reachable through `prev`, but the UI has no "load older"
   control (unchanged view cap of 500). The leave state of an epoch below the restore's HEADS epoch comes only from
   the rows loaded, so until they include a leave's LEAVE row, a claim that dropped the leaver can read as a removal
   and the "@x left" line is missing (§11.9; round 12).
9. **One more size class.** The 256 class is back. With binary payloads it is the *common* class (short texts,
   images, leaves, welcomes), so it no longer singles out rare rows. P still learns whether a text is ≤ 129 B. That
   is coarser than v1's per-batch shapes, but it is new per-row information.
10. **Directory lookups leak a prefix to the operator.** v1 clients resolved handles from the full directory they had
    downloaded, so O learned nothing about whom a user looks up. Stage 1 sends a p-bit prefix of `H(handle)` or
    `H(uid)` for every lookup: handle resolution, the first verification of each co-member or inviter (then kept in a
    MEMBER record, whatever keys the descriptor lists, so restores repeat none except for uids that are not
    registered). Commits look nobody up: `kemPk` travels in the bundles (§5.4). The
    anonymity set is about 64–128 accounts at honest `P` (all accounts while there are fewer than 64). The client
    bounds `p` by the public dirlog size (§10.6), so O can shrink the set only by inflating the audited dirlog.
11. **A third party can delay first contact and inbox deliveries.** v1 had no global quota. Stage 1's inbox has one
    global day cap (2 000, β = 0). Anyone who fills it with PoW-priced invites makes first contacts, and adds of
    members without a 1:1, wait until the next day, and an attacker who refills the cap right after every day rollover
    (about 2.6·10^8 SHA-256 of PoW per day, spread over a few IPs) delays them for as long as it keeps doing so: honest
    retries back off up to 10 minutes and rarely land in the first seconds of a day. Committers retry (§6.12), and
    members with a qualifying 1:1 are unaffected. A device without a cursor must also trial-decrypt up to 56 000
    invites (about 79 MB, §9.3); the cursor in the self lane keeps this to the invites since the last poll.
12. **Creations and adds are distinguishable from removals and rotations.** v1 gave every change and every creation
    the same `[4, 3×N]` shape, revealing N but nothing else. Stage 1 hides N, but invites by inbox are public rows: a
    change or creation followed within seconds by inbox rows probably invited someone without a 1:1, and one followed
    by none probably did not.
13. **Capacity.** One ShardDO per era stores at most 10 GB (about 25 000 active users at the stage-1 estimate) and
    handles about 1 000 requests/s, and one RealtimeDO and one current InboxDO take every client. When a shard fills,
    writes fail with FULL until the next era (§9.1). These are stage-1 bounds, not protocol limits: S > 1 is a
    parameter change because routing by `v` already exists.
14. **A wrong key entry freezes everyone, and a freeze with a removal stops messaging.** Two deliberate changes to v1's
    freezes (§6.6, §6.10):
    - v1 froze only the members whose invite was missing, and the others kept changing membership. Stage 1 derives
      every kept entry from the new epoch key (§5.4), so a wrong entry for any continuing member makes `D'` invalid
      for every member: membership freezes for the whole conversation, and the warning names the signer. Any member
      who signs an e-valid claim could already freeze everyone with an invalid `D'`, so no attacker gains power, and
      in exchange no member can be silently left behind in an older epoch. Honest commits never produce a wrong entry,
      because they take every continuing member's key from the previous bundle, not from the directory.
    - v1 let the members frozen by a claim that removed someone keep messaging in the old epoch, which the removed
      member could still read, and stage 1 would show them that member as removed. Stage 1 refuses texts and images
      there (§11.3 step 2), so such a conversation becomes read-only; the members start a new one. A member who signs
      an e-valid claim could already end everyone's messaging by removing them, so no attacker gains power.
15. **A row in an old epoch can be missed live.** v1 clients processed every row of the global log. Stage 1 clients
    follow the lanes of the current epoch and, for silent members, of the previous one (§11.2). A row that lands in an
    older epoch after every other member swept that lane is shown live by nobody, and restores from a later HEADS
    miss it; only scrollback finds it (§11.10). Honest single-device senders cannot cause this: they re-probe the
    control lane right before every put and re-check late rows (§11.3 steps 6 and 8). Two cases remain: a member's
    own devices racing a claim (one posts in the new epoch while the other's put into the old one is in flight), and
    a malicious member who registers the next bundle in advance and commits two claims back to back, timed against an
    honest put. Neither hides anything from the members who scroll back (§11.10 probes every era such a row can land
    in), and the second costs the attacker two signed
    claims that every member sees. A check after every put (one more `get` per send: the control lane, and the
    sender's own next slot in the following epoch) would close both (§14).

### 13.3 Properties stage 1 strengthens

- **Recipients of invites** are hidden from a quantum P (PQ trial decryption). v1's X25519 view tags revealed them to
  a quantum P.
- **Membership changes no longer reveal the exact member count.** v1 batches were `[4, 3×N]`. Stage 1 bundles carry
  only the bucket 8 or 32, and P cannot list bundles.
- **Removed members** no longer learn who was added (they still learn, through `rm`, which old members stayed).
- **Junk never freezes membership.** Junk, unsigned rows and e-invalid claims are ignored (v1 froze on any row in the
  claim slot). A signed claim can still freeze membership, as in v1, but the warning names its signer, and every
  member reaches the same verdict, so nobody is left behind in an older epoch (§13.2 item 14).
- **Removed members cannot read on in a frozen conversation.** v1 let frozen members keep writing to an epoch whose
  claim had removed someone; stage 1 refuses it (§11.3).
- **Descriptor validity does not depend on the browser.** v1 rejected a descriptor whose name failed the reader's
  `validName`, whose character classes and NFKC follow the Unicode version of the JavaScript engine, so members on
  different browsers could disagree about a claim or a join. Stage 1 applies `validName` only when building and
  displaying a name (§5.1).
- **Signature validity does not depend on the library.** v1's "strict RFC 8032" allows a cofactored or a cofactorless
  check, which disagree on keys with a torsion component. Stage 1 restricts every signing key to the prime-order
  subgroup and pins the cofactored equation (§1.1).
- **Batching is no longer observable.** P cannot see global seq order, batches or arrival order. Times are Δ-rounded.

## 14. Deferred to stage 2 / 3

**Storage and routing:**

- paging sealed eras into R2 (`.idx`/`.dat`), `seal/{E}` objects, manifests, publishing `kroute_E` of sealed eras,
  deleting old ShardDOs;
- the public label-ordered page reads;
- shard maps with S > 1 (routing by `v` is already in place) and emergency splitting (`MOVED`, frozen ranges);
- R2 Range reads of bundle entries.

**Abuse control and transport:**

- anonymous write tokens (VOPRF, NullDO) and refunds;
- OHTTP (O1) and quiet mode (O2);
- PushDO and Web Push;
- separate FeedDO / ConnDO / `segv-rt` Worker, and Bloom-filtered fan-out.

**Inbox:** β > 0 buckets aligned to handle prefixes, dynamic inbox pricing, and the link-only flag (`flags.bit0`).

**Groups:**

- groups above 32 members, shared lanes (`L_e < m`), admin policy;
- member-count buckets 128 / 512 / 1024, batched removals;
- TreeKEM-style O(log m) rekeying.

**Auditability:**

- witnesses and cosignatures, the `/proof/{E}/{label}` inclusion proofs;
- directory inclusion proofs, mirror feeds for the blob registry.

**Cryptography and accounts:**

- PIR for the directory and inbox; ML-DSA signatures;
- AK rotation and bundle versions (`bundle_hist`, `prevsig`); a rotated `kemPk` must enter each conversation through a
  commit that changes that member's `kh` (§5.1, §5.4), which the D′ checks of stage 1 forbid;
- delayed rekeying after AK rotation; periodic PCS-lite rotation.

**Clients:**

- a link-sharing UI and the `Engine` methods for links (the engine implements links internally in stage 1, §11.11);
- read cursors in PREFS;
- a persisted local cache;
- a "load older" UI beyond 500 messages;
- the late-row check of §11.3 step 8 after every put, not only after slow ones, with the sender's own next slot in
  the following epoch (closes §13.2 item 15 at one more `get` per send).

---

## Appendix A. Resolved ambiguities

`DD` refers to the stage-1 design draft ("Label-Indexed Store", §-numbers as in that draft).

| # | Where | Ambiguity, inconsistency or migration assumption | Resolution |
| --- | --- | --- | --- |
| A1 | DD §12.1 migration, §4.7 `pub/v1/*`, §5.2 | DD freezes the v1 log, indexes v1 tags, points `prev` into v1 (`0xFFFF`), and reuses v1 `rk/mk/kc` for continuity. | No migration (no users). All of it is dropped. **Every** label is `segv.sh/v2/`, including the account layer, the PRF input, the seal label (`segv.sh/v2/ak-wrap`) and the epoch keys. `0xFFFF` now only means NONE. |
| A2 | DD §5.2 | `rk/mk/kc` "v1 reuse" versus the new `nk/dk` labels. | All five epoch keys and `ekc` use fresh v2 labels (§4.2). |
| A3 | DD §4.3 vs MVP | DD uses 5 classes (256, 512, 1K, 4K, 16K). The MVP uses [1024, 4096, 16384] because JSON never fit 256. | `[256, 1024, 4096, 16384]`. Binary M (62-byte header) makes 256 the common class (texts ≤ 129 B). 512 is dropped (one bin less of size leakage). Claims (270–456 B) blend into 1024 with medium texts. The 16384 class fits the 12000-byte text limit. |
| A4 | DD §5.4 | The inbox payload carries `D_0`/`dsig_0` and uses a 1024 class (2184 B), and `entryIdx`/`bundleId` sometimes. | Every epoch's descriptor, including e = 0, lives in its SGB2 bundle. J is a fixed 90 B (`conv, e, EK, bundleId, bundleSize`) padded to 256, giving **1416 B** invite bodies: 35% less for every client to scan. |
| A5 | DD §6.7 step 5 | A separate `Cl` format and a csig over `(conv, e, E, k, label, Cl)`. | Claims use the common envelope M (type 16). Its signature is the csig and covers `(conv, e, E, label, M)` with `k = n`. Content is fixed-width (§6.2). |
| A6 | DD §6.7 "cuts" | `(ℓ, E, n)`, with no rule for empty lanes and nothing saying whether the bound is inclusive. Also no rule for posts into epochs older than e. | `cut = (E, cnt)`, an exclusive count of the dense prefix; an empty lane is `(E_start, 0)`. The committer chooses cuts, so they decide only rows in the claim's own Δ batch: rows stored before the claim are always accepted and rows after it are dropped for removed senders (§6.8). Later claims use stored `t` (≥ counts as after). Removal comes from the claim's public `rm`, so frozen readers apply the same rule. |
| A7 | DD §6.7(e) | "`t_reg < t(claim)`" does not say when a missing registration is final. With clock skew, an early MISS could flip later, so evaluation would not be deterministic. | MISS is decisive iff BlobReg's reported `now ≥ t_row`. BlobReg persists a high-water mark so registrations never get `t` below a reported `now` (§6.4, §9.2). |
| A8 | DD §6.7 step 4, user decision | The wait bound. | The committer waits until server `sec ≥ t_reg + Δ + SKEW` with SKEW = 2 s (both params), and at least `(Δ + SKEW)` s of monotonic time after the PUT response. It then checks its own claim: an OK with `t ≤ t_reg` is an e-invalid claim and a retry at the next slot, never a switch (§6.3). |
| A9 | DD §6.7 "winner / confirmed" | "Lower slots all filled", in an era, across eras, and with holes. | Dense prefix per era for the control lane. Finality requires every earlier era to be observed `MISS(sealed)` at its first empty slot (or covered by the account's own HEADS). A claim wins only when every earlier slot is decided not e-valid; undecided slots block (§6.5). Lane rows beyond a hole are accepted through their `prev` chain, with an omission warning (§12.2). |
| A10 | DD §6.7 member processing | D′-invalid versus "excluded", and who can evaluate D′. DD's dummy entries for removed members make a removal look the same as a withheld key, so one malicious member could end the conversation for everyone (v1 only froze it). | The winner is the first e-valid claim for every member of e; nothing private (an entry, D′) changes it. The claim's public `rm` bits name who is dropped, so a removed member's entry is a dummy that nobody reads. D′ must keep exactly the old members `rm` keeps. Every kept entry is derived from the new epoch key (`sealDet`, §5.4), and D and the bundle carry every member's KEM key, so every holder of the new key recomputes every kept entry: an invalid D′, or a key withheld from some or all members, freezes membership for all members alike, as v1's never-delivered state did, and the signer is named (§6.6). No member is left behind, so no repair protocol is needed (§13.2 item 14). Directory registration is not part of validity, because D carries every member's `sigPk` and `kh` (§5.1), so a later registration cannot change anyone's decision. |
| A11 | DD §6.7(b), §6.8 | Admin policy, with groups of 3+ admin-only by default. | Stage 1 keeps the MVP policy: any member may commit. D has no policy field. Admins are deferred. |
| A12 | DD §6.8 | Leave as type 17 on the control lane, with a ranked committer waiting `r × 30 s`. | LEAVE stays on the leaver's own lane (MVP semantics, carried over to later epochs). The next remaining sender MUST rotate first. Ranked proactive rotation is a MAY (§6.9). |
| A13 | DD §6.8 "do not mix add and remove" | The MVP drops leavers inside an add. | Mixing is allowed. Entries are indexed by `D_e`, and new members get J, so a mixed commit leaks nothing extra. |
| A14 | DD §6.7 step 2/6 | Entries for new members appended, `entryIdx` sent in the welcome, and B up to 1024. | New members get EK directly in J and have no entry. Entries exist only for indices of `D_{e−1}` (derived seals for those kept, dummies for those leaving and as padding). B ∈ {8, 32}. |
| A15 | DD §6.6, MVP privacy tests | DD defines no creation-versus-change indistinguishability. The MVP does (decoy, shuffle). | Creation = a registered SGB2 bundle, a class-1 self row, the same wait, a class-1 decoy at a random label, J's, and one class-1 self row (DELIVERED), which is the pattern of a commit (§6.1, §6.3, §6.12). Invite order is irrelevant: entries are unreadable, and J's go to individual inbox rows or 1:1s. Inbox counts still separate "someone invited by inbox" from "nobody" (§13.2 item 12). |
| A16 | DD §5.4 | `rel = ceil((sec + jitter)/Δ_inbox)` with no definition of the cursor, of closed slots, or of retention. | `rel = max(⌊(ms + j)/D⌋ + 1, closed_hw + 1)` and `closed = max(⌊ms/D⌋, closed_hw)`, so a new row never lands at or below a reported `closed` (rows ≤ closed are final), whole-group paging, a persisted `ended` state, and a 4-era client retention with 410 beyond it (§9.3). Δin = 10 s in production (not 5 min), so first contact stays fast. |
| A17 | DD §4.4 | 64-bit `v` used as a SQLite integer. | `v` is an 8-byte big-endian BLOB. JS numbers cannot hold 63 bits, and the BLOB sort order equals the numeric order. |
| A18 | DD §4.4 "no secondary index", `lost = 1` | Batch leaves are lost on restart, which breaks enumeration of "the DB is public". | Stage 1 adds `row_t(t, label)`: batches are always recomputable, the public feed is simple, and nothing is ever `lost`. This costs 2× row writes, which is negligible at stage-1 scale. Each row also stores `bh = H(body)`, so closing a batch of any size never reads a body (§9.1). |
| A19 | DD §4.4 `FULL` / `MOVED` "writer skips n" | Skipping creates a hole, which contradicts dense prefixes. | FULL is a whole-shard failure (retry later, no skip). MOVED is reserved. |
| A20 | DD §6.2 RESUME | A per-socket 10-minute buffer that cannot survive hibernation. | One in-memory ring keyed by publish time plus a `boot` id. On any mismatch, or a replay above 2 MiB, the server sends GAP and the client catches up. No persistence (§9.4, §10.8). Eviction of the hibernated DO resets the ring and `boot` too, so the 10-minute window is an upper bound. |
| A21 | DD §4.8 | Topics included in the put, but publishing is unspecified. | The Worker publishes OK rows with a non-zero topic to the RealtimeDO after the shard answers, through `waitUntil`. Rows carry a per-boot `seq` for RESUME. Clients sweep every 300 s and probe a topic right after subscribing it, so a lost publish costs latency only; a join that arrives before its claim is parked, not rejected (§6.7). |
| A22 | DD §5.4, §6.4 directory | Only `upre`/`hpre` prefix queries. Recovery login and passkey login without a userHandle need lookup by wrap id. | Kept exact `dir/wraps/{id}` (the same leak as v1) and exact own-uid lookup. Others go by prefix; the server accepts any `p ≤ P + 1`, and the client picks `p` bounded by the public dirlog size (§10.6). Prefix lookups leak more to O than v1's local directory (§13.2 item 10). |
| A23 | DD §4.4 `dirlog` | A hash chain in D1 without a sequencer. | One atomic D1 batch with explicit seqs and an optimistic retry on a seq conflict, up to 16 attempts with random backoff (§9.6). D1 is authoritative, with no log fallback. |
| A24 | DD §6.4 | HEADS, the snapshot and self records are named but not encoded. Spam amplifies self-row writes. | Exact encodings (§7). A self row holds a list of records. The snapshot is a compacted record list. Copies are identified by `root = H(D_join)`. |
| A25 | DD §6.12 | Thumbnails in image messages (class 4096). | No thumbnails (the MVP has none). IMAGE is 69 B, so it uses class 0. |
| A26 | DD §4.2 | Δ chosen automatically from load (up to 300 s). At low traffic this makes every commit wait about 5 minutes. | Δ is a fixed deployment parameter, 10 s. The "≥ 8 rows per batch" target is not guaranteed at stage-1 traffic (§13.1). |
| A27 | DD §4.6 / §4.7 | BlobReg is "public" and enumerable (`blobreg/{day}.bin`). The MVP deliberately kept the blob ledger operator-only at day precision. | Readable by id only, with no enumeration API. The checkpoint commits to it through `H(id)` leaves, but takes its head at most once per hour, so P learns at most whether any blob was registered in an hour (§8.2, §9.5). |
| A28 | DD §5.6 | Checkpoints are defined but neither verification nor persistence is. | Compact range verification, persisted `{k, q, C, at}`, a signing key pinned on first use, equal-`q` comparison, a time-based (not `q`-based) skip rule, and messages carrying `(ckq, ck16)` (§12). |
| A29 | DD §4.8 | Puts of up to 64 rows. The MVP has one kind-4 row per atomic batch. | Up to 16 independent rows, ≤ 263 345 B (exactly the largest valid request), PoW priced by bytes. The batch shape no longer leaks, because nothing about a request is stored. |
| A30 | DD §5.1 "scanSk unused" | The bundle still carried the scan key. | The bundle v2 drops `scan`, and the fingerprint covers `(uid, sigPk, kemPk)`. |
| A31 | DD §6.10 | AK rotation is described. | Deferred. Keys never change in stage 1. |
| A32 | DD §6.6 | Welcome via 1:1 is "type 8", with no receive rules. | A WELCOME carries J and is accepted in any held conversation from a verified member. Sending through a 1:1 is a SHOULD, and only through a 1:1 in whose current epoch the recipient has posted, which neither side has left and from which the sender was not removed, checked again for the epoch the row is written in (§6.12, §11.3 step 2); every other recipient gets an inbox invite. |
| A33 | DD §6.6(a) hello | The hello layout mixes `seal` with `H(s)` and the D_0 payload. | `inner = seal(kemPk, "segv.sh/v2/hello", enc(H(s)), J)`, wrapped by AEAD under `mL`, class 2. |
| A34 | DD §6.3 "unread from head differences" | There is no persisted read cursor. | MVP semantics: unread counts rows applied after restore, in memory only (§11.8). |
| A35 | DD §6.4 "upre prefix gets bundle + wraps (~130 KB)" | For a login the uid is often known, but prefix responses with wraps are heavy (~400 KB). | Login uses the exact wrap-id lookup plus the exact own-uid lookup (a few KB). Prefix queries return bundles only. |

## Appendix B. Changes from v1

| area | v1 | v2 stage 1 |
| ---- | -- | ---------- |
| Storage | one global hash-chained log (LogDO), kinds 1–4, `UNIQUE(tag)` | per-era ShardDO rows `(E, label) → (t, cls, body)`, create-only; D1 directory; BlobRegDO; InboxDO; CheckpointDO |
| Reading | download every row since the cursor | point lookups of expected labels (`/get`), topic WebSocket, snapshot + self lane |
| Realtime | `/api/ws` broadcasts every row to everyone; ping only | `/api/v2/rt`: SUB, UNSUB, RESUME (by per-boot `seq`) / HELLO, ROWS, GAP, RESUMED, per-topic delivery, ≤ 256 topics per socket |
| Labels | `segv.sh/v1/*` | `segv.sh/v2/*` everywhere (no compatibility) |
| Bundle | JSON v1 with `scan` | JSON v2 without `scan`; fingerprint over `(uid, sigPk, kemPk)`; `sigPk` must lie in the prime-order subgroup, and every signature uses the pinned cofactored check (§1.1) |
| Directory | kind-1/2 log rows; D1 as a derived index; exact handle lookup | D1 authoritative with a dirlog chain; prefix lookups; exact wrap-id and own-uid lookups |
| Message tags | `msgTag(i, n)`, `claimTag` | `Lmsg_e(ℓ, E, n)` (n per era), `Lctl_e(E, k)`, `Lself`, `Lsnap`, `Lhello` |
| Payload | JSON (`v, t, conv, e, from, n, ts, head{seq, h}`) | binary envelope M (62 B header: type, from, lane, n, prev, prevh, ts, ckq, ck16) |
| Classes | messages [1024, 4096, 16384]; invites [2048] | [256, 1024, 4096, 16384] for all rows; inbox body 1416; descriptors padded to [4096] inside SGB2 bundles (23456 or 81248 B) |
| Descriptor | JSON, inside invites and claims; member keys from the directory | binary D listing `(uid, sigPk, kh = H(enc("segv.sh/v2/kh", kemPk)))` per member, encrypted in the SGB2 bundle under `dk_e`, with the members' `kemPk`s alongside (`pkCt`); the directory supplies handles, and keys only when a member is resolved by handle (or, for a link, by uid); a member whose `sigPk` or `kh` differs from its directory bundle is shown as `?…`; the name's `validName` is a build and display rule, not a parse rule (v1 rejected descriptors with names that failed it) |
| Key delivery | kind-3 invite per member (X25519 view tag + X-Wing) in the same atomic batch as the claim | SGB2 bundle entries (X-Wing, randomness derived from the new epoch key, so every member can recompute them) for continuing members; J via the PQ inbox, a 1:1 WELCOME or a link hello for new members |
| Claims | one slot per epoch; first row wins; burn ⇒ freeze; never-delivered ⇒ freeze | control lane; the first e-valid claim wins for every member (undecided slots block, and sends wait and then fail meanwhile, as in v1); bundle registered before the claim (t_reg + Δ + SKEW, checked on the OK); finality via sealed eras; junk never freezes; public `rm` bits; an invalid D′ or a wrong key entry for any continuing member freezes everyone (attributable; v1 froze only the members whose invite was missing), and a J never overrides a claim; a freeze whose claim removed someone also stops texts in the old epoch |
| Old-epoch acceptance | claim chain by seq | stored `t` against each later claim's `t`, with `rm` naming who is dropped; cuts only for the claim's own Δ batch |
| Creation privacy | decoy kind-4 row + shuffled invites, `[4, 3×N]` | an SGB2 bundle + a class-1 self row + the same wait + a class-1 decoy at a random label + J's + a class-1 self row |
| Multi-device | own invite per epoch; counters by log scan | self lane (records + snapshots + trusted HEADS positions), CAS on shared counters, CONFLICT returns the occupant, resumable J delivery |
| Integrity | client-verified global chain (fatal on gaps); `head` in messages; local checkpoint | signed checkpoint chain (local persistence, range verification), `ck` in messages, `prevh`, immutability, receipts, public feed for auditors |
| Abuse | PoW `register/wrap/append/blob`; RL write/blob/read | PoW `register/wrap/put/inbox/blob`; RL write/inbox/blob/read |
| Blobs | `/api/blob`; D1 ledger (day precision, private) | `/api/v2/blob` + `meta`; BlobRegDO create-only with Δ-precise `t_reg`, readable by id only; its head enters checkpoints hourly |
| Time | `ts` = server ms floored to the second, in the chain | era (week) + `t = tpub` (Δ seconds) |
| AK rotation | not supported | not supported (deferred) |

## Appendix C. Review changelog (round 1)

Every finding of review round 1 was checked against this spec, DD, the MVP code and the Cloudflare documentation, and
accepted. Where a finding offered alternatives, the entry names the one taken.

| id | change |
| --- | --- |
| SEC-1 | Claims carry a public `u32 rm` (§6.2; content 137 + 6m B). e-validity checks its bits (§6.4(e)). REMOVED counts only where `rm` agrees, otherwise the member is frozen with a warning naming the committer (§6.6). Members of e+1 require `D' ∩ D_e` = the members `rm` keeps. Skip needs the self bit of `rm` (§6.7). Every member of e shows "@by removed @x" from `rm`. §0.3, §5.4, §6.9, §13 updated: removed members learn which old members stay. Tests in plan M7. |
| SEC-2 | The winner is the first e-valid claim for everyone; no D′-invalid skipping (§6.5). An invalid D′ freezes all of e, attributably (§6.6, §6.10). §0.3(6), §0.4, §13.3 and A10 restated. Test in plan M7. |
| SEC-3 | Directory registration left every validity rule (§6.6, §6.7). Unregistered or unusable members are shown as unknown members (§11.2). FakeWorld gets a register-between-evaluations hook. |
| SEC-4 | Followed lanes defined (§11.2) and recorded in HEADS. Frozen members post NEED_KEY (type 18) and members of e+1 re-deliver (§6.6). Tests in plan M7. |
| SEC-5 | Cuts bounded by e-validity (f). Old-epoch acceptance is by stored `t` against `t(C)`, with cuts only for the claim's own Δ batch (§6.8). Re-delivery fires only on NEED_KEY rows after the claim, with ranked delays (§6.6). |
| SEC-6 | Bundle size, hash, header and `B ≥ |D_e|` are e-validity rules (g)/(h), evaluated by every member (§6.4). |
| SEC-7 | `ck8` → `ck16`; the M header is 62 B and class-0 texts ≤ 129 B (§3.2, §3.3, §12.4). §13.2 item 2 states that history older than the 2-hour map is not split-view checked. |
| SEC-8 | `segv.ckpt` stores `at`; the range is skipped only after 30 days of client time, and a `q` jump faster than one per minute is a rewrite (§12.3). |
| SEC-9 | No self row is written for claims observed from others (§7.3). Creator sends wait for the decoy (§6.1). Creation and commit self rows are padded to the same classes, and both end with a DELIVERED row (§6.12, §7.1). The remaining inbox-count difference is stated in §13.1 and §13.2 item 12. |
| SEC-10 | Prefix lookups are listed as a weakening (§13.2 item 10) and removed from §13.3. The client bounds `p` by the dirlog size and warns on thin buckets (§2.5, §10.6). |
| SEC-11 | Restore and catch-up process every row from the processed position (HEADS) to the head, so WELCOMEs are never skipped (§5.2, §11.4, §11.6). |
| SEC-12 | Joins are parked until each held copy's control lane is settled; the inbox cursor never passes a parked join (§6.7 step 4, §11.5). |
| SEC-13 | Request copies are REQUEST records that carry D, at most 64, not subscribed, probed cheaply, never bundle-fetched at restore (§7.2, §7.3, §11.5). |
| SEC-14 | The immutability map holds `(H(body), t, cls)`; e-validity uses `t` from a get or CONFLICT (§6.4(g), §12.1). |
| SEC-15 | The blob registry head enters checkpoints at most hourly (§9.5); §8.2, §13.1 and A27 corrected. |
| SEC-16 | Folding a CONV_JOIN for a conv with a CONFIRMED copy drops it with the critical warning; CONFIRMED is written before CONV_JOIN (§7.3). |
| SEC-17 | Request copies probe one key per member lane and the control lane at every catch-up and restore, so corroboration does not depend on realtime (§11.5). |
| SEC-18 | §1.1: decapsulation may throw, independently of the recipient; every caller treats a throw as "does not open" (§5.3, §6.6, §11.5). Unit test in plan M1. |
| COR-1 | The committer checks `t > t_reg` on OK and retries at the next slot otherwise; the wait is anchored on monotonic time (§6.3 steps 5 and 7). |
| COR-2 | e-validity is three-valued; network errors are undecided; undecided slots block the winner and the committer (§6.4, §6.5, §6.3 steps 7–8). |
| COR-3 | Resolved by SEC-1 (no covert removal) and SEC-2 (one winner for all, so re-delivery is chained to the same claim). |
| COR-4 | Same change as SEC-4. |
| COR-5 | Same change as SEC-11; processed positions persist in HEADS. |
| COR-6 | Creation uploads first, then writes CONV_JOIN with EPOCH_PENDING(e = 0); any device resumes delivery (§6.1, §6.11). |
| COR-7 | J delivery is a persisted queue (EPOCH_PENDING + DELIVERED) with retry; the inbox POST carries up to 32 invites (§6.12, §10.5). |
| COR-8 | Same change as SEC-12, plus leavers and removed members keep following their last control lane (§6.7, §6.9). |
| COR-9 | "Confirmed" excludes self (§6.7 step 6). Plan test #24 gains a variant. |
| COR-10 | Validly signed rows beyond a hole are accepted through their `prev` chain with an omission warning; `prevh` is checked for every row (§4.2, §12.2). |
| COR-11 | CAS outcomes defined: identical occupant = OK, network/5xx probed, undecided waited, and the committer completes its own winning claim even after an abort (§6.3). |
| COR-12 | InboxDO persists `closed_hw` and `ended` (§9.3). |
| COR-13 | Inbox poll clamps to `E_now − 3`, uses `after = 0` for later eras, and handles 410 (§11.5). |
| COR-14 | Same change as SEC-5; retraction of dropped rows is deterministic and unread excludes them (§6.8, §11.8). |
| COR-15 | Same change as SEC-6; transient failures are undecided, and sends stop waiting after 30 s (§6.4, §6.6, §11.3). |
| COR-16 | CONTACT creation and request transitions defined; a transition processes all lanes from `E_start` (§7.3, §11.5). |
| COR-17 | Requests are not subscribed; ≤ 256 topics per socket, ≤ 2 sockets per tab, back-off after 1008/1013 (§10.8). |
| COR-18 | The account's own HEADS positions are trusted for starting points and finality (§6.5, §7.2); the restore cost is restated (§11.4). |
| COR-19 | Joins and the cursor that passes them are written in one self row; no record passes an unrecorded join (§7.3). |
| COR-20 | WRONG_ERA counts against attempts and waits when it repeats; shards accept SKEW early (§6.3, §9.1, §11.3). |
| COR-21 | (a) by the creation order of COR-6 and queued sends; (b) scrollback probes each era's dense-prefix end (§11.10). |
| COR-22 | ROWS carry a per-boot `seq`; RESUME is by `seq`; a GAP still installs topics; a new SUB triggers a probe (§10.8). |
| COR-23 | Rotation before send is skipped when frozen or at `e = 2^32 − 2` (§6.9, §11.3). |
| COR-24 | EPOCH_PENDING is keyed by `(conv, root, e, bundleId)`, all kept (§7.3). |
| COR-25 | Snapshots keep CONV_JOIN / REQUEST order (§7.3, §7.4). |
| COR-26 | A failed echo keeps its sealed body and is re-put at the same slot first; probes are bounded; unread excludes own rows (§11.3, §11.8). |
| COR-27 | Plan: engine timer knobs, `busy` semantics and T4 rewritten (§11 constants; plan §2.2, §4). |
| IMP-1 | Plan §0.4 adds a UI change: the conversation pane calls `markRead` on every open; `markRead` starts scrollback once (§11.10, §11.11). |
| IMP-2 | Same change as COR-7. |
| IMP-3 | Same change as COR-6; `createConversation` resolves after step 5 (§11.11). |
| IMP-4 | Same change as COR-1; responses carry `x-segv-now` (§10.1). |
| IMP-5 | RealtimeDO: tags for counting and expiry, 256 topics per socket, 250 000 pairs, 16 MiB ring, close 1013 beyond the budget (§9.4). |
| IMP-6 | Same change as SEC-13. |
| IMP-7 | ShardDO and BlobReg persist `closed_t` and never assign `t` into a closed batch (§9.1, §9.2). |
| IMP-8 | Same change as COR-12. |
| IMP-9 | Shards and inboxes accept writes from `start(E) − SKEW` (§9.1, §9.3); clients bound WRONG_ERA retries. |
| IMP-10 | DESC records remove bundle fetches at restore; immutable and tail responses come from `caches.default` before the rate limiter; idle lanes cost `P0 = 2` keys; 429 back-off (§7.2, §9.7, §11.4). |
| IMP-11 | Capacity stated (§9.1, §13.2 item 13) and in plan §6; inbox tail cached for Δin (§10.5). |
| IMP-12 | Prefix reads use `BETWEEN` with arithmetic bounds; the user count lives in `dirmeta` (§9.6). |
| IMP-13 | dirlog retries: 16 attempts with random back-off; the plan test uses 8 concurrent writers (§9.6). |
| IMP-14 | `x-segv-now`, engine timer knobs, and a FakeWorld `settle` that waits for open inbox slots and pending timers (§10.1, §11; plan §2). |
| IMP-15 | Plan §4 T1 and T4 rewritten. |
| IMP-16 | The CheckpointDO arms its alarm in its constructor; the Worker calls `ensure()` once per isolate (§9.5). |
| IMP-17 | `row` and `inv` are rowid tables with UNIQUE indexes (§9.1, §9.3). |
| IMP-18 | Put body cap = 263 345 B, reported as `limits.putBytes` (§10.3). |
| IMP-19 | Same change as SEC-9 (padding and the trailing DELIVERED row); CONTACTs move to the HEADS row (§6.1, §7.3). |
| IMP-20 | Per-era DOs take `(E, i)` from `ctx.id.name` and arm alarms in `blockConcurrencyWhile` (§9). |
| IMP-21 | Inbox size under attack stated (§9.3, §13.2 item 11); trial decryption in a Web Worker; cursor written at registration and with every join (§11.1, §11.5). |
| CMP-1 | Same change as COR-1. |
| CMP-2 | Same change as COR-6. |
| CMP-3 | Same change as COR-7; the day-cap DoS is §13.2 item 11 and in §0.4. |
| CMP-4 | The inbox cursor is written with joins, every 30 minutes in HEADS, and at registration (§7.3). |
| CMP-5 | Same change as SEC-17. |
| CMP-6 | Same change as IMP-1. |
| CMP-7 | Same change as SEC-4 (NEED_KEY announces the freeze); §0.3(6) and §6.10 state what frozen members receive. |
| CMP-8 | Same change as SEC-1 (option a). |
| CMP-9 | Links stay in scope (DD §12.1): the engine implements them internally with tests, without an `Engine` interface change; only the UI is deferred (§11.11, §14; plan M10 before M9). |
| CMP-10 | Same change as IMP-15. |
| CMP-11 | Same change as IMP-14. |
| CMP-12 | Requests verify only `D.by` at acceptance; prefix responses are cached per session (§10.6, §11.5). |
| CMP-13 | HEADS may be partial and split across records and rows (§7.2, §7.3). |
| CMP-14 | Initial history only for the 20 most recently active copies; the restore cost formula is complete (§11.4, §13.2 item 8). |
| CMP-15 | Intermediate eras are probed at slot 0 only and dropped once sealed (§6.5, §11.2). |
| CMP-16 | Equal `q` with a different `C` is a rewrite (§12.3 step 3). |
| CMP-17 | Same change as COR-23. |
| CMP-18 | The Worker bounds `E` before routing to any DO; ended eras arm no alarms (§9, §9.7, §10.4). |
| CMP-19 | Per-socket SUB/UNSUB rate limits (§9.4). |
| CMP-20 | Same change as COR-6 and SEC-9 (sends queued until the decoy). |
| CMP-21 | Same change as COR-12 (`⌊(ms + j)/D⌋ + 1`). |
| CMP-22 | Same change as SEC-15; directory registration times stated precisely (§13.1). |
| CMP-23 | `kroute` removed from `/era/{E}`; its publication is listed in §14. |
| CMP-24 | Noise warning for e-invalid control rows defined (§6.4); catch-up fetches bodies (§11.6); plan items aligned. |

## Appendix C — Review changelog (round 2)

Every finding of review round 2 was checked against this spec, DD, the MVP code (`src/client/engine.ts`,
`src/server/api.ts`) and the Cloudflare cache semantics, and all nine were accepted. Where a finding offered
alternatives, the entry names the one taken.

| id | change |
| --- | --- |
| RC-1 | D lists `(uid, sigPk)` per member (§5.1; at most 1872 B). `descCt` pads to [2048] (2088 B), so SGB2 bundles are 11640 or 40248 B (§3.2, §5.4, §6.4(g)/(h), §6.7 step 1, Appendix B). The [2048] descriptor class is the smallest that fits a maximal `D ‖ dsig` (1936 B); it is internal to the bundle, which keeps exactly two public sizes, so no new row or blob size class appears. Claims (c), lane rows (§3.3), `dsig′` and joins verify only under keys in D; D′ must keep continuing members' keys (§6.6 step 4). The creator and committers copy new members' keys from verified bundles (§6.1, §6.3); first-contact and skip joins require D's key for `D.by` to equal the directory's, and every join requires self's own key (§6.7). The directory supplies handles and `kemPk` only; a disagreement shows the member as `?…` with "the public keys of @x changed" (§11.2). Unknown continuing members get a dummy entry (§5.4). §6.10, §13.2 items 3–4 (v1's rejection of unknown members is stated as a change), A10, plan M1 tests 1/7/10/12, M6 test 13, M7 test 10(b) (unregistered committer registering between evaluations). |
| RC-2 | A chained join must pass every D′ check against `D_k` and the winning claim; a copy frozen as invalid never accepts a chained join for that claim, and a withheld member receiving an invalid D′ becomes frozen as invalid (§6.6 step 6, §6.7 step 5, §6.10). Plan M7 tests 5, 6 and 8 gain variants where mallory sends J(e+1) of the invalid D′ to every member. |
| RC-3 | Option 1 of the finding, made robust to the two sides' different knowledge: followers keep exactly one lane per silent member, in `f(s)` = the epoch of its latest seen row or the start of the shared run (§11.2); a frozen member posts NEED_KEY (now `u32 e_f`) on its own lane of **every** epoch of its own run, so a copy reaches every follower whatever it saw (§3.3, §6.6 step 6), and followers then follow `e_f`. Follow cost stays bounded by members; the frozen member pays `e − a + 1` class-0 rows once. Restore computes `f(s)` from the same rows (§11.4). Plan M7 test 22 (a lurker silent across two changes, withheld at the third). |
| RC-4 | New MEMBER self record (0x0D: `uid | sigPk | pin | handle`), written on first verification of a co-member or inviter, kept in snapshots for listed members (§7.2–§7.4). Restores and catch-ups make no directory lookups for known members; `kemPk` is fetched only for commits, creations and inbox J (§6.3, §10.6, §11.4, §11.5). The restore cost now lists directory bytes (§11.4). `dirlog` is read only before a session's first prefix lookup. §13.2 item 10 updated. Plan T1 (directory requests included; no prefix lookup at restore), T6 (exactly one directory request) and T7, M6 tests 10 and 14. |
| RC-5 | WELCOME is used only in a 1:1 in whose current epoch the recipient has posted a valid row and which it has not left; otherwise J goes by inbox (§5.2, §6.12 step 1, A32). §6.9 states that leavers stop processing lane rows. Plan M6 test 8 (precondition and variant), M7 test 24 (expired request; leaver), Q5. |
| RC-6 | Old-epoch lanes are swept to their heads, after the ending winner is final, before they leave the expected-label map (§6.6 step 4, §11.2, §11.6). Restore processes every lane of every epoch from the HEADS epoch (or the copy's root) to the current one (§11.4, §5.2); snapshots carry DESC for followed epochs (§7.4). The remaining gap (a row a member writes into an older epoch after writing in a newer one, only possible when its own devices race a claim) is stated and left to scrollback (§11.2). Plan M7 test 23 (restore and live variants). |
| RC-7 | Three frozen states: withheld, **excluded** (REMOVED sealed while `rm` keeps the member) and invalid (§6.6 steps 4 and 6, §11.2). Excluded members get their own warning, post NEED_KEY and are re-delivered like withheld ones (§6.10, §0.3(6)). Plan §0.3 strings, §2.3 `frozen` enum, M7 test 8 (victor posts NEED_KEY, alice re-delivers, victor reaches e+1). |
| RC-8 | Re-delivery is acknowledged and bounded (§6.6 steps 6–7): the re-delivered member posts KEY_OK (new type 19, §3.3) in the epoch it reaches; only ranks 0–2, ordered by most recent activity, re-deliver; each re-delivery writes a DELIVERED record so sibling devices and later sessions do not repeat it (§6.12 step 3, §7.2, §7.3); no lane position is recorded past a NEED_KEY whose re-delivery is pending; snapshots drop these records once HEADS covers the NEED_KEY (§7.4). A freeze costs at most three J copies. §13.1 and §13.2 item 6 updated. Plan M7 test 7 (re-delivery bounds). |
| RC-9 | `x-segv-now` is stamped on the returned response after any cache lookup and stripped before `cache.put` (§9.7, §10.1); clients take the clock offset only from `no-store` responses (§3.1, §10.1). The finding's extra "reject backward jumps larger than the RTT" was not adopted: component clocks may legitimately differ by up to SKEW, and `no-store` responses are never replayed from a cache. Plan M4 route table and server-time test, M5 `staleNow` knob, M6 test 15. |

## Appendix C - Review changelog (round 3)

Round 3 verified the round-2 changes (RC-1..RC-9) and reviewed §5–§7 and §11–§12 again. Every finding was checked
against this spec, DD, the MVP code (`src/client/engine.ts`, `src/server/http.ts`, `@noble/post-quantum` 0.7.1) and
the Cloudflare documentation. Most findings traced back to one mechanism: the partial freeze and its repair (NEED_KEY,
KEY_OK, ranked re-delivery, `f(s)`, chained joins, the excluded state). SIMP3-1 removes the reason that mechanism
existed (only a member's own client could tell whether its key entry was right), so the whole mechanism is deleted
rather than patched; the entries below that it resolves say so. No finding was rejected outright; where a finding
offered alternatives, the entry names the one taken and why.

| id | decision and change |
| --- | --- |
| SIMP3-1 | **Accepted** (the central change of this round). D lists `(uid, sigPk, kh = H(enc("segv.sh/v2/kh", kemPk)))` per member (§5.1; at most 2896 B). SGB2 bundles carry `pkCt` (every member's `kemPk`, B·1216 B under `dk_e`) and descCt pads to [4096], so bundles are 23456 or 81248 B (§3.2, §5.4, §6.4(g)/(h), §6.7 step 1). Kept entries are `sealDet`: X-Wing EncapsulateDerand with randomness and nonce from `rr_e = HKDF(EK_e, …)` (§5.4), the same layout as `seal`. The D′ checks add the `kh`/`pks` checks and the byte-for-byte recomputation of every kept entry (§6.6 step 4), so a wrong entry for any continuing member makes D′ invalid for everyone and nobody is left behind. Added beyond the finding: a join checks `pks` too (§6.7 step 2), so a creator cannot plant a key that later blocks every commit; the D′ checks require every key in `pks'` to be valid; and the chained join is replaced by a one-line "claimed" rule (a J for the claimed epoch is ignored, §6.7 step 5). Deleted: REMOVED/ZERO32 entries, the withheld and excluded states, NEED_KEY (type 18), KEY_OK (type 19), §6.6 step 7 (ranked re-delivery), re-delivery DELIVERED records and the HEADS rule for them, `f(s)`/`run(s)`, EPOCH flag bit0, the unknown-member dummy entry, and every `kemPk` directory lookup at commit time (§3.3, §5.4, §6.3, §6.6, §6.7, §6.10, §6.12, §7.2–§7.4, §10.6, §11.2–§11.4). §0.3(6), §0.4, §6.10, §13.1, §13.2 items 3 (an unknown member's entries reach whoever holds its listed key, the power of a sockpuppet account), 6, 10 and new 14, §13.3, §14 (AK rotation must change `kh` by a commit), A10, A14 and Appendix B restated. Plan: M1 table and tests 1, 2, 6, 7, 10, 12; M7 description and tests 5–9, 27; §2.3; §3 rows 23, 30–32, 49, 50; §6 risk 3; Q9. |
| SIMP3-2 | **Accepted, resolved by SIMP3-1**: ranks and re-delivery no longer exist, so no rank set can exclude the capable members. The finding's no-wire-change alternative (rank windows, a periodic NEED_KEY) was not needed. |
| SIMP3-3 | **Accepted, subsumed by SIMP3-1**: REMOVED and the excluded state are deleted; a dropped member's entry is a dummy, and its removal comes from `rm` (§5.4, §6.6 step 3). `openEntry` returns `EK | null` (plan M1). |
| SIMP3-4 | **Accepted, resolved by SIMP3-1**: NEED_KEY and its O(epochs) fan-out are deleted, and with them the undefined `f(s) = e_f ≥ c` case. |
| SIMP3-5 | **Accepted**. (a) and (c) are resolved by SIMP3-1: an unknown member gets a real entry from `pks`, and no re-delivery channel is ever needed (§11.2). (b) no longer arises for continuing members (a commit looks nobody up, §6.3 step 2); for handle resolution and `D.by` lookups the transient-failure rule of ADV3-9 applies (§10.6). |
| ADV3-3 | **Accepted, with a smaller rule than proposed.** Two corrections to the finding: v1 refused sends only while a claim's batch was incomplete; once a never-delivered freeze was declared (`expireClaims` clears `ep.claim`), v1 let the frozen members keep writing to the old epoch, readable by the members that claim removed. Stage 1 now (1) probes the control lane before every send, as v1's `syncNow` did (§11.3 step 1); (2) drops the 30-s "send in e" fallback altogether: a pending claim makes a send wait up to 30 s and then fail with v1's "the conversation is changing membership; try again in a moment" (§6.6, §11.3 step 2), which is simpler than refusing only for `rm ≠ 0`; (3) refuses texts and images in a frozen epoch whose claim removed a member who had not left, with "a removed member could still read this conversation; start a new conversation" (§6.6 step 6, §11.3 step 2), stricter than v1 and listed in §13.2 item 14 and §13.3. Trace (b) cannot occur any more: with SIMP3-1 no member is frozen while others move on, so §6.8's "live, restored and frozen views agree" holds (§6.8 restated). §0.3(6) no longer says "exactly as in v1". The failed-echo retry re-runs steps 1–2 (§11.3). Plan M7 tests 9, 12, 21. |
| ADV3-1 | **Accepted, resolved by SIMP3-1**: a partial freeze no longer exists, so there is nothing to re-deliver and no rank. |
| ADV3-2 | **Accepted, resolved by SIMP3-1** (no NEED_KEY) and by ADV3-4's followed-lane rule: a member never stays in an older epoch than the others, so the first-epoch-of-run assumption is gone. |
| ADV3-4 | **Accepted.** Followers keep the lane of epoch c−1 of every member silent in c (the round-1 rule, restored), at most one per member (§11.2, §7.2 HEADS `ef = e − 1`, §7.4 DESC for c and c−1, §11.4). With the probe before every send and no 30-s fallback (ADV3-3), an honest row lands in an epoch the others left only in the one-RTT race, which this lane covers; the Sweeping paragraph now states the only remaining gap (a member's own devices racing a claim) correctly. Plan M7 test 22 (replacing the RC-3 lurker test). |
| ADV3-5 | **Accepted.** The never-delivered warning names the signer: "@by's membership change was never delivered to you; the members of this conversation can no longer change" (§6.6 step 4). With SIMP3-1 a freeze is permanent again, so "can no longer change" is accurate, and every member's warning names the signer. Plan §0.3 strings, Q9, §3 row 30. |
| ADV3-6 | **Accepted in part.** The chained-join override is moot (chained joins are deleted). The skip variant is real: restore now lets a skip EPOCH record (flag bit1) for a later epoch override a re-derived removal, without a new warning (§11.4 step 5). Plan M7 test 16 variant. |
| ADV3-8 | **Accepted (statement).** Re-delivery no longer depends on the inbox (SIMP3-1). The sustained refill-every-day attack still delays first contacts and adds of members without a qualifying 1:1; §13.2 item 11 and §0.4 now say "for as long as it keeps refilling the cap", with the PoW cost. A cap-free path was not added: it would be a new mechanism for a delay that §0.4 already lists. |
| ADV3-9 | **Accepted.** A commit never looks a continuing member up (SIMP3-1, §6.3 step 2), so a directory failure cannot produce a wrong entry. §10.6 adds the transient-failure rule: only a complete answer without the user means "no such user"; a network error, timeout, 429, 5xx or an incomplete page sequence retries or fails the operation, and parks a join that needs it. Plan M6 test 5, M7 test 27. |
| LIVE3-1 | **Accepted in parts.** (1) c−1 followed lanes (as ADV3-4). (2) The control-lane probe before every send (§11.3 step 1). (3) Not adopted: the post-put re-probe and re-send is unnecessary once (1) and (2) hold. (4) Scrollback first probes past the swept head of an older epoch's lane (§11.10). (5) The remaining gap is restated in §11.2: only a member's own devices racing a claim; a two-epoch lag cannot happen, because a sender no longer writes into an epoch with a pending claim. |
| LIVE3-2 | **Accepted** (client-only, no wire change). The inbox cursor never leaves era E before a read of E with `more = 0` issued at estimated server time ≥ `end(E) + (2·SKEW + 2·Δin)·1000`; until then each poll re-reads E from its last `closed` and later eras from 0 (§11.5 step 3). Plan: FakeWorld `inboxJitter` and `inboxLagMs` (§2.1, M5), inbox-do test, M6 test 9(b). |
| LIVE3-3 | **Accepted.** §6.7 step 1: a network error, timeout, 429 or 5xx on the blob GET or `blob/meta`, or a blob 404 with a registered id, parks the join; only a hash, size or header mismatch, or an absent blob with `meta` MISS, drops it. A transient `D.by` lookup failure parks it too (§6.7 step 5). The parked join holds the inbox cursor or, for a WELCOME, the lane's processed position (§6.7 step 4, §7.3). Plan M6 test 9(c), M7 test 16. |
| LIVE3-4 | **Accepted, fix (1) in a simpler form.** A leaver keeps processing WELCOME rows of the copy (and nothing else) until a final winner drops it, then sweeps once more (§6.9), which covers both orders of WELCOME and LEAVE. Fix (2), a post-put probe by the sender, was not adopted: (1) alone closes both orders. §6.12 step 1 updated. Plan M7 test 25. |
| LIVE3-5 | **Accepted, resolved by SIMP3-1** (no ranks). |
| LIVE3-6 | **Accepted, resolved by SIMP3-1** (no NEED_KEY, no DELIVERED hold-back, no re-delivery to expire). |
| LIVE3-7 | **Accepted.** (1) A writer never picks a slot below its lane head's era: `max(E_now, head era)` (§7.3, §11.3 step 4). (2) Readers keep the slot after the previous era's dense prefix in the expected-label map until it is `MISS(sealed = 1)`, the self lane included (§11.2). (3) No recorded position (HEADS, processed position, snapshot `(Eh, nh)`) lies in an era before the previous era's prefix end was observed sealed (§7.2, §7.4). §11.7 restated. Plan M6 test 3. |
| LIVE3-8 | **Accepted, as ADV3-6** (skip override in §11.4; chained override moot). |
| LIVE3-9 | **Accepted.** The LEAVE row is put first; the LEAVE record is written only after OK (or a probe finding our body); any device that applies its own account's LEAVE row without a record writes it (§6.9). A record therefore never exists without its row. Plan M7 test 26. |
| LIVE3-10 | **Accepted, resolved by SIMP3-1** (re-delivery DELIVERED records deleted). |
| LIVE3-11 | **Accepted, resolved by SIMP3-1** (no re-delivery; unknown members get real entries). |
| LIVE3-12 | **Accepted, resolved by SIMP3-1** (no automatic NEED_KEY or KEY_OK; a freeze posts nothing). |
| LIVE3-13 | **Accepted.** §6.12 step 4: 409 `wrong era` rebuilds the invites for the returned era (fresh `eid`, new AAD) and retries, waiting as §11.3 step 6 when that era was already tried; only an OK or an idempotent same-body result counts as delivered. Plan M6 test 7 variant, FakeWorld `wrongEraOnce`. |
| LIVE3-14 | **Accepted, the no-wire-change option.** §6.7 step 1 calls `blob/meta` (for `E_start`); §6.4(f) and §11.4 step 5 say where `E_start` comes from and that a reader without it makes one `meta` call (undecided until then); the restore cost lists up to two `meta` requests per changed epoch. An `Estart` field in CONV_JOIN/EPOCH/DESC was not added, to keep the §7.2 records stable. |
| LIVE3-15 | **Accepted.** Snapshots drop an EPOCH_PENDING whose uids are all covered (or that is dead) together with its DELIVERED records (§7.4). Plan M6 test 17. |
| CONS3-1 | **Accepted, option A, simplified.** After every recipient's first attempt the device writes **one** self row with the DELIVERED record (`a = 0` if none succeeded or there are no recipients), and every row carrying DELIVERED is padded like EPOCH_PENDING, so every creation and commit ends with exactly one class-1 self row (§3.2, §6.1, §6.3 step 10, §6.12 step 3, §7.1, §7.2, §13.1, A15, Appendix B). Plan M1 test 6, §3 row 48 with 9 and 31 recipients. |
| CONS3-2 | **Accepted, resolved by SIMP3-1** (no re-delivery, so no copy bound to state). |
| CONS3-3 | **Accepted.** §7.3: one poll's joins go in as few cls-3 rows as fit (5 REQUESTs of a 32-member group per row), the cursor's HEADS only in the last row after every earlier one is CAS OK, and a REQUEST the 64-limit would drop at once is not written. Plan §3 row 46 (≤ 13 rows). |
| CONS3-4 | **Accepted.** A request is probed with at most `2·members + 3` keys: 2 control slots, control `(E_now, 0)` when later (§6.5), and per lane the slot after the head plus `(E_now, 0)` when later (§11.5); the bound is restated in §11.4 and §11.5. Plan §3 row 46, M6 test 10, T7 with an era variant. |
| CONS3-5 | **Accepted, resolved by SIMP3-1** (unknown members get real entries; no re-delivery to them). |
| CONS3-6 | **Accepted.** A failed `D.by` key check (first contact, skip, separate copy) drops the join with the noise warning "ignored a conversation key with an invalid signature" and creates nothing (§6.7 steps 5–6). Plan M7 test 16. |
| CONS3-7 | **Accepted.** HEADS entries are `68 + 6m + 12f` B (§7.2). Plan M1 KAT of a HEADS record. |
| CONS3-8 | **Accepted.** Tests added: creator sends queued until the decoy (M6 test 5); thin-bucket warning, socket and topic limits, the post-1008/1013 back-off and the post-SUB probe (M6 test 16); the CONFIRMED fold rule (M6 test 17); the 410 cursor move (M6 test 9(a)); repeated WRONG_ERA wait (M6 test 3); inbox early acceptance and ended-era alarms (M2 inbox-do and shard-do); an M4 inbox row and an `/era/{E}` row; a WELCOME found by scrollback (M6 test 12). The RC-8 items are deleted with SIMP3-1. |
| CONS3-9 | **Accepted.** The anonymity set is "about 64–128 accounts (all accounts below 64 users)" in §2.5 and §13.2 item 10. |
| CONS3-10 | **Accepted, resolved by deletion**: KEY_OK and its cross-reference are gone (§3.3). |
| CONS3-11 | **Accepted, by restating the bounds** (no InboxDO change): an era holds at most 16 000 rows (~22.7 MB), 4 eras 64 000 (~90.6 MB) (§9.3, §13.2 item 11; plan T2(a), risk 6). Counting the early window under the era's first day would have changed M2 for a bound that only needs to be stated. |
| CONS3-12 | **Accepted.** The migration inserts `('users', 0)` into `dirmeta` (§9.6). Plan §0.5 and the M3 test. |
| CONS3-13 | **Accepted.** The `101` upgrade of `/api/v2/rt` is exempt from `x-segv-now`; HELLO carries the time (§10.1). Plan M4 route table and server-time test, M5 harness. |
| CONS3-14 | **Accepted, resolved by SIMP3-1** (re-delivery DELIVERED records no longer exist). |
| CONS3-15 | **Accepted.** §9.4 and A20 state that eviction of the hibernated RealtimeDO resets the ring and `boot`, so the 10-minute window is an upper bound and low-traffic RESUMEs mostly get GAP (a catch-up, never a lost row). |
| CONS3-16 | **Accepted.** The v2 audit replaces the `/api/log` audit in M8 (plan §0.5, M8). |
| CONS3-17 | **Accepted.** Plan §0.3 lists every new string (§11.1 fatal, §11.3 refusal, §12.1–§12.5, the named frozen warnings) and the reused v1 strings. |
| CONS3-18 | **Accepted.** SNAP pointer rows carry NONE / `ZERO16` and are not part of the `Lself` prev chain (§7.1, §7.4). |

## Appendix C - Review changelog (round 4)

Round 4 verified the round-3 changes again, mainly SIMP3-1 (keys in D, derived entries), ADV3-3/ADV3-4/LIVE3-1 (the
probe before every send and the c−1 followed lanes) and LIVE3-3 (parked joins). Every finding was checked against
this spec, DD and the v1 code (`src/client/engine.ts`, `src/lib/proto.ts` `makeInvite`, `src/server/http.ts`
`finalize`); every trace was reproduced on the text before the change. All 16 findings were accepted; three pairs are
duplicates and share one change. No validity rule (§6.4–§6.6) changed meaning except that a decryption or parse
failure of D′ is now named as D′-invalid. Wire formats of §1–§4 and §8–§10 are unchanged; the one codec change is the
MEMBER self record (§7.2). Where a finding offered alternatives, the entry names the one taken and why.

| id | decision and change |
| --- | --- |
| READV4-1 | **Accepted** (critical). Trace confirmed: the unknown-member rule (§5.1, §7.3, §11.2) compared only `sigPk`, and MEMBER had no `kh`, so a creator or committer could list a real user's uid and `sigPk` with the `kh` of a key it holds; every member showed the slot under the real handle while every later entry was sealed to the attacker's key, also after the attacker's removal. Before SIMP3-1 entries went to the directory key, so the hole is new in round 3. Change: a member is unknown (`?…`, "the public keys of @x changed") when its directory bundle's `sigPk` or the hash of its `kemPk` differs from D (§5.1, §6.7 step 2, §11.2); MEMBER (0x0D) gains `kh[32]` and is `113 + hlen` B (§7.2); a MEMBER is written only when both keys match, and a disagreeing member is looked up again at the next restore (§6.7 step 6, §7.3, §11.4 cost, §11.5); §13.2 item 3 and Appendix B restated. Validity is unchanged. Plan: M1 codec and MEMBER KAT, M6 test 13 (alice's view), new M7 test 28, §0.3 `MemberView.handle`, §2.3 `keyOf`. |
| RECONS4-1 | **Accepted**, same change as READV4-1. |
| READV4-2 | **Accepted.** Traces confirmed: §11.3 set no bound between the step-1 probe and the put (proof of work at a base of up to 26 bits, retries through step 4, WRONG_ERA waits, frozen tabs), step 1 probed only `(E_now, 0)` and not every era of §6.5, a failed probe was unspecified, and the failed-echo retry counted a HIT in an epoch the copy had left as success. Changes: step 1 probes as §6.5 and a failed probe fails the send with nothing put (§11.3 step 1, §6.12 step 4); **fresh probe** (§11.3 step 6): right before each put attempt, after its proof of work, steps 1–2 run again when the answer to the latest probe is more than `(Δ + SKEW)/2` s old by the monotonic clock or the estimated server time, and the row is rebuilt when the epoch changed; **late rows** (new §11.3 step 8): a put answered `Δ + SKEW` or more after its probe was sent, or a failed-echo body found after the copy left its epoch, counts as delivered only if the copy is still in its epoch, or one epoch later with no row of self there; otherwise a TEXT or IMAGE echo fails ("not delivered"), a LEAVE is put again, and a WELCOME's uid stays pending. §11.2 "Why one epoch back is enough" restates the bound: an honest second claim is stored at least Δ + SKEW after the probe. §13.2 item 6 updated. Found while verifying: a malicious member who registers the next bundle in advance can make two claims final within one RTT of an honest put. It and the existing own-device race are now listed as §13.2 item 15 (a row only scrollback finds), with the closing option (the step-8 check after every put) in §14 and plan Q11. Not adopted: re-running step 1 after every return to step 4 regardless of time (the time bound covers it). Plan: M6 `send.ts`, M7 tests 12, 21 and 22 (d)–(f), risk 3, Q11. |
| RECONS4-2 | **Accepted**, same change as READV4-2. The bound is `(Δ + SKEW)/2` rather than a fixed 5 s, so it scales with the test parameters (Δ = 1, SKEW = 0). |
| READV4-3 | **Accepted.** §6.7 step 1 now checks `J.bundleSize ∈ {23456, 81248}`, then a `meta` HIT with that size, and only then fetches the blob, aborting a response whose Content-Length differs; a `meta` MISS drops the join (registered blobs always have their object, §8.2). §6.4 evaluates (g) before (h), so a claim naming a large blob costs no download either. §11.5 bounds a spam join at one `meta` and at most one 81 248-byte fetch. Plan: M6 `conv.ts` and test 10 size variant, M7 test 12. |
| READV4-4 | **Accepted.** §6.4 Outcomes: a 429 is undecided, retried no sooner than its `retry-after`. Plan: M7 `claims.ts`, test 12 variant. |
| READV4-5 | **Accepted, option 1**, with RECONS4-9. §7.3 durability order: while a J found on a lane of epoch e′ of a copy is parked, every HEADS entry written for that copy (self row or snapshot) describes e′, or e′ + 1 with that lane among its followed lanes, and holds that lane's position before the J; §6.7 step 4 refers to it. Not adopted: parking only inbox joins (a WELCOME hit by a transient failure would be lost) and a new self record for parked joins (a codec change). Restore then re-processes from e′ (§11.4), which the §0.3(7) cost already allows ("activity since the account last recorded its processed positions"). Plan: M6 `selflane.ts`, M7 test 23 parked variant. |
| RECONS4-9 | **Accepted**, same change as READV4-5. |
| RECONS4-3 | **Accepted.** §11.4 "Lanes": for the HEADS epoch the followed lanes are exactly those its HEADS entry lists, from their recorded positions; every other member of `D_c ∩ D_{c−1}` counts as having a valid row in c, as it had for the writer. §7.2: the followed-lane list is complete; an entry with another `ef` is ignored (the "processed from its start" clause, which made restore cost depend on history, is removed). §11.2 points to it. Plan: M6 `restore.ts`, new M7 test 29. |
| RECONS4-4 | **Accepted.** §6.6 step 4: the first D′ check is that `descCt` and `pkCt` open under `dk_{e+1}(EK')` and `D' ‖ dsig'` unpads and parses; a failure is D′-invalid, never an unprocessed claim. §6.10 row restated. Plan: M1 test 10 (`openDesc` / `openPks` throw), M7 `claims.ts`. |
| RECONS4-5 | **Accepted.** §2, §5.1, §5.5 step 1 and §10.6 "When clients look up" name the lookup of a link owner by uid; §2 states that the directory's `sigPk` is used only for the `D.by` key check of first-contact and skip joins. Appendix B. |
| RECONS4-6 | **Accepted.** Appendix B and the round-3 SIMP3-1 entry write `kh = H(enc("segv.sh/v2/kh", kemPk))`, as §5.1 defines it. |
| RECONS4-7 | **Accepted.** §11.2: a copy that does not hold c−1 (its root epoch is c, or it reached c by a skip) follows no lane. Plan: M6 `conv.ts`, M7 test 29 variant. |
| RECONS4-8 | **Accepted.** §11.10: for an epoch this session never swept (before the HEADS epoch of the restore), scrollback starts after the lane's cut in the winning claim that ended that epoch, then gallops. Plan: M6 `history.ts` and test 12. |
| RECONS4-10 | **Accepted.** §9.7 exempts the `101` upgrade from HSTS, `nosniff` and `no-referrer` (its headers are immutable; v1's `finalize` returns it untouched); §10.1 "Hardening" refers to the exemption. Plan: M4 route table and server-time test. |
| RECONS4-11 | **Accepted.** The described state cannot arise (§7.3 never records a position past an unprocessed join, and a lost HEADS makes restore start earlier). Plan M6 test 12's variant is rewritten to a reachable gap: a WELCOME that alice's second device writes into an old epoch after bob swept it (the own-device race), found by scrollback live and after a reload (RECONS4-8); it lands with M7's claims. |

## Appendix C - Review changelog (round 5)

Round 5 verified the round-4 changes (mainly the fresh probe and late rows of §11.3, MEMBER with `kh`, the D′ parse
check and scrollback after a reload) and §5–§7 and §11 again. Every finding was checked against this spec, DD and the
v1 code (`src/lib/proto.ts` `validName` and `parseDescriptor`, `docs/PROTOCOL.md` §3.1 and §3.3, all as at commit
3de5f5e); every trace was reproduced on the text before the change. All six findings were accepted; none overlaps
another, but READV5-1 and READV5-3 share one edit (the fresh probe of §11.3 step 6 now re-runs steps 1–3, and step 2
holds the WELCOME check). No e-validity or D′ rule changed meaning; the one change to what M1 implements is that
`parseD` no longer applies `validName` (READV5-2). Wire formats of §1–§4 and §8–§10, and every record layout, are
unchanged.

| id | decision and change |
| --- | --- |
| READV5-1 | **Accepted** (critical). Trace confirmed: §6.12 step 1 qualified the 1:1 once, when the channel was chosen, and §11.3 could then move the send into a later epoch of the carrier (step 1's repeat, the step-2 wait, the fresh probe of step 6) without checking again, so a WELCOME carrying J of G could be built under `mk_{c+1}` of an epoch that a non-member of G holds. Change: §11.3 step 2 gains a refusal: a WELCOME whose current epoch (the one the row would be built in) does not meet every condition of §6.12 step 1 puts nothing, and the recipient gets an inbox invite instead. Step 2 runs after every control probe (step 1, the fresh probe of step 6, and the late-row check of step 8, which never rebuilds a WELCOME), so a WELCOME is never written in an epoch that lists anyone but self and its recipient. §5.2, §6.12 steps 1–2 and A32 point to it. The finding's "evaluate after the probe" option is what step 2 does; binding the row to the qualifying epoch number was not needed, since a later epoch that still qualifies (a rotation of the same two members in which R has posted) is safe. Plan: M6 `deliver.ts` and `send.ts`, new M7 test 30 (`dropPublish` on C1; `beforePut` holding the WELCOME across C1), Q5. |
| READV5-2 | **Accepted, the finding's first option.** Trace confirmed: since RECONS4-4 a D′ parse failure is D′-invalid, and the parse applied `validName`, whose `\p{…}` classes, `trim` and NFKC follow the Unicode version of the browser, so one rename could freeze some members and move others to e+1. v1 had the same latent dependency (`parseDescriptor` throws "descriptor: bad name"). Change: §5.1 parses the name only as `nlen ≤ 256` and valid UTF-8 of 1–64 code points (both deterministic); `validName` becomes a build rule (§6.1 step 2, §6.3 step 2 for a new name; a carried-over name is copied byte for byte, so a committer on an older engine never fails a rotation) and a display rule (a name that fails the reader's `validName` is shown as absent, and §11.9's rename lines compare displayed names). No descriptor, join, D′ check or self record depends on Unicode tables (§5.1, §6.6 step 4, §6.10). §13.3 and Appendix B state the change from v1, which rejected such descriptors. The frozen code-point table was not adopted: it adds a large table to proto.ts for no security gain, because the spoofing defence lives in the display. Plan: M1 descriptor row and test 10, new M6 test 18, risk 3. |
| READV5-3 | **Accepted.** Trace confirmed: the fresh probe went from steps 1–2 straight to step 4, so a TEXT could be built in an epoch that lists a leaver the sender already knew of, without the rotation §6.9 requires; the failed-echo retry skipped step 3 too. Change: the fresh probe of §11.3 step 6 runs steps 1–3 again (the rotation of step 3 then restarts the send at step 1 as usual), and "Retry of a failed echo" runs steps 1–3 first. The step-8 path builds no row itself (a TEXT's retry is the failed-echo retry; a LEAVE needs no rotation). Plan: M6 `send.ts`, M7 test 22 (g). |
| READV5-4 | **Accepted, in a form that also covers a reload.** Trace confirmed: a late LEAVE answers OK, so §6.9 writes the LEAVE record and step 2's "you left" refusal then blocks the re-put that step 8 requires. Change: §6.9 gains **Repeating a LEAVE**: whenever a leaver's copy is in an epoch c that still lists self (not removed or dropped) and the latest LEAVE record names an epoch `e_L < c − 1`, or `e_L = c − 1` while self has a valid row in c (the step-8 condition, evaluated on state, not on timing), a device puts a LEAVE in c again, running §11.3 steps 1 and 2 without the "you left" refusal, then steps 4–8, and writing its own record. Devices check it after every catch-up and restore (§11.4 step 5, §11.6) and in step 8, so a session that ends between the late answer and the repeat is repaired by the next one. The record of the late row stays (its row exists). §6.9 also says that the leaver follows the control lane of its current epoch (a claim that keeps it moves it on). A duplicate LEAVE is harmless. Plan: M6 `conv.ts` and `send.ts`, M7 test 22 (e) and its reload variant. |
| READV5-5 | **Accepted, with a tighter bound than proposed.** Trace confirmed: a row that lands after the sweep goes to `max(E_now, head era)`, so it can be at `(E′, 0)` of a later era, which scrollback never probed. Change: §11.10 also probes slot 0 of every era after the swept head's (or the cut's) era up to the era after that of the claim C that ended the epoch (at most `E_now`), galloping on hits. A row its sender counts as delivered was answered less than `Δ + SKEW` after a control probe that did not see C, so it cannot lie later than that; a later (late) row is re-checked by its sender (§11.3 step 8). This costs one key per idle era, as a live lane does, instead of one per era up to `E_now`. §13.2 item 15 points to it. Plan: M6 `history.ts`, test 12 era-crossing variant. |
| READV5-6 | **Accepted.** Trace confirmed: after READV4-1 a member whose directory keys disagree with D got no MEMBER and was looked up again at every restore, forever (keys never change in stage 1), and §7.3 contradicted §11.5 for a request's `D.by`. Change: a MEMBER is written from every verified directory bundle, whatever D lists (the TOFU pin of the directory's keys, like CONTACT), and unknown members are decided by comparing D with it, without a lookup; only a uid with no verified bundle is looked up again. A request's `D.by` always has a bundle (its key check needs one), so requests make no lookup at restore (§2, §6.7 step 6, §7.3, §11.2, §11.4 cost, §11.5, §13.2 items 3 and 10). Display and validity are unchanged; a directory substitution made at the first lookup now keeps being reported instead of healing silently, as with CONTACT pins (§13.2 item 3). The MEMBER layout is unchanged. Plan: M6 `conv.ts`, tests 10 and 13. |

## Appendix C - Review changelog (round 6)

Round 6 verified the round-5 changes (the WELCOME re-check, names outside validity, the repeated LEAVE, scrollback
across eras, MEMBER pins) and checked the delta against the M0–M5 code at commit 3de5f5e (`src/lib/proto2.ts`,
`src/server/v2/*`, `test/engine2/*`). Every finding was checked against this spec, DD and that code; every trace was
reproduced on the text before the change. All 20 findings were accepted; READV6-5, RECONS6-11 and RECONS6-12 are
duplicates of implementation questions (Appendix D: 19 and 18) and share their change, and RECONS6-3 shares the change
of question 58. Where a finding offered alternatives, the entry names the one taken and why. The same round answered
the 67 implementation questions of M0–M5 (Appendix D). No wire format of §1–§10 changed. The validity rules that
changed are the pinned signature rule (§1.1: keys in the prime-order subgroup, the cofactored equation) and, as named
parse rules, what the code already enforced (§3.3, §7.1).

| id | decision and change |
| --- | --- |
| READV6-1 | **Accepted** (high). Trace confirmed: the repeat rule of §6.9 looked only at the latest LEAVE record, so a leaver who was dropped and then re-added by a skip join put a new LEAVE right after every re-add, and step 2's "you left" refused its sends; the other members also recorded the old leave in the re-added epochs ("every later epoch they hold whose members still include the leaver"). Change (§6.9, §6.7 step 5, §11.2, §11.4 step 5): a copy's leave is *current* until a skip re-add (an EPOCH record with flag bit1 above the latest LEAVE record's epoch) ends it; `left` is set only while it is current, and the skip clears it, live and at restore; the repeat applies only to a current leave; receivers record a leave only in the consecutive epochs that still list the leaver. Both are derived from durable records, so no new record is needed. Plan: M6 `conv.ts`, M7 test 22 (e) re-add variant, new M7 test 32, §3 row 34 note. |
| READV6-2 | **Accepted** (high), the finding's first option. Trace confirmed: no record holds another member's leave, but HEADS lane positions could pass its LEAVE row, so a reload forgot the leave and the next text went to an epoch the leaver can read without the rotation §6.9 requires. Change: §7.3 durability: no HEADS entry for epoch e records a lane position (followed lanes included) past the LEAVE row of another member that `D_e` still lists, so a restore re-reads and applies that row (one row per leaver until a rotation drops it); §7.2 HEADS positions, §11.4 step 5 and its cost restated. §11.10: scrollback applies a LEAVE whenever the local state lacks it. The left mask in HEADS was not adopted: it changes the M1 record layout. Plan: M6 `selflane.ts`, new M7 test 31. |
| READV6-3 | **Accepted** (high). Trace confirmed: for an epoch this session never swept, scrollback started after the cut of the claim that ended the epoch, which the committer chooses freely (§6.4(f) bounds only its era), so one claim could hide every earlier row of a lane after a reload, or make the backward walk unbounded. Change (§11.10, §11.4 step 6): the cuts are never a starting point; for an unswept epoch the client probes slot 0 of every era from `E_start(e)` to the era after the ending claim's (at most `E_now`) and gallops on hits to each era's dense-prefix end. This replaces the RECONS4-8 cut start and folds READV5-5's extra probes into one rule; the cost is one key per idle era, as before. Plan: M6 `history.ts`, test 12 (reload variant restated, new inflated-cut variant). |
| READV6-4 | **Accepted**, with a smaller rule than proposed. Trace confirmed: §11.3 steps 4–8 did not say which epoch they build in after the copy switched through §11.6 or a catch-up during a send (a sibling CONFLICT returning to step 4), so a WELCOME could be built under `mk_{c+1}` without the step-2 check. Change: step 2 names the send's epoch e (the epoch it last checked); steps 4–8 always use e, and the fresh probe of step 6 also runs steps 1–3 again when the copy is no longer in e, so only that re-run can set a new e. Binding to e alone, without the re-run, would let a TEXT go into an epoch the sender already knows a claim has ended. Plan: M6 `send.ts`, M7 test 30 (c). |
| READV6-5 | **Accepted**, merged with question 19. §1.2 `utf8`: decoders MUST NOT strip a leading U+FEFF, and code points are counted with it; §5.1 points to it. Plan M1 test 10 (a 64-code-point name after a BOM is rejected; a lone BOM is a 1-code-point name). |
| RECONS6-1 | **Accepted** (high). Confirmed at HEAD: `checkJoinBundle` (§6.7 steps 1–2) opens no `pkCt`, runs no `pks` check and compares only self's `sigPk`; adding `kh` to `Member` would not break its compilation, so the missing `kh` check would survive. Change: delta M1 item 8 (open `pkCt`, `checkPks`, self's `kh`, failure kinds, tests) and a pointer from delta M6 item 3. Spec unchanged (§6.7 step 2 already requires it). |
| RECONS6-2 | **Accepted.** Confirmed at HEAD: `processClaim` still returns `excluded` and `withheld` and opens only `descCt` inside its `try`. Change: delta M1 item 9 (outcomes removed / `nokey` / `invalid` / accept; `openDesc` and `openPks` in one `try` mapped to D′-invalid; the extended `dPrimeChecks`; tests rewritten). Spec unchanged. |
| RECONS6-3 | **Accepted, the code's rule** (same change as question 58). The M2 InboxDO and the FakeWorld count a post of the SKEW early window against the era's first day, not the previous day as CONS3-11 assumed. §9.3 states `d = max(⌊sec(now)/86400⌋, 7·E)` and the bounds go back to 14 000 rows (~19.8 MB) per era and 56 000 (~79.3 MB) for 4 eras; §13.2 item 11, plan T2(a) and risk 6 follow. CONS3-11 is superseded. Delta M2: no code change. |
| RECONS6-4 | **Accepted**, the finding's first option. Plan M7 test 30 (b) is rewritten on the pattern of test 22 (d): alice's engine clock advances by more than `(Δ + SKEW)/2` between her step-1 probe and sending the put, while C1 becomes final, so the fresh probe finds c+1, nothing is put and bob gets an inbox invite; the held-put case becomes the control (the WELCOME lands in c, is late, counts as delivered, and bob holds G through his followed lane of c). Delta M7 item 7 restated. |
| RECONS6-5 | **Accepted**, the second option (keep "@bob"). Plan M6 test 18: the rename from "@bob" to U+202E + "evil" shows no rename line, only "@mallory rotated the conversation keys" (both names display as absent, §11.9); a later rename to "team" shows "renamed the conversation to “team”", and a rename back to U+202E + "evil" shows "removed the conversation name". Delta M6 item 16 restated. |
| RECONS6-6 | **Accepted.** Trace confirmed: §6.12 step 1 did not exclude a 1:1 that self left or was removed from, and §11.3 step 2 then refused the WELCOME as "you left" or "you are no longer a member" with no fallback. Change: §6.12 step 1 adds "self has not left this copy and was not removed from it"; §11.3 step 2's removed and left refusals do not apply to a WELCOME, whose check sends an inbox invite instead; §6.12 step 4 says every other WELCOME refusal gives an inbox invite. Plan: M6 `deliver.ts` and `send.ts`. |
| RECONS6-7 | **Accepted.** Confirmed: the FakeWorld's blob GET carries no Content-Length (the Worker sets it). Change: §6.7 step 1 says a present Content-Length other than `J.bundleSize` is a size mismatch, and without one the client reads at most `J.bundleSize + 1` bytes; delta M5: the fake sets `content-length`. Plan §2.1 `blobs` row. |
| RECONS6-8 | **Accepted, the simplest option.** At restore the condition "self has a valid row in c" was not decidable. Change (§6.9): the repeat no longer tests it; a current leave whose latest LEAVE record names `e_L < c` is repeated in c. An unneeded repeat costs one row, and a LEAVE of a member already recorded as left changes nothing. This deletes a condition instead of adding a restore rule. |
| RECONS6-9 | **Accepted.** §11.4 step 5: "the freeze itself posts nothing (LEAVEs that §6.9 repeats are still put)"; §6.9 says the repeat applies in a frozen copy too. Delta M6 item 11. |
| RECONS6-10 | **Accepted.** §6.7 step 6: only an accepted join or a created request writes the MEMBER of `D.by`; a dropped join writes nothing (as §7.3 already said). Delta M6 item 3. |
| RECONS6-11 | **Accepted**, merged with question 19 and READV6-5: delta M1 item 1 now says to count code points with the existing `strictUtf8` (`ignoreBOM: true`); a BOM is a code point. |
| RECONS6-12 | **Accepted**, merged with question 18: delta M1 item 5 says "no codec change; add the HEADS KAT". |
| RECONS6-13 | **Accepted.** Delta M5 and plan §2.1 say posts are accepted until `end(E)` and `ended` holds from `end(E) + SKEW`, as §9.3 and the fake already do. |
| RECONS6-14 | **Accepted.** Delta M1 item 3 and the plan M1 table name the target signature `dPrimeChecks({D, dsig, kc, pks, EK}, De, {from, hD, rm}, bundle)`; `parseD` stays inside it (a failure returns `"desc"`), and the caller (`processClaim`) maps every throw of `openDesc` / `openPks` to D′-invalid. |
| RECONS6-15 | **Accepted**, the first option. §6.6 step 4: for a kept member the `sealDet` recomputation performs the `kemPk` encapsulation check, and whether an X-Wing encapsulation succeeds does not depend on its randomness (§2.1), so a checker MAY skip the separate one; an epoch change costs at most 32 encapsulations (§11.4 cost). |

## Appendix C - Review changelog (round 7)

Round 7 verified the round-6 changes and answers against this spec, DD and the code at commit 8092e98 (which replaced
v1 in place: `src/lib/proto.ts`, `src/server/*`, `test/engine/*`, `test/worker/*`). Every trace was checked on the text
before the change. All 13 findings were accepted; VQA-4 and VADV-5 are one hole and share VADV-5's change, and VADV-1
and VADV-2 share the LEFT record. Where a finding offered alternatives, the entry names the one taken and why. The only
wire addition is the self record LEFT (0x0E), which current parsers skip as unknown. Answers 4, 11, 24, 41, 43, 62, 63
and 67 changed (Appendix D).

| id | decision and change |
| --- | --- |
| VQA-1 | **Accepted** (high). Trace confirmed: round 6 anchored the server-time estimate on the monotonic clock only, so §11.3 steps 6 and 8 read one clock twice; a browser's `performance.now()` commonly stops while the system sleeps, and nothing replaced a stale minimum-`rtt` sample or broke `rtt` ties. Change: §11.3 steps 6 and 8 also measure elapsed time by the wall clock (`Date.now()`); a wall clock that steps back counts as no time. §10.1: a new sample discards every older sample whose estimate disagrees with it by more than `(rtt_old + rtt_new)/2 + SKEW + 1 s` (SHOULD), and equal `rtt` prefers the newest; the estimate itself never reads the wall clock (which can be set). §3.1 names the uses of the estimate. The finding's per-sample wall time and "divergence" rule were not adopted: the disagreement test compares against the server itself and needs no extra state. Answer 62 changed. Plan: M6 `api.ts` and `send.ts`, M6 test 15 variant, M7 test 22 (h) (monotonic clock paused for 2 h). |
| VQA-2 | **Accepted**, the first option. Confirmed: `ShardDO.delta()` uses its pin silently, while BlobRegDO and InboxDO log. §3.1: a pinned object MUST keep its pin and SHOULD log the mismatch once per instance, the ShardDO included. Delta M2: `ShardDO.delta()` logs once, as `BlobRegDO.delta()` does. Answer 41 changed. |
| VQA-3 | **Accepted**, the first option (the code follows §9). Confirmed: `InboxDO.alarm()` re-arms at `sealAt()`, which can be under 1 s away; an alarm fired a few ms early would then fire again at once until the clocks agree. §9 is unchanged. Delta M2: `setAlarm(Math.max(this.sealAt(), now + 1000))`. Answer 43 changed. |
| VQA-4 | **Accepted**, merged with VADV-5 (the same hole). The finding's fix (fail the lookup as transient) was not adopted: it blocks lookups for as long as an isolate reports 0, while VADV-5's bound is always safe. |
| VQA-5 | **Accepted**, the second option. §7.2: for a copy that does not hold e−1, every followed-lane entry of a HEADS entry is ignored and the ℓ checks do not apply; the rest of the entry is used. This matches "ignored one at a time" for a wrong `ef`, and an honest writer never writes such lanes. Answer 24 changed. |
| VQA-6 | **Accepted.** Confirmed: HEAD is 8092e98, which merged `proto2.ts` into `proto.ts`, moved `src/server/v2/*`, `test/engine2` and `test/worker/v2`, and deleted v1. `answers.md` and the delta name the current files (the line numbers in `proto-conv.test.ts` are unchanged), answer 16 drops "while v1 exists", delta M9 keeps only what is left (docs, e2e, the greps), and plan §0.1 and M9 say so. |
| VQA-7 | **Accepted.** The delta summary lists every M0–M5 code change, including Q27's SHOULD, and the answers' M6/M7 list includes Q1 and Q5. Both summaries were rewritten for round 7. |
| VQA-8 | **Accepted.** §11.10: "The backward walk above (probing `(E, n−32..n−1)` and the earlier eras) then starts from the heads found." Text only. |
| VADV-1 | **Accepted** (high), the finding's first option. Trace confirmed: READV6-2's position pin covered only a LEAVE row in the HEADS epoch or in a followed lane of the previous one, so two claims that kept the leaver after its row put the row out of every HEADS position, and a reload forgot the leave. Change: new self record LEFT `{conv, root, e, uid}` (0x0E, 68 B; §7.2): a device writes one for every epoch in which it records another member's leave, and no HEADS entry for epoch e is written before the LEFT records of the leaves recorded in e (§7.3 "Others' leaves"); restore takes the leaves of its HEADS epoch from them (§11.4 step 5); snapshots keep the LEFT records of their HEADS epochs (§7.4); §6.9 points to them. The READV6-2 pin is deleted. Not adopted: the parked-J-style pin (it keeps VADV-2's re-fetch and holds HEADS at an old epoch), and making proactive rotation a MUST for the member who joined through a racing add (X in the trace): its committer built `D′` before the LEAVE reached it, the leaver is honest and its own devices repeat the LEAVE in every epoch that still lists them (§6.9), v1 had the same race, and a timer would still leave a window. §6.9 now states this case. Plan: M1 self-lane codec and KAT, M6 `selflane.ts` and `restore.ts`, M7 test 31 rewritten with the two-claim variant. |
| VADV-2 | **Accepted** (same change as VADV-1). Trace confirmed: the pin kept HEADS before another member's LEAVE row for as long as `D_e` listed it, which in a frozen copy is forever, so every restore re-fetched every row the leaver put after its LEAVE. With LEFT records lane positions pass the row, and §11.4's cost no longer counts "one LEAVE row per leaver". Plan M7 test 31 flood variant. |
| VADV-3 | **Accepted.** Confirmed: §7.4 asked for "an EPOCH for every held epoch", which includes the root epoch (0 for every created copy) that §7.1 rejects, so a literal snapshot was rejected as a whole; and nothing said which LEAVE record a snapshot keeps or which one is "latest". Change: §7.4 writes EPOCH records only above the root epoch (CONV_JOIN carries the root key) and states that every held epoch above the root has either the processed claim's position or NONE (skip); §7.3: every LEAVE record is kept and the latest is the one with the highest e; §6.9 says so; §7.4 keeps the LEAVE record with the highest e. No code change in M1 (`parseSnapshot` already rejects EPOCH e = 0). Plan M6 `selflane.ts`, test 17 variant. |
| VADV-4 | **Accepted**, the first option. Trace confirmed: a streamed page of one oversized batch is never cached and cost one `RL_READ` token, so each token could make the era's only shard read the whole batch. Change (§10.9, §10.2, §9.7, §9.1): a feed request that misses `caches.default` takes `⌈bytes / 4 MiB⌉` tokens, the extra ones after `feedBatches` and before the first byte, so a token never buys more than the 4 MiB an uncached tail page already costs. Not adopted: materialising the batch (more storage paths) and a row bound per batch (an attacker filling every batch would block honest puts). Delta M4: the feed handler; answer 63 changed. Plan M4 table and test. |
| VADV-5 | **Accepted** (merged with VQA-4). §10.6: clients use `P* = max(P, ⌊log2(dirSeq / 2080)⌋)` in place of `P`, which is never above the true `P`; the params re-read becomes a MAY; a 409 retry uses `min(P*, P′)` without raising it again. §10.9 points to it. Answers 4, 11 and 67 changed. Plan: M6 `api.ts`, test 16 variant. |

## Appendix C - Review changelog (round 8)

Round 8 checked the round-7 changes, the plan and the delta against this spec, DD and the repository at 8092e98 (read
only), where v2 replaced v1 in place. All 43 findings were accepted; duplicates share one change (R8ADV-1 and
R8CONS-1; R8ADV-5 and part of R8CONS-9; R8ADV-3 and R8CONS-6; R8CONS-3, R8PLAN-3 and R8NAMES-1; the R8NAMES findings
and the R8PLAN rewrite). Where a finding offered alternatives, the entry names the one taken and why. There is no wire
change: LEFT stays 68 B (0x0E) and was rechecked, so it can be implemented now. Answers 16, 49, 56, 61 and 63 changed
(Appendix D). The plan was rewritten for the in-place replacement; its milestone names and test numbers are kept.

| id | decision and change |
| --- | --- |
| R8ADV-1 | **Accepted** (high), the finding's first fix; R8CONS-1 is the same hole. Both traces confirmed: a snapshot keeps only the LEFT records of its own HEADS entry's epoch, and §7.3 let a later HEADS entry rely on a LEFT record "in an earlier row that is CAS OK", which that snapshot had compacted away (a parked J pinning the entry to an older epoch, or a sibling device's older entry being the latest). Change §7.3: every HEADS entry for epoch e MUST sit in the same self row or snapshot as a LEFT record for every member the writer records as left in e; "When to write" and HEADS splitting say so, and §7.4 notes why its LEFT set is then complete. Cost: 71 B per listed leaver per entry, only while a leaver is listed. Not adopted: keeping the LEFT records of every later epoch in snapshots (covers one direction only, and grows) and R8CONS-1's "earlier row after the latest snapshot" (ambiguous when siblings snapshot). Plan: M6 `selflane.ts`, M7 test 31 snapshot variants (a) and (b). Delta M6 items 8–9, M7 item 7. |
| R8ADV-2 | **Accepted** (medium), the finding's option (a). Trace confirmed: a LEFT record carries no time or position, so a leave written before the claim that decides its LEAVE row under §6.8 could never be undone, and the frozen-with-removal gate of §11.3 step 2 then differed between members and between a live device and its restore. Change: §7.3 defines a **final** leave (the copy is frozen, or a probe of its current epoch's control lane answered with `x-segv-now` at least `(t_R + Δ + SKEW)·1000` ms after T0 found no claim stored at or before `t_R` that is undecided or e-valid); LEFT records are written only for final leaves, and while a leave of a copy is not final the device writes no HEADS entry for that copy, so a restore reads the row again. §6.8: a dropped LEAVE row un-records the leave in its epoch and in every epoch it was carried into. §6.9 and §11.2 say LEFT is written once final. LEFT records thus record facts every device agrees on. Not adopted: option (b), a 78-byte LEFT with the row's time and position (a carried LEFT would also need the row's epoch, and a restore would need the times of claims before its HEADS epoch). Plan: M6 `conv.ts` and `selflane.ts` rows, M7 test 31 retracted-leave variant. Delta M6 item 8, M7 item 4. |
| R8ADV-3 | **Accepted** (medium), the second option. Confirmed: a page needing more than the 600 tokens of one `RL_READ` window could never be read, and §9.1 bounds a batch only by the shard's request rate and FULL. Change §10.9 (and §9.1, §9.7, §10.2): a feed request takes `min(⌈bytes / 4 MiB⌉, 64)` tokens. Up to 256 MiB of page a token still buys at most 4 MiB of shard reads; above that, at most `bytes / 64`, and such a batch needs about 1 000 maximal puts within one Δ. Not adopted: reading an oversized batch in parts with a label parameter (a new query parameter and a partial-batch encoding in an implemented codec and in the e2e audit), and a per-batch size bound at the shard (an attacker filling a batch would block honest puts, as VADV-4 noted). Answer 63 changed. Delta M4; plan M4 route and test rows (a pure token-count helper is tested instead of building a 2.5 GB batch). |
| R8ADV-4 | **Accepted** (medium). Confirmed: round 7 gave the harness three clocks (world, engine monotonic, engine wall) but no API that moves them together, so skipping a commit wait broke under either reading of "advance the fake clock". Change (plan §2.1–§2.2): `world.tick(ms)` moves the world and every engine's clocks and fires due engine timers, and `settle` uses it; `world.advance`/`advanceEra` move the server only; `I(e).clock` has `advance(ms, {mono?, wall?})`, `pauseMono()` and `resumeMono()`; engine timers run on the engine's monotonic clock. Added beyond the finding: the `EngineOptions` test hook `beforePutAttempt()`, awaited after the proof of work and before the fresh-probe check, so tests 22 (d), 22 (h) and 30 (b) can place the clock change between the probe and the put. Delta M6 item 17. |
| R8ADV-5 | **Accepted** (low); the same as the second half of R8CONS-9. Confirmed: lee's own repeat in e+1 (§6.9) reaches xena, who then drops lee. Plan M7 test 31 two-claim variant: lee's engine is logged out right after her LEAVE is OK, and when it returns it repeats the LEAVE in e+2. Delta M7 item 7. |
| R8CONS-1 | **Accepted**, merged into R8ADV-1 (same hole, same change). Its test variant is snapshot variant (a). |
| R8CONS-2 | **Accepted.** Confirmed at 8092e98: `proto-conv.test.ts:1482` and `:1506` use 0x0E as an unknown rtype, `RT` stops at MEMBER 0x0d, and the snapshot and S codecs need no change. Delta M1 items 10–11 name the two tests (use 0x10 or 0x30 instead), add LEFT to the `records` table, and list the real edits (`RT`, `LeftRec` in `SelfRecord`, `recordContent`, `parseRecord`). |
| R8CONS-3 | **Accepted**, merged with R8PLAN-3 and R8NAMES-1: the M9 greps name the allowed negative tests. |
| R8CONS-4 | **Accepted**, with R8PLAN-1 and R8NAMES-3: plan §0.1 and the delta's Paths say every v1 file the plan ports is read at 3de5f5e; M6 acceptance drops "the v1 engine specs are still green"; M7's run-time bound is measured once from a worktree of 3de5f5e. |
| R8CONS-5 | **Accepted.** Confirmed: `world.advance` closes every socket by default (`test/engine/fake/world.ts:338-345`), and with the engine's monotonic clock held still every sample has `rtt = 0`. Plan M6 test 15 uses `advanceEra(1, {keepSockets: true})` and gives the first new sample a larger `rtt`; M7 test 22 (h) uses `world.tick` with sockets open, drops the claims' frames to zed and asserts his copy is still in e. Delta M6 item 16, M7 item 7. |
| R8CONS-6 | **Accepted**, the first option, merged with R8ADV-3: `bytes` is the sum of the page's batch encodings, without the 5-byte page header, so an inline page takes one token as answer 63 and the code said. |
| R8CONS-7 | **Accepted.** Delta M3: the `dirmeta` row is already in `0001_init.sql` (no change); M4: the 101 exemption is already implemented by `stampResponse`, and `finalize` is dead code; summary item 5 no longer lists the INSERT. |
| R8CONS-8 | **Accepted.** Answer 56 and Appendix D 56: as 41, confirmed except the ShardDO pin log. Row 65 is unchanged. |
| R8CONS-9 | **Accepted.** Plan M6 test 17 adds a late row's LEAVE(5) after LEAVE(7), so the highest-e record is not the last; test 31's two-claim variant keeps lee offline (R8ADV-5). |
| R8CONS-10 | **Accepted.** Delta M1 item 7 and answer 16: add `!isBadSigPk(pk)` to the existing guarded `verify`, keeping its length checks and try/catch. |
| R8CONS-11 | **Accepted**, the first option (the spec follows the server): §10.2 bounds the nonce by 2^53 − 1 (403 above it) and clients search below 2^32; §1.2 no longer lists the nonce as unbounded. Answer 61 and Appendix D 61. No code change. |
| R8CONS-12 | **Accepted.** Plan M6 test 16 and the delta: the 409 is `{p: 0}`; the retry asks `p = 0` and is not raised again. |
| R8PLAN-1 | **Accepted** (high). Plan §0.1 rewritten as the in-place strategy, as proposed, with one bullet naming the old paths and identifiers (R8NAMES-2). |
| R8PLAN-2 | **Accepted** (high). M9 is documentation and cleanup: `git mv docs/PROTOCOL-v2.md docs/PROTOCOL.md` (after `git rm` of the v1 file), its references and the `vite.config.ts` `fmt.ignorePatterns` entry; `docs/DESIGN.md`; README; nothing deleted; no DO tag or D1 migration added. Added: stale v1 comments, and `docs/STAGE1-PLAN.md` keeps its name (R8NAMES-6). Spec text: Appendix C round 5 and the §13.2 heading name v1's files at 3de5f5e, since `docs/PROTOCOL.md` will be this spec. |
| R8PLAN-3 | **Accepted** (high), merged with R8CONS-3 and R8NAMES-1: M9 acceptance runs the header's checks and greps that allow `src/lib/proto.test.ts` 816, 1070, 1086, 1722 and `test/worker/api.spec.ts` 1832, 1835 (lines at 8092e98; round 9 names the tests instead, V8ADV-7); `LogDO` joins the stale-name grep. |
| R8PLAN-4 | **Accepted** (high). Confirmed: `src/routes/plugin@csp.ts` sends `require-trusted-types-for 'script'` with `trusted-types 'none'`, under which `new Worker(url)` throws. Plan §0.4: `trusted-types segv-worker` and a policy that accepts only the bundled worker URL (M6c); M6 `inbox.ts` row and list item. The spec keeps the Web Worker (§11.5 step 2). |
| R8PLAN-5 | **Accepted.** Plan §5 rewritten: generated secrets and v2 vars, readiness on `/api/v2/params`, steps per milestone (M6b, M6c, M7), `wire.ts` made strippable for the audit, named secrets; §0.5 points to it. Delta M6 item 20, M8. |
| R8PLAN-6 | **Accepted.** Plan §0.3: three additive view fields (`blocked`, `frozen`, `request`) instead of four meanings of `canSend`; `mock-engine.ts`; §0.4: composer, members, conversation list; new doc-comment rows. Q9 decided. |
| R8PLAN-7 | **Accepted.** M6 lands as M6a (sign-in), M6b (minimal end-to-end path, e2e rewritten) and M6c (the rest); the M6, M7 and M8 acceptance lines and M8's E2E paragraph no longer depend on v1 or a build flag. |
| R8PLAN-8 | **Accepted**, merged with R8NAMES-5: the plan header names the checks (`vp check`, `vp test run`, the two extra tsc configs, `npm run build`, a deploy dry run after a `wrangler.jsonc` change, e2e from M6b) and the period without a working app. |
| R8PLAN-9 | **Accepted.** Plan §0.5 describes the baseline (one tag `v1`, one `0001_init.sql`); later changes add tags or migrations. |
| R8PLAN-10 | **Accepted**, with the §0.6 part of R8NAMES-8: §0.6 marks existing files and lists `env.ts`, `batch.ts`, `types.ts` and the new `inbox-worker.ts`. |
| R8PLAN-11 | **Accepted**, with R8NAMES-2 and R8NAMES-3: every path and identifier of M6–M10 and §2–§4 is current, and v1 sources are cited at 3de5f5e. |
| R8PLAN-12 | **Accepted**, with R8NAMES-7: M0–M5 are marked done, with current names and acceptance lines. |
| R8PLAN-13 | **Accepted.** §3 preface names the 3de5f5e specs; §3.1 is two sentences. |
| R8PLAN-14 | **Accepted.** Risk 2's mitigation and a new risk 9 (no working app until M6b); Q1, Q7, Q9 and Q10 restated. |
| R8PLAN-15 | **Accepted.** §2 heading, intro, browser globals, helper list, settle step 2, the transport in `EngineOptions` and `junkRow`'s signature follow the harness at 8092e98. A fresh checkpoint uses `world.tick(CKPT_PERIOD_MS)` (R8ADV-4) rather than the harness comment's server-only `advance`. |
| R8PLAN-16 | **Accepted.** Delta: Paths, a new "Plan strategy (in place)" section, M6 item 20, M8, M9 and the text-only list. |
| R8PLAN-17 | **Accepted** as the summary of R8PLAN-1–16; nothing beyond them. |
| R8NAMES-1 | **Accepted**, merged with R8PLAN-3. |
| R8NAMES-2 | **Accepted**, merged with R8PLAN-1 and R8PLAN-11: the plan uses only current names; §0.1 lists the old ones once and says `/api/v2/` and `segv.sh/v2/` are unchanged. |
| R8NAMES-3 | **Accepted**, merged with R8PLAN-11 and R8CONS-4; the done `session.ts` and `dh.ts` sub-bullets are dropped. |
| R8NAMES-4 | **Accepted**, merged with R8PLAN-2, R8PLAN-7, R8PLAN-9 and R8PLAN-10. |
| R8NAMES-5 | **Accepted**, merged with R8PLAN-8; M2 acceptance is `npm run build` plus `wrangler deploy --dry-run`. |
| R8NAMES-6 | **Accepted**, merged with R8PLAN-2. The plan header names `docs/PROTOCOL-v2.md` as SPEC's in-repository copy. |
| R8NAMES-7 | **Accepted.** Answer 49 names `stampResponse` only; the plan uses `checkBundleShape`/`checkRecordShape`, `handleApi`, `dirRegister`/`dirAddWrap`/`dirByPrefix`/`dirByUid`/`dirWrapsById`/`dirlogPage`/`dirlogHead`, `makeAccount`/`registerOk`, `dirlogRefUser`/`dirlogRefWrap` and `PowScope` from `src/lib/proto.ts`. |
| R8NAMES-8 | **Accepted.** Delta M1 item 10 range `1069-1092`; delta M4 `finalize` wording; plan §0.5 and §0.6 rewritten (R8PLAN-9, R8PLAN-10). |

## Appendix C - Review changelog (round 9)

Round 9 checked the round-8 changes, the plan and the delta against this spec, DD and the repository (read only) at
c993e83 ("Stage 1: apply spec revision sent-2a to M0–M5"), which follows 8092e98 and implements every "Affects M0–M5"
item of `sent-2a/` except the LEFT record. All 18 findings were accepted. V8ADV-1 to V8ADV-5 share one change: the
LEFT record carries its LEAVE row's stored time and position, and round 8's finality rule and HEADS hold are deleted.
V8ADV-7 and V8LAY-3 share one change (line references). The only wire change is LEFT (0x0E, not yet implemented),
which grows from 68 to 78 B. Answer 61 changed (Appendix D). The plan, the delta and `changes-since-sent-2a.md` cite
the repository at c993e83.

| id | decision and change |
| --- | --- |
| V8ADV-1 | **Accepted** (medium). Both traces confirmed: round 8's finality probe sees only the dense prefix, so a claim stored beyond a hole with a time before `t_R`, or a claim stored on `Lctl_{e+1}` before the rename that kept the leaver, could still drop R after its LEFT record was written; a restore then took the leave as a fact while the live device dropped it. Neither offered fix was taken. The root fix (an effective claim time over the control prefix) needs the times of the control rows before a HEADS control position, which a restore does not fetch, so a restored device could compute another time than a live one. The minimal fix (LEFT records only from the entry's own row, superseded by the next HEADS) leaves a window in which a reload restores the stale leave, and the restored device then writes it again. Change instead: round 8's option (b), whose objections do not hold. LEFT is `conv | root | e | uid | u32 t | u16 E | u32 n` (78 B, §7.2), with R's stored time and, for R's own epoch, R's position (NONE for a carried leave; a position field, §3.1). A leave taken from a LEFT record is decided by §6.8 as R would be, with the walk starting at the record's epoch (every earlier claim kept the leaver, or the leave would not have been carried, so no older claim times are needed). A restore processes every claim of its HEADS epoch from the HEADS control position, which never passes an e-valid claim, and every claim after it, so it drops the leave wherever a live device drops R (§3.1, §6.8, §6.9, §7.1–§7.4, §11.2, §11.4 step 5). Deleted: the finality rule, the per-copy HEADS hold, and "no LEFT record exists for it". `acceptOldRow` needs no change: a carried record's NONE position is never before a cut, which is §6.8's rule for later epochs. Plan: M1 table and tests 2 and 4; M6 `selflane.ts`, `conv.ts` and `restore.ts`; M7 claims bullet and test 31 (retracted-leave variants (a) undecided claim, (b) a claim beyond a hole, (c) a pre-stored next claim). Delta M1 items 2, 3, 10 and 11, M6 items 8, 9 and 11, M7 items 4, 6 and 7. |
| V8ADV-2 | **Accepted** (medium), resolved by V8ADV-1's change. Confirmed: a removed copy was never final, so its HEADS stayed before a leaver's flood. Without a finality rule or a HEADS hold, a removed or frozen copy writes LEFT records and HEADS entries like any copy, and lane positions pass the flood. Plan M7 test 31 removed-copy flood variant. |
| V8ADV-3 | **Accepted** (medium), resolved by V8ADV-1's change. Confirmed: a leave restored from a LEFT record had no `t_R`, so it could never become final. Now the record carries the time, the restored device writes it again (with NONE once carried into a later epoch), and nothing waits for finality. Plan M7 test 31 two-claim variant: a second reload before the text also holds lee as left. |
| V8ADV-4 | **Accepted** (low). Confirmed against round 8's text. Without the finality rule a writer can always write the LEFT records; §7.3's MUST now names the device that writes the row or snapshot, and §7.4 keeps the fold's LEFT records of the copied entry's epoch plus one for every other member the snapshot's writer records as left in it. Plan M6 `selflane.ts`; delta M6 item 9. |
| V8ADV-5 | **Accepted** (low), moot after V8ADV-1: no probe waits for `t_R + Δ + SKEW` any more, so `settle` needs no new timer, and M7 test 31 no longer waits for finality. |
| V8ADV-6 | **Accepted** (low), the third option. Confirmed: at base 26 a full put needs 33 bits, and `powSolve` throws when nonces below 2^32 hold no solution (about 61%). §10.2: clients search upward from 0 up to 2^53 − 1, both halves of the `u64` included, so the search cannot run out. Delta M1 item 12: `powSolve` sets the high word; a test starts below 2^32 and crosses it. Answer 61 and Appendix D 61 changed. Not adopted: a retry with the next window (it can run out again) and a client bound of 30 bits (a new rule that refuses deployable params). |
| V8ADV-7 | **Accepted** (low), merged with V8LAY-3: the plan, the delta and `changes-since-sent-2a.md` cite tests by name, give line numbers at c993e83 and mark older ones "at 8092e98"; R8PLAN-3 above is qualified. |
| V8LAY-1 | **Accepted** (medium). Confirmed with Node 26.10's `stripTypeScriptTypes` on copies of both files: `class Rd` in `src/lib/proto.ts` also has parameter properties, so `run.mjs` fails on its first import. Plan §5 preamble and step 3, delta "Plan strategy" and M6 item 20: explicit fields in `Rd` and `Reader`, `from "./proto.ts"` in `wire.ts`, and a unit test in `src/lib/wire.test.ts` that strips both files with `stripTypeScriptTypes` (`node:module`), so a later parameter property cannot break e2e again. |
| V8LAY-2 | **Accepted** (medium), option (b). §11.3 step 2: for an undecided slot or an unfinal winner, `canSend` turns false only once it has stayed so for 30 s, until it settles; a send made before then waits in step 2. Plan §0.3 (`pending`, the `canSend` comment) and M7 test 12; delta M6 item 0 and M7 item 7. Not adopted: option (a), which would hide the composer whenever a claim is in flight, although a send then normally succeeds after a short wait. |
| V8LAY-3 | **Accepted**, merged with V8ADV-7. `changes-since-sent-2a.md` (a) says what is left against c993e83: the LEFT record (now 78 B) with its test edits, the round-8 feed-token change and the round-9 `powSolve` change; the `verify` wording, the test range, the 101 exemption and the `dirmeta` row are done there. |
| V8LAY-4 | **Accepted.** Plan M1–M5 headings use one form, "done at c993e83", naming the open delta items (M1: LEFT and `powSolve`; M4: the round-8 feed-token change). The M5 knobs and the M3 `dirmeta` test landed at c993e83, not 8092e98. |
| V8LAY-5 | **Accepted**, the first option. Plan §2.3 marks every builder except `junkRow` as to be added: `signEpoch`, `buildBundleFor`, `forgeJoin` and `buildMessage` in M6c (M6 tests 10, 13 and 18, `images.spec.ts` #61), and `commitChange`, `buildClaim`, `readableWith` and `entryOutcome` in M7. The §2 heading and the M6c and M7 lists say so. |
| V8LAY-6 | **Accepted.** Plan M6b updates the README as e2e turns green (the status note, the `src/client/` and `test/engine/` rows, the e2e row and the e2e remark); M9 keeps only the `docs/PROTOCOL.md` link and the `docs/DESIGN.md` remark. |
| V8LAY-7 | **Accepted**, both parts. Plan §0.4, §0.6, §2.2 and M6c: the `?worker&url` import lives in `src/client/inbox-worker-url.ts`, which starts with `/// <reference types="vite/client" />`; the engine creates the worker through `EngineOptions.inboxWorker` (a factory whose default imports that module dynamically), and the engine tests pass `null`, so they always use the same-thread path. Delta M6 item 20. |
| V8LAY-8 | **Accepted.** Plan M6 test 15: the new sample's `rtt` is bumped by 1 s, the test asserts that every earlier sample's `rtt` was smaller and that the estimate uses the new sample (`I(e).timeSample`, new in §2.3); the equal-`rtt` pair is taken with the monotonic clock paused (`rtt = 0`), 500 ms of server time apart (below the 1 s discard margin). Delta M6 item 16. |
| V8LAY-9 | **Accepted**, the second option. Plan §5 step 3: the audit decodes every page with the strict `decodeFeed` (an incomplete page is rejected); the streamed 9 MiB page and truncation stay in the Worker and `wire` tests. Delta M8. |
| V8LAY-10 | **Accepted.** The listed round-8 items carry "(round 8)" (spec §6.8, §7.3, §9.1, §9.7, §10.2; plan M7 heading and tests 9, 22 (d)/(h), 30 (b), §2.2 settle, §2.3 `junkRow`), text rewritten in round 9 carries "(round 9)", and the §13.2 heading stays listed in the delta's text-only list. The delta's M7 test 9 line gains the `blocked`/`frozen` assertion. `changes-since-sent-2a.md` says that every delta item is marked and the changed spec and plan sections are listed in the delta, and calls Q1 "decided (restated)". |
| V8LAY-11 | **Accepted.** Plan §3.1 (the `wire` round trips are in `src/lib/wire.test.ts`), M1 test 2 (`_setRandomForTests`, already in `src/lib/proto.ts`), §2.2 `engineFor` (as v1's did at 3de5f5e); delta M1 item 10 (the `records` table at line 1632 at c993e83, 1287 at 8092e98). |

## Appendix C - Review changelog (round 10)

Round 10 checked the round-9 changes, the plan and the delta against this spec, DD and the repository at c993e83 (read
only), and answered the questions R8-1 to R8-10 that the implementing session asked while it applied `sent-2a/`
(Appendix D, `answers.md`). All 18 findings were accepted; R10ADV-1 and R10ADV-3 share one change. There is no wire
change: LEFT stays 78 B (0x0E). New M0–M5 code changes: `acceptOldRow` (R10ADV-2) and a way to stop `powSolve`
(R10ADV-5); the questions add none (R8-2 and R8-3 confirm round 8's open feed-token change). Answers 61 and 63 changed.

| id | decision and change |
| --- | --- |
| R10ADV-1 | **Accepted** (high), the finding's fix. Trace confirmed: a member can be recorded as left in one epoch both from a LEAVE row there (typically the leaver's own §6.9 repeat in an epoch that a racing claim carried its leave into) and from the leave carried in from the previous epoch. Round 9 kept whichever arrived first ("changes nothing"), and §6.8 can drop one source while it accepts the other, so two honest members holding the same rows, or one device live and after a reload, reached opposite frozen-send gates. Change (§6.8, new §6.9 "Several sources", §7.2 LEFT row, §7.3 fold row and "Others' leaves", §7.4, §11.2, §11.4 step 5, §11.10): per copy, epoch and member a receiver keeps only the source with the least key `(t, position)`, NONE counting as after every real position; a source with a smaller key replaces the kept one and is written as a new LEFT record, and one with an equal or larger key changes nothing; the leave stands iff §6.8 accepts the kept source. Along one walk §6.8 accepts a smaller key whenever it accepts a larger one (a smaller t is accepted first, and at equal t only a real position before the cut is), so the least source is accepted whenever any source is, in every order, and dropping it un-records the leave with no fallback. Nothing is added beyond a comparison, and the fold's LEFT rule becomes "least wins" (R10ADV-3). Plan: M6 `conv.ts`, `selflane.ts` and `restore.ts` rows (implemented with M7, R10COH-7); M7 test 31 source-order variant. Delta M6 items 8, 9 and 11; M7 items 4, 6 and 7. |
| R10ADV-2 | **Accepted** (high); the finding's two options become one rule. Trace confirmed: a restore that starts at HEADS epoch c with `EK_c` from a snapshot's EPOCH record never processes `C_{c−1}` (round 11, V10CON-1: one without a snapshot processes it on its way to c), so `acceptOldRow` got `claim = null` for a row on a followed lane of c−1 and accepted it without reaching `C_c`; a LEAVE or TEXT stored after a claim of c that removed its sender was shown after a reload but dropped live, so round 9's "drops the leave wherever a live device drops R" did not hold here. Change §6.8: the walk goes on while the receiver holds `D_{j+1}` or `C_j`; a receiver that holds `D_{j+1}` reads s's bit from it (`rm` has bit 0 exactly for the members `D_{j+1}` lists, §6.6 step 4) and needs `C_j` only at a step whose bit is 1; where it holds `D_{j+1}` but did not process `C_j` (restore, scrollback) it reads `C_j` at its EPOCH record's position before deciding, and it never accepts a row because it lacks `C_j`. Rows on the followed lanes of c−1 thus need no fetch (§11.4 step 5); the initial history and scrollback read an ending claim where a removed sender's row needs it (§11.4 step 6 and cost, §11.10). Code (M1): `acceptOldRow` continues by membership when `epochs[j].claim` is null and `epochs[j+1]` exists, and throws when the sender is not listed there (its caller must read `C_j` first). Plan: M1 test 10 rows; M6 `restore.ts` and `history.ts` rows; M7 test 31 followed-lane variant. Delta M1 item 13 (new), M6 items 11 and 14, M7 item 6. |
| R10ADV-3 | **Accepted** (medium), merged with R10ADV-1. Confirmed: with "every record is kept" and records that may differ per key, every HEADS row and snapshot re-copied all of them, without bound in a frozen copy that keeps leavers listed. Change §7.3: per key `(conv, root, e, uid)` the least record wins, so identical records count once; §7.4 copies exactly one record per member left in the entry's epoch. Plan M6 `selflane.ts`. |
| R10ADV-4 | **Accepted** (low). §6.9, §11.2, the plan's `conv.ts` row and delta M7 item 4 say "the row's stored time and, for the row's own epoch, its position (NONE for an epoch the leave was carried into)", as §7.2 and §7.3 already did. Plan M7 test 31 asserts NONE in a carried record. |
| R10ADV-5 | **Accepted** (low). Confirmed: a nonce at or above 2^32 is reached only after 2^32 hashes (36–48 min in a tab), longer than the 10–20 min a proof's window is accepted, so round 9's full-range search could not make a 33-bit put succeed, and its rationale was wrong. Change §10.2: a client MUST restart the search with the new window when the window it searches in stops being current (each nonce is an independent trial, so nothing is lost), and never sends a stale proof; the expected work at base 26 (about 8.6·10^9 hashes for a full put, over an hour in a tab) is stated as the cost of raising the base that far. The full-range search stays (the search is bounded by time only); "so a search never runs out" is dropped. Not adopted: splitting puts by difficulty (a new client rule for an operator setting). Code: `powSolve` gets a way to stop (delta M1 item 12); M6a `api.ts` restarts it at the window roll. Answer 61 changed. |
| R10COH-1 | **Accepted**, option (a): a name at creation (`validName` on the new name, D's name, the "# name" display) moves into M6b, so the e2e group step and the team-name needle keep their intent, and M6b also takes the flows "group # names" and "name sanitisation"; rename display lands with M7 (corrected in round 11, V10CON-2: this row said M6c kept them). |
| R10COH-2 | **Accepted.** `changes-since-sent-2a.md` lists M1 test 10's NONE row as a to-do (a1), and the delta's status names it. |
| R10COH-3 | **Accepted.** `answers.md` answers R8-1 to R8-10 (Appendix D); drafts R8-2 and R8-3 are superseded by round 8's cap of 64 (R8-3 below), and R8-1 needs no code change. |
| R10COH-4 | **Accepted.** Plan M6 test 8 delivers the J of a creation by WELCOME (its add variant lands with M7); test 10's era variant and test 17's epoch-2 and LEAVE-record parts land with M7 ("and LEAVE-record", round 11, V10CON-2). |
| R10COH-5 | **Accepted.** At c993e83 `docs/STAGE1-PLAN.md` is the `sent-1/` plan and `docs/PROTOCOL-v2.md` the `sent-2a/` spec. The plan header, M9 and `changes-since-sent-2a.md` (d) say that the implementing session copies each revision verbatim (this spec over `docs/PROTOCOL-v2.md`, the plan over `docs/STAGE1-PLAN.md`) in a commit of its own, the first one before M6a. |
| R10COH-6 | **Accepted**, the first option: M6b includes the first batched inbox post, the padded DELIVERED row and the 409 rebuild; M6c adds WELCOMEs, retry and resume. |
| R10COH-7 | **Accepted**, the first option: the LEFT codec is M1; writing LEFT records, their place beside HEADS entries and in snapshots, the kept-source rule and their use at restore land in M7 with leave. M6 writes HEADS entries without LEFT records, since no M6 path records a leave. |
| R10COH-8 | **Accepted.** Delta M5 status: the FakeWorld items landed at c993e83; the builders and the `I(e)`, `settle` and `EngineOptions` items land with M6a–M7. |
| R10COH-9 | **Accepted.** Plan M6a and the note: rewrite the `settle` doc comment in `test/engine/harness.ts` to use `world.tick`. |
| R10COH-10 | **Accepted.** The note and the delta say that dropping the header term affects streamed pages only (a batch of exactly k·4 MiB takes k tokens, not k+1), that c993e83 charges inline pages one token and streamed pages `⌈(5 + bytes)/4 MiB⌉` without a cap, and that the route uses the pure helper (8 388 608 B gives 2). |
| R10COH-11 | **Accepted**, the first option: plan M6 test 15 asserts `I(e).timeSample.rtt < 1000` just before the jump, and afterwards that `timeSample` is the new sample with `rtt ≥ 1000`. |
| R10COH-12 | **Accepted.** Delta M6 item 10 qualifies `canSend` with the 30-s wait; plan §0.3's comment row uses §11.3 step 2's full condition. |
| R10COH-13 | **Accepted.** Plan §2.1: `failGet` in the `blobs` row; §0.4 and §2.2: `inboxWorker?: (() => Promise<Worker \| null>) \| null`, where `null` means no worker. |
| R8-1 | §10.1 status table: other routes MAY answer 500 or 503 "storage unavailable" for a failed Durable Object or R2 call. No code change: clients treat every 5xx alike, so a uniform 503 would change no client behaviour. |
| R8-2 | §10.9: a page that is not streamed takes one token, and a streamed page of b bytes `min(⌈b / 4 MiB⌉, 64)`. This is round 8's rule (no page header); c993e83 still adds the header term for streamed pages. |
| R8-3 | §10.9: the cap stays 64 (round 8), not the draft's 600, and a deployment MUST keep `RL_READ` above it. At the production Δ = 10 the shard's ~1 000 requests/s bound a batch near 2.5 GB, so 64 lets a token buy at most about 10 times the 4 MiB tail-page rate, and only after a Δ of saturating maximal puts (about 10 000, which already deny every honest put of that Δ); each further multiple costs about 1 021 maximal puts more within the Δ (the critique's arithmetic is accepted). A cap of 600 would keep that near 1.05×, but a page above 256 MiB would then need up to every token of a window: an auditor behind a shared address, or one reading checkpoints from the same address, would be refused, each refused attempt burns the tokens it took, and the Workers rate-limit binding counts per location and approximately, so a cost equal to the whole limit may never be granted, which is the unreadable page R8ADV-3 closed. Per-address limits do not bound an attacker with many addresses under either cap, so readability decides. |
| R8-4 | §9.7 "Logs" (a content rule), §3.1, §9.1 and §9.5 drop `logErr`; log text and keys are implementation-defined (preamble). |
| R8-6 | §10.1 order of checks: a check that needs stored state and the 5xx of a failed storage call are not ordered (a cached or missing `P`). |
| R8-7 | §6.6 step 4: a throw of a kept entry's `sealDet` recomputation is a failure of the `pks` check. |
| R8-9 | §6.6 step 4 "Check order", with the critique's correction: the explicit orders of this spec stay normative (the `rm` bit first, the own entry, (g) before (h), §6.7 step 1, §10.1). |
| R8-10 | Preamble "Implementation vocabulary" (merged with R8-4): names, failure codes, unstated check orders and log formats are implementation-defined. |

## Appendix C - Review changelog (round 11)

Round 11 checked the round-10 changes, the plan, the delta, the answers and `changes-since-sent-2a.md` against this
spec, DD and the repository at c993e83 (read only). All 11 findings were accepted; none duplicates another. There is
no layout change: LEFT stays 78 B (0x0E), and EPOCH keeps its 127 B, but a skip's EPOCH now names the claim that
removed self instead of NONE (the codec already accepts any position with flag bit1). New M0–M5 code changes: none
beyond two doc comments in M1 (`acceptOldRow`'s list contract and `EpochRec.claim`) and the 9 MiB test's comment in M4
(`test/worker/api.spec.ts:2343`, V10CON-3; this sentence corrected in round 12, V11CON-8); the open items stay the
LEFT record, the feed tokens, `powSolve` and `acceptOldRow`. Answers R8-2 and R8-9 changed, and the sections of
Appendix D row R8-3 were corrected.

| id | decision and change |
| --- | --- |
| V10ADV-1 | **Accepted** (medium). Trace confirmed: after a skip re-add from k to e′ > k+1, a restore from a snapshot whose HEADS entry is at e′ holds `D_k` but neither `D_{k+1}` nor `C_k`, no record named `C_k` (the skip's EPOCH carried NONE), and §11.4 step 6 and §11.10 stepped to "e−1", which is not held; an implementation that stepped back to k ended the §6.8 walk without a removal and showed rows that a member removed by `C_k` stored after it, which the live device had dropped. Neither offered fix was taken as is. Stopping history at a skip loses the pre-removal history that §0.3 item 7 promises, and processing k's control lane from its start re-evaluates every claim and junk row of k. Change instead, reusing round 10's mechanism: a skip's EPOCH record names the position of the claim of k that removed self (§7.2, §7.4, §6.7 step 7), so every held epoch above the root names the claim that ended the previous held epoch; §6.8 states that the walk's epochs are consecutive (a skip never continues it), that a receiver removed at j+1 needs `C_j` at step j, and that one that did not process it reads it at the position named by the next held epoch's EPOCH record; §11.4 step 6 and §11.10 step into the previous held epoch (k below a skip) and end below the root. No codec change (`parseRecord` accepts any position with flag bit1); doc comments of `EpochRec.claim` and `acceptOldRow` (consecutive epochs, the caller passes the claim that ended the last listed epoch). Plan: M1 claims and self-lane rows, M6 `selflane.ts`, `restore.ts`, `conv.ts` and `history.ts` rows, M7 claims bullet and test 16 history variant. Delta M1 items 13–14, M6 items 3, 9, 11 and 14, M7 items 5–7. |
| V10ADV-2 | **Accepted** (medium), the first fix. Trace confirmed: round 10 made the leave verdict independent of arrival order, but §6.6 step 5 picked a claim's removed/rotated line, and step 6 the frozen-with-removal gate, from the leave state at the moment the claim was processed, and nothing re-derived them when a source arrived later; the "@x left" lines also depended on order. Change: §6.6 steps 5–6 and §11.3 step 2 derive the lines and the gate from the current leave state and re-derive them when a source is added, replaced or dropped; §11.9: a LEAVE row shows "@x left" while it is a kept source in some epoch; §6.9 "Several sources" points there. Plan: §0.3 `canSend` comment, M6 `conv.ts` row, M7 claims bullet, test 31 source-order variant run in both orders for alice (claim first, then the sources; and the sources first), asserting the settled lines and gates. Delta M7 items 2, 4 and 7. |
| V10ADV-3 | **Accepted** (low). §9.1, §9.7 and the §10.2 `RL_READ` row say "one token per started 4 MiB of the page's batches (without the page header), at most 64", as §10.9 does; §10.9's "256 MiB of page" reads "of batches". Text only (the open code change of delta M4 is unchanged). |
| V10ADV-4 | **Accepted** (low), the first fix. Confirmed: §6.4 ordered only (g) before (h), while (f) and (g) each make a request, so two conforming evaluators made different requests for the same junk claim, against the preamble. Change §6.4 "Order of requests": no request before (a)–(e), and (f) when the reader holds `t_reg` of e's own bundle, have passed; then (f)'s `meta` if needed, (g)'s only after (f), (h)'s blob only after (g). §6.6 step 4 "Check order" lists it among the explicit orders. A claim that fails a local rule thus costs no request. No M0–M5 code change (`claimShapeValid` is local). Answer R8-9 and Appendix D R8-9. Plan: M7 e-validity bullet, and §3 row 27 asserts no `blob/meta` for a bad csig; delta M7 item 2. |
| V10ADV-5 | **Accepted** (low), the first fix. Confirmed: a member added by a commit that raced a LEAVE has no source for the leave, so a rotation by a member who saw it is a removal to it ("@alice removed @lee"), and a freezing one would refuse its texts where the others may send. §6.9 now says so instead of "learns of the leave … when a member who saw it rotates". Plan M7 test 31 two-claim variant asserts xena's line. |
| V10CON-1 | **Accepted** (medium). Confirmed: a restore without a snapshot re-derives `EK_c` by processing `C_{c−1}` (§7.3), so the followed-lane variant passed with c993e83's `acceptOldRow`. Plan M7 test 31 followed-lane variant forces a snapshot carrying EPOCH(c) and HEADS(c) before the LEAVE is stored and asserts that the reload processes no claim of c−1. "Never processes `C_{c−1}`" is qualified in §11.4 step 5, §6.8, Appendix C R10ADV-2, the plan's `restore.ts` row, delta M6 item 11 and the note. |
| V10CON-2 | **Accepted.** Appendix C R10COH-1 says M6b takes the flows "group # names" and "name sanitisation" and rename display lands with M7; R10COH-4 adds test 17's LEAVE-record part. |
| V10CON-3 | **Accepted.** Plan M4 feed-token row adds the helper value 64 for 600·4 MiB + 1 B and the `countingLimiter(63)` case (429 after 64 limiter calls, no `feedRows`), and tells the implementer to reword the comment at `test/worker/api.spec.ts:2343` to ⌈9 MiB / 4 MiB⌉ = 3. Answer R8-2 and the note (a2) say so. |
| V10CON-4 | **Accepted.** The delta's round-10 plan text list names the `deliver.ts` row; Appendix D R8-3 lists §10.9 only. |
| V10CON-5 | **Accepted.** `answers.md`'s header lists every open M0–M5 item as the delta's status line does, and the R10ADV-1 bullet moves under "M6/M7". |
| V10CON-6 | **Accepted.** Delta M3 cites `test/worker/directory.spec.ts:222-223` (c993e83). |

## Appendix C - Review changelog (round 12)

Round 12 checked the round-11 changes, the plan, the delta, the answers and `changes-since-sent-2a.md` against this
spec, DD and the repository at c993e83 (read only). All 14 findings were accepted. V11ADV-2, V11CON-2 and V11CON-4
share one change (the "@x left" rule), as do V11ADV-5 and V11CON-3 (§6.4 "Order of requests"). There is no layout
change. New M0–M5 code change: `claimShapeValid` rejects `B < m` (M1, V11CON-3); the open items are now the LEFT
record, the feed tokens, `powSolve`, `acceptOldRow` and this check. Answer R8-9 changed.

| id | decision and change |
| --- | --- |
| V11ADV-1 | **Accepted** (medium), the second fix (narrow the claim). Trace confirmed: a snapshot or HEADS row carries LEFT records only for its HEADS epoch (§7.4), so after a reload the leave state of an older epoch is rebuilt only from the rows that the initial history and scrollback load, and a claim below the HEADS epoch that dropped a leaver can show "removed" where the live view showed "keys rotated"; the "@x left" line of a LEAVE row before the HEADS positions is likewise missing until loaded. Persisting LEFT records for the previous epoch was not taken: it would cover only one epoch below the HEADS epoch, while scrollback reaches deeper claims and "@x left" lines belong to rows that must be loaded anyway, and it would add records and a second LEFT rule to snapshots and HEADS rows. The verdicts and the send gate are unaffected: they depend on the current epoch, whose leave state the LEFT records carry. Change: §6.6 step 5 drops "and after a reload" and states what a reload shows; §11.9 adds a paragraph (and says that a claim history reads without processing it shows its lines as a processed one would, so restores do not differ by whether a line exists); §11.4 step 6 processes the initial history's rows as scrollback's (V11CON-6); §13.2 item 8 records the effect. Plan: M6 `history.ts` row, M7 test 31 restore comparison (V11CON-6). Delta M6 items 11 and 14, M7 item 4. |
| V11ADV-2 | **Accepted** (low), the finding's fix, merged with V11CON-2 and V11CON-4. Trace confirmed: a repeat R′ in e+1 stored in the same Δ batch as R1 in e has the key (t, position), which sorts before the carried (t, NONE), so R′ became the kept source of e+1 while R1 stayed that of e, and round 11's rule gave both an "@x left" line. Change §11.9: a LEAVE row R of x in epoch k shows the line while it is the kept source of x's leave in k, §6.8 accepts it, and x is not recorded as left in k−1 (a leave carried into k shows its line at its source in the earlier epoch), so one leave shows one line; §6.9 "Several sources" points there. Plan: M6 `conv.ts` row, M7 test 31 equal-time repeat. Delta M7 item 4. |
| V11ADV-3 | **Accepted** (low), the finding's fix. Trace confirmed: a skip's EPOCH names `(claimE, claimK)` but not k, and §11.4 step 5 let a restore start at "the latest HEADS position", so a restore that took `EK_{e′}` from a skip's EPOCH record (without a snapshot, or with one older than the epochs reached through own entries before k) never derived those epochs, and the initial history or scrollback could step into the wrong epoch below the skip. Change §11.4 step 5 "Control lane": the restore starts at the copy's highest epoch whose key a snapshot record gives (its root epoch when there is none), or at the HEADS epoch when that is lower, and processes each epoch's control lane (the HEADS epoch from its position, every other from `(E_start, 0)`), so it holds every held epoch; §6.8, §7.2 (EPOCH row), §11.4 step 6 and §11.10 define the previous held epoch as the highest held epoch below; the cost list counts re-derived epochs. Plan: M6 `restore.ts` and `history.ts` rows, M7 test 16 post-snapshot variant. Delta M6 items 11 and 14, M7 item 5. |
| V11ADV-4 | **Accepted** (low). Confirmed: §7.4 kept a DESC for "the previous one" (e′−1 below a skip, which the copy never held), so the initial history below a skip fetched k's bundle. Change §7.4: a DESC for the current epoch and for the copy's previous held epoch (e−1, or k below a skip); §11.4 cost line. Plan: M6 `selflane.ts` row, M7 test 16 asserts no blob GET of k's bundle. Delta M6 item 9. |
| V11ADV-5 | **Accepted** (low), merged with V11CON-3. Confirmed: "no request for a row before (a)–(e) have passed" forbade the body `get` that (a) needs and did not place the `get` that (g) needs for `t_row` after a realtime frame. Change §6.4 "Order of requests": the paragraph orders only `blob/meta` requests and blob fetches; the `get` that supplies the row's body, or its `t_row`, is not ordered by it. Answer R8-9. |
| V11ADV-6 | **Accepted** (low). Confirmed: the §10.2 row's formula gave 0 tokens for an empty page, against §10.9's "at least 1"; c993e83 charges it one. §9.1 and the §10.2 `RL_READ` row say "at least 1 and at most 64". Text only. Delta M4. |
| V11CON-1 | **Accepted.** Confirmed at c993e83: `dropPublish` (`test/engine/fake/rt.ts:182`) loses a matching publish for every subscriber, and alice's catch-ups fetch R1 from her followed lane, so order (i) could pass as the R1-first case and order (ii)'s intermediate assertion fails. Plan M7 test 31 source-order variant hides R1 from alice with `world.shard.hide(E, label(R1), "alice")` (`shard.ts:210`) and releases it with `unhide` (`shard.ts:218`): in (i) after she has applied R′ (her sweep of lee's followed lane then records a head before R1, and her first `markRead`'s scrollback finds it), in (ii) after she has processed C_{e+1} (her next catch-up of the followed lane finds it). Plan §2.1 names `unhide`. Delta M7 item 7. |
| V11CON-2 | **Accepted**, merged with V11ADV-2. Delta M7 item 4 drops "no new line" and "still without a second line" and states the round-12 rule (the line moves to a smaller source when that is a LEAVE row of k). |
| V11CON-3 | **Accepted**, the first fix, merged with V11ADV-5. Confirmed: (g)'s `bundleSize` clause and (h)'s `B ≥ |D_e|` follow from `bundleSize` alone, and c993e83's `claimShapeValid` checks the first but not the second (`bundleShapeValid` checks `B < m` after the download). Change §6.4: the local rules are (a)–(e), the `bundleSize` clause, `B ≥ |D_e|`, and (f) when `t_reg` is held; §6.6 step 4 "Check order" names them. Code (M1): `claimShapeValid` rejects `B < m`. Plan: M1 claims row and test 10, M7 e-validity bullet. Delta M1 item 15 (new), M7 item 2. Answer R8-9. |
| V11CON-4 | **Accepted**, merged with V11ADV-2: §11.9, §6.9 "Several sources", the plan's `conv.ts` row and delta M7 item 4 say "and §6.8 accepts it". |
| V11CON-5 | **Accepted.** Plan M7 test 16 asserts the read of C_k anywhere between the reload and the settled `markRead` (the initial history steps into k first), and the followed-lane variant asserts "no blob GET of epoch c's bundle during the reload" instead of an `I(e)` field. Delta M7 item 7. |
| V11CON-6 | **Accepted**, with V11ADV-1. Plan M7 test 31: the restores give the same verdict, send gate and C_{e+1} line as live; the "@lee left" line at R1 is asserted after each restore's settled `markRead`. §11.4 step 6: the initial history's rows are processed as §11.10 says. |
| V11CON-7 | **Accepted.** Confirmed: at c993e83 `src/lib/proto.ts:1793` is `acceptOldRow`'s first line and the null-claim check is line 1797. Delta M1 item 13 and `changes-since-sent-2a.md` a4 cite 1797. |
| V11CON-8 | **Accepted.** The plan header, the delta header, Appendix C round 11's intro and `answers.md`'s summary name round 11's M4 test-comment fix (`test/worker/api.spec.ts:2343`); delta M6 item 0 says the `canSend` comment follows the current leave state (round 11's rule, as plan §0.3 has it). |

## Appendix D - Implementation questions (M0–M5)

The implementing session asked 67 questions while building M0–M5 from `sent-1/`. The full answers, with the code to
change, are in `answers.md`; this list gives each decision and the sections it changed. Round 7 changed answers 4, 11,
24, 41, 43, 62, 63 and 67 (Appendix C round 7). Round 8 changed answers 16 (wording of the code change), 49 (the
function name), 56, 61 and 63 (Appendix C round 8). Round 9 changed answer 61 (Appendix C round 9). Round 10 changed
answers 61 (restart at the window roll) and 63 (the cap of 64 confirmed against 600), and added the questions R8-1 to
R8-10 that the implementing session asked while applying `sent-2a/` (rows R8-1 to R8-10 at the end; Appendix C round
10). Round 11 changed answers R8-2 (the 9 MiB test's comment drops the header term, V10CON-3) and R8-9 (§6.4 now
orders e-validity's requests, V10ADV-4), and corrected the sections of row R8-3 (V10CON-4; Appendix C round 11).
Round 12 changed answer R8-9 (the local rules include the `bundleSize` clause of (g) and `B ≥ |D_e|` of (h), so
`claimShapeValid` gains `B ≥ m`; the row's own `get` is not ordered; V11CON-3, V11ADV-5; Appendix C round 12).

| n | decision | sections |
| --- | --- | --- |
| 1 | confirmed: SKIPPED covers every body-mode key after the first HIT that does not fit | §10.4 |
| 2 | confirmed: `sealed` of `/era/{E}` by the Worker clock, no DO | §10.9 |
| 3 | confirmed: an unregistered R2 object is registered with its stored size, without reading the body | §10.7 |
| 4 | confirmed (server), superseded by 67; round 7: clients bound `P` from below (`P*`) | §9.6, §10.6, §10.9 |
| 5 | confirmed: a failed ShardDO call is 503 for the whole put or get | §10.1, §10.3, §10.4 |
| 6 | confirmed: every non-immutable inbox 200 is `public, max-age=Δin` | §10.5 |
| 7 | confirmed: 257 rows read, 256 returned; order by b64u uid text | §9.6, §10.6 |
| 8 | confirmed: check order of `POST /wraps`, the cap before the duplicate | §10.6 |
| 9 | confirmed: a repeated id in a registration is 400 | §10.6 |
| 10 | confirmed: bundle and record `ts` are informational | §2.2, §2.4 |
| 11 | confirmed (server); client retries once on 409 with `min(P*, P′)` (round 7) | §10.6 |
| 12 | confirmed: no lower bound on p; the query plan is free (merged with 60) | §9.6 |
| 13 | spec clarification: lifetime `E_LAST = 7100` | §3.1 |
| 14 | confirmed: inbox decoder rejects decreasing `rel`; engine progress rule | §10.5, §10.9 |
| 15 | confirmed: ROWS `n` is 1..65535 | §10.8 |
| 16 | **change the implementation**: `sigPk` in the prime-order subgroup; pinned cofactored verification | §1.1, §2.1, §5.1, §13.3, App. B |
| 17 | spec clarification: signed JSON may be parsed to find the key | §1.2 |
| 18 | superseded by delta (68 + 6m + 12f) | none |
| 19 | confirmed: the parse rules of M are named; a leading BOM is kept | §1.2, §3.3, §5.1, §6.4(a) |
| 20 | confirmed: time and sequence fields ≤ 2^53 − 1; the position rule | §1.2, §3.1 |
| 21 | superseded by delta (D′ open or parse failure is D′-invalid) | none |
| 22 | confirmed: the 10 reserved header bytes are zero | §5.4, §6.4(h), §6.7 |
| 23 | superseded by delta (size checks before download); absent Content-Length rule | §6.7 |
| 24 | confirmed: count caps; a HEADS entry that does not fit D is ignored; round 7: a copy without e−1 ignores only the followed lanes | §7.2, §11.4 |
| 25 | confirmed: MEMBER handle matches the handle regex | §7.2 |
| 26 | confirmed: desc length-only at parse; the consumer checks | §7.2 |
| 27 | confirmed: S and S2 parse rules; restore falls back to older pointers | §7.1, §11.4 |
| 28 | confirmed: `/era/{E}` times in Unix ms (merged with 2) | §10.9 |
| 29 | confirmed: after `ended`, `closed = max(R, closed_hw)` | §9.3 |
| 30 | confirmed: `read` and `head` persist `closed_hw` with their slot rows | §9.3 |
| 31 | confirmed: `/ckpt/range` and `/dirlog` defaults and 404 cases | §10.1, §10.6, §10.9 |
| 32 | confirmed: register and wraps answer 200 `{dirseq}` | §10.6 |
| 33 | confirmed: RESUME counts toward neither rate limit (merged with 37) | §9.4 |
| 34 | confirmed: an unchanged `hd` counts as appeared; empty components list ZERO32 | §9.5 |
| 35 | confirmed (as 29) | §9.3 |
| 36 | confirmed: slot leaves by `(eid, bucket)`; `head(E, g)` | §9.3 |
| 37 | confirmed: what a topic change is; the check order of a frame | §9.4 |
| 38 | confirmed: RESUME with the current seq; ROWS frames ≤ 512 KiB; ring measure | §9.4, §10.8 |
| 39 | confirmed: only OPEN sockets count; lowercase hex tag | §9.4 |
| 40 | confirmed: "the era has not ended" | §9 |
| 41 | Δ and Δin are deployment constants; pins; round 7: **change the implementation** (SHOULD): the ShardDO logs a pin mismatch once | §3.1, §9.1, §9.2, §9.3 |
| 42 | confirmed: the feed never closes a batch | §9.1, §10.9 |
| 43 | alarms re-arm at `max(due, now + 1000)`; round 7: **change the implementation**: the InboxDO alarm | §9 |
| 44 | confirmed: 10 s per component; a never-answered one is left out | §9.5 |
| 45 | confirmed: only `E_now − 1` is the previous era | §9.5 |
| 46 | confirmed: checkpoint `sec` never decreases | §9.5 |
| 47 | confirmed: the first alarm at `now + 60 s` | §9.5 |
| 48 | confirmed: the blobreg hour | §9.5 |
| 49 | superseded by delta (101 exempt); the 421 carries `x-segv-now` | §9.7, §10.1 |
| 50 | confirmed: 410 before 404; the order of inbox read errors | §9.7, §10.5 |
| 51 | confirmed (as 1) | §10.4 |
| 52 | confirmed: the order of checks | §10.1, §10.7 |
| 53 | confirmed: the internal `bh` column; no batch bound | §9.1, App. A18 |
| 54 | confirmed: feed RPCs in chunks; pages of one large batch | §9.1, §10.9 |
| 55 | confirmed: Δ divides 604 800; parameter bounds; client check | §3.1, §6.4(g) |
| 56 | as 41: confirmed, except the ShardDO pin log (round 7, delta M2) | §3.1 |
| 57 | confirmed (as 29); `closed` is monotonic | §9.3 |
| 58 | confirmed: the early window counts against the era's first day; 14 000 / 56 000 | §9.3, §13.2 |
| 59 | confirmed: the two defensive GAP cases | §9.4, §10.8, App. A20 |
| 60 | confirmed (as 12) | §9.6 |
| 61 | confirmed (merged with 19 and 20); round 8: the PoW nonce is bounded by 2^53 − 1 too, as the server already does; only the routing value is not; round 9: clients search the whole range, so `powSolve` changes; round 10: the search restarts with the new window when its window stops being current | §1.2, §3.1, §3.3, §10.2 |
| 62 | spec clarification: clock samples by minimum RTT; round 7: stale samples discarded, ties to the newest, the wall clock in §11.3 steps 6 and 8 | §3.1, §10.1, §11.3 |
| 63 | confirmed: streamed feed pages are not cached; truncation is detectable; round 7: **change the implementation**: one `RL_READ` token per started 4 MiB; round 8: of the batches' bytes (no page header), at most 64 tokens; round 10: the cap of 64 confirmed (R8-3) | §9.1, §9.7, §10.2, §10.9 |
| 64 | confirmed: `put` hashes before its synchronous transaction | §9.1 |
| 65 | confirmed (as 41): BlobReg `'delta'`, InboxDO `'slot'` | §9.2, §9.3 |
| 66 | confirmed: body length mismatches; malformed If-None-Match ignored | §9.7, §10.7 |
| 67 | confirmed (server): params never fails on D1; round 7: clients use `P* = max(P, ⌊log2(dirSeq/2080)⌋)`, the re-read is a MAY | §9.6, §10.6, §10.9 |
| R8-1 | confirmed: other routes MAY answer 500 (or 503 "storage unavailable") for a failed DO or R2 call; no code change | §10.1 |
| R8-2 | **change the implementation** (round 8's rule): a page that is not streamed takes one token, a streamed page `min(⌈b / 4 MiB⌉, 64)`, without the page header; round 11: the 9 MiB test's comment drops the header term too | §10.9 (round 11: §9.1, §9.7 and §10.2 worded alike) |
| R8-3 | **change the implementation** (round 8's rule): the cap stays 64, not 600; a deployment keeps `RL_READ` above it | §10.9 (round 11: was listed as §10.2, §10.9) |
| R8-4 | spec clarification: logs follow a content rule; their text and keys are implementation-defined; no code change | preamble, §3.1, §9.1, §9.5, §9.7 |
| R8-5 | confirmed: `wrongEraOnce(reported?)` defaults to the inbox clock's era; plan knob text and M6 test 7 variant | none (plan §2.1, M6 test 7) |
| R8-6 | confirmed: a stored-state check and a storage 5xx are not ordered; the fake's order conforms | §10.1 |
| R8-7 | confirmed: an unusable kept key reports `"pks"`; a throw of the recomputation fails the check | §6.6 |
| R8-8 | confirmed: a D with more members than B in a join reports `"pks"`; codes are diagnostics | none |
| R8-9 | confirmed: the D′ checks may run in any order; explicit orders stay normative; round 11: §6.4 orders e-validity's requests (none before the local rules pass, then (f), (g), (h)); round 12: **change the implementation**: the local rules include (g)'s `bundleSize` clause and (h)'s `B ≥ |D_e|`, so `claimShapeValid` checks `B ≥ m`; the `get` of the row itself is not ordered | §6.6, §6.4 (rounds 11–12) |
| R8-10 | confirmed: helper names and failure codes are implementation-defined | preamble |

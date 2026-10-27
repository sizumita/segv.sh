# segv.sh protocol v2 (stage 1)

This is the normative spec. It replaces protocol v1. Every implementation (the client crypto core `src/lib/proto.ts`, the
client engine, the Worker and the tests) MUST follow it byte for byte. The rationale lives in `docs/DESIGN.md`.
"Stage 1" is the first build stage of the Label-Indexed Store (LIS). The identifier of the protocol is `segv.sh/v2/` in
every stage, and §14 lists what later stages add. v1 wire formats are removed: a v2 implementation does not read,
write or serve them, and there is no migration (no v1 data exists).

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

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
   - if it publishes an invalid new descriptor, or withholds the new key from every member, membership freezes for
     the whole conversation, exactly as in v1, while messaging in the old epoch continues;
   - if it withholds the new key from some members only (or seals them REMOVED while the public `rm` keeps them),
     those members freeze. They keep messaging in the old epoch, where the other members still read them (§11.2), and
     their clients ask for the key (NEED_KEY, posted on every lane the others may be following). One of the most
     recently active members of the new epoch re-delivers it, which ends the freeze (§6.6).

   Validity never depends on the directory: every descriptor carries each member's signing key (§5.1).

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
  membership, attributably), withholds keys from some members (freezing them until re-delivery) or spams; anyone who
  fills the global inbox day cap (§9.3), which delays first contact and inbox deliveries for everyone; and directory
  key substitution by O (detected only by fingerprint comparison, TOFU pins (CONTACT, MEMBER) and disagreement with
  the keys in descriptors).

## 1. Primitives and encoding

### 1.1 Primitives

| name | definition |
| ---- | ---------- |
| `H(x)` | SHA-256 |
| `HKDF(ikm, salt, info, L)` | HKDF-SHA-256. `L` = 32 unless stated. |
| `HMAC(k, m)` | HMAC-SHA-256 |
| `AEAD` | XChaCha20-Poly1305 with a 24-byte **random** nonce and a 16-byte tag. `aeadSeal(k, pt, aad) = nonce ‖ ct ‖ tag`. `aeadOpen` is its inverse and throws on any failure. |
| `KEM` | X-Wing (`ml_kem768_x25519`, `@noble/post-quantum/hybrid.js`). `keygen(seed32)`; pk is 1216 B, sk 32 B, ciphertext 1120 B and shared secret 32 B. Decapsulating a ciphertext made for another key returns an unrelated secret (implicit rejection). Decapsulation **may throw** on a malformed ciphertext, for example a low-order X25519 component; whether it throws does not depend on the recipient's key. Every caller (inbox scan, SGB2 entries, hellos, wraps) MUST catch the throw and treat it as "does not open". |
| `SIG` | Ed25519 with a 32-byte seed as sk. Verification is **strict RFC 8032** (`zip215: false`): small-order keys and non-canonical encodings are rejected. |
| `random(n)` | n bytes from a CSPRNG |

### 1.2 Encoding

All integers are unsigned and big-endian.

| notation | meaning |
| -------- | ------- |
| `u8, u16, u32, u64` | Fixed width. Encoders MUST reject values out of range (no truncation). |
| `utf8(s)` | UTF-8 bytes. Decoders MUST reject invalid UTF-8. |
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

**Signed JSON rule** (directory only). A signed JSON object is sent as the exact UTF-8 text its signer produced.
Verifiers verify the signature over those bytes first and only then parse. Nobody re-serialises signed JSON. The
server additionally requires canonical form: the keys appear in the order the spec lists, there are no extra keys,
and `JSON.stringify(JSON.parse(text))` equals `text`.

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
  in a MEMBER self record (§7.2), so restores do not repeat the lookups.
- Descriptors carry each member's `sigPk` (§5.1). The directory supplies handles and `kemPk` only; it never decides
  whether a row, claim or descriptor is valid.

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
- `checkUserKeys(sigPk, kemPk)`: `sigPk` decodes to a point that is not of small order, and `KEM.encap(kemPk)`
  succeeds. The server runs it at registration and clients run it on every bundle they use.

### 2.2 Bundle (public identity)

```
bundleBytes = utf8(JSON.stringify({v:2, uid:b64u(uid), handle, sig:b64u(sigPk), kem:b64u(kemPk), ts:<ms>}))
bundleSig   = SIG.sign(enc("segv.sh/v2/bundle", bundleBytes), sigSk)
```

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

A query names only the top `p` bits (§10.6), so O learns one of about 32–128 accounts. The client bounds `p` by the
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

- `Δ` (u16 seconds) and `SKEW` (u16 seconds, the bound on clock differences between server components) are deployment
  parameters reported by `/api/v2/params`. They MUST NOT change within an era.
- Production values are `Δ = 10` and `SKEW = 2`. Tests MAY use `Δ = 1` and `SKEW = 0`.
- Era 0xFFFF is reserved and means "none".
- **The server's components are the time authority.** Each Durable Object uses its own `Date.now()`. Clients estimate
  server time as `local + offset`, where `offset` comes from the most recent server time seen: the `x-segv-now` header
  of any `no-store` API response (§10.1; never of a cacheable response, which may come from a cache with a stale
  header), `now` in `/api/v2/params`, or the realtime HELLO. Clients use it only to pick `E` and to
  time claim commits (§6.3), and never trust it alone: a claim's e-validity is checked from server answers (§6.4).
- A position on a lane is a pair `(E, n)`, ordered lexicographically. **NONE** = `(0xFFFF, 0xFFFFFFFF)` sorts before
  every real position.

### 3.2 Size classes

```
CLASSES   = [256, 1024, 4096, 16384]            cls = index 0..3; row body length = CLASSES[cls] + 40
```

| cls | plaintext | body | typical content |
| --- | --------- | ---- | --------------- |
| 0 | 256 | 296 | text ≤ 129 B, image reference, leave, need-key, key-ok, welcome, most self rows, snapshot pointers |
| 1 | 1024 | 1064 | text ≤ 897 B, claims, decoys, self rows with EPOCH_PENDING |
| 2 | 4096 | 4136 | text ≤ 3969 B, link hellos, large self rows |
| 3 | 16384 | 16424 | text ≤ 12000 B (the client limit), very large self rows |

Every row in a shard, whatever its content (message, claim, decoy, self record, snapshot pointer, hello), uses these
classes. P cannot tell them apart except by class.

| other object | length |
| ------------ | ------ |
| inbox invite body | 1120 + 24 + 256 + 16 = **1416** |
| SGB2 key bundle blob | 16 + 2088 + B·1192, with B ∈ {8, 32}: **11640** or **40248** |
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
| `type` | 1 TEXT, 2 IMAGE, 8 WELCOME, 16 CLAIM, 17 LEAVE, 18 NEED_KEY, 19 KEY_OK. Every other value is invalid. |
| `from` | The sender's index in `D_e` (§5.1). |
| `lane` | For lane rows (types 1, 2, 8, 17, 18, 19): equal to `from` (stage 1: one lane per member). For CLAIM: `0xFFFF`. |
| `n` | The slot within era `E`: the lane counter, or `k` for CLAIM. |
| `Eprev, nprev, prevh` | Lane rows only: the position of the sender's previous **valid** row on this lane in this epoch, and `prevh = t16(H(enc("segv.sh/v2/prev", label_prev, body_prev)))`, where `body_prev` is that row's stored body. For the first row of the lane in the epoch, and for every CLAIM: NONE and `ZERO16`. |
| `ts` | The sender's clock in ms (display only, §11.8). |
| `ckq, ck16` | The sender's latest verified checkpoint: `q` and `t16(C_q)`. `(0, 00…)` if it has none (§12.3, §12.4). |

A receiver accepts a conversation row only if all of the following hold:

- it decrypts and unpads;
- the length is `≥ 62 + 64` and `len` matches;
- `ver = 2` and `type` is valid;
- `from < |D_e|`;
- the label recomputes: `Lmsg_e(lane, E, n)` for lane rows with `lane = from`, or `Lctl_e(E, n)` for CLAIM;
- the content rules of its type hold;
- `sig` verifies under `D_e.members[from].sigPk`, the key carried in the descriptor (§5.1), never a directory key.

Content rules:

- **TEXT (1)**: 1..12000 bytes of valid UTF-8.
- **IMAGE (2)**: `id[32] | k[32] | u8 mime | u16 w | u16 h` (69 B), with `mime` 1 = image/webp or 2 = image/jpeg and
  `1 ≤ w, h ≤ 8192`.
- **WELCOME (8)**: a join payload `J` (§5.2), 90 B.
- **CLAIM (16)**: see §6.2.
- **LEAVE (17)**: `len = 0`.
- **NEED_KEY (18)**: `u32 e_f` (`len = 4`), with `e_f ≥ e` (the row's own epoch). Posted by a member frozen in epoch
  `e_f` because its key for `e_f + 1` was withheld, or it was sealed REMOVED while `rm` keeps it (§6.6). The same
  NEED_KEY is posted on the sender's lane of several epochs, so `e_f` names the epoch it is frozen in. It is not
  displayed.
- **KEY_OK (19)**: `len = 0`. Posted once by a member whose freeze ended, in the epoch it reached (§6.6 step 7). It is
  not displayed.

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
D = u8 ver(=2) | conv[16] | u32 e | prev[32] | by[16] | u64 ts | u8 m | (uid[16] | sigPk[32]) × m
    | u16 nlen | name[nlen]
dsig = SIG.sign(enc("segv.sh/v2/epoch", D, kc_e), sk_by)                 verified under D's own sigPk of `by`
```

The rules:

- `1 ≤ m ≤ 32`, and the uids are distinct.
- Every `sigPk` is a valid Ed25519 point that is not of small order (the `sigPk` half of `checkUserKeys`).
- `by` is one of the uids.
- `e < 2^32 − 1`: the last epoch could have no successor, so it is never created or accepted.
- `e = 0 ⇔ prev = ZERO32`. Otherwise `prev = H(D_{e−1})`.
- `ts ≤ 2^53 − 1`.
- `nlen = 0` means no name. Otherwise `name` is valid UTF-8 satisfying `validName`:
  - 1–64 code points, at least one of them `\p{L}\p{N}\p{P}\p{S}`;
  - none of `\p{Cc}\p{Cf}\p{Cs}` or U+061C, U+2028, U+2029, U+115F, U+1160, U+3164, U+FFA0, U+2800;
  - after NFKC and trimming leading whitespace, it does not start with `@`.
- Nothing follows `name`. The maximum length is 78 + 48·32 + 2 + 256 = 1872 B.

`members[i] = (uid, sigPk)` is member index `i`, which is also lane `i`. Clients display chosen names with a `#`
prefix. `H(D)` is SHA-256 over these exact bytes.

**Keys in D.** Every signature of a member of epoch e (lane rows, claims, `dsig` of `D_{e+1}`) is verified under the
`sigPk` that `D_e` lists for it. The directory is never consulted for validity, so a later registration, or a
directory answer that differs between readers, cannot change any member's decision. Where the keys come from:

- the creator (§6.1) and a committer adding members (§6.3) copy each new member's `sigPk` from that member's verified
  directory bundle;
- a committer copies every continuing member's `(uid, sigPk)` from `D_e` unchanged, and §6.6 requires it;
- a recipient accepts a first-contact or skip join only if D's `sigPk` for `D.by` equals the `sigPk` of `D.by`'s
  verified directory bundle (§6.7), and any join only if D lists self with self's own `sigPk`.

The directory supplies only handles and `kemPk`. A member whose directory bundle is missing, fails `checkUserKeys`, or
has a `sigPk` different from the one in D is shown as an unknown member (§11.2); its rows still verify under the key in
D.

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
  and MUST NOT use any other conversation. Receivers MUST accept a WELCOME in any conversation, from any verified
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

Every epoch, including e = 0, is defined by one bundle blob. The blob carries the encrypted descriptor and one key
wrap per index of the previous epoch.

```
blob = "SGB2" | u8 ver(=1) | u8 B | 00[10]                                        16-byte header
       | descCt                                                                    2088 B
       | entry_0 | … | entry_{B−1}                                                 B × 1192 B
descCt  = aeadSeal(dk_e, pad(D_e ‖ dsig_e, [2048]), aad = enc("segv.sh/v2/desc", conv, u32 e))     D ‖ dsig ≤ 1936 B
entry_i = seal(kemPk_{X_i}, "segv.sh/v2/rekey", enc(conv, u32 e, u16 i), EK_e)    real wrap, or a dummy seal (§1.4) of a 32-byte value
bundleId = H(blob) (raw 32 B; the blob id is b64u(bundleId)); bundleSize = len(blob)
```

- **B.** B = 8 if `max(|D_prev|, |D_e|) ≤ 8`, otherwise B = 32. For e = 0, B = 8 if `|D_0| ≤ 8`, otherwise 32.
- **Entries for e > 0.** For `i < |D_{e−1}|`, `X_i = D_{e−1}.members[i]` and the entry is a real seal to
  `kemPk_{X_i}`, taken from X_i's directory bundle after verifying it, checking `checkUserKeys`, checking that its
  `sigPk` equals the one in `D_{e−1}`, and comparing it with X_i's MEMBER and CONTACT pins (§7.3):
  - if `X_i ∈ D_e`, the sealed value is `EK_e`;
  - otherwise (the member was removed, or left and was dropped), the sealed value is **`REMOVED = ZERO32`**.

  If X_i has no usable bundle (an unknown member, §11.2), its entry is a dummy seal: a kept X_i is then frozen as
  withheld (§6.6) and can be re-delivered J through a 1:1 WELCOME; a dropped X_i still learns its removal from `rm`.
  Every `i ≥ |D_{e−1}|` is a dummy seal.
- **Entries for e = 0.** Every entry is a dummy. All members receive J.
- **New members** (in `D_e` but not in `D_{e−1}`) have no entry. They receive J.
- **Removal is public to the old epoch.** The claim that points at the bundle carries `rm` (§6.2), so every member of
  `D_{e−1}` sees who is dropped, and a REMOVED entry counts only where `rm` agrees (§6.6).
- **What the layout hides.**
  - P cannot list bundles (§8.2). Anyone who learns a bundle id learns only B.
  - Other members cannot open a member's entry.
  - A removed member learns that it was removed and, from `rm`, which old members stay. It cannot read `D_e`, so it
    does not learn who was added or the new name.
  - A random EK equals `ZERO32` with probability 2^−256.

### 5.5 Link hello

Bob (the link owner) creates `s`, writes a LINK record (§7.2), subscribes to `Tlink`, and shares the link. Links are
valid for at most 4 eras.

Alice opens the link:

1. Fetch Bob's bundle by uid prefix (§10.6), verify it, and run `checkUserKeys`.
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
   - `members = [(C, sigPk_C), …others]`, each other member with the `sigPk` of its verified bundle;
     `prev = ZERO32`, `by = C`;
   - the name, if any, is cleaned by the client before `validName`.
3. Compute `dsig_0` and build the SGB2 blob (all entries dummy).
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
9. Write DELIVERED records (§7.2) as deliveries succeed (§6.12).

The creator's sends in the new conversation are queued locally (the echo shows `sending`) until step 7 has completed.
So no row of the new conversation precedes the decoy, and every row of epoch 0 lies in an era ≥ `era(t_reg)` =
`E_start(0)`. If the session ends during steps 6–9, any device of the account finishes them (§6.11).

Steps 4–9 give a creation the same shape as a membership change (§6.3): a blob registration, a class-1 self row, one
class-1 row at least Δ+SKEW after the registration, then J deliveries and class-0 self rows. Nobody reads the decoy.
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
   - every continuing member keeps its `(uid, sigPk)` from `D_e`; every added member gets the `sigPk` of its verified
     directory bundle (resolved by handle);
   - `|D'| ≤ 32`, and `e+1 < 2^32 − 1`;
   - the name is carried over unless the commit renames.

   Then compute `dsig'`, `rm`, and the SGB2 blob. The entries need the `kemPk` of every member of `D_e`, fetched by
   prefix (§10.6) and checked as §5.4 says. Commits, creations (§6.1) and inbox deliveries of J (§6.12) are the only
   times a client needs other members' `kemPk`.
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
10. **Deliver J** for e+1 to the uids of EPOCH_PENDING (§6.12), writing DELIVERED records.

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

- **(a)** It decrypts under `mk_e` with AAD `enc("segv.sh/v2/msg", u16 E, label)`, the envelope parses with
  `type = 16`, `lane = 0xFFFF` and `n = k`, the content has exactly `137 + 6·|D_e|` bytes, and `m = |D_e|`.
- **(b)** `from < |D_e|`. Stage 1 policy: any member may commit.
- **(c)** `sig` verifies under `D_e.members[from].sigPk`, the key listed in `D_e` (§5.1). Whether the committer is
  registered in the directory, now or later, plays no part.
- **(d)** `prevD = H(D_e)`.
- **(e)** `rm` has no bit at or above `m`, and bit `from` of `rm` is 0.
- **(f)** Every cut satisfies `E_start(e) ≤ E_ℓ ≤ E`.
- **(g)** `bundleSize ∈ {11640, 40248}`, and BlobReg has `bundleId` registered with `size = bundleSize` and
  `t_reg < t_row`. `t_row` is the stored time of the claim row, taken from a `get` HIT or a CONFLICT, never from a
  realtime frame alone (§12.1). Evaluate with `GET /api/v2/blob/{id}/meta`:
  - **HIT** `{t, size}`: decide by the rule. Registrations are create-only and never change.
  - **MISS** `{now}`, where `now` is BlobReg's clock in seconds since T0:
    - If `now ≥ t_row`, (g) fails for good: any later registration gets `t_reg ≥ tpub(now) ≥ t_row`.
    - If `now < t_row` (only possible within SKEW of a batch boundary), (g) is undecided: retry after `t_row − now`
      seconds.
- **(h)** The blob, fetched with `GET /api/v2/blob/{id}`, hashes to `bundleId`, is `bundleSize` bytes long, and has the
  header `"SGB2"`, ver 1, `B ∈ {8, 32}` with `bundleSize = 16 + 2088 + 1192·B`, and `B ≥ |D_e|`.

Outcomes:

- If any of (a)–(f) fails, or (g) or (h) fails definitively, the row is **not e-valid**. It is ignored: it still
  occupies its slot and is part of the dense prefix. A row that does not decrypt gives the noise warning "ignored an
  undecryptable message". A row that decrypts but fails another rule gives the noise warning "ignored an invalid
  membership change".
- A network error, a timeout, a 5xx, a 404 for a blob whose registration was seen, or a MISS with `now < t_row` makes
  the row **undecided**. The reader retries with backoff (1 s, doubling to 60 s).

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
   - `V = REMOVED` (ZERO32): the committer told X privately that it was removed while the public `rm` keeps it. X is
     **frozen as excluded** with the critical warning "@by made an invalid membership change that excluded you;
     waiting for another member to re-send the key". The other members are not affected: if `D'` is valid they move
     to e+1 with X still listed, and X is repaired like a withheld member (steps 6–7).
   - The entry does not open, or `ekc_{e+1}(V) ≠ ekc`: the key was **withheld**, and X is **frozen as withheld** with
     the critical warning "a membership change was never delivered to you; the members of this conversation can no
     longer change" (the v1 text).
   - Otherwise `EK' = V`. Decrypt `descCt` with `dk_{e+1}(EK')`, unpad, and parse `D'` (it is self-delimiting; the
     last 64 bytes are `dsig'`). **The D′ checks** (against `D_e` and C) are all of:
     - `H(D') = hD`;
     - `D'.conv = conv`, `D'.e = e+1`, `D'.prev = H(D_e)`;
     - `D'.by = D_e.members[from].uid`;
     - `dsig'` verifies with `kc_{e+1}` under `D_e.members[from].sigPk` (the committer's key in `D_e`);
     - the old members in `D'` are exactly those with `rm` bit 0: `D' ∩ D_e = {D_e.members[j] : bit j of rm = 0}` (as
       sets of uids). In particular X ∈ D';
     - every continuing member has the same `sigPk` in `D'` as in `D_e`.

     If a check fails, the claim is **D′-invalid** and X is **frozen as invalid** with the critical warning "@by made
     an invalid membership change; the members of this conversation can no longer change". Every member who obtains
     `EK'` sees the same `D'` (it is bound by `hD` and `ekc`) and runs the same checks on data it already holds, so no
     member of e moves to e+1, not even later through a join (§6.7 step 5): membership is frozen for the whole
     conversation, as a v1 burned slot was, but the signer is known.
   - Otherwise X **accepts e+1**:
     - members `D'`; leaves carry over (§6.9); system lines (§11.9);
     - X subscribes to `T_{e+1}`. It sweeps every lane of e to its head before that lane leaves the expected-label
       map, and keeps one followed older lane per continuing member who has not yet posted in e+1 (§11.2);
     - X starts sending in e+1.

     X writes no self record for this epoch: restore re-derives it from the control lane, and snapshots carry it
     (§7.3).
5. **System lines from `rm`.** Every member of e that processes C, frozen or not, shows "`who(by)` removed `who(x)`,
   …" for the members whose `rm` bit is 1 and who had not left, and "keys rotated after `who(l)`, … left" for dropped
   leavers (§11.9). A removed member shows only "@by removed you".
6. **Frozen.** There are three frozen states: **withheld** and **excluded** (repairable, only X is affected) and
   **invalid** (D′-invalid, the whole conversation is affected). A frozen member:
   - stays in epoch e with `canSend = true`, keeps sending and receiving there, and applies the cut rule through
     `rm` (§6.8);
   - refuses its own membership changes with "the members of this conversation can no longer change; start a new
     conversation" (its control lane of e has a winner it cannot follow);
   - when frozen as **withheld or excluded** (never as invalid), posts **NEED_KEY** (type 18, content `u32 e`, §3.3).
     Let `a` be the first epoch of X's own run in this copy: its root epoch, or the epoch of its latest skip re-add
     (an EPOCH record with flag bit1). X posts one NEED_KEY on its own lane of every epoch `a, a+1, …, e`, oldest first,
     batched up to 16 rows per put. Followers keep exactly one older lane of a silent member, somewhere in that range
     (§11.2), so at least one copy reaches every member that can re-deliver. X does this once per (claim, account):
     not if its lane of e already holds a NEED_KEY with `t > t(C)`. The cost is `e − a + 1` class-0 rows, once per
     freeze;
   - leaves the frozen state when it accepts J(e+1) by the chained rule (§6.7 step 5). It then catches up the claim
     chain from e+1 (its own entries carry it to later epochs), and posts one **KEY_OK** (type 19) on its lane of the
     epoch it reached. A withheld or excluded member that receives a chained J whose `D` fails the D′ checks becomes
     frozen as invalid instead.
7. **Re-delivery.** A member Y that holds epoch `e_f + 1` and sees a valid NEED_KEY with content `e_f` from a member s,
   where Y holds the final winning claim C of `e_f`, s's `rm` bit in C is 0, and the NEED_KEY's stored `t > t(C)`,
   re-delivers J(e_f+1) to s (§6.12), unless one of these holds (Y re-checks them right before sending):
   - Y has seen a valid row of s in an epoch after `e_f` (a KEY_OK, or any other row);
   - a DELIVERED record of Y's account for `(conv, root, e_f+1, bundleId)` already lists s;
   - Y's rank is above 2.

   **Rank.** Order the members of `D_{e_f+1}` that are still in Y's current epoch, other than s, by the stored `t` of
   their latest valid row as Y has seen it (latest first; members without a row last, by index). Y's rank r is its
   position. Only ranks 0–2 re-deliver, so the most recently active members do it and lurkers never do. Views may
   differ slightly, so occasionally a fourth member also sends; duplicates are ignored (§6.7 step 3).

   Y waits `r × 60 s + random(0..30 s)`, re-checks, sends, and writes a DELIVERED record `(conv, root, e_f+1, bundleId,
   [s])` at once, so sibling devices and later sessions of Y's account do not send again. A device does not record a
   lane position past a NEED_KEY whose re-delivery it still has pending (§7.3). A freeze therefore costs at most three
   J copies, and usually one: once s is online it accepts the first J within about one inbox poll and posts KEY_OK,
   which stops the later ranks.

While the current epoch's winner is undecided, not yet final, or being processed, sends wait at most 30 s and then go
to e (§11.3). Commits wait until the control lane is settled.

### 6.7 Accepting a join (J from inbox, WELCOME or hello)

1. Fetch the blob `bundleId`. Check its hash, that its size is 11640 or 40248, and the header (`"SGB2"`, ver 1, B
   matching the size). On failure, give a noise warning and stop.
2. Decrypt `descCt` with `dk_e(EK)` and parse `D`. Check all of:
   - `D.conv = J.conv` and `D.e = J.e < 2^32 − 1`;
   - `dsig` verifies with `kc_e(EK)` under D's own `sigPk` for `D.by`;
   - self ∈ D, listed with self's own `sigPk`.

   Registration of the other members is not part of validity: a member whose bundle is missing, fails
   `checkUserKeys` or disagrees with D is shown as an unknown member (§11.2). If any check fails, give a noise warning
   and stop. Whether D's key for `D.by` is the directory's is checked in steps 5–6, only where it matters (skip and
   first contact).
3. **Duplicate.** If any copy already holds `(conv, e)` with the same `H(D)`, ignore the join.
4. **Settle the held copies.** For each held copy of `conv`, catch up the control lane of its current epoch k until
   either the winner is final and processed, or every slot is decided not e-valid and the current era has been
   probed. If a slot is still undecided or a winner not yet final, **park** the join: keep it, re-evaluate it after the
   next catch-up, and keep the inbox cursor before it (§11.5). A removed member or a leaver keeps following the control
   lane of its last epoch until such a winner is final and processed.
5. **Fit.** For each held copy, with current epoch k:
   - **Chained.** `e = k + 1`; the final winning claim C of k has bit self of `rm` = 0, `hD = H(D)`,
     `ekc = ekc_e(EK)` and `bundleId = J.bundleId`; and D passes every **D′ check** of §6.6 step 4 against `D_k` and C
     (`prev = H(D_k)`, `D.by = D_k.members[from].uid`, `dsig` under the committer's key in `D_k`, `D ∩ D_k` = the
     members `rm` keeps, unchanged keys for continuing members, self ∈ D). This is the claimed epoch: accept it into
     that copy. This happens on re-delivery to a withheld or excluded member, or when a welcome races the claim. If
     the claim matches but D fails a D′ check, the copy becomes (or stays) frozen as invalid and the join is dropped:
     a copy frozen as D′-invalid never accepts a chained join for that claim, and since D′ validity depends only on
     `D_k`, C and `D'`, it is the same for every member.
   - **Skip.** `e > k + 1`, and the final winning claim of k has bit self of `rm` = 1 (self was removed or dropped by a
     public, signed claim). Accept it on the signature alone (a re-add), provided D's `sigPk` for `D.by` equals the
     `sigPk` of `D.by`'s verified directory bundle (from a MEMBER record, or fetched by prefix, §10.6) and agrees with
     any CONTACT or MEMBER pin.
   - Otherwise it does not fit this copy. A held conversation never skips epochs.
6. **No fit.**
   - If the client holds no copy: this is a first contact. Accept it on the signature alone as a new copy whose root
     is `H(D)`, with the same `D.by` key check as a skip. A newly added member cannot verify the history before it. The
     copy is a **request** (§11.5) unless `D.by` is a contact (§7.3). The first verification of `D.by`'s bundle writes
     a MEMBER record (§7.2).
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
7. On acceptance, write CONV_JOIN or REQUEST (a new copy) or EPOCH (chained or skip) to the self lane at once (§7.3).
   For an accepted copy, subscribe to `T_e` and probe the control lane and the lanes from `E_start(e)`. A request is
   probed as §11.5 says.

### 6.8 Old-epoch acceptance (cuts and claim times)

A receiver accepts a valid lane row R of epoch e from `s = D_e.members[i]` at `(E', n')`, with stored time `t_R`,
iff this walk accepts it. For `j = e, e+1, …`, while the receiver holds the final winning claim `C_j` of epoch j (with
stored time `t_j`) and s is a member of `D_j` at index `i_j` (`i_e = i`):

- If bit `i_j` of `rm(C_j)` is 0, s continues into `D_{j+1}`. If the receiver holds `D_{j+1}`, continue with `j + 1`;
  otherwise (a frozen receiver) stop and accept.
- If the bit is 1 (s was removed or dropped at j+1), accept iff `t_R < t_j`, or `j = e`, `t_R = t_j` and R is before the
  cut of lane i in `C_e`. Stop.

If the walk ends without a removal, accept.

- A committer cannot erase a removed member's earlier rows with a low cut: rows with `t_R < t(C)` are always
  accepted. It cannot let a removed member keep posting with a high cut either: rows with `t_R > t(C)` are always
  dropped. The cut only decides rows in the claim's own Δ batch.
- A member removed at e+1 cannot post into e after the claim, nor into any earlier epoch after a later claim that
  removed it. Equal times count as "after" for later claims, which is the safe side.
- Valid rows of members who are still listed are shown even if they land late.
- Every device applies the rule to the same stored `t` and the same public `rm`, so live, restored and frozen views
  agree. Decisions are recomputed when the receiver learns a new final winner: a row that is now dropped is removed from
  the view and from `unread`. Dropped rows give no warning, and §11.3 step 7 marks one's own echo `failed`.

### 6.9 Leave and remove

- **Leave.** The leaver posts a LEAVE row (type 17) on its own lane of the current epoch and writes a LEAVE self
  record. The leaver stops sending, shows "you left the conversation" once, and sets `canSend = false`. It keeps
  following the control lane of that epoch until a final winner drops it (§6.7 step 4), but it **stops processing
  lane rows** of the copy (it no longer probes lanes, and ignores lane rows that arrive on `T_e`), so a WELCOME posted
  there would never be seen; senders therefore never use a copy in which the recipient left as a WELCOME channel
  (§6.12). Receivers record the leave in e and in every later epoch they hold whose members still include the leaver.
- **Rotation after a leave.** A remaining member MUST commit an epoch without the leavers (§6.3) before sending a TEXT
  or IMAGE in an epoch that lists a member who has left, unless it is frozen in that epoch or the epoch is
  `2^32 − 2` (§11.3). Clients MAY rotate proactively: the remaining member of rank r (by index among non-leavers) waits
  `r × 30 s + random(0..10 s)` after seeing the leave, and aborts if a claim appears first.
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
| e-valid claim with an invalid `D'` (bad `hD`, `dsig'` or `prev`, old members that disagree with `rm`, or a continuing member's key changed) | **Membership freezes for the whole conversation, as in v1**, and messaging in e continues. The difference: csig is valid, so the warning names the signer. A J for that `D'` sent afterwards fails the same D′ checks (§6.7 step 5), so the committer cannot move chosen members into the invalid epoch. |
| e-valid claim that withholds the key from every member | Everyone is frozen (the v1 "never delivered" state). Attributable in the same way. |
| e-valid claim that withholds the key from some members | Those members freeze, keep messaging in e (the others follow one lane of each silent member, §11.2), post NEED_KEY on every lane a follower may hold, and are re-delivered J(e+1) by one of the three most recently active members of e+1 (§6.6). The others continue in e+1. |
| REMOVED sealed to a member whose `rm` bit is 0 | That member is frozen as **excluded**, with a critical warning naming the committer, posts NEED_KEY and is repaired like a withheld member. A member cannot be removed covertly: if `D'` also omits it, `D'` is invalid for everyone (previous row). |
| A new member's J that never arrives | The committer's devices keep retrying the delivery (§6.12). If it still never arrives, the new member does not join, and the others continue, as in v1. |

**What still freezes or stops:**

- a conversation whose winning claim's signer made it unusable (invalid `D'`, or the key withheld from everyone);
- a member whose key was withheld, or who was sealed REMOVED against `rm` (until re-delivery);
- a member whose `rm` bit is 1 is removed, by design;
- a conversation at `e = 2^32 − 2` cannot change;
- a member who keeps filling control slots with junk delays committers by one probe per junk row, which costs it PoW
  for every row.

**What still progresses:** messaging in every case. Membership changes in every case except the two listed above.

**Why this is safe.** Who wins depends only on facts that every member of e evaluates identically:

- the rows' existence and stored `t`;
- the content readable with `mk_e`, including `rm` and the cuts;
- signatures, verified under the keys that `D_e` lists (§5.1);
- create-only blob registrations and the blob bytes (bound by `bundleId`);
- the sealing of past eras.

Nothing a member learns only from its own entry or from `D'` changes the winner, and the directory never enters
validity: an unregistered member who commits, and registers between two members' evaluations, gets the same verdict
from both. Whether `D'` is valid is the same for everyone who can open it, and a chained join is held to the same D′
checks, so no member enters an epoch that the others rejected. So two members of e follow different epochs e+1 only if
the server lies to one of them (§0.4, §12.6), or if a member's key was withheld, which that member sees and which
re-delivery repairs.

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

J is delivered for a creation, a commit and a re-delivery in the same way:

1. A recipient R gets a WELCOME row (§11.3) in a 1:1 copy only if the recipient provably holds that copy and
   processes its lanes. All of these must hold for self's accepted copy:
   - its current epoch c lists exactly self and R, and self is not frozen in c;
   - self has seen a valid row of R in epoch c (R can only post in an epoch it holds, and posting turns a request copy
     into an accepted one, §11.5, which is never dropped, §7.3);
   - R has not left (no LEAVE of R in c or an earlier epoch of the copy; a leaver stops processing lane rows, §6.9).

   A 1:1 that R has never posted in (for example one that is still a request on R's side, which R may drop after 4
   eras or when 64 newer requests push it out, §7.3) does not qualify.
2. Every other recipient gets an inbox invite. Invites are posted in random order, batched up to 32 per
   `POST /api/v2/inbox` (§10.5).
3. For a creation or a commit, every successful WELCOME or invite is recorded in a DELIVERED record (§7.2), batched per
   request. A commit without recipients writes one DELIVERED record with `a = 0` after switching, so every creation
   and commit ends with a class-0 self row. A re-delivery (§6.6 step 7) writes a DELIVERED record for
   `(conv, root, e_f+1, bundleId)` listing s, which no EPOCH_PENDING owns; it only stops repeats.
4. On 429 (rate limit), a per-row FULL (the day cap), a network error or a 5xx, the uids stay pending. The device
   retries with backoff, honouring `retry-after` (10 s, doubling to 10 minutes), and raises once per recipient the
   noise warning "@x has not been notified yet; retrying". Pending deliveries survive reloads and logouts through
   EPOCH_PENDING (§6.11).

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
- `Eprev`, `nprev` and `prevh` point to the previous self row (written by any device), using the same `prevh` formula
  as §3.3. The first row of the account uses NONE / `ZERO16`.
- `1 ≤ count ≤ 255`.
- A writer SHOULD batch the records it produces in one burst (for example all joins found by one inbox poll) into one
  row, up to cls 3. This keeps self-lane writes from being amplified by spam.
- A self row that carries EPOCH_PENDING is padded with `pad(S, [1024, 4096, 16384])`, so it is class 1 even when it
  would fit class 0. Creations and commits of any size then write the same classes (§13.1).
- Self rows are not signed: `kS` is known only to the account.
- Readers ignore unknown `rtype` values (forward compatibility), but MUST reject malformed known records.

### 7.2 Record types

`root` identifies a conversation **copy**: `root = H(D)` of the first epoch the account accepted in that copy (§6.7).

| rtype | name | content |
| ----- | ---- | ------- |
| 0x01 | CONV_JOIN | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | rootBy[16] | u8 via` (137 B). An accepted copy. `via`: 1 = created, 2 = inbox, 3 = welcome, 4 = hello, 5 = request accepted. |
| 0x02 | EPOCH | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u16 claimE | u32 claimK | u8 flags` (127 B). Epoch e ≥ 1 of this copy. `(claimE, claimK)` is the position of the winning claim on `Lctl_{e−1}`, or NONE for a skip re-add. `flags`: bit0 = accepted by a chained join, bit1 = accepted by a skip join, both 0 for an epoch derived from the account's own bundle entry. Other bits are 0. |
| 0x03 | EPOCH_PENDING | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u32 t_reg | u8 a | uid[16] × a` (125 + 16a B). Creation (e = 0) or commit intent: the uids that need J. |
| 0x04 | LEAVE | `conv[16] | root[32] | u32 e` (52 B) |
| 0x05 | CONTACT | `uid[16] | pin[32]` (48 B). TOFU pin of the bundle (§2.2). |
| 0x06 | LINK | `s[16] | u16 Ecreated | u16 Eexpires | u8 flags` (21 B). bit0 = one-shot, bit1 = revoked. |
| 0x07 | PREFS | `u8 key | value[len−1]`. No keys are defined in stage 1. The latest value per key wins. |
| 0x08 | HEADS | `u16 Ein | u32 relIn | u16 c | entry × c`, with `entry = conv[16] | root[32] | u32 e | u64 lastTs | u16 ctlE | u32 ctlCnt | u8 m | (u16 E | u32 cnt) × m | u8 f | (u32 ef | u16 ℓ | u16 E | u32 cnt) × f` (71 + 6m + 12f B per entry). Processed positions (§7.3). `c = 0` records only the inbox cursor. |
| 0x09 | CONFIRMED | `conv[16] | root[32]`. The copy is corroborated (§6.7). |
| 0x0A | DELIVERED | `conv[16] | root[32] | u32 e | bundleId[32] | u8 a | uid[16] × a` (85 + 16a B). These uids have been sent J for that EPOCH_PENDING, or, when no EPOCH_PENDING of the account has this key, re-delivered J(e) (§6.6 step 7). |
| 0x0B | REQUEST | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u32 t_reg | rootBy[16] | u8 via | u16 dlen | desc[dlen]` (143 + dlen B), where `desc = D ‖ dsig` of epoch e. A request copy (§11.5). |
| 0x0C | DESC | `conv[16] | root[32] | u32 e | u16 dlen | desc[dlen]` (54 + dlen B, `dlen ≤ 1936`), `desc = D ‖ dsig`. The descriptor of epoch e of the copy, so a restore needs no bundle fetch for it. |
| 0x0D | MEMBER | `uid[16] | sigPk[32] | pin[32] | u8 hlen | handle[hlen]` (81 + hlen B, `3 ≤ hlen ≤ 20`). A co-member's directory bundle as self verified it (`pin` as in §2.2), so restores need no directory lookup for that member (§11.4). |
| 0x20 | SNAP | `blobId[32] | key[32] | u32 size | u16 Eh | u32 nh` (74 B). Allowed only in rows at `Lsnap`. |

**HEADS positions.** A HEADS entry describes epoch e of the copy as processed by the writing device:

- `(ctlE, ctlCnt)`: every era of the control lane before `ctlE` was observed sealed, and every slot before
  `(ctlE, ctlCnt)` was decided not e-valid;
- `(E, cnt)` for lane ℓ (one per member of `D_e`): every row of lane ℓ before `(E, cnt)` was fetched and processed
  (joins, leaves, NEED_KEY and KEY_OK included, and every re-delivery a NEED_KEY there triggered is done or recorded);
- the `f` followed lanes of older epochs (§11.2), each with its processed position (same rule);
- `lastTs`: the copy's `lastTs` (§11.8), used to rank copies for the initial history (§11.4).

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
| LEAVE | `(conv, root, e)` | |
| CONTACT | `uid` | the first one wins (see the pin check below) |
| LINK | `s` | |
| CONFIRMED | `(conv, root)` | |
| HEADS | per `(conv, root)` | the latest entry wins; `(Ein, relIn)` takes the maximum. A record may hold any subset of copies. |

**Contacts.** A CONTACT is written for every user that self resolves by handle (creation, add), and for `D.by` of a
copy when self first posts in it or opens it (§11.5). An incoming join never creates a contact. A second CONTACT for the
same uid with a different pin, or a directory bundle whose pin differs from the pinned one, raises the critical warning
"the public keys of @x changed".

**Members.** A MEMBER is written the first time self verifies the directory bundle of a uid that appears in a D it
holds (as an accepted copy's member, or as `D.by` of a request) and finds its `sigPk` equal to the key in that D. A
CONTACT for a resolved handle comes with a MEMBER. The same pin rule applies: a second MEMBER, a CONTACT or a later
directory bundle with a different pin for the same uid raises "the public keys of @x changed". A member of a D whose
key differs from its MEMBER's `sigPk` is shown as an unknown member (§11.2), and raises the same warning. MEMBER
records exist so that restores need no directory lookups (§11.4); they never affect validity.

**Copy keys.** The local view key of a copy is `b64u(conv)` for the copy whose CONV_JOIN or REQUEST comes first.
Later copies get `b64u(conv) + "~" + i` (i = 1, 2, … in that order). Snapshots keep the original self-lane order of
these records (§7.4), so every device numbers copies the same way.

**When to write.**

- A device writes a record when it causes the event: a creation (CONV_JOIN and EPOCH_PENDING in one row), a commit
  (EPOCH_PENDING, later DELIVERED), an accepted join (CONV_JOIN, REQUEST or EPOCH), a leave, a corroboration
  (CONFIRMED, written before any CONV_JOIN in the same row), or an accepted request (CONV_JOIN with `via = 5`). New
  CONTACT and MEMBER records ride in the next HEADS row; the device uses them locally at once. The MEMBER for a
  request's `D.by` rides in the REQUEST's row. A re-delivery writes its DELIVERED record at once (§6.6 step 7).
- Epochs accepted through the account's own bundle entry are **not** written as self rows: restore re-derives them from
  the control lane (§11.4), and snapshots carry them. So no self row follows a claim observed from another member
  (§13.1).
- Records are written at once, without waiting for siblings. Duplicates from sibling devices are harmless.
- **Durability order.** The joins found by one inbox poll are written in one self row together with a HEADS record
  (`c = 0`) that moves the cursor past them. No HEADS record or snapshot records an inbox cursor or a lane position past
  a join, leave or J that is not yet durably recorded (CAS OK), nor past a NEED_KEY whose re-delivery this device
  still has scheduled (§6.6 step 7). A failed write is retried before the cursor advances.
- **HEADS** is written in every snapshot; as a self row at most every 30 minutes (after a random delay of up to 5
  minutes), when processed positions advanced or new CONTACT or MEMBER records wait; and once right after
  registration, with the cursor at the current inbox slot. A writer splits HEADS over several records and rows so that
  each row fits cls 3.
- Writes use CAS at the first empty slot. On CONFLICT the device applies the occupant (if it opens under `kS`) and
  retries at `n+1`. On WRONG_ERA it writes at `(E', 0)`.

### 7.4 Snapshots

A snapshot compacts the self lane into one blob:

```
S2   = "SGS2" | u8 ver(=1) | u16 Eh | u32 nh | u64 ts | u32 count | record × count       (records as in §7.1)
blob = aeadSeal(skey, padme(S2), aad = utf8("segv.sh/v2/snapshot")); skey = random(32); id = b64u(H(blob))
```

- `(Eh, nh)` is the last self-lane position whose effects are included, or NONE.
- The records are the compacted state, with CONV_JOIN and REQUEST records in their original self-lane order:
  - per accepted copy: its CONV_JOIN, an EPOCH for every held epoch (those derived from the account's own bundle entries
    included, with flags 0), a DESC for the current epoch and for every epoch that holds a followed lane, every
    EPOCH_PENDING that is not dead with its DELIVERED records, LEAVE, CONFIRMED, and the latest HEADS entry.
    Re-delivery DELIVERED records (no EPOCH_PENDING) are dropped: the HEADS entry already covers their NEED_KEY rows;
  - the live REQUESTs (at most 64);
  - every CONTACT;
  - the MEMBER record, where one exists, of every uid listed in a D carried by a DESC or a live REQUEST, or held as a
    CONTACT (other MEMBER records are dropped, and looked up again if ever needed);
  - every LINK that has not expired;
  - the latest PREFS per key;
  - a HEADS record with the inbox cursor.
- **Pointer.** A self row whose only record is `SNAP{blobId, skey, size, Eh, nh}` is put at `Lsnap(E_now, j)`, where
  `j` is the first empty slot. Slots are dense per era, and the first writer of a slot wins.
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
`blockConcurrencyWhile`: if the era has not ended, it sets the alarm to `min(getAlarm(), due)`, where `due` is the
earliest of the seal time and an open batch's close time. A DO of an era that has already ended arms nothing; it seals
synchronously in `prepare()`. Every write that opens a batch arms `min(current alarm, batch due)` in the same
synchronous block as the commit.

### 9.1 ShardDO (`shard/v2/{E}/{i}`, SQLite; stage 1 has one per era, i = 0)

```sql
CREATE TABLE meta  (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
  -- 'state' 'open'|'sealed' | 'last_t' u32 | 'open_t' u32 (absent = no open batch)
  -- 'closed_t' u32 (t of the newest closed batch; absent = none) | 'head' 32 B (ZERO32 initially) | 'delta' u16
CREATE TABLE row   (id INTEGER PRIMARY KEY,
                    v BLOB NOT NULL CHECK (length(v) = 8), label BLOB NOT NULL CHECK (length(label) = 16),
                    t INTEGER NOT NULL, cls INTEGER NOT NULL CHECK (cls BETWEEN 0 AND 3), body BLOB NOT NULL,
                    UNIQUE (v, label));
CREATE INDEX row_t ON row (t, label);            -- batch recomputation + public feed (no arrival order is exposed)
CREATE TABLE batch (t INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
```

Bodies (296–16 424 B) live in a rowid table: SQLite advises against WITHOUT ROWID for rows this large. The rowid is
internal and never exposed; feed and batches order by `(t, label)`.

**Era state.**

- `now` = `Date.now()`, and `s = sec(now)`.
- `prepare()` runs first in every RPC: if `now ≥ end(E) + SKEW·1000` and the state is open, close the open batch and
  persist `state = sealed`, in one transaction.
- The seal alarm, due at `end(E) + SKEW·1000`, does the same.
- `MISS(sealed = 1)` is returned only once `state = sealed` is persisted.
- **Accept window.** Writes are accepted while `start(E) − SKEW·1000 ≤ now < end(E)`. Opening SKEW early means two
  shards whose clocks differ by at most SKEW never both refuse a write at an era boundary.

**Batches.**

- `closeBatch(t0)` requires `t0 > closed_t`. It reads `SELECT label, cls, body FROM row WHERE t = t0 ORDER BY label`.
  Each leaf is `leaf(enc("segv.sh/v2/leaf", u16 E, label, u32 t0, u8 cls, H(body)))`. It computes `root` and `head'`,
  inserts the batch row, sets `head = head'` and `closed_t = t0`, and deletes `open_t`.
- An alarm is due at `T0 + (open_t + Δ)·1000 + 1000` while a batch is open. When it fires, close the batch if
  `tpub(now) > open_t`. Seal alarms and batch alarms share the one DO alarm: always arm the earliest that is due.

**`put(E, i, rows: {v, label, cls, body}[])`** returns one result per row. It runs synchronously inside
`transactionSync`, with no await:

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
  else:  INSERT row (v, label, t, cls, body); open_t = t; last_t = t; OK(t)
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

**`feed(E, i, after_t, budget)`** returns closed batches with `t > after_t` in ascending order. Each batch carries its
rows from `row_t`, ordered by label. The DO stops at the first batch that would exceed `budget` bytes, but always
returns at least one batch. This is the public enumeration of the database.

**Retention and capacity.** Old era DOs are kept and stay readable. Paging into R2 and deletion come in stage 2. A DO
stores at most 10 GB, and one object handles about 1 000 requests/s, so a single shard per era bounds stage 1 (§13.2
item 13). The CheckpointDO logs (`logErr`) when a shard's `size` passes 4 GiB. The emergency path is S = 2 by
parameter for the next era, since routing by `v` already exists (stage-2 work).

### 9.2 BlobRegDO (`blobreg/v2`, SQLite, one instance)

```sql
CREATE TABLE meta  (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;   -- 'last_t', 'open_t', 'closed_t', 'head', 'hw'
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
CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;     -- 'head', 'closed_hw', 'ended'
CREATE TABLE inv  (id INTEGER PRIMARY KEY, bucket INTEGER NOT NULL, rel INTEGER NOT NULL,
                   eid BLOB NOT NULL CHECK (length(eid) = 16), body BLOB NOT NULL CHECK (length(body) = 1416),
                   UNIQUE (bucket, eid));
CREATE INDEX inv_rel ON inv (bucket, rel, eid);
CREATE TABLE cnt  (bucket INTEGER NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (bucket, day)) WITHOUT ROWID;
CREATE TABLE slot (rel INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
```

The slot clock uses milliseconds since T0 and `Δin` = `INBOX_SLOT` seconds (a deployment parameter; production 10,
tests 1). Let `D = Δin·1000` and `ms = now − T0`.

```
closed  = max(⌊ms / D⌋, closed_hw)                     reported to readers; every row with rel ≤ closed is final
rel     = max(⌊(ms + j) / D⌋ + 1, closed_hw + 1)        j uniform in [0, D), drawn per row and never stored
```

- `closed_hw` is the largest `closed` ever reported. A read that reports a larger value persists it first (at most one
  write per slot). So `rel > closed_hw` and `rel > ⌊ms/D⌋` always hold: a new row never lands in a slot a reader has
  already passed, even after a clock step back.
- **Era end.** Posts are accepted while `start(E) − SKEW·1000 ≤ now < end(E)` and `ended` is not set. Once
  `now ≥ end(E) + SKEW·1000`, `prepare()` (or the alarm) persists `ended = 1`. From then on `closed` is the maximum
  `rel` of the era (all rows are final), and only then may the Worker mark responses immutable (§10.5).

**`post(E, bucket, rows: {eid, body}[])`** (1..32 rows) returns one result per row:

- If posts are not accepted (above), the whole call returns `WRONG_ERA(era(now))`.
- If `(bucket, eid)` exists with the same body, the row's result is its `rel` (an idempotent retry). With another body:
  `CONFLICT`.
- If `cnt(bucket, ⌊sec/86400⌋) ≥ INBOX_DAY_CAP` (2000): `FULL`.
- Otherwise insert, increment `cnt`, and return `OK(rel)`.

**`read(bucket, after, limit)`** returns `{closed, rows}`:

- `closed` as above.
- `rows` are those with `after < rel ≤ closed`, ordered by `(rel, eid)`.
- Whole `rel` groups are always returned. Once at least `limit` rows have been returned, the read stops before the
  next group, and `more = 1`.

**Slot commitments.** Before `read` and `head`, close every closed slot with rows that has no `slot` row yet. Each
leaf is `leaf(enc("segv.sh/v2/leaf/inbox", u16 E, u32 bucket, u32 rel, eid, H(body)))`, ordered by `eid`, and the
chain uses `t = rel`.

**Retention.** Clients never read inbox eras older than `E_now − 3`, and the Worker answers 410 for them. The rows are
still stored (and committed).

**Size under attack.** The day cap bounds an era to 14 000 rows (about 20 MB), and the 4 retained eras to 56 000
rows (about 80 MB, 56 000 X-Wing decapsulations). Only a device with no inbox cursor reads that much (§11.5).

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
    rows and at most 16 MiB.

**Limits.**

- 8 sockets per client tag, and 20 000 sockets in total. Both are counted with `getWebSockets(tag)` and
  `getWebSockets()`, without deserialising attachments.
- 256 topics per socket, and 250 000 (topic, socket) pairs in total.
- Per socket, at most 30 SUB/UNSUB frames and 2 048 topic changes per minute (counted in the attachment, with `win` =
  the current minute).
- Frames up to 8 KiB.

With these limits the index (about 120 B per pair), the ring and the attachments stay well under the 128 MB memory of an
isolate.

**`fetch(upgrade)`** (from the Worker only):

1. Take the client tag from `x-segv-client` (32 hex characters, else "none").
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

**Durability.** Nothing about topics or rows is persisted. After a restart, `boot` changes, so a RESUME gets GAP.

### 9.5 CheckpointDO (`ckpt/v2`, SQLite, one instance)

```sql
CREATE TABLE cp   (q INTEGER PRIMARY KEY, sec INTEGER NOT NULL, hd BLOB NOT NULL, heads BLOB NOT NULL,
                   C BLOB NOT NULL, sig BLOB NOT NULL);
CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;   -- 'final:<cid>', 'blobreg:hour', 'blobreg:head'
```

An alarm runs every 60 s and is re-armed in the same commit. The constructor arms it inside `blockConcurrencyWhile`
when no alarm is set. The Worker calls the DO's `ensure()` at most once per isolate (a module-level flag), never per
request.

**Collecting heads.**

- Collect `(cid, head)` from:
  - `shard/{E_now}/0` and `inbox/{E_now}/0`;
  - `shard/{E_now−1}/0` and `inbox/{E_now−1}/0`, until they are sealed and their final head has appeared once;
  - `blobreg`, **at most once per hour**: on the first alarm of each UTC hour the DO reads the registry head and stores
    it; every other checkpoint reuses the stored value. P therefore learns at most, per hour, whether any blob was
    registered;
  - `dirlog`, read from D1 (`SELECT seq, h FROM dirlog ORDER BY seq DESC LIMIT 1`, or ZERO32 when empty).
- A component that fails to answer keeps its previous head.
- Sort the list by cid (byte order).
- Log (`logErr`) when a shard reports `size` above 4 GiB.

**Building and signing.**

```
hd  = H(enc("segv.sh/v2/ckpt/heads", [cid_1, head_1, cid_2, head_2, …]))
C_q = H(enc("segv.sh/v2/ckpt", C_{q−1}, u32 q, u32 sec, hd))            C_0 = ZERO32, q starts at 1
sig = SIG.sign(enc("segv.sh/v2/ckpt-sig", u32 q, C_q), SRV_SK)
```

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
unavailable, writes return 503 and reads return 503.

**Prefix reads.** A lookup of the top `p` bits equal to `x` reads
`WHERE hpre BETWEEN ?lo AND ?hi [AND uid > ?after] ORDER BY uid LIMIT 256` (or `upre`), with
`lo = x · 2^(32−p)` and `hi = lo + 2^(32−p) − 1`. Both are computed with arithmetic, never with 32-bit shifts
(`1 << 32` is 1 in JavaScript). `p = 0` covers the whole table. The user count `P` is derived from `dirmeta.users`,
never from `count(*)`.

### 9.7 Hardening (all endpoints)

These carry over from v1:

- `APP_HOSTS` host pinning: other hosts get 421 on `/api/*` and a 308 to the canonical host on pages;
- HSTS on https; `nosniff` and `no-referrer` on every response;
- `workers_dev: false` and `preview_urls: false`;
- Workers invocation logs disabled;
- `console.error` lines redact ids and addresses (`logErr`);
- an `HttpError` cancels any request body that was not read;
- a rate limiter error fails closed with 503;
- request bodies are capped by both the declared and the actual length.

New in stage 1:

- **Era bounds before any DO.** The Worker checks `E` with its own clock before it routes a request, so nobody can
  instantiate (and arm alarms in) arbitrary era objects. With `lo = era(now − SKEW·1000)` and
  `hi = era(now + SKEW·1000)`:
  - put rows and inbox posts need `lo ≤ E ≤ hi`, else WRONG_ERA (put) or 409 (inbox), without a DO call;
  - get, feed, era and inbox reads with `E > hi` get NO_ERA (get) or 400/404, and with `E < E_FIRST` (a deployment
    parameter: the era of the first deploy) get `MISS(sealed = 1)` (get) or 404, without a DO call.
- **Cache before limits.** Immutable responses (blob GETs, ended inbox eras, `/ckpt/{q}`, immutable feed pages) and the
  short-lived inbox tail (§10.5) are served from `caches.default` when present, before the rate limiter. The Worker
  strips `x-segv-now` before `cache.put` and stamps a fresh `x-segv-now` on the response it returns, after the cache
  lookup (§10.1).

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
- **Server time.** Every `/api/v2/*` response carries `x-segv-now: <server ms>`, set on the response object the Worker
  returns, after any `caches.default` lookup, and never stored in `caches.default` (§9.7). Clients update their clock
  offset from it (taking the midpoint of the request) **only for responses whose `cache-control` is `no-store`**: a
  `public` response (blob GETs, `/ckpt/{q}`, inbox reads, immutable feed pages) may be replayed by the browser's HTTP
  cache with the header it was first stored with, possibly weeks old. Every API call a client makes regularly (`get`,
  `put`, params, `blob/meta`, directory, `ckpt/latest`) is `no-store`, so the estimate of §3.1 never goes stale.
- **Hardening.** §9.7 applies to every response, including the era bounds and the cache-before-limits rule.

**Status codes:**

| code | meaning |
| ---- | ------- |
| 200 / 201 | success (put and get carry per-row status inside a 200) |
| 400 | malformed request (bad layout, length, encoding, class, count, id or handle) |
| 403 | missing, malformed, stale or insufficient proof of work |
| 404 | unknown path, user, uid or blob |
| 405 | wrong method |
| 409 | conflict: handle or uid taken, duplicate wrap, inbox wrong era (`{error, era}`), directory prefix bits out of range (`{error, p}`) |
| 410 | inbox era older than `E_now − 3` |
| 411 / 413 | blob without Content-Length / too large; body over the endpoint cap |
| 421 | host not in `APP_HOSTS` |
| 426 | `/api/v2/rt` without an upgrade |
| 429 | rate limited, or too many sockets from this client (`retry-after`) |
| 503 | rate limiter or D1 unavailable, global socket cap, missing server secrets |
| 500 | internal error |

### 10.2 Proof of work and rate limits

```
window = ⌊serverNowMs / 600000⌋
pre    = H(enc("segv.sh/v2/pow", scope, u32 window, digest))
valid  ⇔ leadingZeroBits(H(pre ‖ u64 nonce)) ≥ powDifficulty(scope, base, bytes)
header   x-segv-pow: "<window>.<nonce>"      (^\d{1,12}\.\d{1,16}$; window ∈ {current, current−1})
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
params.

**Per-IP rate limits.** The key is the IPv4 address or the IPv6 /64 (an IPv4-mapped address counts as IPv4). Keys are
never stored.

| binding | limit | endpoints |
| ------- | ----- | --------- |
| `RL_WRITE` | 60 / 60 s | register, wraps, put |
| `RL_INBOX` | 10 / 60 s | inbox post (one token per POST of up to 32 invites) |
| `RL_BLOB` | 20 / 60 s | blob PUT |
| `RL_READ` | 600 / 60 s | get, inbox read, directory reads, dirlog, blob GET and meta, ckpt, feed, era, rt upgrade |

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
4. Computes `v(E, label)` and `shard`, groups rows by `(E, shard)`, and calls each ShardDO's `put`.
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

The Worker groups keys by `(E, shard)`, preserves the order, and returns SKIPPED for every body-mode key after the
budget is reached. `MISS(sealed = 1)` is final: era E can no longer gain that row. Keys with `E < E_FIRST` get
`MISS(sealed = 1)` and keys with `E > era(now + SKEW)` get NO_ERA, both without a DO call (§9.7).

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

Errors: 410 for `E < E_now − 3`, and 400 for `E > era(now + SKEW)` or `bucket ≠ 0`.

Cache rules:

- Once the InboxDO has persisted `ended` (§9.3), a response for that era with `more = 0` is immutable
  (`public, max-age=31536000, immutable`).
- A response for the current era is `public, max-age=Δin`. The Worker serves it from `caches.default`, keyed by
  `(E, bucket, after, limit)`. Every row up to the reported `closed` is final, so a response at most Δin old is still
  correct, and most clients poll with the same `after` (the last `closed`).

### 10.6 Directory (JSON)

**`POST /api/v2/register`** (PoW `register`; `RL_WRITE`; body ≤ 64 KiB):

- Body `{"bundle": text, "sig": b64u, "wraps": [{"record": text, "sig": b64u}, …1..4]}`.
- The server checks the canonical bundle, the field sizes, the handle regex, `bundleSig`, and `checkUserKeys`. For
  every record it checks canonical form, sizes, `uid` equal to the bundle's, `recordSig` under the bundle key, and
  that ids are distinct.
- It writes the user, the wraps and the dirlog entries atomically (§9.6).
- Response `{"dirseq": n}` on success. 409 if the handle or uid is taken.

**`POST /api/v2/wraps`** (PoW `wrap`; `RL_WRITE`; body ≤ 16 KiB):

- Body `{"record": text, "sig": b64u}`.
- 404 for an unknown uid. 400 for a bad signature or more than 64 wraps. 409 for a duplicate `(uid, id)`.
- Response `{"dirseq": n}`.

**User lookups.** `GET /api/v2/dir/h/{p}/{x}` and `GET /api/v2/dir/u/{p}/{x}`:

- `p` is the number of prefix bits (decimal, 0..32) and `x` the prefix value (decimal, `0 ≤ x < 2^p`).
- The server accepts `p ∈ [0, min(32, P+1)]`, where `P = max(0, ⌊log2(users / 32)⌋)` is reported in params and
  `users` is `dirmeta.users`. Otherwise it answers 409 `{error, p: P}`.
- Rows are those whose `hpre` (or `upre`) has the top p bits equal to x (a `BETWEEN` range, §9.6), ordered by uid.
  Pass `?after=<uid>` to page; at most 256 per page.
- **Client choice of p.** The client uses `p = max(0, min(P − 1, ⌊log2(dirSeq / 64)⌋, 16))`, where `dirSeq` is the
  dirlog head `seq` (read once per session, before its first prefix lookup, from `/api/v2/dirlog`; every account adds
  at least two dirlog entries). An operator that inflates `P` to make lookups exact must also inflate the public,
  audited dirlog. If a page for `p ≥ 1` returns fewer than 8 users, the client gives the noise warning "the directory
  answered fewer accounts than expected". Clients cache prefix responses for the session.
- **When clients look up.** A prefix response holds `users / 2^p` bundles (about 64–128, each about 1.9 KB, so
  120–240 KB). Clients therefore look a user up only to resolve a handle (creation, add), to verify a co-member or a
  joiner's `D.by` the first time (then a MEMBER record is written, §7.3), and to fetch `kemPk` when committing or
  sending J by inbox (§6.3, §6.12).
  Restores and catch-ups use MEMBER records and make no lookup for known members (§11.4).
- Response: `{"p": p, "users": [{"uid", "handle", "bundle", "sig", "regEra", "dirseq"}], "more": bool}`.
- Clients MUST verify every bundle they use (`verifyBundle`, `checkUserKeys`, `uid` and `handle` match), filter
  locally, and compare with their CONTACT and MEMBER pins (§7.3).

**`GET /api/v2/dir/uid/{uid}`** is the exact lookup of one user. Clients use it only for their own account.
Response: `{"user": {…} }`, or 404.

**`GET /api/v2/dir/wraps/{id}[?uid=<b64u>]`** returns `{"wraps": [{"uid", "record", "sig", "dirseq"}]}`:

- at most 64 records, oldest (lowest dirseq) first;
- `id` is 1..1023 bytes and `uid` 16 bytes;
- an unknown id returns an empty list (status 200).

**`GET /api/v2/dirlog?after=<seq>&limit=<1..1000>`** returns `{"entries": [{"seq", "kind", "ref", "h"}],
"head": {"seq", "h"}}`. It is the public audit log of the directory.

### 10.7 Blobs

**`PUT /api/v2/blob/{id}`** (`id` = 43 b64u characters for 32 bytes; PoW `blob`; `RL_BLOB`):

- Content-Length is required (411 without it). Over 12 MiB → 413. Below 41 bytes → 400.
- If BlobReg already has the id, respond `201 {"id", "size", "t"}` without reading the body.
- Otherwise:
  1. Stream the body into R2 `b/{id}` through a fixed-length stream with `sha256 = id`. A mismatch → 400. In a
     concurrent put, the upload counts only if the stored digest equals the id.
  2. `BlobReg.register(id, size)`.
  3. Respond `201 {"id", "size", "t"}`, where `t` is `t_reg` in seconds since T0.

**`GET /api/v2/blob/{id}`** returns the raw bytes (served from `caches.default` when present, §9.7):

- headers: `cache-control: public, max-age=31536000, immutable`, `etag`, `content-disposition: attachment`,
  `content-security-policy: default-src 'none'; sandbox`, `cross-origin-resource-policy: same-origin`;
- `If-None-Match` is honoured with 304;
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
ROWS    = 0x81 | u16 n | (u64 seq | topic[16] | u16 E | label[16] | u32 t | u8 cls | body[CLASSES[cls]+40]) × n
GAP     = 0x82 | u64 since_seq                                    rows published after since_seq may have been missed
RESUMED = 0x83                                                    the replay for RESUME is complete
```

**RESUME.** If `boot` equals the server's boot and the ring still holds every row with `seq > since_seq`, the server
replays those rows whose topic is in the set, as ROWS frames, then sends RESUMED. Otherwise it sends
`GAP(since_seq)`. In both cases the RESUME's topic set is installed. Sequence numbers are per boot and strictly
increasing, so rows published in the same millisecond are never skipped.

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

**`GET /api/v2/era/{E}`** returns `{"era", "start", "end", "delta", "shards", "kcommit", "sealed"}`. It is immutable
once sealed. Publishing `kroute_E` for sealed eras belongs to stage 2 (paging, §14) and is not part of stage 1.

**`GET /api/v2/ckpt/latest`** returns `{"q", "sec", "hd", "C", "sig", "heads": [{"cid", "head"}]}` (binary fields in
b64u). 404 when there is none yet.

**`GET /api/v2/ckpt/{q}`** has the same shape. It is immutable (`public, max-age=31536000, immutable`).

**`GET /api/v2/ckpt/range?after=<q>&limit=<1..1440>`** returns
`{"from": {"q": after, "C": b64u(C_after)}, "entries": [{"q", "sec", "hd"}], "latest": {"q", "C", "sig"}}`.

- Entries have `q > after`, in ascending order.
- The client recomputes `C` forward from `from.C`.
- When the last entry is `latest`, the result MUST equal `latest.C`. Otherwise the client pages on.

**`GET /api/v2/feed/{E}/{i}?after=<t>`** (binary; `RL_READ`) is the public enumeration of a shard's closed batches:

```
response = u8 more | u32 nb | batch × nb
batch    = u32 t | u32 n | root[32] | head[32] | (label[16] | u8 cls | body[CLASSES[cls]+40]) × n     rows ordered by label
```

Pages hold about 4 MiB. Batches are never split. A page whose `more = 1`, or any page of a sealed era, is immutable;
the tail page is `no-store`. Clients never use the feed. It exists so that the database stays public and mirrors and
auditors can verify batch roots and the head chain against checkpoints.

## 11. Client algorithms

Constants: `W = 8` (lane lookahead and gallop chunk), `P0 = 2` (probe depth of an idle lane), `SEND_ATTEMPTS = 8`,
`HISTORY_INITIAL = 30` rows per lane, `HISTORY_COPIES = 20`, `VIEW_MESSAGES = 500`, `MAX_TEXT_BYTES = 12000`,
`MAX_REQUESTS = 64`, `RESUME_AFTER = 10 min`.

Every protocol delay (the re-delivery and rotation rank delays, `RESUME_AFTER`, the HEADS delay, the poll and
catch-up intervals, the processing wait of §11.3) is a named engine option, so tests can shorten it. Waits on server
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
| epochs `e → {EK, keys, D, H(D), bundleId, E_start, …}` | For each lane ℓ: the dense-prefix position, the processed position, the last valid row (for `prev`/`prevh`), and the rows seen. For the control lane: the position `(E_c, cnt_c)`, the evaluated rows and their e-validity (valid, not valid, undecided), the winning claim with its finality and processing state, and the sealed eras observed. Also the set of members who left. |
| current epoch | `removed`, `left`, `frozen` (withheld, excluded or invalid, §6.6 step 6) |
| followed lanes | at most one `(e, ℓ)` per member, in an older epoch (below) |
| re-deliveries | NEED_KEYs seen, with their scheduled rank timers (§6.6 step 7) |
| messages | message list, `unread`, `lastTs` |

**Unknown members.** A member of a D whose uid has no directory bundle, whose bundle fails `checkUserKeys`, or whose
bundle's (or MEMBER record's) `sigPk` differs from the `sigPk` in D is an **unknown member**. It is shown with the
handle `?` + the first 8 b64u characters of its uid. Its rows verify under the key in D like any member's (§5.1), so
they are shown, under that name. It gets no J, and a commit gives it a dummy entry (§5.4). A `sigPk` that differs from
the directory's raises the critical warning "the public keys of @x changed" (either the descriptor's author or the
directory lied, and the handle is not shown for a key it does not belong to); a missing bundle is looked up again on
the next restore. Members of a request copy other than `D.by` are shown the same way until the copy is opened or
accepted (§11.5).

**Followed lanes.** For each member s of the copy's current epoch c, other than self, of whom no valid row in c has
been seen, the client follows exactly one lane of s in an older epoch `f(s)`:

- `run(s)` is the earliest epoch r such that the copy holds every epoch `r..c` and s is listed in each of them;
- `f(s)` is the latest epoch in `[run(s), c − 1]` in which the client has seen a valid row of s, or `run(s)` if there
  is none; if `run(s) = c`, s has no followed lane;
- after a valid NEED_KEY of s with content `e_f`, `f(s) = e_f`, so the frozen member's messages in `e_f` are heard.

A followed lane is dropped when a valid row of s in c (or later) is seen, or when a claim drops s.

**Why a frozen member is always heard.** A frozen s posts NEED_KEY on its own lane of every epoch from the first epoch
`a` of its own run to `e_f` (§6.6 step 6). A follower's `f(s)` is an epoch in which s posted (so `a ≤ f(s) ≤ e_f`, as s
posts only in epochs it holds), or `run(s)`, which is at least `a` and at most `e_f` whenever the follower held `e_f`,
which it must in order to re-deliver. So one NEED_KEY lands on every follower's followed lane, wherever s froze, even if
s stayed silent across several epoch changes. (A listed member that never received its first J holds no epoch of the
copy, so it neither freezes nor posts.) The cost is bounded by members, not by epochs: at most one followed old lane per
member, plus the NEED_KEY rows a frozen member writes once. HEADS records the followed lanes (§7.2); at restore, a
member of the HEADS epoch without a followed lane in the HEADS entry is treated as having a valid row in the HEADS epoch
(it posted there, or the HEADS epoch is `run(s)`; either way the rule above holds). A copy without a HEADS entry is
processed from its root epoch at restore (§11.4), which computes `f(s)` exactly as a live client does.

**Sweeping.** Before any lane of an older epoch leaves the expected-label map (when the copy switches epochs, or a
followed lane is dropped or moved), the client processes it from its processed position to its dense-prefix head,
probed at that moment, after the winner that ended the epoch is final. So a WELCOME, LEAVE or NEED_KEY posted in an
older epoch before the switch is never skipped. A row that a member writes into an older epoch after it already wrote
in a newer one (only possible when two of its own devices race a claim) is found by scrollback only (§11.10).

The client also keeps:

- the **expected-label map**, `label → (copy, e, kind, ℓ|ctl, E, n)`, covering:
  - for each lane of the current epoch and each followed lane: the next `W` slots in the head's era, and slot 0 of
    `E_now` if that is later. An era between them is probed only at slot 0, and never again once that slot is
    `MISS(sealed = 1)`;
  - the next 2 control slots of every epoch whose winner is not yet final and processed;
- the self-lane and inbox cursors, and the processed positions of every lane.

### 11.3 Send (TEXT / IMAGE / LEAVE / NEED_KEY / KEY_OK / WELCOME)

Sends are serialized per conversation. The UI echo appears at once, with status `sending` (none for LEAVE, NEED_KEY,
KEY_OK and WELCOME). NEED_KEY rows (§6.6 step 6) skip steps 1–3 and use the lane, keys and head of the epoch they are
posted in, which may be older than e.

1. Re-check the session. Make sure the control lane of the current epoch e is caught up: probe it if the realtime
   socket was not connected for the whole time since the last probe, or if the last probe is older than 30 s.
2. If the current epoch has a winner that is not yet final or processed, or an undecided slot, wait for it, at most
   30 s. Then:
   - if the user was removed: fail with "you are no longer a member of this conversation";
   - if the user has left: fail with "you left this conversation";
   - if the wait timed out: send in e, as a frozen member would.

   A frozen member sends normally in e.
3. If the epoch lists a member who has left (other than self) and the type is TEXT or IMAGE, commit a rotation (§6.3),
   unless self is frozen in e or `e = 2^32 − 2`. On a conflict, follow the winner. Then restart at step 1. If the
   commit fails with "can no longer change", send in e.
4. Pick the slot:
   - `(E, n)`: if the lane head is in `E_now`, then `n = head.n + 1`; otherwise `(E_now, 0)`;
   - `prev` = the sender's last valid row on its lane in epoch e.
5. Build M, sign it, pad it (a text over 12000 bytes fails with "message is too long"), and encrypt it.
6. Put with topic `T_e` and handle the result. Every attempt, WRONG_ERA included, counts against `SEND_ATTEMPTS`, except
   the junk skipping below.
   - **OK**: verify the receipt, apply the row locally (the echo becomes `sent`), and update the lane head.
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

**Retry of a failed echo.** "Try again" first re-puts the kept sealed body at its original slot. OK, or a CONFLICT with
an identical body, is success. Only another occupant or a WRONG_ERA makes the client build the message again at a new
slot. A message is therefore never delivered twice.

### 11.4 New device / reload (restore)

Every unlock restores. There is no persisted local cache in stage 1.

1. Directory and checkpoints: §11.1.
2. **Snapshot pointer.** Probe `Lsnap(E_now, 0..15)` and `Lsnap(E_now−1, 0..15)` (body mode).
   - Take the highest `(E, j)` inside a dense prefix. If all 16 slots of an era hit, gallop.
   - If neither era has one, probe `Lsnap(E, 0)` for `E = E_now−2` down to `regEra`, and stop at the first hit.
3. If there is a snapshot: fetch the blob, check its hash, decrypt, parse `S2`, and apply its records. The self
   position is `(Eh, nh)`.
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
   - **Control lane.** From the latest HEADS position (trusted, §7.2), or from `(E_start, 0)`, probe and process claims
     as in §6.4–§6.6. Repeat for each new epoch: each costs one bundle fetch.
   - **Lanes.** For **every epoch** of the copy from the epoch of its HEADS entry (or from the copy's root epoch when it
     has no HEADS entry) up to the current epoch, and for each lane of that epoch, from its processed position in HEADS
     (or from the epoch's start): probe `P0` slots, gallop with `W` on hits to find the head, then fetch the bodies of
     every slot from the processed position to the head and process them (§6.8): WELCOMEs, LEAVEs, NEED_KEYs and
     KEY_OKs take effect. The lanes of an epoch are processed before the switch past it, exactly as the sweep of a live
     client (§11.2), so followed lanes come out the same. Followed lanes recorded in HEADS are processed from their
     positions. Rows applied during restore never count as unread.
   - **Frozen copies** re-derive their freeze, and post NEED_KEY if their lane of `e_f` holds none after the claim
     (§6.6 step 6).
   - **Unfinished deliveries** (§6.11).
6. **Initial history.** For the `HISTORY_COPIES` copies with the newest `lastTs` (from HEADS), also fetch the last
   `HISTORY_INITIAL` slots of each lane of the current epoch (body mode), and, if the epoch has fewer than 30 rows,
   rows of the previous epoch up to its winner's time. Other copies load their history when they are opened (§11.10).
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
- one bundle (11–40 KB) per epoch that has no DESC record, which in practice means the epochs since the snapshot;
- the rows written since the account's last HEADS, in bodies, in every epoch since HEADS;
- `HISTORY_COPIES × lanes × HISTORY_INITIAL` rows of initial history;
- `MAX_REQUESTS × (members + 2)` keys for requests;
- the inbox rows since the cursor (at most about 30 minutes of inbox when HEADS is current);
- **directory:** the exact own-uid lookup, plus one prefix response (about 64–128 bundles, 120–240 KB) per distinct
  co-member that has no MEMBER record. With a current snapshot or HEADS that is none, so the directory bytes of a
  restore do not grow with the directory or with the number of co-members.

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
3. The cursor becomes `(E, closed)` of the last era read, but never passes a parked join (§6.7 step 4). Joins and the
   new cursor are written in one self row (§7.3).

**Requests.** A copy created by a first-contact join whose `D.by` is not a contact (§7.3) is a **request**:

- It is recorded as a REQUEST self record, which carries `D`, so a restore needs no bundle fetch for it. At most
  `MAX_REQUESTS` are live (§7.3).
- At acceptance only `D.by`'s bundle (its `sigPk` against D, §6.7) and `dsig` are verified, and a MEMBER for `D.by` is
  written with the REQUEST. Other members' rows verify under the keys in D; their bundles are fetched (for handles)
  only when the copy is opened or accepted, and until then they are shown as `?…` (§11.2).
- It is not subscribed. On restore and at every catch-up it is probed with the next 2 control slots and one key per
  lane: the slot after the lane's known head (from HEADS, which covers requests too), or `(E_start, 0)` when none is
  known, plus `(E_now, 0)` if that era is later. Hits are galloped, fetched and processed, so a member who has not
  posted yet still sees the others' rows after a restore, and corroboration does not depend on realtime.
- It becomes an accepted copy (a CONV_JOIN with `via = 5`, plus CONTACT for `D.by`) when the user opens it
  (`markRead`), when self posts in it, when `D.by` becomes a contact, or when a valid row from a member other than
  `rootBy` and self is seen (which also writes CONFIRMED). On that transition the client processes every lane from
  `E_start` in body mode, looks up the members that have no MEMBER record, then treats the copy like any other.

This bounds what an inbox spammer costs a victim: one bundle fetch and at most one directory lookup per join (none
when `D.by` already has a MEMBER record), at most `MAX_REQUESTS × (members + 2)` keys per catch-up, no directory
lookups at restore, and no topics.

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
from the processed position to the head. When a catch-up makes a copy switch epochs, the old epoch's lanes are swept
to their heads first (§11.2). Then it polls the inbox and resumes unfinished deliveries (§6.11). On 429 it backs off
as `retry-after` says.

### 11.7 Multi-device

- Devices of one account share every counter through CAS. They do not coordinate in any other way:
  - a CONFLICT whose occupant is a valid row signed by self (lanes) or opens under `kS` (self lane) is applied and
    treated as the new head;
  - an identical body means our own lost write.
- Sibling devices subscribe to the same topics, so they see each other's sends in real time.
- A committer's other devices learn new epochs through their own bundle entries, and finish its deliveries (§6.11).
- Two devices may write `(E, n)` and `(E+1, 0)` of one lane around an era boundary. Readers find both, because they
  probe each era's dense prefix (§11.10, §12.2).

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

### 11.10 Scrollback

When a conversation is opened (`markRead`, which the UI calls every time it opens a conversation pane), the client
loads older rows until the view holds `VIEW_MESSAGES` messages or the history is exhausted. This runs once per copy
and session; later calls are no-ops.

- For each lane, probe `(E, n−32..n−1)`.
- At `n = 0`, move to the previous era that has rows: follow `prev` of the oldest loaded valid row, and also probe the
  dense-prefix end of each earlier era down to `prev`'s era, so rows that are not on the `prev` chain (a sibling's row
  written across an era boundary) are found too.
- Below the first row of an epoch, continue in epoch e−1, using its keys from the self lane (its DESC, or its bundle
  for `D_{e−1}`).

Rows found by scrollback are processed like any other (a WELCOME or LEAVE that lies before the processed position was
already processed and is not applied twice). Older rows are never counted as unread.

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
| membership changes and creations | Both show the same row pattern: a class-1 self row, one class-1 row at least Δ+SKEW later (claim or decoy, which P cannot tell from a medium text), then J deliveries and a class-0 self row; at most hourly, that some blob was registered. Members who receive J by inbox add that many inbox rows within seconds, while a removal or rotation adds none, so P can tell "someone was invited by inbox" from "nobody was" (§13.2 item 12). Not the member count, not who. No self rows follow a claim observed by other members. A freeze (withheld key) adds, once, the frozen member's class-0 NEED_KEY rows (one per epoch of its run), at most three re-deliveries each followed by a class-0 self row, and one class-0 KEY_OK; P cannot tell them from short texts except by timing. | Which IPs fetch the bundle blob, so the members. | The members of e+1 see D′. Every member of e, removed ones included, sees `rm` (who of the old members was dropped). |
| content | The size class only. Safe against a quantum P. | Same, plus blob fetches per IP (image recipients). | Everything in epochs held. |
| directory | handle ↔ uid ↔ keys, registration time, every wrap (credential ids, recovery ids). | The same, plus a p-bit prefix of every lookup, and the exact wrap id and own uid at every login. | — |

Never stored anywhere: topics, subscriptions, IPs, RESUME rings, rate-limit keys, arrival order inside a Δ batch, and
inbox jitter.

### 13.2 Properties of v1 (docs/DESIGN.md §3) that stage 1 weakens

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
   changed". Conversely, v1 rejected a conversation that listed an unregistered uid ("ignored a conversation with
   unknown members"), and keys always came from the log. Stage 1 accepts such a conversation and takes members' keys
   from the signed descriptor, so validity never depends on the directory (§6.10); a member whose uid is not
   registered, or whose key in D is not the directory's, is shown as an unknown member `?…` with that warning, never
   under a handle (§11.2). A creator or committer can therefore list a fake key for a real uid, but cannot make a row
   appear under that user's handle.
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
   - A member whose key was withheld waits for a re-delivery by one of the three most recently active members of the
     new epoch (about a minute per rank), and, if none of them is online, until one is.
7. **Ordering.** v1 showed a server total order (seq). Stage 1 orders by clamped sender time, so concurrent messages
   may be ordered differently on different devices. A row shown live can be withdrawn when a claim that removed its
   sender becomes known (§6.8).
8. **History on a fresh device.** v1 replayed everything (all history available at once, at O(global) cost). Stage 1
   shows the last 30 rows per lane of the 20 most recently active conversations at once, and loads up to 500 per
   conversation when it is opened. Older history stays reachable through `prev`, but the UI has no "load older"
   control (unchanged view cap of 500).
9. **One more size class.** The 256 class is back. With binary payloads it is the *common* class (short texts,
   images, leaves, welcomes), so it no longer singles out rare rows. P still learns whether a text is ≤ 129 B. That
   is coarser than v1's per-batch shapes, but it is new per-row information.
10. **Directory lookups leak a prefix to the operator.** v1 clients resolved handles from the full directory they had
    downloaded, so O learned nothing about whom a user looks up. Stage 1 sends a p-bit prefix of `H(handle)` or
    `H(uid)` for every lookup: handle resolution, the first verification of each co-member or inviter (then kept in a
    MEMBER record, so restores repeat none), and `kemPk` fetches when committing. The anonymity set is about 32–128
    accounts at honest `P`. The client bounds `p` by the public dirlog size (§10.6), so O can shrink the set only by
    inflating the audited dirlog.
11. **A third party can delay first contact and inbox deliveries.** v1 had no global quota. Stage 1's inbox has one
    global day cap (2 000, β = 0). Anyone who fills it with PoW-priced invites makes first contacts, and adds of
    members without a 1:1, wait until the next day. Committers retry (§6.12), and members with a 1:1 are unaffected.
    A device without a cursor must also trial-decrypt up to 56 000 invites (about 80 MB, §9.3); the cursor in the self
    lane keeps this to the invites since the last poll.
12. **Creations and adds are distinguishable from removals and rotations.** v1 gave every change and every creation
    the same `[4, 3×N]` shape, revealing N but nothing else. Stage 1 hides N, but invites by inbox are public rows: a
    change or creation followed within seconds by inbox rows probably invited someone without a 1:1, and one followed
    by none probably did not.
13. **Capacity.** One ShardDO per era stores at most 10 GB (about 25 000 active users at the stage-1 estimate) and
    handles about 1 000 requests/s, and one RealtimeDO and one current InboxDO take every client. When a shard fills,
    writes fail with FULL until the next era (§9.1). These are stage-1 bounds, not protocol limits: S > 1 is a
    parameter change because routing by `v` already exists.

### 13.3 Properties stage 1 strengthens

- **Recipients of invites** are hidden from a quantum P (PQ trial decryption). v1's X25519 view tags revealed them to
  a quantum P.
- **Membership changes no longer reveal the exact member count.** v1 batches were `[4, 3×N]`. Stage 1 bundles carry
  only the bucket 8 or 32, and P cannot list bundles.
- **Removed members** no longer learn who was added (they still learn, through `rm`, which old members stayed).
- **Junk never freezes membership.** Junk, unsigned rows and e-invalid claims are ignored (v1 froze on any row in the
  claim slot). A signed claim can still freeze membership, as in v1, but the warning names its signer. A key withheld
  from some members freezes only them, and re-delivery repairs it.
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
- AK rotation and bundle versions (`bundle_hist`, `prevsig`);
- delayed rekeying after AK rotation; periodic PCS-lite rotation.

**Clients:**

- a link-sharing UI and the `Engine` methods for links (the engine implements links internally in stage 1, §11.11);
- read cursors in PREFS;
- a persisted local cache;
- a "load older" UI beyond 500 messages.

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
| A10 | DD §6.7 member processing | D′-invalid versus "excluded", and who can evaluate D′. DD's dummy entries for removed members make a removal look the same as a withheld key, so one malicious member could end the conversation for everyone (v1 only froze it). | The winner is the first e-valid claim for every member of e; nothing private (an entry, D′) changes it. The claim's public `rm` bits name who is dropped, and **removed members get a real seal of `REMOVED = ZERO32`**; a REMOVED entry counts only where `rm` agrees. D′ must keep exactly the old members `rm` keeps. An invalid D′ (or a key withheld from everyone) freezes membership for all, as in v1, but the signer is named. A key withheld from some members (or a REMOVED entry where `rm` keeps the member: the stage-1 "excluded" freeze) freezes only them; they post NEED_KEY, the others keep following one lane of each silent member, and a ranked re-delivery of J(e+1), which must pass the same D′ checks, lifts the freeze (§6.6, §6.7). Directory registration is not part of validity, because D carries every member's `sigPk` (§5.1), so a later registration cannot change anyone's decision. |
| A11 | DD §6.7(b), §6.8 | Admin policy, with groups of 3+ admin-only by default. | Stage 1 keeps the MVP policy: any member may commit. D has no policy field. Admins are deferred. |
| A12 | DD §6.8 | Leave as type 17 on the control lane, with a ranked committer waiting `r × 30 s`. | LEAVE stays on the leaver's own lane (MVP semantics, carried over to later epochs). The next remaining sender MUST rotate first. Ranked proactive rotation is a MAY (§6.9). |
| A13 | DD §6.8 "do not mix add and remove" | The MVP drops leavers inside an add. | Mixing is allowed. Entries are indexed by `D_e`, and new members get J, so a mixed commit leaks nothing extra. |
| A14 | DD §6.7 step 2/6 | Entries for new members appended, `entryIdx` sent in the welcome, and B up to 1024. | New members get EK directly in J and have no entry. Entries exist only for indices of `D_{e−1}` (REMOVED for those leaving, dummies as padding). B ∈ {8, 32}. |
| A15 | DD §6.6, MVP privacy tests | DD defines no creation-versus-change indistinguishability. The MVP does (decoy, shuffle). | Creation = a registered SGB2 bundle, a class-1 self row, the same wait, a class-1 decoy at a random label, J's, and a class-0 self row, which is the pattern of a commit (§6.1, §6.3). Invite order is irrelevant: entries are unreadable, and J's go to individual inbox rows or 1:1s. Inbox counts still separate "someone invited by inbox" from "nobody" (§13.2 item 12). |
| A16 | DD §5.4 | `rel = ceil((sec + jitter)/Δ_inbox)` with no definition of the cursor, of closed slots, or of retention. | `rel = max(⌊(ms + j)/D⌋ + 1, closed_hw + 1)` and `closed = max(⌊ms/D⌋, closed_hw)`, so a new row never lands at or below a reported `closed` (rows ≤ closed are final), whole-group paging, a persisted `ended` state, and a 4-era client retention with 410 beyond it (§9.3). Δin = 10 s in production (not 5 min), so first contact stays fast. |
| A17 | DD §4.4 | 64-bit `v` used as a SQLite integer. | `v` is an 8-byte big-endian BLOB. JS numbers cannot hold 63 bits, and the BLOB sort order equals the numeric order. |
| A18 | DD §4.4 "no secondary index", `lost = 1` | Batch leaves are lost on restart, which breaks enumeration of "the DB is public". | Stage 1 adds `row_t(t, label)`: batches are always recomputable, the public feed is simple, and nothing is ever `lost`. This costs 2× row writes, which is negligible at stage-1 scale. |
| A19 | DD §4.4 `FULL` / `MOVED` "writer skips n" | Skipping creates a hole, which contradicts dense prefixes. | FULL is a whole-shard failure (retry later, no skip). MOVED is reserved. |
| A20 | DD §6.2 RESUME | A per-socket 10-minute buffer that cannot survive hibernation. | One in-memory ring keyed by publish time plus a `boot` id. On any mismatch the server sends GAP and the client catches up. No persistence (§9.4). |
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
| A32 | DD §6.6 | Welcome via 1:1 is "type 8", with no receive rules. | A WELCOME carries J and is accepted in any held conversation from a verified member. Sending through a 1:1 is a SHOULD, and only through a 1:1 in whose current epoch the recipient has posted and which it has not left (§6.12); every other recipient gets an inbox invite. |
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
| Bundle | JSON v1 with `scan` | JSON v2 without `scan`; fingerprint over `(uid, sigPk, kemPk)` |
| Directory | kind-1/2 log rows; D1 as a derived index; exact handle lookup | D1 authoritative with a dirlog chain; prefix lookups; exact wrap-id and own-uid lookups |
| Message tags | `msgTag(i, n)`, `claimTag` | `Lmsg_e(ℓ, E, n)` (n per era), `Lctl_e(E, k)`, `Lself`, `Lsnap`, `Lhello` |
| Payload | JSON (`v, t, conv, e, from, n, ts, head{seq, h}`) | binary envelope M (62 B header: type, from, lane, n, prev, prevh, ts, ckq, ck16) |
| Classes | messages [1024, 4096, 16384]; invites [2048] | [256, 1024, 4096, 16384] for all rows; inbox body 1416; descriptors padded to [2048] inside SGB2 bundles (11640 or 40248 B) |
| Descriptor | JSON, inside invites and claims; member keys from the directory | binary D listing `(uid, sigPk)` per member, encrypted in the SGB2 bundle under `dk_e`; the directory supplies handles and `kemPk` only |
| Key delivery | kind-3 invite per member (X25519 view tag + X-Wing) in the same atomic batch as the claim | SGB2 bundle entries (X-Wing) for continuing members; J via the PQ inbox, a 1:1 WELCOME or a link hello for new members |
| Claims | one slot per epoch; first row wins; burn ⇒ freeze; never-delivered ⇒ freeze | control lane; the first e-valid claim wins for every member (undecided slots block); bundle registered before the claim (t_reg + Δ + SKEW, checked on the OK); finality via sealed eras; junk never freezes; public `rm` bits plus explicit REMOVED entries; an invalid D′ or a key withheld from all freezes everyone (v1 semantics, attributable), and chained joins must pass the same D′ checks; a key withheld from some (or REMOVED against `rm`) freezes only them until a NEED_KEY-triggered re-delivery by one of the three most recently active members, acknowledged by KEY_OK |
| Old-epoch acceptance | claim chain by seq | stored `t` against each later claim's `t`, with `rm` naming who is dropped; cuts only for the claim's own Δ batch |
| Creation privacy | decoy kind-4 row + shuffled invites, `[4, 3×N]` | an SGB2 bundle + a class-1 self row + the same wait + a class-1 decoy at a random label + J's + a class-0 self row |
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

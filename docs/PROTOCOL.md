# segv.sh protocol v2 (stage 1)

This is the normative spec. It replaces protocol v1. Every implementation (the client crypto core `src/lib/proto.ts`, the
client engine, the Worker and the tests) MUST follow it byte for byte. The rationale lives in `docs/DESIGN.md`.
"Stage 1" is the first build stage of the Label-Indexed Store (LIS). The identifier of the protocol is `segv.sh/v2/` in
every stage, and §14 lists what later stages add. v1 wire formats are removed: a v2 implementation does not read,
write or serve them, and there is no migration (no v1 data exists).

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

**Implementation vocabulary**. These are implementation-defined and not part of the protocol: the names of
functions, constants and types that implementations and their tests use (for example
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

- The server stores **public** data only, with one exception, below. Anyone may read every other stored byte,
  forever, and the server never sees a secret of an account or a conversation. It has no sessions. Writes are
  anonymous. Abuse control is proof of work plus per-IP rate limits, and no address is stored.
- **The exception: push registrations.** A deployment MAY offer Web Push notifications (§9.8, §10.10, §11.13). Then one
  component, PushDO, stores data that is never served: for each device that turned notifications on, its push endpoint
  (the URL at which its browser's push service accepts messages for it) with that subscription's encryption keys,
  sealed under a server secret, keyed hashes of the bells it registered (§4.2), and the day of its last registration.
  It stores no uid, handle, conversation, topic, IP address or sender, and nothing about a ring: which devices a
  message reached is held in memory only, for at most a few minutes, and never written. Bells are independent PRF
  outputs, so the stored registrations link no conversation or account to another; the devices of one account
  register the same bells, so theirs are linked (§13.4). The platform keeps a history of this storage for 30 days, so a
  registration, and its deletion, can be recovered from it for up to 30 days after it changed. PushDO applies each
  change in memory at once and writes it to storage only after the UTC day in which it was made has ended, in a pass
  that starts at 00:00 UTC (the pass that a restart of the object starts deletes only what has expired or no longer
  opens), so that history dates a change by its day only: it shows, per day, which endpoints were registered, which
  changed their bells and which were deleted, and on a day with few changes, endpoints whose bells changed, or that
  were deleted, that day may belong to members of one conversation (§13.4).
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
  - R2 for blobs;
  - optionally, one **PushDO**, which holds the push registrations and sends contentless pushes (§9.8).

### 0.2 Adversaries

| name | capability |
| ---- | ---------- |
| **P** | Public reader. Reads and archives everything stored, forever, and may later own a quantum computer. **P\*** = P plus active use of every public API (including the WebSocket). |
| **O** | The operator / platform. Sees every request when it happens (IP, path, timing, WebSocket topics), can run arbitrary server code, and can delay, omit or reorder responses. Cannot break the cryptography. |
| **M** | A member of a conversation, possibly malicious. M holds the epoch keys of the epochs it belongs to, and may write any row an outsider can write plus rows under labels it can compute. |
| **N** | A push service, only for a device that turned notifications on (§11.13): Apple's for Safari and for iOS and iPadOS web apps, Google's (FCM) for Chrome and most Chromium browsers, Mozilla's for Firefox, Microsoft's for Edge. It holds the device's push subscription, which it can link to the device and often to an account with the browser's vendor, and it sees every push sent to that subscription: its time and its size. It cannot read a push (RFC 8291), and every push has the same length and the same fixed text; the bells that a push names are encrypted to the device (§9.8). |

### 0.3 Guarantees in stage 1

1. **Confidentiality.** Message text, images, reactions, conversation names and member lists are confidential
   against everyone who holds none of: a member's passkey PRF output, recovery code or AK, or the epoch key. This holds
   against a quantum P: every key is delivered with X-Wing, and everything else is 256-bit symmetric. Pushes carry
   none of them (§9.8). A device whose user chose a preview (§11.13) decrypts the conversation's name, or its name
   and newest message, itself and shows them through the operating system's notifications, which this guarantee does
   not cover (§13.4).
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
     That member still holds the old epoch's keys, so stage 1 refuses texts, images and reactions there (§11.3),
     where v1 let the frozen members keep writing to it.

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
  as long as it keeps refilling the cap every day; where push is offered, anyone who fills PushDO's endpoint cap with
  registrations (§9.8), which keeps every new device from turning notifications on until they expire, or its cap of
  registrations changed in a day, which keeps every device from registering a new or changed set until the next day,
  or who keeps more pushes due than the one PushDO sends, which delays everyone's notifications; and directory key
  substitution by O (detected only by fingerprint comparison, TOFU pins (CONTACT, MEMBER) and disagreement with the
  keys in descriptors).
- **Web Push** (optional; §9.8, §11.13, §13.4):
  - Delivery is best effort. A push service may drop or delay a push, a browser may revoke a subscription, the
    pushes to one device are coalesced to at most one per `PUSH_WINDOW` (60 s), except across a restart of PushDO, and
    a registration expires 30 days after its device last refreshed it. A restart (an eviction or a deploy) loses the
    pushes then due and the registration changes that PushDO has not yet written, so a device may get the
    notifications of its earlier set, or none, until it registers again at its next start, or within 24 hours while it
    runs (§9.8, §11.13). Messages from a client that does not ring (the first release, §7.1) notify nobody, and a
    contact that the first release recorded when a third member's row accepted a request counts (§7.3): that
    conversation, and the later ones that user starts, ring although the user never accepted them.
  - A push names at most the `PUSH_BELLS` = 4 bells that rang its device last, and a push that the push service
    replaces with the next one loses its bells (§9.8), so a preview may leave a conversation out. A preview may also
    miss rows, or show a row that the app later drops (§11.13).
  - **Previews** (§11.13). On a device whose preview is `name` or `message`, conversation names, and with `message`
    handles and message text, pass to the operating system's notifications, which show them on the lock screen as its
    settings say, may keep them in a notification history after the messages, the app or its data are gone, and may
    forward them to paired devices; the device also keeps the names and handles, sealed under a device key. With
    `message`, every push makes the device read its conversation's rows, also while the app is closed, so O learns at
    each push the device's IP address and that it received the push, and can link its endpoint to that address; a
    member can cause this by ringing, and O by sending a push.
  - A device that is closed while the epoch of a conversation changes twice gets no notification for it until it is
    opened (senders ring the bells of the current and the previous epoch only), and one that is closed while it
    changes once stops getting them as soon as another device of its account posts in the new epoch.
  - O learns, at every ring, the bells of the conversation's other members and the devices registered under them,
    also devices that are offline, and links them to the conversation through the topic of the row's put; a device's
    endpoint stays the same across its IP addresses. N learns when each of its devices is notified, and can guess from
    the times which devices share a conversation.
  - A member can make the other members' devices show a notification (at most one per device per `PUSH_WINDOW`, a
    restart of PushDO aside), and can take the 8 places of another member's bell with its own endpoints first, which
    keeps that member's devices from registering under it, and so from notifications for that conversation, for as long
    as it holds them (the bells change with each epoch, and it can take the new ones too), without letting it read
    anything new. Registering its own endpoints and ringing them also tells it how many places other devices hold, and
    so whether that member has notifications on; and holding all but one place of that member's new bell after an epoch
    change (which any member can cause), and probing the free place every few minutes, tells it when the member's first
    device registered that bell, that is, when it was first open after the change. A member removed at an epoch change
    can do the same with the previous epoch's bells of the members silent in the new epoch, and learn when messages are
    sent there and, since a sender never rings its own bell, which of those members sends each, until each of them
    posts in the new epoch or the epoch changes again.
  - Notifications are shown also while the app is open.

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
not affected; the PoW nonce has the same bound, set in §10.2.

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
  `sigPk` is used only for the `D.by` key check of first-contact joins, re-adds included (§6.7 step 6).

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
  `/api/v2/params`. `E_FIRST` (§9.7) is in 0..0xFFFE. It is normally the era of the deployment's first deploy, and
  MUST be at most `era(t_deploy − SKEW·1000)`, where `t_deploy` is that deploy's time: the Worker accepts writes and
  inbox posts into `era(now − SKEW·1000)` (§9.7), and a row accepted into an era below `E_FIRST` would never be read.
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
- A **position field** is `(Eprev, nprev)` of M and S, `(claimE, claimK)` of EPOCH and of ENDED, `(E, n)`
  of LEFT, or `(Eh, nh)` of SNAP and S2. If its E is 0xFFFF it MUST be exactly NONE: parsers reject
  `(0xFFFF, n)` with `n ≠ 0xFFFFFFFF`, and encoders refuse it. A position with `E ≠ 0xFFFF` may have any n. The
  `(E, cnt)` pairs are not position fields and have no parse-time range rule: the claim cuts (§6.2) and, in HEADS,
  `(ctlE, ctlCnt)`, the lane and followed-lane positions, and the inbox cursor `(Ein, relIn)`. §6.4(f) bounds the
  cuts.

### 3.2 Size classes

```
CLASSES   = [256, 1024, 4096, 16384]            cls = index 0..3; row body length = CLASSES[cls] + 40
```

| cls | plaintext | body | typical content |
| --- | --------- | ---- | --------------- |
| 0 | 256 | 296 | text ≤ 129 B, image reference, reaction, leave, welcome, most self rows, snapshot pointers |
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
| `type` | 1 TEXT, 2 IMAGE, 3 REACTION, 8 WELCOME, 16 CLAIM, 17 LEAVE. Every other value is invalid. |
| `from` | The sender's index in `D_e` (§5.1). |
| `lane` | For lane rows (types 1, 2, 3, 8, 17): equal to `from` (stage 1: one lane per member). For CLAIM: `0xFFFF`. |
| `n` | The slot within era `E`: the lane counter, or `k` for CLAIM. |
| `Eprev, nprev, prevh` | Lane rows only: the position of the sender's previous **valid** row on this lane in this epoch, and `prevh = t16(H(enc("segv.sh/v2/prev", label_prev, body_prev)))`, where `body_prev` is that row's stored body. For the first row of the lane in the epoch, and for every CLAIM: NONE and `ZERO16`. |
| `ts` | The sender's clock in ms (display only, §11.8). |
| `ckq, ck16` | The sender's latest verified checkpoint: `q` and `t16(C_q)`. `(0, 00…)` if it has none (§12.3, §12.4). |

**Parse rules** (normative; they decide "the envelope parses" in §6.4(a)). A body *does not decrypt* if its length is
not a class body length (§3.2) or `aeadOpen` fails. Otherwise the row is *malformed*, and is not accepted, unless all
of these hold:

1. `unpad` (§1.3) succeeds. The result x has `len(x) ≥ 62 + 64`; `M` = x without its last 64 bytes, and `sig` = the
   last 64 bytes.
2. `ver = 2` and `type ∈ {1, 2, 3, 8, 16, 17}`.
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
- **REACTION (3)**: `u32 te | u16 tl | u16 tE | u32 tn | th[16] | u8 op | u8 elen | emoji[elen]` (30 + elen B, so at
  most 62 B and the row is always class 0). It is the sender's reaction to the row at `(tE, tn)` on lane `tl` of epoch
  `te` (the **target**, §11.12), with `th = t16(HMAC(rk_te, enc("segv.sh/v2/react", label_t, body_t)))` over the
  target's label and stored body, keyed by the route key of the target's epoch (§4.2), so that only a holder of that
  epoch can tell which public row a reaction names; `op` is 1 (add) or 0 (remove); `emoji` is `1 ≤ elen ≤ 32` bytes of
  valid UTF-8 (§1.2). Any other `op`, `elen` or length is malformed. The target fields `te`, `tl`, `tE`, `tn` and `th`
  have no parse rule, and whether `emoji` is one emoji is not a parse rule either (§11.12).
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
B_e(ℓ)          = t16(HMAC(nk_e, enc("segv.sh/v2/bell", u16 ℓ)))                    push bell of lane ℓ of epoch e
```

- **Lanes.** In stage 1 there is one lane per member, `L_e = |D_e| ≤ 32`, and lane `ℓ` belongs to
  `D_e.members[ℓ]`. Only that member's devices write it, and they share the counter (§11.7).
- **Bells.** `B_e(ℓ)` is the push bell of `D_e.members[ℓ]` in epoch e (§11.13). Every member of e can compute every
  bell of e, and nobody else can: a member removed at the change to e + 1 knows the bells of e but none of e + 1.
  Bells, topics and labels are independent PRF outputs, so bells link no conversation, epoch or member to another
  without `nk_e`. All devices of one account compute the same bells, without any record.
- **Counters.** `n` (and `k`) restart at 0 in every era.
- **Dense prefixes.** Slots fill densely within an era: honest writers always write the first empty slot. The **dense
  prefix** of a lane in era `E` is the slots `(E, 0..h−1)` up to and including the last one before the first empty slot
  `(E, h)`. Writers and the control lane use only the dense prefix. Any row of any content inside the prefix
  *occupies* its slot, junk included. Junk beyond a hole is ignored. A validly signed lane row beyond a hole is evidence
  that the server omitted the hole: receivers accept it through its `prev` chain and warn (§12.2).
- **Lane head.** The lane head is the last slot of the dense prefix of the latest era that has one, or NONE.
- **Epoch start.** `E_start(e)` = `era(t_reg)` of the SGB2 bundle that defines epoch e (§5.4, §8.2). No row of epoch
  e is in an earlier era (§6.1 and §6.3 write nothing for e before `t_reg` is known), so clients never probe earlier
  eras. A device takes `t_reg` from the `meta` answer that accepted the epoch when it holds one (§6.4(g)'s for the
  claim it processed to reach the epoch, whose bundleId is the epoch's; §6.7 step 1's for a join; the PUT response for
  its own creation, §6.1 step 4), and otherwise from these sources, in this order: a TREG for the epoch's
  bundleId (that of its CONV_JOIN, EPOCH or REQUEST record, or of the final winning claim that the device processed;
  §7.2); a REQUEST or EPOCH_PENDING record of the copy for e with that bundleId (a REQUEST also after a CONV_JOIN
  superseded it, §7.3; a dead EPOCH_PENDING names another bundle and gives nothing); else one
  `GET /api/v2/blob/{id}/meta`, made only when the device needs that epoch's `E_start` (a claim of the epoch to
  evaluate, §6.4(f), or a lane or the control lane of the epoch probed from `(E_start, 0)`, §11.4 step 5, §11.10) or
  shows the epoch's join line (§11.8). Every source gives the same value, since a registration never changes (§8.2).
  The row of a join's CONV_JOIN holds a TREG for its bundle, a creation's EPOCH_PENDING and an
  accepted request's REQUEST name theirs (§7.3), and a snapshot keeps a TREG for the bundle of every CONV_JOIN or
  EPOCH record whose `t_reg` its writer holds (§7.4), so the request is made only for a join that an earlier
  version recorded (a legacy skip record included, §7.2), until a snapshot holds its TREG.

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
- a recipient accepts a first-contact join (a re-add after a removal included, §6.7 step 6) only if D's `sigPk` for
  `D.by` equals the `sigPk` of `D.by`'s verified directory bundle (§6.7), and any join only if D lists self with self's
  own `sigPk` and `kh`.

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
   `uids = D_0 \ {C}`), padded to class 1 (§7.1). The EPOCH_PENDING names the bundle's `t_reg`, so the row holds no
   TREG (§7.3). CONTACT and MEMBER records for the resolved users go into the next HEADS row (§7.3), so their number
   does not change the class of this row. From here on the conversation exists for every device of the account:
   `createConversation` resolves, with the copy in `conversations`. Steps 6–9 continue in the background.
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
10. **Deliver J** for e+1 to the uids of EPOCH_PENDING (§6.12), then write the DELIVERED row (§6.12 step 3), with
    `a = 0` when EPOCH_PENDING lists no uid (a removal, rotation or rename that adds nobody), so every commit ends with
    the same class-1 self row.

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

**Order of requests**. The **local rules** are (a)–(e), the `bundleSize` clause of (g), and
`B ≥ |D_e|` of (h), where `B = (bundleSize − 4192) / 2408` follows from `bundleSize`; (f) is local too when the reader
holds `t_reg` of e's own bundle. A reader makes no `blob/meta` request and no blob fetch for a row before its local
rules have passed; then it makes (f)'s `meta` request if it needs one, (g)'s `meta` request only after (f) has passed,
and (h)'s blob fetch only after (g) has passed. The `get` that supplies the row's body, or its `t_row` for (g) when the
row arrived in a realtime frame (§6.4(g), §11.6), is not ordered by this paragraph. So a row that fails a
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
   - The copy has **ended**. It never moves to a later epoch: no J continues it (§6.7 step 5), and a J
     that re-adds self starts a separate copy (§6.7 step 6). The state is latched once C is processed, or once the
     copy holds the epoch that the account's ENDED record for it names (below), whether a restore or a live device
     applies that record, and nothing revives it. An ended copy keeps its epochs, its rows and its lines, and is
     **inert** for every rule that looks for another copy of its conversation: it fits no J, no trigger accepts it
     (§11.5), its rows confirm nothing (C itself can, §6.7 step 6), and §6.7 step 6 counts it in the second-copy rule
     and the confirmed check only for a J that contradicts its history ("Forks of an ended copy"; also a J below its
     root whose own copy reaches the epoch before it, or stops below that epoch without ending, "An overtaken J"), and
     for ⚠ only while another held copy contests it (the marks are pairwise). For such a J a confirmed ended copy
     counts as a confirmed copy, so the J is rejected: also an honest re-add for an epoch below the root of a forged
     ended copy, for as long as self holds that copy, which is for good once a row of the forger's second account has
     accepted it (§11.5, §13.2 item 16).
   - X sets the copy to removed (`canSend = false`; §11.2) and shows "@by removed you", unless X had left in e: the copy
     holds a LEAVE record for an epoch `e_L ≤ e` (§6.9; a copy that a legacy skip record started counts only its own
     records, §7.2). Snapshots keep every LEAVE record of the copy (§7.4), so a restore, or history that reads C,
     decides this from the same records as the live device. The line is derived from the records, not latched when C is
     processed: when a LEAVE record for an epoch `≤ e` is applied after C (a sibling's record that reaches the device on
     `Tself` after C, or the leaver's own record, which it writes only after its LEAVE put's OK, §6.9, while C was
     stored just before that row), the line is derived again, as step 5's lines are. A restore that later processes or
     reads C shows the same as the live device. When X had left in e only because its LEAVE put raced C (the row stored
     after C, its record written after the put's OK), X shows "you left the conversation" at that row, although §6.8
     drops the row (§6.9), so one of the two lines shows.
   - X stops following new epochs, and once C is final it sweeps the lanes of e, and the lanes of e−1 it still
     followed, to their heads (§11.2) and then stops following them: §6.8 drops every row of e that a member stores
     after C, for X as for a removed sender's rows, so that sweep finds every row of e X will ever
     show, and restores and scrollback show the same rows. It keeps its old epochs for history.
   - X records the end in an **ENDED** record `(conv, root, e, C's position)`, written with its next HEADS row
     (§7.2, §7.3), so that a restore neither probes the control lane of e nor fetches C's
     bundle again: it reads C at that position only when it needs C, for the copy's rows or history (§11.4 step 5).
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
       is then a failure of this check: at most 32 encapsulations in all);
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

     **Check order**. The D′ checks are one conjunction over data the member already holds: the claim is
     D′-invalid iff at least one of them fails, whichever it is. A checker MAY evaluate them in any order and MAY stop
     at the first failure (for example, it may compare `H(D')` with `hD` before parsing D′). Every check MUST be
     total: for any bytes a committer or the server can supply it passes or fails, and it never throws past the
     checker, waits or makes a request. The same holds for the local checks of §6.7 steps 1–2 on a fetched blob. This
     paragraph changes no order that this spec states explicitly, such as the `rm` bit before the entry (step 3: a
     removed member is removed whatever its entry holds), the own entry before the D′ checks (this step: it selects
     the warning), the order of e-validity's requests (§6.4: the local rules first, among them the `bundleSize`
     clause of (g) and `B ≥ |D_e|` of (h), then (f), (g) and (h)), `bundleSize`, then `meta`, then the blob (§6.7 step
     1), and the server's order of checks (§10.1).
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
   leavers (§11.9). A removed member shows only "@by removed you" (nothing when it had left in e, step 3). Who had
   left is the member's current leave state
   in e (§6.9), not the state when C was processed: when a source of a leave in e is added, replaced or dropped later
   (a sweep, scrollback, a late frame, or §6.8 on a new final winner), the two lines are derived again, so the same rows
   give the same lines in every order of arrival. A reload holds fewer rows: the leave state of its HEADS
   epoch and of later epochs comes from the LEFT records and the lanes it processes (§11.4 step 5), as live, but that of
   an older epoch only from the rows that the initial history and scrollback load (§11.4 step 6, §11.10). So until
   they load a leave's source, a claim below the HEADS epoch can show a removal where the live view showed "keys
   rotated". The gate of step 6 depends only on the current epoch, so a reload keeps it.
6. **Frozen.** There is one frozen state; the two warnings above differ only in what X could see. A frozen member:
   - stays in epoch e, keeps receiving there, and applies the cut rule through `rm` (§6.8);
   - keeps sending there (`canSend = true`), unless `rm` of C has a bit for a member who had not left (by the current
     leave state, step 5). That member was told it was removed but still holds e's keys, so texts, images and
     reactions in e are refused (§11.3);
   - refuses its own membership changes with "the members of this conversation can no longer change; start a new
     conversation" (its control lane of e has a winner it cannot follow).

   A freeze is permanent, as in v1: the members start a new conversation to change membership. It needs no self
   record, because every device re-derives it from the control lane and the bundle (§11.4).

While the current epoch has an undecided control slot before any winner, or a winner that is not yet final or
processed, sends wait until the control lane has been so for 30 s and then fail, as in v1 (§11.3 step 2; the
30 s count from when the lane became unsettled, not from each send). Commits wait until the control lane
is settled.

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
   directory's is checked in step 6, only where it matters (a first contact, a re-add included, or a separate copy).
3. **Duplicate.** Ignore the join if any copy, ended or not, already holds `(conv, e)` with the same `H(D)`. Step 4
   can move a copy to e (it processes the claim that ended e − 1), so this step is applied again after step 4. One D
   can be registered in several bundles (`descCt` is sealed with a random nonce, §5.4), so no rule here compares
   `bundleId`.
4. **Settle the held copies.** For each held copy of `conv`, catch up the control lane of its current epoch k until
   either the winner is final and processed, or every slot is decided not e-valid and the current era has been
   probed (processing a winner moves the copy on, or ends it, §6.6 step 3, and the catch-up goes on in its new
   current epoch). If a slot is still undecided or a winner not yet final, **park** the join: keep it, re-evaluate it
   after the next catch-up, and keep the inbox cursor (for a WELCOME, the lane's processed position, and the carrier
   copy's HEADS entry at that lane's epoch) before it (§7.3, §11.5). A removed member or a leaver keeps following the
   control lane of its last epoch until such a winner is final and processed. A copy that has ended needs nothing
   more: its last winner was processed, or it holds the epoch that its ENDED record names (§6.6 step 3, §7.2); a copy
   whose ENDED record names a later epoch is settled up to that epoch as any copy is, and ends there. A copy that an
   earlier J of the same inbox poll (or batch of joins) created is not held yet (its records are written with the
   poll's, §7.3): a J of its conversation is parked until the next poll, when that copy is held and this step settles it
   (§11.5 step 2). So an honest re-add's J always finds the copies it follows settled: one that a later claim removed
   self from has ended here, and steps 5–6 count it for nothing. Then apply step 3 again.
5. **Fit.** For each held copy that has not ended, with current epoch k:
   - **Claimed.** `e = k + 1` and the final winning claim C of k names `hD = H(D)`: ignore the join. The copy has
     processed C (step 4), so it either holds e already (step 3) or is frozen by C, and a J never overrides the
     verdict of the claim (§6.6).
   - Otherwise it does not fit this copy. A held conversation never skips epochs.

   An ended copy fits no J (§6.6 step 3): a J that re-adds self after a removal starts a separate copy in step 6.
6. **No fit.** In this step a held copy that has ended (§6.6 step 3) counts as no copy, except for a J that contradicts
   its history, a fork, for which it counts as a held copy ("Forks of an ended copy", below). **An overtaken J**: when
   the J is no fork of an ended copy by its own epoch (one for an epoch that the copy holds with another `H(D)`, or for
   the epoch after its last, below), its e is below the root epoch of every held copy of `conv` that has not ended, and
   some held copy of `conv`, ended or not, has its root epoch above e (r is the lowest such root), the device first
   settles the copy that the J would start, as step 4 settles a held copy: its control lane of e, under the J's EK, from
   `(E_start(e), 0)`, and on through the epochs that its own entries reach, stopping if it reaches epoch r − 1 (a
   pending claim or a transient failure parks the join). Each epoch that copy reaches is compared with every held copy
   that holds it: one that holds it with another `H(D)` makes the J a fork of that copy (below), and the settle stops
   there (no copy held when the settle starts holds an epoch between e and r, since it would hold e and make the J a
   duplicate or a fork, so this decides only for a copy added while the J is parked, such as a sibling's). If that copy
   ends first (a final winning claim of an epoch below r − 1 removes self), it is kept as a separate copy that has ended
   (a request or not, by the rule below), after the `D.by` key check below, with no warning, and nothing below applies
   to it: an honest J that a later re-add overtook (one carried by a WELCOME that a device processes after its inbox
   delivered the later re-add's J, or one that reaches a sibling after its own) is no second copy, since an honest
   re-add at r follows a removal at r − 2 or earlier. A copy that reaches r − 1 (it lists self in the epoch before a
   re-add at r), or that stops below it without ending (frozen, or with no winning claim), contradicts the copies rooted
   at r, which then count as held copies for its J, confirmed as defined below, also when they have ended; its J goes on
   below, as every other J that fits no copy does, without being settled further. For every J that this paragraph does
   not keep:
   - If the client holds no copy: this is a first contact. Accept it on the signature alone as a new copy whose root
     is `H(D)`, after the **`D.by` key check**: D's `sigPk` for `D.by` equals the `sigPk` of `D.by`'s verified
     directory bundle (from a MEMBER record, or fetched by prefix, §10.6) and agrees with any CONTACT or MEMBER pin.
     If the check fails, drop the join with the noise warning "ignored a conversation key with an invalid
     signature" (anyone can send such a join, §12.7), and no copy is created; a lookup that fails transiently parks
     the join (step 1). A newly added member cannot verify the history before it. The copy is a **request** (§11.5)
     unless `D.by` is a contact (§7.3). For an accepted join or a created request, the first verification of
     `D.by`'s bundle writes a MEMBER record from it (§7.3); a dropped join writes nothing. **A re-add** after a
     removal is such a first contact: its copy, rooted at `H(D)` of e (§7.2), is separate from the ended
     copy, which keeps its epochs, rows and lines ("@by removed you", or the leave lines); the new copy shows
     "`who(by)` added you" (§11.9) and has no leave (§6.9).
   - If any held copy is **confirmed**, reject the join with the critical warning "ignored a conversation key that does
     not match the conversation history".

     A copy is confirmed when either holds:
     - a member other than its `rootBy` **and other than self** has posted a valid row in it (of any type, a REACTION
       included, §11.12), or a final e-valid claim by such a member exists in it;
     - self created it.

     A row confirms a copy only once the copy's control lane is settled (step 4) and only while the copy has not
     ended (§11.5). A claim confirms it once the device processes it, or reads it at a record's
     position (§6.8), the claim that ended the copy included, since it proves a third member as a row does. A device
     records a confirmation in a CONFIRMED record (§7.3): a row's at once, a claim's with its next HEADS row, so a
     restore that never processes the claim (one below its start, or the one an ENDED record stands for, §11.4 step 5)
     holds the copy as confirmed, as the live device did.
   - Otherwise keep the join as a **separate copy** (a request or not, by the same rule, after the same `D.by` key
     check as a first contact) and raise the critical warning "@x sent you a second, different copy of a conversation
     you were added to; both are shown marked ⚠ — only one can be genuine". A copy that is not confirmed is shown
     with "⚠ " while it and another held copy of the conversation **contest** each other:
     - two copies that have not ended always do;
     - an ended copy and another copy do while the other holds one of its epochs or the epoch after its last (a fork
       of it, below);
     - an ended copy rooted at r and a copy rooted below r do while the latter holds epoch r − 1 or has not ended (it
       contradicts the copies rooted at r, as "An overtaken J" above says).

     For ⚠, a copy whose ENDED record (§7.2) the fold holds counts as ended at the epoch that the record names, also
     while the device has not yet brought the copy to that epoch (a request whose probe has not reached it, §11.4 step
     5). A restore derives all of this from the copies' root epochs, their current or last epochs and their ENDED
     records. An honest re-add's copy starts at least two epochs after the removal that ended the copy before it, and
     an honest copy rooted below it has ended by then, two epochs below its root, so honest copies contest nothing,
     except on a lagging device, which marks a copy that it has not yet processed to its end only until it does.

   **Forks of an ended copy**. A J that contradicts an ended copy's own history is a provable fork: one for an epoch e
   that the copy holds with another `H(D)` (with the same one it is a duplicate, step 3), or one for `e = k + 1`, where
   k is the copy's last epoch (its final claim removed self, so no D of k + 1 that lists self, as step 2 requires, has
   that claim's `hD`). For such a J the ended copy counts as a held copy in this step, confirmed as defined above, and
   the J's own copy is not settled first: the J is rejected, or kept with the second-copy warning, as against a copy
   that has not ended. A J for an epoch above `k + 1` contradicts nothing that the copy holds. One below the copy's root
   epoch, when it is an overtaken J (above), contradicts the copy, which then counts for it in the same way, when its
   own copy, settled first, reaches an epoch that the copy holds with another `H(D)`, or when the copy is rooted at r
   and the J's own copy does not end below r − 1.
7. On acceptance, write CONV_JOIN or REQUEST (a new copy) to the self lane at once (§7.3), a CONV_JOIN in the same
   row as a TREG for its bundle, and a REQUEST with its own `t_reg` field, each with the `t_reg` of step 1's `meta`
   answer. For an accepted copy that has not ended, subscribe to `T_e` and probe the control lane and the lanes from
   `E_start(e)`. A request is probed as §11.5 says. A copy kept as ended (step 6) is not subscribed; the lanes of each
   epoch it held are processed before the switch past it, as a restore processes them (§11.4 step 5 "Lanes"), and those
   of its last epoch swept as §6.6 step 3 says.

### 6.8 Old-epoch acceptance (cuts and claim times)

A receiver accepts a valid lane row R of epoch e from `s = D_e.members[i]` at `(E', n')`, with stored time `t_R`,
iff this walk accepts it. For `j = e, e+1, …`, while s is a member of `D_j` at index `i_j` (`i_e = i`) and the
receiver holds `D_{j+1}` or the final winning claim `C_j` of epoch j (with stored time `t_j`). The epochs are
consecutive held epochs of the row's copy: a walk never crosses copies. A copy that a re-add started holds no epoch
below its root, and an ended copy none above the epoch whose final claim removed self (§6.6 step 3, §6.7 step 6).

- If bit `i_j` of `rm(C_j)` is 0, s continues into `D_{j+1}`. If the receiver holds `D_{j+1}`, continue with `j + 1`.
  Otherwise a receiver removed or dropped at j+1 (its own bit in `rm(C_j)` is 1) accepts iff `t_R < t_j`, or `j = e`,
  `t_R = t_j` and R is before the cut of lane i in `C_e`, and stops; any other receiver (a frozen one, or one that holds
  `C_j` but has not yet derived `D_{j+1}`) stops and accepts, and decides the row again once it derives `D_{j+1}`.
- If the bit is 1 (s was removed or dropped at j+1), accept iff `t_R < t_j`, or `j = e`, `t_R = t_j` and R is before the
  cut of lane i in `C_e`. Stop.

If the walk ends without a removal, accept. So a removed receiver's view of an epoch ends at the claim that removed it,
for every sender, as a removed sender's rows end there for everyone.

**The bit without `C_j`**. A receiver that holds `D_{j+1}` accepted it through `C_j`, whose `rm` has bit
0 exactly for the members of `D_j` that `D_{j+1}` lists (§6.6 step 4). It therefore reads s's bit from `D_{j+1}`, and
needs `C_j` itself only at a step whose bit is 1 (for `t_j`, and for the cut when `j = e`). A receiver that was removed
or dropped at j+1 holds no `D_{j+1}` and needs `C_j` at step j. A receiver that needs `C_j` but did not
process it (a restore that started at a later HEADS epoch with that epoch's key from a snapshot's EPOCH record, §11.4
step 5, or scrollback, §11.10) reads `C_j` from the position that the EPOCH record of epoch j+1 names (§7.2).
When self was removed or dropped at j+1, the copy has ended at j and holds no later epoch: `C_j` is the claim that ended
it, which a restore processes, or reads at the position of the copy's ENDED record (§7.2, §11.4 step 5). A restore
starts no higher than its snapshot's top (§11.4 step 5: the highest epoch whose key the copy's CONV_JOIN or a flag-0
EPOCH record of the snapshot gives), below which the snapshot holds an EPOCH record for every held epoch (§7.4); above
it, it re-derives every held epoch by processing the claim before it (§7.3, §11.4 step 5), and between a lower start
(the HEADS epoch) and it, it reads each winning claim at the position this paragraph names (§11.4 step 5). So it holds
every held epoch and those claims. The copy's previous held epoch below an epoch e is e − 1, which the copy holds unless
e is its root epoch. The read is a body `get`, opened with `mk_j`, whose stored `t`, `rm` and cuts the receiver uses
without evaluating the claim again (the record is the account's own). It retries a transient failure, and the row is not
shown before it is decided. A receiver never accepts a row because it lacks `C_j`.

- A committer cannot erase a removed member's earlier rows with a low cut: rows with `t_R < t(C)` are always
  accepted. It cannot let a removed member keep posting with a high cut either: rows with `t_R > t(C)` are always
  dropped. The cut only decides rows in the claim's own Δ batch.
- A member removed at e+1 cannot post into e after the claim, nor into any earlier epoch after a later claim that
  removed it. Equal times count as "after" for later claims, which is the safe side.
- Valid rows of members who are still listed are shown even if they land late, except to a receiver that a claim
  stored before them removed.
- Every device applies the rule to the same stored `t` and the same public `rm` (from `C_j`, or from `D_{j+1}` as
  above), so live, restored and frozen views agree: a freeze stops every continuing member of e at e (§6.6), so frozen
  members hold the same claims as the others, and a removed receiver drops every row stored after the claim that
  removed it, so its final sweep (§6.6 step 3), a restore and scrollback show the same rows. A row
  that it showed before it processed that claim and that was stored after it is retracted like any other row this
  rule drops (below). Decisions are recomputed when the receiver learns a new final winner: a
  row that is now dropped is removed from the view and from `unread`. Dropped rows give no warning, and §11.3 step 7
  marks one's own echo `failed`. A leave stands in an epoch only while this walk accepts the source the receiver keeps
  for it there (§6.9: the least of the leaver's LEAVE rows in that epoch and the leaves carried into it). When that
  source is dropped, the leave is un-recorded in that epoch, and no other source can keep it: along the same walk a
  source with a smaller key is accepted whenever one with a larger key is.
- A LEFT record (§7.2) carries the stored time of its LEAVE row and, when it names the row's own epoch, the row's
  position. A leave taken from one (§11.4 step 5) is decided by this walk exactly as the row would be: the walk starts
  at the record's epoch, and the equal-time cut applies only to a record that carries a position (a carried record's
  position is NONE, which is never before a cut). So a claim that drops the row un-records the leave on a restored
  device too. Every device keeps the least source per epoch and member, whatever the order in which it
  learned the sources, and its LEFT record names that source (§6.9, §7.3), so live and restored views agree whenever
  the record was written.

### 6.9 Leave and remove

- **Leave.** The leaver posts a LEAVE row (type 17) on its own lane of the current epoch (§11.3) and, only after the
  put returned OK (or a probe found its own body), writes a LEAVE self record. A device that applies a LEAVE row of
  its own account for which no LEAVE record exists writes the record, so a crash between the two writes is repaired by
  any device, and a record never exists without its row. The leaver stops sending, shows "you left the conversation"
  once, at the earliest own LEAVE row it holds (a repeat, below, adds no line; after a reload the line appears when
  the initial history or scrollback loads that row, while the copy is `left` at once from its LEAVE records), and sets
  `canSend = false`. §6.8 does not decide this line, which follows the device's own leave: an own LEAVE row that §6.8
  drops, because it was stored after the claim that removed self (the put raced that claim), still places it, while §6.6
  step 3 withholds "@by removed you". It keeps following the control lane of its current epoch (a claim that keeps it
  moves it to the next epoch like any member, §6.6) until a final winner drops it (§6.7 step 4). Until then it also
  keeps processing the copy's lanes for WELCOME rows only (it shows nothing else), and sweeps them once more when the
  dropping winner is final (§11.2, §6.6 step 3), so a WELCOME stored before that winner is not lost, also one written
  before the sender learned of the leave, or before the leave itself. A WELCOME stored after that winner is dropped for
  the leaver by §6.8, like every row of that epoch. Only another device of the sender's own account can write one,
  racing the rotation its sibling committed (in a 1:1 the sender's account is the only other member, §6.12), and its J
  may then be lost for the leaver (§13.2 item 15). Senders still never choose a copy in which they have seen the
  recipient's LEAVE as a WELCOME channel (§6.12). Receivers record the leave in e and in the consecutive later epochs
  e+1, e+2, … that they hold, up to the first that does not list the leaver; so a leaver who is dropped and later
  re-added is not recorded as left in the epochs of the re-add (on the leaver's side, the re-add is a separate copy
  without a leave, below). Each epoch in which a receiver records the leave gets a LEFT record with the row's stored
  time and, for the row's own epoch, its position (NONE for an epoch the leave was carried into; §7.3), so a reload does
  not forget the leave and decides it by §6.8 as it would decide the row.
- **Several sources**. A member can be recorded as left in one epoch k from several **sources**: each of
  its LEAVE rows in k (with the row's stored time and position), and each leave carried into k from an earlier epoch
  (with that row's stored time and NONE), for example the leaver's own repeat (below) in an epoch into which a racing
  claim carried its first leave. A source's **key** is `(t, position)`, compared by t, then by position, where NONE
  counts as after every real position (unlike the order of §3.1). Per copy, epoch and member, the receiver keeps only
  the source with the least key, whatever the order in which it learned the sources: a source with a smaller key
  replaces the kept one (the receiver writes its LEFT record, §7.3), and one with an equal or larger key changes
  nothing. The leave stands in k iff §6.8 accepts the kept source; because a smaller key is accepted whenever a larger
  one is (§6.8), the kept source is accepted whenever any source is, and every device that holds the same rows reaches
  the same verdict. The "@x left" line belongs to one LEAVE row per leave: a kept source that §6.8 accepts, in an
  epoch k such that x is not recorded as left in k−1 (§11.9). A claim's removed and rotated lines follow the leave state
  (§6.6 step 5), so they too depend on the rows held, not on the order in which they arrived.
- **The leaver's own state.** A copy's leave is **current** once the copy has a LEAVE record (its own records: for a
  copy that a legacy skip record started, those that §7.2 assigns to it), and it stays current: a leave belongs to
  its copy, which never continues past the claim that drops self (§6.6 step 3), and a re-add starts a separate copy,
  which has no leave (§6.7 step 6). The latest LEAVE record is the one with the highest e, whatever the order of
  the records (§7.3). While the leave is current the copy is `left` (§11.2; sends are refused, §11.3 step 2).
- **Repeating a LEAVE.** The others see a LEAVE row only if it lies in their current epoch, or in the previous one
  while they follow the leaver's lane there (§11.2). So whenever a leaver's copy is in an epoch c that still lists self
  (self was not removed or dropped), its leave is current, and its latest LEAVE record names an epoch `e_L < c`, a
  device of the account puts a LEAVE in c. Devices check this after every catch-up and restore, and in §11.3 step 8,
  also in a frozen copy (the freeze itself posts nothing, §11.4 step 5). The put runs §11.3 steps 1 and 2 (without the
  "you left" refusal), then steps 4–8, and writes its own LEAVE record after its OK. This is how a late LEAVE (§11.3
  step 8) is repeated, also by another device or after a reload. The rule does not test whether the others still
  follow self's lane of c − 1 (a restore cannot see self's rows before its HEADS positions); an unneeded repeat costs
  one row, and a duplicate LEAVE is harmless.
- **Rotation after a leave.** A remaining member MUST commit an epoch without the leavers (§6.3) before sending a TEXT,
  IMAGE or REACTION in an epoch that lists a member who has left, unless it is frozen in that epoch or the epoch is
  `2^32 − 2` (§11.3). Clients MAY rotate proactively: the remaining member of rank r (by index among non-leavers) waits
  `r × 30 s + random(0..10 s)` after seeing the leave, and aborts if a claim appears first. A member added by a commit
  that raced the LEAVE (its committer built `D′` before the row reached it, so `D′` still lists the leaver) holds no
  epoch of that row and does not see it. It records the leave only when the leaver's device repeats it in an epoch
  the new member holds (above). Until then, a claim that drops the leaver (a member who saw the leave rotating) is a
  removal to it: it shows "`who(by)` removed `who(x)`" where the members who saw the leave show "keys rotated after
  `who(x)` left", and if that claim froze the conversation it refuses texts there while they may still send (§6.6
  steps 5–6). Members that hold different rows can thus show different lines and gates. Its texts sent
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
    claim, the record is dead: it is ignored and dropped from snapshots. A record of a legacy copy is checked in the
    copy that §7.2 "Legacy skip records" assigns it to. A record for k + 1 of a copy that ended at k is
    dead without a read of `C_k`: the claim that ended the copy removed self, and a claim of self never does, since
    its committer is listed in its `D′` (§5.1, §6.6).

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
- A record with an unknown `rtype` is skipped by its `len` (forward compatibility). This is how a client that
  predates a record type reads rows that hold one: the **first release** (the client deployed in production on
  2026-10-27) skips TREG and ENDED (§7.2).
- A known record's content has exactly the length its layout gives and obeys its row in §7.2: CONV_JOIN and REQUEST
  `via ∈ 1..5`; EPOCH `e ≥ 1`, only flag bit1 allowed, `(claimE, claimK)` a position; ENDED `(claimE, claimK)` a
  position other than NONE; LINK only flag bits 0–1; PREFS `len ≥ 1`; the counts of §7.2; DESC and
  REQUEST `224 ≤ dlen ≤ 2960`; MEMBER's handle; LEFT's `(E, n)` a position; SNAP's `(Eh, nh)` a position.
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
| 0x01 | CONV_JOIN | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | rootBy[16] | u8 via` (137 B). An accepted copy. `via`: 1 = created, 2 = inbox, 3 = welcome, 4 = hello, 5 = request accepted. Its bundle's `t_reg` is in a TREG for its bundleId (in a join's row and in every snapshot), or in the EPOCH_PENDING or REQUEST that names the bundle (§7.3, §4.2). |
| 0x02 | EPOCH | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u16 claimE | u32 claimK | u8 flags` (127 B). Epoch e ≥ 1 of this copy, reached through the account's own bundle entry (§6.6 step 4); new code writes EPOCH records only in snapshots, with flags 0 (§7.3, §7.4), each with a TREG for its bundleId (§7.4). `(claimE, claimK)` is the position of the final winning claim on `Lctl_{e−1}` that ended the copy's epoch e − 1, so every held epoch above the root names the claim that a walk below it needs (§6.8). A restore holds every held epoch (§11.4 step 5), because it never starts above its snapshot's top, the highest epoch that the CONV_JOIN or a flag-0 EPOCH record of the snapshot gives (§11.4 step 5), and a snapshot holds a record for every held epoch below its top (§7.4). `flags`: bit1 marks a **legacy skip record** (below), which the first release writes for a skip re-add; new code never sets it. Every other bit, bit0 included, is 0. |
| 0x03 | EPOCH_PENDING | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u32 t_reg | u8 a | uid[16] × a` (125 + 16a B). Creation (e = 0) or commit intent: the uids that need J. |
| 0x04 | LEAVE | `conv[16] | root[32] | u32 e` (52 B) |
| 0x05 | CONTACT | `uid[16] | pin[32]` (48 B). TOFU pin of the bundle (§2.2). |
| 0x06 | LINK | `s[16] | u16 Ecreated | u16 Eexpires | u8 flags` (21 B). bit0 = one-shot, bit1 = revoked. |
| 0x07 | PREFS | `u8 key | value[len−1]`. No keys are defined in stage 1. The latest value per key wins. |
| 0x08 | HEADS | `u16 Ein | u32 relIn | u16 c | entry × c`, with `entry = conv[16] | root[32] | u32 e | u64 lastTs | u16 ctlE | u32 ctlCnt | u8 m | (u16 E | u32 cnt) × m | u8 f | (u32 ef | u16 ℓ | u16 E | u32 cnt) × f` (68 + 6m + 12f B per entry). Processed positions (§7.3). `c = 0` records only the inbox cursor. |
| 0x09 | CONFIRMED | `conv[16] | root[32]`. The copy is corroborated (§6.7), by a row or by a claim (§6.7 step 6). |
| 0x0A | DELIVERED | `conv[16] | root[32] | u32 e | bundleId[32] | u8 a | uid[16] × a` (85 + 16a B). These uids have been sent J for that EPOCH_PENDING (§6.12 step 3). Its row is padded to class ≥ 1 (§7.1). |
| 0x0B | REQUEST | `conv[16] | root[32] | u32 e | EK[32] | bundleId[32] | u32 bundleSize | u32 t_reg | rootBy[16] | u8 via | u16 dlen | desc[dlen]` (143 + dlen B), where `desc = D ‖ dsig` of epoch e. A request copy (§11.5). |
| 0x0C | DESC | `conv[16] | root[32] | u32 e | u16 dlen | desc[dlen]` (54 + dlen B, `dlen ≤ 2960`), `desc = D ‖ dsig`. The descriptor of epoch e of the copy, so a restore needs no bundle fetch for it. |
| 0x0D | MEMBER | `uid[16] | sigPk[32] | kh[32] | pin[32] | u8 hlen | handle[hlen]` (113 + hlen B). `handle` matches `^[a-z0-9_]{3,20}$` (§2.1), so `3 ≤ hlen ≤ 20` and the handle is ASCII; any other handle makes the record malformed. A co-member's directory bundle as self verified it: its `sigPk`, `kh = H(enc("segv.sh/v2/kh", kemPk))` of its `kemPk` (§5.1), and `pin` (§2.2), so restores need no directory lookup for that member (§11.4). |
| 0x0E | LEFT | `conv[16] | root[32] | u32 e | uid[16] | u32 t | u16 E | u32 n` (78 B). Another member's leave as self recorded it: `uid` is recorded as left in epoch e of the copy (§6.9). `t` is the stored time of the LEAVE row R of the leave's kept source (§6.9), and `(E, n)`, a position field (§3.1), is R's position when e is R's own epoch, or NONE when the leave was carried into e from an earlier epoch. Written as §7.3 says, so a restore does not need R and decides the leave as R would be decided (§6.8). |
| 0x0F | TREG | `bundleId[32] | u32 t_reg` (36 B). The registration time `t_reg` (seconds since T0, §8.2) of the blob `bundleId`, which for the epoch that bundle defines gives `E_start(e)` (§4.2) and the time of its join line (§11.8). It is a fact about the blob, so it names no copy or epoch. Written in the row of a join's CONV_JOIN (§7.3), and kept by snapshots for the bundle of every CONV_JOIN and EPOCH record they hold (§7.4). No parse rule on `t_reg`. |
| 0x12 | ENDED | `conv[16] | root[32] | u32 e | u16 claimE | u32 claimK` (58 B). The copy has ended in its epoch e (§6.6 step 3): the final winning claim of e, at `(claimE, claimK)` on `Lctl_e` (a position other than NONE), removed or dropped self. Written with the next HEADS row after that claim is processed, and kept by snapshots (§7.3, §7.4), so a restore neither probes that control lane nor fetches the claim's bundle (§11.4 step 5). The first release skips it (§7.1). |
| 0x20 | SNAP | `blobId[32] | key[32] | u32 size | u16 Eh | u32 nh` (74 B). Allowed only in rows at `Lsnap`. |

**Why TREG is a record of its own**. Appending `u32 t_reg` to CONV_JOIN and EPOCH would make them 141 and
131 B. The first release parses those records at exactly 137 and 127 B, and a row whose record has another length is
rejected as a whole (§7.1), so it would drop every row that holds such a CONV_JOIN or EPOCH (a creation, a join, an
accepted request, the rows of a poll's joins with the HEADS record that moves its cursor), in a tab still open on it or
after a rollback. It skips an unknown rtype by its `len` (§7.1), so a separate record keeps every row readable by it and
by later clients, and leaves the layouts that production self lanes already hold unchanged. TREG is keyed by the bundle
id alone, since `t_reg` is BlobReg's registration time of that blob (§8.2); at 39 B with its header it keeps a join's
row in class 0, and a creation's or accepted request's row needs none (§7.3). The CONV_JOIN and EPOCH records an earlier
version wrote have no TREG; a device takes their `t_reg` from the other sources of §4.2. No other stored layout differs
from the first release's, and every snapshot is written by a client that writes TREG (the first release writes none).
ENDED is a record type of its own in the same way, which the first release skips.
**Legacy skip records**. The first release lets a copy whose self was removed continue at a later epoch e′
through an EPOCH record with flag bit1 (a *skip re-add*). It writes such records, also for request copies, and a tab
still open on it may write one after new code is deployed; new code never writes one (§6.7). A reader MUST read an EPOCH
record `(conv, root, e′, EK, bundleId, bundleSize, claimE, claimK, flags)` with flag bit1 as the **join of a separate
copy** `(conv, H(D_{e′}))` at epoch e′, as if §6.7 step 6 had accepted that J:

- `D_{e′}` comes from the bundle (no DESC of that copy exists before a snapshot converts it), fetched and checked as
  §11.4 step 5 checks an epoch's bundle (its hash and size, `descCt` and `pkCt` open under `dk_{e′}(EK)`, `D.conv =
  conv`, `D.e = e′`, `dsig` under `kc_{e′}` for `D.by`, and self listed with its own `sigPk` and `kh`, §6.7 step 2). A
  record that fails a check is ignored, without a warning; a transient failure is retried. A record that matches a
  CONV_JOIN or REQUEST of its conv by `(e′, EK, bundleId)` (one that a snapshot wrote for it, below, or one that a
  device wrote for the same J) is that record's copy, with no fetch.
- Its key is `(conv, H(D_{e′}))`: it is the same copy as a CONV_JOIN or REQUEST of that key, written by a device that
  took the same J as a first contact, so the records merge (a CONV_JOIN supersedes the rest, §7.3), and two legacy
  records that read as one copy count once. Among the copies of its conversation it takes the place of the first of
  these records (§7.3 "Copy keys").
- It is an accepted copy (as a CONV_JOIN with `rootBy = D_{e′}.by`) when the fold holds a CONV_JOIN for `(conv,
  root)` that stays with the legacy copy it came from (below), and otherwise a request (as a REQUEST of the EPOCH
  record's row, so its age and its place among the 64 live requests are that row's, §7.3). When the fold also holds
  a CONV_JOIN or REQUEST of its own key, that record decides, as for any copy: a CONV_JOIN supersedes, and a REQUEST
  stays a request, which the legacy record never accepts (a tab on the first release that took a re-add
  as a skip of an accepted copy otherwise accepted a re-add that new code, by the first-contact rules, held as a
  request); the user's acceptance in such a tab does accept it (below).
- Its `t_reg` comes from a TREG for its bundleId, else from one `blob/meta` request (§4.2).
- `(claimE, claimK)` is ignored. The legacy copy `(conv, root)` ends at the claim that removed self (§6.6 step 3),
  which a restore processes like any other, and never continues.
- The legacy copy's records that name an epoch (HEADS entries, LEAVE and LEFT) belong to the copy that the bit1
  record of `(conv, root)` with the highest e′ at or below that epoch starts, and those below its lowest e′ to the
  legacy copy itself. An EPOCH_PENDING of the legacy copy, and its DELIVERED records, belong to the one of these
  copies whose final winning claim of e − 1 names its bundleId, or that holds e with that bundle, and are dead when
  none of them does (§6.11). A HEADS entry for an epoch that its copy never holds (below its root, or above the epoch in
  which it ended) counts as absent (§11.4 step 5). So each of these copies has its own latest HEADS entry (§7.3), and
  its own leave (§6.9) and lines (§6.6 step 3). A CONFIRMED record and a CONV_JOIN of `(conv, root)` stay with the
  legacy copy, except those that the first release writes for a copy it continued by a skip: a CONFIRMED and a CONV_JOIN
  with `via = 5`, each in a self row without a HEADS record, that come after a bit1 record of `(conv, root)` in
  self-lane order belong to the copy that the latest such bit1 record before them starts, which that CONFIRMED confirms
  and that CONV_JOIN accepts, also when the fold holds a REQUEST of that copy's own key (the first release writes both
  only in rows of their own, for a row of a third member in that copy, or for the user's acceptance of it as a request,
  with the legacy copy's root epoch and key in the CONV_JOIN). New code writes every CONFIRMED and every CONV_JOIN with
  `via = 5` in a self row that also holds a HEADS record (§7.3), so they stay with their copy, and a snapshot writes
  every copy's records under that copy's own key (§7.4). A separate copy is otherwise confirmed as any copy is (§6.7
  step 6). The records do not name the branch they describe: when a device on the first release continued one copy past
  the epoch of a sibling's later bit1 record (only a forged J leads there, since an honest re-add follows a removal),
  that copy's records of those epochs go to the later record's copy, and it restores those epochs without them, from the
  start of their lanes, where it finds its own LEAVE rows again (§6.9).

A snapshot writes such a copy as its own CONV_JOIN (`via = 2`: the carrier is not recorded, and `via` 2 to 4 decide
nothing) or REQUEST, with the records any copy of its kind gets, and keeps the bit1 record beside it (§7.4), which a
reader matches to that record without a fetch (above), so the conversion is done once; the kept record still assigns
the records that a tab on the first release writes later under the legacy key. A
restore reads the bit1 records of the snapshot and of the self delta this way (§11.4 step 5), and a live device reads
one that a sibling writes on `Tself` the same way (§11.7). Compatibility: the first release reads the CONV_JOIN or
REQUEST that new code writes for a re-add as a new copy, but its fold drops a CONV_JOIN for a conversation that holds
another copy with a CONFIRMED record, with the critical warning of §6.7 step 6 (a rule that §7.3 withdraws). So a tab
still open on it may show that warning and continue the ended copy by its own skip until it reloads into new code, which
reads that skip as the same separate copy; and a client rolled back to the first release drops such a re-add's CONV_JOIN
on every restore, with that warning, and never takes the J as a skip, since the inbox cursor that new code recorded lies
past it: the re-add is hidden on that client until it rolls forward, and no record is lost. Unlike in the first release,
a claim confirms a copy too, the claim that ends it included (§6.7 step 6), so more copies carry a CONFIRMED record,
most of them ended ones, and that fold drops a re-add's CONV_JOIN in more conversations. Such a client, or an old tab,
also accepts a request on a row of a member other than `rootBy` and self only while the copy holds no CONFIRMED record,
so a request that a claim confirmed stays a request there until the user accepts it or it expires; new code accepts it
on that row (§11.5). Conversely, a CONV_JOIN that the first release's fold dropped by that rule is held by new code as
written, without a warning, and is marked ⚠ while it is contested (§6.7 step 6).

**Counts.**

- EPOCH_PENDING and DELIVERED: `a ≤ 32` (honest writers write at most 31; `a = 0` is valid). The uids form a set; a
  repeated uid is not a parse error.
- HEADS entry: `1 ≤ m ≤ 32` and `f ≤ 32`. `c` may be any u16 (`c = 0` records only the cursor).
- A record that breaks a count rule is malformed (§7.1).
- When a reader uses a HEADS entry for epoch e of a copy, it MUST ignore the entry (the copy restores as if it had no
  HEADS entry, §11.4 step 5) if `m ≠ |D_e|`, or if two followed lanes with `ef = e − 1` name the same ℓ, or one of
  them names `ℓ ≥ |D_{e−1}|`. Followed lanes with `ef ≠ e − 1` are ignored one at a time (below). For a copy that does
  not hold epoch e−1 (e is its root epoch, §11.2), the reader MUST ignore every followed-lane entry and use the rest of
  the entry; the two ℓ checks then do not apply.

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
| CONV_JOIN | `(conv, root)` | the first one wins; it supersedes a REQUEST, and a legacy skip record read as a copy (§7.2), with the same key. Another copy of the same `conv` never makes the fold drop a CONV_JOIN: §6.7 step 6 decides on the device that takes the J, and a sibling's record is held as written. A CONV_JOIN with `via = 5` of a legacy copy's key that the first release wrote after a bit1 record, in a row without a HEADS record, accepts the copy that §7.2 assigns it to. |
| REQUEST | `(conv, root)` | the first one wins. At most 64 are live: older ones (by self-lane order) are dropped, and so is a REQUEST whose row's stored `t` is more than 4 eras old. A REQUEST that a CONV_JOIN supersedes, or that is no longer live, makes no request copy but still names its bundle's `t_reg` (§4.2). |
| EPOCH | `(conv, root, e)` | flags 0: the first one wins. A record with flag bit1 is a legacy skip record (§7.2): every one is kept apart from the flag-0 records and read as the join of its own copy, and those that read as the same copy count once; one that matches a CONV_JOIN or REQUEST of its conv by `(e, EK, bundleId)` is that record's copy (§7.2) |
| TREG | `bundleId` | the first one wins (every record of a key carries the registration time of `bundleId`, which never changes, §8.2); a reader uses the TREG for the epoch's bundleId (§4.2) |
| ENDED | `(conv, root)` | the first one wins (every device that processes the copy's end names the same claim, §6.5); a device that applies it, its own or a sibling's, ends the copy once the copy holds that epoch, without processing the claim (§6.6 step 3) |
| EPOCH_PENDING | `(conv, root, e, bundleId)` | every record is kept |
| DELIVERED | `(conv, root, e, bundleId)` | the uids are united |
| DESC | `(conv, root, e)` | the first one wins |
| MEMBER | `uid` | the first one wins (see the pin check below) |
| LEAVE | `(conv, root, e)` | every record is kept; the copy's *latest* LEAVE record is the one with the highest e (§6.9) |
| LEFT | `(conv, root, e, uid)` | the record with the least `(t, (E, n))` wins, NONE counting as after every real position (the key of §6.9), so identical records count once and the fold holds at most one record per key; it stands for its LEAVE row and is decided by §6.8 |
| CONTACT | `uid` | the first one wins (see the pin check below) |
| LINK | `s` | |
| CONFIRMED | `(conv, root)` | (written for a confirming row or claim, §6.7 step 6); one of a legacy copy's key that the first release wrote after a bit1 record, in a row without a HEADS record, belongs to the copy that §7.2 assigns it to |
| HEADS | per copy | the latest entry wins (an entry of a legacy copy belongs to the copy that §7.2 assigns its epoch to); `(Ein, relIn)` takes the maximum. A record may hold any subset of copies. A restore also keeps, per epoch of a copy, the furthest control position `(ctlE, ctlCnt)` of the entries it applied, the replaced ones included (§11.4 step 5). |

**Contacts.** A CONTACT is written for every user that self resolves by handle (creation, add), and for `D.by` (the
copy's `rootBy`) when the user accepts a live copy whose `rootBy` is neither self nor a contact: with the accept
control (`accept`, §11.11), or by self's first TEXT, IMAGE or REACTION in it (§11.5). An incoming join never creates a
contact, and neither does a third member's row that accepts a request (§11.5), nor `markRead`, which only reports an
open pane (§11.10): a user becomes a contact only by self's own act. (The first release also writes one when a third
member's row accepts a request; such a record counts like any other, so that user's conversations ring, §13.4.) A
second CONTACT for the same uid with a different pin, or a directory bundle whose pin differs from the pinned one,
raises the critical warning "the public keys of @x changed".

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
Later copies get `b64u(conv) + "~" + i` (i = 1, 2, … in that order). A legacy skip record counts, for this order, as
the CONV_JOIN or REQUEST of the copy it starts, at its own place (§7.2), and a snapshot writes that copy's record
there. A device numbers it when it applies it, without its bundle: as the copy of an earlier CONV_JOIN, REQUEST or
bit1 record of its conv with the same `(e, EK, bundleId)` (a device or tab that took the same J), else as a new copy,
and a later CONV_JOIN or REQUEST that matches it so belongs to that copy; when the bundle later shows that it starts a
copy that already has a key (the same D in another bundle), or it fails a check (§7.2), its number stays unused. Keys
are view ids of one session and are never stored (§11.4): a device gives each copy its key when it applies the copy's
first record, keeps it for the session, ended or not, and never reuses a number. Snapshots keep the original self-lane
order of these records (§7.4), so a restore numbers copies as the device that wrote them, except after a snapshot
dropped an expired request of the conversation (later copies' numbers move down), after a sibling's row in an earlier
era was applied after this device's own later row (§7.2; the live device keeps the keys it gave), and once at the
upgrade, where a conversation that the first release continued by a skip shows the copy that the bit1 record starts as
`~i` and its ended copy as `b64u(conv)`.

**When to write.**

- A device writes a record when it causes the event: a creation (CONV_JOIN and EPOCH_PENDING in one row), a commit
  (EPOCH_PENDING, later DELIVERED), an accepted join (CONV_JOIN or REQUEST), a leave, a
  corroboration by a row (CONFIRMED, written before any CONV_JOIN in the same row), or an accepted request (CONV_JOIN
  with `via = 5`). The row of a join's CONV_JOIN also holds a TREG for its bundle, with the `t_reg` of §6.7 step 1's
  `meta` answer; a creation's row and an accepted request's hold none, since the EPOCH_PENDING or the REQUEST names
  the bundle's `t_reg` (so a lone join's row stays class 0, at 211 B, while a row holding several joins of
  one poll grows 39 B per join and may move up a class). New CONTACT and MEMBER records ride in the next HEADS row
  (except a CONTACT that the user's acceptance writes, below), and so do a copy's ENDED record and a CONFIRMED that a
  claim causes (§6.6 step 3, §6.7 step 6), since no self row follows a claim observed from another member (§13.1); LEFT
  records ride in every HEADS row or snapshot that holds an entry for their epoch (below). The device uses them locally
  at once. The MEMBER for a request's `D.by` rides in the REQUEST's row.
- **CONFIRMED and accepting records.** Every CONFIRMED and every CONV_JOIN with `via = 5` is written in a self row
  that also holds a HEADS record (at least `c = 0` with the inbox cursor), whatever its key, so that §7.2 never moves
  it to a copy that a legacy skip record starts, also when such a record lands only later or in another era: the first
  release writes these records only in rows without one. The CONTACT that the user's acceptance of a live copy whose
  `rootBy` is neither self nor a contact writes (§11.5) is written at once, in a self row that also holds a HEADS
  record, and never waits for the next HEADS row, which a device closed sooner would never write: for a request, in
  the row of its CONV_JOIN with `via = 5`; for another such copy, in a HEADS row written at once for it.
- **Others' leaves.** For every member uid that the device records as left in epoch e of a copy (§6.9: by applying its
  LEAVE row R, by carrying the leave into a later epoch, or at restore from a LEFT record, §11.4 step 5), it writes
  `LEFT{conv, root, e, uid, t, E, n}` for the source it keeps for uid in e (§6.9), where `t` is that
  source's LEAVE row R's stored time and `(E, n)` is R's position when e is R's own epoch, or NONE when the leave was
  carried into e. When a source with a smaller key replaces the kept one, the device writes the new source's
  record. A LEFT record stands for R: a leave taken from it is decided by §6.8 as R would be, so a claim
  that drops R un-records the leave on a live and on a restored device alike, however long before that claim the
  record was written. Every HEADS entry for epoch e, in a self row or a snapshot, MUST be accompanied **in the
  same row or snapshot** by a LEFT record naming the kept source of every member that the device writing the row or
  snapshot records as left in e (an earlier row does not count, because a snapshot may have compacted
  it away). Whichever HEADS entry a restore uses thus has the LEFT records of its epoch beside it, whatever snapshots or
  sibling rows came between, and lane positions may pass the LEAVE rows.
- Epochs accepted through the account's own bundle entry are **not** written as self rows: restore re-derives them from
  the control lane (§11.4), and snapshots carry them. So no self row follows a claim observed from another member
  (§13.1), and no self row of new code holds an EPOCH record: a re-add starts a separate copy with a CONV_JOIN or
  REQUEST (§6.7 step 6).
- Records are written at once, without waiting for siblings. Duplicates from sibling devices are harmless.
- **Durability order.** The joins found by one inbox poll are written, in order, in as few self rows as fit cls 3
  (a 32-member REQUEST is about 2.9 KB, so a row holds 5 of them; each CONV_JOIN goes in the same row as its
  TREG, and a CONV_JOIN with its TREG takes 179 B, so a row holds 91), and the HEADS record (`c = 0`) that
  moves the cursor past them goes in the last of these rows, written only after every earlier one is CAS OK. A
  REQUEST that the
  64-request limit would drop at once is not written. No HEADS record or snapshot records an inbox cursor or a lane
  position past a join, an own leave or a J that is not yet durably recorded (CAS OK) or is parked (§6.7). Others'
  leaves are made durable by their LEFT records (above). While a J found on a lane of epoch e′ of a copy is parked,
  every HEADS entry written for that copy (in a self row or a snapshot) describes epoch e′, or epoch e′ + 1 with that
  lane among its followed lanes, and holds that lane's position before the J, even after the copy has moved on:
  restore processes lanes only from the HEADS epoch on (§11.4). A failed write is retried before the cursor advances.
- **HEADS** is written in every snapshot; as a self row at most every 30 minutes (after a random delay of up to 5
  minutes), when processed positions advanced or new CONTACT, MEMBER, LEFT, ENDED or CONFIRMED records wait; and once
  right after registration, with the registration cursor (§11.1, §11.5). A writer splits HEADS over several records and
  rows so that each row fits cls 3, keeping each entry in the same row as the LEFT records of its epoch (above), and
  spreads the records that wait for a HEADS row over those rows in the same way: each row holds at most 255 records
  (§7.1) and a HEADS record.
- Writes use CAS at the first empty slot of era `max(E_now, the era of the self-lane head, regEra)`, never below the
  head's era or `regEra`: a device whose estimate lags must not write below the registration era, where a restore
  never looks (§11.4 steps 2–4). A device writes no self row before it knows `regEra` (§11.1 step 2).
  On CONFLICT the device applies the occupant (if it opens under `kS`) and retries at `n+1`. When the row holds the
  CONV_JOIN or REQUEST of a copy that §6.7 step 6 accepted, and the occupant holds a CONFIRMED record for another copy
  of the same conversation, the device first runs §6.7 steps 3–6 again for that J, step 4 settling every held copy of
  the conversation, those that the occupants added included: a J that step 3 now ignores as a duplicate, or that step 6
  now rejects (with step 6's critical warning), is taken out of the row, and so is one that cannot be decided at once (a
  pending claim, a transient failure), which is parked, with the cursor before it (§6.7 step 4). On WRONG_ERA(E′) it
  writes at the first empty slot of E′, unless E′ is below `max(the head's era, regEra)`; then it retries later. Once
  the account exists, every server component's clock is at least `start(regEra) − SKEW·1000` (§11.5 "Registration
  cursor"), so the Worker and the ShardDO accept `regEra` (§9.1, §9.7), and under the clock model a WRONG_ERA never
  names an era below it.

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
  - per accepted copy, ended or not: its CONV_JOIN, an EPOCH (flags 0) for every held epoch **above the copy's root
    epoch** (the CONV_JOIN carries the root epoch's key, and EPOCH requires `e ≥ 1`, §7.1), a DESC for the current epoch
    and for e − 1 when the copy holds it (whose lanes may be followed, §11.2; either one's history may be loaded at
    restore, §11.4 step 6), every EPOCH_PENDING that is neither dead nor complete (every listed uid covered) with its
    DELIVERED records, every LEAVE record of the copy (at most one per epoch, 52 B each, so §6.6 step 3 decides "had
    left in e" after a restore as live), CONFIRMED, its ENDED record (the fold's whenever the fold holds one, also while
    the writer has not yet brought the copy to that epoch, else one for a claim that the writer processed), the HEADS
    entry that the writer would write for the copy at that moment (§7.3: its own
    processed positions, which a parked J holds at an earlier epoch), and the LEFT records naming that entry's epoch:
    for each member that the fold or the snapshot's writer records as left in that epoch, exactly one, the least of the
    fold's record and the writer's kept source (§6.9), as §7.3 requires (a snapshot holds at most one LEFT record per
    member, so repeated HEADS rows and snapshots never pile up copies). Every held epoch above the root was reached
    through the account's own bundle entry, so its EPOCH has flags 0 and `(claimE, claimK)` = the position of the
    winning claim on `Lctl_{e−1}` that the device processed, or read at its record's position (§7.2). With them goes a
    TREG for the bundle of the CONV_JOIN and of each EPOCH (39 B with its record header, one per bundleId), for each
    bundle whose `t_reg` the writer holds from a source that names it (§4.2: a TREG; the copy's REQUEST, or an
    EPOCH_PENDING of that epoch, with that bundleId; or a `meta` answer for that bundle id, such as §6.4(g)'s for the
    claim the writer processed to reach the epoch, §6.7 step 1's, or a restore's); the writer makes no request only to
    add one. A complete or dead EPOCH_PENDING and its DELIVERED records are dropped, as is a REQUEST that is no longer
    live: nothing reads them, the EPOCH or CONV_JOIN record already carries the epoch key, and the TREG its bundle's
    `t_reg`, which the writer holds from an EPOCH_PENDING only when its bundleId is the epoch's (a lost commit's names
    another bundle, also when it is complete because it lists no uid);
  - the live REQUESTs (at most 64), ended or not (an ended request is kept until it expires, §11.5), each with its
    CONFIRMED and ENDED records (a claim can confirm a request that no row accepted, §6.7 step 6), and no EPOCH record:
    a restore re-derives a request's epochs above its root by its probe, an ended request's up to the epoch of its ENDED
    record (§11.5);
  - **a copy that a legacy skip record starts** (§7.2) is written as any copy of its kind: an accepted one
    as its own CONV_JOIN (`conv`, `root = H(D_{e′})`, `e = e′`, the record's EK, bundleId and bundleSize, `rootBy =
    D_{e′}.by`, `via = 2`) with a DESC of e′ and the records above, a request as its own REQUEST (with `desc = D_{e′} ‖
    dsig` and its `t_reg`), each at the place of the first record of that copy among the CONV_JOIN and REQUEST
    records (§7.3 "Copy keys"), and with the records of the legacy copy that §7.2 assigns to it, under its own key.
    The bit1 record is kept beside that record, unchanged, and a restore matches it to it by `(conv, e′, EK,
    bundleId)` without a fetch, so it needs no conversion, while the kept record still assigns the legacy copy's
    later records: HEADS entries, LEAVE and LEFT by epoch, EPOCH_PENDING and DELIVERED by bundle, and the CONFIRMED and
    `via = 5` CONV_JOIN of a tab on the first release by their place (§7.2);
  - every CONTACT;
  - the MEMBER record, where one exists, of every uid listed in a D carried by a DESC or a live REQUEST, or held as a
    CONTACT (other MEMBER records are dropped, and looked up again if ever needed);
  - every LINK that has not expired;
  - the latest PREFS per key;
  - a HEADS record with the inbox cursor.
- **Pointer.** A self row whose only record is `SNAP{blobId, skey, size, Eh, nh}`, with prev fields NONE / `ZERO16`
  (§7.1), is put at `Lsnap(E, j)` with `E = max(E_now, regEra)` (never below `regEra`, as for self rows, §7.3), where
  `j` is the first empty slot. Slots are dense per era, and the first writer of a slot wins.
- **When to write.** A device SHOULD write a snapshot when it is online and either holds no snapshot pointer in the
  era `max(E_now, regEra)`, or has applied more than 200 self records since the latest snapshot. Nothing else defers
  one. Every snapshot holds an EPOCH record for every held epoch below its top, which a restore relies on (§11.4 step
  5): a device holds every epoch of each copy from its root, since no copy continues past a gap (§6.6 step 3, §6.7).

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
  `RL_READ` token per started 4 MiB of the page's batches (without the page header), at least 1 and at most 64 (§10.9).

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
- **Logs**: `console.error` lines carry no request bodies, client addresses or headers, uids, handles, labels, eids,
  topics, blob ids, credential ids, push endpoints, their keys or bells, and error messages, which may quote such
  values, are redacted before they are logged (this implementation's `logErr`); public values (deployment parameters,
  the era of the object that logs, a route label without path parameters, counts and sizes) may appear. Their text, keys
  and format are implementation-defined (preamble);
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
    parameter: normally the era of the first deploy, and at most `era(t_deploy − SKEW·1000)`, §3.1) get
    `MISS(sealed = 1)` (get) or 404, without a DO call. An inbox read with
    `E < E_now − 3` gets 410 first (§10.5).
- **Cache before limits.** Immutable responses (blob GETs, ended inbox eras, `/ckpt/{q}`, immutable feed pages whose
  batches fit the 4 MiB page budget) and the short-lived inbox tail (§10.5) are served from `caches.default` when
  present, before the rate limiter. The Worker strips `x-segv-now` before `cache.put` and stamps a fresh `x-segv-now`
  on the response it returns, after the cache lookup (§10.1). A feed page streamed because its one batch exceeds
  4 MiB (§10.9) is not stored in `caches.default` (copying the stream would buffer the whole batch); it is sent
  without Content-Length and with the same `cache-control` as any other page, and costs one `RL_READ` token per
  started 4 MiB of the page's batches (without the page header), at most 64 (§10.9).

The Worker passes Durable Objects only what they need. Client addresses and headers never reach a DO; the RealtimeDO
gets the opaque client tag only.

### 9.8 PushDO (`push/v2`, SQLite, one instance; optional)

A deployment offers Web Push only when the Worker secrets `VAPID_SK` and `PUSH_KEY` are set and the whole push
configuration below is valid; push is then **on**. The Worker then serves the two endpoints of §10.10 and params `push`
(§10.9), and PushDO, which the Worker reaches with `getByName("push/v2")`, stores the registrations of the devices that
turn notifications on (§11.13) and sends their notifications. Otherwise push is **off** and none of this exists: params
carry no `push`, both paths are unknown (404), and no PushDO is ever addressed. PushDO is the one component that
stores data that is not public (§0.1): nothing serves it, and no checkpoint covers it (§9.5). The Worker passes it the
fields of the two requests only.

**Configuration** (with `VAPID_SK` set):

| name | kind | meaning |
| ---- | ---- | ------- |
| `VAPID_SK` | secret | The VAPID private key (RFC 8292): a P-256 scalar `d`, 32 bytes big-endian, b64u, with `1 ≤ d < n`. The Worker derives its public key `[d]G`, 65 bytes uncompressed (`0x04 ‖ x ‖ y`), from it and reports that key as params `push.vapid`, the key every device subscribes with. |
| `PUSH_KEY` | secret, required | 32 bytes, b64u: the key under which registrations are stored (below). |
| `VAPID_SUB` | var or secret, required | The operator's contact, a `mailto:` or `https:` URI, sent as the JWT's `sub` claim. |
| `PUSH_HOSTS` | var | The hosts that may receive pushes, comma-separated; an entry `*.d` matches every host that ends with `.d`. Default `web.push.apple.com,fcm.googleapis.com,updates.push.services.mozilla.com,*.notify.windows.com`. |
| `POW_PUSH` | var | The PoW base of `push/sub` (§10.2), default 20. |
| `PUSH_MAX_SUBS` | var | The most endpoints stored, default 100 000. |
| `PUSH_DAY_SUBS` | var | The most endpoints whose registration may change in one day, default 2 000 ("Memory", below). |

A deployment that offers push MUST also set `APP_HOSTS` (§9.7), whose first host gives the payload's `navigate` URL.
**An invalid push configuration turns push off, and nothing else.** When `VAPID_SK` is set but the push configuration is
invalid (`VAPID_SK` not a valid P-256 scalar; `PUSH_KEY` missing or not 32 bytes; `VAPID_SUB` missing, or not a
`mailto:` or `https:` URI; `PUSH_HOSTS`, `POW_PUSH`, `PUSH_MAX_SUBS` or `PUSH_DAY_SUBS` present but malformed or out of
range; `APP_HOSTS` empty), push is off exactly as without `VAPID_SK`: params omit `push` and `pow.push` (§10.9), and
`push/sub` and `ring` answer as when push is not configured (§10.10). The Worker logs the reason once per isolate,
naming the setting but never its value (§9.7), and every other endpoint works as before: push settings never make the
Worker answer 503 "server misconfigured" (§3.1). While push is off, PushDO sends nothing, and its daily pass deletes
only the endpoints whose day has expired (below): it never deletes one because its `box` does not open, since
`PUSH_KEY` may be the setting that is missing or malformed. A new `PUSH_KEY` invalidates every registration (none of
them matches or opens under it): the next daily pass deletes them, they count toward `PUSH_MAX_SUBS` until then, and
devices register again at each device's next start (§11.13); so it SHOULD NOT change. A new `VAPID_SK` makes every push
to an existing subscription fail until its device subscribes again with the new key, at its next start (§11.13), so it
SHOULD NOT change either.

**Storage.** Durable storage holds the registrations as the daily passes wrote them (below), and nothing else:

```sql
CREATE TABLE sub (ep BLOB PRIMARY KEY CHECK (length(ep) = 16), box BLOB NOT NULL, day INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX sub_day ON sub (day);
CREATE TABLE tok (tk BLOB NOT NULL CHECK (length(tk) = 16), ep BLOB NOT NULL, PRIMARY KEY (tk, ep)) WITHOUT ROWID;
CREATE INDEX tok_ep ON tok (ep);
```

- `ep` names an endpoint: `t16(HMAC(PUSH_KEY, enc("segv.sh/v2/push/ep", endpoint)))`.
- `box` holds the endpoint and the subscription's keys: `aeadSeal(PUSH_KEY, enc(endpoint, p256dh, auth),
  aad = enc("segv.sh/v2/push/sub", ep))`.
- `tk` stands for a bell registered for the endpoint: `t16(HMAC(PUSH_KEY, enc("segv.sh/v2/push/bell", bell)))`. A bell
  is a capability (whoever holds it can ring it or register under it), so it is never stored in the clear.
- `day` is the UTC day of the endpoint's last registration, `⌊Unix ms / 86 400 000⌋`, the only time kept for a
  registration.

`PUSH_KEY` protects all of it against a leak of the storage alone, not against O. The platform keeps a point-in-time
history of a Durable Object's storage for 30 days, so a registration, its changes and its deletion stay recoverable from
that history for up to 30 days. That is why nothing about a ring is ever written, and why only the daily pass writes the
registrations, and a change only after the UTC day in which it was made has ended: the history then shows, per day,
which endpoints were registered, which changed their bell sets and which were deleted, and nothing finer than a day. A
day's changes still tell something: an epoch change makes the open devices of every member replace one bell, a creation,
an accepted request, a leave or an ended copy adds or removes one, and a ring can make several stale endpoints of one
conversation's members refuse their pushes and be deleted, so on a day with few changes, endpoints whose sets changed,
or that were deleted, that day may be co-members (§13.4).

**Memory.** The object's memory holds two things:

- **The day's registration changes.** Every `sub` (below), and every deletion at a push, takes effect in memory at
  once, noted with its UTC day, and replaces any earlier change of that endpoint: from then on rings and pushes use the
  stored registrations with the changes in memory applied. Only the daily pass (below) writes them to storage, once
  their day has ended. A `sub` whose keys and bells equal those **stored** for its endpoint is kept as its day alone (a
  refresh); any other `sub` is kept whole, also when it repeats a change already in memory.
- **Everything a ring causes**, which is never written: per endpoint with a push in flight, the time of its last push
  (`last`), the time of its next one (`due`) and the attempts made for that one (`tries`), each kept at most
  `PUSH_WINDOW` after the endpoint's last push, and the bells that rang it since its last push (`rang`: those of its
  registered bells that the rings carried, newest first, at most `PUSH_BELLS` = 4), kept until that push is sent or
  dropped; and the rings of the last `RING_DEDUP` = 120 s, each identified by a hash of its row and of its distinct bells
  in ascending byte order.

A restart of the object (an eviction, or a deploy) loses both: the pushes then due and the windows, so the limit of one
push per `PUSH_WINDOW` and the dedup of rings hold except across a restart; and the registration changes not yet
written, so the registrations are again those that the daily passes wrote. Devices send their sets again at their next
start and at least once a day while they run (§11.13), and an endpoint whose deletion was lost is deleted again at its
first push, since a device ends its subscription before it deletes its registration (§11.13) and a refused push is
refused again. All of this is best effort (§0.4). The object's alarm, which the platform stores, holds only the time of
its next run, which follows the clock alone (below).

**Limits.** At most `PUSH_TOKENS` = 256 bells per endpoint (params `push.maxTokens`, equal to `limits.topics`), at most
`PUSH_PER_BELL` = 8 endpoints per bell, at most `PUSH_BELLS` = 4 bells named by one push, at most `PUSH_MAX_SUBS`
endpoints in all, at most `PUSH_DAY_SUBS` endpoints with changes in memory that register them or change their keys or
bells (a deletion, or a refresh of the day alone, does not count), and at most `PUSH_ROWS` = 20 000 rows read, written
or deleted by one alarm run's part of the daily pass.

**`sub(endpoint, p256dh, auth, tokens)`** (from `push/sub`, whose fields the Worker has checked, §10.10) changes the
registrations in memory, at once:

1. With `tokens` empty, delete the endpoint's registration and its push state, and answer OK.
2. If the endpoint is not registered and `PUSH_MAX_SUBS` endpoints are, answer FULL. If the call registers the
   endpoint, or changes its keys or bells, while `PUSH_DAY_SUBS` other endpoints have such changes in memory, answer
   FULL.
3. Set its registration: the given keys, `day` = today, and each distinct bell, except a bell that 8 other endpoints
   already hold: that one is left out for this endpoint, which takes no other endpoint's place. Answer OK.

Each call thus replaces an endpoint's registration as a whole and refreshes it; a bell's places go to the endpoints
that hold them first, for as long as they keep refreshing them.

**`ring(E, label, tokens)`** (from `ring`, after the Worker found the row fresh, §10.10):

1. If the ring (its row and bells) is among the rings of the last `RING_DEDUP`, stop; otherwise remember it. A repeat
   of a ring (the sender's retry) thus changes nothing, while a ring of the same row with other bells, which a third
   party who read the row's label in the public feed could send first, never suppresses the sender's.
2. For each distinct endpoint registered under the `tk` of one of `tokens`: put the bells of `tokens` under which it
   is registered at the front of its `rang`, in their order in `tokens`, removing their earlier places there and
   keeping the first `PUSH_BELLS`. Then, if a push to it is due, nothing else changes; otherwise set
   `due = max(now, last + PUSH_WINDOW·1000) + j` (`now + j` when there is no `last`) and `tries = 0`, where j is uniform
   in `[0, PUSH_JITTER·1000]` ms, drawn per endpoint and push.

A ring writes nothing, not even the alarm (below). So an endpoint gets at most one push per `PUSH_WINDOW` = 60 s,
except across a restart, however many rows ring it (later rings within the window coalesce into one push at its end),
and every push is delayed by an independent jitter of up to `PUSH_JITTER` = Δ seconds, and then until the alarm's next
run, at most `PUSH_TICK`.

**Alarm.** The alarm runs on a fixed cadence that nothing else moves: at every multiple of `PUSH_TICK` = 10 s of Unix
time, whether push is on or off and whatever is registered or due. Each run first arms the next multiple. When no
alarm is set, the constructor (inside `blockConcurrencyWhile`) arms it at the next multiple, as CheckpointDO's does
(§9.5): at the object's first start, and after the platform has lost the alarm. That is the only write at the time of
an event; otherwise the stored alarm time follows the clock alone, and neither a ring nor a registration writes it. As
every alarm handler of §9, it never arms a time in the past. Each run then does, in this order:

1. its part of the daily pass (below), in one transaction;
2. while push is on, the pushes that are due, earliest `due` first, in batches of at most 50 and at most one batch a
   second, until none is due or the next run's time has come; the rest wait for the next run. While push is off, it
   sends nothing and drops what is due.

**The daily pass** is the only writer of `sub` and `tok`. A pass starts at the first run of each UTC day (normally the
one at 00:00) and at the first run after the object starts, and goes through the stored endpoints and those with a
change in memory in ascending order of `ep`, a part at each run, until it has gone through all of them:

- It deletes every endpoint whose day lies more than `PUSH_EXPIRY` = 30 days before today, its day being that of its
  change in memory when it has one (today's included), else its stored `day`; so a refresh in memory always keeps its
  endpoint. While push is on, it also deletes every stored endpoint whose `box` does not open under the current
  `PUSH_KEY`; while push is off, it deletes by day only.
- It writes every change in memory made on an earlier UTC day (a deletion; a registration, with its `box` and bells;
  or a refresh, the new `day` alone), which then leaves memory. Changes made today wait for the next day's pass.

A run's part reads, writes and deletes at most `PUSH_ROWS` rows and never splits an endpoint's rows; the next run
continues after the last `ep` that it committed. A part whose transaction fails changes nothing: its changes stay in
memory, and the next run tries that part again. The position of a pass lives in memory, so after a restart the pass
that the first run starts goes through every endpoint again from the lowest `ep`, and finds done what earlier parts
committed. The order of `ep`, a keyed hash, keeps the parts of a pass from following the order in which the changes
were made. So a run's work stays bounded however much expires or changes on one day: with `PUSH_ROWS` = 20 000, the
worst day, on which all `PUSH_MAX_SUBS` endpoints expire with 256 bells each and a full day of changes is written
(about 27 million rows), takes about 1 400 runs, some 4 hours.

**Sending a push.** For a due endpoint the alarm takes the endpoint and its keys from its registration, opening `box`
for a stored one; when the endpoint's host is no longer in `PUSH_HOSTS`, or the `box` does not open, it deletes the
endpoint instead. Otherwise it sends one Web Push message (RFC 8030), `POST <endpoint>`, never following a redirect
(`fetch` with `redirect: "manual"`), with:

- `TTL: 86400`, `Urgency: normal` and `Topic: segv`, so that a push that the push service still holds for the device
  is replaced by the next one (whose `rang` does not repeat the replaced push's bells);
- `Content-Encoding: aes128gcm`, `Content-Type: application/octet-stream`, and as the body the payload below
  encrypted to `p256dh` and `auth` as RFC 8291 says: a fresh P-256 key pair and a random 16-byte salt per push, one
  record, record size 4096;
- `Authorization: vapid t=<JWT>, k=<b64u of the VAPID public key>` (RFC 8292): a JWT signed with ES256 under
  `VAPID_SK`, with the header `{"typ":"JWT","alg":"ES256"}` and the claims `aud` (the origin of the endpoint, such as
  `https://web.push.apple.com`), `exp` (at most 12 hours after the request, in seconds since the Unix epoch) and `sub`
  (`VAPID_SUB`). A JWT MAY be reused for the same `aud` until one hour before its `exp`.

The **payload** is this UTF-8 text, where `<host>` is the first host of `APP_HOSTS` and `<bells>` is the unpadded
b64u (86 characters) of the endpoint's `rang` at the time of the attempt, 16 bytes per bell, followed by zero bytes up
to `16·PUSH_BELLS` = 64 bytes:

```
{"web_push":8030,"mutable":true,"notification":{"title":"segv.sh","body":"new messages","navigate":"https://<host>/","tag":"segv","data":{"bells":"<bells>"}}}
```

Every push of a deployment thus has the same length and the same text, and differs only in `<bells>`. It is a
declarative push message (W3C Push API). A browser that supports those (Safari on iOS and iPadOS 18.4 and later)
hands it, since it is `mutable`, to the device's Service Worker as a proposed notification that carries `data`, and
shows that notification itself when the Service Worker shows none in time; other browsers pass the payload to the
Service Worker (§11.13). `tag` makes a new notification replace an earlier one that is still shown. The payload holds
no text of any message and names no sender or count. Its bells tell the device alone, once the browser has decrypted
the push (RFC 8291), which of its registrations rang: O knows them from the rings, and N cannot read them.

The answer decides the rest:

- a 2xx: the push is sent; `last` = when it was sent, nothing is due, and `rang` is emptied;
- a 429, a 5xx, a network error, or no answer within 10 s: retry once (`tries = 1`), after the answer's `retry-after`
  when that is at most 60 s, else after 10 s; when the retry fails as well, drop the push (`last` = its first
  attempt, `rang` emptied), and keep the endpoint;
- anything else, a 3xx or any 4xx other than 429 (404 and 410 for a subscription that expired or was revoked, 400,
  401, 403, 413): delete the endpoint, so that an endpoint that no push service accepts is gone at its first push.

A dropped push is reported only as a count in the logs (§9.7).

**Capacity.** One PushDO holds every registration in stage 1, within the limits above, and sends at most about 50
pushes a second; a flood of registrations or rings can fill it or delay everyone's notifications (§0.4). §14 has the
path beyond it.

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
  clock stepped, and the newer answer wins. Before its first valid params answer the client uses `SKEW = 0` in this
  margin: a smaller margin can only discard an older sample, which the newer one replaces anyway, while a guessed
  larger one could keep a sample from before a stop of the monotonic clock; every rule that needs SKEW for a decision
  (the era of a write, the waits, the registration cursor of §11.5) runs after params. Among the
  remaining samples taken in the last 10 minutes (monotonic), a
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
| 200 / 201 / 204 | success (put and get carry per-row status inside a 200; `push/sub` and `ring` answer 204 with no body, §10.10) |
| 400 | malformed request (bad layout, length, encoding, class, count, id or handle) |
| 403 | missing, malformed, stale or insufficient proof of work |
| 404 | unknown path (the push endpoints while push is off included, §9.8, §10.10), user, uid, blob, era or checkpoint |
| 405 | wrong method |
| 409 | conflict: handle or uid taken, duplicate wrap, inbox wrong era (`{error, era}`), directory prefix bits out of range (`{error, p}`) |
| 410 | inbox era older than `E_now − 3` |
| 411 / 413 | blob without Content-Length / too large; body over the endpoint cap |
| 421 | host not in `APP_HOSTS` |
| 426 | `/api/v2/rt` without an upgrade |
| 429 | rate limited, or too many sockets from this client (`retry-after`) |
| 503 | rate limiter or D1 unavailable, global socket cap, push subscription cap (§10.10), server misconfigured (missing secrets, invalid parameters; never the push settings, §9.8), a failed Durable Object call on put, get or `push/sub` (`retry-after: 5`) |
| 500 | internal error (other routes MAY answer 500, or 503 `{error: "storage unavailable"}`, for a failed Durable Object or R2 call; clients treat every 5xx alike) |

**Order of checks.** The Worker answers with the first check that fails, in this order:

1. host pinning: 421 (§9.7);
2. server configuration (secrets, deployment parameters, §3.1): 503 `{error: "server misconfigured"}`, without any DO
   or D1 call (push settings are not part of it: an invalid one only turns push off, §9.8);
3. path: 404 when no route matches (`/api/v2/push/sub` and `/api/v2/ring` match no route while push is off: not
   configured, or configured invalidly, §9.8); method: 405 with `allow`; for `/api/v2/rt`: 426 without an upgrade, 403
   for a foreign Origin;
4. for the cacheable GETs (blob, inbox read, feed page, `/ckpt/{q}`): the path, query and era-bound checks that need
   no storage (§9.7, §10.5, §10.9), then the `caches.default` lookup; a hit is returned here;
5. the rate limit: 429 with `retry-after`, or 503 when the limiter fails;
6. for requests with a body, the declared length before any byte is read. Blob PUT: missing → 411, above 12 MiB →
   413, below 41 B → 400. Other endpoints: above the endpoint cap → 413. A malformed Content-Length → 400. Then, while
   the body is read: more bytes than the cap → 413, and a length that differs from the declared one → 400 (blob PUT:
   §10.7);
7. proof of work: 403;
8. strict parse of the binary layout or JSON body: 400;
9. the endpoint's own rules (era bounds per row or key, bucket, directory rules, DO and D1 answers). `ring` answers
   204 here and does the rest after its answer (§10.10).

For endpoints whose PoW digest is `H(body)`, step 6 reads the whole body before step 7. A blob PUT reads its body only
while streaming it into R2, after its PoW and its registry check (§10.7). Where this list does not order two checks
(for example two parameter checks, or a parameter check of a non-cacheable GET against the rate limit), either answer
conforms. Example: a put with Content-Length 263 346 gets 413 without a PoW check. Within step 9, a check that needs
stored state and the 5xx of a failed D1, Durable Object or R2 call are not ordered against each other either: during a
D1 failure, an isolate that holds a cached `P` (§9.6) answers 409 for a prefix lookup whose `p` is out of range, and
one without answers 503; both conform, and a client that gets 409 and then 503 on its one retry fails the lookup as
transient (§10.6).

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
| `push` | H(body) | len(body) | — (always base) | 20 (`POW_PUSH`; only while push is on, §9.8) |

Overrides must match `^\d{1,2}$` and be ≤ 64. Clients refuse a base above 26. On 403 a client retries once with fresh
params. The nonce is the decimal value of the `u64` that is hashed; the server answers 403 "malformed proof of work"
for a nonce above 2^53 − 1. Clients search nonces upward within that bound, both halves of the `u64`
included, so the search is bounded by time only. A proof is accepted only while its window is the current
or the previous one, 10 to 20 minutes: a client searches with the window that is current by its estimated
server time, and when that window stops being current before a nonce is found, it MUST restart the search with the
new window (a new `pre`), so it never sends a proof that is already stale. Restarting loses nothing, because every
nonce is an independent trial. The expected work is `2^difficulty` hashes: at the highest base a client accepts (26), a
full put (33 bits) expects about 8.6·10^9 hashes, over an hour in a browser tab, and a deployment that raises the base
that far accepts that cost.

**Per-IP rate limits.** The key is the IPv4 address or the IPv6 /64 (an IPv4-mapped address counts as IPv4). Keys are
never stored.

| binding | limit | endpoints |
| ------- | ----- | --------- |
| `RL_WRITE` | 60 / 60 s | register, wraps, put, `push/sub` |
| `RL_INBOX` | 10 / 60 s | inbox post (one token per POST of up to 32 invites) |
| `RL_BLOB` | 20 / 60 s | blob PUT |
| `RL_RING` | 60 / 60 s | `ring` (§10.10; a binding of its own, so that ringing after each put leaves `RL_WRITE` to the puts) |
| `RL_READ` | 600 / 60 s | get, inbox read, directory reads, dirlog, blob GET and meta, ckpt, feed (one token per started 4 MiB of the page's batches, without the page header, at least 1 and at most 64, §10.9), era, rt upgrade |

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

Clients never read eras below `E_FIRST`: a cursor never lies below `(max(E_FIRST, E_now − 3), 0)` (§11.5).

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
  warning "the directory answered fewer accounts than expected". Clients cache prefix responses for the session; a
  cached answer serves only the users it lists ("Transient failures" below).
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
  handle or uid means "no such user", and only a fresh one. An answer is **fresh** for an operation
  when it was fetched after that operation began, where an operation is a creation, an add, a restore, a catch-up,
  or an inbox poll with the joins it processes. A cached answer serves only the users it lists, so a handle or uid that
  a cached answer lacks (it may have registered since) is looked up again with a fresh complete answer, unless the
  cached one is already fresh for the current operation; the new answer replaces the cached one, and only a fresh answer
  can make a handle or uid "no such user" (§6.1 step 1, §6.3) or a member unknown (§11.2). A uid that a fresh answer
  lacked stays unknown for the rest of the session, with no further lookup (it is looked up again at the next restore,
  §7.3), and a handle that the user enters again starts a new operation, so it is looked up fresh. A negative conclusion
  thus costs at most one more prefix fetch (120–240 KB) per prefix and operation; directory answers are `no-store`
  (§10.1), so the fetch reaches the server. A network error, a timeout, a 429, a 5xx or a page sequence that does not
  complete is retried, or fails the operation with that error; it never makes a handle unknown (§6.1 step 1, §6.3) or a
  member unknown (§11.2), and a join that needs the lookup is parked (§6.7).

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

A deployment whose push is on (§9.8) also reports `"push":{"vapid":"<b64u 65-byte P-256 public key>","window":60,
"maxTokens":256}` and `pow.push`; while push is off (not configured, or configured invalidly) it reports neither.
`window` is `PUSH_WINDOW` in seconds and `maxTokens` is `PUSH_TOKENS`. A client ignores the keys of params that it does
not know (the first release does), and takes a `push` whose `vapid` is not 65 bytes starting with `0x04`, whose `window`
or `maxTokens` is not a positive integer, or that comes without `pow.push`, as no push.

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
`bytes` is the sum of the encodings of the page's batches, without the 5-byte page header. So every page that
is not streamed (its batches fit the 4 MiB budget; the empty page included) takes one token, and a streamed page of
one batch of b bytes takes `min(⌈b / 4 194 304⌉, 64)`. The Worker takes the first token in step 5 of §10.1
and the others after `feedBatches` returned the batch sizes, before it sends the first byte, and answers 429 with
`retry-after` if one is refused. So up to 256 MiB of batches no request makes the shard read more than 4 MiB of rows
per token, the rate of an uncached tail page. The cap keeps every page readable by one address within one `RL_READ`
window, with room to spare for an address that other readers share and for a limiter that counts approximately; a
deployment MUST keep its `RL_READ` limit per window (600, §10.2) above 64. Above 256 MiB a token
buys `bytes / 64` of shard reads. Such a batch needs about 1 021 maximal puts (263 056 B of feed encoding each) within
one Δ, and every further 4 MiB per token about 1 021 more; at the production Δ = 10 the shard's ~1 000 requests/s
(§9.1) bound a batch near 2.5 GB, so a token buys at most about 10 times the tail-page rate, and only after a flood
that took the shard's whole write capacity for a Δ. Page composition is deterministic for a given `after`. A page whose
`more = 1`, or any page of a sealed era, is immutable; the tail page is `no-store`. If a streamed page fails part-way,
the response ends abnormally: it is truncated, never altered. Feed readers MUST reject a page whose bytes end before its
`nb` batches and their `n` rows are complete, and fetch it again.

Rows of a batch are strictly ascending by label (bytewise). A feed consumer recomputes each batch's `root` over the rows
in the order received, and `head` from the previous batch, so misordered rows fail that check and decoders need not
check the order. Every head in a checkpoint was obtained through `head()`, which closes a due batch first, so its batch
is already in the feed; the feed may hold later batches. Auditors check that each checkpointed `shard/{E}/{i}` head
occurs in the feed's head chain (not that it is the last head). Clients never use the feed. It exists so that the
database stays public and mirrors and auditors can verify batch roots and the head chain against checkpoints.

### 10.10 Web Push: `POST /api/v2/push/sub` and `POST /api/v2/ring`

Both exist only while push is on (§9.8). While it is off, because the deployment does not configure it or configures it
invalidly, they match no route (404, §10.1 step 3), exactly alike in both cases, and a client never calls them, since
params carry no `push` (§10.9). The general rules of §10.1 apply to both, in its order of checks.

**`POST /api/v2/push/sub`** (JSON; PoW `push`; `RL_WRITE`; body ≤ 16 KiB) registers a device's push subscription and
its bells, replacing everything that endpoint had:

```json
{"endpoint": "<https URL>", "p256dh": "<b64u 65 B>", "auth": "<b64u 16 B>", "tokens": ["<b64u 16 B>", …]}
```

- `endpoint` is a string of at most 1024 bytes that parses as an absolute URL whose serialization equals it, with the
  scheme `https`, no username or password, no port (443 is implied), and a host that `PUSH_HOSTS` lists (§9.8). The
  list keeps the server from sending requests to arbitrary hosts.
- `p256dh` is 65 bytes, an uncompressed P-256 point on the curve (`0x04 ‖ x ‖ y`), and `auth` is 16 bytes: the
  subscription's `getKey("p256dh")` and `getKey("auth")`.
- `tokens` holds 0 to `PUSH_TOKENS` = 256 bells of 16 bytes; a repeated bell counts once. An empty list deletes the
  endpoint's registration.

A body that breaks any of these rules, or holds another key, is 400. Otherwise PushDO replaces the endpoint's
registration as a whole and refreshes it (§9.8), and the answer is 204 with no body, also when a bell whose 8 places
other endpoints hold was left out. For a new endpoint while PushDO holds `PUSH_MAX_SUBS` endpoints, and for a new
or changed registration while it holds the day's changes of `PUSH_DAY_SUBS` other endpoints (§9.8), the answer is 503
`{error: "push full"}` with `retry-after: 3600`, and for a failed PushDO call 503 `{error: "storage unavailable"}` with
`retry-after: 5`. Knowing an endpoint is what allows replacing or deleting its registration: only the device, its push
service and the operator know it (§13.4).

**`POST /api/v2/ring`** (binary; `RL_RING`; no PoW; body ≤ 1044 B) asks the server to notify the devices registered
under some bells, about a row stored in the last minute:

```
request = u8 ver (= 1) | u16 E | label[16] | u8 n (1..64) | token[16] × n          20 + 16n bytes
```

A body whose `ver` is not 1, whose `n` is out of range or whose length is not `20 + 16n` is 400; a repeated token
counts once. Once a request has passed steps 1–8 of §10.1, the Worker answers **204** with no body, and only then,
through `ctx.waitUntil`:

1. it goes on only if `max(E_FIRST, era(now − (RING_FRESH + Δ + SKEW)·1000)) ≤ E ≤ era(now + SKEW·1000)`, with
   `RING_FRESH` = 60 s;
2. it reads the row with one ShardDO `get` of `(E, label)` in exists mode (§9.1), and goes on only for a HIT whose
   stored time, which is rounded down to Δ (§3.1), satisfies `t + Δ ≥ sec(now) − RING_FRESH`; a MISS, sealed or not,
   ends it;
3. it calls PushDO's `ring(E, label, tokens)` (§9.8), which ignores a ring of the same row and bells within
   `RING_DEDUP`.

A failure in these steps is logged (§9.7) and changes nothing else. The answer thus never depends on whether a bell is
registered, whether the row exists or was rung before, or how long these steps take, so a member learns nothing about
other members' devices from it. A ring needs no proof of work: it needs the `(E, label)` of a row stored in the last
minute, such as the one its sender has just put (any fresh row serves), and `RL_RING` bounds the rings per address.
What rings can cause is bounded by PushDO: one ring per row and set of bells, and at most one push per endpoint per
`PUSH_WINDOW`, except across a restart of PushDO, which empties its memory (§9.8).

## 11. Client algorithms

Constants: `W = 8` (lane lookahead and gallop chunk), `P0 = 2` (probe depth of an idle lane), `SEND_ATTEMPTS = 8`,
`HISTORY_INITIAL = 30` rows per lane, `HISTORY_COPIES = 20`, `VIEW_MESSAGES = 500`, `MAX_TEXT_BYTES = 12000`,
`MAX_REQUESTS = 64`, `RESUME_AFTER = 10 min`, `MAX_REACTIONS = 8` (emoji per member and message, §11.12).

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

After `register`, the client writes its first self row: a HEADS record (`c = 0`) whose cursor is the registration
cursor of §11.5, taken once from the register response's `x-segv-now` and kept by every retry of the write, so its
first restore does not scan the inbox from the start of the era. Like every self row, it is written in an era no lower
than `regEra` (§7.3).

### 11.2 Per-copy state

| item | contents |
| ---- | -------- |
| identity | `(conv, root)`, `rootBy`, `confirmed`, `request` |
| epochs `e → {EK, keys, D, H(D), bundleId, E_start, …}` | For each lane ℓ: the dense-prefix position, the processed position, the last valid row (for `prev`/`prevh`), and the rows seen. For the control lane: the position `(E_c, cnt_c)`, the evaluated rows and their e-validity (valid, not valid, undecided), the winning claim with its finality and processing state, and the sealed eras observed. Also the set of members who left in e, each with its kept source (§6.9): the stored time of the LEAVE row it comes from and, when e is that row's epoch, the row's position (NONE for a leave carried into e), kept in LEFT records (§7.3). |
| current epoch | `removed` (the copy has **ended**: the final winning claim of its current epoch removed or dropped self; latched, §6.6 step 3), `left` (the copy's leave is current, §6.9), `frozen` (with its cause, for the warning text: own entry not opened, or `D'` invalid; §6.6 steps 4 and 6) |
| followed lanes | the lane of epoch c−1 of each member silent in c (below) |
| messages | message list (each message with its reactions, and the REACTION rows that wait for their target, §11.12), `unread`, `lastTs` |

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
Members of a request copy other than `D.by` are shown the same way until the copy is accepted (§11.5).

**Followed lanes.** In the copy's current epoch c, if the copy holds epoch c−1, the client also follows, for each
member s of both `D_c` and `D_{c−1}` other than self of whom no valid row in c has been seen (a row of any type, a
REACTION included, §11.12), s's lane of epoch c−1.
A copy that does not hold c−1 (its root epoch is c) follows no lane. That lane leaves when a valid row of s in c is
seen, or when the copy switches past c (the lanes of c then become the candidates). There is at most one followed lane
per member, always in c−1. A restore takes the followed lanes of its HEADS epoch from the HEADS entry (§11.4).

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
followed lane is dropped), and before the lanes of the epoch that a claim removed self from leave it (§6.6 step 3), the
client processes each from its processed position to its dense-prefix head, probed at that moment, after the winner that
ended the epoch is final. So a WELCOME or LEAVE posted in an older epoch before it leaves the map is never skipped. Two
gaps remain, and scrollback finds their rows (§11.10, §13.2 item 15): a row that a member writes into an older epoch
after it already wrote in a newer one, which only two of its own devices racing a claim can do; and an honest row raced
by a malicious member who registers the next bundle in advance and commits two claims back to back.

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

### 11.3 Send (TEXT / IMAGE / REACTION / LEAVE / WELCOME)

Sends are serialized per conversation. The UI echo appears at once, with status `sending` (none for LEAVE, WELCOME
and REACTION). A REACTION has no echo: wherever this section marks an echo `failed`, a REACTION's send fails with the
same error instead, nothing keeps its body, and it is not retried (the user reacts again).

1. Re-check the session. Probe the control lane of the current epoch e as §6.5 says (its next 2 slots, and slot 0 of
   every later era up to `E_now`), in one `get`, whatever the realtime state, and process what it finds (§6.4–§6.6);
   if that switches the copy to a later epoch, repeat this step for it. This costs one `get` per send, as v1's sync
   before every send did, and keeps a send from landing in e after a claim whose realtime frame was lost (§11.2). If
   the `get` fails (a network error, a timeout, a 429 or a 5xx), nothing is put: the echo becomes `failed` with the
   error "message was not delivered (membership changed or the request failed); try again", and its retry is a new
   send (a LEAVE fails with the same error; a WELCOME's uid stays pending, §6.12 step 4).
2. If the control lane of the current epoch has an undecided slot before any winner, or a winner that is not yet final
   or processed, wait for it until the lane has been so for 30 s, counted from when the device first saw it so (the
   start that the view's `canSend` uses, below), and not from this send: a send made while the view
   already shows `canSend = false` fails at once, one made earlier waits only what is left, and sends queued behind it
   (sends are serialized per conversation) do not wait 30 s each. When the lane settles and later becomes so again,
   the count starts again. (Slots after a processed final winner, as in a frozen epoch, never block.)
   Then:
   - if the user was removed: fail with "you are no longer a member of this conversation" (not for a WELCOME, last
     bullet);
   - if the user has left: fail with "you left this conversation" (except a LEAVE repeated by §6.9, and not for a
     WELCOME, last bullet);
   - if the wait timed out: fail with "the conversation is changing membership; try again in a moment" (the v1 text).
     Writing into e now could reach a member that the pending claim removes;
   - if self is frozen in e, the winning claim of e has an `rm` bit for a member who had not left (by the leave state
     when this check runs, §6.6 step 5), and the type is TEXT, IMAGE or REACTION: fail with "a removed member could
     still read this conversation; start a new conversation" (§6.6 step 6);
   - if the type is WELCOME and the current epoch (the one the row would be built in) does not meet every condition of
     §6.12 step 1 (a copy that self left or was removed from never does): put nothing; the recipient gets an inbox
     invite instead (§6.12 steps 1–2). A WELCOME is thus never written in an epoch that lists anyone but self and its
     recipient.

   Otherwise a frozen member sends normally in e. The view's `canSend` is false whenever this step would fail for a
   TEXT, and follows the leave state as it changes. For an undecided slot, or a winner not yet final or
   processed, the view cannot know whether a wait would time out, so `canSend` turns false only once the slot or
   winner has stayed so for 30 s, until it is settled; a send made before then waits here for what is left of those 30
   s.

   **The send's epoch.** The epoch this step last checked is the send's epoch e. Steps 4–8 build, put and judge the row
   in e, also when the copy has meanwhile switched to a later epoch through §11.6 or a catch-up; only a re-run of steps
   1–3 (step 6) sets a new e.
3. If the epoch lists a member who has left (other than self) and the type is TEXT, IMAGE or REACTION, commit a
   rotation (§6.3), unless self is frozen in e or `e = 2^32 − 2`. On a conflict, follow the winner. Then restart at
   step 1. If the commit fails with "can no longer change" (self is now frozen), restart at step 1 too: step 2 decides
   whether e still takes the send.
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
     update the lane head. For a TEXT or IMAGE row, this success and the two others below (a CONFLICT with its own
     body, a probe that finds its own body) are each followed by the row's ring (§11.13), whether or not this device
     has notifications on.
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
   echo `failed`, with the same "not delivered" error (a dropped REACTION counts for nothing, §11.12).
8. **Late rows.** A row is *late* when the answer to its put (or to the probe that found its body) arrived `Δ + SKEW`
   seconds or more after its latest step-1 probe was sent, by the monotonic clock, the wall clock or the estimated
   server time (as in step 6), or
   when the retry of a failed echo finds it after the copy left its epoch. The others may have swept its lane before
   it landed (§11.2). After a late row in epoch e, its echo stays `sending`, and step 1 runs again and waits as step 2
   does. The row counts as delivered only if the copy is then still in e, or in e+1 with no valid row of self in e+1
   (so the others still follow self's lane of e). Otherwise, or if the probe fails or the wait times out: a TEXT or
   IMAGE echo becomes `failed` with the same "not delivered" error, and its retry builds the message again in the
   current epoch; a REACTION's send fails with that error; a LEAVE is put again in the current epoch by the rule of
   §6.9 (its record for the late row stays, since that row exists); a WELCOME's uid stays pending (§6.12 step 4). A
   member that did see the late row then sees the message twice.

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
   - If neither era has one, probe `Lsnap(E, 0)` for `E = E_now−2` down to `regEra`, and stop at the first hit. No
     pointer and no self row lies below `regEra` (§7.3, §7.4).
3. If there is a snapshot: fetch the blob, check its hash, decrypt, parse `S2`, and apply its records. The self
   position is `(Eh, nh)`. The client tries the pointers it found from the highest `(E, j)` down, continuing the
   step-2 search into earlier eras, and uses the first pointer that opens and parses as a pointer row (§7.1) and whose
   blob is a HIT, hashes to `blobId`, decrypts with `skey` and parses as S2. A transient error (network error,
   timeout, 429, 5xx) is retried with backoff, never skipped. When no pointer qualifies, restore runs without a
   snapshot, from `(regEra, 0)`; old era DOs stay readable in stage 1 (§9.1), so the result is the same.
4. **Self delta.** Probe `Lself` densely from the position after `(Eh, nh)` (or from `(regEra, 0)` without a
   snapshot):
   - `W` slots of that position's era from it, and slot `(E′, 0)` of each later era up to `E_now` (self rows fill every
     era densely from slot 0, §7.3, so slot 0 tells whether E′ has any);
   - whenever every slot of a probe hits, the next `W` slots of its era (gallop);
   - apply the records in order.

   An idle era costs one probe key.
5. **Per accepted copy.**
   - Epoch keys come from CONV_JOIN and EPOCH records and from the claims the restore processes (the own entry, §6.6
     step 4). An EPOCH_PENDING never gives a held epoch: its commit may have lost, and when its claim is
     the final winner, processing that claim gives the same key through the own entry; until then it is only a
     delivery intent (§6.11). `D` of an epoch comes from a DESC record, or, only when there is none, from its bundle.
     Signatures need no directory (§5.1). Members' handles come from MEMBER records (§7.2); only members of a held D
     that have none are looked up by prefix, batched per prefix and cached for the session, and the result is written
     as a MEMBER record. Restore never fetches `kemPk`.
   - **Control lane.** The restore holds every held epoch of the copy. For a copy whose CONV_JOIN the
     snapshot holds, call the highest epoch whose key that CONV_JOIN or an EPOCH record of the snapshot gives the
     snapshot's **top** (a flag-0 record: a bit1 record that the snapshot keeps beside a converted copy, §7.4, gives its
     legacy copy no epoch). For any other copy the top is its root epoch: a copy without a snapshot; a request accepted
     after the snapshot, whose CONV_JOIN is in the self delta and whose snapshot record is its REQUEST, which restores
     from its root as a request does (§11.5); and a copy that a legacy skip record of the self delta starts (§7.2). The
     restore starts at the top, or at the HEADS epoch when that is lower (the root epoch for a copy without a HEADS
     entry, as for its lanes below). Neither an EPOCH_PENDING (its commit may have lost) nor an EPOCH record of the self
     delta sets the start: new code writes no EPOCH record as a self row (§7.3), and a legacy skip record starts a
     separate copy (§7.2). A snapshot holds an EPOCH record for every held epoch below its top, because its writer held
     them all: a flag-0 EPOCH is written only by a device that processed the claim before it. From its start the restore
     reaches each epoch in turn:
     - **below the top**, it reads the epoch's winning claim at the position that the next held epoch's EPOCH record
       names (§7.2; a body `get`, opened with that epoch's `mk`) and uses it as §6.8 uses such a read, without probing
       the slots before it and without evaluating the claim again: the record is the account's own, and it gives the
       next held epoch's key. The claim's lines, the sweep of the epoch's
       lanes and the switch follow as for a processed claim;
     - **at or above the top**, it probes and processes the epoch's claims as in §6.4–§6.6, from the furthest control
       position `(ctlE, ctlCnt)` among the HEADS entries for that epoch that it applied from the snapshot or the self
       delta, the latest one included (§7.3; a control position stays true of its epoch, so an entry that a lagging
       sibling's later entry replaced still counts; an entry that §7.2 says to ignore counts as absent), or from
       `(E_start, 0)` when it applied none;
     - **at the epoch that the copy's ENDED record names** (§7.2), once it holds that epoch, it
       neither probes nor evaluates that control lane: the copy has ended there (§6.6 step 3), latched, and the
       restore reads the claim at the record's position (as below the top) only when it needs it: to decide a row of
       the copy (§6.8), and for the copy's history (step 6, §11.10), which shows the claim's "@by removed you" line
       (unless self had left in that epoch). An ENDED record for an epoch that the restore does not reach (the copy
       ends, is frozen or stops below it) is ignored. A request reaches that epoch through its step-8 probe (§11.5),
       which processes its claims below it as for any request and stops there in the same way.

     So the restore re-derives every held epoch above the top (one reached through the account's own entry after the
     snapshot, or any without a snapshot, §7.3), holds every held epoch and the claim that ended each held epoch below
     the current one (processed, read at its record's position, or named by an EPOCH record, §6.8), and processes the
     claim that ended an ended copy's last epoch when the copy has no ENDED record (§6.6 step 3: the copy ends again,
     with its "@by removed you" line unless self had left in that epoch; a copy that ended before the upgrade from the
     first release, or whose HEADS row with its ENDED record was not yet written). Each epoch it re-derives costs one
     bundle fetch, the rule-(g) `blob/meta` request and at most 32 entry recomputations (§6.6 step 4); an ended copy's
     last claim costs the fetch and the request, without the recomputations, when the restore processes it, and with an
     ENDED record only one claim read, once the copy's history needs the claim; an epoch between a lower start and the
     top costs one claim read (and its bundle when no DESC record gives its D). `E_start` of an epoch is `era(t_reg)` of
     that epoch's own bundle, taken as §4.2 says: from the rule-(g) `meta` answer of the claim the restore processed to
     reach the epoch, from a TREG for the epoch's bundleId (that of its CONV_JOIN, EPOCH or REQUEST record, or of the
     final winning claim that the restore processed), from a REQUEST or EPOCH_PENDING record of the copy naming that
     bundle (a REQUEST also once a CONV_JOIN superseded it, §7.3; a dead EPOCH_PENDING names another and gives nothing),
     or else from one `GET /api/v2/blob/{id}/meta`, made when the restore needs that epoch's `E_start` (a claim of the
     epoch to evaluate, §6.4(f), or a lane or the control lane of the epoch probed from `(E_start, 0)`) or shows its
     join line, which it does for every copy (§11.8). The row of a join's CONV_JOIN holds a TREG for its bundle, and a
     creation's or accepted request's bundle is named by its EPOCH_PENDING or REQUEST (§7.3), so only a join that an
     earlier version recorded (a legacy skip record included) costs that request, once per restore until a snapshot
     holds its TREG (§7.4).
   - **Legacy skip records**. Every EPOCH record with flag bit1, of the snapshot or of the self delta, is read as §7.2
     says: one that matches a CONV_JOIN or REQUEST of its conv by `(e′, EK, bundleId)` is that record's copy (a snapshot
     keeps each such record beside the record it wrote for its copy, §7.4), and for any other the restore takes `D_{e′}`
     from the bundle, and restores the separate copy `(conv, H(D_{e′}))` from its root e′ like any copy joined at e′,
     accepted or a request as §7.2 says, with the HEADS entry, LEAVE, LEFT, EPOCH_PENDING and DELIVERED records that
     §7.2 assigns to it, and with its join line "`who(by)` added you" at the time §11.8 gives every join line. The
     legacy copy it came from restores as any copy and ends at the claim that removed self, with "@by removed you"
     unless self had left in that epoch (§6.6 step 3). The restore raises no warning for either (warnings belong to the
     device that takes a J, §6.7 step 6), and §6.7 step 6 decides their ⚠ marks. Its step-10 snapshot writes the
     separate copy under its own key, beside the bit1 record (§7.4), so the next restore makes no fetch for it.
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
     is dropped as it is live. A restore that took `EK_c` from a snapshot's EPOCH record never processes
     `C_{c−1}`; one that re-derived c (any epoch above the top: without a snapshot, or above the snapshot's EPOCH
     records) processed it on its way to c (Control lane, above), and decides those rows the same way. A HEADS entry
     that §7.2 says to ignore counts as absent, and so does one for an epoch that its copy never holds (below its root,
     or above the epoch in which it ended; §7.2). The members recorded as left in the HEADS epoch are those its LEFT
     records name (§7.3: per member the record with the least key), each decided by §6.8 with the record's time and
     position, as its LEAVE row would be, when a claim of that epoch or a later one is processed; a LEAVE found here is
     applied as a live one is (§6.9: it replaces the kept source only when its key is smaller), and the switch to a
     later epoch carries the leaves over (§6.6 step 4). Rows applied during restore never count as unread.
   - **Frozen copies** re-derive their freeze from the control lane and the bundle (§6.6). The freeze itself posts
     nothing (LEAVEs that §6.9 repeats are still put).
   - **Unfinished deliveries** (§6.11), and LEAVEs that §6.9 repeats.
   - **Ended copies** (§6.6 step 3) keep their epochs, rows and lines. A restore holds them as the live
     device did: it processes the claim that ended each one, or holds the copy's ENDED record instead (Control lane,
     above; a request's claims in its step-8 probe, which for a request with an ENDED record processes the claims
     below the epoch that record names and stops there, §11.5), sweeps its last epoch's lanes, and neither subscribes it
     (step 9) nor probes it after that. A restore that processes such a claim writes the copy's ENDED record, and the
     CONFIRMED that the claim may cause, as a live device does (§7.3).
6. **Initial history.** For the `HISTORY_COPIES` copies with the newest `lastTs` (from HEADS), also fetch the last
   `HISTORY_INITIAL` slots of each lane of the current epoch (body mode), and, if the epoch has fewer than 30 rows,
   rows of the copy's previous held epoch (e−1, step 5 and §11.10; none below the root epoch) up to the time of the
   claim that ended it (its lane heads found as §11.10 says for an epoch this session never swept, never from the
   claim's cuts; that claim read at the position the current epoch's EPOCH record names when the restore did not process
   it, §6.8). These rows are processed as §11.10 says for rows found by scrollback. The history of an ended copy that
   the restore holds by its ENDED record reads the claim that ended its last epoch at the record's position, and shows
   that claim's line (§6.6 step 3). Other copies load their history when they are opened (§11.10). Build the views,
   ordered by §11.8. The slots and the "fewer than 30 rows" count every row, REACTION rows included (§11.12): the
   initial history is a number of slots, so its cost never depends on what the rows hold, and a lane with many
   reactions shows fewer of its messages until scrollback loads more. A REACTION whose target lies before the slots
   loaded waits until scrollback loads it.
7. **Inbox.** Read from the HEADS cursor (§11.5). Steps 4–5 have applied the self delta and restored every copy,
   a sibling's re-add copies and the copies of legacy skip records included, and settled the control lanes of the
   accepted ones; a request's is settled by step 8's probe, or by §6.7 step 4 when a J of its conversation comes first.
   So a J that a sibling took is a duplicate here and §6.7 step 6 sees which copies have ended (§6.7 steps 3–6).
8. **Requests** (§11.5): probe each live REQUEST copy once.
9. **Subscribe** (§10.8): `Tself`, `T_e` of the current epoch of each accepted copy that has not ended, the topics of
   followed lanes, and
   `Tlink` of each live link.
10. If more than 200 self records were applied since the snapshot, or there is no snapshot in `max(E_now, regEra)`,
    write a snapshot (§7.4; nothing defers it). Write HEADS when positions advanced (§7.3).
11. **Notifications.** If this device has notifications on, send its registration set, and write the notification
    cache when its preview is not `none` (§11.13).

Requests are paced to `RL_READ`: on 429 the client waits for `retry-after` and continues where it stopped.

**Cost.** In keys, rows and bytes, a restore costs:

- `copies × (members × P0 + 2)` probe keys (no control key for a copy at the epoch that its ENDED record names), plus
  `members × P0` keys per epoch changed since HEADS, plus up to one followed lane per member, plus a gallop per lane
  that moved;
- the control lanes it processes (step 5), only those of the snapshot's top and the epochs above it, each from the
  furthest control position that a HEADS entry it applied for that epoch gives, or from `(E_start, 0)` for an epoch
  without one (typically one reached through the account's own entry after its HEADS entries): one key per slot up
  to the epoch's winner, and a `blob/meta` request for each row before the winner that passes e-validity's local
  rules (§6.4 "Order of requests"), such as a member's signed junk claims. This part depends on the control-lane
  activity since the account recorded those positions and on the epochs since the snapshot: a restore never probes
  the control lane of an epoch below the top, whose winner it reads at the position an EPOCH record names, or below its
  start. An ended copy's last epoch is its top (or above it), so a restore processes the claim that ended it, from the
  furthest HEADS position for that epoch, only when the copy has no ENDED record; with one it probes no key of that
  control lane;
- one bundle (23–81 KB) per claim that the restore processes (step 5: one per epoch it re-derives, plus, for each
  ended copy without an ENDED record, the claim that ended it; and step 8: one per epoch above a request's root, below)
  and per epoch whose D it needs and has no DESC
  record for, which in practice means the epochs since the snapshot (every held epoch without one; a snapshot's DESC
  records cover its current and previous held epochs, §7.4);
- one claim row (in a batched `get`) per older epoch whose ending claim the initial history or a removed sender's row
  needs and the restore did not process (§6.8), per epoch between a lower start and the top (step 5), and per ended copy
  with an ENDED record whose history the restore loads (step 6);
- per claim processed (an epoch re-derived since HEADS or since the snapshot, or the claim that ended an ended copy
  without an ENDED record, step 5; and a request's epoch above its root, which its step-8
  probe re-derives on every restore, an ended request's up to the epoch of its ENDED record, the claim that ended it
  spared, §11.5), one `blob/meta` request (rule (g)) and at most 32 X-Wing encapsulations (the entry recomputations and
  the key checks of added members, §6.6 step 4, a few ms each);
- no `blob/meta` request for an epoch's `E_start` or join line when a TREG, a REQUEST or an EPOCH_PENDING names its
  bundle (§4.2), as for every request, created copy and accepted request (its EPOCH_PENDING or REQUEST), every copy
  joined since the upgrade (the TREG in its row, §7.3), and every one for whose bundle a snapshot holds a TREG (§7.4);
- for every other copy (an inbox, WELCOME or hello join that an earlier version recorded, or a copy that a legacy
  skip record starts, without a TREG, and no snapshot holding one yet), one `blob/meta` request per restore, which
  gives both its `E_start` and its join line: a restore shows the join line of every copy (§11.8). After its restore a
  device holds every such `t_reg`, so the first snapshot written after the upgrade holds their TREGs (§7.4) and the
  requests stop there; a copy created, joined or accepted since costs none. A copy that a legacy skip record starts also
  costs its bundle (for `D_{e′}`, §7.2) on each restore until a snapshot holds its own record and DESC, and a legacy
  copy whose HEADS entries all belong to the copies of its skip records (§7.2) walks its own lanes from its root once,
  until a snapshot holds its entry;
- the rows written since the account's last HEADS, in bodies, in every epoch since HEADS;
- `HISTORY_COPIES × lanes × HISTORY_INITIAL` rows of initial history;
- `MAX_REQUESTS × (2 · members + 3)` keys for requests (§11.5);
- the inbox rows since the cursor (at most about 30 minutes of inbox when HEADS is current);
- **directory:** the exact own-uid lookup, plus one prefix response (about 64–128 bundles, 120–240 KB) per distinct
  co-member that has no MEMBER record. With a current snapshot or HEADS that is none, except for listed uids that are
  not registered (§7.3; a member whose keys disagree with D has a MEMBER record and costs nothing), so the directory
  bytes of a restore do not grow with the directory or with the number of co-members.

It does not depend on the number of messages ever sent. As an example, 100 copies of 8 members are about 1 800 probe
keys (8 `get` requests) plus at most 4 800 history rows (about 1.4 MB at class 0), plus about 3 KB for the own bundle,
and no `blob/meta` request when no epoch changed since HEADS, no request has moved past its root epoch (its later epochs
are re-derived on every restore, above), a TREG, REQUEST or EPOCH_PENDING names every copy's bundle, and every copy that
has ended has its ENDED record, as from the first snapshot written after the upgrade on (before it, one per copy joined
by an earlier version, up to 100 here, all to the single BlobRegDO, on each restore until that snapshot, normally only
the first one, whose step 10 writes it). With ENDED records an ended copy costs its lanes' probe keys, and one claim row
when its history is loaded; a copy that ended before the upgrade from the first release costs the claim once more, on
each restore until a HEADS row or snapshot holds its ENDED record, normally only the first.

### 11.5 Inbox poll and requests

The client polls every `max(inboxSlot, 2)` seconds while the page is visible, on reconnect, and after unlock.

1. Let `(Ec, rc)` be the cursor. For each era E from `max(Ec, E_now − 3)` to `era(server now)` (from params or
   `x-segv-now`): `GET …/inbox/{E}/0?after=a` until `more = 0`, with `a = rc` for `E = Ec` and `a = 0` for every later
   era. A 410 moves the cursor to `(max(E_FIRST, E_now − 3), 0)`. Without a cursor (the self lane holds no HEADS
   record), start at the registration cursor with `t_r = start(regEra)` (below).
2. Trial-decrypt each row (§5.3), in chunks in a Web Worker, so the page stays responsive. A decapsulation that throws
   means "not for me". Process each J (§6.7). Joins found in one poll are processed one after the other, each after
   the held copies of its conversation are caught up and settled (§6.7 step 4). A J of a conversation of which an
   earlier J of the same poll created a copy is parked, with the cursor before it, until the next poll, when that copy
   is held and settled (§6.7 step 4): so an honest sequence of re-adds, each after a removal
   that ended the copy before it, gives one separate copy per re-add and no warning, in one poll or in several.
3. The cursor becomes `(E, closed)` of the last era read, but never passes a parked join (§6.7 step 4), and never
   leaves an era E before E is **complete**: a read of E returned `more = 0` and was issued at an estimated server time
   of at least `end(E) + (2·SKEW + 2·Δin)·1000`. Until then InboxDO E may still hold rows with `rel` above the `closed`
   it reported (posts are accepted until `end(E)` by its own clock, with up to Δin of jitter, and the tail may come
   from a cache up to Δin old, §10.5), so the cursor stays at `(E, closed of E)` and each poll reads E from there and
   every later era from `after = 0`. Joins found again in a later era are duplicates (§6.7 step 3). Joins and the new
   cursor are written as §7.3 says.

**Registration cursor**. An account's inbox starts at the cursor `(era(t), ⌊(t − T0)/D⌋)` with
`t = t_r − SKEW·1000` and `D = Δin·1000` (§9.3), raised to `(max(E_FIRST, E_now − 3), 0)` when its era is below that.
`t_r` is the `x-segv-now` of the response to the device's own register request (a 2xx, or a 5xx of that request; both
carry the header, §10.1) when the device holds that response; the device takes it once, and every retry of the
registration's HEADS write (§11.1) keeps that cursor. Otherwise `t_r = start(regEra)`: on a device that finds no
cursor in the self lane (step 1), on a registering device whose response was lost (§2.5 step 8), and on a reload
before the registration's HEADS landed. The register Worker read `t_r` before it wrote the account (`regEra =
era(t_r)`, §9.6), and every invite for the account is posted after that write, when the InboxDO's clock is at least
`t_r − SKEW·1000 ≥ start(regEra) − SKEW·1000`; so the invite lands in an era at or above `era(t)` and, in that era,
with a `rel` above the cursor's (§9.3), also when it lands in `regEra − 1` (a registration less than SKEW after
`start(regEra)`, which the Worker's bound `era(now − SKEW·1000)` admits, §9.7). The cursor MUST NOT come from the
client's server-time estimate, at the write or at the response's arrival: the estimate can run ahead of `t_r` and pass
such an invite. A cursor at or before this one, but not below `(max(E_FIRST, E_now − 3), 0)`, is also correct
(duplicates are harmless, §6.7 step 3), so an implementation MAY keep an extra margin and apply the floor after it.
The start without a cursor reads, beyond `(regEra, 0)`, the rows of `regEra − 1` posted in about its last
`SKEW + 2·Δin` seconds (22 s in production): at most one day cap of rows (2 000, about 2.8 MB), and the 4-era bound of
§9.3 and §13.2 item 11 still holds.

**Requests.** A copy created by a first-contact join whose `D.by` is not a contact (§7.3) is a **request**:

- It is recorded as a REQUEST self record, which carries `D`, so a restore needs no bundle fetch for it. At most
  `MAX_REQUESTS` are live (§7.3).
- At acceptance only `D.by`'s bundle (its `sigPk` against D, §6.7) and `dsig` are verified, and a MEMBER for `D.by` is
  written with the REQUEST from that bundle (§7.3), so `D.by` is never looked up at restore. Other members' rows
  verify under the keys in D; their bundles are fetched (for handles) only when the copy is accepted, and until then
  they are shown as `?…` (§11.2).
- It is not subscribed. On restore and at every catch-up it is probed (an ended request only until the claim that
  ended it is processed, or, when the restore holds its ENDED record, only until it reaches the epoch that
  record names, whose control lane it neither probes nor evaluates; a restore re-derives a request's later epochs only
  here, §7.4) with at most `2 · members + 3` keys: the next 2 control slots, plus control `(E_now, 0)` if that era is
  later (§6.5); and per lane the slot after the lane's known head (from HEADS, which covers requests too), or `(E_start,
  0)` when none is known, plus `(E_now, 0)` if that era is later. Hits are galloped, fetched and processed, so a member
  who has not posted yet still sees the others' rows after a restore, and corroboration does not depend on realtime.
- It becomes an accepted copy (a CONV_JOIN with `via = 5`, which copies the REQUEST's epoch key, plus CONTACT for `D.by`
  when the user's own act accepts it; the REQUEST keeps naming the bundle's `t_reg`, so the row holds no TREG, §7.3)
  when the user accepts it (`accept`, §11.11, from the accept control of the request's read-only preview, which itself
  accepts nothing), when self sends a TEXT, IMAGE or REACTION in it (§11.12), when `D.by` becomes a contact, or when a
  valid row (of any type) from a member other than `rootBy` and self is seen (which also writes CONFIRMED, unless the
  copy holds one: a request that a claim confirmed, §6.7 step 6, which accepts nothing, is still accepted by such a
  row). A row accepts or confirms a copy only once the copy's control lane is settled (§6.7 step 4), so a restore, or a
  catch-up, that meets a member's row from before the claim that removed self processes that claim first, and the ended
  request is neither accepted nor confirmed. None of these accepts an ended request (below), nor a request whose ENDED
  record the fold holds while its probe has not yet reached that epoch. On that transition the client processes every
  lane from `E_start` in body mode, looks up the members that have no MEMBER record, then treats the copy like any
  other.
- **A live copy whose `rootBy` is neither self nor a contact**, other than a request (a request that a third member's
  row accepted, or a copy that a legacy skip record starts, which §7.2 reads as accepted when its legacy copy was), has
  not been accepted by the user, and does not ring (§11.13). Only an explicit act of the user writes the CONTACT for
  its `rootBy`: self's TEXT, IMAGE or REACTION in it, or `accept` (§11.11) from the accept control, which the UI shows
  for such a copy, as for a request, for as long as its `rootBy` is neither self nor a contact. That CONTACT is written
  at once, in a self row that also holds a HEADS record (§7.3), after `rootBy`'s MEMBER is looked up when it has none
  (§11.11; a TEXT, IMAGE or REACTION whose lookup fails fails before its put, with `accept`'s error). `markRead`, which
  only reports an open pane (§11.10), writes no CONTACT for it.
- **An ended request**. A request copy ends as any copy does, when the final winning claim of its current epoch k
  removes self (§6.6 step 3), and is then inert, for good: no trigger above accepts it, its rows confirm nothing (the
  claim that ended it confirms it when a member other than `rootBy` and self made it), and §6.7 step 6 counts it in the
  confirmed check and the second-copy rule only for a J that contradicts its history ("Forks of an ended copy"), and for
  ⚠ only while another held copy contests it (pairwise, §6.7 step 6). It is shown with its rows up to the claim that
  removed self (for example among the conversations self left or was removed from, or above a later copy's join line),
  without ⚠ unless it is so contested, until it expires (§7.3). A J that re-adds self is a first contact like any other
  (§6.7 step 6): a new copy, a request unless `D.by` is a contact, with no warning when every other copy of the
  conversation has ended.
- A skip EPOCH record that an earlier version wrote for a request copy (the first release let a request copy take a
  skip) is read as the join of a separate copy (§7.2 "Legacy skip records"): a request, unless the request copy it came
  from was accepted. The request copy itself ends at the claim that removed self.

This bounds what an inbox spammer costs a victim: one `blob/meta` request and at most one bundle fetch of at most
81 248 bytes (§6.7 step 1), at most 32 key checks (§6.7 step 2) and at most one directory lookup per join (none when
`D.by` already has a MEMBER record, when the poll already fetched that prefix, or when a fresh answer already lacked
that uid in this session; §10.6), at most `MAX_REQUESTS × (2 · members + 3)` keys per catch-up, no directory lookups at
restore, and no topics. Only a member or a former member of a conversation knows its `conv`, so only they can send a J
that also costs the settling of the victim's copies of that conversation (§6.7 step 4) and, for a J below the root epoch
of every copy of it that has not ended and below the root of some held copy, ended or not (r the lowest such root), of
the J's own copy, never past epoch r − 2 (§6.7 step 6), which costs what a member's control-lane activity costs a
restore (§11.4 cost), again for each such J sent.

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
- A sibling's re-add reaches a device as the CONV_JOIN or REQUEST of a new copy on `Tself` (§6.7 steps 6–7), which
  it holds as written (§7.3), with that copy's join line and no warning. Siblings that take the same J
  hold one copy, keyed `(conv, H(D))`; siblings that take different Js (one J each, for re-adds that a second removal
  separates) hold different copies, each on both devices, and so does every restore and snapshot. A lagging sibling
  that has not yet processed the removal holds the new copy beside the copy that is about to end, marked ⚠ only
  until that copy ends (§6.7 step 6). A sibling's ENDED record ends the copy on a device that applies it once the
  copy holds that epoch, without processing the claim, as at a restore (§6.6 step 3; it is the
  account's own record of a final winner). Such a device still reads the claim at the record's position (§6.8) when it
  holds rows of that epoch: it drops the rows stored after the claim, as every removed receiver does, and so retracts
  those it has already shown, and decides the rows that reach it later the same way. A legacy skip record that a tab
  still open on the first release writes is read as §7.2 says, so it merges with the copy of a device that took the
  same J, and never accepts it when that device holds it as a request, unless the user accepts it in that tab.
- Two devices may write `(E, n)` and `(E+1, 0)` of one lane (or of the self lane) around an era boundary, in either
  order. Readers find both: they keep the end of E's dense prefix in the expected-label map until it is observed
  sealed (§11.2), record no position in E+1 before that (§7.2), and scrollback probes each era's dense-prefix end
  (§11.10, §12.2). A single device never writes below its lane head's era (§7.3, §11.3 step 4).

### 11.8 Order, timestamps, unread

- **Timestamps.** Shown times are the sender's `ts`, clamped to `[T0 + t·1000 − 300 000, T0 + (t+Δ)·1000 + 300 000]`,
  where `t` is the row's stored time.
- **Order.** A conversation's messages are ordered by `(clamped ts, epoch, E, lane, n)`.
  - Local echoes come last until applied.
  - System lines take the clamped `ts` of the claim or LEAVE row that caused them. A join's line ("started the
    conversation" or "added you", §11.9), whatever carried J (an inbox invite, a WELCOME or a link hello; a re-add's
    copy and a copy that a legacy skip record starts included, §6.7 step 6, §7.2) and also for the creator's own copy,
    shows at `D.ts` of the joined epoch's descriptor, clamped to the same window around the stored time `t_reg` of that
    epoch's bundle (seconds since T0, a multiple of Δ, §9.2):
    `[T0 + t_reg·1000 − 300 000, T0 + (t_reg + Δ)·1000 + 300 000]`. `D.ts` is the committer's clock, so a far-future
    value would otherwise keep the copy at the top of the conversation list through `lastTs`, a request from a spammer
    included. The device holds `t_reg` from the `meta` answer of §6.7 step 1 (from the PUT response for its own
    creation, §6.1 step 4), and a restore takes it as §4.2 says: from a TREG for the epoch's bundleId, or a REQUEST or
    EPOCH_PENDING record naming its bundle, so it makes no `blob/meta` request for the line, or else, for a join that an
    earlier version recorded without a TREG (a legacy skip record included), from one `GET /api/v2/blob/{id}/meta`
    (§11.4 step 5 and cost). A restore shows the join line of every copy, whatever part of the history it loads. The
    line sorts before every row of that epoch with the same clamped `ts`.
  - There is no server total order, so concurrent messages from different senders may appear in different orders on
    different devices.
- **`lastTs`** is the maximum clamped `ts` of the copy's TEXT and IMAGE rows and system lines. A REACTION row never
  raises it (§11.12): `lastTs` ranks the copies whose history a restore loads (§11.4 step 6), and a reaction that is
  later removed could not lower it again.
- **`unread`** counts TEXT and IMAGE rows not signed by self (and epochs committed by others) applied after restore
  finished, while `live`, never a REACTION row. It is not persisted. `markRead` resets it. A row applied during
  restore, a row from a sibling device, and a row later dropped by §6.8 never count.
- **`MessageView.seq`** is a local, increasing application counter used as a stable tie-breaker. It is not a server
  sequence.

### 11.9 System lines (exact text)

These strings are kept from v1. `who(u)` is "you" for self and `@handle` otherwise.

| event | system line |
| ----- | ----------- |
| join at e = 0 | "`who(by)` started the conversation" |
| join at e > 0 (a re-add's copy included, §6.7 step 6) | "`who(by)` added you" |
| accepted e+1, members added | "`who(by)` added `who(a)`, …" |
| a claim with `rm` bits for members who had not left (shown by every member of e, frozen ones included) | "`who(by)` removed `who(r)`, …" |
| a claim that drops only leavers | "keys rotated after `who(l)`, … left" |
| accepted e+1, no membership change | "`who(by)` rotated the conversation keys" |
| accepted e+1, renamed | "`who(by)` renamed the conversation to “name”" |
| accepted e+1, name removed | "`who(by)` removed the conversation name" |
| removed (`rm` bit set for self) | "`@by` removed you" (not shown when self had left in that epoch, §6.6 step 3; derived again when a LEAVE record arrives later; shown at restore too, once the restore processes the claim or, for a copy restored by its ENDED record, once its history reads the claim; it stays in the ended copy, and a re-add's copy shows its own join line, §6.6 step 3) |
| frozen | the critical warning of §6.6, no system line |
| leave | "you left the conversation" (own, once, at the earliest own LEAVE row held; also one that §6.8 drops, §6.9) or "`@x` left" |

The rename lines compare the names as displayed (§5.1): a name that fails the reader's `validName` counts as no name.
A REACTION row shows no line (§11.12).

Lines that depend on others' leaves are derived from the leave state (§6.9), not latched when an event is processed. A
LEAVE row R of x in epoch k shows "`@x` left" while it is the kept source of x's leave in k, §6.8 accepts it, and x is
not recorded as left in k−1 (a leave carried into k shows its line at its source in an earlier epoch), so one leave
shows one line. R loses its line when a source with a smaller key replaces it, when §6.8 drops it, or when x becomes
recorded as left in k−1. A claim's "removed" and "keys rotated" lines are derived again whenever the leave state of its
epoch changes (§6.6 step 5). The same rows thus give the same lines, whatever the order in which they arrived.

After a reload the device holds fewer rows (§6.6 step 5): a LEAVE row before the HEADS positions shows its line only
once the initial history or scrollback loads it (§11.4 step 6, §11.10), and the leave state of an epoch below the HEADS
epoch is rebuilt only from the rows they load. Until they load a leave's source, its "@x left" line is missing, or
shows at a later LEAVE row of the same leave that they did load (a repeat that is the kept source of a later epoch, x
not yet being recorded as left in the epoch before it), and moves to the earlier row once that row loads, so one
leave still shows at most one line; and a claim below the HEADS epoch can show a removal where the live
view showed "keys rotated". A claim that history reads without processing it (§6.8) shows its lines as a processed claim
would. The own "you left the conversation" line likewise appears once the history loads an own LEAVE row, at the
earliest one it holds (also one that §6.8 drops, §6.9), while the copy is `left` at once from its LEAVE records (§6.9).
In the same way, "@by removed you" of a copy that a restore holds by its ENDED record appears once the initial history
or scrollback reads the claim that ended it (§11.4 steps 5–6), while the copy has ended at once.

### 11.10 Scrollback

When a conversation is opened (`markRead`, which the UI calls every time it opens a conversation pane, though not while
the pane shows a read-only preview, a request's or that of another copy whose `byContact` is false, whose accept control
calls `accept` instead; `markRead` accepts nothing and writes no CONTACT, §11.11), the client loads older rows until the
view holds `VIEW_MESSAGES` messages (TEXT and IMAGE rows; REACTION rows are not messages, §11.12) or the history is
exhausted. This runs once per copy and session; later calls are no-ops.

- For each lane, probe `(E, n−32..n−1)`.
- At `n = 0`, move to the previous era that has rows: follow `prev` of the oldest loaded valid row, and also probe the
  dense-prefix end of each earlier era down to `prev`'s era, so rows that are not on the `prev` chain (a sibling's row
  written across an era boundary) are found too.
- Below the first row of an epoch e, continue in the copy's previous held epoch e−1, using its keys from the self lane
  or the restore (§11.4 step 5) and its DESC, or its bundle, for its D; the history ends below the copy's root epoch. A
  copy's history is its own: a re-add's copy does not continue into the ended copy before it, which shows its own
  history (§11.11). On entering a lane of an older epoch e, which the winning claim C ended, first find the lane's head
  (a session that did not process C reads it at the position that the EPOCH record of e+1 names, §6.8; an ended copy's
  last claim is processed by a restore, or read at the position of its ENDED record, §11.4 step 5):
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
replaces the kept source only when its key is smaller; a REACTION applies to its target as §11.12 says, and one
whose target is not loaded yet waits for it; in an epoch that a claim removed self from, a row
stored after that claim is dropped, §6.8, as the live final sweep dropped it). Older rows are never
counted as unread.

### 11.11 Engine operations

| Engine call | protocol |
| ----------- | -------- |
| `register`, `login`, `loginWithRecovery`, `addPasskey`, `logout` | §2.5. `logout` bumps the generation, closes the socket and stops polls and background deliveries, clears the remembered session, revokes image URLs, and drops all state. Another device or the next session finishes pending deliveries (§6.11). |
| `createConversation(handles, name)` | §6.1, by handle. It resolves after step 5, with the new copy in `conversations`; steps 6–9 run in the background. |
| `sendText` / `sendImage` / `leave` | §11.3. An image is uploaded first (§8.1); the echo shows a local preview. |
| `react(convId, messageKey, emoji, on)` | §11.3 and §11.12: one REACTION row for the TEXT or IMAGE row of that message, with `op` 1 for `on` and 0 otherwise. It resolves when the row counts as delivered (§11.3 step 8) and fails with §11.3's errors; there is no echo. Each `MessageView` carries `reactions: {emoji, count, mine}[]`. |
| the notification setting of the device | §11.13: turning it on subscribes the browser and registers the set; turning it off unsubscribes, then deletes the registration and the notification cache. The preview (`none`, `name`, `message`) decides what notifications show. The names of these calls are implementation-defined. |
| `addMembers` | Drop leavers (a separate commit first if a requested user is a listed leaver), then §6.3 with the added uids. Resolves after the switch and the first delivery attempt. |
| `removeMember` | §6.3 without that uid and without leavers. Removing self is refused ("use “leave” to leave a conversation"). |
| `markRead(convId)` | Resets `unread` and starts scrollback once (§11.10). It only reports that the conversation's pane is open: it accepts no copy and writes no CONTACT, whatever the copy (§11.5). |
| `accept(convId)` | The user's acceptance, from the accept control (§11.5). For a live copy whose `rootBy` is neither self nor a contact it writes, at once, in a self row that also holds a HEADS record (§7.3): for a request, unless §11.5 lets nothing accept it, the CONV_JOIN with `via = 5` and the CONTACT for `D.by`; for another such copy, the CONTACT for its `rootBy`. For any other copy, an ended one included, it does nothing. When `rootBy` has no MEMBER record (§7.3), which only a copy that is not a request can lack, `accept` first looks it up by uid as §10.6 does and writes the MEMBER in the CONTACT's row; when the lookup fails or finds no verified bundle for `rootBy`, `accept` fails with "could not verify who started this conversation; try again" and writes nothing. It resolves when that row is written and fails with the write's error. Each `ConversationView` carries `byContact`, false when the copy's `rootBy` is neither self nor a contact; while it is false and the copy has not ended, the UI shows the copy as a request's read-only preview, with the accept control, which calls `accept`. |
| `loadImage` | §8.1, cached by `id.k`. |

Links (§4.3, §5.5) are implemented in the engine as internal operations (`createLink`, `openLink`), together with the
LINK record, `Tlink` subscriptions and hello probing. They are not on the `Engine` interface in stage 1, because the
link-sharing UI is deferred (§14).

**Ended copies**. A copy that has ended (§6.6 step 3) stays in `conversations`, under its own key (§7.3
"Copy keys"), with its history and lines and `canSend = false`; an ended request stays until it expires (§11.5).
A re-add's copy is another entry, with its own join line. Informative: a client MAY show the copies of one
conversation as one thread, each ended copy's history above the next copy's join line, in the order of their keys;
the engine's view stays one `ConversationView` per copy, and the UI's archives list already shows the copies self
left or was removed from.

### 11.12 Reactions

A REACTION row (type 3, §3.3) is a member's emoji reaction to a TEXT or IMAGE row. It is a lane row like any other:
it is sent on the sender's own lane of the send's epoch by the rules of §11.3 (no echo; refused wherever a text is
refused; a rotation first when the epoch lists a member who has left), accepted by §3.3 and §6.8, and part of its
lane's `prev` chain (§12.2). It writes no self record of its own.

- **Target.** A REACTION row R of epoch e that the reader holds and accepts reacts to the row T at `(tE, tn)` on lane
  `tl` of epoch `te` when all of these hold: `te ≤ e`, R's copy holds epoch `te` (a reaction never crosses copies) and
  `tl < |D_te|`; T is a TEXT or IMAGE row that the reader holds and accepts (§3.3, §6.8); and `th = t16(HMAC(rk_te,
  enc("segv.sh/v2/react", label_T, body_T)))` over T's label and stored body. Otherwise R reacts to nothing and is
  ignored, without a warning. While the reader holds no decided row at T's position (its history has not loaded it yet,
  §11.4 step 6, §11.10, or §6.8 has not decided it), R waits, and it takes effect once T is loaded and accepted. A
  target in an epoch that the copy does not hold (one before its root: the copy of a member added later, or a re-add's
  copy) never loads, so such a reaction never takes effect there.
- **State.** For a target T, a member u (by uid) and an emoji x (its bytes), the reaction is on or off. The reader
  takes u's REACTION rows that react to T in lane order (by the row's epoch, then by `(E, n)`; u's devices share the
  lane through CAS, §11.7, so every device sees the same order) and walks them from an empty set: an add (`op = 1`)
  of x puts x in the set, unless x is in it already or the set already holds `MAX_REACTIONS` = 8 emoji, in which
  case the add is ignored; a remove (`op = 0`) of x takes x out of the set. So the latest row for (T, u, x) decides,
  except that an add of a ninth emoji while eight are on is ignored, and a later remove frees a place. Only accepted
  rows count: a REACTION row that §6.8 drops counts for nothing, and when a new final winner makes §6.8 drop a row it
  had accepted (§6.8), the state is computed again; a retracted target loses its reactions.
- **Agreement.** The state depends only on the rows the reader holds and accepts, so devices that hold the same rows
  show the same reactions. A device that holds fewer (after a reload, until the initial history or scrollback reaches
  them) shows those of the rows it holds and the others once they load, as for lines (§11.9).
- **Display.** A message shows each emoji that is on for at least one member, with the number of those members and
  whether self is one of them (`MessageView.reactions`, §11.11), in an order the client chooses. Whether an emoji
  string is one emoji is a display rule, never a validity rule: a client MAY leave out a string that its own Unicode
  tables do not make one emoji, which changes neither the state nor the count of 8, so devices with other tables
  agree on the state and differ only in what they show. A client SHOULD send one emoji only, and SHOULD NOT send a
  REACTION that changes nothing by the state it holds (an add of an emoji that is on, a remove of one that is off, or
  an add beyond the 8).
- **Not a message.** A REACTION creates no `MessageView` and is not a message for `VIEW_MESSAGES` (§11.10); it never
  counts toward `unread`, never raises `lastTs` (§11.8), shows no system line (§11.9) and does not ring (§11.13). It
  is a valid row of its member wherever a rule asks for one: the followed lanes and sweeps (§11.2), the qualifying
  1:1 of §6.12 step 1, confirmation (§6.7 step 6) and the acceptance of a request (§11.5: self's REACTION accepts it as
  self's TEXT does, and writes the CONTACT for the `rootBy` of any live copy whose `rootBy` is neither self nor a
  contact, while that of a member other than `rootBy` and self is a third member's row). The initial history counts it
  as a row (§11.4 step 6).
- **Compatibility.** The first release reads type 3 as invalid, so a REACTION row is junk to it (§3.3): it occupies
  its slot and is not shown, and a later row's `prev` check compares `prevh` with the stored body of the slot it
  names, which needs no parse (§12.2). That client shows no reactions, and a third member's REACTION neither confirms
  nor accepts a copy there; the CONFIRMED and CONV_JOIN records that new code writes for it do (§7.3). One path of
  that client differs: when it walks back along the `prev` chain of a realtime row that lies beyond the part of its
  lane that its catch-up reached (§12.2 "Rows beyond a hole"), it stops at a REACTION on that chain with the warning
  "the server is showing different messages from @x to different members" instead of going on. A second path differs
  in its scrollback (§11.10): it moves to an earlier era of a lane only through the `prev` of the oldest row of the era
  that it can read, and a row whose `prev` lies in the same era ends the lane for it; so when a member's first rows of
  an era are REACTION rows, that client loads none of the member's rows of earlier eras on that lane.

### 11.13 Notifications (Web Push)

Notifications are optional (§9.8). A client offers them only when params carry `push` (§10.9), and calls neither
endpoint of §10.10 otherwise. They are off by default and chosen per device, the pushes carry no content (§9.8), and
invites never ring. What a notification shows is the device's own choice (its preview, below): by default the same
fixed text for every push; otherwise the conversation's name, or its name and newest message, which the device
decrypts itself.

- **The setting** belongs to the device, is off by default and is never synced: it is no PREFS key (§7.2), and the
  device keeps it in its own storage, with the endpoint it last registered. A client shows it only when params carry
  `push` and the browser supports Web Push (on iOS and iPadOS, only in a web app opened from the Home Screen).
  Turning it on, in a user gesture: request the notification permission, register the Service Worker (below), call
  `pushManager.subscribe({userVisibleOnly: true, applicationServerKey: <push.vapid>})`, and register the set. Turning
  it off, and `logout`: `unsubscribe()` first, then send the endpoint with an empty set, and delete the notification
  cache (below); `logout` also turns the setting off, so the next account that signs in on that browser starts with
  notifications off. In this order, a tab closed between the two steps, or a deletion that a restart of PushDO loses
  (§9.8), leaves registered only a subscription that has ended, which PushDO deletes at its first push; in the other
  order it would leave a live subscription registered, and the next account on that browser would get the previous
  one's notifications for up to 30 days.
- **The preview** belongs to the device like the setting, is never synced, and is one of `none` (the default: the
  fixed text of §9.8), `name` (the conversation's name) and `message` (its name and newest message). A device offers
  `name` and `message` only while it keeps its session across restarts (the remembered session, §11.11), since the
  Service Worker needs the notification cache, which is kept only then; when the device stops keeping its session, its
  preview becomes `none`.
- **The registration set** of a device holds, for each copy that is not a request, has not ended, whose leave is not
  current (§6.9), whose `rootBy` is self or a contact (§7.3), and that the user has not muted on this device (a local
  choice, not synced), the bell `B_c(ℓ)` of self's lane ℓ in the copy's current epoch c; frozen copies are included. It
  holds no bell of an earlier epoch (senders ring those, below), none of a request, and none of another live copy whose
  `rootBy` is neither self nor a contact (§11.5), so a conversation started by someone who is not a contact never rings
  before the user accepts it or self sends a TEXT, IMAGE or REACTION in it (either makes `rootBy` a contact, §11.5).
  When the set has more than `push.maxTokens` bells, it holds those of the copies with the newest `lastTs`.
- **Registering.** `POST /api/v2/push/sub` (§10.10) with the whole set replaces the endpoint's registration. A device
  sends it when the set changes (an epoch switch, a join, an accepted request, a new contact, a leave, an ended copy, a
  mute), at most once per Δ (changes within Δ go together); after each restore (§11.4 step 11); and at least once per
  24 hours while the session runs, so that a registration in use never reaches its expiry, and one that a restart of
  PushDO lost or reverted (§9.8) comes back within a day. Each time, it first reads
  `pushManager.getSubscription()`: when the endpoint differs from the one it last registered, it sends the old
  endpoint with an empty set before the new one; when the subscription is gone, or was made with another
  `applicationServerKey` than `push.vapid`, it sends the old endpoint with an empty set and subscribes again (or,
  where the browser needs a user gesture for that, shows the setting as off). A failed request is retried with backoff
  (1 s, doubling to 10 minutes), never sooner than its `retry-after` (an hour after "push full"); a 404 means that the
  deployment no longer offers push: the device calls `unsubscribe()` and shows the setting as off.
- **Ringing.** After each successful put of a TEXT or IMAGE row (§11.3 step 6: an OK with a verified receipt, a
  CONFLICT with its own body, or a probe that finds its own body), also a late one (§11.3 step 8), the sender sends
  one `POST /api/v2/ring` (§10.10) for the row's `(E, label)` with these bells, e being the send's epoch: `B_e(ℓ)` for
  every lane `ℓ ≠ from` of `D_e`; and, when the copy holds e − 1, `B_{e−1}(ℓ′)` for each member of both `D_{e−1}` and
  `D_e` other than self of whom the copy has seen no valid row in e (§11.2), ℓ′ being its index in `D_{e−1}`. With no
  bell nothing is sent. The sender rings every such lane, whether or not its member turned notifications on, which the
  sender does not know. It does not wait for the answer, and the send's outcome never depends on it; after a network
  error, a timeout or a 5xx it sends the same request once more, within Δ, and never otherwise. Nothing else rings: no
  WELCOME, CLAIM, LEAVE or REACTION row, no self row, no inbox invite and no link hello.
- **Why the previous epoch.** A device that is closed while the epoch changes keeps the bell of the epoch it last
  saw registered until it is opened and processes the change. Senders ring that bell while its member has posted
  nothing in the new epoch, and stop once a device of that member has, or once the epoch changes again. A member
  removed at the change knows the old bells and can watch them for as long as any continuing member stays silent,
  learning when messages are sent and by which of the silent members (§13.4).
- **The notification cache.** While notifications are on, the preview is `name` or `message` and the device keeps its
  session, the client keeps a cache for the Service Worker in the origin's storage, sealed with AEAD under a device key
  that the browser cannot export (a non-extractable WebCrypto key kept beside it), and never sends it anywhere. For each
  copy whose bell is in the registration set it holds that bell, the copy's `ref` (below) and the name that the client
  shows for it. With `message` it also holds the copy's current epoch c, `conv`, `mk_c`, `rk_c`, self's lane index, the
  `sigPk` of each member of `D_c` and the handle that the client shows for it, and for each lane of c its **next slot**:
  the slot after the lane's head as the client last knew it, or `(E_start(c), 0)`. The client writes the cache whenever
  it sends the registration set, when a copy's name changes, when the page is hidden, and at least every 5 minutes while
  the session runs, each lane's next slot as the later of the stored one and its own. It deletes the cache whenever the
  preview changes, before the change takes effect (and then writes it again for a preview other than `none`), when
  notifications are turned off, and at `logout`, so that no name or key of a `message` cache outlives a downgrade. No
  write brings back a cache that was deleted, or one decided under an earlier preview, from any tab: the cache keeps a
  generation, which every deletion moves on; a client reads it before it decides to write, and its write is stored only
  while the generation is unchanged; the Service Worker's write is stored only while the cache it read is still the one
  stored; and only a client creates the device key, together with the cache. The cache holds no key that the kept
  session does not already give (AK derives every key of every held epoch with the server's help, §11.4), but it holds
  names and handles, which the device keeps nowhere else.
- **The Service Worker** is registered at scope `/`, without a `fetch` handler and without caching, so it never serves
  the app's pages or scripts; its registration takes a Trusted Types policy in the app's CSP. A browser that supports
  declarative push messages hands it the proposed notification of the payload (§9.8), and other browsers the payload
  itself; either way it gets the payload's `title`, `body`, `navigate`, `tag` and `bells`. For every push it shows at
  least one notification, within 8 s of the push event (a browser may revoke a subscription whose pushes show nothing:
  `userVisibleOnly`):
  1. When it has no cache, the preview is `none`, or no bell of `bells` other than the zero padding is in the cache: one
     notification with the payload's `title`, `body` and `tag` that opens `navigate`, or with the same fixed values
     when the payload is not that JSON. It does nothing else.
  2. Otherwise one notification per distinct copy that the bells name, in their order. With `name` its title is the
     copy's name and its body the payload's `body`; its `tag` is the copy's `ref`, and it opens the copy's URL (below).
  3. With `message` it first makes one `POST /api/v2/get` (§10.4) for those copies: for each lane of each copy's cached
     epoch other than self's, the slot before the lane's next slot when it is in the same era, and the slots from the
     next slot on, at most `W` of those per lane and at most 256 keys in all, with slot 0 of `E_now` in place of the
     last of them when the next slot's era is below `E_now`. It keeps a row only when it opens under the cached `mk_c`
     and parses (§3.3), its label recomputes as `Lmsg_c(from, E, n)` with `from` its lane, its signature verifies under
     the cached `sigPk`, and it is a TEXT or IMAGE; a row in the slot before the next slot, which the client has already
     read (as it does when it is open while the push comes), only when it was stored in the last 5 minutes. A copy's
     notification is then that of step 2 with, as its body, the copy's newest such row by clamped `ts` (§11.8):
     `@handle: ` and its text, cut to 200 characters, or `@handle sent an image`, followed by ` (+k)` when it found k
     more. A copy without such a row, or whose answer has not come 8 s after the push event, gets the notification of
     step 2 as it is. Then it moves each lane's next slot past the dense prefix it found from that slot on, keeping the
     later of the stored one and its own.

  It takes the text of these notifications from the cache and from rows that verify only, never from the payload,
  which O composes. It reads no key but the cache's device key, makes no request but that `get`, and stores nothing
  but the next slots. It checks no checkpoint, receipt or `prev` chain (§12) and reads no control lane, so a preview
  may miss rows, or show a row that the app later drops (§6.8). Its `notificationclick` handler focuses an open window
  of the app and moves it to the notification's URL, or opens that URL.
- **Conversation URLs** (informative). The client names a copy in its page URL by
  `ref = b64u(HMAC(HKDF(AK, "", "segv.sh/ui/ref"), utf8(key))[0..9])` (12 characters), where `key` is the copy key
  (§7.3): the same on every device of the account, except where §7.3 lets copy keys differ, another value for any
  other account, and nothing that tells `conv`. The URL is `https://<host>/#c/<ref>`, whose fragment never reaches
  the server. Opening it shows that copy once the client holds it, and the conversation list when no copy has that
  `ref` once the restore has ended. A notification of a copy opens that URL, and the client closes the notifications
  whose `tag` is a copy's `ref` when it shows that copy.
- **While the app is open**, a device still gets notifications, also for the conversation on screen: telling the
  server which device is in use would tell O when each device is used. In place of the steps above, the Service
  Worker MAY show none while a window of the app has focus, where the browser allows that.

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
- **Every type.** Lane rows of every type are on the chain: a REACTION, a WELCOME or a LEAVE is a valid row of its
  lane like a TEXT, names its `prev` and is named by the next row's (§11.12).

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

| linkage | P / P\* (public archive, public API) | O (operator, direct TLS) | M (member) | N (push service) |
| ------- | ------------------------------------ | ------------------------ | ---------- | ---------------- |
| message ↔ sender | None: no sender column, the signature is inside the AEAD, writes are anonymous. Only Δ-rounded `t` and the class. | The writer's IP for every put, which with an IP-to-account match (unlock, own-bundle lookup) gives the account. | Verifiable, not deniable. | — |
| message ↔ recipients | None for rows. Inbox invite: one of all users (β = 0), even against a quantum P. | Exactly, through the socket's topic set and the labels each client fetches. | The member list. | — |
| message ↔ message (same conversation) | No identifiers. Rows in the same Δ batch and rare classes are visible. With S = 1 and low traffic, timing correlation is strong. | Exactly: same topic, same IP. | Everything. | — |
| user ↔ conversation | None. The directory reveals that the account exists and when it registered (the client's `ts`, and the minute through the dirlog head in checkpoints). | The topic set and fetch pattern per socket / IP, linked to the uid at unlock. | Co-members of shared conversations. | — |
| user ↔ user | None. Global inbox counts per slot are public. | The whole social graph, including a p-bit prefix of every handle and co-member lookup (§13.2 item 10). | Co-members only. | — |
| activity of a user | Directory events (registration, wrap additions); the size of the global inbox; self rows (one after each own creation, commit, join or leave, and at most one HEADS row per 30 minutes while active), which P cannot tell from other rows except by timing. Per-user send volume is not visible. | Per-IP read and write volume and times; online time; topic sets; with a `message` preview, when each such device receives a push, also while the app is closed (§13.4). | Send times in shared conversations. | When each of its devices that turned notifications on is notified (§11.13). |
| activity of a conversation | Not directly: rows have uniform labels. | Exact per-topic volume and times. | Everything. After removal: only that a claim happened, its `rm` bits and its cuts; with push, also, through the old bells, when messages are sent in the new epoch and which of the members silent there sends them, until they all post there or the epoch changes again (§13.4). | — |
| membership changes and creations | Both show the same row pattern: a class-1 self row, one class-1 row at least Δ+SKEW later (claim or decoy, which P cannot tell from a medium text), then J deliveries and one class-1 self row (DELIVERED, padded for any number of recipients, §6.12); at most hourly, that some blob was registered. Members who receive J by inbox add that many inbox rows within seconds, while a removal or rotation adds none, so P can tell "someone was invited by inbox" from "nobody was" (§13.2 item 12). Not the member count, not who. No self rows follow a claim observed by other members, and a freeze writes nothing. | Which IPs fetch the bundle blob, so the members. | The members of e+1 see D′. Every member of e, removed ones included, sees `rm` (who of the old members was dropped). | — |
| content | The size class only (a reaction is a class-0 row, like a short text). Safe against a quantum P. | Same, plus blob fetches per IP (image recipients); with push, which puts are texts or images, since a ring follows them (§13.4). | Everything in epochs held. | Nothing: every push has the same length and fixed text, and the bells in it are encrypted to the device (§9.8). |
| directory | handle ↔ uid ↔ keys, registration time, every wrap (credential ids, recovery ids). | The same, plus a p-bit prefix of every lookup, and the exact wrap id and own uid at every login. | — | — |
| device ↔ notifications (§9.8, §11.13) | None: push data is not public. | At each `push/sub`: the IP ↔ the endpoint ↔ its bells. Stored: the endpoint ↔ keyed hashes of its bells ↔ the day of its last registration, also in the platform's 30-day storage history, in which PushDO writes a change only after its UTC day has ended, so it shows which endpoints' bells changed, and which were deleted, on which day, and on a quiet day those that changed together may be co-members (§13.4); the number of bells is about the number of conversations it is notified for. With a `message` preview, each push is followed by a `get` of the conversation's lanes from the device's IP, which links the endpoint to that IP and dates the push's arrival (§13.4). | — | That the device uses this server (the VAPID key), linked to its subscription and often to an account with the browser's vendor. |
| message ↔ recipients' devices | None. | At each ring: the writer's IP ↔ the row ↔ the bells of the other lanes ↔ every endpoint registered under them, **offline devices included** (held in memory only, never stored). | — | When each device is notified (within `PUSH_JITTER` + `PUSH_TICK` of the ring, at most once per `PUSH_WINDOW`); comparing the times of its devices suggests which share a conversation. |
| devices ↔ account | None. | The devices of one account register the same bells, so the stored registrations link them (not to the account). | — | — |

Never stored anywhere: topics, WebSocket topic subscriptions, IPs, RESUME rings, rate-limit keys, arrival order
inside a Δ batch, and inbox jitter. PushDO stores only what §9.8 lists, and never a uid, handle, conversation, topic,
IP or sender (§0.1, §13.4). The N column applies only to devices that turned notifications on; N sees nothing of the
others.

### 13.2 Properties of v1 that stage 1 weakens

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
   (about 4 weeks). A first-contact invite that none of the recipient's devices picks up within that window is lost, and
   the inviter must re-invite. An account keeps at most 64 requests that it has not accepted (§11.5), so a spammer can
   push out a genuine request from a stranger before the user accepts it. Conversations that were joined are recorded in
   the self lane and never lost.
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
   and the "@x left" line is missing or sits at a later repeat of that leave (§11.9).
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
      member could still read, and stage 1 would show them that member as removed. Stage 1 refuses texts, images and
      reactions there (§11.3 step 2), so such a conversation becomes read-only; the members start a new one. A member
      who signs an e-valid claim could already end everyone's messaging by removing them, so no attacker gains power.
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
    sender's own next slot in the following epoch) would close both (§14). The first case has one more effect on a
    member that the racing claim drops: §6.8 ends that member's view of the epoch at the claim, so a
    WELCOME that the sender's other device stored there after it is lost for that member (§6.9).
16. **A re-add after a removal starts a separate copy, accepted on `D.by`'s signature alone**. v1 continued a removed
    member's copy at the re-add (its skip rule), and its devices replayed one global log and agreed. Stage 1 keeps each
    membership in a copy of its own (§6.6 step 3, §6.7 step 6), so the history of one conversation can be split across
    copies: a client MAY show them as one thread (§11.11), and scrollback of a re-add's copy does not reach the ended
    copy's rows, which that copy shows. A removed member accepts a re-add on the signature of `D.by` under its directory
    key alone, as a first contact (§6.7 step 6), and any member or former member of the conversation knows `conv` and
    can send one, into a branch that only it writes. While self holds no copy of the conversation that has not ended,
    such a forged re-add shows no warning, as any first contact does; a later honest re-add then meets §6.7 step 6,
    which keeps it with the second-copy warning, or rejects it with the critical warning when the forged copy is
    confirmed (its forger can confirm it with a second account), also once the forged copy has ended (its branch removed
    self), when the honest J is for an epoch that copy holds or the one after its last, which makes it a fork of that
    copy. That warning names the second J's `D.by`, so it cannot tell who forged: the user is warned, and only an
    out-of-band check tells which copy is genuine. A J that provably contradicts an ended copy's history (one for an
    epoch the copy holds, with another D, or for the epoch after its last) is a fork, rejected or warned about as
    against a live copy (§6.7 step 6). While self holds a copy that has not ended, a J at or above that copy's root is
    compared with it at once (rejected, or kept with the second-copy warning), never settled first; only a J below the
    root of every such copy, and below the root of some held copy, ended or not, is settled first, and kept without a
    warning when its own branch removes self at least two epochs below the lowest such root (an overtaken J, §6.7 step
    6; an ended copy's root counts too, so a J below an ended copy's root whose branch still lists self in the epoch
    before it is compared with that copy). A member can start such a copy into a forged branch: it is kept without a
    warning and never shown as a second live copy, but it is not inert for fork detection, since a later J that
    contradicts its history is rejected or warned about as against it; an honest re-add, which comes above the live
    copy's root, never contradicts it. The same comparison works against an honest re-add when a former member forged
    the higher copy: a forged J for a high epoch, sent while self holds no copy that has not ended, is a first contact
    without a warning; once its branch has removed self and a second account of the forger has confirmed it, every
    later honest re-add for an epoch below its root is an overtaken J whose own copy, live, stops below that root
    without ending, so the forged copy counts against it as confirmed, and the re-add is rejected with the critical
    warning, which names no one (§6.6 step 3, §6.7 step 6). This lasts while self holds the forged copy, and the forger
    can make it permanent: before its branch removes self, a row of its second account in the forged copy accepts it
    (a request is accepted by a third member's row, §11.5) and confirms it, so self holds an accepted, confirmed copy
    that has ended, which never expires, and every later honest re-add of self for an epoch below its root is
    rejected. Only a forged copy that stays a request goes away, after 4 eras (§7.3). The members then start a new
    conversation. Keeping such a re-add with the second-copy warning instead would not end this: a forged J below an
    honest ended copy's root would then be kept live, accepted and confirmed in the same way, and reject every later
    honest re-add, which comes above its root, for good.

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

### 13.4 Web Push (optional)

Notifications add one observer (N, §0.2) and the only data the server stores that is not public (§0.1, §9.8). The
user-facing rules are fixed: off by default, per device and never synced; pushes that carry no content, whose
notifications show the same fixed text unless the user of the device chooses a preview that the device decrypts itself
(§11.13); invites, requests and reactions never ring, and neither does a conversation that the user has not accepted (§11.13),
with one exception: a contact that the first release recorded when a third member's row accepted a request counts
(§7.3), so that conversation, and the later ones that user starts, ring although the user never accepted them.

- **Stored.** Per endpoint: the endpoint and its subscription keys, sealed under `PUSH_KEY`; keyed hashes of its bells
  (`tk`); and the day of its last registration. Nothing about a ring is stored: which endpoints a message reached lives
  in PushDO's memory only, for at most a few minutes (§9.8). Bells are PRF outputs under keys that only members hold
  (§4.2), and their stored hashes are keyed under `PUSH_KEY`, so the stored data links no conversation or account to
  another, except that the devices of one account hold the same bells, and the number of an endpoint's bells tells about
  how many conversations it is notified for. The platform keeps a point-in-time history of this storage for 30 days, so
  a registration, its changes and its deletion stay recoverable from that history for up to 30 days. PushDO writes a
  change only after the UTC day in which it was made has ended (§9.8), so the history shows, per day, which endpoints
  were registered, which changed their bell sets and which were deleted, and nothing finer than a day. That still tells
  something: an epoch change makes the open devices of every member replace one bell, a creation, an accepted request, a
  leave or an ended copy adds or removes one, and one ring can get several stale endpoints of members of one
  conversation deleted, so on a day with few changes, endpoints whose sets changed, or that were deleted, that day may
  be co-members. The day's changes themselves live in PushDO's memory until then.
- **O** (live, not stored) sees, at each `push/sub`, an IP with an endpoint and its bells, and at each ring the
  writer's IP, the row, the other lanes' bells and every endpoint registered under them, devices that are offline
  included. With the row's topic, which the put carries, that links each such device to the conversation. Topics
  already give O the social graph of the sockets that are open (§13.2 item 1); endpoints add devices that are closed,
  under identifiers that stay the same across IP addresses. A put that a ring follows from the same IP is a TEXT or an
  IMAGE, so O can tell those from the rows that never ring (reactions, LEAVEs, WELCOMEs, claims and self rows), which
  their class alone does not tell from texts.
- **N** sees each push to its subscriptions: the time (the ring's, plus up to `PUSH_JITTER` and then up to
  `PUSH_TICK`, at most once per `PUSH_WINDOW` except across a restart of PushDO) and the size, which is the same for
  every push. Pushes to the devices of one conversation follow the same rings, so N can guess from their times which
  of its subscriptions share a conversation; the jitter only blurs this. The bells in a push are encrypted to the
  device, and do not change its size.
- **M** can ring the bells of its conversations with any fresh row (one ring per row and set of bells), which makes the
  other members' devices show the notification at most once per `PUSH_WINDOW` (a restart of PushDO aside). It can
  register its own endpoints under their bells: a bell's 8 places go to the endpoints that take them first (§9.8), so M
  can keep a member's devices from registering under that bell, and so from that conversation's notifications, for as
  long as M holds the places, and can take the new bells' places after each epoch change; and by registering its own
  endpoints and ringing them it learns how many places other devices hold, and so whether that member has
  notifications on. The places also give it a time: after an epoch change, which any member can cause, M can hold all
  but one place of a member's new bell and probe the free place every few minutes (register an endpoint there, ring
  it, delete it); the first probe left out dates, to within the probes' interval, when the member's first device
  registered that bell, that is, when it was first open after the change. None of this lets M read anything new. A
  member removed at an epoch change still knows that epoch's bells, and senders keep ringing the old bell of each
  member silent in the new epoch (§11.13), so the removed member can register under or ring those bells for as long as
  any such member stays silent, at most until the epoch changes again. It then learns when messages are sent in the
  new epoch and, since a sender never rings its own bell, which of the silent members sends each and when each of them
  first posts there; not what is sent.
- **Previews** (§11.13) are a choice of each device's user; they add nothing to a push and nothing to what the server
  stores. With `name` the device makes no request: the bells in the push and its cache name the conversation. With
  `message`, every push makes the device read the new rows of the conversations it names, wherever the device is and
  also while the app is closed: O learns at each such push the device's IP address, that it is on, and when the push
  arrived, which links the endpoint to that address; the labels it reads belong to conversations that the ring
  already linked to the endpoint. A member can cause such reads by ringing, and O by sending a push whose bells it
  chooses; O cannot make a preview show text that no member signed, but it can make a device show the name of any of
  its conversations. What a preview shows passes to the operating system: the lock screen, as its settings say; the
  notification history, which may keep it after the messages, the app or its data are deleted, and from which
  forensic tools have recovered messages of other messengers; and paired devices. A device's notification history
  holds the times of its notifications and what they showed. The device keeps the names and handles of its
  conversations, and with `message` the keys of their current epochs, in the notification cache, sealed under a device
  key beside the kept session.
- **Others.** A third party who reads a fresh row's `(E, label)` in the public feed knows no bell, so its rings reach
  no device, and the dedup is keyed by the row and the bells together, so they never suppress the writer's ring
  (§9.8). Anyone can fill PushDO's endpoint cap with registrations, or its cap of registrations changed in a day, or
  keep more pushes due than the one PushDO sends (§0.4).
- **Not affected.** The confidentiality of content (§0.3 item 1) apart from what previews show, the public data and what P learns (§0.3 item 2), and
  every other guarantee of §0.3. A deployment whose push is off (not configured, or configured invalidly, §9.8)
  behaves as if this section did not exist, apart from the registrations that PushDO may still hold from before, until
  they expire.

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
- Web Push beyond one PushDO (§9.8): bells sharded by prefix over several PushDOs, with the coalescing window kept
  per endpoint by one shard that owns it; bells chosen by their owner (a secret whose hash the members learn through a
  new record per epoch), so that members can no longer register under others' bells; unread badges;
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

## Appendix A. Changes from v1

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
| Old-epoch acceptance | claim chain by seq | stored `t` against each later claim's `t`, with `rm` naming who is dropped; cuts only for the claim's own Δ batch; a removed member's view of an epoch ends at the claim that removed it, for every sender |
| Creation privacy | decoy kind-4 row + shuffled invites, `[4, 3×N]` | an SGB2 bundle + a class-1 self row + the same wait + a class-1 decoy at a random label + J's + a class-1 self row |
| Multi-device | own invite per epoch; counters by log scan | self lane (records + snapshots + trusted HEADS positions), CAS on shared counters, CONFLICT returns the occupant, resumable J delivery |
| Re-add after a removal | the skip rule: the removed copy continues at the re-add's epoch | a separate copy, rooted at the re-add's descriptor, as a first contact; the removed copy has ended and keeps its history (§6.6 step 3, §6.7 step 6, §13.2 item 16) |
| Reactions | none | REACTION rows (type 3) on the sender's lane, bound to the target row's label and body; per member and emoji the latest row decides, at most 8 emoji per member and message; no unread count, no `lastTs`, no line (§11.12) |
| Notifications | none | optional Web Push: devices register bells derived from the epoch key, a sender rings the other lanes' bells after a text or image, and one PushDO sends a contentless push, coalesced per device; it stores no uid, conversation or IP; a device may show a preview that it decrypts itself (§9.8, §10.10, §11.13, §13.4) |
| Integrity | client-verified global chain (fatal on gaps); `head` in messages; local checkpoint | signed checkpoint chain (local persistence, range verification), `ck` in messages, `prevh`, immutability, receipts, public feed for auditors |
| Abuse | PoW `register/wrap/append/blob`; RL write/blob/read | PoW `register/wrap/put/inbox/blob` (and `push`); RL write/inbox/blob/read (and ring) |
| Blobs | `/api/blob`; D1 ledger (day precision, private) | `/api/v2/blob` + `meta`; BlobRegDO create-only with Δ-precise `t_reg`, readable by id only; its head enters checkpoints hourly |
| Time | `ts` = server ms floored to the second, in the chain | era (week) + `t = tpub` (Δ seconds) |
| AK rotation | not supported | not supported (deferred) |

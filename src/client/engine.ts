// The segv.sh client engine: unlocks the account key with a passkey (PRF) or recovery code,
// downloads + verifies the public log, finds the rows addressed to this account, and turns them
// into conversations. Implements docs/PROTOCOL.md. Browser only — import it dynamically.
import * as P from "~/lib/proto";
import * as api from "./api";
import type { WireRow } from "./api";
import { makeScanner, type Scanner } from "./dh";
import { prepareImage } from "./image";
import { clearSession, loadSession, saveSession } from "./session";
import type {
  ConversationView,
  Engine,
  EngineState,
  ImageRef,
  MemberView,
  MessageView,
} from "./types";
import {
  createPasskey,
  forgetCredential,
  prfCapability,
  prfForCredential,
  signInWithPasskey,
} from "./webauthn";

/** Upcoming counters watched per (conversation, epoch, member). Grows as members actually send. */
const WINDOW = 8;
const MAX_TEXT_BYTES = 12_000;
const SEND_ATTEMPTS = 8;
const VIEW_MESSAGES = 500; // newest messages per conversation handed to the UI
const CHECKPOINT_KEY = "segv.checkpoint";
const LAST_EPOCH = 0xffffffff; // can have no successor, so never accepted

class UserError extends Error {}
/** Someone else changed the conversation's membership first (409 on the claim slot). */
class ConflictError extends UserError {}

interface Account {
  uid: Uint8Array;
  uidB: string;
  AK: Uint8Array;
  id: P.Identity;
  handle: string;
  scan: Scanner;
}

interface UserRec extends P.User {
  seq: number;
  fp?: string;
}

/** A claim that decrypted, parsed, chains to its epoch and carries a valid committer signature. */
interface Claim {
  seq: number;
  dText: string;
  d: P.Descriptor;
  dsig: Uint8Array;
}

interface Epoch {
  e: number;
  EK: Uint8Array;
  keys: P.EpochKeys;
  dText: string;
  d: P.Descriptor;
  members: string[];
  myIndex: number;
  maxN: number[]; // per member index: highest counter whose slot is used (-1 = none)
  seen: Set<number>[];
  registered: number[]; // per member index: tags are registered for every unseen n < registered[i]
  claim: Claim | null; // the valid claim occupying this epoch's slot (= the next epoch)
  frozen: boolean; // the slot was burned by an invalid row: membership can never change again
  left: Set<string>;
}

interface Conv {
  /** Local key (view id). Normally the protocol conversation id; `~n` is appended to conflicting copies. */
  key: string;
  /** Protocol conversation id (b64u of `conv`). */
  id: string;
  /** Who added us (the committer of the first epoch we accepted). */
  rootBy: string;
  /** Someone other than `rootBy` has posted a valid message or claim here (or we created it). A newcomer
   *  cannot verify the history before they joined; corroboration by another member is the best signal. */
  confirmed: boolean;
  conv: Uint8Array;
  epochs: Map<number, Epoch>;
  current: number;
  messages: MessageView[];
  unread: number;
  lastTs: number;
  removed: boolean;
  left: boolean;
}

type TagTarget =
  | { type: "msg"; c: Conv; ep: Epoch; i: number; n: number }
  | { type: "claim"; c: Conv; ep: Epoch };

const emptyState = (): EngineState => ({
  phase: "boot",
  progress: "",
  error: "",
  me: null,
  conversations: [],
  head: { seq: 0, h: P.b64u(P.ZERO32) },
  connected: false,
  syncing: false,
  warnings: [],
  prfSupported: null,
});

function message(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/** Fisher–Yates with a CSPRNG (bias of 2^32 mod n is negligible for n <= 41). */
function shuffle<T>(xs: T[]): T[] {
  const out = xs.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const r = new DataView(P.random(4).buffer).getUint32(0) % (i + 1);
    [out[i], out[r]] = [out[r], out[i]];
  }
  return out;
}

export class SegvEngine implements Engine {
  private state: EngineState = emptyState();
  private listeners = new Set<(s: EngineState) => void>();
  private emitTimer: ReturnType<typeof setTimeout> | null = null;

  private account: Account | null = null;
  private directory = new Map<string, UserRec>();
  private byHandle = new Map<string, string>();
  private convs = new Map<string, Conv>(); // by Conv.key
  private byConv = new Map<string, Conv[]>(); // protocol conversation id -> its copies
  private tags = new Map<string, TagTarget>();
  private head = { seq: 0, h: P.ZERO32 as Uint8Array };
  private hashes = new Map<number, string>();
  private feed: { close(): void } | null = null;
  private poll: ReturnType<typeof setInterval> | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  private live = false; // initial sync finished: new rows count as unread
  private generation = 0; // bumped on logout so stale async work stops
  private pending = new Map<string, string>(); // tag b64u -> local echo key
  private sendChains = new Map<string, Promise<unknown>>();
  private imageCache = new Map<string, Promise<string>>(); // key: `${id}.${k}`
  private localCounter = 0;
  private fatal = false;
  private critical: string[] = []; // security warnings: sticky, never evicted
  private noise = new Map<string, number>(); // other warnings, deduplicated with a count
  private logTags = new Set<string>(); // tag of every kind-3/4 row applied so far (UNIQUE in the log)
  private openClaims: { c: Conv; ep: Epoch }[] = []; // valid claims that list us, until our invite arrives

  // ───────────── public API ─────────────

  getState(): EngineState {
    return this.state;
  }

  subscribe(fn: (s: EngineState) => void): () => void {
    this.listeners.add(fn);
    fn(this.state);
    return () => this.listeners.delete(fn);
  }

  async boot(): Promise<void> {
    this.patch({ prfSupported: await prfCapability() });
    const s = await loadSession();
    if (!s) return this.patch({ phase: "signed-out" });
    try {
      await this.unlock(s.AK, P.fromB64u(s.uid), "");
    } catch (e) {
      await clearSession();
      this.patch({ phase: "signed-out", error: `could not restore session: ${message(e)}` });
    }
  }

  async register(handleIn: string, remember = false): Promise<{ recoveryCode: string }> {
    return this.authFlow(async () => {
      const handle = handleIn.trim().toLowerCase().replace(/^@/, "");
      if (!P.HANDLE_RE.test(handle))
        throw new UserError("handle must be 3–20 characters: a–z, 0–9, _");
      this.progress("checking handle…");
      if (await api.getUser(handle)) throw new UserError(`@${handle} is taken`);
      const AK = P.random(32);
      const uid = P.random(16);
      const id = P.deriveIdentity(AK);
      const { bundle, sig } = P.makeBundle(uid, handle, id, Date.now());

      this.progress("creating passkey…");
      const { credId, prf: prf0 } = await createPasskey(uid, handle);
      let prf = prf0;
      if (!prf) {
        this.progress("confirm the passkey once more to derive your keys…");
        prf = await prfForCredential(credId);
      }
      if (!prf) {
        await forgetCredential(credId);
        throw new UserError(
          "this passkey provider does not support the WebAuthn PRF extension, so it cannot hold encryption keys. " +
            "try iCloud Keychain, Google Password Manager, Windows Hello (Windows 11 24H2+) or a FIDO2 security key.",
        );
      }
      const now = Date.now();
      const code = P.newRecoveryCode();
      const rk = P.recoveryKem(code);
      const wraps = [
        P.makeWrap(uid, "passkey", credId, P.credKem(prf, credId), AK, id, now),
        P.makeWrap(uid, "recovery", rk.id, rk, AK, id, now),
      ];
      try {
        await api.register({ bundle, sig, wraps }, (m) => this.progress(m));
      } catch (e) {
        // A definitive rejection: the account does not exist, so the new passkey is useless.
        if (e instanceof api.ApiError && e.status >= 400 && e.status < 500) {
          await forgetCredential(credId);
          if (e.status === 409) throw new UserError(`@${handle} is taken`);
          throw e;
        }
        // Network error / 5xx: the server may have committed before the response was lost.
        const landed = await api.getUser(handle).catch(() => null);
        if (!landed || landed.bundle !== bundle) {
          if (landed) await forgetCredential(credId);
          throw e;
        }
      }
      await this.unlock(AK, uid, handle);
      if (remember) await this.remember(uid, AK);
      return { recoveryCode: P.formatRecoveryCode(code) };
    });
  }

  async login(remember: boolean): Promise<void> {
    return this.authFlow(async () => {
      this.progress("waiting for passkey…");
      const { credId, uid, prf } = await signInWithPasskey();
      if (!prf)
        throw new UserError(
          "this passkey did not return a PRF secret (unsupported provider or browser). use your recovery code instead.",
        );
      this.progress("unlocking…");
      const found = this.unwrapFrom(
        await api.getWraps(credId, uid),
        "passkey",
        credId,
        P.credKem(prf, credId),
        uid,
      );
      if (!found) throw new UserError("no account key for this passkey on this server");
      await this.unlock(found.AK, found.uid, "");
      if (remember) await this.remember(found.uid, found.AK);
    });
  }

  async loginWithRecovery(codeText: string, remember: boolean): Promise<void> {
    return this.authFlow(async () => {
      let code: Uint8Array;
      try {
        code = P.parseRecoveryCode(codeText);
      } catch (e) {
        throw new UserError(message(e));
      }
      this.progress("unlocking…");
      const rk = P.recoveryKem(code);
      const found = this.unwrapFrom(await api.getWraps(rk.id, null), "recovery", rk.id, rk, null);
      if (!found) throw new UserError("recovery code not recognised");
      await this.unlock(found.AK, found.uid, "");
      if (remember) await this.remember(found.uid, found.AK);
    });
  }

  async addPasskey(): Promise<void> {
    const acc = this.requireAccount();
    await this.action(async () => {
      this.progress("creating passkey…");
      const { credId, prf: prf0 } = await createPasskey(acc.uid, acc.handle || "segv");
      let prf = prf0;
      if (!prf) {
        this.progress("confirm the new passkey once more…");
        prf = await prfForCredential(credId);
      }
      if (!prf) {
        await forgetCredential(credId);
        throw new UserError("this passkey provider does not support the WebAuthn PRF extension");
      }
      this.assertSession(acc);
      const wrap = P.makeWrap(
        acc.uid,
        "passkey",
        credId,
        P.credKem(prf, credId),
        acc.AK,
        acc.id,
        Date.now(),
      );
      await api.postWrap(wrap, (m) => this.progress(m));
    });
  }

  async logout(): Promise<void> {
    this.generation++;
    this.feed?.close();
    this.feed = null;
    if (this.poll) clearInterval(this.poll);
    this.poll = null;
    await clearSession();
    for (const p of this.imageCache.values()) p.then((u) => URL.revokeObjectURL(u)).catch(() => {});
    this.resetData();
    this.account = null;
    this.fatal = false;
    this.state = { ...emptyState(), phase: "signed-out", prfSupported: this.state.prfSupported };
    this.emitNow();
  }

  async createConversation(handles: string[], name?: string): Promise<string> {
    const acc = this.requireAccount();
    return this.action(async () => {
      const others = await this.resolveHandles(handles);
      this.assertSession(acc);
      const members = [acc.uidB, ...others.filter((u) => u !== acc.uidB)];
      if (members.length < 2) throw new UserError("add at least one other person");
      if (members.length > P.MAX_MEMBERS) throw new UserError(`at most ${P.MAX_MEMBERS} members`);
      const cleanName = this.cleanName(name);
      const conv = P.random(16);
      const EK = P.random(32);
      const keys = P.epochKeys(EK, conv, 0);
      const dText = P.makeDescriptor({
        conv: P.b64u(conv),
        e: 0,
        members,
        prev: null,
        by: acc.uidB,
        ts: Date.now(),
        ...(cleanName ? { name: cleanName } : {}),
      });
      const dsig = P.signDescriptor(dText, keys.kc, acc.id.sigSk);
      // A decoy kind-4 row (random tag, random body) gives creations the same [4, 3×N] shape as
      // membership changes, so observers cannot tell a new conversation from a changed one.
      // C = enc(D, dsig, csig); the next descriptor also carries a 43-character prev instead of null.
      const claimLen = 4 + P.utf8(dText).length + 45 + 4 + 64 + 4 + 64;
      const cls = P.MSG_CLASSES.findIndex((x) => x >= claimLen + 1);
      const decoy: P.Row = {
        kind: 4,
        tag: P.random(16),
        body: P.random(P.MSG_BODY_LENS[cls < 0 ? 0 : cls]),
      };
      await api.append([decoy, ...this.invites(members, dText, EK, dsig)], (m) => this.progress(m));
      await this.syncNow();
      return P.b64u(conv);
    });
  }

  async sendText(convId: string, text: string): Promise<void> {
    this.requireAccount();
    const body = text.replace(/\s+$/, "");
    if (!body.trim()) return;
    if (P.utf8(body).length > MAX_TEXT_BYTES)
      return this.failNow(new UserError("message is too long"));
    await this.sendPayload(convId, { t: "text", text: body });
  }

  async sendImage(convId: string, file: File): Promise<void> {
    const acc = this.requireAccount();
    const gen = this.generation;
    const c = this.conv(convId);
    const echo = this.addEcho(c, "image", "[image]");
    try {
      this.progress("preparing image…");
      const img = await prepareImage(file);
      const { blob, id, key } = P.encryptBlob(img.bytes);
      this.assertSession(acc, gen);
      await api.putBlob(id, blob, (m) => this.progress(m));
      this.assertSession(acc, gen);
      const k = P.b64u(key);
      this.imageCache.set(
        `${id}.${k}`,
        Promise.resolve(URL.createObjectURL(new Blob([img.bytes as BlobPart], { type: img.mime }))),
      );
      await this.sendPayload(
        convId,
        { t: "image", img: { id, k, mime: img.mime, w: img.w, h: img.h } },
        echo,
      );
    } catch (e) {
      if (this.account === acc && this.generation === gen) {
        this.markEcho(c, echo, "failed");
        this.failNow(e);
      }
    } finally {
      this.progress("");
    }
  }

  async addMembers(convId: string, handles: string[]): Promise<void> {
    const acc = this.requireAccount();
    const gen = this.generation;
    const c = this.conv(convId);
    await this.action(async () => {
      let ep = this.sendableEpoch(c);
      const wanted = await this.resolveHandles(handles);
      this.assertSession(acc, gen);
      ep = this.sendableEpoch(c);
      // A leaver comes back only through an explicit add on top of an epoch without them (otherwise their
      // pending leave would carry over into the new epoch and rotate them straight out again).
      if (wanted.some((u) => ep.left.has(u) && ep.members.includes(u))) {
        await this.changeMembers(
          c,
          ep.members.filter((u) => !ep.left.has(u)),
          acc,
          gen,
        );
        ep = this.sendableEpoch(c);
      }
      const stay = ep.members.filter((u) => !ep.left.has(u));
      const add = wanted.filter((u) => !stay.includes(u));
      if (add.length === 0) throw new UserError("nobody new to add");
      await this.changeMembers(c, [...stay, ...add], acc, gen);
    });
  }

  async removeMember(convId: string, uid: string): Promise<void> {
    const acc = this.requireAccount();
    const gen = this.generation;
    const c = this.conv(convId);
    await this.action(async () => {
      if (uid === acc.uidB) throw new UserError("use “leave” to leave a conversation");
      const ep = this.sendableEpoch(c);
      if (!ep.members.includes(uid)) throw new UserError("not a member");
      await this.changeMembers(
        c,
        ep.members.filter((u) => u !== uid && !ep.left.has(u)),
        acc,
        gen,
      );
    });
  }

  async leave(convId: string): Promise<void> {
    this.requireAccount();
    await this.sendPayload(convId, { t: "leave" });
  }

  loadImage(img: ImageRef): Promise<string> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(img.id) || !/^[A-Za-z0-9_-]{43}$/.test(img.k))
      return Promise.reject(new Error("bad image reference"));
    // Keyed by id AND key: a message that names someone else's blob with a wrong key must not get
    // the plaintext this session already decrypted for another conversation.
    const cacheKey = `${img.id}.${img.k}`;
    let p = this.imageCache.get(cacheKey);
    if (!p) {
      p = (async () => {
        const blob = await api.getBlob(img.id);
        const data = P.decryptBlob(blob, img.id, P.fromB64u(img.k));
        return URL.createObjectURL(new Blob([data as BlobPart], { type: img.mime }));
      })();
      this.imageCache.set(cacheKey, p);
      p.catch(() => this.imageCache.delete(cacheKey));
    }
    return p;
  }

  markRead(convId: string): void {
    const c = this.convs.get(convId);
    if (c && c.unread !== 0) {
      c.unread = 0;
      this.scheduleEmit();
    }
  }

  clearError(): void {
    this.patch({ error: "" });
  }

  // ───────────── auth helpers ─────────────

  private async authFlow<T>(fn: () => Promise<T>): Promise<T> {
    if (this.account) throw new UserError("already signed in");
    this.patch({ phase: "working", error: "", progress: "" });
    try {
      return await fn();
    } catch (e) {
      if (!this.account) this.patch({ phase: "signed-out" });
      this.patch({ error: message(e) });
      throw e;
    } finally {
      this.progress("");
    }
  }

  /**
   * Opens the wrap for `id` with the unlock key. Wraps are bound to the unlock secret (`key.auth`), so a
   * wrap filed by someone else under our public id cannot open. If wraps of more than one account open,
   * something is badly wrong: refuse instead of guessing.
   */
  private unwrapFrom(
    wraps: { record: string; sig: string }[],
    kind: P.WrapKind,
    id: Uint8Array,
    key: P.UnlockKey,
    expectUid: Uint8Array | null,
  ): { AK: Uint8Array; uid: Uint8Array } | null {
    let found: { AK: Uint8Array; uid: Uint8Array } | null = null;
    for (const w of wraps) {
      try {
        const rec = P.parseWrap(w.record, w.sig);
        if (rec.kind !== kind || !P.equalBytes(rec.id, id)) continue;
        if (expectUid && rec.uid !== P.b64u(expectUid)) continue;
        const AK = P.openWrap(rec, key);
        if (!P.verify(P.fromB64u(w.sig), P.wrapSigMsg(w.record), P.deriveIdentity(AK).sigPk))
          continue;
        const uid = P.fromB64u(rec.uid);
        if (found && !P.equalBytes(found.uid, uid))
          throw new UserError("this key opens more than one account; refusing to guess");
        found ??= { AK, uid };
      } catch (e) {
        if (e instanceof UserError) throw e;
        /* not ours / corrupted: try the next one */
      }
    }
    return found;
  }

  private async unlock(AK: Uint8Array, uid: Uint8Array, handle: string): Promise<void> {
    const id = P.deriveIdentity(AK);
    const uidB = P.b64u(uid);
    this.resetData();
    this.account = { uid, uidB, AK, id, handle, scan: await makeScanner(id.scanSk) };
    this.patch({
      phase: "ready",
      me: {
        uid: uidB,
        handle,
        fingerprint: P.fingerprint({
          uid: uidB,
          sigPk: id.sigPk,
          kemPk: id.kemPk,
          scanPk: id.scanPk,
        }),
      },
      warnings: [],
    });
    void this.startSync(this.generation);
  }

  /** "Remember this device" is a convenience: failing to store the session must not fail the sign-in. */
  private async remember(uid: Uint8Array, AK: Uint8Array) {
    try {
      await saveSession(P.b64u(uid), AK);
    } catch (e) {
      this.patch({
        error: `this browser could not remember the session (${message(e)}); you will need to sign in again next time`,
      });
    }
  }

  private resetData() {
    this.directory.clear();
    this.byHandle.clear();
    this.convs.clear();
    this.byConv.clear();
    this.tags.clear();
    this.head = { seq: 0, h: P.ZERO32 };
    this.hashes.clear();
    this.pending.clear();
    this.sendChains.clear();
    this.imageCache.clear();
    this.critical = [];
    this.noise.clear();
    this.logTags.clear();
    this.openClaims = [];
    this.live = false;
    this.queue = Promise.resolve();
  }

  /** Throws if the user signed out (or another account signed in) since `acc` was captured. */
  private assertSession(acc: Account, gen = this.generation) {
    if (this.account !== acc || this.generation !== gen) throw new UserError("signed out");
  }

  // ───────────── sync ─────────────

  private async startSync(gen: number) {
    this.patch({ syncing: true });
    this.loadCheckpoint();
    this.feed?.close();
    this.feed = api.openFeed({
      onRows: (rows) => {
        if (gen === this.generation)
          void this.enqueue(() => this.ingest(rows, gen)).catch(() => {});
      },
      onState: (connected) => {
        if (gen !== this.generation) return;
        this.patch({ connected });
        // After a reconnect, catch up on anything we missed while offline.
        if (connected && this.live) void this.syncNow().catch(() => {});
      },
    });
    // Fallback when the live feed is down: poll the log.
    if (this.poll) clearInterval(this.poll);
    this.poll = setInterval(() => {
      if (gen !== this.generation || this.fatal) return;
      if (this.live && !this.state.connected) void this.syncNow().catch(() => {});
    }, 10_000);
    for (let attempt = 0; ; attempt++) {
      try {
        await this.enqueue(() => this.backfill(gen));
        break;
      } catch (e) {
        if (gen !== this.generation || this.fatal) return;
        // Never judge the account or the checkpoint on a partial log: retry with backoff.
        this.patch({ error: `sync failed: ${message(e)} (retrying)` });
        await new Promise((r) => setTimeout(r, Math.min(30_000, 500 * 2 ** attempt)));
      }
    }
    if (gen !== this.generation || this.fatal) return;
    if (this.state.error.startsWith("sync failed:")) this.patch({ error: "" });
    this.checkCheckpointLength();
    this.live = true;
    this.patch({ syncing: false });
    const acc = this.account;
    if (acc && !this.directory.has(acc.uidB))
      this.die("your account was not found in the log of this server");
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn);
    this.queue = p.catch(() => {});
    return p;
  }

  /** Fetches and applies every row after the current head. */
  private syncNow(): Promise<void> {
    const gen = this.generation;
    return this.enqueue(() => this.backfill(gen));
  }

  /** Pages through the log until the server's head. Pages may be short (byte budget): never treat a short page as the end. */
  private async backfill(gen: number) {
    for (;;) {
      if (gen !== this.generation || this.fatal) return;
      const { rows, head } = await api.getLog(this.head.seq, 1000);
      if (gen !== this.generation || this.fatal) return;
      if (rows.length === 0) return;
      await this.applyRows(rows, gen, true);
      if (this.fatal || !Number.isSafeInteger(head?.seq) || this.head.seq >= head.seq) {
        this.expireClaims(true); // at the head: every batch we applied is complete
        return;
      }
    }
  }

  private async ingest(rows: WireRow[], gen: number) {
    if (gen !== this.generation || this.fatal || rows.length === 0) return;
    const sorted = [...rows].sort((a, b) => a.seq - b.seq);
    if (sorted[0].seq > this.head.seq + 1) {
      await this.backfill(gen); // gap: fetch what we missed (also covers the rows in this frame)
      return;
    }
    await this.applyRows(sorted, gen, false);
    this.expireClaims(true); // a feed frame carries whole batches
  }

  /**
   * A claim and every invite of its epoch are one atomic batch (<= 40 rows). Once that batch is complete and our
   * invite is not in it, the committer never delivered the keys: membership is frozen and messaging continues.
   */
  private expireClaims(batchComplete: boolean) {
    if (this.openClaims.length === 0) return;
    this.openClaims = this.openClaims.filter(({ c, ep }) => {
      if (!ep.claim || c.epochs.has(ep.e + 1)) return false;
      if (!batchComplete && this.head.seq < ep.claim.seq + 39) return true;
      ep.claim = null;
      ep.frozen = true;
      if (ep.e === c.current)
        this.warn(
          "a membership change was never delivered to you; the members of this conversation can no longer change",
          true,
        );
      return false;
    });
  }

  private async applyRows(rows: WireRow[], gen: number, strict: boolean) {
    for (const w of rows) {
      if (gen !== this.generation || this.fatal) return;
      if (w.seq <= this.head.seq) continue;
      if (w.seq !== this.head.seq + 1) {
        if (strict)
          this.die(
            `the server skipped log entries (expected #${this.head.seq + 1}, got #${w.seq})`,
          );
        return;
      }
      let tag: Uint8Array;
      let body: Uint8Array;
      try {
        tag = P.fromB64u(w.tag);
        body = P.fromB64u(w.body);
        if (!Number.isSafeInteger(w.ts) || !Number.isInteger(w.kind) || w.kind < 0 || w.kind > 255)
          throw new Error("bad row");
      } catch {
        this.die(`malformed log entry #${w.seq}`);
        return;
      }
      const h = P.rowHash(this.head.h, w.seq, w.kind, tag, body, w.ts);
      if (P.b64u(h) !== w.h) {
        this.die(
          `log integrity check failed at entry #${w.seq}: the server's history does not hash-chain`,
        );
        return;
      }
      this.head = { seq: w.seq, h };
      this.hashes.set(w.seq, w.h);
      this.checkCheckpoint(w.seq, w.h);
      try {
        await this.processRow(w.seq, w.kind, tag, body, w.ts);
      } catch (e) {
        console.warn(`segv: row #${w.seq} skipped:`, e);
      }
      this.expireClaims(false);
    }
    this.saveCheckpoint();
    this.state = { ...this.state, head: { seq: this.head.seq, h: P.b64u(this.head.h) } };
    this.scheduleEmit();
  }

  // The last log position this device verified (public data). A different hash at that position, or a
  // shorter log, means the server rewrote or rolled back history. Once detected, the old checkpoint is
  // kept so every later session warns again.
  private checkpoint: { seq: number; h: string } | null = null;
  private checkpointBroken = false;

  private loadCheckpoint() {
    this.checkpointBroken = false;
    try {
      const cp = JSON.parse(localStorage.getItem(CHECKPOINT_KEY) ?? "null") as {
        seq?: unknown;
        h?: unknown;
      } | null;
      this.checkpoint =
        cp && Number.isSafeInteger(cp.seq) && typeof cp.h === "string"
          ? { seq: cp.seq as number, h: cp.h }
          : null;
    } catch {
      this.checkpoint = null; // storage unavailable
    }
  }

  private checkCheckpoint(seq: number, h: string) {
    const cp = this.checkpoint;
    if (cp && cp.seq === seq && cp.h !== h && !this.checkpointBroken) {
      this.checkpointBroken = true;
      this.warn(
        `the server's log differs from what this device verified before at entry #${seq}: history was rewritten`,
        true,
      );
    }
  }

  private checkCheckpointLength() {
    const cp = this.checkpoint;
    if (cp && cp.seq > this.head.seq && !this.checkpointBroken) {
      this.checkpointBroken = true;
      this.warn(
        `the server's log is shorter than what this device verified before (#${cp.seq} > #${this.head.seq}): it was rolled back`,
        true,
      );
    }
  }

  private saveCheckpoint() {
    const cp = this.checkpoint;
    if (this.checkpointBroken || (cp && this.head.seq <= cp.seq)) return;
    this.checkpoint = { seq: this.head.seq, h: P.b64u(this.head.h) };
    try {
      localStorage.setItem(CHECKPOINT_KEY, JSON.stringify(this.checkpoint));
    } catch {
      /* storage unavailable */
    }
  }

  // ───────────── row processing ─────────────

  private async processRow(
    seq: number,
    kind: number,
    tag: Uint8Array,
    body: Uint8Array,
    ts: number,
  ) {
    if (kind === 1) return this.userRow(seq, tag, body);
    const tagB = P.b64u(tag);
    if (kind === 3 || kind === 4) this.logTags.add(tagB);
    if (!this.account) return;
    const t = this.tags.get(tagB);
    if (t) {
      // Any row on a slot we watch consumes it, whatever its kind: a squatted counter must still
      // advance the sender's window, and a squatted claim slot freezes membership.
      if (t.type === "claim") return this.claimRow(t.c, t.ep, seq, kind, tag, body, ts);
      return this.msgRow(t.c, t.ep, t.i, t.n, seq, kind, tag, body, ts);
    }
    if (kind === 3) return this.inviteRow(seq, tag, body, ts);
  }

  private userRow(seq: number, tag: Uint8Array, body: Uint8Array) {
    const j = JSON.parse(P.fromUtf8(body)) as { bundle?: unknown; sig?: unknown };
    if (typeof j.bundle !== "string" || typeof j.sig !== "string") throw new Error("bad user row");
    const u = P.verifyBundle(j.bundle, j.sig);
    if (!P.equalBytes(tag, P.userTag(P.fromB64u(u.uid)))) throw new Error("user row tag mismatch");
    if (this.directory.has(u.uid)) return;
    if (this.byHandle.has(u.handle)) {
      this.warn(`ignored a second registration of @${u.handle}`);
      return;
    }
    this.directory.set(u.uid, { ...u, seq });
    this.byHandle.set(u.handle, u.uid);
    const acc = this.account;
    if (acc && u.uid === acc.uidB) {
      if (
        !P.equalBytes(u.sigPk, acc.id.sigPk) ||
        !P.equalBytes(u.kemPk, acc.id.kemPk) ||
        !P.equalBytes(u.scanPk, acc.id.scanPk)
      ) {
        this.die("the public keys registered for your account do not match your passkey's keys");
        return;
      }
      acc.handle = u.handle;
      if (this.state.me) this.state = { ...this.state, me: { ...this.state.me, handle: u.handle } };
    }
  }

  private async inviteRow(seq: number, tag: Uint8Array, body: Uint8Array, ts: number) {
    const acc = this.account!;
    if (body.length < 32 || tag.length !== 16) return;
    const s = await acc.scan(body.subarray(0, 32));
    if (!s || this.account !== acc) return;
    const row = { tag, body };
    const vk = P.inviteViewKey(acc.id.scanSk, acc.id.scanPk, row, () => s);
    if (!vk) return;
    let o: { dText: string; EK: Uint8Array; dsig: Uint8Array };
    try {
      o = P.openInvite(acc.id.kemSk, vk, row);
    } catch {
      this.warn("ignored an undecryptable invite addressed to you");
      return;
    }
    this.acceptEpoch(o.dText, o.EK, o.dsig, seq, ts);
  }

  /** §3.3: decides whether a decrypted invite becomes an epoch of a conversation. */
  private acceptEpoch(dText: string, EK: Uint8Array, dsig: Uint8Array, seq: number, ts: number) {
    const acc = this.account!;
    let d: P.Descriptor;
    try {
      d = P.parseDescriptor(dText);
    } catch {
      this.warn("ignored a malformed conversation key");
      return;
    }
    if (d.e >= LAST_EPOCH)
      return this.warn("ignored a conversation key with an impossible epoch number");
    const convBytes = P.fromB64u(d.conv);
    const keys = P.epochKeys(EK, convBytes, d.e);
    const by = this.directory.get(d.by);
    if (!by || !P.verifyDescriptorSig(dText, keys.kc, dsig, by.sigPk))
      return this.warn("ignored a conversation key with an invalid signature");
    if (!d.members.includes(acc.uidB)) return;
    if (!d.members.every((m) => this.directory.has(m)))
      return this.warn("ignored a conversation with unknown members");

    const copies = this.byConv.get(d.conv) ?? [];
    if (copies.some((k) => k.epochs.get(d.e)?.dText === dText)) return; // duplicate invite

    // A conversation we already hold may only move forward along its claim chain; skipping ahead is
    // only legitimate when a valid, signed claim removed us and we are now added back (we cannot see the
    // epochs in between, so that one is accepted on its signature, like a first invite).
    let c: Conv | undefined;
    let prev: Epoch | undefined;
    for (const k of copies) {
      const cur = k.epochs.get(k.current)!;
      const chained =
        d.e === cur.e + 1 &&
        d.prev === P.b64u(P.H(P.utf8(cur.dText))) &&
        cur.members.includes(d.by) &&
        cur.claim !== null &&
        cur.claim.dText === dText &&
        P.equalBytes(cur.claim.dsig, dsig);
      if (chained) {
        c = k;
        prev = cur;
        break;
      }
      if (d.e > cur.e + 1 && cur.claim !== null && !cur.claim.d.members.includes(acc.uidB)) {
        c = k;
        break;
      }
    }
    if (!c && copies.length > 0) {
      // Does not fit any copy we hold. If one of them is corroborated by other members, this is junk.
      if (copies.some((k) => k.confirmed))
        return this.warn(
          "ignored a conversation key that does not match the conversation history",
          true,
        );
      // Otherwise we cannot tell which is genuine (e.g. a removed member planted a fake epoch before we were
      // really added): keep both, visibly marked, rather than silently trusting whichever came first.
      this.warn(
        `@${by.handle} sent you a second, different copy of a conversation you were added to; both are shown marked ⚠ — only one can be genuine`,
        true,
      );
    }
    // (No fitting copy: first contact, possibly as a member added at e > 0 — accepted on its signature.)

    if (!c) {
      const key = copies.length === 0 ? d.conv : `${d.conv}~${copies.length}`;
      c = {
        key,
        id: d.conv,
        rootBy: d.by,
        confirmed: d.by === acc.uidB,
        conv: convBytes,
        epochs: new Map(),
        current: -1,
        messages: [],
        unread: 0,
        lastTs: ts,
        removed: false,
        left: false,
      };
      this.convs.set(key, c);
      this.byConv.set(d.conv, [...copies, c]);
    }
    const n = d.members.length;
    const ep: Epoch = {
      e: d.e,
      EK,
      keys,
      dText,
      d,
      members: d.members,
      myIndex: d.members.indexOf(acc.uidB),
      maxN: Array(n).fill(-1),
      seen: Array.from({ length: n }, () => new Set<number>()),
      registered: Array(n).fill(0),
      claim: null,
      frozen: false,
      // Leaves that were not rotated out yet (e.g. a leave that landed after this epoch's claim) carry over.
      left: new Set(prev ? [...prev.left].filter((u) => d.members.includes(u)) : []),
    };
    c.epochs.set(d.e, ep);
    for (let i = 0; i < n; i++) this.registerTags(c, ep, i);
    const ct = P.b64u(P.claimTag(keys.rk));
    if (this.logTags.has(ct)) ep.frozen = true; // the claim slot was burned before we could watch it
    else this.tags.set(ct, { type: "claim", c, ep });
    c.current = d.e;
    c.removed = false;
    c.left = ep.left.has(acc.uidB);
    c.lastTs = Math.max(c.lastTs, ts);

    const who = (u: string) => (u === acc.uidB ? "you" : `@${this.handleOf(u)}`);
    if (d.e === 0) this.system(c, seq, ts, `${who(d.by)} started the conversation`);
    else if (prev) {
      const added = d.members.filter((u) => !prev.members.includes(u));
      const gone = prev.members.filter((u) => !d.members.includes(u));
      const left = gone.filter((u) => prev.left.has(u));
      const removed = gone.filter((u) => !prev.left.has(u));
      if (added.length) this.system(c, seq, ts, `${who(d.by)} added ${added.map(who).join(", ")}`);
      if (removed.length)
        this.system(c, seq, ts, `${who(d.by)} removed ${removed.map(who).join(", ")}`);
      if (left.length && !added.length && !removed.length)
        this.system(c, seq, ts, `keys rotated after ${left.map(who).join(", ")} left`);
      if (!gone.length && !added.length)
        this.system(c, seq, ts, `${who(d.by)} rotated the conversation keys`);
      if ((d.name ?? "") !== (prev.d.name ?? ""))
        this.system(
          c,
          seq,
          ts,
          d.name
            ? `${who(d.by)} renamed the conversation to “${d.name}”`
            : `${who(d.by)} removed the conversation name`,
        );
    } else this.system(c, seq, ts, `${who(d.by)} added you`);
    if (this.live && d.by !== acc.uidB) c.unread++;
  }

  private registerTags(c: Conv, ep: Epoch, i: number) {
    let n = ep.registered[i];
    for (; n < ep.maxN[i] + 1 + WINDOW; n++) {
      if (ep.seen[i].has(n)) continue;
      const t = P.b64u(P.msgTag(ep.keys.rk, i, n));
      if (this.logTags.has(t)) {
        // The slot was used before we watched it (e.g. squatted beyond the window): it is taken, slide past it.
        ep.seen[i].add(n);
        ep.maxN[i] = Math.max(ep.maxN[i], n);
        continue;
      }
      this.tags.set(t, { type: "msg", c, ep, i, n });
    }
    ep.registered[i] = Math.max(ep.registered[i], n);
  }

  /** A row on this epoch's claim slot. Only a valid, signed claim moves the conversation on. */
  private claimRow(
    c: Conv,
    ep: Epoch,
    seq: number,
    kind: number,
    tag: Uint8Array,
    body: Uint8Array,
    ts: number,
  ) {
    this.tags.delete(P.b64u(tag));
    if (ep.claim || ep.frozen) return;
    const acc = this.account!;
    let claim: Claim | null = null;
    if (kind === 4) {
      try {
        const o = P.openClaim(ep.keys.mk, { tag, body });
        const d = P.parseDescriptor(o.dText);
        const by = this.directory.get(d.by);
        if (
          d.conv === c.id &&
          d.e === ep.e + 1 &&
          d.prev === P.b64u(P.H(P.utf8(ep.dText))) &&
          ep.members.includes(d.by) &&
          by &&
          P.verifyClaimSig(tag, o.dText, o.dsig, o.csig, by.sigPk)
        )
          claim = { seq, dText: o.dText, d, dsig: o.dsig };
      } catch {
        /* invalid */
      }
    }
    if (!claim) {
      // The slot is burned (UNIQUE tags): membership can never change, but messaging goes on.
      ep.frozen = true;
      if (ep.e === c.current)
        this.warn(
          "a conversation received an invalid membership change; its members can no longer change",
        );
      return;
    }
    ep.claim = claim;
    if (claim.d.by !== c.rootBy) c.confirmed = true;
    if (claim.d.members.includes(acc.uidB)) this.openClaims.push({ c, ep });
    if (ep.e === c.current && !claim.d.members.includes(acc.uidB)) {
      c.removed = true;
      // A leaver already got "you left the conversation" from their leave row.
      if (!ep.left.has(acc.uidB))
        this.system(c, seq, ts, `@${this.handleOf(claim.d.by)} removed you`);
    }
  }

  /**
   * A sender may post into epoch `ep` at `seq` only while they are a member of the epoch that was current
   * at that point: walk the chain of claims that `seq` comes after.
   */
  private senderAllowed(c: Conv, ep: Epoch, seq: number, from: string): boolean {
    let k: Epoch | undefined = ep;
    while (k?.claim && seq > k.claim.seq) {
      if (!k.claim.d.members.includes(from)) return false;
      k = c.epochs.get(k.e + 1);
    }
    return true;
  }

  private msgRow(
    c: Conv,
    ep: Epoch,
    i: number,
    n: number,
    seq: number,
    kind: number,
    tag: Uint8Array,
    body: Uint8Array,
    ts: number,
  ) {
    const acc = this.account!;
    const tagB = P.b64u(tag);
    this.tags.delete(tagB);
    // The slot is used whatever the row turns out to be, so the counter advances past junk.
    ep.seen[i].add(n);
    if (n > ep.maxN[i]) {
      ep.maxN[i] = n;
      this.registerTags(c, ep, i);
    }
    if (kind !== 4) return this.warn("ignored a row squatting a message slot");
    let o: { text: string; payload: P.Payload; psig: Uint8Array };
    try {
      o = P.openMessage(ep.keys.mk, { tag, body });
    } catch {
      return this.warn("ignored an undecryptable message");
    }
    const p = o.payload;
    const from = ep.members[i];
    if (!P.validPayload(p) || p.conv !== c.id || p.e !== ep.e || p.from !== from || p.n !== n)
      return this.warn("ignored a malformed message");
    const sender = this.directory.get(from);
    if (!sender || !P.verifyMessageSig(tag, o.text, o.psig, sender.sigPk))
      return this.warn("ignored a message with an invalid signature", true);
    if (!this.senderAllowed(c, ep, seq, from)) return;
    if (from !== c.rootBy && from !== acc.uidB) c.confirmed = true;

    if (p.head.seq > 0 && p.head.seq < seq) {
      const known = this.hashes.get(p.head.seq);
      if (known && known !== p.head.h)
        this.warn(
          `split view: @${sender.handle} saw a different log than this device — the server may be lying to one of you`,
          true,
        );
    }
    const local = this.pending.get(tagB);
    if (local) {
      this.pending.delete(tagB);
      c.messages = c.messages.filter((m) => m.key !== local);
    }
    const mine = from === acc.uidB;
    c.lastTs = Math.max(c.lastTs, ts);
    if (p.t === "leave") {
      // Record the leave in this epoch and every later one that still lists the leaver.
      for (let k: Epoch | undefined = ep; k && k.members.includes(from); k = c.epochs.get(k.e + 1))
        k.left.add(from);
      if (mine && c.epochs.get(c.current)?.left.has(from)) c.left = true;
      this.system(c, seq, ts, mine ? "you left the conversation" : `@${sender.handle} left`);
      return;
    }
    c.messages.push({
      key: tagB,
      seq,
      from,
      fromHandle: sender.handle,
      mine,
      ts: p.ts,
      kind: p.t,
      ...(p.t === "text" ? { text: p.text } : {}),
      ...(p.t === "image" && p.img
        ? { image: { id: p.img.id, k: p.img.k, mime: p.img.mime, w: p.img.w, h: p.img.h } }
        : {}),
      status: "sent",
    });
    if (this.live && !mine) c.unread++;
  }

  private system(c: Conv, seq: number, ts: number, text: string) {
    c.messages.push({
      key: `sys:${seq}:${c.messages.length}`,
      seq,
      from: "",
      fromHandle: "",
      mine: false,
      ts,
      kind: "system",
      text,
      status: "sent",
    });
  }

  // ───────────── sending ─────────────

  private sendableEpoch(c: Conv): Epoch {
    if (c.removed) throw new UserError("you are no longer a member of this conversation");
    if (c.left) throw new UserError("you left this conversation");
    const ep = c.epochs.get(c.current);
    if (!ep) throw new UserError("conversation not ready");
    if (ep.claim)
      throw new UserError("the conversation is changing membership; try again in a moment");
    return ep;
  }

  private sendPayload(
    convId: string,
    partial: Pick<P.Payload, "t" | "text" | "img">,
    echo?: MessageView,
  ): Promise<void> {
    const c = this.conv(convId);
    const acc = this.requireAccount();
    const gen = this.generation;
    const e =
      echo ?? (partial.t === "leave" ? undefined : this.addEcho(c, "text", partial.text ?? ""));
    const run = async () => {
      let tagB = "";
      try {
        for (let attempt = 0; attempt < SEND_ATTEMPTS; attempt++) {
          this.assertSession(acc, gen);
          await this.syncNow();
          this.assertSession(acc, gen);
          const ep = this.sendableEpoch(c);
          const leavers = [...ep.left].filter((u) => u !== acc.uidB && ep.members.includes(u));
          if (leavers.length && partial.t !== "leave" && !ep.frozen) {
            try {
              await this.changeMembers(
                c,
                ep.members.filter((u) => !leavers.includes(u)),
                acc,
                gen,
              );
            } catch (err) {
              if (!(err instanceof ConflictError)) throw err;
            }
            continue; // send in whatever epoch is current now
          }
          const n = ep.maxN[ep.myIndex] + 1;
          const tag = P.msgTag(ep.keys.rk, ep.myIndex, n);
          const payload: P.Payload = {
            v: 1,
            t: partial.t,
            conv: c.id,
            e: ep.e,
            from: acc.uidB,
            n,
            ts: Date.now(),
            ...(partial.text !== undefined ? { text: partial.text } : {}),
            ...(partial.img ? { img: partial.img } : {}),
            head: { seq: this.head.seq, h: P.b64u(this.head.h) },
          };
          let row: P.Row;
          try {
            row = P.makeMessage(ep.keys.mk, tag, payload, acc.id.sigSk);
          } catch {
            throw new UserError("message is too long");
          }
          tagB = P.b64u(tag);
          if (e) this.pending.set(tagB, e.key);
          try {
            await api.append([row], (m) => this.progress(m));
          } catch (err) {
            if (err instanceof api.ApiError && err.status === 409) {
              this.pending.delete(tagB);
              continue; // the slot is taken: the next sync advances our counter past it
            }
            if (err instanceof api.ApiError && err.status > 0 && err.status < 500) throw err;
            // Network error / 5xx: the row may have landed. The sync below tells.
          }
          await this.syncNow();
          if (e && this.pending.has(tagB)) {
            this.pending.delete(tagB);
            throw new UserError(
              "message was not delivered (membership changed or the request failed); try again",
            );
          }
          return;
        }
        throw new UserError("could not send: too many conflicts, try again");
      } catch (err) {
        if (tagB) this.pending.delete(tagB);
        if (e) this.markEcho(c, e, "failed");
        if (this.account === acc && this.generation === gen) this.failNow(err);
      } finally {
        this.progress("");
      }
    };
    const prev = this.sendChains.get(convId) ?? Promise.resolve();
    const next = prev.then(run, run);
    this.sendChains.set(convId, next);
    return next;
  }

  private async changeMembers(c: Conv, members: string[], acc: Account, gen: number) {
    this.assertSession(acc, gen);
    const ep = this.sendableEpoch(c);
    if (ep.frozen)
      throw new UserError(
        "the members of this conversation can no longer change; start a new conversation",
      );
    const list = [...new Set(members)];
    if (!list.includes(acc.uidB)) throw new UserError("you cannot remove yourself; use “leave”");
    if (list.length > P.MAX_MEMBERS) throw new UserError(`at most ${P.MAX_MEMBERS} members`);
    for (const u of list) this.user(u);
    const EK = P.random(32);
    const e = ep.e + 1;
    if (e >= LAST_EPOCH) throw new UserError("this conversation cannot change any more");
    const keys = P.epochKeys(EK, c.conv, e);
    const dText = P.makeDescriptor({
      conv: c.id,
      e,
      members: list,
      prev: P.b64u(P.H(P.utf8(ep.dText))),
      by: acc.uidB,
      ts: Date.now(),
      ...(ep.d.name !== undefined ? { name: ep.d.name } : {}),
    });
    const dsig = P.signDescriptor(dText, keys.kc, acc.id.sigSk);
    const rows = [
      P.makeClaim(ep.keys.mk, ep.keys.rk, dText, dsig, acc.id.sigSk),
      ...this.invites(list, dText, EK, dsig),
    ];
    this.assertSession(acc, gen);
    try {
      await api.append(rows, (m) => this.progress(m));
    } catch (err) {
      if (err instanceof api.ApiError && err.status === 409) {
        await this.syncNow();
        throw new ConflictError(
          "someone else changed this conversation at the same time; try again",
        );
      }
      throw err;
    }
    await this.syncNow();
  }

  /** One invite per member, in random order (the batch order must not reveal who is who). */
  private invites(members: string[], dText: string, EK: Uint8Array, dsig: Uint8Array): P.Row[] {
    return shuffle(members).map((uid) => {
      const u = this.user(uid);
      try {
        return P.makeInvite(u, dText, EK, dsig);
      } catch {
        throw new UserError(`@${u.handle} has unusable public keys; cannot encrypt to them`);
      }
    });
  }

  private addEcho(c: Conv, kind: "text" | "image", text: string): MessageView {
    const acc = this.requireAccount();
    const m: MessageView = {
      key: `local:${++this.localCounter}`,
      seq: 0,
      from: acc.uidB,
      fromHandle: acc.handle,
      mine: true,
      ts: Date.now(),
      kind,
      text,
      status: "sending",
    };
    c.messages.push(m);
    this.scheduleEmit();
    return m;
  }

  private markEcho(c: Conv, echo: MessageView, status: MessageView["status"]) {
    c.messages = c.messages.map((m) => (m.key === echo.key ? { ...m, status } : m));
    this.scheduleEmit();
  }

  // ───────────── lookups ─────────────

  private async resolveHandles(handles: string[]): Promise<string[]> {
    const names = [
      ...new Set(
        handles
          .flatMap((h) => h.split(/[\s,]+/))
          .map((h) => h.trim().toLowerCase().replace(/^@/, ""))
          .filter(Boolean),
      ),
    ];
    if (names.length === 0) throw new UserError("enter at least one handle");
    if (names.some((h) => !this.byHandle.has(h))) await this.syncNow();
    const missing = names.filter((h) => !this.byHandle.has(h));
    if (missing.length) throw new UserError(`unknown: ${missing.map((h) => "@" + h).join(", ")}`);
    return names.map((h) => this.byHandle.get(h)!);
  }

  private user(uid: string): UserRec {
    const u = this.directory.get(uid);
    if (!u) throw new UserError("unknown user");
    return u;
  }

  private handleOf(uid: string): string {
    return this.directory.get(uid)?.handle ?? uid.slice(0, 8);
  }

  private fpOf(uid: string): string {
    const u = this.directory.get(uid);
    if (!u) return "";
    u.fp ??= P.fingerprint(u);
    return u.fp;
  }

  private conv(convId: string): Conv {
    const c = this.convs.get(convId);
    if (!c) throw new UserError("unknown conversation");
    return c;
  }

  private cleanName(name?: string): string | undefined {
    // Drop control / format characters, collapse whitespace, cap the length (see P.validName).
    const n = [
      ...(name ?? "")
        .replace(/[\p{Cc}\p{Cf}\u061c\u2028\u2029\u115f\u1160\u3164\uffa0\u2800]/gu, " ")
        .replace(/\s+/g, " ")
        .trim(),
    ]
      .slice(0, P.MAX_NAME)
      .join("")
      .trim();
    if (n.normalize("NFKC").startsWith("@"))
      throw new UserError("a group name cannot start with “@” (it would look like a person)");
    return P.validName(n) ? n : undefined;
  }

  private requireAccount(): Account {
    if (!this.account) throw new UserError("not signed in");
    return this.account;
  }

  // ───────────── state & errors ─────────────

  private async action<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      this.failNow(e);
      throw e;
    } finally {
      this.progress("");
    }
  }

  private failNow(e: unknown) {
    if (!(e instanceof UserError)) console.error("segv:", e);
    this.patch({ error: message(e) });
  }

  /**
   * Security warnings (`critical`) stay until sign-out and are never evicted. Everything else is noise an
   * outsider can trigger (e.g. junk invites), so it is deduplicated and only the latest few are kept.
   */
  private warn(text: string, critical = false) {
    if (critical) {
      if (this.critical.includes(text)) return;
      this.critical.push(text);
    } else {
      const n = (this.noise.get(text) ?? 0) + 1;
      this.noise.delete(text); // re-insert so the most recent stays last
      this.noise.set(text, n);
      while (this.noise.size > 5) this.noise.delete(this.noise.keys().next().value!);
    }
    const noise = [...this.noise].map(([t, n]) => (n > 1 ? `${t} (×${n})` : t));
    this.state = { ...this.state, warnings: [...this.critical, ...noise] };
    this.scheduleEmit();
  }

  private die(text: string) {
    this.fatal = true;
    this.feed?.close();
    this.feed = null;
    if (this.poll) clearInterval(this.poll);
    this.poll = null;
    this.patch({ phase: "fatal", error: text, syncing: false, connected: false });
  }

  private progress(text: string) {
    if (this.state.progress !== text) this.patch({ progress: text });
  }

  private patch(p: Partial<EngineState>) {
    this.state = { ...this.state, ...p };
    this.scheduleEmit(true);
  }

  private scheduleEmit(soon = false) {
    if (this.emitTimer) {
      if (!soon) return;
      clearTimeout(this.emitTimer);
    }
    this.emitTimer = setTimeout(() => this.emitNow(), soon ? 0 : this.live ? 30 : 200);
  }

  private emitNow() {
    if (this.emitTimer) clearTimeout(this.emitTimer);
    this.emitTimer = null;
    if (this.account) this.state = { ...this.state, conversations: this.views() };
    for (const fn of this.listeners) {
      try {
        fn(this.state);
      } catch (e) {
        console.error(e);
      }
    }
  }

  private views(): ConversationView[] {
    const acc = this.account!;
    const out: ConversationView[] = [];
    for (const c of this.convs.values()) {
      const ep = c.epochs.get(c.current);
      if (!ep) continue;
      const members: MemberView[] = ep.members.map((uid) => ({
        uid,
        handle: this.handleOf(uid),
        fingerprint: this.fpOf(uid),
        left: ep.left.has(uid),
      }));
      const others = members.filter((m) => m.uid !== acc.uidB).map((m) => "@" + m.handle);
      out.push({
        id: c.key,
        // Chosen names are marked with "#" so a group can never pass for a 1:1 ("@bob"); an unconfirmed
        // copy of a conversation we hold in more than one version is marked with "⚠".
        name:
          (!c.confirmed && (this.byConv.get(c.id)?.length ?? 0) > 1 ? "⚠ " : "") +
          (ep.d.name ? `# ${ep.d.name}` : others.join(", ") || "just you"),
        members,
        epoch: ep.e,
        canSend: !c.removed && !c.left && !ep.claim,
        lastTs: c.lastTs,
        unread: c.unread,
        messages:
          c.messages.length > VIEW_MESSAGES ? c.messages.slice(-VIEW_MESSAGES) : c.messages.slice(),
      });
    }
    return out.sort((a, b) => b.lastTs - a.lastTs);
  }
}

let instance: SegvEngine | null = null;

/** The browser-wide engine singleton. */
export function getEngine(): Promise<Engine> {
  if (!instance) {
    instance = new SegvEngine();
    void instance.boot();
  }
  return Promise.resolve(instance);
}

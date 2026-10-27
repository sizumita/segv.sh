// One session's conversations (docs/PROTOCOL-v2.md §6.1, §6.7, §6.12, §7.3, §11.2–§11.8): the copies restored from
// the self lane, catch-up, the inbox and its joins, creation, sending, requests and their acceptance, realtime
// routing, HEADS writes and the views. The engine (engine.ts) owns accounts and the session lifecycle and creates one
// Messaging per unlocked session.
import * as P from "~/lib/proto";
import { isTransient, type Api, type DirUser, type Params } from "./api";
import {
  HISTORY_COPIES,
  HISTORY_INITIAL,
  MAX_TEXT_BYTES,
  clampTs,
  cleanName,
  copyKeyOf,
  currentEpoch,
  memberHandle,
  newEpoch,
  rowKey,
  systemLine,
  unknownHandle,
  viewOf,
  type Copy,
  type Epoch,
  type KnownUser,
} from "./conv";
import { buildCreation, parseHandleList, resolveHandles, type Recipient } from "./create";
import { Deliveries, jobKey, type DeliveryJob, type WelcomeOutcome } from "./deliver";
import { SessionEnded, UserError, message } from "./errors";
import {
  cursorAt,
  minCursor,
  sameThread,
  scanInbox,
  workerDecrypt,
  type Decrypt,
  type InboxCursor,
} from "./inbox";
import { acceptJoin, secondCopyWarning, type JoinCtx, type NewCopy } from "./join";
import type {
  EngineClock,
  EngineDelays,
  EngineOptions,
  EngineTimer,
  WebSocketCtor,
} from "./options";
import { Realtime } from "./realtime";
import { keysChangedWarning, type SelfLane } from "./selflane";
import { prepareImage } from "./image";
import { WelcomeRefused, sendRow, type SendCtx } from "./send";
import {
  applyLaneRow,
  refreshHandles,
  syncLanes,
  targetsOf,
  type FoundRow,
  type LaneTarget,
  type SyncCtx,
} from "./sync";
import type { ConversationView, MessageView } from "./types";

type Bytes = Uint8Array;

/** Topics per realtime socket (§10.8). */
const RT_TOPICS = 256;

/** A self row holds at most this many bytes of records (cls 3 minus the S header and a margin, §7.1, §7.3). */
const ROW_BUDGET = 16_384 - 32 - 64;

/** The account of the session, as the engine holds it. */
export interface SessionAccount {
  uid: Bytes;
  uidB: string;
  id: P.Identity;
  handle: string;
  regEra: number;
}

/** What Messaging needs from the engine. */
export interface MessagingHost {
  api: Api;
  clock: EngineClock;
  delays: EngineDelays;
  opts: EngineOptions;
  acc: SessionAccount;
  self: SelfLane;
  /** throws SessionEnded once the session changed */
  check(): void;
  warn(text: string, critical?: boolean): void;
  /** state changed: bump the version and schedule an emit */
  changed(): void;
  /** emits the state now (createConversation resolves with the copy in `conversations`) */
  emitNow(): void;
  progress(text: string): void;
  error(text: string): void;
  /** waits on a protocol timer (counted in `busy`) */
  wait(ms: number): Promise<void>;
  /** serialises state-changing work */
  enqueue<T>(fn: () => Promise<T>): Promise<T>;
  /** counts an in-flight action (settle waits for it) */
  track<T>(p: Promise<T>): Promise<T>;
  setConnected(on: boolean): void;
}

export class Messaging {
  /** copies by view key */
  readonly copies = new Map<string, Copy>();
  private readonly byConv = new Map<string, Copy[]>();
  /** users verified in the directory this session, by b64u uid */
  private readonly users = new Map<string, KnownUser>();
  /** uids the directory answered without (complete and fresh): not looked up again until the next restore (§7.3) */
  private readonly unregistered = new Set<string>();
  /** CONTACT and MEMBER records for the next HEADS row (§7.3) */
  private pendingRecords: P.SelfRecord[] = [];
  /** the local echo of each row being sent, by row key */
  private readonly echoes = new Map<string, { c: Copy; echoKey: string }>();
  private readonly sendChains = new Map<string, Promise<unknown>>();
  /** T_e of every held epoch, by b64u topic */
  private readonly topics = new Map<string, { c: Copy; ep: Epoch }>();
  /** at most 2 realtime sockets of at most 256 topics each (§10.8) */
  private readonly rts: Realtime[] = [];
  private WS: WebSocketCtor | null = null;
  private seqCounter = 0;
  private localCounter = 0;
  /** the inbox cursor of this session (never past a parked join) */
  private cursor: InboxCursor | null = null;
  private headsDue = false;
  private headsTimer = false;
  private lastHeads = "";
  private readonly timers: EngineTimer[] = [];
  private stopped = false;
  live = false;
  /** the J delivery queue (§6.11, §6.12) */
  private readonly deliveries: Deliveries;
  /** EPOCH_PENDING records this session wrote (resumed at once, §6.11) */
  private readonly ownPending = new Set<string>();
  /** decrypted images by `id.k` (never by id alone, §8.1) */
  readonly imageCache = new Map<string, Promise<string>>();

  constructor(private readonly h: MessagingHost) {
    this.deliveries = new Deliveries({
      api: h.api,
      params: () => this.params(),
      check: () => h.check(),
      wait: (ms) => h.wait(ms),
      track: (p) => h.track(p),
      warn: (t) => h.warn(t),
      pks: (job) => this.pksOf(job),
      handleOf: (uidB) => this.handleOfUid(uidB),
      welcomeChannel: async (uid) => this.welcomeChannel(uid),
      sendWelcome: (c, uid, J) => this.sendWelcome(c as Copy, uid, J),
      delivered: (job, uids) =>
        h.enqueue(async () => {
          const bundleId = job.J.bundleId;
          await h.self.write([
            { rtype: P.RT.DELIVERED, conv: job.conv, root: job.root, e: job.e, bundleId, uids },
          ]);
        }),
    });
  }

  // ───────────────────────── lifecycle ─────────────────────────

  /**
   * Restore (§11.4 steps 5–9, without snapshots): the copies of the fold, their lanes from the HEADS positions,
   * the initial history, the inbox, the subscriptions. Rows applied here never count as unread.
   */
  async restore(): Promise<void> {
    const f = this.h.self.fold;
    this.cursor = f.cursor;
    const Enow = P.era(this.h.api.serverNow());
    for (const [k, rec] of f.joins) if (!this.byKey(k)) await this.materialize(k, rec, false);
    for (const [k, rec] of f.requests(Enow))
      if (!this.byKey(k)) await this.materialize(k, rec, true);
    await syncLanes(this.syncCtx(), targetsOf(this.copies.values()), true);
    await this.initialHistory();
    await this.resolveMembers([...this.copies.values()].filter((c) => !c.request));
    await this.pollInbox();
    this.resumeDeliveries();
  }

  /** Starts realtime and the periodic inbox poll and catch-up (§11.5, §11.6). */
  start(): void {
    this.live = true;
    const WS =
      this.h.opts.WebSocket ??
      (typeof WebSocket === "undefined" ? null : (WebSocket as unknown as WebSocketCtor));
    this.WS = WS;
    this.subscribe();
    this.every(
      () => Math.max(this.params().inboxSlot, 2) * 1000,
      () => this.h.enqueue(() => this.pollInbox()),
    );
    this.every(
      () => (this.rts[0]?.connected ? 300_000 : this.h.delays.catchUpInterval),
      () => this.catchUp(),
    );
  }

  stop(): void {
    this.stopped = true;
    for (const rt of this.rts) rt.stop();
    this.rts.length = 0;
    for (const t of this.timers) t.cancel();
    void this.worker?.then((w) => w?.terminate());
  }

  private worker: Promise<Worker | null> | null = null;

  /**
   * Trial decryption in the inbox Web Worker when one can be made (§11.5 step 2; EngineOptions.inboxWorker: absent
   * is the default factory, null is none), else on this thread.
   */
  private async decrypter(): Promise<Decrypt> {
    const opt = this.h.opts.inboxWorker;
    if (opt === null) return sameThread;
    const make = opt ?? (() => import("./inbox-worker-url").then((m) => m.createInboxWorker()));
    this.worker ??= make().catch(() => null);
    const w = await this.worker;
    return w ? workerDecrypt(w) : sameThread;
  }

  private every(ms: () => number, fn: () => Promise<unknown>): void {
    const tick = () => {
      if (this.stopped) return;
      void fn()
        .catch(() => {})
        .finally(() => {
          if (!this.stopped) this.timers.push(this.h.clock.setTimer(tick, ms()));
        });
    };
    this.timers.push(this.h.clock.setTimer(tick, ms()));
  }

  private params(): Params {
    return this.h.api.cachedParams!;
  }

  // ───────────────────────── catch-up (§11.6) ─────────────────────────

  /**
   * One catch-up: the self lane (a sibling's joins and acceptances), every held copy's lanes and control lane, the
   * inbox, and a HEADS row when positions moved.
   */
  async catchUp(): Promise<void> {
    await this.h.enqueue(async () => {
      this.h.check();
      await this.h.self.catchUp({ E: this.h.acc.regEra, n: 0 });
      await this.absorbFold();
      await syncLanes(this.syncCtx(), targetsOf(this.copies.values()), false);
      await this.pollInbox();
      await this.resolveMembers([...this.copies.values()].filter((c) => !c.request));
    });
    this.resumeDeliveries();
    await this.flushHeads();
  }

  private catchUpSoon(): Promise<void> {
    return this.h.track(this.catchUp()).catch(() => {});
  }

  /** New copies and acceptances written by sibling devices (§7.3, §11.7). */
  private async absorbFold(): Promise<void> {
    const f = this.h.self.fold;
    for (const [k, rec] of f.joins) {
      const c = this.byKey(k);
      if (!c) await this.materialize(k, rec, false);
      else if (c.request) this.becomeAccepted(c);
    }
    const Enow = P.era(this.h.api.serverNow());
    for (const [k, rec] of f.requests(Enow))
      if (!this.byKey(k)) await this.materialize(k, rec, true);
    for (const k of f.confirmed) {
      const c = this.byKey(k);
      if (c) c.confirmed = true;
    }
  }

  // ───────────────────────── copies ─────────────────────────

  private byKey(foldKey: string): Copy | undefined {
    for (const c of this.copies.values()) if (copyKeyOf(c) === foldKey) return c;
    return undefined;
  }

  copiesOf(convB: string): Copy[] {
    return this.byConv.get(convB) ?? [];
  }

  private register(c: Copy): void {
    this.copies.set(c.key, c);
    const list = this.byConv.get(c.convB) ?? [];
    list.push(c);
    this.byConv.set(c.convB, list);
    for (const ep of c.epochs.values()) this.topics.set(P.b64u(ep.topic), { c, ep });
    this.subscribe();
    this.h.changed();
  }

  private copy(convId: string): Copy {
    const c = this.copies.get(convId);
    if (!c) throw new UserError("unknown conversation");
    return c;
  }

  private newCopy(
    key: string,
    x: { conv: Bytes; root: Bytes; rootBy: Bytes; request: boolean; confirmed: boolean },
    ep: Epoch,
  ): Copy {
    return {
      key,
      conv: x.conv,
      convB: P.b64u(x.conv),
      root: x.root,
      rootBy: x.rootBy,
      request: x.request,
      confirmed: x.confirmed,
      epochs: new Map([[ep.e, ep]]),
      current: ep.e,
      removed: false,
      left: false,
      frozen: null,
      messages: [],
      order: new Map(),
      unread: 0,
      lastTs: 0,
      ready: Promise.resolve(),
      history: false,
      leaves: new Set(),
    };
  }

  /** The system line of the epoch a copy was joined at (§11.9). */
  private joinLine(c: Copy, ep: Epoch): void {
    const by = this.whoOf(c, ep, ep.D.by);
    const text = ep.e === 0 ? `${by} started the conversation` : `${by} added you`;
    // A join without a stored row of its own takes D.ts clamped to the §11.8 window around the bundle's t_reg, so a
    // far-future D.ts cannot pin the copy to the top of the list (answer R10-2). It sorts before the epoch's rows.
    const ts = ep.tReg !== null ? clampTs(ep.D.ts, ep.tReg, this.params().delta) : ep.D.ts;
    const key = `sys:${ep.e}:join`;
    if (c.order.has(key)) return;
    c.order.set(key, [ts, ep.e, -1, -1, -1]);
    const m = systemLine(key, ts, text);
    let i = c.messages.length;
    while (i > 0 && (c.order.get(c.messages[i - 1].key)?.[0] ?? Infinity) > ts) i--;
    c.messages.splice(i, 0, m);
    c.lastTs = Math.max(c.lastTs, ts);
  }

  /**
   * A copy from its CONV_JOIN or REQUEST record (§11.4 step 5): the root epoch's D from the REQUEST's desc, a DESC
   * record or the bundle (checked as §7.2 says), E_start from EPOCH_PENDING, REQUEST or blob meta, and the lane
   * positions of its HEADS entry when it fits D.
   */
  private async materialize(
    k: string,
    rec: P.ConvJoinRec | P.RequestRec,
    request: boolean,
  ): Promise<void> {
    const f = this.h.self.fold;
    const key = f.viewKeys.get(k);
    if (!key) return;
    const e = rec.e;
    const keys = P.epochKeys(rec.EK, rec.conv, e);
    let D: P.Descriptor | null = null;
    let dsig: Bytes | null = null;
    let pks: Bytes | null = null;
    const descOk = (desc: Bytes): boolean => {
      try {
        const s = P.splitDesc(desc);
        const d = P.parseD(s.D);
        if (
          !P.equalBytes(d.conv, rec.conv) ||
          d.e !== e ||
          !P.verifyD(d, keys.kc, s.dsig) ||
          !P.equalBytes(d.hash, rec.root)
        )
          return false;
        D = d;
        dsig = s.dsig;
        return true;
      } catch {
        return false;
      }
    };
    if (request) {
      if (!descOk((rec as P.RequestRec).desc)) return; // a REQUEST that fails is ignored (§7.2)
    } else {
      const desc = f.desc.get(`${k}:${e}`);
      if (!desc || !descOk(desc.desc)) {
        const got = await this.h.api.getBlob(rec.bundleId, rec.bundleSize);
        if (!got || !got.sizeOk || !P.equalBytes(P.H(got.bytes), rec.bundleId)) return;
        try {
          const pair = P.openDesc(keys.dk, rec.conv, e, got.bytes);
          if (!descOk(P.concat(pair.D, pair.dsig))) return;
          pks = P.openPks(keys.dk, rec.conv, e, got.bytes);
        } catch {
          return;
        }
      }
    }
    if (!D || !dsig) return;
    const Dv: P.Descriptor = D;
    let tReg: number | null = request ? (rec as P.RequestRec).tReg : null;
    // E_start from an EPOCH_PENDING only when it names this epoch's own bundle (sent-2b, round 14)
    if (tReg === null)
      tReg =
        f.pending.find(
          (x) =>
            copyKeyOf(x.rec) === k && x.rec.e === e && P.equalBytes(x.rec.bundleId, rec.bundleId),
        )?.rec.tReg ?? null;
    if (tReg === null) tReg = (await this.h.api.blobMeta(rec.bundleId))?.t ?? null;
    if (tReg === null) return;
    const ep = newEpoch({
      e,
      EK: rec.EK,
      D: Dv,
      dsig: dsig!,
      bundleId: rec.bundleId,
      bundleSize: rec.bundleSize,
      tReg,
      pks,
      self: this.h.acc.uid,
    });
    const heads = f.heads.get(k);
    if (heads && heads.e === e && heads.lanes.length === Dv.members.length) {
      heads.lanes.forEach(
        (x, j) =>
          (ep.lanes[j].next = { E: Math.max(x.E, ep.Estart!), n: x.E < ep.Estart! ? 0 : x.cnt }),
      );
      ep.ctl.next = {
        E: Math.max(heads.ctl.E, ep.Estart!),
        n: heads.ctl.E < ep.Estart! ? 0 : heads.ctl.cnt,
      };
    }
    const created = rec.rtype === P.RT.CONV_JOIN && rec.via === P.VIA.CREATED;
    const c = this.newCopy(
      key,
      {
        conv: rec.conv,
        root: rec.root,
        rootBy: rec.rootBy,
        request,
        confirmed: created || f.confirmed.has(k),
      },
      ep,
    );
    c.lastTs = heads?.lastTs ?? 0;
    this.joinLine(c, ep);
    this.register(c);
  }

  /**
   * §11.4 step 6 (initial history): for the copies with the newest lastTs, the slots before each lane's processed
   * position in its era, up to HISTORY_INITIAL, processed like scrollback (never unread).
   */
  private async initialHistory(): Promise<void> {
    const copies = [...this.copies.values()]
      .sort((a, b) => b.lastTs - a.lastTs)
      .slice(0, HISTORY_COPIES);
    const keys: { c: Copy; ep: Epoch; j: number; E: number; n: number; label: Bytes }[] = [];
    for (const c of copies) {
      c.history = true;
      const ep = c.epochs.get(c.current);
      if (!ep) continue;
      ep.lanes.forEach((lane, j) => {
        for (let n = Math.max(0, lane.next.n - HISTORY_INITIAL); n < lane.next.n; n++)
          keys.push({ c, ep, j, E: lane.next.E, n, label: P.Lmsg(ep.keys.rk, j, lane.next.E, n) });
      });
    }
    if (keys.length === 0) return;
    const st = await this.h.api.get(
      keys.map((x) => ({ E: x.E, label: x.label, mode: 0 as const })),
    );
    const ctx = this.syncCtx();
    keys.forEach((x, i) => {
      const s = st[i];
      if (s.s === "hit" && s.body)
        applyLaneRow(
          ctx,
          x.c,
          x.ep,
          x.j,
          { E: x.E, n: x.n, label: x.label, t: s.t, body: s.body },
          true,
        );
    });
  }

  // ───────────────────────── users (§7.3, §10.6, §11.2) ─────────────────────────

  private knownUser(uidB: string): KnownUser | undefined {
    const u = this.users.get(uidB);
    if (u) return u;
    const m = this.h.self.fold.members.get(uidB);
    return m ? { handle: m.handle, sigPk: m.sigPk, kh: m.kh, kemPk: null } : undefined;
  }

  private handleOf(c: Copy, ep: Epoch, j: number): string {
    const m = ep.D.members[j];
    if (P.equalBytes(m.uid, this.h.acc.uid)) return this.h.acc.handle;
    const uidB = P.b64u(m.uid);
    if (c.request && !P.equalBytes(m.uid, ep.D.by)) return unknownHandle(uidB);
    return memberHandle(m, this.knownUser(uidB)).handle;
  }

  /** "you" for self, else "@handle" (§11.9). */
  private whoOf(c: Copy, ep: Epoch, uid: Bytes): string {
    if (P.equalBytes(uid, this.h.acc.uid)) return "you";
    const j = P.memberIndex(ep.D, uid);
    return "@" + (j >= 0 ? this.handleOf(c, ep, j) : unknownHandle(P.b64u(uid)));
  }

  /** Records a verified directory user: its MEMBER rides in the next HEADS row unless the fold has one (§7.3). */
  private learnUser(u: DirUser, contact: boolean): void {
    const kh = P.kemHash(u.kemPk);
    this.users.set(u.uid, { handle: u.handle, sigPk: u.sigPk, kh, kemPk: u.kemPk });
    const f = this.h.self.fold;
    const had = f.members.get(u.uid);
    if (had && !P.equalBytes(had.pin, u.pin)) this.h.warn(keysChangedWarning(u.handle), true);
    if (
      !had &&
      !this.pendingRecords.some((r) => r.rtype === P.RT.MEMBER && P.b64u(r.uid) === u.uid)
    )
      this.pendingRecords.push({
        rtype: P.RT.MEMBER,
        uid: u.uidBytes,
        sigPk: u.sigPk,
        kh,
        pin: u.pin,
        handle: u.handle,
      });
    if (
      contact &&
      !f.contacts.has(u.uid) &&
      !this.pendingRecords.some((r) => r.rtype === P.RT.CONTACT && P.b64u(r.uid) === u.uid)
    )
      this.pendingRecords.push({ rtype: P.RT.CONTACT, uid: u.uidBytes, pin: u.pin });
    this.markHeads();
  }

  /**
   * Looks up the members of accepted copies that have no MEMBER record (by uid prefix, cached for the session); a
   * member whose keys differ from D's is shown as unknown and raises the critical warning (§11.2).
   */
  private async resolveMembers(copies: readonly Copy[]): Promise<void> {
    const want = new Map<string, Bytes>();
    for (const c of copies) {
      const ep = c.epochs.get(c.current);
      if (!ep) continue;
      for (const m of ep.D.members) {
        const uidB = P.b64u(m.uid);
        if (
          P.equalBytes(m.uid, this.h.acc.uid) ||
          this.knownUser(uidB) ||
          this.unregistered.has(uidB)
        )
          continue;
        want.set(uidB, m.uid);
      }
    }
    for (const [uidB, uid] of want) {
      let u: DirUser | null;
      try {
        u = await this.h.api.userByUidPrefix(uid);
      } catch {
        continue; // transient: still unknown, looked up again later
      }
      this.h.check();
      if (u) this.learnUser(u, false);
      else this.unregistered.add(uidB); // a complete answer without it (re-asked fresh once, R10-1)
    }
    let changed = false;
    for (const c of copies) {
      const ep = c.epochs.get(c.current);
      if (!ep) continue;
      for (const m of ep.D.members) {
        if (P.equalBytes(m.uid, this.h.acc.uid)) continue;
        const r = memberHandle(m, this.knownUser(P.b64u(m.uid)));
        if (r.mismatch)
          this.h.warn(keysChangedWarning(this.knownUser(P.b64u(m.uid))!.handle), true);
      }
      const before = c.messages.map((m) => m.fromHandle).join();
      refreshHandles(c, (uidB) => {
        const j = ep.D.members.findIndex((m) => P.b64u(m.uid) === uidB);
        return j >= 0 ? this.handleOf(c, ep, j) : null;
      });
      if (c.messages.map((m) => m.fromHandle).join() !== before) changed = true;
    }
    if (changed || want.size) this.h.changed();
  }

  // ───────────────────────── rows ─────────────────────────

  private syncCtx(): SyncCtx {
    return {
      api: this.h.api,
      selfUid: this.h.acc.uid,
      delta: () => this.params().delta,
      live: () => this.live,
      mono: () => this.h.clock.mono(),
      seq: () => ++this.seqCounter,
      warn: (t, c) => this.h.warn(t, c),
      changed: () => {
        this.markHeads();
        this.h.changed();
      },
      handleOf: (c, ep, j) => this.handleOf(c, ep, j),
      onWelcome: (c, ep, j, J) => {
        // Own WELCOMEs (this device's or a sibling's) carry J of copies the account already holds.
        if (!P.equalBytes(ep.D.members[j].uid, this.h.acc.uid)) void this.welcome(c, ep, J);
      },
      onValidRow: (c, ep, j) => this.corroborate(c, ep, j),
      takeEcho: (key) => {
        const x = this.echoes.get(key);
        this.echoes.delete(key);
        return x ? { c: x.c, echoKey: x.echoKey } : undefined;
      },
    };
  }

  /**
   * A valid row of a member other than rootBy and self confirms the copy (§6.7 step 6), and accepts a request
   * (§11.5); both are recorded (CONFIRMED before the CONV_JOIN, §7.3).
   */
  private corroborate(c: Copy, ep: Epoch, j: number): void {
    const uid = ep.D.members[j].uid;
    if (P.equalBytes(uid, c.rootBy) || P.equalBytes(uid, this.h.acc.uid) || c.confirmed) return;
    c.confirmed = true;
    void this.h
      .track(
        this.h.enqueue(async () => {
          const recs: P.SelfRecord[] = [{ rtype: P.RT.CONFIRMED, conv: c.conv, root: c.root }];
          if (c.request) recs.push(...this.acceptRecords(c));
          await this.h.self.write(recs);
          if (c.request) this.becomeAccepted(c);
        }),
      )
      .catch((e) => this.h.warn(`could not record a conversation: ${message(e)}`));
  }

  /** A WELCOME's J (M6c sends them; receivers accept them whenever the row is processed, §5.2). */
  private async welcome(_c: Copy, _ep: Epoch, J: P.Join): Promise<void> {
    await this.h.track(this.h.enqueue(() => this.processJoins([{ J, at: null }])));
  }

  /** Applies a row that this device's own send stored (or a sibling's found by the send). */
  private applyOwn(c: Copy, ep: Epoch, row: FoundRow): void {
    const j = ep.myIndex;
    applyLaneRow(this.syncCtx(), c, ep, j, row, false);
    const lane = ep.lanes[j];
    if (P.posCmp({ E: row.E, n: row.n + 1 }, lane.next) > 0) lane.next = { E: row.E, n: row.n + 1 };
  }

  /**
   * Realtime rows (§11.6): Tself catches the self lane up; a row on T_e that is the next slot of its lane is applied
   * at once, anything else (a later slot, a control row) makes that copy catch up.
   */
  private onRows(rows: { topic: Bytes; E: number; label: Bytes; t: number; body: Bytes }[]): void {
    const tself = P.b64u(P.topicSelf(this.h.acc.id.nS));
    const stale = new Set<Copy>();
    let self = false;
    for (const r of rows) {
      const topic = P.b64u(r.topic);
      if (topic === tself) {
        self = true;
        continue;
      }
      const x = this.topics.get(topic);
      if (!x) continue;
      const v = P.acceptRow(
        { keys: x.ep.keys, conv: x.c.conv, e: x.ep.e, members: x.ep.D.members },
        r.E,
        r.label,
        r.body,
      );
      if (!v.ok || v.msg.type === P.MT.CLAIM) {
        stale.add(x.c);
        continue;
      }
      const lane = x.ep.lanes[v.msg.lane];
      if (lane && lane.next.E === r.E && lane.next.n === v.msg.n) {
        applyLaneRow(
          this.syncCtx(),
          x.c,
          x.ep,
          v.msg.lane,
          { E: r.E, n: v.msg.n, label: r.label, t: r.t, body: r.body },
          false,
        );
        lane.next = { E: r.E, n: v.msg.n + 1 };
      } else if (!x.c.order.has(rowKey(r.E, r.label))) stale.add(x.c);
    }
    if (self || stale.size)
      void this.h
        .track(
          this.h.enqueue(async () => {
            if (self) {
              await this.h.self.catchUp({ E: this.h.acc.regEra, n: 0 });
              await this.absorbFold();
            }
            if (stale.size) await syncLanes(this.syncCtx(), targetsOf(stale), false);
          }),
        )
        .catch(() => {});
  }

  private newSocket(WS: WebSocketCtor): Realtime {
    const rt = new Realtime(WS, this.h.clock, {
      onRows: (rows) => this.onRows(rows),
      onMissed: () => void this.catchUpSoon(),
      onSubscribed: () => void this.catchUpSoon(),
      onHello: (s, sent, recv) => this.h.api.time.add(s, sent, recv),
      onState: () => this.h.setConnected(this.rts.some((x) => x.connected)),
    });
    rt.start();
    return rt;
  }

  /**
   * The topics, in priority order (§10.8): Tself, then the current epochs of accepted copies by recent activity.
   * Requests are never subscribed. At most 256 per socket and 2 sockets; the rest are covered by catch-up.
   */
  private subscribe(): void {
    if (!this.live || !this.WS) return;
    const topics: Bytes[] = [P.topicSelf(this.h.acc.id.nS)];
    const accepted = [...this.copies.values()]
      .filter((c) => !c.request)
      .sort((a, b) => b.lastTs - a.lastTs);
    for (const c of accepted) {
      const ep = c.epochs.get(c.current);
      if (ep) topics.push(ep.topic);
    }
    const parts = [topics.slice(0, RT_TOPICS), topics.slice(RT_TOPICS, 2 * RT_TOPICS)];
    parts.forEach((part, i) => {
      if (part.length === 0) return;
      this.rts[i] ??= this.newSocket(this.WS!);
      this.rts[i].setTopics(part);
    });
    if (parts[1].length === 0 && this.rts[1]) {
      this.rts[1].stop();
      this.rts.length = 1;
    }
  }

  // ───────────────────────── inbox and joins (§6.7, §11.5) ─────────────────────────

  /** Reads the inbox, accepts the joins found (in order) and moves the cursor (§11.5). */
  async pollInbox(): Promise<void> {
    const p = await this.h.api.params();
    const scan = await scanInbox(
      this.h.api,
      this.h.acc.id.kemSk,
      this.cursor,
      p,
      this.h.acc.regEra,
      (t) => this.h.warn(t),
      await this.decrypter(),
    );
    this.h.check();
    await this.processJoins(
      scan.joins.map((x) => ({ J: x.J, at: { E: x.E, rel: x.rel } })),
      scan.cursor,
    );
  }

  private joinCtx(pending: NewCopy[]): JoinCtx {
    return {
      api: this.h.api,
      self: { uid: this.h.acc.uid, sigPk: this.h.acc.id.sigPk, kh: P.kemHash(this.h.acc.id.kemPk) },
      copiesOf: (convB) => [
        ...this.copiesOf(convB),
        ...pending
          .filter((x) => P.b64u(x.conv) === convB)
          .map((x) => this.newCopy("", { ...x, confirmed: false }, x.epoch)),
      ],
      member: (uidB) => this.h.self.fold.members.get(uidB) ?? null,
      contact: (uidB) => this.h.self.fold.contacts.get(uidB) ?? null,
      warn: (t, c) => this.h.warn(t, c),
    };
  }

  /**
   * Accepts joins one after the other, writes their records in as few rows as fit with the cursor's HEADS in the
   * last one (the durability order of §7.3), then holds the new copies. A parked join holds the cursor before it.
   */
  private async processJoins(
    found: { J: P.Join; at: { E: number; rel: number } | null }[],
    next?: InboxCursor,
  ): Promise<void> {
    const created: NewCopy[] = [];
    let cursor = next ?? null;
    for (const x of found) {
      const out = await acceptJoin(
        this.joinCtx(created),
        x.J,
        x.at ? { via: P.VIA.INBOX, ...x.at } : { via: P.VIA.WELCOME },
      );
      this.h.check();
      if (out.kind === "parked" && x.at && cursor)
        cursor = minCursor(cursor, { E: x.at.E, rel: Math.max(0, x.at.rel - 1) });
      if (out.kind === "new") created.push(out.copy);
    }
    const moved =
      cursor && (!this.cursor || cursor.E !== this.cursor.E || cursor.rel !== this.cursor.rel);
    if (created.length === 0) {
      if (moved) {
        this.cursor = cursor;
        this.markHeads();
      }
      return;
    }
    const records = created.flatMap((x) => x.records);
    const heads: P.HeadsRec | null = cursor
      ? { rtype: P.RT.HEADS, Ein: cursor.E, relIn: cursor.rel, entries: [] }
      : null;
    await this.writeRows(records, heads);
    if (cursor) this.cursor = cursor;
    for (const x of created) this.adopt(x);
  }

  /** Writes records in as few self rows as fit cls 3, `last` in the final row, each after the previous is CAS OK. */
  private async writeRows(records: P.SelfRecord[], last: P.SelfRecord | null): Promise<void> {
    const rows: P.SelfRecord[][] = [[]];
    let size = 0;
    const all = last ? [...records, last] : records;
    for (const r of all) {
      const len = P.encodeRecord(r).length;
      if (
        rows[rows.length - 1].length > 0 &&
        (size + len > ROW_BUDGET || rows[rows.length - 1].length >= 255)
      ) {
        rows.push([]);
        size = 0;
      }
      rows[rows.length - 1].push(r);
      size += len;
    }
    for (const row of rows) if (row.length) await this.h.self.write(row);
  }

  /** Holds a copy accepted by a join (after its records are written). */
  private adopt(x: NewCopy): void {
    const k = copyKeyOf(x);
    const key = this.h.self.fold.viewKeys.get(k);
    if (!key || this.copies.has(key)) return;
    const c = this.newCopy(key, { ...x, confirmed: false }, x.epoch);
    this.users.set(P.b64u(x.rootBy), x.dby);
    if (x.member) this.pendingRecords.push(x.member);
    this.joinLine(c, x.epoch);
    if (this.live && !P.equalBytes(x.rootBy, this.h.acc.uid)) c.unread++;
    if (x.second) this.h.warn(secondCopyWarning(x.dby.handle), true);
    this.register(c);
    this.markHeads();
    void this.h
      .track(
        this.h.enqueue(async () => {
          await syncLanes(this.syncCtx(), targetsOf([c]), !this.live);
          if (!c.request) await this.resolveMembers([c]);
        }),
      )
      .catch(() => {});
  }

  // ───────────────────────── requests (§11.5) ─────────────────────────

  /** The CONV_JOIN (via 5) and CONTACT that accept a request copy. */
  private acceptRecords(c: Copy): P.SelfRecord[] {
    const root = [...c.epochs.values()].sort((a, b) => a.e - b.e)[0];
    const recs: P.SelfRecord[] = [
      {
        rtype: P.RT.CONV_JOIN,
        conv: c.conv,
        root: c.root,
        e: root.e,
        EK: root.EK,
        bundleId: root.bundleId,
        bundleSize: root.bundleSize,
        rootBy: c.rootBy,
        via: P.VIA.REQUEST_ACCEPTED,
      },
    ];
    const m = this.h.self.fold.members.get(P.b64u(c.rootBy));
    if (m && !this.h.self.fold.contacts.has(P.b64u(c.rootBy)))
      recs.push({ rtype: P.RT.CONTACT, uid: c.rootBy, pin: m.pin });
    return recs;
  }

  /** A request copy becomes accepted: subscribed, its members looked up, every lane processed from E_start. */
  private becomeAccepted(c: Copy): void {
    if (!c.request) return;
    c.request = false;
    this.subscribe();
    this.h.changed();
    void this.h
      .track(
        this.h.enqueue(async () => {
          await this.resolveMembers([c]);
          await syncLanes(this.syncCtx(), targetsOf([c]), true);
        }),
      )
      .catch(() => {});
  }

  /** Accepts a request copy now (it was opened, or self posts in it). */
  private async accept(c: Copy): Promise<void> {
    if (!c.request) return;
    await this.h.enqueue(() => this.h.self.write(this.acceptRecords(c)));
    this.becomeAccepted(c);
  }

  markRead(convId: string): void {
    const c = this.copies.get(convId);
    if (!c) return;
    if (c.unread !== 0) {
      c.unread = 0;
      this.h.changed();
    }
    if (c.request) void this.h.track(this.accept(c)).catch((e) => this.h.error(message(e)));
  }

  // ───────────────────────── creation (§6.1) ─────────────────────────

  async create(handles: string[], name: string | undefined): Promise<string> {
    const acc = this.h.acc;
    const names = parseHandleList(handles).filter((h) => h !== acc.handle);
    if (names.length === 0) throw new UserError("add at least one other person");
    cleanName(name); // a name that would look like a person is refused before any request (§5.1)
    this.h.progress("looking up handles…");
    const others = await resolveHandles(this.h.api, names);
    this.h.check();
    const now = Math.floor(this.h.clock.wall());
    const cr = buildCreation({ uid: acc.uid, id: acc.id }, others, name, now);
    this.h.progress("uploading conversation keys…");
    const { t: tReg } = await this.h.api.putBlob(cr.bundleId, cr.blob, (m) => this.h.progress(m));
    const putAt = this.h.clock.mono();
    this.h.check();
    const material = { e: 0, EK: cr.EK, bundleId: cr.bundleId, bundleSize: cr.bundleSize };
    await this.h.enqueue(() =>
      this.h.self.write([
        {
          rtype: P.RT.CONV_JOIN,
          conv: cr.conv,
          root: cr.D.hash,
          ...material,
          rootBy: acc.uid,
          via: P.VIA.CREATED,
        },
        {
          rtype: P.RT.EPOCH_PENDING,
          conv: cr.conv,
          root: cr.D.hash,
          ...material,
          tReg,
          uids: others.map((u) => u.uidBytes),
        },
      ]),
    );
    this.h.check();
    this.ownPending.add(jobKey(copyKeyOf({ conv: cr.conv, root: cr.D.hash }), 0, cr.bundleId));
    for (const u of others) this.learnUser(u, true);
    const k = copyKeyOf({ conv: cr.conv, root: cr.D.hash });
    const key = this.h.self.fold.viewKeys.get(k)!;
    const ep = newEpoch({ ...material, D: cr.D, dsig: cr.dsig, tReg, pks: cr.pks, self: acc.uid });
    const c = this.newCopy(
      key,
      { conv: cr.conv, root: cr.D.hash, rootBy: acc.uid, request: false, confirmed: true },
      ep,
    );
    let release!: () => void;
    c.ready = new Promise<void>((r) => (release = r));
    this.joinLine(c, ep);
    this.register(c);
    this.h.emitNow();
    const recipients: Recipient[] = others.map((u) => ({
      uid: u.uidBytes,
      kemPk: u.kemPk,
      handle: u.handle,
    }));
    void this.h.track(this.finishCreation(c, ep, putAt, tReg, recipients, release)).catch(() => {});
    return key;
  }

  /** §6.1 steps 6–9: the commit wait, the decoy (then own sends may go), the invites, the DELIVERED row. */
  private async finishCreation(
    c: Copy,
    ep: Epoch,
    putAt: number,
    tReg: number,
    recipients: Recipient[],
    release: () => void,
  ): Promise<void> {
    try {
      for (;;) {
        const p = this.params();
        const left = Math.max(
          putAt + (p.delta + p.skew) * 1000 - this.h.clock.mono(),
          P.T0_MS + (tReg + p.delta + p.skew) * 1000 - this.h.api.serverNow(),
        );
        if (left <= 0) break;
        await this.h.wait(left);
        this.h.check();
      }
      await this.retry(() => this.putDecoy());
    } finally {
      release();
    }
    // §6.1 steps 8–9: the first attempt for every recipient, then one DELIVERED row (also when nobody got J).
    const J: P.Join = {
      conv: c.conv,
      e: ep.e,
      EK: ep.EK,
      bundleId: ep.bundleId,
      bundleSize: ep.bundleSize,
    };
    const job = this.deliveries.enqueue({
      key: jobKey(copyKeyOf(c), ep.e, ep.bundleId),
      conv: c.conv,
      root: c.root,
      e: ep.e,
      J,
      uids: new Set(recipients.map((r) => P.b64u(r.uid))),
      writeEmpty: true,
    });
    await this.deliveries.first(job);
  }

  /** §6.1 step 7: a class-1 row of random bytes at a random label of the current era, without a topic. */
  private async putDecoy(): Promise<void> {
    let E = P.era(this.h.api.serverNow());
    for (let k = 0; k < 4; k++) {
      const [r] = await this.h.api.put([
        { E, label: P.random(16), cls: 1, topic: P.ZERO16, body: P.random(P.BODY_LENS[1]) },
      ]);
      if (r.s === "ok" || r.s === "conflict") return;
      if (r.s === "wrong_era") E = r.era;
      else throw new Error(`decoy refused (${r.s})`);
    }
  }

  /** Retries background work with back-off until it succeeds or the session ends. */
  private async retry(fn: () => Promise<void>): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      this.h.check();
      try {
        return await fn();
      } catch (e) {
        if (e instanceof SessionEnded) throw e;
        if (!isTransient(e)) this.h.warn(message(e));
        await this.h.wait(Math.min(this.h.delays.retryMax, this.h.delays.retryBase * 2 ** attempt));
      }
    }
  }

  // ───────────────────────── deliveries (§6.11, §6.12) ─────────────────────────

  /**
   * Resumes unfinished deliveries (§6.11): every EPOCH_PENDING of the account with uids not covered by DELIVERED
   * records, once established (e = 0: the account holds its CONV_JOIN; later epochs land with M7), and written by
   * this device in this session or stored more than RESUME_AFTER ago.
   */
  private resumeDeliveries(): void {
    if (this.stopped) return;
    const f = this.h.self.fold;
    const nowSec = Math.floor((this.h.api.serverNow() - P.T0_MS) / 1000);
    for (const { rec, t } of f.pending) {
      const k = copyKeyOf(rec);
      const key = jobKey(k, rec.e, rec.bundleId);
      if (rec.e !== 0 || !f.joins.has(k)) continue;
      const covered = f.delivered.get(key) ?? new Set<string>();
      const uids = rec.uids.map((u) => P.b64u(u)).filter((u) => !covered.has(u));
      if (uids.length === 0) continue;
      // This session's own creations deliver through their own attempts (§6.1 steps 8–9, then the job's loop);
      // another device's (or an earlier session's) once RESUME_AFTER has passed.
      if (this.ownPending.has(key) || nowSec - t < this.h.delays.resumeAfter / 1000) continue;
      const J: P.Join = {
        conv: rec.conv,
        e: rec.e,
        EK: rec.EK,
        bundleId: rec.bundleId,
        bundleSize: rec.bundleSize,
      };
      const job = this.deliveries.enqueue({
        key,
        conv: rec.conv,
        root: rec.root,
        e: rec.e,
        J,
        uids: new Set(uids),
        writeEmpty: false,
      });
      this.deliveries.start(job);
    }
  }

  /** The recipients' kemPk from the epoch's bundle (held, or fetched once), by b64u uid. */
  private async pksOf(job: DeliveryJob): Promise<Map<string, Bytes>> {
    const c = this.byKey(copyKeyOf(job));
    let ep = c?.epochs.get(job.e);
    let D: P.Descriptor | null = ep?.D ?? null;
    let pks = ep && P.equalBytes(ep.bundleId, job.J.bundleId) ? ep.pks : null;
    if (!pks || !D) {
      const got = await this.h.api.getBlob(job.J.bundleId, job.J.bundleSize);
      if (!got || !got.sizeOk || !P.equalBytes(P.H(got.bytes), job.J.bundleId))
        throw new Error("bundle not available");
      const keys = P.epochKeys(job.J.EK, job.conv, job.e);
      D = P.parseD(P.openDesc(keys.dk, job.conv, job.e, got.bytes).D);
      pks = P.openPks(keys.dk, job.conv, job.e, got.bytes);
      if (ep && P.equalBytes(ep.bundleId, job.J.bundleId)) ep.pks = pks;
    }
    const out = new Map<string, Bytes>();
    D.members.forEach((m, j) => out.set(P.b64u(m.uid), pks!.slice(j * 1216, (j + 1) * 1216)));
    ep = undefined;
    return out;
  }

  private handleOfUid(uidB: string): string {
    return this.knownUser(uidB)?.handle ?? unknownHandle(uidB);
  }

  /**
   * §6.12 step 1: an accepted 1:1 copy whose current epoch lists exactly self and R, self not frozen, not left, not
   * removed, with a valid row of R seen in that epoch, and R not left.
   */
  private qualifies(c: Copy, ep: Epoch, uid: Bytes): boolean {
    if (c.request || c.frozen !== null || c.left || c.removed || ep.D.members.length !== 2)
      return false;
    const j = P.memberIndex(ep.D, uid);
    if (j < 0 || j === ep.myIndex || ep.myIndex < 0) return false;
    return ep.lanes[j].seen && !c.leaves.has(P.b64u(uid));
  }

  private welcomeChannel(uid: Bytes): Copy | null {
    let best: Copy | null = null;
    for (const c of this.copies.values()) {
      const ep = c.epochs.get(c.current);
      if (ep && this.qualifies(c, ep, uid) && (!best || c.lastTs > best.lastTs)) best = c;
    }
    return best;
  }

  /** Puts J as a WELCOME on self's lane of the 1:1 (§11.3 with the step-2 WELCOME check; no echo). */
  private async sendWelcome(c: Copy, uid: Bytes, J: P.Join): Promise<WelcomeOutcome> {
    const run = async (): Promise<WelcomeOutcome> => {
      try {
        await sendRow(
          {
            ...this.sendCtx(c, null),
            welcomeTo: uid,
            qualifies: (cc, ep, u) => this.qualifies(cc, ep, u),
          },
          c,
          {
            type: P.MT.WELCOME,
            join: J,
          },
        );
        return "ok";
      } catch (e) {
        if (e instanceof WelcomeRefused) return "invite";
        if (e instanceof SessionEnded) throw e;
        return "pending";
      }
    };
    const prev = this.sendChains.get(c.key) ?? Promise.resolve();
    const next = prev.then(run, run);
    this.sendChains.set(c.key, next);
    return next;
  }

  // ───────────────────────── images (§8.1) ─────────────────────────

  /** Re-encodes, encrypts and uploads an image, then sends its IMAGE row (§8.1, §11.3). */
  sendImage(convId: string, file: File): Promise<void> {
    const c = this.copy(convId);
    const echo = this.addEcho(c, "image", "[image]");
    const run = async () => {
      try {
        this.h.progress("preparing image…");
        const img = await prepareImage(file);
        this.h.check();
        const { blob, id, key } = P.encryptBlob(img.bytes);
        if (blob.length > P.BLOB_MAX) throw new UserError("image is too large");
        await this.h.api.putBlob(P.fromB64u(id), blob, (m) => this.h.progress(m));
        this.h.check();
        const k = P.b64u(key);
        this.imageCache.set(
          `${id}.${k}`,
          Promise.resolve(
            URL.createObjectURL(new Blob([img.bytes as BlobPart], { type: img.mime })),
          ),
        );
        if (c.request) await this.accept(c);
        const mime = img.mime === "image/webp" ? 1 : 2;
        await sendRow(this.sendCtx(c, echo.key), c, {
          type: P.MT.IMAGE,
          image: { id: P.fromB64u(id), k: key, mime, w: img.w, h: img.h },
        });
        if (c.messages.some((m) => m.key === echo.key)) this.markEcho(c, echo.key, "sent");
      } catch (e) {
        for (const [kk, x] of this.echoes) if (x.echoKey === echo.key) this.echoes.delete(kk);
        this.markEcho(c, echo.key, "failed");
        if (!(e instanceof SessionEnded)) this.h.error(message(e));
      } finally {
        this.h.progress("");
      }
    };
    const prev = this.sendChains.get(convId) ?? Promise.resolve();
    const next = prev.then(run, run);
    this.sendChains.set(convId, next);
    return this.h.track(next);
  }

  /** Downloads, checks and decrypts an image; cached by `id.k` (§8.1). Resolves with an object URL. */
  loadImage(img: { id: string; k: string; mime: string }): Promise<string> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(img.id) || !/^[A-Za-z0-9_-]{43}$/.test(img.k))
      return Promise.reject(new Error("bad image reference"));
    if (img.mime !== "image/webp" && img.mime !== "image/jpeg")
      return Promise.reject(new Error("bad image type"));
    const cacheKey = `${img.id}.${img.k}`;
    let p = this.imageCache.get(cacheKey);
    if (!p) {
      p = (async () => {
        const got = await this.h.api.getBlobUpTo(P.fromB64u(img.id), P.BLOB_MAX);
        if (!got) throw new Error("image not found");
        const data = P.decryptBlob(got, img.id, P.fromB64u(img.k));
        return URL.createObjectURL(new Blob([data as BlobPart], { type: img.mime }));
      })();
      this.imageCache.set(cacheKey, p);
      p.catch(() => this.imageCache.delete(cacheKey));
    }
    return p;
  }

  // ───────────────────────── sending (§11.3) ─────────────────────────

  private addEcho(c: Copy, kind: "text" | "image", text: string): MessageView {
    const m: MessageView = {
      key: `local:${++this.localCounter}`,
      seq: 0,
      from: this.h.acc.uidB,
      fromHandle: this.h.acc.handle,
      mine: true,
      ts: Math.floor(this.h.clock.wall()),
      kind,
      text,
      status: "sending",
    };
    c.messages.push(m);
    this.h.changed();
    return m;
  }

  private markEcho(c: Copy, key: string, status: MessageView["status"]): void {
    const i = c.messages.findIndex((m) => m.key === key);
    if (i >= 0) c.messages[i] = { ...c.messages[i], status };
    this.h.changed();
  }

  private sendCtx(c: Copy, echoKey: string | null): SendCtx {
    return {
      api: this.h.api,
      clock: this.h.clock,
      params: () => this.params(),
      selfUid: this.h.acc.uid,
      sigSk: this.h.acc.id.sigSk,
      processingWait: this.h.delays.processingWait,
      check: () => this.h.check(),
      probeControl: (cc) =>
        this.h.enqueue(() => syncLanes(this.syncCtx(), this.controlTarget(cc), false)),
      wait: (ms) => this.h.wait(ms),
      applyOwn: (cc, ep, row) => this.applyOwn(cc, ep, row),
      expectEcho: (key) => {
        if (echoKey) this.echoes.set(key, { c, echoKey });
      },
      beforePutAttempt: this.h.opts.beforePutAttempt,
      progress: (t) => this.h.progress(t),
    };
  }

  private controlTarget(c: Copy): LaneTarget[] {
    const ep = currentEpoch(c);
    return [{ c, ep, lane: "ctl" }];
  }

  sendText(convId: string, text: string): Promise<void> {
    const c = this.copy(convId);
    const body = text.replace(/\s+$/, "");
    if (!body.trim()) return Promise.resolve();
    if (P.utf8(body).length > MAX_TEXT_BYTES)
      return Promise.reject(new UserError("message is too long"));
    const echo = this.addEcho(c, "text", body);
    const run = async () => {
      try {
        if (c.request) await this.accept(c);
        await sendRow(this.sendCtx(c, echo.key), c, { type: P.MT.TEXT, text: body });
        if (c.messages.some((m) => m.key === echo.key)) this.markEcho(c, echo.key, "sent");
      } catch (e) {
        for (const [k, x] of this.echoes) if (x.echoKey === echo.key) this.echoes.delete(k);
        this.markEcho(c, echo.key, "failed");
        if (!(e instanceof SessionEnded)) this.h.error(message(e));
      } finally {
        this.h.progress("");
      }
    };
    const prev = this.sendChains.get(convId) ?? Promise.resolve();
    const next = prev.then(run, run);
    this.sendChains.set(convId, next);
    return this.h.track(next);
  }

  /** Every send chain (the harness waits for them). */
  get chains(): Map<string, Promise<unknown>> {
    return this.sendChains;
  }

  // ───────────────────────── HEADS (§7.2, §7.3) ─────────────────────────

  private markHeads(): void {
    this.headsDue = true;
    if (this.headsTimer || this.stopped || !this.live) return;
    this.headsTimer = true;
    const d = this.h.delays;
    const ms = d.headsInterval + Math.floor(Math.random() * d.headsJitter);
    void this.h
      .track(
        this.h.wait(ms).then(async () => {
          this.headsTimer = false;
          await this.flushHeads();
        }),
      )
      .catch(() => {
        this.headsTimer = false;
      });
  }

  /** The HEADS entry of a copy: its current epoch's positions, never past an unsealed earlier era (§7.2, §11.2). */
  private headsEntry(c: Copy): P.HeadsEntry | null {
    const ep = c.epochs.get(c.current);
    if (!ep || ep.Estart === null) return null;
    return {
      conv: c.conv,
      root: c.root,
      e: ep.e,
      lastTs: Math.max(0, Math.floor(c.lastTs)),
      ctl: { E: ep.ctl.next.E, cnt: ep.ctl.next.n },
      lanes: ep.lanes.map((l) => {
        const at = l.tail ?? l.next;
        return { E: at.E, cnt: at.n };
      }),
      followed: [],
    };
  }

  /** Writes a HEADS row (cursor, every copy's entry, waiting CONTACT and MEMBER records) when something moved. */
  async flushHeads(): Promise<void> {
    if (!this.live || this.stopped) return;
    await this.h.enqueue(async () => {
      if (!this.headsDue && this.pendingRecords.length === 0) return;
      this.headsDue = false;
      const p = await this.h.api.params();
      const cursor =
        this.cursor ?? cursorAt(P.eraStart(this.h.acc.regEra), p, P.era(this.h.api.serverNow()));
      const entries = [...this.copies.values()]
        .map((c) => this.headsEntry(c))
        .filter((x): x is P.HeadsEntry => x !== null);
      const sig = JSON.stringify([
        cursor,
        entries.map((x) => [P.b64u(x.conv), x.e, x.ctl, x.lanes, x.lastTs]),
      ]);
      const recs = this.pendingRecords;
      if (sig === this.lastHeads && recs.length === 0) return;
      // Split the entries over records that each fit a row with the waiting records (§7.3 "HEADS splitting").
      const chunks: P.HeadsEntry[][] = [[]];
      let size = recs.reduce((n, r) => n + P.encodeRecord(r).length, 0) + 11;
      for (const x of entries) {
        const len = 68 + 6 * x.lanes.length + 12 * x.followed.length;
        if (chunks[chunks.length - 1].length > 0 && size + len > ROW_BUDGET) {
          chunks.push([]);
          size = 11;
        }
        chunks[chunks.length - 1].push(x);
        size += len;
      }
      for (let i = 0; i < chunks.length; i++) {
        const heads: P.HeadsRec = {
          rtype: P.RT.HEADS,
          Ein: cursor.E,
          relIn: cursor.rel,
          entries: chunks[i],
        };
        await this.h.self.write(i === 0 ? [...recs, heads] : [heads]);
      }
      this.pendingRecords = this.pendingRecords.filter((r) => !recs.includes(r));
      this.lastHeads = sig;
    });
  }

  // ───────────────────────── views ─────────────────────────

  views(): ConversationView[] {
    const x = {
      selfUid: this.h.acc.uid,
      selfHandle: this.h.acc.handle,
      user: (uidB: string) => this.knownUser(uidB),
      copiesOf: (convB: string) => this.copiesOf(convB).length,
      mono: this.h.clock.mono(),
      processingWait: this.h.delays.processingWait,
    };
    const out: ConversationView[] = [];
    for (const c of this.copies.values()) {
      const v = viewOf(c, x);
      if (v) out.push(v);
    }
    return out.sort((a, b) => b.lastTs - a.lastTs);
  }
}

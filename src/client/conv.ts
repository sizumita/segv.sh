// Conversation copies as this device holds them (docs/PROTOCOL.md §11.2): epochs, lanes and positions, the
// message list in the order of §11.8, names (§5.1) and the view the UI renders. Pure state: the probing, sending and
// joining modules change it, and the engine builds views from it.
import * as P from "~/lib/proto";
import { UserError } from "./errors";
import type { Blocked, ConversationView, MemberView, MessageView } from "./types";

type Bytes = Uint8Array;

/** Lane lookahead and gallop chunk (§11). */
export const W_SLOTS = 8;
/** Probe depth of an idle lane (§11). */
export const P0 = 2;
export const HISTORY_INITIAL = 30;
export const HISTORY_COPIES = 20;
export const VIEW_MESSAGES = 500;
export const MAX_TEXT_BYTES = 12_000;
export const SEND_ATTEMPTS = 8;
/** Shown times are clamped to the row's stored time ± this (§11.8). */
const TS_SLACK_MS = 300_000;

export const NOT_MEMBER = "you are no longer a member of this conversation";
export const CHANGING = "the conversation is changing membership; try again in a moment";
export const NOT_DELIVERED =
  "message was not delivered (membership changed or the request failed); try again";

/** A slot (E, n) of a lane. */
export interface Slot {
  E: number;
  n: number;
}

/** A stored row this device saw: what the next own row's prev fields point to (§3.3). */
export interface RowRef extends Slot {
  label: Bytes;
  body: Bytes;
}

/**
 * One lane of an epoch (§11.2). `next` is the first slot not yet processed: every occupied slot of the dense prefix
 * before it was processed (§7.2's processed position is `(next.E, next.n)`). `tail`, when set, is the slot after the
 * dense prefix of an earlier era with rows that has not been observed sealed yet: a sibling may still write there
 * (§11.2 expected-label map, §11.7), so it is probed until `MISS(sealed = 1)` or a HIT, and no position past it is
 * recorded in HEADS.
 */
export interface Lane {
  next: Slot;
  tail: Slot | null;
  /** the member's last valid row on this lane in this epoch (prev / prevh of the next own row) */
  last: RowRef | null;
  /** a valid row of this member has been seen in this epoch */
  seen: boolean;
  /** the oldest valid row loaded, with its prev pointer (scrollback continues below it, §11.10) */
  oldest: { E: number; n: number; prev: Slot } | null;
  /** the dense-prefix end in the latest era with rows, as observed: a commit's cut for this lane (§6.2, §6.3 step 6) */
  head: P.EraCount | null;
  /**
   * For a lane of an epoch below the current one: walked to its head after it stopped being followed (§11.2
   * "Sweeping"). A lane that is not swept is a followed lane, or one still to sweep once more.
   */
  swept: boolean;
  /** prevh(label, body) of the rows of this lane this session holds, by "E:n" (§12.2 "Every row") */
  prevhs: Map<string, Bytes>;
  /** the prevh a held row expects of the row at "E:n", which this session has not loaded yet (§12.2) */
  expect: Map<string, Bytes>;
}

/** A stored row: its slot, label, stored time (seconds since T0) and body. */
export interface StoredRow extends Slot {
  label: Bytes;
  t: number;
  body: Bytes;
}

/** The first e-valid row of a control lane (§6.5), with what its evaluation fetched. */
export interface Winner extends StoredRow {
  claim: P.Claim;
  from: number;
  /** the claim row's sender time (ms), for its system lines */
  ts: number;
  /** t_reg of the claim's bundle: E_start of epoch e+1 */
  tReg: number;
  blob: Bytes;
  final: boolean;
  processed: boolean;
}

/** The control lane of an epoch (§6.4–§6.6). */
export interface ControlLane {
  /** the first slot not yet decided: every row before it in the dense prefix is not e-valid */
  next: Slot;
  /** rows found at or after `next`, in lane order, waiting to be decided */
  queue: StoredRow[];
  /** eras whose dense-prefix end was observed MISS(sealed = 1) (finality, §6.5) */
  sealed: Set<number>;
  /** the dense-prefix length observed per era (where finality probes an unsealed era's end) */
  counts: Map<number, number>;
  winner: Winner | null;
  /** monotonic time since an undecided slot, or a winner not yet final or processed, has stood (§11.3 step 2) */
  pendingSince: number | null;
  /** an undecided row is evaluated again no sooner than this (monotonic; back-off 1 s doubling to 60 s) */
  retryAt: number;
  attempt: number;
}

/** The claim that ended an epoch (its processed final winner): what the §6.8 walk reads. */
export interface Ended {
  t: number;
  rm: number;
  cuts: readonly P.Cut[];
  at: Slot;
}

/**
 * The kept source of a member's leave in an epoch (§6.9 "Several sources"): its LEAVE row's stored time and, in that
 * row's own epoch, the row's position (NONE for a leave carried into the epoch, or one taken from a LEFT record that
 * says so). `key` and `order` locate the row's "@x left" line when this device applied the row itself.
 */
export interface LeaveSource {
  t: number;
  row: P.Pos;
  key: string | null;
  order: number[] | null;
}

/** An applied lane row, kept so that §6.8 can be decided again when a new final winner is learned. */
export interface AppliedRow {
  j: number;
  E: number;
  n: number;
  t: number;
  /** the row counted toward `unread` */
  unread: boolean;
  /** the row is in the view (false: §6.8 dropped it) */
  shown: boolean;
  /** reactTh(rk_e, label, body): what a REACTION to this row names (§3.3, §11.12) */
  th: Bytes;
}

/** A REACTION row the device applied (§11.12): its position and member, and what it reacts to. */
export interface ReactionRow {
  /** the row's epoch, lane (its member's index there), slot and stored time */
  e: number;
  j: number;
  E: number;
  n: number;
  t: number;
  /** the member, by b64u uid */
  uid: string;
  /** the row passed §6.8 when applied (and the copy was not left then) */
  shown: boolean;
  reaction: P.Reaction;
}

export interface Epoch {
  e: number;
  EK: Bytes;
  keys: P.EpochKeys;
  D: P.Descriptor;
  dsig: Bytes;
  bundleId: Bytes;
  bundleSize: number;
  /** era(t_reg) of the bundle: no row of the epoch is in an earlier era (§4.2); null until known */
  Estart: number | null;
  /** t_reg (seconds since T0), when known */
  tReg: number | null;
  /** pks of the bundle (kemPk per member, §5.4), when this device opened the bundle */
  pks: Bytes | null;
  /** T_e */
  topic: Bytes;
  myIndex: number;
  lanes: Lane[];
  ctl: ControlLane;
  /** the claim that ended this epoch, once processed (or read at its record's position) */
  ended: Ended | null;
  /**
   * The position of the claim that ended the copy here, from its ENDED record, while that claim is not read yet: the
   * copy has ended, and the claim is read only when a row of the epoch is decided or its history loads (§11.4 step 5).
   */
  endedAt: P.Pos | null;
  /** the kept leave source of each member recorded as left here, by b64u uid (self's own leave is `Copy.left`) */
  left: Map<string, LeaveSource>;
  /** its lanes are processed (false only below the HEADS epoch of a restore, §11.4 step 5) */
  lanesOn: boolean;
  /** the valid rows applied in this epoch, of any type (the initial history's "fewer than 30 rows", §11.4 step 6) */
  loaded: number;
  /** applied TEXT and IMAGE rows by message key (§6.8 retraction) */
  rows: Map<string, AppliedRow>;
}

export interface Copy {
  /** the view key: b64u(conv), or b64u(conv)~i for a later copy (§7.3 "Copy keys") */
  key: string;
  conv: Bytes;
  convB: string;
  /** H(D) of the first epoch the account accepted */
  root: Bytes;
  /** that epoch: the copy holds every epoch from it to `current`, though a restore materializes them from its start */
  rootE: number;
  /**
   * The highest epoch whose key the snapshot's CONV_JOIN or flag-0 EPOCH records give, while a restore has not reached
   * it: the epochs below it are reached by the claims those records name, read without probing (§11.4 step 5).
   */
  top: number | null;
  /** D.by of that epoch */
  rootBy: Bytes;
  request: boolean;
  confirmed: boolean;
  epochs: Map<number, Epoch>;
  current: number;
  removed: boolean;
  left: boolean;
  frozen: null | "nokey" | "invalid";
  messages: MessageView[];
  /** sort keys of applied rows and system lines, by message key (local echoes have none: they go last) */
  order: Map<string, number[]>;
  unread: number;
  lastTs: number;
  /** a creation in steps 6–9 (§6.1): own sends wait for the decoy */
  ready: Promise<void>;
  /** the initial history was loaded (§11.4 step 6) */
  history: boolean;
  /** members (b64u uid) whose LEAVE row was seen in this copy (a WELCOME never goes to them, §6.12 step 1) */
  leaves: Set<string>;
  /** scrollback ran in this session (once per copy, §11.10) */
  scrolled: boolean;
  /** system lines whose text is rendered again when handles resolve or the leave state changes, by message key */
  lines: Map<string, () => string>;
  /** the HEADS entry a restore starts from, until the copy reaches its epoch (§11.4 step 5) */
  heads: P.HeadsEntry | null;
  /**
   * The copy that a J below the root of every live copy would start, settled before §6.7 step 6 decides the J: not
   * held (no topics, records, warnings or welcomes) until it is kept as an ended copy.
   */
  probe: boolean;
  /** the REACTION rows applied, by row key (§11.12) */
  reactions: Map<string, ReactionRow>;
  /** the reactions shown on the messages are to be computed again (a row, a target or a §6.8 decision changed) */
  reactionsDirty: boolean;
}

/** The epoch the copy was joined at: its root epoch (every epoch above it is held, §6.6 step 3). */
export const rootEpoch = (c: Copy): number => c.rootE;

/**
 * Two held copies of one conversation contest each other (§6.7 step 6): two that have not ended always do; an ended
 * copy and another do while the other holds one of its epochs or the epoch after its last; and an ended copy rooted
 * at r and a copy rooted below r do while the latter holds r − 1 or has not ended. `endOf` gives the epoch at which a
 * copy ended, or null: a copy whose ENDED record the fold holds counts as ended at that record's epoch, also before
 * the device brought it there.
 */
export function contest(
  a: Copy,
  b: Copy,
  endOf: (c: Copy) => number | null = (c) => (c.removed ? c.current : null),
): boolean {
  const ea = endOf(a);
  const eb = endOf(b);
  if (ea === null && eb === null) return true;
  const last = (y: Copy, ey: number | null) => ey ?? y.current;
  const holds = (y: Copy, ey: number | null, lo: number, hi: number) =>
    rootEpoch(y) <= hi && last(y, ey) >= lo;
  const against = (x: Copy, ex: number | null, y: Copy, ey: number | null): boolean => {
    if (ex === null) return false;
    const r = rootEpoch(x);
    if (holds(y, ey, r, ex + 1)) return true;
    return rootEpoch(y) < r && (ey === null || holds(y, ey, r - 1, r - 1));
  };
  return against(a, ea, b, eb) || against(b, eb, a, ea);
}

/** The fold key of a copy: (conv, root). */
export const copyKeyOf = (c: { conv: Bytes; root: Bytes }): string =>
  `${P.b64u(c.conv)}.${P.b64u(c.root)}`;

/** A row's message key: era and label hex (§0.3 `MessageView.key`). */
export const rowKey = (E: number, label: Bytes): string => `${E}:${P.hex(label)}`;

export function newLane(start: Slot): Lane {
  return {
    next: { ...start },
    tail: null,
    last: null,
    seen: false,
    oldest: null,
    head: null,
    swept: false,
    prevhs: new Map(),
    expect: new Map(),
  };
}

/** An epoch's state from its key material and its verified descriptor. */
export function newEpoch(x: {
  e: number;
  EK: Bytes;
  D: P.Descriptor;
  dsig: Bytes;
  bundleId: Bytes;
  bundleSize: number;
  tReg: number | null;
  pks: Bytes | null;
  self: Bytes;
}): Epoch {
  const keys = P.epochKeys(x.EK, x.D.conv, x.e);
  const Estart = x.tReg === null ? null : eraOfSec(x.tReg);
  const start = { E: Estart ?? 0, n: 0 };
  return {
    e: x.e,
    EK: x.EK,
    keys,
    D: x.D,
    dsig: x.dsig,
    bundleId: x.bundleId,
    bundleSize: x.bundleSize,
    Estart,
    tReg: x.tReg,
    pks: x.pks,
    topic: P.topicConv(keys.nk),
    myIndex: P.memberIndex(x.D, x.self),
    lanes: x.D.members.map(() => newLane(start)),
    ctl: newControl(start),
    ended: null,
    endedAt: null,
    left: new Map(),
    lanesOn: true,
    loaded: 0,
    rows: new Map(),
  };
}

/** The era of a stored time in seconds since T0. */
export const eraOfSec = (t: number): number => Math.floor(t / (P.ERA_MS / 1000));

export function newControl(start: Slot): ControlLane {
  return {
    next: { ...start },
    queue: [],
    sealed: new Set(),
    counts: new Map(),
    winner: null,
    pendingSince: null,
    retryAt: 0,
    attempt: 0,
  };
}

/** The kemPk of member j from the epoch's bundle (§5.4), or null when this device did not open the bundle. */
export function pkOf(ep: Epoch, j: number): Bytes | null {
  if (!ep.pks) return null;
  return ep.pks.slice(j * 1216, (j + 1) * 1216);
}

export function currentEpoch(c: Copy): Epoch {
  const ep = c.epochs.get(c.current);
  if (!ep) throw new UserError("conversation not ready");
  return ep;
}

// ───────────────────────── messages (§11.8) ─────────────────────────

/** The shown time: the sender's ts clamped to the row's stored time ± 5 min (§11.8). */
export function clampTs(ts: number, t: number, deltaS: number): number {
  const lo = P.T0_MS + t * 1000 - TS_SLACK_MS;
  const hi = P.T0_MS + (t + deltaS) * 1000 + TS_SLACK_MS;
  return Math.min(Math.max(ts, lo), hi);
}

function cmpOrder(a: number[] | undefined, b: number[] | undefined): number {
  if (!a || !b) return a ? -1 : b ? 1 : 0; // local echoes (no order) last
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? -1) - (b[i] ?? -1);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * Inserts an applied message at its place in the order `(clamped ts, epoch, E, lane, n)` (§11.8); local echoes stay
 * last. Returns false when a message with this key is already there.
 */
export function insertMessage(c: Copy, m: MessageView, order: number[]): boolean {
  if (c.order.has(m.key)) return false;
  c.order.set(m.key, order);
  let i = c.messages.length;
  while (i > 0 && cmpOrder(c.order.get(c.messages[i - 1].key), order) > 0) i--;
  c.messages.splice(i, 0, m);
  if (m.kind !== "system" || m.ts > 0) c.lastTs = Math.max(c.lastTs, m.ts);
  return true;
}

export function removeMessage(c: Copy, key: string): void {
  const i = c.messages.findIndex((m) => m.key === key);
  if (i >= 0) c.messages.splice(i, 1);
  c.order.delete(key);
}

export function systemLine(key: string, ts: number, text: string): MessageView {
  return {
    key,
    seq: 0,
    from: "",
    fromHandle: "",
    mine: false,
    ts,
    kind: "system",
    text,
    status: "sent",
    reactions: [],
  };
}

// ───────────────────────── names (§5.1, §11.9) ─────────────────────────

/**
 * Cleans a new group name: control and format characters become spaces, whitespace is collapsed, at most 64 code
 * points. A name that would look like a person (a leading "@") is refused. Returns undefined for no name.
 */
export function cleanName(name?: string): string | undefined {
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

/** The name as displayed: D's name only when it passes the local validName (§5.1), else none. */
export const displayName = (D: P.Descriptor): string | null =>
  D.name !== null && P.validName(D.name) ? D.name : null;

// ───────────────────────── members (§11.2) ─────────────────────────

/** What this device knows of a user from its MEMBER record or a verified directory bundle. */
export interface KnownUser {
  handle: string;
  sigPk: Bytes;
  kh: Bytes;
  /** the directory kemPk, when this session verified the bundle (a MEMBER record holds only kh) */
  kemPk: Bytes | null;
}

export const unknownHandle = (uidB: string): string => `?${uidB.slice(0, 8)}`;

/**
 * A member's displayed handle: its handle when its MEMBER record (or verified bundle) carries exactly the keys D
 * lists, else `?` + 8 uid characters (§11.2). `mismatch` is true when the keys differ (the critical warning).
 */
export function memberHandle(
  m: P.Member,
  known: KnownUser | undefined,
): { handle: string; mismatch: boolean } {
  const uidB = P.b64u(m.uid);
  if (!known) return { handle: unknownHandle(uidB), mismatch: false };
  if (!P.equalBytes(known.sigPk, m.sigPk) || !P.equalBytes(known.kh, m.kh))
    return { handle: unknownHandle(uidB), mismatch: true };
  return { handle: known.handle, mismatch: false };
}

// ───────────────────────── views ─────────────────────────

export interface ViewCtx {
  selfUid: Bytes;
  selfHandle: string;
  /** a user by b64u uid */
  user(uidB: string): KnownUser | undefined;
  /** the copy is contested by another held copy of its conversation (§6.7 step 6: ⚠ unless confirmed) */
  contested(c: Copy): boolean;
  /** the copy's `rootBy` is self or a contact (§11.11 `byContact`) */
  byContact(c: Copy): boolean;
  /** monotonic now (for the 30 s processing wait) */
  mono: number;
  processingWait: number;
}

// ───────────────────────── leaves and the §6.8 walk ─────────────────────────

/** The consecutive held epochs from e on, as §6.8 walks them (a walk never crosses copies). */
export function walkEpochs(c: Copy, e: number): P.WalkEpoch[] {
  const out: P.WalkEpoch[] = [];
  for (let k = e; ; k++) {
    const ep = c.epochs.get(k);
    if (!ep) break;
    out.push({
      members: ep.D.members.map((m) => m.uid),
      claim: ep.ended ? { t: ep.ended.t, rm: ep.ended.rm, cuts: ep.ended.cuts } : null,
    });
  }
  return out;
}

/**
 * §6.8 for a valid row of member i of epoch e at `pos` (NONE for a carried leave) stored at `t`. A claim the walk
 * needs and this device does not hold never makes it accept.
 */
export function acceptedOld(c: Copy, e: number, i: number, pos: P.Pos, t: number): boolean {
  const list = walkEpochs(c, e);
  const last = c.epochs.get(e + list.length - 1);
  const selfRemoved = !!last?.ended && last.myIndex >= 0 && P.rmHas(last.ended.rm, last.myIndex);
  try {
    return P.acceptOldRow({ i, E: pos.E, n: pos.n, t }, list, selfRemoved);
  } catch {
    return false;
  }
}

/** The member (b64u uid) is recorded as left in epoch ep (§6.9): it has a kept source there that §6.8 accepts. */
export function leftIn(c: Copy, ep: Epoch, uidB: string): boolean {
  const s = ep.left.get(uidB);
  if (!s) return false;
  const i = ep.D.members.findIndex((m) => P.b64u(m.uid) === uidB);
  return i >= 0 && acceptedOld(c, ep.e, i, s.row, s.t);
}

/** The order of leave sources (§6.9): by t, then position, NONE after every real position. */
export function sourceCmp(a: { t: number; row: P.Pos }, b: { t: number; row: P.Pos }): number {
  if (a.t !== b.t) return a.t - b.t;
  const an = P.isNone(a.row);
  const bn = P.isNone(b.row);
  if (an || bn) return an === bn ? 0 : an ? 1 : -1;
  return P.posCmp(a.row, b.row);
}

/**
 * The frozen-with-removal gate (§6.6 step 6, §11.3 step 2): the claim that froze the epoch has an rm bit for a member
 * who had not left, by the current leave state.
 */
export function frozenWithRemoval(c: Copy, ep: Epoch): boolean {
  const w = ep.ctl.winner;
  if (c.frozen === null || !w) return false;
  return ep.D.members.some((m, j) => P.rmHas(w.claim.rm, j) && !leftIn(c, ep, P.b64u(m.uid)));
}

function blockedOf(c: Copy, ep: Epoch, x: ViewCtx): Blocked {
  if (c.removed) return "removed";
  if (c.left) return "left";
  if (frozenWithRemoval(c, ep)) return "frozen";
  if (ep.ctl.pendingSince !== null && x.mono - ep.ctl.pendingSince >= x.processingWait)
    return "pending";
  return "";
}

export function viewOf(c: Copy, x: ViewCtx): ConversationView | null {
  const ep = c.epochs.get(c.current);
  if (!ep) return null;
  const members: MemberView[] = ep.D.members.map((m, j) => {
    const uidB = P.b64u(m.uid);
    const self = P.equalBytes(m.uid, x.selfUid);
    // a request's members other than its D.by (rootBy) are unknown until it is opened (§11.5)
    const known = c.request && !self && !P.equalBytes(m.uid, c.rootBy) ? undefined : x.user(uidB);
    const handle = self ? x.selfHandle : memberHandle(m, known).handle;
    const kemPk = pkOf(ep, j) ?? known?.kemPk ?? null;
    return {
      uid: uidB,
      handle,
      fingerprint:
        kemPk && (self || !handle.startsWith("?")) ? P.fingerprint(m.uid, m.sigPk, kemPk) : "",
      left: self ? c.left : leftIn(c, ep, uidB),
    };
  });
  const others = members.filter((m) => m.uid !== P.b64u(x.selfUid)).map((m) => "@" + m.handle);
  const name = displayName(ep.D);
  const blocked = blockedOf(c, ep, x);
  return {
    id: c.key,
    name:
      (!c.confirmed && x.contested(c) ? "⚠ " : "") +
      (name ? `# ${name}` : others.join(", ") || "just you"),
    members,
    epoch: ep.e,
    canSend: blocked === "",
    blocked,
    frozen: c.frozen !== null,
    request: c.request,
    byContact: x.byContact(c),
    lastTs: c.lastTs,
    unread: c.unread,
    messages:
      c.messages.length > VIEW_MESSAGES ? c.messages.slice(-VIEW_MESSAGES) : c.messages.slice(),
  };
}

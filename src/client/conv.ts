// Conversation copies as this device holds them (docs/PROTOCOL-v2.md §11.2): epochs, lanes and positions, the
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
}

/** The control lane of an epoch, before claims are processed (claims land with M7). */
export interface ControlLane {
  next: Slot;
  /** a row that opens as a claim of this epoch was found: membership is changing (undecided until M7 evaluates it) */
  claimSeen: boolean;
  /** monotonic time when `claimSeen` became true (the 30 s processing wait of §11.3 step 2) */
  claimSince: number | null;
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
}

export interface Copy {
  /** the view key: b64u(conv), or b64u(conv)~i for a later copy (§7.3 "Copy keys") */
  key: string;
  conv: Bytes;
  convB: string;
  /** H(D) of the first epoch the account accepted */
  root: Bytes;
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
}

/** The fold key of a copy: (conv, root). */
export const copyKeyOf = (c: { conv: Bytes; root: Bytes }): string =>
  `${P.b64u(c.conv)}.${P.b64u(c.root)}`;

/** A row's message key: era and label hex (§0.3 `MessageView.key`). */
export const rowKey = (E: number, label: Bytes): string => `${E}:${P.hex(label)}`;

export function newLane(start: Slot): Lane {
  return { next: { ...start }, tail: null, last: null, seen: false };
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
    ctl: { next: { ...start }, claimSeen: false, claimSince: null },
  };
}

/** The era of a stored time in seconds since T0. */
export const eraOfSec = (t: number): number => Math.floor(t / (P.ERA_MS / 1000));

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
  /** how many copies of this conv the device holds */
  copiesOf(convB: string): number;
  /** monotonic now (for the 30 s processing wait) */
  mono: number;
  processingWait: number;
}

function blockedOf(c: Copy, ep: Epoch, x: ViewCtx): Blocked {
  if (c.removed) return "removed";
  if (c.left) return "left";
  if (
    ep.ctl.claimSeen &&
    ep.ctl.claimSince !== null &&
    x.mono - ep.ctl.claimSince >= x.processingWait
  )
    return "pending";
  return "";
}

export function viewOf(c: Copy, x: ViewCtx): ConversationView | null {
  const ep = c.epochs.get(c.current);
  if (!ep) return null;
  const members: MemberView[] = ep.D.members.map((m, j) => {
    const uidB = P.b64u(m.uid);
    const self = P.equalBytes(m.uid, x.selfUid);
    // a request's members other than D.by are unknown until it is opened (§11.5)
    const known = c.request && !self && !P.equalBytes(m.uid, ep.D.by) ? undefined : x.user(uidB);
    const handle = self ? x.selfHandle : memberHandle(m, known).handle;
    const kemPk = pkOf(ep, j) ?? known?.kemPk ?? null;
    return {
      uid: uidB,
      handle,
      fingerprint:
        kemPk && (self || !handle.startsWith("?")) ? P.fingerprint(m.uid, m.sigPk, kemPk) : "",
      left: false,
    };
  });
  const others = members.filter((m) => m.uid !== P.b64u(x.selfUid)).map((m) => "@" + m.handle);
  const name = displayName(ep.D);
  const blocked = blockedOf(c, ep, x);
  return {
    id: c.key,
    name:
      (!c.confirmed && x.copiesOf(c.convB) > 1 ? "⚠ " : "") +
      (name ? `# ${name}` : others.join(", ") || "just you"),
    members,
    epoch: ep.e,
    canSend: blocked === "",
    blocked,
    frozen: c.frozen !== null,
    request: c.request,
    lastTs: c.lastTs,
    unread: c.unread,
    messages:
      c.messages.length > VIEW_MESSAGES ? c.messages.slice(-VIEW_MESSAGES) : c.messages.slice(),
  };
}

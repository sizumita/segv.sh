// Plain helpers shared by the UI components (no Qwik APIs, no secrets).
import {
  MAX_LIVE_ALIASES,
  type ConversationView,
  type Engine,
  type EngineState,
  type IdentityView,
  type MemberView,
  type MessageView,
  type PersonView,
} from "@segv/engine/types";
import { loadEngine } from "./engine-loader";
import type { ListView, UiState } from "./state";

// Mirrors of packages/protocol/src/proto.ts (HANDLE_RE, MAX_MEMBERS, MAX_NAME), kept in sync by
// util.test.ts. Not imported from proto on purpose: UI modules are also part of the SSR
// bundle, and sharing a module with the /api code there turns the Worker entry chunk into a
// shared chunk with extra exports, which workerd refuses to load.
export const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
export const MAX_MEMBERS = 32;
export const MAX_NAME = 64;

/** UTF-8 budget for the JSON-encoded text field of a message payload. The padded payload class
 * is 16 KiB (PROTOCOL §3.5); this leaves room for the other fields + signature. The engine
 * remains the authority and may reject earlier. */
export const MAX_TEXT_JSON_BYTES = 15_000;
/** Refuse to even try decoding absurdly large picks (the engine re-encodes to ≤ 8 MiB). */
export const MAX_IMAGE_INPUT_BYTES = 50 * 1024 * 1024;
/** Mirror of FILE_MAX (packages/protocol/src/proto.ts, §8.3): the largest file the engine sends. */
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
/** Mirror of MAX_EMOJI_BYTES (packages/protocol/src/proto.ts, §3.3): the longest emoji a reaction carries, in UTF-8. */
export const MAX_EMOJI_BYTES = 32;

export function errMsg(e: unknown): string {
  let s = "";
  if (e instanceof Error) s = e.message;
  else if (typeof e === "string") s = e;
  s = s.trim();
  if (!s) return "something went wrong";
  return s.length > 300 ? `${s.slice(0, 300)}…` : s;
}

/** Runs an engine call; a rejection becomes `ui.localError` instead of an unhandled error. */
export async function act<T>(ui: UiState, fn: (e: Engine) => Promise<T>): Promise<T | undefined> {
  ui.localError = "";
  try {
    return await fn(await loadEngine());
  } catch (e) {
    ui.localError = errMsg(e);
    return undefined;
  }
}

/**
 * Makes a temporary handle (`createAlias`, §2.6), one at a time: `ui.makingAlias` holds while it runs. Resolves with
 * its uid, or undefined when it failed (`ui.localError` says why) or another one is being made.
 */
export async function makeAlias(ui: UiState): Promise<string | undefined> {
  if (ui.makingAlias) return undefined;
  ui.makingAlias = true;
  try {
    return await act(ui, (e) => e.createAlias());
  } finally {
    ui.makingAlias = false;
  }
}

const chains = new Map<string, Promise<unknown>>();
/** Serialises async work per key (e.g. sends within one conversation keep their order). */
export function enqueue(key: string, fn: () => Promise<unknown>): Promise<unknown> {
  const prev = chains.get(key) ?? Promise.resolve();
  const next = prev.catch(() => undefined).then(fn);
  chains.set(key, next);
  void next
    .finally(() => {
      if (chains.get(key) === next) chains.delete(key);
    })
    .catch(() => undefined);
  return next;
}

export function normaliseHandle(raw: string): string {
  return raw.normalize("NFKC").trim().replace(/^@+/, "").toLowerCase();
}

export const isHandle = (h: string): boolean => HANDLE_RE.test(h);

/** Only a temporary handle starts with `_` (§2.6): nobody registers one of their choosing. */
export const isReservedHandle = (h: string): boolean => h.startsWith("_");

/** "bob, @Carol  dave、ｅｒｉｎ" -> ["bob","carol","dave","erin"], in order, repeats kept. */
export function splitHandles(raw: string): string[] {
  return raw
    .normalize("NFKC")
    .split(/[\s,、;]+/)
    .map(normaliseHandle)
    .filter(Boolean);
}

const NOT_A_HANDLE = "(3–20 of a–z 0–9 _)";
const YOURSELF = "you are always included — leave yourself out";
const yours = (h: string) => `@${h} is one of your own handles`;
const TOO_MANY = `at most ${MAX_MEMBERS} members per conversation`;

export type ParsedHandles = { ok: true; handles: string[] } | { ok: false; error: string };

/**
 * "bob, @carol dave" -> ["bob","carol","dave"] (also accepts 、 and ， from Japanese IMEs), for the account whose
 * handle is `self`, into a conversation whose members are `existing` (self among them, if any). `own` are the user's
 * other handles (the owner's and its temporary handles', §2.6), never invited: the others would see that they are all
 * the same person.
 */
export function parseHandles(
  raw: string,
  self?: string,
  existing: readonly string[] = [],
  own: readonly string[] = [],
): ParsedHandles {
  const parts = splitHandles(raw);
  if (!parts.length) return { ok: false, error: "enter at least one handle" };
  const bad = parts.filter((p) => !isHandle(p));
  if (bad.length) {
    return {
      ok: false,
      error: `not a valid handle: ${bad.slice(0, 3).join(", ")} ${NOT_A_HANDLE}`,
    };
  }
  const handles = [...new Set(parts)];
  if (self && handles.includes(self)) return { ok: false, error: YOURSELF };
  const mine = handles.find((h) => own.includes(h));
  if (mine) return { ok: false, error: yours(mine) };
  const dup = handles.filter((h) => existing.includes(h));
  if (dup.length) return { ok: false, error: `already a member: ${dup.map(atHandle).join(", ")}` };
  if (handles.length + Math.max(existing.length, 1) > MAX_MEMBERS) {
    return { ok: false, error: TOO_MANY };
  }
  return { ok: true, handles };
}

/**
 * Adds the handles typed or pasted in `raw` ("bob, @carol") to `chips`, the people a new conversation is started with
 * by the account whose handle is `self`: each valid handle once, never `self` or another of the user's own handles
 * (`own`), and at most MAX_MEMBERS − 1 in all. What is not added stays in `rest`, and `error` says why the first of it
 * was not.
 */
export function addChips(
  chips: readonly string[],
  raw: string,
  self: string,
  own: readonly string[],
): { chips: string[]; rest: string; error: string } {
  const out = [...chips];
  const rest: string[] = [];
  let error = "";
  for (const h of splitHandles(raw)) {
    if (out.includes(h)) continue;
    const why = !isHandle(h)
      ? `not a valid handle: ${h} ${NOT_A_HANDLE}`
      : h === self
        ? YOURSELF
        : own.includes(h)
          ? yours(h)
          : out.length >= MAX_MEMBERS - 1
            ? TOO_MANY
            : "";
    if (!why) out.push(h);
    else if (!rest.includes(h)) {
      rest.push(h);
      error ||= why;
    }
  }
  return { chips: out, rest: rest.join(", "), error };
}

// ---- accounts, people and nicknames ----

/**
 * The user's accounts (§2.6): `state.identities`, or the owner alone from `state.me` while the engine lists none.
 */
export function identitiesOf(s: Pick<EngineState, "identities" | "me">): IdentityView[] {
  if (s.identities.length || !s.me) return s.identities;
  const { uid, handle, fingerprint } = s.me;
  return [{ uid, handle, fingerprint, alias: false, index: -1, retired: false, status: "ready" }];
}

/**
 * An account that runs and can start conversations: the owner, or a temporary handle that is neither retired, failed,
 * nor idle (live, but beyond the MAX_LIVE_ALIASES that this device runs, §2.6).
 */
export const runs = (i: IdentityView): boolean => i.status === "ready" || i.status === "starting";

/** Why no temporary handle can be made or brought back: MAX_LIVE_ALIASES are live (not retired, §2.6). */
export const ALIAS_CAP = `at most ${MAX_LIVE_ALIASES} temporary handles can be active; retire one first`;

/** As many temporary handles are live as can be (§2.6 `MAX_LIVE_ALIASES`). */
export const atAliasCap = (ids: readonly IdentityView[]): boolean =>
  ids.filter((i) => i.alias && !i.retired).length >= MAX_LIVE_ALIASES;

/**
 * A handle as the UI shows it: always with its "@", so that a nickname, which never has one, never reads like a
 * handle (§11.19). An unknown member's `?…` stays as it is; "" stays "".
 */
export const atHandle = (handle: string): string =>
  !handle || handle.startsWith("?") ? handle : `@${handle}`;

/** A user as the UI names them: the nickname the user gave them (§11.19), else their `@handle`. */
export const nameOf = (handle: string, nickname = ""): string => nickname || atHandle(handle);

/** A user with their handle in sight beside a nickname: "Mom (@bob)", or "@bob" (§11.19). */
export const nameWithHandle = (handle: string, nickname = ""): string =>
  nickname ? `${nickname} (${atHandle(handle)})` : atHandle(handle);

/** How names compare in a search: NFKC, trimmed, without a leading @, lower case. */
export const foldName = (s: string): string =>
  s.normalize("NFKC").trim().replace(/^@+/, "").toLowerCase();

/**
 * `q` names a handle only: it starts with "@" (after NFKC and trimming), which no nickname does (§5.1 validName), so
 * that a nickname spelled like a handle never stands for it (§11.19).
 */
export const handleOnly = (q: string): boolean => q.normalize("NFKC").trim().startsWith("@");

/** `q` names `p` exactly: their handle, or their nickname unless `q` is an "@handle". */
export const namesExactly = (p: Pick<PersonView, "handle" | "nickname">, q: string): boolean => {
  const f = foldName(q);
  return (
    f !== "" &&
    (p.handle === f || (!handleOnly(q) && p.nickname !== "" && foldName(p.nickname) === f))
  );
};

/**
 * The people to suggest for `q` (§11.19), except the handles in `skip`: those whose handle or nickname holds it (only
 * the handle for an "@handle"), or everyone for an empty `q`. One whose handle `q` is comes first, then one whose
 * nickname it is, then the contacts of the account `as`, and those that start with `q` before those that only hold it;
 * at most `max`.
 */
export function suggest(
  people: readonly PersonView[],
  q: string,
  as: string,
  skip: readonly string[],
  max = 6,
): PersonView[] {
  const f = foldName(q);
  const handle = handleOnly(q);
  const ranked: { p: PersonView; r: number }[] = [];
  for (const p of people) {
    if (skip.includes(p.handle)) continue;
    // an "@handle" never matches a nickname
    const n = handle ? "" : foldName(p.nickname);
    if (f && !p.handle.includes(f) && !n.includes(f)) continue;
    const exact = !f ? 2 : p.handle === f ? 0 : n !== "" && n === f ? 1 : 2;
    const prefix = !f || p.handle.startsWith(f) || (n !== "" && n.startsWith(f));
    ranked.push({ p, r: exact * 4 + (p.contactOf.includes(as) ? 0 : 2) + (prefix ? 0 : 1) });
  }
  const key = (p: PersonView) => foldName(nameOf(p.handle, p.nickname));
  ranked.sort((a, b) => a.r - b.r || (key(a.p) < key(b.p) ? -1 : key(a.p) > key(b.p) ? 1 : 0));
  return ranked.slice(0, max).map((x) => x.p);
}

/**
 * The handle of the one person whose nickname `text` is (ignoring case), if there is exactly one. Never for an
 * "@handle", which names a handle only (§11.19), nor for the handle of someone known: that person's handle wins, as
 * it does in `suggest`.
 */
export function byNickname(people: readonly PersonView[], text: string): string | undefined {
  const f = foldName(text);
  if (!f || handleOnly(text) || people.some((p) => p.handle === f)) return undefined;
  const hits = people.filter((p) => p.nickname !== "" && foldName(p.nickname) === f);
  return hits.length === 1 ? hits[0].handle : undefined;
}

/**
 * `typed` is a nickname, or the start of one ("mom " of "mom smith"): a space or a comma in it is part of the nickname,
 * not the end of a handle.
 */
export function startsNickname(people: readonly PersonView[], typed: string): boolean {
  const t = typed.normalize("NFKC").toLowerCase().trimStart();
  if (!t) return false;
  return people.some(
    (p) => p.nickname !== "" && p.nickname.normalize("NFKC").toLowerCase().startsWith(t),
  );
}

// ---- lists ----

/** This user left or was removed: the history stays readable, nothing can be sent. */
export const isGone = (c: Pick<ConversationView, "blocked">): boolean =>
  c.blocked === "removed" || c.blocked === "left";

/**
 * The list a conversation belongs in: archives once gone (a removed request too), requests while its inviter is
 * neither self nor a contact (the user has not accepted it, §11.11), else chats.
 */
export function listOf(c: Pick<ConversationView, "blocked" | "byContact">): ListView {
  if (isGone(c)) return "archives";
  return c.byContact ? "chats" : "requests";
}

/**
 * A request's inviter, if it is known. A request resolves only self and its inviter (`D.by`); the other members stay
 * `?…` until it is accepted (§11.5), and a handle never starts with `?`.
 */
export function inviterOf(
  c: Pick<ConversationView, "members" | "request">,
): MemberView | undefined {
  if (!c.request) return undefined;
  const known = c.members.filter((m) => !m.you && !m.handle.startsWith("?"));
  return known.length === 1 ? known[0] : undefined;
}

export function textTooLong(text: string): boolean {
  return new TextEncoder().encode(JSON.stringify(text)).length > MAX_TEXT_JSON_BYTES;
}

// ---- edits ----

/**
 * Self can edit the message (§11.18 "Sending"): self's text, a reply carrying a text included, once it is sent (an echo
 * names no row yet). Where self can post at all is the caller's check.
 */
export const editable = (m: MessageView): boolean =>
  m.mine && m.kind === "text" && m.status === "sent" && !!m.text;

/** The message that ArrowUp in the empty message box edits: self's last sent text in the conversation. */
export function lastEditable(msgs: readonly MessageView[]): MessageView | undefined {
  for (let i = msgs.length - 1; i >= 0; i--) if (editable(msgs[i])) return msgs[i];
  return undefined;
}

// ---- time ----
const pad2 = (n: number) => String(n).padStart(2, "0");
const valid = (ts: number) => Number.isFinite(ts) && ts > 0;

export function clock(ts: number): string {
  if (!valid(ts)) return "--:--";
  const d = new Date(ts);
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

export function dayKey(ts: number): string {
  if (!valid(ts)) return "----------";
  const d = new Date(ts);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

export function dayLabel(ts: number, now: number): string {
  const k = dayKey(ts);
  if (now && k === dayKey(now)) return "today";
  if (now && k === dayKey(now - 86_400_000)) return "yesterday";
  return k;
}

export const fullTime = (ts: number): string => `${dayKey(ts)} ${clock(ts)}`;

export function relTime(ts: number, now: number): string {
  if (!valid(ts) || !now) return "";
  const s = Math.max(0, now - ts) / 1000;
  if (s < 60) return "now";
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h`;
  if (s < 7 * 86_400) return `${Math.floor(s / 86_400)}d`;
  return dayKey(ts);
}

// ---- images ----
export function fitBox(w: number, h: number, max: number): { w: number; h: number } {
  const ok = (n: number) => Number.isFinite(n) && n >= 1 && n <= 65_535;
  if (!ok(w) || !ok(h)) return { w: max, h: Math.round(max * 0.75) };
  const s = Math.min(1, max / w, max / h);
  return { w: Math.max(1, Math.round(w * s)), h: Math.max(1, Math.round(h * s)) };
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  const mb = n / 1024 / 1024;
  return mb < 10 ? `${mb.toFixed(1).replace(/\.0$/, "")} MB` : `${Math.round(mb)} MB`;
}

/**
 * A file's name cut to `max` characters by eliding its middle, so that its end, where the extension is, stays visible
 * (§8.3). The name is already a safe name (the engine's `safeFileName`).
 */
export function shortName(name: string, max = 48): string {
  const chars = Array.from(name);
  if (chars.length <= max) return name;
  const dot = name.lastIndexOf(".");
  const ext = dot > 0 ? Array.from(name.slice(dot)).length : 0;
  const tail = Math.min(Math.max(ext + 6, 12), Math.floor(max / 2));
  return `${chars.slice(0, max - tail - 1).join("")}…${chars.slice(-tail).join("")}`;
}

export function extFor(mime: string): string {
  const m = /^image\/(webp|jpeg|png|gif|avif)$/.exec(mime);
  return m ? (m[1] === "jpeg" ? "jpg" : m[1]) : "img";
}

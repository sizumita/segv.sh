// Plain helpers shared by the UI components (no Qwik APIs, no secrets).
import type { ConversationView, Engine } from "~/client/types";
import { loadEngine } from "./engine-loader";
import type { ListView, UiState } from "./state";

// Mirrors of src/lib/proto.ts (HANDLE_RE, MAX_MEMBERS, MAX_NAME), kept in sync by
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

export type ParsedHandles = { ok: true; handles: string[] } | { ok: false; error: string };

/** "bob, @carol dave" -> ["bob","carol","dave"] (also accepts 、 and ， from Japanese IMEs). */
export function parseHandles(raw: string, self?: string, existing: string[] = []): ParsedHandles {
  const parts = raw
    .normalize("NFKC")
    .split(/[\s,、;]+/)
    .map(normaliseHandle)
    .filter(Boolean);
  if (!parts.length) return { ok: false, error: "enter at least one handle" };
  const bad = parts.filter((p) => !isHandle(p));
  if (bad.length) {
    return {
      ok: false,
      error: `not a valid handle: ${bad.slice(0, 3).join(", ")} (3–20 of a–z 0–9 _)`,
    };
  }
  const handles = [...new Set(parts)];
  if (self && handles.includes(self))
    return { ok: false, error: "you are always included — leave yourself out" };
  const dup = handles.filter((h) => existing.includes(h));
  if (dup.length) return { ok: false, error: `already a member: ${dup.join(", ")}` };
  if (handles.length + Math.max(existing.length, 1) > MAX_MEMBERS) {
    return { ok: false, error: `at most ${MAX_MEMBERS} members per conversation` };
  }
  return { ok: true, handles };
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
 * The handle of a request's inviter, if it is known. A request resolves only self and its inviter (`D.by`); the other
 * members stay `?…` until it is accepted (§11.5), and a handle never starts with `?`.
 */
export function inviterOf(
  c: Pick<ConversationView, "members" | "request">,
  meUid: string,
): string | undefined {
  if (!c.request) return undefined;
  const known = c.members.filter((m) => m.uid !== meUid && !m.handle.startsWith("?"));
  return known.length === 1 ? known[0].handle : undefined;
}

export function textTooLong(text: string): boolean {
  return new TextEncoder().encode(JSON.stringify(text)).length > MAX_TEXT_JSON_BYTES;
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
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function extFor(mime: string): string {
  const m = /^image\/(webp|jpeg|png|gif|avif)$/.exec(mime);
  return m ? (m[1] === "jpeg" ? "jpg" : m[1]) : "img";
}

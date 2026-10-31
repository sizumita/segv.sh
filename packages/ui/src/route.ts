// The open conversation in the page URL: `/#c/<ref>` (`ConversationView.ref`). A fragment never reaches the server,
// and the ref tells nothing about the conversation's secret id. Plain helpers (no Qwik APIs); the client-only parts
// touch `location` and `history` and run only in the browser.
import type { ConversationView } from "@segv/engine/types";
import type { UiState } from "./state";
import { listOf } from "./util";

const CHAT_HASH = /^#c\/([A-Za-z0-9_-]{12})$/;

/** The ref that a URL fragment names (`#c/<ref>`), or "" for any other fragment. */
export function refOfHash(hash: string): string {
  const m = CHAT_HASH.exec(hash);
  return m ? m[1] : "";
}

/** The URL fragment of a conversation's ref. */
export const hashOfRef = (ref: string): string => `#c/${ref}`;

/**
 * Marks the history entries this page pushed. After a reload the entry below belongs to the old page, and going back
 * to it would load the app again, so `leaveChat` only goes back to an entry of this page.
 */
const PAGE = Math.random().toString(36).slice(2);

/** Shows a conversation (and the list that holds it). */
export function showChat(ui: UiState, c: Pick<ConversationView, "id" | "blocked" | "byContact">) {
  ui.wanted = "";
  ui.active = c.id;
  ui.members = false;
  ui.list = listOf(c);
}

/**
 * Matches `ui.wanted` against the conversations: shows the one it names, or forgets it once the restore has ended
 * without it (a ref of another account, or of a conversation this one no longer holds).
 */
export function resolveWanted(
  ui: UiState,
  conversations: readonly ConversationView[],
  restored: boolean,
) {
  if (!ui.wanted) return;
  const c = conversations.find((x) => x.ref === ui.wanted);
  if (c) showChat(ui, c);
  else if (restored) ui.wanted = "";
}

/** After back / forward or an edited fragment: show what the URL names. */
export function followUrl(
  ui: UiState,
  conversations: readonly ConversationView[],
  restored: boolean,
) {
  const ref = refOfHash(location.hash);
  const c = ref ? conversations.find((x) => x.ref === ref) : undefined;
  if (c) {
    showChat(ui, c);
    return;
  }
  // The list, and a ref not loaded yet waits until the restore ends.
  ui.wanted = restored ? "" : ref;
  ui.active = "";
  ui.members = false;
}

/**
 * Puts the shown conversation in the URL. Opening one from the list pushes an entry, so that back (a phone's back
 * gesture included) returns to the list; switching between conversations and closing one replace it.
 */
export function writeUrl(ref: string) {
  const hash = ref ? hashOfRef(ref) : "";
  if (location.hash === hash) return;
  const url = location.pathname + location.search + hash;
  if (hash && !refOfHash(location.hash)) history.pushState({ segv: PAGE }, "", url);
  else history.replaceState(history.state, "", url);
}

/** The conversation's back button: back to the list entry below when this page pushed it, else close in place. */
export function leaveChat(ui: UiState) {
  const s = history.state as { segv?: string } | null;
  if (s?.segv === PAGE) {
    history.back();
    return;
  }
  ui.wanted = "";
  ui.active = "";
  ui.members = false;
}

/** Closes the notifications of a conversation once it is shown: their tag is its ref (§11.13). */
export function closeNotifications(ref: string): void {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  navigator.serviceWorker
    .getRegistration("/")
    .then((r) => r?.getNotifications({ tag: ref }))
    .then((ns) => ns?.forEach((n) => n.close()))
    .catch(() => {});
}

/** A tapped notification: the Service Worker asks an open window to show its URL (packages/engine/src/sw-core.ts). */
export function openFromWorker(data: unknown): void {
  const m = data as { type?: unknown; url?: unknown } | null;
  if (m?.type !== "segv.open" || typeof m.url !== "string") return;
  try {
    const u = new URL(m.url);
    if (u.origin === location.origin && u.hash && location.hash !== u.hash) location.hash = u.hash;
  } catch {
    // not a URL: stay where we are
  }
}

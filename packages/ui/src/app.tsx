import {
  $,
  component$,
  useContextProvider,
  useOnDocument,
  useOnWindow,
  useStore,
  useVisibleTask$,
} from "@qwik.dev/core";
import type { EngineState } from "@segv/engine/types";
import { Chat } from "./chat";
import { refreshServiceWorker } from "@segv/engine/sw-url";
import { loadEngine } from "./engine-loader";
import { Fatal } from "./fatal";
import { Leaving } from "./leaving";
import { Recovery } from "./recovery";
import {
  closeNotifications,
  followUrl,
  openFromWorker,
  refOfHash,
  resolveWanted,
  writeUrl,
} from "./route";
import { SignedOut } from "./signed-out";
import { initialEngineState, initialUiState, StateCtx, UiCtx } from "./state";
import { StateCopier } from "./state-copy";
import { errMsg } from "./util";
import { Viewer } from "./viewer";

const KEYS = Object.keys(initialEngineState()) as (keyof EngineState)[];

/** The window event that asks the UI to open its settings. */
const OPEN_SETTINGS = "segv-open-settings";

/**
 * Opens the settings while signed in: an app's own menu or shortcut (the desktop app's "Settings…", ⌘, or Ctrl+,).
 * Does nothing while signed out, or while the recovery code is shown.
 */
export function openSettings(): void {
  window.dispatchEvent(new Event(OPEN_SETTINGS));
}

/** Signed in, and the restore has put every conversation in the list. */
const restored = (s: EngineState) =>
  !!s.me && (s.phase === "ready" || s.phase === "working") && !s.syncing;

/**
 * Takes the engine's latest state into the UI at once, also while the page is hidden: a link or a notification may
 * name a conversation that came while the page was hidden, before the page sees that it is shown again.
 */
const latest = { apply: () => {} };

/** The tab's title: the unread count first, which a background tab shows. */
function titleOf(s: EngineState): string {
  const unread = s.conversations.reduce((n, c) => n + (c.unread > 0 ? c.unread : 0), 0);
  return unread > 0 ? `(${unread}) segv.sh` : "segv.sh";
}

export const App = component$(() => {
  // Shallow store: each top-level field is replaced wholesale by a fresh snapshot.
  const state = useStore<EngineState>(initialEngineState(), { deep: false });
  const ui = useStore(initialUiState());
  useContextProvider(StateCtx, state);
  useContextProvider(UiCtx, ui);

  useVisibleTask$(
    async ({ cleanup }) => {
      // A link, a reload or a notification may name a conversation (route.ts): show it once it is loaded.
      ui.wanted = refOfHash(location.hash);
      // A new /sw.js applies from this launch on, not whenever the browser gets round to checking it.
      refreshServiceWorker();
      // A tapped notification of a conversation, while this window is open.
      const onWorker = (e: MessageEvent) => openFromWorker(e.data);
      navigator.serviceWorker?.addEventListener("message", onWorker);
      cleanup(() => navigator.serviceWorker?.removeEventListener("message", onWorker));
      const onOpenSettings = () => {
        const signedIn = state.phase === "ready" || (state.phase === "working" && !!state.me);
        if (signedIn && !ui.recovery) ui.settings = true;
      };
      window.addEventListener(OPEN_SETTINGS, onOpenSettings);
      cleanup(() => window.removeEventListener(OPEN_SETTINGS, onOpenSettings));
      ui.visible = document.visibilityState === "visible";
      ui.now = Date.now();
      // The clock of relative times ("5 min"): a hidden page has nothing to show it on (a closed desktop window can
      // stay hidden for days), so it skips the ticks and catches up when shown (visibilitychange below).
      const tick = window.setInterval(() => {
        if (document.visibilityState === "visible") ui.now = Date.now();
      }, 30_000);
      cleanup(() => window.clearInterval(tick));

      let engine;
      try {
        engine = await loadEngine();
      } catch (e) {
        state.phase = "fatal";
        state.error = `could not load the client: ${errMsg(e)}`;
        return;
      }

      // Coalesce bursts (log backfill) into at most one UI update per ~frame. A hidden page (a background tab, a closed
      // desktop window, which can stay hidden for days) updates only its title, and takes the latest state when shown.
      // The UI never shares objects with the engine: it holds copies, the same ones as long as nothing changed.
      const copier = new StateCopier();
      let pending: EngineState | null = null;
      let timer = 0;
      let lastPhase = state.phase;
      const apply = (evenHidden = false) => {
        if (timer) window.clearTimeout(timer);
        timer = 0;
        const s = pending;
        if (!s) return;
        document.title = titleOf(s);
        if (!evenHidden && document.visibilityState !== "visible") return;
        pending = null;
        const snap = copier.copy(s);
        for (const k of KEYS)
          if (state[k] !== snap[k]) (state as unknown as Record<string, unknown>)[k] = snap[k];
        if (snap.phase !== lastPhase) {
          if (snap.phase === "signed-out" || snap.phase === "boot") {
            ui.active = "";
            ui.list = "chats";
            ui.members = false;
            ui.viewer = undefined;
            ui.settings = false;
            ui.leaving = "";
            ui.hiddenWarnings = [];
          }
          lastPhase = snap.phase;
        }
        if (ui.active && !snap.conversations.some((c) => c.id === ui.active)) ui.active = "";
        if (snap.me && (snap.phase === "ready" || snap.phase === "working"))
          resolveWanted(ui, snap.conversations, restored(snap));
      };
      const unsubscribe = engine.subscribe((s) => {
        pending = s;
        // While backfilling the log, re-render at most ~8x/s; otherwise once per frame.
        if (!timer) timer = window.setTimeout(() => apply(), s.syncing ? 120 : 16);
      });
      const onShown = () => {
        if (document.visibilityState === "visible") apply();
      };
      document.addEventListener("visibilitychange", onShown);
      latest.apply = () => apply(true);
      cleanup(() => {
        unsubscribe();
        document.removeEventListener("visibilitychange", onShown);
        latest.apply = () => {};
        if (timer) window.clearTimeout(timer);
      });
    },
    { strategy: "document-ready" },
  );

  // The URL follows the conversation on screen (not before the engine has booted: a link's ref waits in ui.wanted).
  useVisibleTask$(
    ({ track }) => {
      const phase = track(() => state.phase);
      const id = track(() => ui.active);
      const wanted = track(() => ui.wanted);
      if (phase === "boot" || wanted) return;
      const c = id ? state.conversations.find((x) => x.id === id) : undefined;
      writeUrl(c ? c.ref : "");
      if (c) closeNotifications(c.ref);
    },
    { strategy: "document-ready" },
  );
  // Back, forward, or an edited fragment.
  useOnWindow(
    "popstate",
    $(() => {
      latest.apply();
      followUrl(ui, state.conversations, restored(state));
    }),
  );
  useOnWindow(
    "hashchange",
    $(() => {
      latest.apply();
      followUrl(ui, state.conversations, restored(state));
    }),
  );

  useOnDocument(
    "visibilitychange",
    $(() => {
      ui.visible = document.visibilityState === "visible";
      if (!ui.visible) return;
      ui.now = Date.now();
      // A web app on a phone is often resumed rather than launched again.
      refreshServiceWorker();
    }),
  );
  useOnDocument(
    "keydown",
    $((e: KeyboardEvent) => {
      if (e.key === "Escape" && ui.viewer) ui.viewer = undefined;
    }),
  );

  const phase = state.phase;
  const signedIn = phase === "ready" || (phase === "working" && !!state.me);

  // A stable root element: useOnDocument() listeners are attached to the component's first
  // element, so it must not be swapped out when the phase changes.
  return (
    <div class="app">
      {ui.recovery ? (
        <Recovery />
      ) : phase === "boot" ? (
        <p class="boot" aria-busy="true">
          loading…
        </p>
      ) : phase === "fatal" ? (
        <Fatal />
      ) : signedIn ? (
        <Chat />
      ) : (
        <SignedOut />
      )}
      {ui.viewer && <Viewer />}
      {ui.leaving && <Leaving />}
      <noscript>segv.sh needs javascript: all encryption happens in your browser.</noscript>
    </div>
  );
});

import {
  $,
  component$,
  useContextProvider,
  useOnDocument,
  useOnWindow,
  useStore,
  useVisibleTask$,
} from "@qwik.dev/core";
import type { EngineState } from "~/client/types";
import { Chat } from "./chat";
import { loadEngine } from "./engine-loader";
import { Fatal } from "./fatal";
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
import { errMsg } from "./util";
import { Viewer } from "./viewer";

const KEYS = Object.keys(initialEngineState()) as (keyof EngineState)[];

/** Signed in, and the restore has put every conversation in the list. */
const restored = (s: EngineState) =>
  !!s.me && (s.phase === "ready" || s.phase === "working") && !s.syncing;

function snapshot(s: EngineState): EngineState {
  try {
    return structuredClone(s); // the UI never shares objects with the engine
  } catch {
    return JSON.parse(JSON.stringify(s)) as EngineState;
  }
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
      // A tapped notification of a conversation, while this window is open.
      const onWorker = (e: MessageEvent) => openFromWorker(e.data);
      navigator.serviceWorker?.addEventListener("message", onWorker);
      cleanup(() => navigator.serviceWorker?.removeEventListener("message", onWorker));
      ui.visible = document.visibilityState === "visible";
      ui.now = Date.now();
      const tick = window.setInterval(() => (ui.now = Date.now()), 30_000);
      cleanup(() => window.clearInterval(tick));

      let engine;
      try {
        engine = await loadEngine();
      } catch (e) {
        state.phase = "fatal";
        state.error = `could not load the client: ${errMsg(e)}`;
        return;
      }

      // Coalesce bursts (log backfill) into at most one UI update per ~frame.
      let pending: EngineState | null = null;
      let timer = 0;
      let lastPhase = state.phase;
      const apply = () => {
        timer = 0;
        const s = pending;
        pending = null;
        if (!s) return;
        const snap = snapshot(s);
        for (const k of KEYS) (state as unknown as Record<string, unknown>)[k] = snap[k];
        if (snap.phase !== lastPhase) {
          if (snap.phase === "signed-out" || snap.phase === "boot") {
            ui.active = "";
            ui.list = "chats";
            ui.members = false;
            ui.viewer = undefined;
            ui.settings = false;
          }
          lastPhase = snap.phase;
        }
        if (ui.active && !snap.conversations.some((c) => c.id === ui.active)) ui.active = "";
        if (snap.me && (snap.phase === "ready" || snap.phase === "working"))
          resolveWanted(ui, snap.conversations, restored(snap));
        const unread = snap.conversations.reduce((n, c) => n + (c.unread > 0 ? c.unread : 0), 0);
        document.title = unread > 0 ? `(${unread}) segv.sh` : "segv.sh";
      };
      const unsubscribe = engine.subscribe((s) => {
        pending = s;
        // While backfilling the log, re-render at most ~8x/s; otherwise once per frame.
        if (!timer) timer = window.setTimeout(apply, s.syncing ? 120 : 16);
      });
      cleanup(() => {
        unsubscribe();
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
    $(() => followUrl(ui, state.conversations, restored(state))),
  );
  useOnWindow(
    "hashchange",
    $(() => followUrl(ui, state.conversations, restored(state))),
  );

  useOnDocument(
    "visibilitychange",
    $(() => {
      ui.visible = document.visibilityState === "visible";
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
      <noscript>segv.sh needs javascript: all encryption happens in your browser.</noscript>
    </div>
  );
});

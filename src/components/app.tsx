import {
  $,
  component$,
  useContextProvider,
  useOnDocument,
  useStore,
  useVisibleTask$,
} from "@qwik.dev/core";
import type { EngineState } from "~/client/types";
import { Chat } from "./chat";
import { loadEngine } from "./engine-loader";
import { Fatal } from "./fatal";
import { Recovery } from "./recovery";
import { SignedOut } from "./signed-out";
import { initialEngineState, initialUiState, StateCtx, UiCtx } from "./state";
import { errMsg } from "./util";
import { Viewer } from "./viewer";

const KEYS = Object.keys(initialEngineState()) as (keyof EngineState)[];

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

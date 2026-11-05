import { $, component$, useContext, useSignal } from "@qwik.dev/core";
import { ConvList } from "./conv-list";
import { ConversationPane } from "./conversation";
import { Errors } from "./errors";
import { Settings } from "./settings";
import { StateCtx, UiCtx } from "./state";
import { Warnings } from "./warnings";

/** The width of the conversation list, in CSS pixels, on this device (global.css: --side). */
const SIDE_KEY = "segv.listWidth";
const SIDE = 300;
const SIDE_MIN = 200;
const SIDE_MAX = 560;
/** One arrow key press on the handle. */
const SIDE_STEP = 16;

const clampSide = (w: number) => Math.round(Math.min(SIDE_MAX, Math.max(SIDE_MIN, w)));

function readSide(): number {
  try {
    const n = Number(localStorage.getItem(SIDE_KEY));
    return n ? clampSide(n) : SIDE;
  } catch {
    return SIDE;
  }
}

function saveSide(w: number): void {
  try {
    if (w === SIDE) localStorage.removeItem(SIDE_KEY);
    else localStorage.setItem(SIDE_KEY, String(w));
  } catch {
    // storage off: the width lasts until the page closes
  }
}

/**
 * Signed-in screen: status bar (sync, checkpoint, security warnings), errors, then list | conversation. Online or
 * offline is at the top of the list (conv-list.tsx).
 */
export const Chat = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const active = ui.active ? state.conversations.find((c) => c.id === ui.active) : undefined;
  // Only drawn in the browser (the server draws the loading screen), so it can read the stored width at once.
  const side = useSignal(readSide);
  const root = useSignal<HTMLElement>();
  const drag = useSignal<{ x: number; w: number } | undefined>();
  // The width the drag has reached (not drawn from: the drag writes it onto the page itself).
  const dragged = useSignal(0);

  const setSide = $((w: number) => {
    side.value = clampSide(w);
    saveSide(side.value);
  });
  // While dragging, the width goes straight onto the page, not through a new drawing of this component.
  const onDown = $((e: PointerEvent, el: HTMLElement) => {
    if (e.button !== 0) return;
    el.setPointerCapture(e.pointerId);
    drag.value = { x: e.clientX, w: side.value };
    dragged.value = side.value;
  });
  const onMove = $((e: PointerEvent) => {
    const d = drag.value;
    if (!d) return;
    dragged.value = clampSide(d.w + e.clientX - d.x);
    root.value?.style.setProperty("--side", `${dragged.value}px`);
  });
  const onUp = $(() => {
    if (!drag.value) return;
    drag.value = undefined;
    void setSide(dragged.value);
  });
  const onKey = $((e: KeyboardEvent) => {
    if (e.key === "ArrowLeft") void setSide(side.value - SIDE_STEP);
    else if (e.key === "ArrowRight") void setSide(side.value + SIDE_STEP);
    else if (e.key === "Home") void setSide(SIDE_MIN);
    else if (e.key === "End") void setSide(SIDE_MAX);
  });

  return (
    <div class="chat" ref={root} style={`--side: ${side.value}px`}>
      <header class="bar">
        {state.syncing && <span>syncing…</span>}
        {state.progress && (
          <span class="grow" role="status">
            {state.progress}
          </span>
        )}
        <span
          class="dim push"
          title={
            state.head.h ? `verified checkpoint ${state.head.h}` : "no checkpoint verified yet"
          }
        >
          checkpoint #{state.head.seq}
        </span>
        <Warnings />
      </header>

      <Errors />

      <div class="panes" data-pane={active ? "conv" : "list"}>
        <ConvList />
        {/* Drag to change the list's width, or use the arrow keys; a double click puts it back. */}
        <div
          class={["sizer", drag.value && "drag"]}
          role="separator"
          aria-orientation="vertical"
          aria-label="conversation list width"
          aria-valuenow={side.value}
          aria-valuemin={SIDE_MIN}
          aria-valuemax={SIDE_MAX}
          tabIndex={0}
          title="drag to resize"
          preventdefault:pointerdown
          onPointerDown$={onDown}
          onPointerMove$={onMove}
          onPointerUp$={onUp}
          onPointerCancel$={onUp}
          onDblClick$={() => setSide(SIDE)}
          onKeyDown$={onKey}
        />
        <section class="right" aria-label="conversation">
          {active ? (
            <ConversationPane key={active.id} conv={active} />
          ) : (
            <p class="empty dim">
              {state.conversations.length
                ? "select a conversation."
                : "start a conversation on the left."}
            </p>
          )}
        </section>
      </div>
      {ui.settings && <Settings />}
    </div>
  );
});

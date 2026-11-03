import { $, component$, useContext, useSignal, useStore, useVisibleTask$ } from "@qwik.dev/core";
import type { ConversationView, MessageView } from "@segv/engine/types";
import { quickList } from "./emoji";
import { EmojiPicker, type Anchor } from "./emoji-picker";
import { MsgFile } from "./msg-file";
import { MsgImage } from "./msg-image";
import { MsgText } from "./msg-text";
import { UiCtx, type UiState } from "./state";
import { act, clock, dayKey, dayLabel, fullTime } from "./util";

const GROUP_MS = 5 * 60_000;
const NEAR_BOTTOM_PX = 48;

const isLine = (m: MessageView) => m.kind === "system" || m.kind === "leave";

/** The emoji that self reacted with in this page's life, newest first, which lead the picker's "frequently used" row. */
const recent: string[] = [];
function remember(emoji: string): void {
  const i = recent.indexOf(emoji);
  if (i >= 0) recent.splice(i, 1);
  recent.unshift(emoji);
  if (recent.length > 16) recent.length = 16;
}

/**
 * Sends one reaction (§11.12) and remembers an emoji that it adds, for the picker. Resolves true once sent; a rejection
 * becomes `ui.localError`.
 */
const sendReaction = (ui: UiState, convId: string, key: string, emoji: string, on: boolean) =>
  act(ui, async (e) => {
    if (on) remember(emoji);
    await e.react(convId, key, emoji, on);
    return true;
  });

/** Self's emoji on a message, as sent. */
const mine = (m: MessageView): string[] => m.reactions.filter((r) => r.mine).map((r) => r.emoji);

/** A smiling face with a plus: add a reaction. */
const ReactIcon = () => (
  <svg
    class="icon"
    viewBox="0 0 20 20"
    aria-hidden="true"
    fill="none"
    stroke="currentColor"
    stroke-width="1.5"
    stroke-linecap="round"
  >
    <path d="M16.95 9.15A7 7 0 1 1 10.85 3.05" />
    <path d="M7 12a3.5 3.5 0 0 0 6 0" />
    <path d="M16 1v6M13 4h6" />
    <circle cx="7.5" cy="8.5" r="1" fill="currentColor" stroke="none" />
    <circle cx="12.5" cy="8.5" r="1" fill="currentColor" stroke="none" />
  </svg>
);

export const Messages = component$<{ conv: ConversationView }>((props) => {
  const ui = useContext(UiCtx);
  const box = useSignal<HTMLElement>();
  const stick = useSignal(true); // follow new messages unless the user scrolled up
  const newBelow = useSignal(false);
  /**
   * The message whose reactions the picker edits ('' = closed), where the button that opened it is (`chip`: the one
   * after the reactions, else the one among the actions), and its "frequently used" row as it was then (a JSON list).
   * The pane is drawn again for each conversation (chat.tsx keys it), so none of this outlives one.
   */
  const pick = useStore<{ key: string; anchor: Anchor; chip: boolean; quick: string }>({
    key: "",
    anchor: { top: 0, bottom: 0, left: 0, right: 0 },
    chip: false,
    quick: "[]",
  });
  /** On a touch screen, which has no hover, the message whose actions a tap shows ('' = none). */
  const active = useSignal("");

  // Auto-scroll: to the bottom when the conversation opens, and on new messages while stuck.
  useVisibleTask$(({ track }) => {
    const n = track(() => props.conv.messages.length);
    track(() => props.conv.messages[n - 1]?.key ?? "");
    const lastMine = props.conv.messages[n - 1]?.mine ?? false;
    const el = box.value;
    if (!el) return;
    if (stick.value || lastMine) {
      stick.value = true;
      el.scrollTop = el.scrollHeight;
      newBelow.value = false;
    } else {
      newBelow.value = true;
    }
  });

  const onScroll = $((_: Event, el: HTMLElement) => {
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_BOTTOM_PX;
    stick.value = atBottom;
    if (atBottom) newBelow.value = false;
  });

  const jump = $(() => {
    const el = box.value;
    if (el) el.scrollTop = el.scrollHeight;
    stick.value = true;
    newBelow.value = false;
  });

  // One click handler for the list: an "add a reaction" button opens (or closes) the picker beside it, and on a touch
  // screen a tap on a message shows its actions, or hides them.
  const onClick = $((ev: MouseEvent) => {
    const t = ev.target as Element;
    const open = t.closest<HTMLElement>("[data-react-open]");
    if (open) {
      const key = open.dataset.reactOpen ?? "";
      if (pick.key === key) {
        pick.key = "";
        return;
      }
      const r = open.getBoundingClientRect();
      const used = props.conv.messages.flatMap(mine).reverse();
      pick.anchor = { top: r.top, bottom: r.bottom, left: r.left, right: r.right };
      pick.chip = !open.closest(".mtools");
      pick.quick = JSON.stringify(quickList(recent, used));
      pick.key = key;
      return;
    }
    if (!matchMedia("(hover: none)").matches || t.closest("a, button, input, .spoiler")) return;
    const key = t.closest<HTMLElement>(".m[data-key]")?.dataset.key ?? "";
    active.value = key && key !== active.value ? key : "";
  });

  const closePicker = $((refocus: boolean) => {
    const key = pick.key;
    pick.key = "";
    active.value = "";
    const from = pick.chip ? ".reacts" : ".mtools";
    if (refocus && key)
      box.value
        ?.querySelector<HTMLElement>(`${from} [data-react-open="${CSS.escape(key)}"]`)
        ?.focus({ preventScroll: true });
  });

  const react = $((key: string, emoji: string, on: boolean) =>
    sendReaction(ui, props.conv.id, key, emoji, on),
  );

  const msgs = props.conv.messages;
  // A reaction is a post: not in a read-only preview (it would accept the copy) or where nothing can be sent.
  const canReact = props.conv.canSend && props.conv.byContact;
  const picked = pick.key ? msgs.find((m) => m.key === pick.key) : undefined;
  const pk = picked?.key ?? "";
  return (
    <div class="msgwrap">
      <div
        class="msgs"
        ref={box}
        onScroll$={onScroll}
        onClick$={onClick}
        role="log"
        aria-live="polite"
        tabIndex={0}
      >
        {msgs.length === 0 && <p class="dim empty">no messages yet.</p>}
        {msgs.map((m, i) => {
          const prev = i > 0 ? msgs[i - 1] : undefined;
          const newDay = !prev || dayKey(prev.ts) !== dayKey(m.ts);
          const head =
            newDay || !prev || isLine(prev) || prev.from !== m.from || m.ts - prev.ts > GROUP_MS;
          const tools = canReact && m.status === "sent";
          return (
            <div key={m.key} class="mrow">
              {newDay && (
                <p class="day">
                  <span>{dayLabel(m.ts, ui.now)}</span>
                </p>
              )}
              {isLine(m) ? (
                <p class="sys" title={fullTime(m.ts)}>
                  {m.kind === "leave"
                    ? `${m.mine ? "you" : m.fromHandle || "someone"} left the conversation`
                    : m.text}
                  <span class="t"> · {clock(m.ts)}</span>
                </p>
              ) : (
                <div
                  class={[
                    "m",
                    m.mine && "mine",
                    head && "head",
                    (active.value === m.key || pk === m.key) && "active",
                  ]}
                  title={fullTime(m.ts)}
                  data-key={m.key}
                >
                  {tools && (
                    <div class="mtools-at">
                      <div class="mtools" role="toolbar" aria-label="message actions">
                        <button
                          type="button"
                          data-react-open={m.key}
                          aria-label="add a reaction"
                          title="add a reaction"
                          aria-haspopup="dialog"
                          aria-expanded={pk === m.key}
                        >
                          <ReactIcon />
                        </button>
                      </div>
                    </div>
                  )}
                  {head && (
                    <p class="meta">
                      <b>{m.fromHandle || "unknown"}</b>
                      {m.mine && <span class="dim"> (you)</span>}{" "}
                      <span class="dim">{clock(m.ts)}</span>
                    </p>
                  )}
                  {m.kind === "image" && m.image ? (
                    <MsgImage img={m.image} hold={props.conv.request} />
                  ) : m.kind === "file" && m.file ? (
                    <MsgFile file={m.file} />
                  ) : (
                    <MsgText text={m.text ?? ""} />
                  )}
                  {m.status === "sending" && <p class="st">sending…</p>}
                  {m.status === "failed" && <p class="st failed">failed — not delivered</p>}
                  {m.status === "sent" && m.reactions.length > 0 && (
                    <Reactions
                      convId={props.conv.id}
                      m={m}
                      canReact={canReact}
                      open={pk === m.key}
                    />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
      {newBelow.value && (
        <button type="button" class="newbelow" onClick$={jump}>
          new messages — jump to latest
        </button>
      )}
      {picked && (
        <EmojiPicker
          key={pk}
          anchor={pick.anchor}
          msgKey={pk}
          on={JSON.stringify(mine(picked))}
          quick={pick.quick}
          onPick$={react}
          onClose$={closePicker}
        />
      )}
    </div>
  );
});

/**
 * The reactions under a message, each with its count; a click turns self's on or off (§11.12). The button at their end
 * opens the picker, as the one among the message's actions does.
 */
const Reactions = component$<{ convId: string; m: MessageView; canReact: boolean; open: boolean }>(
  (props) => {
    const ui = useContext(UiCtx);
    const busy = useSignal(false);

    const toggle = $(async (emoji: string, on: boolean) => {
      if (busy.value) return;
      busy.value = true;
      try {
        await sendReaction(ui, props.convId, props.m.key, emoji, on);
      } finally {
        busy.value = false;
      }
    });

    return (
      <div class="reacts">
        {props.m.reactions.map((r) => (
          <button
            type="button"
            key={r.emoji}
            class={["react", r.mine && "mine"]}
            disabled={!props.canReact || busy.value}
            aria-pressed={r.mine}
            title={r.mine ? "remove your reaction" : "react with this too"}
            onClick$={() => toggle(r.emoji, !r.mine)}
          >
            <span class="ej">{r.emoji}</span> {r.count}
          </button>
        ))}
        {props.canReact && (
          <button
            type="button"
            class="react add"
            data-react-open={props.m.key}
            aria-label="add a reaction"
            title="add a reaction"
            aria-haspopup="dialog"
            aria-expanded={props.open}
          >
            <ReactIcon />
          </button>
        )}
      </div>
    );
  },
);

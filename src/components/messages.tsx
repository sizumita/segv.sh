import { $, component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import type { ConversationView, MessageView } from "~/client/types";
import { loadEngine } from "./engine-loader";
import { MsgImage } from "./msg-image";
import { UiCtx } from "./state";
import { clock, dayKey, dayLabel, errMsg, fullTime } from "./util";

/** The reaction palette (one emoji each; §11.12). */
const PALETTE = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

const GROUP_MS = 5 * 60_000;
const NEAR_BOTTOM_PX = 48;

const isLine = (m: MessageView) => m.kind === "system" || m.kind === "leave";

export const Messages = component$<{ conv: ConversationView }>((props) => {
  const ui = useContext(UiCtx);
  const box = useSignal<HTMLElement>();
  const stick = useSignal(true); // follow new messages unless the user scrolled up
  const newBelow = useSignal(false);

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

  const msgs = props.conv.messages;
  // A reaction is a post: not in a read-only preview (it would accept the copy) or where nothing can be sent.
  const canReact = props.conv.canSend && props.conv.byContact;
  return (
    <div class="msgwrap">
      <div class="msgs" ref={box} onScroll$={onScroll} role="log" aria-live="polite" tabIndex={0}>
        {msgs.length === 0 && <p class="dim empty">no messages yet.</p>}
        {msgs.map((m, i) => {
          const prev = i > 0 ? msgs[i - 1] : undefined;
          const newDay = !prev || dayKey(prev.ts) !== dayKey(m.ts);
          const head =
            newDay || !prev || isLine(prev) || prev.from !== m.from || m.ts - prev.ts > GROUP_MS;
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
                <div class={["m", m.mine && "mine", head && "head"]} title={fullTime(m.ts)}>
                  {head && (
                    <p class="meta">
                      <b>{m.fromHandle || "unknown"}</b>
                      {m.mine && <span class="dim"> (you)</span>}{" "}
                      <span class="dim">{clock(m.ts)}</span>
                    </p>
                  )}
                  {m.kind === "image" && m.image ? (
                    <MsgImage img={m.image} hold={props.conv.request} />
                  ) : (
                    <p class="body">{m.text ?? ""}</p>
                  )}
                  {m.status === "sending" && <p class="st">sending…</p>}
                  {m.status === "failed" && <p class="st failed">failed — not delivered</p>}
                  {m.status === "sent" && (m.reactions.length > 0 || canReact) && (
                    <Reactions convId={props.conv.id} m={m} canReact={canReact} />
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
    </div>
  );
});

/** The reactions under a message, each with its count, and the palette to add one (§11.12). */
const Reactions = component$<{ convId: string; m: MessageView; canReact: boolean }>((props) => {
  const ui = useContext(UiCtx);
  const open = useSignal(false);
  const busy = useSignal(false);

  const toggle = $(async (emoji: string, on: boolean) => {
    if (busy.value) return;
    busy.value = true;
    open.value = false;
    ui.localError = "";
    try {
      await (await loadEngine()).react(props.convId, props.m.key, emoji, on);
    } catch (e) {
      ui.localError = errMsg(e);
    } finally {
      busy.value = false;
    }
  });

  const mineOn = (emoji: string) => props.m.reactions.some((r) => r.emoji === emoji && r.mine);
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
          {r.emoji} {r.count}
        </button>
      ))}
      {props.canReact &&
        (open.value ? (
          <span class="palette" role="group" aria-label="react">
            {PALETTE.map((e) => (
              <button
                type="button"
                key={e}
                class={["react", mineOn(e) && "mine"]}
                disabled={busy.value}
                onClick$={() => toggle(e, !mineOn(e))}
              >
                {e}
              </button>
            ))}
          </span>
        ) : (
          <button
            type="button"
            class="react add"
            aria-label="add a reaction"
            onClick$={() => (open.value = true)}
          >
            +
          </button>
        ))}
    </div>
  );
});

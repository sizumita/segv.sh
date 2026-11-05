import { $, component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import type { ConversationView, MessageView } from "@segv/engine/types";
import { MsgFile } from "./msg-file";
import { MsgImage } from "./msg-image";
import { Composer } from "./composer";
import { MsgText } from "./msg-text";
import { gist, ReplyIcon, ReplyQuote } from "./reply";
import { PaneCtx, UiCtx } from "./state";
import { clock, dayKey, dayLabel, fullTime } from "./util";

/** How the chain above the message ends. */
type Top = "root" | "waiting" | "none" | "unloaded";

interface Item {
  m: MessageView;
  /** the message it replies to, when the pane shows that one too */
  parent: MessageView | undefined;
  /** above: the chain the message replies to; this: the message; below: the replies to it, as a tree */
  at: "above" | "this" | "below";
}

/**
 * A message's replies, from the messages the view holds (§11.17 "Thread"): the chain of messages it replies to, up to
 * one that is not a reply, then the message, then every reply below it, each right after what it replies to, in the
 * order of the conversation. Other replies to the messages above it are left out.
 */
export function threadOf(
  msgs: readonly MessageView[],
  key: string,
): { items: Item[]; top: Top } | null {
  const byKey = new Map(msgs.map((m) => [m.key, m]));
  const start = byKey.get(key);
  if (!start) return null;
  const chain: MessageView[] = [];
  const seen = new Set<string>();
  let top: Top = "root";
  for (let cur: MessageView | undefined = start; cur && !seen.has(cur.key);) {
    seen.add(cur.key);
    chain.unshift(cur);
    const r: MessageView["reply"] = cur.reply;
    if (!r) break;
    if (r.state !== "shown") {
      top = r.state;
      break;
    }
    cur = byKey.get(r.key);
    if (!cur) top = "unloaded";
  }
  const kids = new Map<string, MessageView[]>();
  for (const m of msgs) {
    if (m.reply?.state !== "shown" || m.key === m.reply.key) continue;
    const list = kids.get(m.reply.key);
    if (list) list.push(m);
    else kids.set(m.reply.key, [m]);
  }
  const items: Item[] = chain.map((m, i) => ({
    m,
    parent: chain[i - 1],
    at: m === start ? "this" : "above",
  }));
  const walk = (parent: MessageView) => {
    for (const m of kids.get(parent.key) ?? []) {
      if (seen.has(m.key)) continue; // never twice, whatever the targets say
      seen.add(m.key);
      items.push({ m, parent, at: "below" });
      walk(m);
    }
  };
  walk(start);
  return { items, top };
}

const TOP_TEXT: Record<Exclude<Top, "root">, string> = {
  waiting: "the message it replies to is not loaded",
  none: "the message it replies to is not available",
  unloaded: "earlier messages of this thread are not loaded",
};

/** The list follows a new last message while it is scrolled to within this of its end. */
const NEAR_END_PX = 48;

/**
 * The side pane beside the conversation with a message's replies; `PaneState.thread` names the message. Its message box
 * replies to the last message it shows, or to the one whose "reply" was pressed (`PaneState.threadTo`) until it sends.
 */
export const ReplyTree = component$<{ conv: ConversationView; canReply: boolean }>((props) => {
  const pane = useContext(PaneCtx);
  const ui = useContext(UiCtx);
  const box = useSignal<HTMLElement>();
  const list = useSignal<HTMLElement>();
  /** the list is scrolled to its end */
  const atEnd = useSignal(false);
  /** the message the pane was drawn for, and its last message then */
  const shownFor = useSignal("");
  const shownLast = useSignal("");

  // On another message: reply to its last message again, and bring the message itself into view. On a new last message
  // (one just sent from here, or one that came) while at the end, or one of self's: follow it.
  useVisibleTask$(({ track }) => {
    const thread = track(() => pane.thread);
    track(() => props.conv.messages.length);
    track(() => props.conv.messages[props.conv.messages.length - 1]?.key);
    const last = threadOf(props.conv.messages, thread)?.items.at(-1)?.m;
    const el = list.value;
    if (thread !== shownFor.value) {
      shownFor.value = thread;
      shownLast.value = last?.key ?? "";
      pane.threadTo = "";
      requestAnimationFrame(() =>
        el?.querySelector(".ti.on")?.scrollIntoView({ block: "nearest" }),
      );
      return;
    }
    if (!last || last.key === shownLast.value) return;
    shownLast.value = last.key;
    if (el && (atEnd.value || last.mine))
      requestAnimationFrame(() => (el.scrollTop = el.scrollHeight));
  });

  const onScroll = $((_: Event, el: HTMLElement) => {
    atEnd.value = el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_END_PX;
  });

  // "reply" makes the pane's message box reply to its message; a quote line shows that reply's own chain and replies;
  // "(edited)" shows the message's versions (edit.tsx).
  const onClick = $((ev: MouseEvent) => {
    const el = ev.target as Element;
    const h = el.closest<HTMLElement>("[data-history]");
    if (h) {
      pane.history = h.dataset.history ?? "";
      return;
    }
    const q = el.closest<HTMLElement>("[data-thread]");
    if (q) {
      pane.thread = q.dataset.thread ?? "";
      return;
    }
    const t = el.closest<HTMLElement>("[data-reply]");
    if (!t) return;
    pane.threadTo = t.dataset.reply ?? "";
    box.value?.querySelector<HTMLTextAreaElement>(".composer textarea")?.focus();
  });

  const setTo = $((key: string) => {
    pane.threadTo = key;
  });

  const tree = threadOf(props.conv.messages, pane.thread);
  // What the box replies to: the message whose "reply" was pressed, else the last one that was sent (not an echo).
  const sent = tree?.items.filter((x) => x.m.status === "sent").map((x) => x.m) ?? [];
  const chosen = pane.threadTo ? sent.find((m) => m.key === pane.threadTo) : undefined;
  const target = chosen ?? sent.at(-1);
  return (
    <aside class="rtree" aria-label="replies" ref={box} onClick$={onClick}>
      <header class="row">
        <h3 class="grow">replies</h3>
        <button
          type="button"
          class="xbtn"
          aria-label="close the replies"
          title="close"
          onClick$={() => (pane.thread = "")}
        >
          ×
        </button>
      </header>
      <div class="tscroll" ref={list} onScroll$={onScroll}>
        {!tree ? (
          <p class="dim small">this message is no longer loaded.</p>
        ) : (
          <ol class="tlist">
            {tree.top !== "root" && <li class="ttop dim small">{TOP_TEXT[tree.top]}</li>}
            {tree.items.map(({ m, parent, at }, i) => {
              const prev = i > 0 ? tree.items[i - 1].m : undefined;
              const newDay = !prev || dayKey(prev.ts) !== dayKey(m.ts);
              // Flat, without indents: a reply names what it replies to when that is not right above it.
              const quote = parent !== undefined && parent !== prev;
              return (
                <li
                  key={m.key}
                  class={["ti", at === "this" && "on", chosen === m && "to"]}
                  title={fullTime(m.ts)}
                  aria-current={at === "this" ? "true" : undefined}
                >
                  <div class="tb">
                    {quote && <ReplyQuote m={m} target={parent} />}
                    <p class="meta">
                      <b>{m.fromHandle || "unknown"}</b>
                      {m.mine && <span class="dim"> (you)</span>}
                      <span class="dim">
                        {newDay ? `${dayLabel(m.ts, ui.now)} ` : ""}
                        {clock(m.ts)}
                      </span>
                      {props.canReply && m.status === "sent" && (
                        <button
                          type="button"
                          class="treply"
                          data-reply={m.key}
                          aria-label={`reply to ${m.fromHandle || "this message"}`}
                          title="reply"
                        >
                          <ReplyIcon />
                        </button>
                      )}
                    </p>
                    {m.kind === "image" && m.image ? (
                      <MsgImage img={m.image} hold={props.conv.request} />
                    ) : m.kind === "file" && m.file ? (
                      <MsgFile file={m.file} />
                    ) : (
                      <MsgText text={m.text ?? ""} edited={m.edited} msgKey={m.key} />
                    )}
                    {m.status === "sending" && <p class="st">sending…</p>}
                    {m.status === "failed" && <p class="st failed">failed — not delivered</p>}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </div>
      {props.canReply && target && (
        <Composer
          convId={props.conv.id}
          blocked={props.conv.blocked}
          replyTo={target.key}
          replyWho={target.fromHandle || "unknown"}
          replyGist={gist(target)}
          canStop={chosen !== undefined}
          setReply$={setTo}
          label="reply"
        />
      )}
    </aside>
  );
});

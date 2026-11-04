import { component$ } from "@qwik.dev/core";
import { plainText } from "@segv/engine/markdown";
import type { MessageView } from "@segv/engine/types";

/** The longest gist a quote shows; CSS cuts it to its width. */
const GIST_MAX = 160;

/**
 * One line of a message for a quote (§11.17 "Display"): its text without Markdown, a spoiler hidden whole, or what it
 * holds.
 */
export function gist(m: MessageView): string {
  if (m.kind === "image") return "image";
  if (m.kind === "file") return m.file?.name || "file";
  const s = plainText(m.text ?? "")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > GIST_MAX ? `${s.slice(0, GIST_MAX)}…` : s;
}

/** The view's messages by key, built once per render where replies are shown. */
export const keyed = (msgs: readonly MessageView[]): Map<string, MessageView> =>
  new Map(msgs.map((m) => [m.key, m]));

/** The message a reply's target names, when the view holds it. */
export const targetIn = (
  byKey: ReadonlyMap<string, MessageView>,
  m: MessageView,
): MessageView | undefined => (m.reply?.state === "shown" ? byKey.get(m.reply.key) : undefined);

/** A curved arrow pointing left: reply. */
export const ReplyIcon = () => (
  <svg
    class="icon"
    viewBox="0 0 20 20"
    aria-hidden="true"
    fill="none"
    stroke="currentColor"
    stroke-width="1.5"
    stroke-linecap="round"
    stroke-linejoin="round"
  >
    <path d="M8 4.5 3 9.5l5 5" />
    <path d="M3.5 9.5H11a6 6 0 0 1 6 6v1" />
  </svg>
);

/**
 * The line above a reply that names its target: a thin curve from the reply up to the target's sender and the start of
 * its text, or why it is not shown. A click opens the reply's thread beside the conversation (`data-thread`, handled by
 * the list in messages.tsx).
 */
export const ReplyQuote = component$<{ m: MessageView; target: MessageView | undefined }>(
  (props) => {
    const r = props.m.reply;
    const t = props.target;
    if (!r) return null;
    const what = t
      ? gist(t)
      : r.state === "none"
        ? "the original message is not available"
        : "the original message is not loaded";
    return (
      <button
        type="button"
        class={["rq", !t && "gone"]}
        data-thread={props.m.key}
        title="show the replies"
        aria-label={
          t ? `reply to ${t.fromHandle}: ${what}. show the replies` : `${what}. show the replies`
        }
      >
        <span class="rq-line" aria-hidden="true" />
        {t && (
          <b class="rq-who">
            {t.fromHandle || "unknown"}
            {t.mine && <span class="dim"> (you)</span>}
          </b>
        )}
        <span class={["rq-text", (!t || t.kind !== "text") && "dim"]}>{what}</span>
      </button>
    );
  },
);

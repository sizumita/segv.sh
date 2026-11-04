import {
  $,
  component$,
  noSerialize,
  sync$,
  useContext,
  useId,
  useOnDocument,
  useSignal,
  useStore,
  useVisibleTask$,
  type NoSerialize,
  type QRL,
} from "@qwik.dev/core";
import type { Blocked } from "@segv/engine/types";
import { loadEngine } from "./engine-loader";
import { ReplyIcon } from "./reply";
import { UiCtx } from "./state";
import {
  enqueue,
  errMsg,
  fmtBytes,
  MAX_FILE_BYTES,
  MAX_IMAGE_INPUT_BYTES,
  textTooLong,
} from "./util";

const MAX_PENDING = 10;

type Stash = HTMLElement & { _segvFiles?: File[] };

/** What a pick is sent as: an image is re-encoded without its metadata (§8.1), a file goes as it is (§8.3). */
interface Pending {
  f: File;
  as: "image" | "file";
}

/** An image the engine can re-encode; any other file, an SVG included, is sent as a file. */
const isImage = (f: File): boolean => f.type.startsWith("image/") && f.type !== "image/svg+xml";

/** Enter sends unless shift is held, an IME is composing, or the device is touch-first. */
const ENTER_SENDS = sync$((e: KeyboardEvent): void => {
  if (e.key !== "Enter" || e.shiftKey || e.isComposing || e.keyCode === 229) return;
  if (matchMedia("(hover: none) and (pointer: coarse)").matches) return;
  e.preventDefault();
  (e.target as HTMLElement).setAttribute("data-send", "1");
});

/** Clipboard / drop data is only readable during dispatch: stash the files synchronously. */
const STASH_FILES = sync$((e: ClipboardEvent | DragEvent, el: HTMLElement): void => {
  const dt = "clipboardData" in e ? e.clipboardData : (e as DragEvent).dataTransfer;
  const files = dt ? Array.from(dt.files) : [];
  if (files.length) {
    (el as HTMLElement & { _segvFiles?: File[] })._segvFiles = files;
    if (e.type === "drop") e.preventDefault();
  }
});

/** A menu item opens its file picker within the click itself, as browsers require. */
const PICK = sync$((_: MouseEvent, el: HTMLElement): void => {
  const which = el.getAttribute("data-pick");
  el.closest(".attach")?.querySelector<HTMLInputElement>(`input[data-pick="${which}"]`)?.click();
});

/**
 * The "+" beside the message box and its menu: an image (re-encoded without its metadata, §8.1) or a file (sent as it
 * is, §8.3). A click outside or escape closes the menu.
 */
const Attach = component$<{ onPick$: QRL<(picked: File[], asFiles?: boolean) => void> }>(
  (props) => {
    const open = useSignal(false);
    const box = useSignal<HTMLElement>();
    const plus = useSignal<HTMLButtonElement>();
    const first = useSignal<HTMLButtonElement>();
    // the reply pane has a message box of its own: one id per menu
    const id = useId();
    const menuId = `attach-menu-${id}`;

    useOnDocument(
      "click",
      $((e: Event) => {
        if (open.value && !box.value?.contains(e.target as Node)) open.value = false;
      }),
    );
    useOnDocument(
      "keydown",
      $((e: KeyboardEvent) => {
        if (e.key !== "Escape" || !open.value) return;
        open.value = false;
        plus.value?.focus();
      }),
    );
    useVisibleTask$(({ track }) => {
      if (track(() => open.value)) first.value?.focus();
    });

    const close = $(() => {
      open.value = false;
    });
    const picked = $((el: HTMLInputElement, asFiles: boolean) => {
      const files = Array.from(el.files ?? []);
      el.value = "";
      return props.onPick$(files, asFiles);
    });

    return (
      <div class="attach" ref={box}>
        <button
          type="button"
          class="plus"
          ref={plus}
          aria-label="attach"
          aria-expanded={open.value}
          aria-controls={menuId}
          onClick$={() => (open.value = !open.value)}
        >
          <span aria-hidden="true">+</span>
        </button>
        {open.value && (
          <div class="menu" id={menuId}>
            <button type="button" ref={first} data-pick="image" onClick$={[PICK, close]}>
              image <span class="small note">metadata removed</span>
            </button>
            <button type="button" data-pick="file" onClick$={[PICK, close]}>
              file <span class="small note">sent as it is, up to {fmtBytes(MAX_FILE_BYTES)}</span>
            </button>
          </div>
        )}
        <input
          class="vh"
          type="file"
          accept="image/*"
          multiple
          tabIndex={-1}
          aria-label="attach image"
          data-pick="image"
          onChange$={(_, el: HTMLInputElement) => picked(el, false)}
        />
        <input
          class="vh"
          type="file"
          multiple
          tabIndex={-1}
          aria-label="attach file"
          data-pick="file"
          onChange$={(_, el: HTMLInputElement) => picked(el, true)}
        />
      </div>
    );
  },
);

/** An arrow pointing up: send. */
const SendIcon = () => (
  <svg
    class="icon"
    viewBox="0 0 20 20"
    aria-hidden="true"
    fill="none"
    stroke="currentColor"
    stroke-width="2"
    stroke-linecap="round"
    stroke-linejoin="round"
  >
    <path d="M10 16V4M5 9l5-5 5 5" />
  </svg>
);

/** Why the composer is replaced by a notice (`ConversationView.blocked`); "" never reaches it. */
const BLOCKED_TEXT: Record<Exclude<Blocked, "">, string> = {
  removed:
    "you are no longer a member of this conversation. you can read its history but cannot send.",
  left: "you are no longer a member of this conversation. you can read its history but cannot send.",
  pending: "the conversation is changing membership; you can send again in a moment.",
  frozen: "a removed member could still read this conversation; start a new conversation.",
};

/**
 * A message box: the conversation's, below its messages, or the reply pane's (reply-tree.tsx). While `replyTo` names
 * a message (`replyWho` and `replyGist` describe it), what is sent replies to it (§11.17): the text and each
 * attachment of that send. After a send, and with escape or × where `canStop`, it calls `setReply$("")`.
 */
export const Composer = component$<{
  convId: string;
  blocked: Blocked;
  /** the key of the message that what is sent replies to ('' = none) */
  replyTo: string;
  replyWho: string;
  replyGist: string;
  /** escape and × stop replying */
  canStop: boolean;
  setReply$: QRL<(key: string) => void>;
  /** the box's accessible name */
  label?: string;
}>((props) => {
  const ui = useContext(UiCtx);
  const draft = useSignal("");
  const hint = useSignal("");
  const ta = useSignal<HTMLTextAreaElement>();
  const files = useStore<{ list: NoSerialize<Pending[]> }>({ list: undefined });

  useVisibleTask$(() => {
    if (matchMedia("(hover: hover) and (pointer: fine)").matches) ta.value?.focus();
  });

  /** The box grows with its text: by CSS where `field-sizing` works, otherwise to the text's height here. */
  useVisibleTask$(({ track }) => {
    if (CSS.supports("field-sizing: content")) return;
    track(() => draft.value);
    const el = ta.value;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  });

  /** Adds picks: as files with "attach file", otherwise images as images and every other file as a file. */
  const addFiles = $((picked: File[], asFiles = false) => {
    const cur = files.list ?? [];
    const next = [...cur];
    for (const f of picked) {
      const as = !asFiles && isImage(f) ? "image" : "file";
      if (as === "image" && f.size > MAX_IMAGE_INPUT_BYTES) {
        hint.value = `${f.name || "image"} is too large (${fmtBytes(f.size)})`;
        continue;
      }
      if (as === "file" && f.size > MAX_FILE_BYTES) {
        hint.value = `${f.name || "file"} is too large (at most ${fmtBytes(MAX_FILE_BYTES)})`;
        continue;
      }
      if (next.length >= MAX_PENDING) {
        hint.value = `at most ${MAX_PENDING} attachments at once`;
        break;
      }
      next.push({ f, as });
    }
    files.list = next.length ? noSerialize(next) : undefined;
  });

  const send = $(async () => {
    const convId = props.convId;
    const text = draft.value.replace(/^\s*\n/, "").trimEnd();
    const picks = files.list ?? [];
    if (!text.trim() && !picks.length) return;
    if (text && textTooLong(text)) {
      hint.value = "message too long";
      return;
    }
    const replyTo = props.replyTo;
    draft.value = "";
    files.list = undefined;
    hint.value = "";
    ui.localError = "";
    await props.setReply$("");
    try {
      const engine = await loadEngine();
      const to = replyTo || undefined;
      for (const p of picks)
        await enqueue(convId, () =>
          p.as === "image" ? engine.sendImage(convId, p.f, to) : engine.sendFile(convId, p.f, to),
        );
      if (text.trim()) await enqueue(convId, () => engine.sendText(convId, text, to));
    } catch (e) {
      ui.localError = errMsg(e);
      if (!draft.value && text) {
        draft.value = text; // give the text back if it never left, with what it replied to
        if (replyTo) await props.setReply$(replyTo);
      }
    }
  });

  if (props.blocked !== "") {
    return (
      <div class="composer">
        <p class="dim">{BLOCKED_TEXT[props.blocked]}</p>
      </div>
    );
  }

  const pending = files.list ?? [];
  const tooLong = textTooLong(draft.value);
  return (
    <div
      class="composer"
      preventdefault:dragover
      onDrop$={[
        STASH_FILES,
        $((_: DragEvent, el: HTMLElement) => {
          const s = el as Stash;
          const f = s._segvFiles;
          s._segvFiles = undefined;
          if (f) return addFiles(f);
        }),
      ]}
    >
      {pending.length > 0 && (
        <ul class="pending" aria-label="attachments to send">
          {pending.map(({ f, as }, i) => (
            <li key={`${i}:${f.name}:${f.size}`}>
              <span>
                {as === "image"
                  ? `image: ${f.name || "pasted image"}`
                  : `file: ${f.name || "file"} (sent as it is)`}{" "}
                ({fmtBytes(f.size)})
              </span>{" "}
              <button
                type="button"
                class="link"
                onClick$={() => {
                  const next = (files.list ?? []).filter((_, j) => j !== i);
                  files.list = next.length ? noSerialize(next) : undefined;
                }}
              >
                remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {props.replyTo && props.replyWho && (
        <div class="replybar">
          <ReplyIcon />
          <span class="rtext">
            replying to <b>{props.replyWho}</b> <span class="dim">{props.replyGist}</span>
          </span>
          {props.canStop && (
            <button
              type="button"
              class="xbtn"
              aria-label="stop replying"
              title="stop replying (esc)"
              onClick$={async () => {
                await props.setReply$("");
                ta.value?.focus();
              }}
            >
              ×
            </button>
          )}
        </div>
      )}
      <div class="inputrow">
        <Attach onPick$={addFiles} />
        <div class="field">
          <textarea
            ref={ta}
            rows={1}
            aria-label={props.label ?? "message"}
            placeholder={props.label ?? "message"}
            bind:value={draft}
            onKeyDown$={[
              ENTER_SENDS,
              $((e: KeyboardEvent, el: HTMLTextAreaElement) => {
                if (e.key === "Escape" && !e.isComposing && props.canStop && props.replyTo) {
                  void props.setReply$("");
                  return;
                }
                if (el.getAttribute("data-send")) {
                  el.removeAttribute("data-send");
                  return send();
                }
              }),
            ]}
            onPaste$={[
              STASH_FILES,
              $((_: ClipboardEvent, el: HTMLTextAreaElement) => {
                const s = el as Stash;
                const f = s._segvFiles;
                s._segvFiles = undefined;
                if (f) return addFiles(f);
              }),
            ]}
          />
          <button
            type="button"
            class="send"
            aria-label="send"
            onClick$={[
              $(() => {
                if (matchMedia("(hover: hover) and (pointer: fine)").matches) ta.value?.focus();
              }),
              send,
            ]}
            disabled={tooLong || (!draft.value.trim() && !pending.length)}
          >
            <SendIcon />
          </button>
        </div>
      </div>
      {(tooLong || hint.value) && (
        <p class={["small", tooLong ? "strong" : "dim", "hint"]}>
          {tooLong ? "message too long" : hint.value}
        </p>
      )}
    </div>
  );
});

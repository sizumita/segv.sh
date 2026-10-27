import {
  $,
  component$,
  noSerialize,
  sync$,
  useContext,
  useSignal,
  useStore,
  useVisibleTask$,
  type NoSerialize,
} from "@qwik.dev/core";
import type { Blocked } from "~/client/types";
import { loadEngine } from "./engine-loader";
import { UiCtx } from "./state";
import { enqueue, errMsg, fmtBytes, MAX_IMAGE_INPUT_BYTES, textTooLong } from "./util";

const MAX_PENDING = 10;

type Stash = HTMLElement & { _segvFiles?: File[] };

/** Enter sends unless shift is held, an IME is composing, or the device is touch-first. */
const ENTER_SENDS = sync$((e: KeyboardEvent): void => {
  if (e.key !== "Enter" || e.shiftKey || e.isComposing || e.keyCode === 229) return;
  if (matchMedia("(hover: none) and (pointer: coarse)").matches) return;
  e.preventDefault();
  (e.target as HTMLElement).setAttribute("data-send", "1");
});

/** Clipboard / drop data is only readable during dispatch: stash the image files synchronously. */
const STASH_FILES = sync$((e: ClipboardEvent | DragEvent, el: HTMLElement): void => {
  const dt = "clipboardData" in e ? e.clipboardData : (e as DragEvent).dataTransfer;
  const files = dt ? Array.from(dt.files).filter((f) => f.type.startsWith("image/")) : [];
  if (files.length) {
    (el as HTMLElement & { _segvFiles?: File[] })._segvFiles = files;
    if (e.type === "drop") e.preventDefault();
  }
});

/** Why the composer is replaced by a notice (docs/STAGE1-PLAN.md §0.4); "" never reaches it. */
const BLOCKED_TEXT: Record<Exclude<Blocked, "">, string> = {
  removed:
    "you are no longer a member of this conversation. you can read its history but cannot send.",
  left: "you are no longer a member of this conversation. you can read its history but cannot send.",
  pending: "the conversation is changing membership; you can send again in a moment.",
  frozen: "a removed member could still read this conversation; start a new conversation.",
};

export const Composer = component$<{ convId: string; blocked: Blocked }>((props) => {
  const ui = useContext(UiCtx);
  const draft = useSignal("");
  const hint = useSignal("");
  const ta = useSignal<HTMLTextAreaElement>();
  const files = useStore<{ list: NoSerialize<File[]> }>({ list: undefined });

  useVisibleTask$(() => {
    if (matchMedia("(hover: hover) and (pointer: fine)").matches) ta.value?.focus();
  });

  const addFiles = $((picked: File[]) => {
    const cur = files.list ?? [];
    const next = [...cur];
    for (const f of picked) {
      if (!f.type.startsWith("image/")) {
        hint.value = `${f.name || "file"} is not an image`;
        continue;
      }
      if (f.size > MAX_IMAGE_INPUT_BYTES) {
        hint.value = `${f.name || "image"} is too large (${fmtBytes(f.size)})`;
        continue;
      }
      if (next.length >= MAX_PENDING) {
        hint.value = `at most ${MAX_PENDING} images at once`;
        break;
      }
      next.push(f);
    }
    files.list = next.length ? noSerialize(next) : undefined;
  });

  const send = $(async () => {
    const convId = props.convId;
    const text = draft.value.replace(/^\s*\n/, "").trimEnd();
    const pics = files.list ?? [];
    if (!text.trim() && !pics.length) return;
    if (text && textTooLong(text)) {
      hint.value = "message too long";
      return;
    }
    draft.value = "";
    files.list = undefined;
    hint.value = "";
    ui.localError = "";
    try {
      const engine = await loadEngine();
      for (const f of pics) await enqueue(convId, () => engine.sendImage(convId, f));
      if (text.trim()) await enqueue(convId, () => engine.sendText(convId, text));
    } catch (e) {
      ui.localError = errMsg(e);
      if (!draft.value && text) draft.value = text; // give the text back if it never left
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
        <ul class="pending" aria-label="images to send">
          {pending.map((f, i) => (
            <li key={`${i}:${f.name}:${f.size}`}>
              <span>
                image: {f.name || "pasted image"} ({fmtBytes(f.size)})
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
      <textarea
        ref={ta}
        rows={2}
        aria-label="message"
        placeholder="message"
        bind:value={draft}
        onKeyDown$={[
          ENTER_SENDS,
          $((_: KeyboardEvent, el: HTMLTextAreaElement) => {
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
      <div class="row">
        <label class="btn">
          attach image
          <input
            class="vh"
            type="file"
            accept="image/*"
            multiple
            onChange$={(_, el: HTMLInputElement) => {
              const picked = Array.from(el.files ?? []);
              el.value = "";
              return addFiles(picked);
            }}
          />
        </label>
        <span class={["small", "grow", tooLong ? "strong" : "dim", "hint"]}>
          {tooLong
            ? "message too long"
            : hint.value || "enter to send · shift+enter for a new line"}
        </span>
        <button
          type="button"
          class="send"
          onClick$={[
            $(() => {
              if (matchMedia("(hover: hover) and (pointer: fine)").matches) ta.value?.focus();
            }),
            send,
          ]}
          disabled={tooLong || (!draft.value.trim() && !pending.length)}
        >
          send
        </button>
      </div>
    </div>
  );
});

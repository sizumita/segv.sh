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
import { EditIcon, SaveIcon } from "./edit";
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

/**
 * ArrowUp in the empty box edits self's last message (§11.18), where the box allows it (`data-up-edits`: the
 * conversation's box, with nothing attached and nothing being edited): without modifiers, an IME composing, or a
 * touch-first device. The browser's own move of the caret is prevented here, as only a synchronous handler can.
 */
const UP_EDITS = sync$((e: KeyboardEvent, el: HTMLTextAreaElement): void => {
  if (e.key !== "ArrowUp" || e.shiftKey || e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.isComposing || e.keyCode === 229 || el.value !== "" || !el.hasAttribute("data-up-edits"))
    return;
  if (!matchMedia("(hover: hover) and (pointer: fine)").matches) return;
  e.preventDefault();
  el.setAttribute("data-edit-last", "1");
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
const Attach = component$<{
  onPick$: QRL<(picked: File[], asFiles?: boolean) => void>;
  /** nothing can be attached (while a message is edited) */
  disabled?: boolean;
}>((props) => {
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
  useVisibleTask$(({ track }) => {
    if (track(() => props.disabled)) open.value = false;
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
        disabled={props.disabled}
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
});

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
 *
 * The conversation's box also edits self's messages (§11.18). While `editKey` names one, the box holds that message's
 * text in place of the user's draft, which comes back afterwards; Enter or "save" saves the edit, escape or × stops
 * editing (`setEdit$("")`), and nothing can be attached. ArrowUp in the empty box calls `editLast$`.
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
  /** the key of self's message that the box edits ('' or absent = none) */
  editKey?: string;
  /** that message's current text, which the box starts from */
  editText?: string;
  /** one line of it, for the "editing" bar */
  editGist?: string;
  /** starts editing `key`, or stops ('' ); false when `key` cannot be edited (it then changes nothing) */
  setEdit$?: QRL<(key: string) => boolean>;
  /** ArrowUp in the empty box: edit self's last message */
  editLast$?: QRL<() => void>;
}>((props) => {
  const ui = useContext(UiCtx);
  const draft = useSignal("");
  const hint = useSignal("");
  const ta = useSignal<HTMLTextAreaElement>();
  const files = useStore<{ list: NoSerialize<Pending[]> }>({ list: undefined });
  /** the message whose text the box holds ('' = it holds the user's own draft) */
  const editing = useSignal("");
  /** the user's own draft, while the box holds a message's text */
  const saved = useSignal("");
  /** counts the saves of edits, so that a failed save puts editing back only while no later one has started */
  const saves = useSignal(0);
  /** a save stopped editing: the box takes the focus back once the "editing" bar has gone */
  const savedFocus = useSignal(false);

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

  // Editing starts, or moves to another message: the box sets the user's draft aside and holds the message's text, with
  // the caret at its end. Editing stops: the draft comes back. A save changes `editing` itself, so that nothing here
  // undoes it.
  useVisibleTask$(
    ({ track }) => {
      const key = track(() => props.editKey ?? "");
      // The "editing" bar above the box came or went, which takes the focus from the box: it goes back there, unless
      // the user has moved it elsewhere.
      const refocus = () => {
        const el = ta.value;
        const a = document.activeElement;
        if (el && (!a || a === document.body)) el.focus();
      };
      if (key === editing.value) {
        // back to editing after a failed save, or a save stopped editing
        if (key || savedFocus.value) refocus();
        savedFocus.value = false;
        return;
      }
      const was = editing.value;
      editing.value = key;
      hint.value = "";
      if (!key) {
        draft.value = saved.value;
        saved.value = "";
        refocus();
        return;
      }
      if (!was) saved.value = draft.value;
      const text = props.editText ?? "";
      draft.value = text;
      const el = ta.value;
      if (!el) return;
      el.value = text;
      el.focus();
      el.setSelectionRange(text.length, text.length);
    },
    { strategy: "document-ready" },
  );

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

  /**
   * Saves the edit of the message the box holds (§11.18): editing stops at once and the user's draft comes back; an
   * unchanged text sends nothing; a failure shows its error and goes back to editing with the text that was not saved.
   */
  const save = $(async () => {
    const key = editing.value;
    const text = draft.value.replace(/^\s*\n/, "").trimEnd();
    if (!text.trim() || textTooLong(text)) return; // the hint below the box says why
    const before = (props.editText ?? "").replace(/^\s*\n/, "").trimEnd();
    editing.value = "";
    draft.value = saved.value;
    saved.value = "";
    hint.value = "";
    ui.localError = "";
    savedFocus.value = true;
    await props.setEdit$?.("");
    if (text === before) return;
    const restored = draft.value;
    const n = ++saves.value;
    const convId = props.convId;
    try {
      const engine = await loadEngine();
      await enqueue(convId, () => engine.editText(convId, key, text));
    } catch (e) {
      ui.localError = errMsg(e);
      // Back to editing, with the text that was not saved: not once the user has moved on (another edit, a reply, a
      // new draft), nor for a message that can no longer be edited.
      const movedOn = editing.value || props.editKey || props.replyTo || draft.value !== restored;
      if (movedOn || n !== saves.value) return;
      saved.value = restored;
      editing.value = key;
      draft.value = text;
      if (await props.setEdit$?.(key)) return;
      editing.value = "";
      draft.value = restored;
      saved.value = "";
    }
  });

  const send = $(async () => {
    // While editing, the box saves the edit, once it holds the message's text; never a new message.
    if (props.editKey || editing.value) {
      if (editing.value === props.editKey) await save();
      return;
    }
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

  const isEditing = !!props.editKey;
  const pending = isEditing ? [] : (files.list ?? []);
  const tooLong = textTooLong(draft.value);
  // Once the box holds the message's text: an edit cannot remove all of it (there is no deletion, §0.4).
  const emptyEdit = isEditing && editing.value === props.editKey && !draft.value.trim();
  const label = isEditing ? "edit message" : (props.label ?? "message");
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
          if (f && !props.editKey) return addFiles(f);
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
      {isEditing ? (
        <div class="replybar editbar">
          <EditIcon />
          <span class="rtext">
            editing <span class="dim">{props.editGist}</span>
          </span>
          <button
            type="button"
            class="xbtn"
            aria-label="stop editing"
            title="stop editing (esc)"
            onClick$={async () => {
              await props.setEdit$?.("");
              ta.value?.focus();
            }}
          >
            ×
          </button>
        </div>
      ) : (
        props.replyTo &&
        props.replyWho && (
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
        )
      )}
      <div class="inputrow">
        <Attach onPick$={addFiles} disabled={isEditing} />
        <div class="field">
          <textarea
            ref={ta}
            rows={1}
            aria-label={label}
            placeholder={label}
            data-up-edits={props.editLast$ && !isEditing && !pending.length ? "1" : undefined}
            bind:value={draft}
            onKeyDown$={[
              ENTER_SENDS,
              UP_EDITS,
              $((e: KeyboardEvent, el: HTMLTextAreaElement) => {
                if (e.key === "Escape" && !e.isComposing && props.editKey) {
                  void props.setEdit$?.("");
                  return;
                }
                if (e.key === "Escape" && !e.isComposing && props.canStop && props.replyTo) {
                  void props.setReply$("");
                  return;
                }
                if (el.getAttribute("data-edit-last")) {
                  el.removeAttribute("data-edit-last");
                  return props.editLast$?.();
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
                if (f && !props.editKey) return addFiles(f);
              }),
            ]}
          />
          <button
            type="button"
            class="send"
            aria-label={isEditing ? "save" : "send"}
            title={isEditing ? "save" : undefined}
            onClick$={[
              $(() => {
                if (matchMedia("(hover: hover) and (pointer: fine)").matches) ta.value?.focus();
              }),
              send,
            ]}
            disabled={tooLong || (!draft.value.trim() && (isEditing || !pending.length))}
          >
            {isEditing ? <SaveIcon /> : <SendIcon />}
          </button>
        </div>
      </div>
      {(tooLong || emptyEdit || hint.value) && (
        <p class={["small", tooLong ? "strong" : "dim", "hint"]}>
          {tooLong ? "message too long" : emptyEdit ? "an edit cannot be empty" : hint.value}
        </p>
      )}
    </div>
  );
});

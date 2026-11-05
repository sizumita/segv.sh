import { component$, useContext, useId, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import type { ConversationView, EditVersion } from "@segv/engine/types";
import { loadEngine } from "./engine-loader";
import { MsgText } from "./msg-text";
import { PaneCtx } from "./state";
import { fullTime } from "./util";

/** A pencil: edit the message. */
export const EditIcon = () => (
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
    <path d="M13.6 3.6a1.98 1.98 0 0 1 2.8 2.8L7 15.8l-3.5.7.7-3.5z" />
    <path d="M12 5.2l2.8 2.8" />
  </svg>
);

/** A check mark: save the edit. */
export const SaveIcon = () => (
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
    <path d="M4.5 10.5l3.5 3.5 7.5-8" />
  </svg>
);

/**
 * The versions of an edited message (§11.18 "Display"), oldest first: its own text, then each edit's, each with its
 * time; `PaneState.history` names the message. A modal <dialog> like "open this link?" (leaving.tsx): every way of
 * closing clears `PaneState.history`, and so does the message leaving the view. The list is read again when an edit of
 * the message comes while it is open.
 */
export const EditHistory = component$<{ conv: ConversationView }>((props) => {
  const pane = useContext(PaneCtx);
  const dlg = useSignal<HTMLDialogElement>();
  const versions = useSignal<EditVersion[] | null>(null);
  /** what the list was read for: the message's key and its edits then */
  const readFor = useSignal("");
  const id = useId();
  const titleId = `eh-title-${id}`;

  useVisibleTask$(
    ({ cleanup }) => {
      const d = dlg.value;
      if (!d) return;
      const onClose = () => (pane.history = "");
      d.addEventListener("close", onClose);
      if (!d.open) d.showModal();
      cleanup(() => d.removeEventListener("close", onClose));
    },
    { strategy: "document-ready" },
  );

  useVisibleTask$(
    async ({ track }) => {
      const key = track(() => pane.history);
      const m = track(() => props.conv.messages.find((x) => x.key === key));
      if (!m) {
        dlg.value?.close();
        return;
      }
      const at = `${key}\n${m.edited?.count ?? 0}\n${m.edited?.ts ?? 0}`;
      if (at === readFor.value) return;
      readFor.value = at;
      let list: EditVersion[] = [];
      try {
        list = (await loadEngine()).editHistory(props.conv.id, key);
      } catch {
        // the engine is not there: nothing to show
      }
      if (readFor.value === at) versions.value = list;
    },
    { strategy: "document-ready" },
  );

  const list = versions.value;
  return (
    <dialog
      ref={dlg}
      class="history"
      aria-labelledby={titleId}
      // A click on the backdrop lands on the <dialog> itself; the sheet inside covers the rest.
      onClick$={(e, el) => {
        if (e.target === el) el.close();
      }}
    >
      <div class="sheet">
        <header class="row">
          <h2 id={titleId} class="grow">
            edit history
          </h2>
          <button
            type="button"
            class="xbtn"
            aria-label="close"
            title="close (esc)"
            onClick$={() => dlg.value?.close()}
          >
            ×
          </button>
        </header>
        {list && list.length === 0 && <p class="dim small">no earlier versions.</p>}
        {list && list.length > 0 && (
          <ol class="versions">
            {list.map((v, i) => (
              <li key={i}>
                <p class="vmeta">
                  <b>{i === 0 ? "original" : `edit ${i}`}</b>{" "}
                  <span class="dim">{fullTime(v.ts)}</span>
                </p>
                <MsgText text={v.text} />
              </li>
            ))}
          </ol>
        )}
      </div>
    </dialog>
  );
});

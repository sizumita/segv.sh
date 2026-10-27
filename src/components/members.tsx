import { $, component$, useContext, useSignal } from "@qwik.dev/core";
import type { ConversationView } from "~/client/types";
import { StateCtx, UiCtx } from "./state";
import { act, parseHandles } from "./util";

export const Members = component$<{ conv: ConversationView }>((props) => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const confirmUid = useSignal("");
  const confirmLeave = useSignal(false);
  const busy = useSignal(false);
  const add = useSignal("");
  const addError = useSignal("");

  const conv = props.conv;
  const meUid = state.me?.uid ?? "";
  /** add and remove need a sendable, unfrozen conversation; a frozen member can still leave (SPEC §6.6 step 6) */
  const canChange = conv.canSend && !conv.frozen;
  const canLeave = conv.blocked !== "removed" && conv.blocked !== "left";

  const addMembers = $(async () => {
    if (busy.value) return;
    const c = props.conv;
    const parsed = parseHandles(
      add.value,
      state.me?.handle,
      c.members.map((m) => m.handle),
    );
    if (!parsed.ok) {
      addError.value = parsed.error;
      return;
    }
    addError.value = "";
    busy.value = true;
    const ok = await act(ui, async (e) => {
      await e.addMembers(c.id, parsed.handles);
      return true;
    });
    busy.value = false;
    if (ok) add.value = "";
  });

  return (
    <aside class="members" aria-label="members">
      <header class="row">
        <h3 class="grow">members · epoch {conv.epoch}</h3>
        <button type="button" class="link" onClick$={() => (ui.members = false)}>
          close
        </button>
      </header>
      <p class="dim small">
        compare safety numbers with each member in person or over another channel. if they don't
        match, someone may be impersonating them.
      </p>
      <ul class="mlist">
        {conv.members.map((m) => {
          const self = m.uid === meUid;
          return (
            <li key={m.uid}>
              <p class="row">
                <b class="grow">
                  {m.handle}
                  {self && <span class="dim"> (you)</span>}
                  {m.left && <span class="dim"> (left)</span>}
                </b>
                {!self && canChange && confirmUid.value !== m.uid && (
                  <button
                    type="button"
                    class="link"
                    disabled={busy.value}
                    onClick$={() => {
                      confirmUid.value = m.uid;
                      confirmLeave.value = false;
                    }}
                  >
                    remove
                  </button>
                )}
              </p>
              <p class="fp small" aria-label={`safety number of ${m.handle}`}>
                {m.fingerprint}
              </p>
              {confirmUid.value === m.uid && (
                <p class="row confirm">
                  <span class="grow">remove {m.handle}?</span>
                  <button
                    type="button"
                    disabled={busy.value}
                    onClick$={async () => {
                      busy.value = true;
                      await act(ui, (e) => e.removeMember(props.conv.id, m.uid));
                      busy.value = false;
                      confirmUid.value = "";
                    }}
                  >
                    remove
                  </button>
                  <button type="button" class="link" onClick$={() => (confirmUid.value = "")}>
                    cancel
                  </button>
                </p>
              )}
            </li>
          );
        })}
      </ul>

      {canChange && (
        <>
          <form class="addm" preventdefault:submit onSubmit$={addMembers}>
            <input
              type="text"
              aria-label="add members"
              placeholder="add: handles"
              autocapitalize="none"
              autocomplete="off"
              spellcheck={false}
              bind:value={add}
              onInput$={() => (addError.value = "")}
              disabled={busy.value}
            />
            <button type="submit" disabled={busy.value || !add.value.trim()}>
              add
            </button>
          </form>
          {addError.value && (
            <p class="small strong" role="alert">
              {addError.value}
            </p>
          )}
        </>
      )}
      {canLeave && (
        <>
          <div class="leave">
            {!confirmLeave.value ? (
              <button
                type="button"
                class="link"
                disabled={busy.value}
                onClick$={() => {
                  confirmLeave.value = true;
                  confirmUid.value = "";
                }}
              >
                leave conversation
              </button>
            ) : (
              <p class="row confirm">
                <span class="grow">
                  leave for good? you can only come back if someone adds you.
                </span>
                <button
                  type="button"
                  disabled={busy.value}
                  onClick$={async () => {
                    busy.value = true;
                    await act(ui, (e) => e.leave(props.conv.id));
                    busy.value = false;
                    confirmLeave.value = false;
                  }}
                >
                  leave
                </button>
                <button type="button" class="link" onClick$={() => (confirmLeave.value = false)}>
                  cancel
                </button>
              </p>
            )}
          </div>
        </>
      )}
    </aside>
  );
});

import {
  $,
  component$,
  sync$,
  useContext,
  useSignal,
  useVisibleTask$,
  type QRL,
} from "@qwik.dev/core";
import type { ConversationView, MemberView } from "@segv/engine/types";
import { StateCtx, UiCtx } from "./state";
import {
  act,
  atHandle,
  identitiesOf,
  isGone,
  MAX_NAME,
  nameWithHandle,
  parseHandles,
} from "./util";

/**
 * Escape in the nickname box stops editing, and does not close what the panel is in. An escape while an input method
 * composes cancels the composition only (Safari sends it with keyCode 229 and isComposing false).
 */
const NICK_KEYS = sync$((e: KeyboardEvent, el: HTMLInputElement): void => {
  if (e.key !== "Escape" || e.isComposing || e.keyCode === 229) return;
  e.preventDefault();
  el.setAttribute("data-cancel", "1");
});

/**
 * The nickname the user gives a member, for their own eyes (§11.19), in place of the member's row while it is edited:
 * "save" writes it, "remove" takes it off, "cancel" or Escape leaves it as it was.
 */
const NickForm = component$<{ m: MemberView; onDone$: QRL<() => void> }>((props) => {
  const ui = useContext(UiCtx);
  const text = useSignal(props.m.nickname);
  const busy = useSignal(false);
  const box = useSignal<HTMLInputElement>();

  useVisibleTask$(() => {
    const el = box.value;
    if (!el || !matchMedia("(hover: hover) and (pointer: fine)").matches) return;
    el.focus();
    el.select();
  });

  const write = $(async (nickname: string) => {
    if (busy.value) return;
    busy.value = true;
    const ok = await act(ui, async (e) => {
      await e.setNickname(props.m.uid, nickname);
      return true;
    });
    busy.value = false;
    if (ok) await props.onDone$();
  });

  const t = text.value.trim();
  // §11.19: what the engine refuses, said before it is sent (it checks it all the same)
  const bad =
    [...t].length > MAX_NAME || t.normalize("NFKC").startsWith("@")
      ? "a nickname: 1–64 characters, not starting with @"
      : "";
  const handle = props.m.handle;
  return (
    <form
      class="nickform"
      preventdefault:submit
      onSubmit$={() => {
        if (t && !bad) return write(t);
      }}
    >
      <input
        ref={box}
        type="text"
        aria-label={`nickname for @${handle}`}
        placeholder={`a name for @${handle}`}
        autocomplete="off"
        maxLength={MAX_NAME * 2}
        value={text.value}
        disabled={busy.value}
        aria-invalid={bad ? true : undefined}
        onInput$={(_, el: HTMLInputElement) => (text.value = el.value)}
        onKeyDown$={[
          NICK_KEYS,
          $((_: KeyboardEvent, el: HTMLInputElement) => {
            if (!el.getAttribute("data-cancel")) return;
            el.removeAttribute("data-cancel");
            return props.onDone$();
          }),
        ]}
      />
      <p class={["small", bad ? "strong" : "dim"]}>
        {bad || "only you see it, on your devices; others still see their handle."}
      </p>
      <p class="row">
        <button type="submit" disabled={busy.value || !t || !!bad || t === props.m.nickname}>
          {busy.value ? "saving…" : "save"}
        </button>
        {props.m.nickname && (
          <button type="button" class="link" disabled={busy.value} onClick$={() => write("")}>
            remove
          </button>
        )}
        <button type="button" class="link" disabled={busy.value} onClick$={props.onDone$}>
          cancel
        </button>
      </p>
    </form>
  );
});

export const Members = component$<{ conv: ConversationView }>((props) => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const confirmUid = useSignal("");
  const confirmLeave = useSignal(false);
  /** the member whose nickname is being edited ('' = none) */
  const naming = useSignal("");
  const busy = useSignal(false);
  const add = useSignal("");
  const addError = useSignal("");

  const conv = props.conv;
  /**
   * add and remove need a sendable, unfrozen conversation; a frozen member can still leave (§6.6 step 6). A request
   * is read-only until accepted: changing or leaving it would post in it, which accepts it (§11.5).
   */
  const canChange = !conv.request && conv.canSend && !conv.frozen;
  const canLeave = !conv.request && !isGone(conv);

  const addMembers = $(async () => {
    if (busy.value) return;
    const c = props.conv;
    const self = c.members.find((m) => m.you)?.handle;
    const own = identitiesOf(state)
      .map((i) => i.handle)
      .filter((h) => h && h !== self);
    const parsed = parseHandles(
      add.value,
      self,
      c.members.map((m) => m.handle),
      own,
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
          const self = m.you;
          // nicknames are for other users the client shows by handle: never for the user's own accounts (another one
          // is a separate member here, §2.6), nor for an unknown `?…` member (§11.19)
          const nameable = !self && !m.own && !m.handle.startsWith("?");
          return (
            <li key={m.uid}>
              <p class="row">
                <span class="grow mname">
                  {m.nickname ? (
                    <>
                      <b>{m.nickname}</b> <span class="dim">{atHandle(m.handle)}</span>
                    </>
                  ) : (
                    <b>{atHandle(m.handle)}</b>
                  )}
                  {self && <span class="dim"> (you)</span>}
                  {m.own && <span class="dim"> (your other handle)</span>}
                  {m.left && <span class="dim"> (left)</span>}
                </span>
                {nameable && naming.value !== m.uid && (
                  <button
                    type="button"
                    class="link small"
                    aria-label={
                      m.nickname
                        ? `change the nickname of @${m.handle}`
                        : `give @${m.handle} a nickname`
                    }
                    title="a name only you see"
                    onClick$={() => {
                      naming.value = m.uid;
                      confirmUid.value = "";
                    }}
                  >
                    nickname
                  </button>
                )}
                {!self && canChange && confirmUid.value !== m.uid && (
                  <button
                    type="button"
                    class="link small"
                    disabled={busy.value}
                    onClick$={() => {
                      confirmUid.value = m.uid;
                      confirmLeave.value = false;
                      naming.value = "";
                    }}
                  >
                    remove
                  </button>
                )}
              </p>
              {naming.value === m.uid && (
                <NickForm
                  key={m.uid}
                  m={m}
                  onDone$={$(() => {
                    naming.value = "";
                  })}
                />
              )}
              <p class="fp small" aria-label={`safety number of ${atHandle(m.handle)}`}>
                {m.fingerprint}
              </p>
              {confirmUid.value === m.uid && (
                <p class="row confirm">
                  <span class="grow">remove {nameWithHandle(m.handle, m.nickname)}?</span>
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
          <div class="mleave">
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

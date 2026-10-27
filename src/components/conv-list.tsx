import { $, component$, useContext, useSignal } from "@qwik.dev/core";
import { type ListView, StateCtx, UiCtx } from "./state";
import { act, listOf, MAX_NAME, parseHandles, relTime } from "./util";

const LISTS: { id: ListView; empty: string }[] = [
  { id: "chats", empty: "no conversations yet." },
  { id: "requests", empty: "no requests." },
  { id: "archives", empty: "nothing archived." },
];

export const ConvList = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const showFp = useSignal(false);
  const showNew = useSignal(false);
  const handles = useSignal("");
  const name = useSignal("");
  const formError = useSignal("");
  const creating = useSignal(false);
  const addingKey = useSignal(false);

  const me = state.me;
  const formOpen = showNew.value || state.conversations.length === 0;
  const counts: Record<ListView, number> = { chats: 0, requests: 0, archives: 0 };
  for (const c of state.conversations) counts[listOf(c)]++;
  const shown = state.conversations.filter((c) => listOf(c) === ui.list);
  // The switcher appears once there is something besides chats (or while another list is open).
  const lists = LISTS.filter((l) => l.id === "chats" || l.id === ui.list || counts[l.id] > 0);

  const create = $(async () => {
    if (creating.value) return;
    const parsed = parseHandles(handles.value, state.me?.handle);
    if (!parsed.ok) {
      formError.value = parsed.error;
      return;
    }
    const n = name.value.trim();
    if ([...n].length > MAX_NAME) {
      formError.value = `group name: at most ${MAX_NAME} characters`;
      return;
    }
    formError.value = "";
    creating.value = true;
    const id = await act(ui, (e) => e.createConversation(parsed.handles, n || undefined));
    creating.value = false;
    if (id) {
      handles.value = "";
      name.value = "";
      showNew.value = false;
      ui.active = id;
      ui.list = "chats";
      ui.members = false;
    }
  });

  return (
    <aside class="left" aria-label="conversations">
      {me && (
        <div class="me">
          <button
            type="button"
            class="link"
            aria-expanded={showFp.value}
            title="show your safety number"
            onClick$={() => (showFp.value = !showFp.value)}
          >
            @{me.handle}
          </button>
          {showFp.value && (
            <div class="fp-box">
              <p class="dim small">your safety number — compare it with your contacts in person:</p>
              <p class="fp">{me.fingerprint}</p>
            </div>
          )}
        </div>
      )}

      <div class="newconv">
        {!formOpen ? (
          <button type="button" class="link" onClick$={() => (showNew.value = true)}>
            new conversation
          </button>
        ) : (
          <form preventdefault:submit onSubmit$={create}>
            <p class="small">new conversation</p>
            <input
              type="text"
              aria-label="handles"
              placeholder="handles: bob, carol"
              autocapitalize="none"
              autocomplete="off"
              spellcheck={false}
              bind:value={handles}
              onInput$={() => (formError.value = "")}
              disabled={creating.value}
            />
            <input
              type="text"
              aria-label="group name (optional)"
              placeholder="group name (optional)"
              autocomplete="off"
              maxLength={MAX_NAME * 2}
              bind:value={name}
              disabled={creating.value}
            />
            {formError.value && (
              <p class="small strong" role="alert">
                {formError.value}
              </p>
            )}
            <p class="row">
              <button type="submit" disabled={creating.value || !handles.value.trim()}>
                {creating.value ? "starting…" : "start"}
              </button>
              {state.conversations.length > 0 && (
                <button
                  type="button"
                  class="link"
                  onClick$={() => {
                    showNew.value = false;
                    formError.value = "";
                  }}
                >
                  cancel
                </button>
              )}
            </p>
          </form>
        )}
      </div>

      {lists.length > 1 && (
        <nav class="lists" aria-label="lists">
          {lists.map((l) => (
            <button
              key={l.id}
              type="button"
              class="link"
              aria-pressed={ui.list === l.id}
              onClick$={() => (ui.list = l.id)}
            >
              {l.id}
              {l.id !== "chats" && counts[l.id] > 0 && (
                <span class={l.id === "requests" ? "strong" : "dim"}> {counts[l.id]}</span>
              )}
            </button>
          ))}
        </nav>
      )}

      <nav class="list" aria-label={ui.list === "chats" ? "conversation list" : ui.list}>
        {shown.map((c) => (
          <button
            key={c.id}
            type="button"
            class={["conv", c.id === ui.active && "on", c.unread > 0 && "unread"]}
            aria-current={c.id === ui.active ? "true" : undefined}
            onClick$={() => {
              ui.active = c.id;
              ui.members = false;
            }}
          >
            <span class="name">{c.name || "(no name)"}</span>
            {ui.list === "archives" && <span class="dim small">{c.blocked}</span>}
            {c.unread > 0 && (
              <span class="badge" aria-label={`${c.unread} unread`}>
                {c.unread > 99 ? "99+" : c.unread}
              </span>
            )}
            <span class="when">{relTime(c.lastTs, ui.now)}</span>
          </button>
        ))}
        {shown.length === 0 && (
          <p class="dim small pad">{LISTS.find((l) => l.id === ui.list)?.empty}</p>
        )}
      </nav>

      <footer class="foot">
        <button
          type="button"
          class="link"
          disabled={addingKey.value}
          onClick$={async () => {
            addingKey.value = true;
            ui.notice = "";
            const ok = await act(ui, async (e) => {
              await e.addPasskey();
              return true;
            });
            addingKey.value = false;
            if (ok) {
              ui.notice = "passkey added.";
              setTimeout(() => {
                if (ui.notice === "passkey added.") ui.notice = "";
              }, 6000);
            }
          }}
        >
          {addingKey.value ? "adding passkey…" : "add passkey"}
        </button>
        <button type="button" class="link" onClick$={() => act(ui, (e) => e.logout())}>
          sign out
        </button>
      </footer>
    </aside>
  );
});

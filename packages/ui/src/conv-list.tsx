import { $, component$, useContext, useSignal } from "@qwik.dev/core";
import { showChat } from "./route";
import { type ListView, StateCtx, UiCtx } from "./state";
import { act, listOf, MAX_NAME, parseHandles, relTime } from "./util";

const LISTS: { id: ListView; empty: string }[] = [
  { id: "chats", empty: "no conversations yet." },
  { id: "requests", empty: "no requests." },
  { id: "archives", empty: "nothing archived." },
];

/** A gear: the settings. */
const GearIcon = () => (
  <svg
    class="icon"
    viewBox="0 0 20 20"
    aria-hidden="true"
    fill="none"
    stroke="currentColor"
    stroke-width="1.4"
    stroke-linejoin="round"
  >
    <path d="M15.9 7.78L18.23 8.33L18.23 11.67L15.9 12.22L15.74 12.6L17 14.64L14.64 17L12.6 15.74L12.22 15.9L11.67 18.23L8.33 18.23L7.78 15.9L7.4 15.74L5.36 17L3 14.64L4.26 12.6L4.1 12.22L1.77 11.67L1.77 8.33L4.1 7.78L4.26 7.4L3 5.36L5.36 3L7.4 4.26L7.78 4.1L8.33 1.77L11.67 1.77L12.22 4.1L12.6 4.26L14.64 3L17 5.36L15.74 7.4Z" />
    <circle cx="10" cy="10" r="2.6" />
  </svg>
);

export const ConvList = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const showNew = useSignal(false);
  const handles = useSignal("");
  const name = useSignal("");
  const formError = useSignal("");
  const creating = useSignal(false);

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
      ui.wanted = "";
      ui.active = id;
      ui.list = "chats";
      ui.members = false;
    }
  });

  return (
    <aside class="left" aria-label="conversations">
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
            onClick$={() => showChat(ui, c)}
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
      {/* The account, at the foot of the list: the handle, online or offline, and the settings. */}
      {me && (
        <div class="me">
          <span class="handle strong">@{me.handle}</span>
          <span class={state.connected ? "dim" : "strong"}>
            {state.connected ? "online" : "offline"}
          </span>
          <button
            type="button"
            class="gear"
            aria-label="settings"
            title="settings"
            aria-haspopup="dialog"
            onClick$={() => (ui.settings = true)}
          >
            <GearIcon />
          </button>
        </div>
      )}
    </aside>
  );
});

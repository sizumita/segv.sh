import { component$, useContext } from "@qwik.dev/core";
import { showChat } from "./route";
import { type ListView, StateCtx, UiCtx } from "./state";
import { identitiesOf, listOf, relTime } from "./util";
import { Warnings } from "./warnings";

const LISTS: { id: ListView; empty: string }[] = [
  { id: "chats", empty: "no conversations yet." },
  { id: "requests", empty: "no requests." },
  { id: "archives", empty: "nothing archived." },
];

/** A pencil on a sheet: a new conversation. */
const NewIcon = () => (
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
    <path d="M9 3.5H5.5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V11" />
    <path d="M14.6 2.9a1.6 1.6 0 0 1 2.3 2.3L10.3 11.8l-3 .8.8-3z" />
  </svg>
);

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

  const me = state.me;
  const counts: Record<ListView, number> = { chats: 0, requests: 0, archives: 0 };
  for (const c of state.conversations) counts[listOf(c)]++;
  const shown = state.conversations.filter((c) => listOf(c) === ui.list);
  // The switcher appears once there is something besides chats (or while another list is open).
  const lists = LISTS.filter((l) => l.id === "chats" || l.id === ui.list || counts[l.id] > 0);
  // The temporary handle that holds a conversation (§2.6), for its row; none for the owner's.
  const aliases = new Map(
    identitiesOf(state)
      .filter((i) => i.alias)
      .map((i) => [i.uid, i.handle || "…"]),
  );

  return (
    <aside class="left" aria-label="conversations">
      <div class="newconv">
        <button
          type="button"
          class="newbtn"
          aria-haspopup="dialog"
          onClick$={() => (ui.newChat = true)}
        >
          <NewIcon />
          new conversation
        </button>
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
            <span class="cname">
              <span class="name">{c.name || "(no name)"}</span>
              {aliases.has(c.as) && <span class="as">as @{aliases.get(c.as)}</span>}
            </span>
            {ui.list === "archives" && <span class="dim small">{c.blocked}</span>}
            {c.unread > 0 && (
              <span class="badge" aria-label={`${c.unread} unread`}>
                {c.unread > 99 ? "99+" : c.unread}
              </span>
            )}
            <span class="when">{relTime(c.lastTs, ui.now)}</span>
          </button>
        ))}
        {shown.length === 0 &&
          (state.conversations.length === 0 ? (
            <p class="dim small pad">
              no conversations yet.{" "}
              <button
                type="button"
                class="link"
                aria-haspopup="dialog"
                onClick$={() => (ui.newChat = true)}
              >
                start one
              </button>
            </p>
          ) : (
            <p class="dim small pad">{LISTS.find((l) => l.id === ui.list)?.empty}</p>
          ))}
      </nav>
      {/* The foot of the list: a running task's progress, then the account: the handle, the connection with the latest
          verified checkpoint, the security warnings and the settings. */}
      {state.progress && (
        <p class="progress-line small" role="status">
          {state.progress}
        </p>
      )}
      {me && (
        <div class="me">
          <span class="handle strong">@{me.handle}</span>
          <span
            class={state.connected ? "dim" : "strong"}
            title={
              state.head.h ? `verified checkpoint ${state.head.h}` : "no checkpoint verified yet"
            }
          >
            {!state.connected ? "offline" : state.syncing ? "syncing…" : "online"} #{state.head.seq}
          </span>
          <Warnings />
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

import { component$, useContext, useVisibleTask$ } from "@qwik.dev/core";
import type { ConversationView } from "~/client/types";
import { Composer } from "./composer";
import { loadEngine } from "./engine-loader";
import { Members } from "./members";
import { Messages } from "./messages";
import { UiCtx } from "./state";

export const ConversationPane = component$<{ conv: ConversationView }>((props) => {
  const ui = useContext(UiCtx);
  const conv = props.conv;
  const active = conv.members.filter((m) => !m.left).length;

  // Opening the pane is the engine's "conversation opened" hint (§11.10–§11.11): it accepts a request copy and
  // starts scrollback once, even when nothing is unread (after a reload every conversation has unread = 0).
  useVisibleTask$(async ({ track }) => {
    const id = track(() => props.conv.id);
    const visible = track(() => ui.visible);
    if (visible && document.visibilityState === "visible") {
      try {
        (await loadEngine()).markRead(id);
      } catch {
        // ignore: it is sent again the next time the pane opens
      }
    }
  });

  // Mark read while the conversation is on screen and the tab is visible: when new messages arrive, and when the
  // tab becomes visible again.
  useVisibleTask$(async ({ track }) => {
    const unread = track(() => props.conv.unread);
    const visible = track(() => ui.visible);
    const id = props.conv.id;
    if (unread > 0 && visible && document.visibilityState === "visible") {
      try {
        (await loadEngine()).markRead(id);
      } catch {
        // ignore: the badge simply stays
      }
    }
  });

  return (
    <>
      <header class="convhead">
        <button
          type="button"
          class="link back"
          onClick$={() => {
            ui.active = "";
            ui.members = false;
          }}
        >
          back
        </button>
        <h2 class="title" title={conv.name}>
          {conv.name || "(no name)"}
        </h2>
        <span class="dim small">
          {active} member{active === 1 ? "" : "s"}
        </span>
        <button
          type="button"
          class={["link", ui.members && "strong"]}
          aria-expanded={ui.members}
          onClick$={() => (ui.members = !ui.members)}
        >
          members
        </button>
      </header>
      <div class={["convbody", ui.members && "with-members"]}>
        <div class="thread">
          <Messages conv={conv} />
          <Composer convId={conv.id} blocked={conv.blocked} />
        </div>
        {ui.members && <Members conv={conv} />}
      </div>
    </>
  );
});

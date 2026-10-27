import { $, component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import type { ConversationView } from "~/client/types";
import { Composer } from "./composer";
import { loadEngine } from "./engine-loader";
import { Members } from "./members";
import { Messages } from "./messages";
import { StateCtx, UiCtx } from "./state";
import { errMsg, inviterOf, isGone } from "./util";

export const ConversationPane = component$<{ conv: ConversationView }>((props) => {
  const ui = useContext(UiCtx);
  const conv = props.conv;
  const active = conv.members.filter((m) => !m.left).length;

  // Opening the pane is the engine's "conversation opened" hint (§11.10–§11.11): it starts scrollback once, even
  // when nothing is unread (after a reload every conversation has unread = 0). It also accepts a request copy, so a
  // request is shown as a preview instead and the hint waits for the accept button (or another acceptance, §11.5).
  useVisibleTask$(async ({ track }) => {
    const id = track(() => props.conv.id);
    const request = track(() => props.conv.request);
    const visible = track(() => ui.visible);
    if (!request && visible && document.visibilityState === "visible") {
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
    const request = track(() => props.conv.request);
    const visible = track(() => ui.visible);
    const id = props.conv.id;
    if (unread > 0 && !request && visible && document.visibilityState === "visible") {
      try {
        (await loadEngine()).markRead(id);
      } catch {
        // ignore: the badge simply stays
      }
    }
  });

  // An accepted request moves to chats: follow it there.
  useVisibleTask$(({ track }) => {
    const request = track(() => props.conv.request);
    if (!request && ui.list === "requests") ui.list = "chats";
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
          {conv.request && !isGone(conv) ? (
            <RequestBar conv={conv} />
          ) : (
            <Composer convId={conv.id} blocked={conv.blocked} />
          )}
        </div>
        {ui.members && <Members conv={conv} />}
      </div>
    </>
  );
});

/** In place of the composer while a conversation is a request: what accepting does, and the button. */
const RequestBar = component$<{ conv: ConversationView }>((props) => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const accepting = useSignal(false);

  // The engine reports a failed acceptance in `state.error`: let the user try again.
  useVisibleTask$(({ track }) => {
    const error = track(() => state.error);
    if (error) accepting.value = false;
  });

  const accept = $(async () => {
    if (accepting.value) return;
    accepting.value = true;
    ui.localError = "";
    try {
      const engine = await loadEngine();
      engine.clearError(); // so that a failure shows as a new error, even with the same text
      // markRead accepts a request copy (§11.5, §11.11); the pane leaves preview once `request` turns false.
      engine.markRead(props.conv.id);
    } catch (e) {
      accepting.value = false;
      ui.localError = errMsg(e);
    }
  });

  const conv = props.conv;
  const who = inviterOf(conv, state.me?.uid ?? "");
  return (
    <div class="composer request" role="region" aria-label="request">
      <p>
        <b>message request</b>{" "}
        {who ? `from @${who}, who is not in your contacts.` : "from someone not in your contacts."}
      </p>
      <p class="dim small">
        you can read it here without accepting it; images load only when you open them. accept to
        reply. accepting adds {who ? `@${who}` : "the sender"} to your contacts, so their next
        conversations are not requests.
        {conv.members.length > 2 && " the other members' handles are looked up when you accept."}
      </p>
      <p class="row">
        <button type="button" disabled={accepting.value} onClick$={accept}>
          {accepting.value ? "accepting…" : "accept"}
        </button>
      </p>
    </div>
  );
});

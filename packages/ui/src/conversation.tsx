import {
  $,
  component$,
  useContext,
  useContextProvider,
  useSignal,
  useStore,
  useVisibleTask$,
} from "@qwik.dev/core";
import type { ConversationView } from "@segv/engine/types";
import { Composer } from "./composer";
import { loadEngine } from "./engine-loader";
import { Members } from "./members";
import { Messages } from "./messages";
import { gist } from "./reply";
import { ReplyTree } from "./reply-tree";
import { leaveChat } from "./route";
import { PaneCtx, StateCtx, UiCtx, type PaneState } from "./state";
import { errMsg, inviterOf, isGone } from "./util";

export const ConversationPane = component$<{ conv: ConversationView }>((props) => {
  const ui = useContext(UiCtx);
  // chat.tsx keys this pane by conversation: the reply and the open thread start empty in each one
  const pane = useStore<PaneState>({ reply: "", thread: "", threadTo: "" });
  useContextProvider(PaneCtx, pane);
  const conv = props.conv;
  const active = conv.members.filter((m) => !m.left).length;

  // Opening the pane is the engine's "pane is open" hint (§11.10–§11.11): it starts scrollback once, even when nothing
  // is unread (after a reload every conversation has unread = 0). It accepts nothing; still, no read-only preview
  // calls it: a copy whose inviter is not a contact waits for the accept button (§11.11).
  useVisibleTask$(async ({ track }) => {
    const id = track(() => props.conv.id);
    const byContact = track(() => props.conv.byContact);
    const visible = track(() => ui.visible);
    if (byContact && visible && document.visibilityState === "visible") {
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
    const byContact = track(() => props.conv.byContact);
    const visible = track(() => ui.visible);
    const id = props.conv.id;
    if (unread > 0 && byContact && visible && document.visibilityState === "visible") {
      try {
        (await loadEngine()).markRead(id);
      } catch {
        // ignore: the badge simply stays
      }
    }
  });

  // An accepted copy moves to chats: follow it there.
  useVisibleTask$(({ track }) => {
    const byContact = track(() => props.conv.byContact);
    if (byContact && ui.list === "requests") ui.list = "chats";
  });

  // One side pane at a time: opening the members closes the replies.
  useVisibleTask$(({ track }) => {
    if (track(() => ui.members)) pane.thread = "";
  });

  // A reply is a post (§11.17): not where nothing can be sent, nor in a read-only preview, which it would accept.
  const canReply = conv.canSend && conv.byContact;
  const replyTo = pane.reply ? conv.messages.find((m) => m.key === pane.reply) : undefined;

  return (
    <>
      <header class="convhead">
        <button type="button" class="link back" onClick$={() => leaveChat(ui)}>
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
          {!conv.byContact && !isGone(conv) ? (
            <RequestBar conv={conv} />
          ) : (
            <Composer
              convId={conv.id}
              blocked={conv.blocked}
              // a target that left the view (§6.8 dropped it) is not replied to
              replyTo={replyTo ? replyTo.key : ""}
              replyWho={replyTo ? replyTo.fromHandle || "unknown" : ""}
              replyGist={replyTo ? gist(replyTo) : ""}
              canStop={true}
              setReply$={$((key: string) => {
                pane.reply = key;
              })}
            />
          )}
        </div>
        {ui.members && <Members conv={conv} />}
        {!ui.members && pane.thread && <ReplyTree conv={conv} canReply={canReply} />}
      </div>
    </>
  );
});

/**
 * In place of the composer while the conversation's inviter is neither self nor a contact (a request, or a copy that
 * only another member's message accepted): what accepting does, and the button, which calls `accept` (§11.11).
 */
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
      // The user's acceptance: the pane leaves the preview once `byContact` turns true.
      await engine.accept(props.conv.id);
    } catch (e) {
      ui.localError = errMsg(e);
    } finally {
      accepting.value = false;
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
        you can read it here without accepting it; images and files load only when you open them.
        accept to reply. accepting adds {who ? `@${who}` : "the sender"} to your contacts, so their
        next conversations are not requests.
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

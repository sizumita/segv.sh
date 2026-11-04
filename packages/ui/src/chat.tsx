import { component$, useContext } from "@qwik.dev/core";
import { ConvList } from "./conv-list";
import { ConversationPane } from "./conversation";
import { Errors } from "./errors";
import { Settings } from "./settings";
import { StateCtx, UiCtx } from "./state";
import { Warnings } from "./warnings";

/** Signed-in screen: status bar (with the security warnings), errors, then list | conversation. */
export const Chat = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const active = ui.active ? state.conversations.find((c) => c.id === ui.active) : undefined;

  return (
    <div class="chat">
      <header class="bar">
        <b>segv.sh</b>
        <span class={state.connected ? "" : "strong"}>
          {state.connected ? "online" : "offline"}
        </span>
        {state.syncing && <span>syncing…</span>}
        {state.progress && (
          <span class="grow" role="status">
            {state.progress}
          </span>
        )}
        <span
          class="dim push"
          title={
            state.head.h ? `verified checkpoint ${state.head.h}` : "no checkpoint verified yet"
          }
        >
          checkpoint #{state.head.seq}
        </span>
        <Warnings />
      </header>

      <Errors />

      <div class="panes" data-pane={active ? "conv" : "list"}>
        <ConvList />
        <section class="right" aria-label="conversation">
          {active ? (
            <ConversationPane key={active.id} conv={active} />
          ) : (
            <p class="empty dim">
              {state.conversations.length
                ? "select a conversation."
                : "start a conversation on the left."}
            </p>
          )}
        </section>
      </div>
      {ui.settings && <Settings />}
    </div>
  );
});

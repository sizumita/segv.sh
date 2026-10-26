import { component$, useContext } from "@qwik.dev/core";
import { ConvList } from "./conv-list";
import { ConversationPane } from "./conversation";
import { Errors } from "./errors";
import { StateCtx, UiCtx } from "./state";

/** Signed-in screen: status bar, alerts, then list | conversation. */
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
        {ui.notice && <span role="status">{ui.notice}</span>}
        <span class="dim push" title={state.head.h ? `head ${state.head.h}` : undefined}>
          log #{state.head.seq}
        </span>
      </header>

      {state.warnings.length > 0 && (
        <div class="warnings" role="alert">
          {state.warnings.map((w, i) => (
            <p key={`${i}:${w}`}>
              <b>security warning:</b> {w}
            </p>
          ))}
        </div>
      )}
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
    </div>
  );
});

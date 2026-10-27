import { component$, useContext } from "@qwik.dev/core";
import { StateCtx, UiCtx } from "./state";
import { act } from "./util";

export const Fatal = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  return (
    <main class="page">
      <h1>segv.sh stopped</h1>
      <p class="alert" role="alert">
        {state.error || "an unrecoverable error occurred."}
      </p>
      <p>the client stopped. reload to try again.</p>
      <p>
        <button type="button" onClick$={() => location.reload()}>
          reload
        </button>{" "}
        <button type="button" class="link" onClick$={() => act(ui, (e) => e.logout())}>
          sign out
        </button>
      </p>
    </main>
  );
});

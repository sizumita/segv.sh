import { $, component$, useContext } from "@qwik.dev/core";
import { loadEngine } from "./engine-loader";
import { StateCtx, UiCtx } from "./state";

/** Engine error + local (rejected call) error, deduplicated, each dismissable. */
export const Errors = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);

  const dismiss = $(async () => {
    ui.localError = "";
    try {
      (await loadEngine()).clearError();
    } catch {
      // engine unavailable: nothing to clear
    }
  });

  const list = [...new Set([state.error, ui.localError].filter(Boolean))];
  if (!list.length) return null;
  return (
    <div class="errors" role="alert">
      {list.map((e) => (
        <p key={e} class="error">
          <span>error: {e}</span>
          <button type="button" class="link" onClick$={dismiss}>
            dismiss
          </button>
        </p>
      ))}
    </div>
  );
});

import { component$, sync$, useContext, useOnWindow, useSignal } from "@qwik.dev/core";
import { UiCtx } from "./state";

/** Shown once, right after register(): blocks the app until the user confirms they saved it. */
export const Recovery = component$(() => {
  const ui = useContext(UiCtx);
  const saved = useSignal(false);
  const copied = useSignal("");

  // Closing the tab now would lose the code forever: ask the browser to confirm.
  useOnWindow(
    "beforeunload",
    sync$((e: BeforeUnloadEvent) => {
      e.preventDefault();
    }),
  );

  const code = ui.recovery?.code ?? "";
  const groups = code.split(/[\s-]+/).filter(Boolean);

  return (
    <main class="page recovery" aria-labelledby="rc-title">
      <h1 id="rc-title">save your recovery code</h1>
      <p class="code" aria-label="recovery code">
        <span>{groups.slice(0, 4).join(" ")}</span>
        <span>{groups.slice(4).join(" ")}</span>
      </p>
      <p class="row">
        <button
          type="button"
          onClick$={async () => {
            try {
              await navigator.clipboard.writeText(ui.recovery?.code ?? "");
              copied.value = "copied.";
            } catch {
              copied.value = "copy failed — select the code and copy it by hand.";
            }
          }}
        >
          copy
        </button>
        <span class="dim" role="status">
          {copied.value}
        </span>
      </p>
      <p>
        this code is the <b>only</b> way back into your account if you lose your passkey. nobody —
        including the server — can reset it. it is shown once.
      </p>
      <p class="dim">
        keep it offline or in a password manager. anyone who has it can read your messages and act
        as you.
      </p>
      <p>
        <label class="check">
          <input type="checkbox" bind:checked={saved} /> i saved it
        </label>
      </p>
      <p>
        <button
          type="button"
          disabled={!saved.value}
          onClick$={() => {
            ui.recovery = undefined;
          }}
        >
          continue
        </button>
      </p>
    </main>
  );
});

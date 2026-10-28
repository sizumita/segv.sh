import { component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import { Errors } from "./errors";
import { StateCtx, UiCtx } from "./state";
import { act } from "./util";

/**
 * Account settings in a modal <dialog>: the browser traps focus, closes it on escape and gives focus back to the
 * button that opened it. Every way of closing goes through the dialog's `close` event, which clears `ui.settings`.
 */
export const Settings = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const dlg = useSignal<HTMLDialogElement>();
  const addingKey = useSignal(false);
  const added = useSignal(false);
  const pushBusy = useSignal(false);

  useVisibleTask$(
    ({ cleanup }) => {
      const d = dlg.value;
      if (!d) return;
      const onClose = () => (ui.settings = false);
      d.addEventListener("close", onClose);
      if (!d.open) d.showModal();
      cleanup(() => d.removeEventListener("close", onClose));
    },
    { strategy: "document-ready" },
  );

  const me = state.me;
  if (!me) return null;
  return (
    <dialog
      ref={dlg}
      class="settings"
      aria-labelledby="st-title"
      // A click on the backdrop lands on the <dialog> itself; the sheet inside covers the rest.
      onClick$={(e, el) => {
        if (e.target === el) el.close();
      }}
    >
      <div class="sheet">
        <header class="row">
          <h2 id="st-title" class="grow">
            settings
          </h2>
          <button type="button" class="link" onClick$={() => dlg.value?.close()}>
            close
          </button>
        </header>
        <Errors />

        <section aria-labelledby="st-account">
          <h3 id="st-account">account</h3>
          <p class="strong">@{me.handle}</p>
          <p class="dim small">your safety number — compare it with your contacts in person:</p>
          <p class="fp">{me.fingerprint}</p>
        </section>

        <section aria-labelledby="st-passkeys">
          <h3 id="st-passkeys">passkeys</h3>
          <p class="dim small">
            add a passkey on another device or password manager (with PRF support), so that losing
            one does not lock you out.
          </p>
          <p class="row">
            <button
              type="button"
              disabled={addingKey.value}
              onClick$={async () => {
                addingKey.value = true;
                added.value = false;
                const ok = await act(ui, async (e) => {
                  await e.addPasskey();
                  return true;
                });
                addingKey.value = false;
                added.value = !!ok;
              }}
            >
              {addingKey.value ? "adding passkey…" : "add passkey"}
            </button>
            {added.value && <span role="status">passkey added.</span>}
          </p>
        </section>

        {state.notifications !== "unavailable" && (
          <section aria-labelledby="st-push">
            <h3 id="st-push">notifications</h3>
            <p class="dim small">
              a notification that says only “new messages”, on this device only.
            </p>
            <p class="row">
              <span>{state.notifications === "on" ? "on" : "off"}</span>
              <button
                type="button"
                disabled={pushBusy.value}
                onClick$={async () => {
                  // Turning on asks for permission: it must start inside this click.
                  const on = state.notifications !== "on";
                  pushBusy.value = true;
                  await act(ui, (e) => e.setNotifications(on));
                  pushBusy.value = false;
                }}
              >
                {state.notifications === "on" ? "turn off" : "turn on"}
              </button>
            </p>
          </section>
        )}

        <section aria-labelledby="st-signout">
          <h3 id="st-signout">sign out</h3>
          <p class="dim small">
            locks this account on this device. to come back, sign in with a passkey or your recovery
            code.
          </p>
          <p class="row">
            <button type="button" onClick$={() => act(ui, (e) => e.logout())}>
              sign out
            </button>
          </p>
        </section>
      </div>
    </dialog>
  );
});

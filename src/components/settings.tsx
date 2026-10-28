import { component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import { Errors } from "./errors";
import { StateCtx, UiCtx } from "./state";
import { act } from "./util";

type Preview = "none" | "name" | "message";

/** What notifications show on this device (docs/PROTOCOL.md §11.13). */
const PREVIEWS: { id: Preview; label: string; hint: string }[] = [
  { id: "none", label: "“new messages”", hint: "the same text for every notification" },
  { id: "name", label: "the conversation's name", hint: "decrypted on this device" },
  {
    id: "message",
    label: "the name and the newest message",
    hint: "this device fetches and decrypts it after each notification, also while the app is closed",
  },
];

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
  const previewBusy = useSignal(false);
  const quietBusy = useSignal(false);

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

        {(state.notifications !== "unavailable" || state.quiet !== "unavailable") && (
          <section aria-labelledby="st-push">
            <h3 id="st-push">notifications</h3>
            {state.notifications === "unavailable" ? (
              <p class="dim small">this browser cannot show notifications.</p>
            ) : (
              <p class="dim small">on this device only. invites and requests never notify.</p>
            )}
            {state.notifications !== "unavailable" && (
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
            )}
            {state.notifications === "on" &&
              (state.preview === "unavailable" ? (
                <p class="dim small">
                  to show conversation names or messages, sign in with “remember this device”: this
                  device decrypts them itself, from what it keeps.
                </p>
              ) : (
                <fieldset class="choice" disabled={previewBusy.value}>
                  <legend>notifications show</legend>
                  {PREVIEWS.map((p) => (
                    <label key={p.id}>
                      <input
                        type="radio"
                        name="preview"
                        value={p.id}
                        checked={state.preview === p.id}
                        onChange$={async () => {
                          previewBusy.value = true;
                          await act(ui, (e) => e.setPreview(p.id));
                          previewBusy.value = false;
                        }}
                      />
                      {p.label} <span class="dim small">— {p.hint}</span>
                    </label>
                  ))}
                  {state.preview !== "none" && (
                    <p class="dim small">
                      your phone or computer may show what notifications say on the lock screen and
                      keep it in its notification history.
                    </p>
                  )}
                </fieldset>
              ))}
            {state.quiet !== "unavailable" && (
              <>
                <p class="row">
                  <label>
                    <input
                      type="checkbox"
                      checked={state.quiet === "on"}
                      disabled={quietBusy.value}
                      onChange$={async (_, el) => {
                        quietBusy.value = true;
                        await act(ui, (e) => e.setQuiet(el.checked));
                        quietBusy.value = false;
                      }}
                    />{" "}
                    quiet my other devices while i use this one
                  </label>
                </p>
                <p class="dim small">
                  while you use segv.sh here, your other devices get no notification for the
                  messages this one shows. to do this, this device tells the server which messages
                  reached you while you were using it.
                </p>
              </>
            )}
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

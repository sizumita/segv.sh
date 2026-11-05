import { $, component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import { MAX_LIVE_ALIASES, type IdentityView } from "@segv/engine/types";
import { Errors } from "./errors";
import { StateCtx, UiCtx } from "./state";
import { act, ALIAS_CAP, atAliasCap, identitiesOf, makeAlias } from "./util";

type Preview = "none" | "name" | "message";

/** What notifications show on this device (docs/PROTOCOL.md §11.13). */
const PREVIEWS: { id: Preview; label: string; hint: string; local?: string }[] = [
  { id: "none", label: "“new messages”", hint: "the same text for every notification" },
  { id: "name", label: "the conversation's name", hint: "decrypted on this device" },
  {
    id: "message",
    label: "the name and the newest message",
    hint: "this device fetches and decrypts it after each notification, also while the app is closed",
    // An app without push shows only the messages that reach it while it runs (§11.13).
    local: "decrypted on this device",
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

        <Aliases />

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
              <p class="dim small">
                on this device only. invites and requests never notify.
                {state.localNotify &&
                  " segv.sh notifies while it runs, also with its window closed: keep it in the menu bar or the system tray."}
              </p>
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
                      {p.label}{" "}
                      <span class="dim small">
                        — {state.localNotify && p.local ? p.local : p.hint}
                      </span>
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

/** What a temporary handle's state reads as (§2.6 "Running aliases"). */
const STATUS: Record<IdentityView["status"], string> = {
  starting: "starting…",
  ready: "ready",
  retired: "retired",
  failed: "not registered correctly",
  // valid, only not run on this device: retiring another one starts it
  idle: `not run here: more than ${MAX_LIVE_ALIASES} are active`,
};

/**
 * The temporary handles (§2.6): extra accounts with random handles, which nothing stored or sent relates to the user's
 * own, each retired or brought back here, and a button that makes a new one.
 */
const Aliases = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  /** the handle being retired or brought back, and the one asked about ('' = none) */
  const busy = useSignal("");
  const confirm = useSignal("");
  /** the handle just made ('' = none) */
  const made = useSignal("");

  const setRetired = $(async (uid: string, retired: boolean) => {
    busy.value = uid;
    confirm.value = "";
    made.value = "";
    await act(ui, (e) => e.setAliasRetired(uid, retired));
    busy.value = "";
  });

  const all = identitiesOf(state);
  const aliases = all.filter((i) => i.alias);
  const fresh = made.value ? aliases.find((a) => a.uid === made.value) : undefined;
  // no more can be made or brought back until one is retired (§2.6 MAX_LIVE_ALIASES)
  const capped = atAliasCap(all);
  return (
    <section aria-labelledby="st-aliases">
      <h3 id="st-aliases">temporary handles</h3>
      <p class="dim small">
        temporary handles are extra handles with random names. people you talk to as one see only
        that handle, never yours or your other ones. retire one to stop it: its conversations are
        hidden and it receives nothing until you bring it back.
      </p>
      <p class="dim small">
        use a temporary handle from this device as you would a separate person: the times you are
        active can still link them.
      </p>
      {aliases.length > 0 && (
        <ul class="aliases">
          {aliases.map((a) => {
            const h = `@${a.handle || "…"}`;
            const off = a.status === "retired";
            return (
              <li key={a.uid} class={{ off }}>
                <div class="arow">
                  <span class="ahandle" title={a.handle ? undefined : "its handle is being read"}>
                    {h}
                  </span>
                  <span class={["astatus", a.status]}>{STATUS[a.status]}</span>
                  {off ? (
                    <button
                      type="button"
                      disabled={busy.value === a.uid || capped}
                      title={capped ? ALIAS_CAP : undefined}
                      aria-label={`bring back ${h}`}
                      onClick$={() => setRetired(a.uid, false)}
                    >
                      {busy.value === a.uid ? "bringing back…" : "bring back"}
                    </button>
                  ) : (
                    confirm.value !== a.uid && (
                      <button
                        type="button"
                        class="link"
                        disabled={busy.value === a.uid}
                        aria-label={`retire ${h}`}
                        onClick$={() => (confirm.value = a.uid)}
                      >
                        {busy.value === a.uid ? "retiring…" : "retire"}
                      </button>
                    )
                  )}
                </div>
                {confirm.value === a.uid && (
                  <p class="row confirm" role="group" aria-label={`retire ${h}`}>
                    <span class="grow">retire {h}? its conversations will be hidden.</span>
                    <button type="button" onClick$={() => setRetired(a.uid, true)}>
                      retire
                    </button>
                    <button type="button" class="link" onClick$={() => (confirm.value = "")}>
                      cancel
                    </button>
                  </p>
                )}
                {a.fingerprint && (
                  <details class="afp">
                    <summary class="small dim">safety number</summary>
                    <p class="fp small">{a.fingerprint}</p>
                  </details>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <p class="row">
        <button
          type="button"
          disabled={ui.makingAlias || capped}
          aria-busy={ui.makingAlias}
          aria-describedby="st-alias-note"
          onClick$={async () => {
            made.value = "";
            made.value = (await makeAlias(ui)) ?? "";
          }}
        >
          {ui.makingAlias ? "making a handle…" : "new temporary handle"}
        </button>
        {ui.makingAlias && state.progress && (
          <span class="dim small" role="status">
            {state.progress}
          </span>
        )}
        {!ui.makingAlias && fresh && <span role="status">@{fresh.handle || "…"} is ready.</span>}
      </p>
      <p class="dim small" id="st-alias-note">
        {capped
          ? `${ALIAS_CAP}.`
          : "when a handle is made is public: handles made close together, or soon after you signed up, can be linked by that time."}
      </p>
    </section>
  );
});

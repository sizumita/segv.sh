import { $, component$, noSerialize, useContext, useSignal } from "@qwik.dev/core";
import { Errors } from "./errors";
import { StateCtx, UiCtx } from "./state";
import { act, isHandle, normaliseHandle } from "./util";

export const SignedOut = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const handle = useSignal("");
  const handleHint = useSignal("");
  const remember = useSignal(false);
  const useCode = useSignal(false);
  const code = useSignal("");

  const working = state.phase === "working";

  const create = $(async () => {
    const h = normaliseHandle(handle.value);
    if (!isHandle(h)) {
      handleHint.value = "a handle is 3–20 characters: a–z, 0–9 and _";
      return;
    }
    handleHint.value = "";
    handle.value = h;
    const res = await act(ui, (e) => e.register(h, remember.value));
    if (res?.recoveryCode) ui.recovery = noSerialize({ code: res.recoveryCode });
  });

  const signIn = $(async () => {
    await act(ui, (e) => e.login(remember.value));
  });

  const unlock = $(async () => {
    const c = code.value.trim();
    if (!c) return;
    await act(ui, (e) => e.loginWithRecovery(c, remember.value));
    // Do not keep the code around once it has been used (or rejected).
    code.value = "";
  });

  return (
    <main class="page" aria-busy={working}>
      <header>
        <h1>segv.sh</h1>
        <p class="dim">
          end-to-end encrypted messenger. the server is a public log of ciphertext; your keys never
          leave this browser.
        </p>
      </header>

      {state.prfSupported === false && (
        <p class="alert" role="alert">
          this browser or passkey provider does not support the WebAuthn PRF extension, which
          segv.sh needs to unlock your keys with a passkey. try an up-to-date browser and a passkey
          provider with PRF support, or unlock with your recovery code below.
        </p>
      )}

      <section aria-labelledby="new-title">
        <h2 id="new-title">new account</h2>
        <form class="row" preventdefault:submit onSubmit$={create}>
          <input
            type="text"
            name="handle"
            aria-label="handle"
            placeholder="handle"
            autocomplete="username"
            autocapitalize="none"
            spellcheck={false}
            maxLength={40}
            bind:value={handle}
            disabled={working}
          />
          <button type="submit" disabled={working}>
            create account
          </button>
        </form>
        <p class={["small", handleHint.value ? "strong" : "dim"]}>
          {handleHint.value || "3–20 characters: a–z, 0–9, _. public and permanent."}
        </p>
      </section>

      <section aria-labelledby="in-title">
        <h2 id="in-title">sign in</h2>
        <p class="row">
          <button type="button" onClick$={signIn} disabled={working}>
            sign in with passkey
          </button>
        </p>
        <p>
          <label class="check">
            <input type="checkbox" bind:checked={remember} disabled={working} /> remember this
            device
          </label>
        </p>
        <p class="dim small">
          keeps you signed in on this device until you sign out. leave it off on shared computers.
        </p>
        <p>
          <button
            type="button"
            class="link"
            aria-expanded={useCode.value}
            onClick$={() => (useCode.value = !useCode.value)}
          >
            {useCode.value ? "hide recovery code" : "use recovery code"}
          </button>
        </p>
        {useCode.value && (
          <form class="row" preventdefault:submit onSubmit$={unlock}>
            <input
              type="text"
              name="recovery"
              aria-label="recovery code"
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
              autocomplete="off"
              autocapitalize="characters"
              spellcheck={false}
              maxLength={64}
              bind:value={code}
              disabled={working}
            />
            <button type="submit" disabled={working || !code.value.trim()}>
              unlock
            </button>
          </form>
        )}
      </section>

      {working && (
        <p class="progress" role="status">
          {state.progress || "working…"}
        </p>
      )}
      <Errors />
    </main>
  );
});

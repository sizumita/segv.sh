import { component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import { UiCtx } from "./state";

/**
 * Before a [label](url) link opens (./msg-text.tsx): where it really goes, with its host in bold, since the label
 * can say anything. A modal <dialog> like the settings; every way of closing clears `ui.leaving`.
 */
export const Leaving = component$(() => {
  const ui = useContext(UiCtx);
  const dlg = useSignal<HTMLDialogElement>();

  useVisibleTask$(
    ({ cleanup }) => {
      const d = dlg.value;
      if (!d) return;
      const onClose = () => (ui.leaving = "");
      d.addEventListener("close", onClose);
      if (!d.open) d.showModal();
      cleanup(() => d.removeEventListener("close", onClose));
    },
    { strategy: "document-ready" },
  );

  const href = ui.leaving;
  let host = "";
  let rest = "";
  try {
    const u = new URL(href);
    host = u.host;
    rest = u.pathname + u.search + u.hash;
  } catch {
    // shown whole below
  }
  // href is a normalised http(s) URL (src/client/markdown.ts safeHref): scheme, "//", any user info, host, rest.
  const split = host !== "" && href.endsWith(host + rest);
  const head = split ? href.slice(0, href.length - host.length - rest.length) : href;
  return (
    <dialog
      ref={dlg}
      class="leave"
      aria-labelledby="lv-title"
      aria-describedby="lv-url"
      onClick$={(e, el) => {
        if (e.target === el) el.close();
      }}
    >
      <div class="sheet">
        <h2 id="lv-title">open this link?</h2>
        <p class="dim small">its text can say anything. it goes to:</p>
        <p id="lv-url" class="url">
          {split ? (
            <>
              <span class="dim">{head}</span>
              <b>{host}</b>
              <span class="dim">{rest}</span>
            </>
          ) : (
            head
          )}
        </p>
        <div class="row">
          <button type="button" onClick$={() => dlg.value?.close()}>
            cancel
          </button>
          <a
            class="btn"
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            onClick$={() => dlg.value?.close()}
          >
            open
          </a>
        </div>
      </div>
    </dialog>
  );
});

import {
  component$,
  noSerialize,
  useContext,
  useSignal,
  useVisibleTask$,
  type NoSerialize,
} from "@qwik.dev/core";
import { UiCtx } from "./state";
import { extFor } from "./util";

/**
 * The shown image as a File for the share sheet (touch devices with Web Share for files), or null: the decrypted bytes
 * as they arrived, read back from their blob: URL.
 */
async function shareFile(src: string, mime: string): Promise<File | null> {
  if (typeof navigator.canShare !== "function" || typeof navigator.share !== "function")
    return null;
  // A desktop keeps the plain download.
  if (!matchMedia("(hover: none) and (pointer: coarse)").matches) return null;
  const blob = await (await fetch(src)).blob();
  const type = blob.type || mime;
  const file = new File([blob], `segv-image.${extFor(type)}`, { type });
  return navigator.canShare({ files: [file] }) ? file : null;
}

/** Full-size image overlay. Click anywhere or press escape to close. */
export const Viewer = component$(() => {
  const ui = useContext(UiCtx);
  const closeBtn = useSignal<HTMLButtonElement>();
  const share = useSignal<NoSerialize<File>>();

  useVisibleTask$(async ({ track }) => {
    const src = track(() => ui.viewer?.src);
    share.value = undefined;
    closeBtn.value?.focus();
    if (!src) return;
    // Prepared now: Safari opens the share sheet only from a call made directly in the click.
    try {
      const file = await shareFile(src, ui.viewer?.mime ?? "");
      if (file && ui.viewer?.src === src) share.value = noSerialize(file);
    } catch {
      // keep the download link
    }
  });

  const v = ui.viewer;
  if (!v || !v.src.startsWith("blob:")) return null;
  const w = Number.isFinite(v.w) && v.w > 0 ? Math.round(v.w) : undefined;
  const h = Number.isFinite(v.h) && v.h > 0 ? Math.round(v.h) : undefined;
  return (
    <div
      class="viewer"
      role="dialog"
      aria-modal="true"
      aria-label="image"
      onClick$={() => {
        ui.viewer = undefined;
      }}
    >
      <img src={v.src} width={w} height={h} alt="image, full size" />
      <p class="row" stoppropagation:click>
        {share.value ? (
          <button
            type="button"
            onClick$={async () => {
              const file = share.value;
              if (!file) return;
              try {
                await navigator.share({ files: [file] });
              } catch {
                // closed by the user (AbortError) or refused: nothing to do
              }
            }}
          >
            save
          </button>
        ) : (
          <a href={v.src} download={`segv-image.${extFor(v.mime)}`}>
            save
          </a>
        )}
        <button
          type="button"
          ref={closeBtn}
          onClick$={() => {
            ui.viewer = undefined;
          }}
        >
          close
        </button>
      </p>
    </div>
  );
});

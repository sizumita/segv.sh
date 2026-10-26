import { component$, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import { UiCtx } from "./state";
import { extFor } from "./util";

/** Full-size image overlay. Click anywhere or press escape to close. */
export const Viewer = component$(() => {
  const ui = useContext(UiCtx);
  const closeBtn = useSignal<HTMLButtonElement>();

  useVisibleTask$(() => {
    closeBtn.value?.focus();
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
        <a href={v.src} download={`segv-image.${extFor(v.mime)}`}>
          save
        </a>
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

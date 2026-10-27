import { component$, noSerialize, useContext, useSignal, useVisibleTask$ } from "@qwik.dev/core";
import type { ImageRef } from "~/client/types";
import { loadEngine } from "./engine-loader";
import { UiCtx } from "./state";
import { errMsg, fitBox } from "./util";

const MAX_SIDE = 320;

/**
 * Encrypted image: fetched + decrypted by the engine when scrolled into view. With `hold` (a request not yet
 * accepted) it waits until the user asks for it.
 */
export const MsgImage = component$<{ img: ImageRef; hold?: boolean }>((props) => {
  const ui = useContext(UiCtx);
  const url = useSignal("");
  const err = useSignal("");
  const attempt = useSignal(0);
  const asked = useSignal(false);

  // Default strategy (intersection-observer): only images that scroll into view are downloaded.
  useVisibleTask$(async ({ track }) => {
    track(() => props.img.id);
    track(() => attempt.value);
    if (track(() => !!props.hold && !asked.value)) return;
    const img = props.img;
    url.value = "";
    err.value = "";
    try {
      const u = await (await loadEngine()).loadImage(img);
      // Only ever display object URLs minted by the engine.
      if (typeof u !== "string" || !u.startsWith("blob:")) throw new Error("unexpected image url");
      if (props.img.id === img.id) url.value = u;
    } catch (e) {
      if (props.img.id === img.id) err.value = errMsg(e);
    }
  });

  const box = fitBox(props.img.w, props.img.h, MAX_SIDE);

  if (url.value) {
    return (
      <div class="img">
        <button
          type="button"
          class="imgbtn"
          aria-label="open image"
          onClick$={() => {
            ui.viewer = noSerialize({
              src: url.value,
              w: props.img.w,
              h: props.img.h,
              mime: props.img.mime,
            });
          }}
        >
          <img src={url.value} width={box.w} height={box.h} alt="image" decoding="async" />
        </button>
      </div>
    );
  }
  return (
    <div class="img">
      <canvas class="ph" width={box.w} height={box.h} aria-hidden="true" />
      <p class="phmsg small">
        {props.hold && !asked.value ? (
          <button type="button" class="link" onClick$={() => (asked.value = true)}>
            show image
          </button>
        ) : err.value ? (
          <>
            <span>image unavailable: {err.value}</span>{" "}
            <button type="button" class="link" onClick$={() => attempt.value++}>
              retry
            </button>
          </>
        ) : (
          <span class="dim">decrypting image…</span>
        )}
      </p>
    </div>
  );
});

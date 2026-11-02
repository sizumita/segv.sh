import { $, component$, noSerialize, useSignal, type NoSerialize } from "@qwik.dev/core";
import type { FileRef } from "@segv/engine/types";
import { loadEngine } from "./engine-loader";
import { errMsg, fmtBytes, shortName } from "./util";

/**
 * The file as a File for the share sheet (touch devices with Web Share for files, as the image viewer does), or null.
 * Its bytes are read back from the engine's blob: URL.
 */
async function shareFile(url: string, name: string): Promise<File | null> {
  if (typeof navigator.canShare !== "function" || typeof navigator.share !== "function")
    return null;
  if (!matchMedia("(hover: none) and (pointer: coarse)").matches) return null;
  const blob = await (await fetch(url)).blob();
  const file = new File([blob], name, { type: "application/octet-stream" });
  return navigator.canShare({ files: [file] }) ? file : null;
}

/** Saves the bytes behind `url` as a download named `name`. */
function download(url: string, name: string): void {
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/**
 * A file of a FILE row (§8.3): its name and size, and a control that saves it. The engine fetches and decrypts the
 * file only when the user asks for it; its bytes are saved under its name, and never shown here.
 */
export const MsgFile = component$<{ file: FileRef }>((props) => {
  const url = useSignal("");
  const busy = useSignal(false);
  const err = useSignal("");
  const share = useSignal<NoSerialize<File>>();

  const save = $(async () => {
    if (busy.value) return;
    const f = props.file;
    busy.value = true;
    err.value = "";
    try {
      const u = await (await loadEngine()).loadFile(f);
      // Only ever hand out object URLs minted by the engine.
      if (typeof u !== "string" || !u.startsWith("blob:")) throw new Error("unexpected file url");
      if (props.file.id !== f.id) return;
      url.value = u;
      // The share sheet opens only from a tap of its own: the next one.
      const file = await shareFile(u, f.name).catch(() => null);
      if (file) share.value = noSerialize(file);
      else download(u, f.name);
    } catch (e) {
      if (props.file.id === f.id) err.value = errMsg(e);
    } finally {
      busy.value = false;
    }
  });

  const f = props.file;
  const label = `save ${f.name}`;
  return (
    <div class="file">
      <p class="fname" title={f.name}>
        {shortName(f.name)}
      </p>
      <p class="small">
        <span class="dim">{fmtBytes(f.size)}</span>
        {f.id && (
          <>
            {" · "}
            {busy.value ? (
              <span class="dim">decrypting…</span>
            ) : share.value ? (
              <button
                type="button"
                class="link"
                aria-label={label}
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
            ) : url.value ? (
              <a href={url.value} download={f.name} aria-label={label}>
                save
              </a>
            ) : (
              <>
                {err.value && <span>unavailable: {err.value} · </span>}
                <button type="button" class="link" aria-label={label} onClick$={save}>
                  {err.value ? "retry" : "save"}
                </button>
              </>
            )}
          </>
        )}
      </p>
    </div>
  );
});

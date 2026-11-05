import { $, component$, useContext, useOnDocument, useSignal } from "@qwik.dev/core";
import { StateCtx, UiCtx } from "./state";

/** A warning's text without the engine's repeat count, so a dismissed one stays hidden when it repeats. */
export const warningKey = (w: string): string => w.replace(/ \(×\d+\)$/, "");

/**
 * Security warnings, as a chip at the foot of the conversation list: the list opens above it on hover, on focus, or
 * on a tap (which keeps it open until a tap outside or Escape). Dismissing hides a warning on this page only; the
 * engine keeps it (§12.7).
 */
export const Warnings = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const open = useSignal(false);
  const root = useSignal<HTMLElement>();

  useOnDocument(
    "click",
    $((e: Event) => {
      if (open.value && !root.value?.contains(e.target as Node)) open.value = false;
    }),
  );

  const shown = state.warnings.filter((w) => !ui.hiddenWarnings.includes(warningKey(w)));
  if (!shown.length) return null;

  const label = `${shown.length} security warning${shown.length > 1 ? "s" : ""}`;
  return (
    <div
      ref={root}
      class={{ warn: true, open: open.value }}
      onKeyDown$={(e) => {
        if (e.key === "Escape") {
          open.value = false;
          (document.activeElement as HTMLElement | null)?.blur();
        }
      }}
    >
      <button
        type="button"
        class="warn-chip"
        aria-expanded={open.value}
        aria-label={label}
        onClick$={() => (open.value = !open.value)}
      >
        ⚠ {shown.length}
      </button>
      <div class="warn-pop" role="alert">
        <div class="warn-list">
          <b>{label}</b>
          {shown.map((w, i) => (
            <p key={`${i}:${w}`}>
              <span>{w}</span>
              <button
                type="button"
                class="link"
                onClick$={() => {
                  ui.hiddenWarnings = [...ui.hiddenWarnings, warningKey(w)];
                }}
              >
                dismiss
              </button>
            </p>
          ))}
          {shown.length > 1 && (
            <button
              type="button"
              class="link all"
              onClick$={() => {
                ui.hiddenWarnings = [...ui.hiddenWarnings, ...shown.map(warningKey)];
                open.value = false;
              }}
            >
              dismiss all
            </button>
          )}
        </div>
      </div>
    </div>
  );
});

// The window's title bar on macOS: the page fills the whole window under the system's buttons (titleBarStyle
// "Overlay"), and its top strip moves the window as a title bar would, and zooms it on a double click. Controls in
// that strip (the conversation header's) keep working. On Windows the system draws the title bar above the page
// (src-tauri/tauri.windows.conf.json), which leaves the page nothing to do.
import { getCurrentWindow } from "@tauri-apps/api/window";

declare global {
  interface Window {
    /** What the native code tells the page about its window before the page loads (src-tauri/src/lib.rs, Windows). */
    readonly __SEGV_WINDOW__?: { readonly os?: string; readonly backdrop?: string };
  }
}

/**
 * Marks the root element with the window's system and backdrop (data-os, data-backdrop), which desktop.css styles: on
 * Windows the system's title bar, and Mica or an opaque window. Called first, before anything reads them.
 */
export function markWindow(): void {
  const w = window.__SEGV_WINDOW__;
  const root = document.documentElement;
  if (w?.os) root.dataset.os = w.os;
  if (w?.backdrop) root.dataset.backdrop = w.backdrop;
}

/** The height of the strip that acts as the title bar, in CSS pixels (desktop.css: --titlebar). */
const TITLEBAR = 44;

const INTERACTIVE =
  "a, button, input, textarea, select, label, summary, [role='button'], [contenteditable]";

function inTitleBar(e: MouseEvent): boolean {
  if (e.button !== 0 || e.clientY > TITLEBAR) return false;
  const t = e.target;
  return !(t instanceof Element && t.closest(INTERACTIVE));
}

export function moveByTitleBar(): void {
  if (document.documentElement.dataset.os === "windows") return;
  const w = getCurrentWindow();
  document.addEventListener("mousedown", (e) => {
    if (!inTitleBar(e)) return;
    e.preventDefault();
    if (e.detail === 2) void w.toggleMaximize();
    else void w.startDragging();
  });
}

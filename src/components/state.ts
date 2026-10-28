import { createContextId, type NoSerialize } from "@qwik.dev/core";
import type { EngineState } from "~/client/types";

/**
 * The lists on the left: `chats`, `requests` (request copies, §11.5, shown as a preview until accepted) and
 * `archives` (conversations this user left or was removed from).
 */
export type ListView = "chats" | "requests" | "archives";

/** UI-only state. Secrets (the recovery code) and live objects are wrapped in noSerialize(). */
export interface UiState {
  /** id of the conversation shown on the right ('' = none). Secret: the URL names it by its `ref` instead. */
  active: string;
  /** a ref from the URL (`#c/<ref>`) whose conversation is not loaded yet ('' = none; route.ts) */
  wanted: string;
  /** which list the left pane shows */
  list: ListView;
  /** members panel open */
  members: boolean;
  /** recovery code to show once after register(); cleared when the user confirms */
  recovery: NoSerialize<{ code: string }>;
  /** error from a rejected engine call (when the engine did not set state.error itself) */
  localError: string;
  /** settings dialog open */
  settings: boolean;
  /** document.visibilityState === 'visible' */
  visible: boolean;
  /** clock for relative times, refreshed every 30 s */
  now: number;
  /** full-size image overlay */
  viewer: NoSerialize<{ src: string; w: number; h: number; mime: string }>;
}

export const initialEngineState = (): EngineState => ({
  phase: "boot",
  progress: "",
  error: "",
  me: null,
  conversations: [],
  head: { seq: 0, h: "" },
  connected: false,
  syncing: false,
  warnings: [],
  prfSupported: null,
  notifications: "unavailable",
  preview: "unavailable",
  quiet: "unavailable",
});

export const initialUiState = (): UiState => ({
  active: "",
  wanted: "",
  list: "chats",
  members: false,
  recovery: undefined,
  localError: "",
  settings: false,
  visible: true,
  now: 0,
  viewer: undefined,
});

export const StateCtx = createContextId<EngineState>("segv.state");
export const UiCtx = createContextId<UiState>("segv.ui");

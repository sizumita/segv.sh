import { createContextId, type NoSerialize } from "@qwik.dev/core";
import type { EngineState } from "~/client/types";

/** UI-only state. Secrets (the recovery code) and live objects are wrapped in noSerialize(). */
export interface UiState {
  /** id of the conversation shown on the right ('' = none). Never put it in the URL. */
  active: string;
  /** members panel open */
  members: boolean;
  /** recovery code to show once after register(); cleared when the user confirms */
  recovery: NoSerialize<{ code: string }>;
  /** error from a rejected engine call (when the engine did not set state.error itself) */
  localError: string;
  /** short-lived success notice ("passkey added") */
  notice: string;
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
});

export const initialUiState = (): UiState => ({
  active: "",
  members: false,
  recovery: undefined,
  localError: "",
  notice: "",
  visible: true,
  now: 0,
  viewer: undefined,
});

export const StateCtx = createContextId<EngineState>("segv.state");
export const UiCtx = createContextId<UiState>("segv.ui");

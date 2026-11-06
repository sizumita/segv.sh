import { createContextId, type NoSerialize } from "@qwik.dev/core";
import type { EngineState, ImageRef } from "@segv/engine/types";

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
  /** "new conversation" dialog open (new-chat.tsx) */
  newChat: boolean;
  /** the account the last new conversation was started as, for the next one (a uid; '' = the owner) */
  startAs: string;
  /** a temporary handle is being made (`createAlias`, a proof of work): one at a time */
  makingAlias: boolean;
  /** document.visibilityState === 'visible' */
  visible: boolean;
  /** clock for relative times, refreshed every 30 s */
  now: number;
  /** full-size image overlay: the engine's object URL of `img`, which the viewer holds while open */
  viewer: NoSerialize<{ src: string; w: number; h: number; mime: string; img: ImageRef }>;
  /** the URL of a [label](url) link the user clicked, to confirm before it opens ('' = none) */
  leaving: string;
  /** security warnings the user dismissed, by their text without the repeat count (warnings.tsx) */
  hiddenWarnings: string[];
}

export const initialEngineState = (): EngineState => ({
  phase: "boot",
  progress: "",
  error: "",
  me: null,
  identities: [],
  people: [],
  conversations: [],
  head: { seq: 0, h: "" },
  connected: false,
  syncing: false,
  warnings: [],
  prfSupported: null,
  notifications: "unavailable",
  localNotify: false,
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
  newChat: false,
  startAs: "",
  makingAlias: false,
  visible: true,
  now: 0,
  viewer: undefined,
  leaving: "",
  hiddenWarnings: [],
});

/**
 * The state of the open conversation's pane (conversation.tsx), which starts empty for each conversation: the pane is
 * drawn again when another one opens.
 */
export interface PaneState {
  /** the key of the message the composer replies to ('' = none, §11.17) */
  reply: string;
  /** the message whose replies the side pane shows: the chain above it and the replies below it ('' = closed) */
  thread: string;
  /** the message the side pane's message box replies to ('' = the last message the pane shows) */
  threadTo: string;
  /** the key of self's message that the composer edits ('' = none, §11.18); never set together with `reply` */
  edit: string;
  /** the message whose versions the "edit history" dialog shows ('' = closed, edit.tsx) */
  history: string;
}

export const StateCtx = createContextId<EngineState>("segv.state");
export const UiCtx = createContextId<UiState>("segv.ui");
export const PaneCtx = createContextId<PaneState>("segv.pane");

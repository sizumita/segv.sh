// Contract between the client engine (src/client/engine.ts) and the Qwik UI.
// Everything in EngineState is plain, serialisable data (strings, numbers, booleans, arrays,
// objects) so the UI can copy it into a Qwik store. Secrets never appear here.

export type Phase =
  | "boot" // engine is loading / checking for a remembered session
  | "signed-out" // no session: show register / sign-in
  | "working" // a sign-in / registration is in progress (see `progress`)
  | "ready" // signed in; conversations are live
  | "fatal"; // unrecoverable (account check failure: account missing from the directory, or keys mismatch); `error` explains

export interface Me {
  uid: string; // b64u
  handle: string;
  fingerprint: string; // "12345 67890 ..." (6 groups of 5 digits)
}

export interface MemberView {
  uid: string;
  /** handle, or `?` + 8 uid characters for a member not (or not validly, or not yet) resolved in the directory (§11.2) */
  handle: string;
  fingerprint: string;
  /** recorded as left in the current epoch (its LEAVE row, or a LEFT record at restore) and not yet rotated out */
  left: boolean;
}

export interface ImageRef {
  id: string;
  k: string;
  mime: string;
  w: number;
  h: number;
}

export interface MessageView {
  /** stable unique key (era and label hex for a row, `local:<n>` for a local echo) */
  key: string;
  /** local application order (stable tie-breaker), not a server sequence; 0 for a local echo */
  seq: number;
  from: string; // uid ('' for system lines)
  fromHandle: string;
  mine: boolean;
  /** ms; sender time clamped to the row's public time ± 5 min (§11.8) */
  ts: number;
  kind: "text" | "image" | "leave" | "system";
  text?: string; // text body, or the system line ("alice added bob")
  image?: ImageRef;
  status: "sent" | "sending" | "failed";
}

/**
 * Why a conversation cannot be sent to (`""` when it can, so `canSend === (blocked === "")`):
 * - `removed` / `left`: this user is no longer a member (both: `removed`);
 * - `pending`: an undecided control slot, or a winning claim not yet final or processed, has stayed so for the 30 s
 *   processing wait, so a text would fail (§11.3 step 2); a shorter wait shows nothing, and a send made
 *   meanwhile waits;
 * - `frozen`: frozen by a change whose `rm` removed a member who had not left (§6.6 step 6).
 */
export type Blocked = "" | "removed" | "left" | "pending" | "frozen";

export interface ConversationView {
  /** opaque copy key (`b64u(conv)`, or `b64u(conv)~i` for a later copy, §7.3); secret, only ever used locally */
  id: string;
  name: string; // explicit group name ("# name"), or the other members' handles joined by ", "
  members: MemberView[]; // current epoch, in descriptor order
  epoch: number;
  /**
   * true iff `blocked` is `""`: false once this user was removed or left, while an undecided control slot, or a
   * winning claim not yet final or processed, has stayed so for 30 s, and in a frozen conversation whose freezing
   * change removed a member who had not left, by the current leave state (§11.3 step 2); otherwise a frozen
   * member can still send
   */
  canSend: boolean;
  blocked: Blocked;
  /** the members can no longer change (§6.6 steps 4 and 6): adding and removing fail; sending and leaving work */
  frozen: boolean;
  /** a request copy (§11.5): opening it (`markRead`) accepts it and makes its inviter a contact */
  request: boolean;
  lastTs: number; // for sorting
  unread: number;
  /** display order (§11.8); local echoes last */
  messages: MessageView[];
}

export interface EngineState {
  phase: Phase;
  progress: string; // human-readable status ("waiting for passkey…", "solving proof of work…"), '' when idle
  error: string; // last user-facing error, '' when none
  me: Me | null;
  conversations: ConversationView[]; // most recent activity first
  /** latest verified checkpoint: {seq: q, h: b64u(C_q)}; `{seq: 0, h: ""}` until a checkpoint is verified */
  head: { seq: number; h: string };
  connected: boolean; // realtime socket (/api/v2/rt) is open
  syncing: boolean; // restoring or catching up
  warnings: string[]; // security warnings (split view, signature failures, …)
  prfSupported: boolean | null; // getClientCapabilities()['extension:prf'] if known
}

export interface Engine {
  getState(): EngineState;
  /** Calls `fn` immediately and after every state change. Returns an unsubscribe function. */
  subscribe(fn: (s: EngineState) => void): () => void;

  /** Creates an account + passkey. Resolves with the recovery code to show ONCE.
   *  `remember` keeps the session on this device (like `login(remember)`). */
  register(handle: string, remember?: boolean): Promise<{ recoveryCode: string }>;
  /** Discoverable passkey sign-in (PRF unlock). */
  login(remember: boolean): Promise<void>;
  /** Unlock with the recovery code instead of a passkey. */
  loginWithRecovery(code: string, remember: boolean): Promise<void>;
  /** Signed in only: enrol another passkey for this account. */
  addPasskey(): Promise<void>;
  /** Forget the session on this device (in-memory keys and remembered session). */
  logout(): Promise<void>;

  /**
   * Starts a conversation with the given handles (1 handle = 1:1). Resolves with the conversation id after the bundle
   * upload and the first self row, with the conversation already in `conversations` (§6.1 step 5); the
   * invitations finish in the background (at least Δ + SKEW later).
   */
  createConversation(handles: string[], name?: string): Promise<string>;
  sendText(convId: string, text: string): Promise<void>;
  sendImage(convId: string, file: File): Promise<void>;
  /** Resolves after the switch to the new epoch and the first delivery attempt (§6.3). */
  addMembers(convId: string, handles: string[]): Promise<void>;
  /** Resolves after the switch to the new epoch and the first delivery attempt (§6.3). */
  removeMember(convId: string, uid: string): Promise<void>;
  leave(convId: string): Promise<void>;

  /** Downloads + decrypts an image. Resolves with an object URL (cached per image id). */
  loadImage(img: ImageRef): Promise<string>;
  /**
   * Resets `unread`. Also the "conversation opened" hint: it accepts a request copy and starts scrollback once
   * (§11.10–§11.11), even when `unread` is 0.
   */
  markRead(convId: string): void;
  clearError(): void;
}

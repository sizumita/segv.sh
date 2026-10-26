// Contract between the client engine (src/client/engine.ts) and the Qwik UI.
// Everything in EngineState is plain, serialisable data (strings, numbers, booleans, arrays,
// objects) so the UI can copy it into a Qwik store. Secrets never appear here.

export type Phase =
  | "boot" // engine is loading / checking for a remembered session
  | "signed-out" // no session: show register / sign-in
  | "working" // a sign-in / registration is in progress (see `progress`)
  | "ready" // signed in; conversations are live
  | "fatal"; // unrecoverable (e.g. log integrity failure); `error` explains

export interface Me {
  uid: string; // b64u
  handle: string;
  fingerprint: string; // "12345 67890 ..." (6 groups of 5 digits)
}

export interface MemberView {
  uid: string;
  handle: string;
  fingerprint: string;
  left: boolean; // posted "leave" in the current epoch but has not been rotated out yet
}

export interface ImageRef {
  id: string;
  k: string;
  mime: string;
  w: number;
  h: number;
}

export interface MessageView {
  key: string; // stable unique key (tag hex, or "local:<n>" for local echoes)
  seq: number; // log sequence number (0 for a local echo)
  from: string; // uid ('' for system lines)
  fromHandle: string;
  mine: boolean;
  ts: number; // ms; sender-claimed time for messages, log time for system lines
  kind: "text" | "image" | "leave" | "system";
  text?: string; // text body, or the system line ("alice added bob")
  image?: ImageRef;
  status: "sent" | "sending" | "failed";
}

export interface ConversationView {
  id: string; // b64u conv id (secret; only ever shown locally)
  name: string; // explicit group name, or the other members' handles joined by ", "
  members: MemberView[]; // current epoch, in descriptor order
  epoch: number;
  canSend: boolean; // false once this user was removed
  lastTs: number; // for sorting
  unread: number;
  messages: MessageView[]; // ascending by seq (local echoes last)
}

export interface EngineState {
  phase: Phase;
  progress: string; // human-readable status ("waiting for passkey…", "solving proof of work…"), '' when idle
  error: string; // last user-facing error, '' when none
  me: Me | null;
  conversations: ConversationView[]; // most recent activity first
  head: { seq: number; h: string }; // latest verified log head
  connected: boolean; // live WebSocket is open
  syncing: boolean; // backfilling the log
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

  /** Starts a conversation with the given handles (1 handle = 1:1). Returns the conversation id. */
  createConversation(handles: string[], name?: string): Promise<string>;
  sendText(convId: string, text: string): Promise<void>;
  sendImage(convId: string, file: File): Promise<void>;
  addMembers(convId: string, handles: string[]): Promise<void>;
  removeMember(convId: string, uid: string): Promise<void>;
  leave(convId: string): Promise<void>;

  /** Downloads + decrypts an image. Resolves with an object URL (cached per image id). */
  loadImage(img: ImageRef): Promise<string>;
  markRead(convId: string): void;
  clearError(): void;
}

// Contract between the client engine (packages/engine/src/engine.ts) and the Qwik UI.
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

/**
 * One account that this device runs for the user (§2.6, §11.11 "Accounts in the view"): the owner (the account that
 * signed in) or one of its aliases, the temporary handles. Listed owner first, then the aliases by index.
 */
export interface IdentityView {
  /** b64u uid */
  uid: string;
  /** the handle; an alias's is computed on the device from its keys (§2.6), retired ones included */
  handle: string;
  fingerprint: string;
  /** an alias (a temporary handle); false for the owner */
  alias: boolean;
  /** the alias's index (§2.6); -1 for the owner */
  index: number;
  /** a retired alias: not run, its conversations not shown (§2.6 "Retiring") */
  retired: boolean;
  /**
   * `starting` while its restore runs (or waits for its turn), `ready` once it runs, `failed` when this device does not
   * run it because its directory entry did not check (§2.6 "Running aliases"), `idle` when it is live but beyond the
   * MAX_LIVE_ALIASES with the highest indices that this device runs, `retired` for a retired alias. The owner is
   * `starting` or `ready`.
   */
  status: "starting" | "ready" | "failed" | "idle" | "retired";
}

/** At most this many aliases run at once (§2.6 `MAX_LIVE_ALIASES`); creating and bringing back fail beyond it. */
export const MAX_LIVE_ALIASES = 16;

/**
 * A user that one of the device's accounts knows (a MEMBER record: verified in the directory, §7.3), for suggestions
 * and nicknames. The owner and its aliases are never listed.
 */
export interface PersonView {
  uid: string;
  handle: string;
  /** the nickname the user gave them (§11.19), "" for none */
  nickname: string;
  /** the uids of the device's accounts (owner and aliases) of which this user is a contact (§7.3) */
  contactOf: string[];
}

export interface MemberView {
  uid: string;
  /** handle, or `?` + 8 uid characters for a member not (or not validly, or not yet) resolved in the directory (§11.2) */
  handle: string;
  /** the nickname the user gave this member (§11.19); "" for none, and always "" for an unknown (`?…`) member */
  nickname: string;
  /** the member is the copy's own account (the owner or the alias that holds the copy, §2.6) */
  you: boolean;
  /**
   * the member is another of the user's own accounts (the owner, or one of its aliases, §2.6), listed with that
   * account's own keys (a slot with its uid and other keys is an unknown member): "your other handle"
   */
  own: boolean;
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

/** A file of a FILE row (§8.3). */
export interface FileRef {
  /** b64u blob id; "" in the echo of a file still being sent */
  id: string;
  /** b64u key; "" in an echo */
  k: string;
  /** the safe name (§8.3): what the UI shows and saves the file as */
  name: string;
  /** bytes */
  size: number;
}

/** At most this many emoji are on per member and message (§11.12 `MAX_REACTIONS`); the UI offers no more. */
export const MAX_REACTIONS = 8;

/** One emoji under a message (§11.12): how many members have it on, and whether self is one of them. */
export interface ReactionView {
  emoji: string;
  count: number;
  mine: boolean;
}

/**
 * The target of a reply (a REPLY row, §11.17): `shown` with the target's message key, `waiting` while the target is
 * not loaded (or not decided) yet, or `none` when the reply names no message this conversation can show (`key` "").
 */
export interface ReplyView {
  key: string;
  state: "shown" | "waiting" | "none";
}

/**
 * A message's edits (EDIT rows, §11.18): when the latest was made, how many count, and whether the text shown is an
 * edit this device is still sending.
 */
export interface EditedView {
  /** ms: the clamped ts (§11.8) of the latest edit that counts, or this device's clock for an edit still being sent */
  ts: number;
  /** the EDIT rows that count for the message (0 while only an edit of this device is being sent) */
  count: number;
  /** the text shown is an edit this device is still sending */
  sending: boolean;
}

/** One version of an edited message (§11.18 "Display"): its text, and when it was sent (clamped, §11.8). */
export interface EditVersion {
  text: string;
  ts: number;
}

export interface MessageView {
  /** stable unique key (era and label hex for a row, `local:<n>` for a local echo) */
  key: string;
  /** local application order (stable tie-breaker), not a server sequence; 0 for a local echo */
  seq: number;
  from: string; // uid ('' for system lines)
  fromHandle: string;
  /** the sender's nickname (§11.19), "" for none (and for self, system lines and unknown members) */
  fromNickname: string;
  mine: boolean;
  /** ms; sender time clamped to the row's public time ± 5 min (§11.8) */
  ts: number;
  kind: "text" | "image" | "file" | "leave" | "system";
  text?: string; // text body, or the system line ("alice added bob")
  image?: ImageRef;
  file?: FileRef;
  status: "sent" | "sending" | "failed";
  /** the reactions to a TEXT, IMAGE, FILE or REPLY message (§11.12); empty for every other message */
  reactions: ReactionView[];
  /** what a REPLY replies to (§11.17), in its view and its echo; absent for every other message */
  reply?: ReplyView;
  /**
   * The message's edits (§11.18), absent while none counts and none of this device is being sent; `text` is then the
   * current text (that of its latest edit, or of the edit being sent).
   */
  edited?: EditedView;
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
  /**
   * opaque view id: the copy key (`b64u(conv)`, or `b64u(conv)~i` for a later copy, §7.3) for a copy of the owner, and
   * a prefixed copy key for a copy of an alias, unique among the copies of every account on the device; secret, only
   * ever used locally
   */
  id: string;
  /** the uid of the account that holds the copy: the owner's, or an alias's (§2.6, `EngineState.identities`) */
  as: string;
  /**
   * The copy's name in the page URL (`/#c/<ref>`): 12 b64u characters, a keyed hash of `id` under a key derived from
   * the account key. Every device of the account computes the same ref, other accounts a different one, and it tells
   * nothing about `conv`. It sits in a URL fragment, which browsers never send to the server.
   */
  ref: string;
  /** explicit group name ("# name"), or the other members' names (a nickname, else `@handle`, §11.19) joined by ", " */
  name: string;
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
  /** a request copy (§11.5): the user accepts it with `accept`; opening its preview accepts nothing */
  request: boolean;
  /**
   * The copy's inviter (`rootBy`) is self or a contact (§11.11). While it is false and the copy has not ended, the UI
   * shows the copy as a request's read-only preview, whose accept control calls `accept`.
   */
  byContact: boolean;
  lastTs: number; // for sorting
  unread: number;
  /** display order (§11.8); local echoes last */
  messages: MessageView[];
}

export interface EngineState {
  phase: Phase;
  progress: string; // human-readable status ("waiting for passkey…", "solving proof of work…"), '' when idle
  error: string; // last user-facing error, '' when none
  /** the owner: the account that signed in */
  me: Me | null;
  /** every account this device runs for the user: the owner first, then its aliases by index (§2.6, §11.11) */
  identities: IdentityView[];
  /** users the device's accounts know, for suggestions and nicknames (§11.19); never the user's own accounts */
  people: PersonView[];
  conversations: ConversationView[]; // most recent activity first, every account's copies together
  /** latest verified checkpoint: {seq: q, h: b64u(C_q)}; `{seq: 0, h: ""}` until a checkpoint is verified */
  head: { seq: number; h: string };
  connected: boolean; // realtime socket (/api/v2/rt) is open
  /** restoring or catching up; true until the owner and every live alias have restored (or failed, §2.6) */
  syncing: boolean;
  warnings: string[]; // security warnings (split view, signature failures, …)
  prfSupported: boolean | null; // getClientCapabilities()['extension:prf'] if known
  /**
   * Notifications on this device (§11.13): "unavailable" when the browser has no Web Push (on iOS and iPadOS, outside
   * a Home Screen web app) or the server offers none; otherwise whether they are on. Per device, never synced.
   */
  notifications: "unavailable" | "off" | "on";
  /**
   * The notifications come from the app itself while it runs, from the rows that reach it, also with its window
   * closed (an app without push, §11.13): no push service is involved, and none comes while the app is not running.
   */
  localNotify: boolean;
  /**
   * What notifications show on this device (§11.13): "unavailable" while notifications are unavailable or the session
   * is not kept on this device (the Service Worker needs the notification cache, which is kept only then).
   */
  preview: "unavailable" | "none" | "name" | "message";
  /**
   * "Quiet my other devices while I use this one" (§11.13): "unavailable" when the server offers no push; otherwise
   * whether this device marks the rows it shows seen while in use, so that the account's devices get no push for them.
   * Per device, on by default, never synced; it works whether or not this device's own notifications are on.
   */
  quiet: "unavailable" | "off" | "on";
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
   * Starts a conversation with the given handles (1 handle = 1:1), as the account `as` (the uid of the owner or of a
   * live alias; the owner when absent, §11.11). Resolves with the conversation id after the bundle upload and the first
   * self row, with the conversation already in `conversations` (§6.1 step 5); the invitations finish in the background
   * (at least Δ + SKEW later). Rejects with "@x is one of your own handles" for a handle of another of the user's
   * accounts (§2.6).
   */
  createConversation(handles: string[], name?: string, as?: string): Promise<string>;
  /**
   * Creates a temporary handle (an alias, §2.6 "Creating"): registers it (a proof of work) and starts it. Resolves with
   * its uid once it runs; rejects with "could not create a temporary handle; try again", or with "at most 16 temporary
   * handles can be active; retire one first".
   */
  createAlias(): Promise<string>;
  /** Retires an alias, or brings it back (§2.6 "Retiring"; bringing back fails like `createAlias` beyond the cap). */
  setAliasRetired(uid: string, retired: boolean): Promise<void>;
  /**
   * Gives the user `uid` a nickname, or removes it with "" (§11.19). Rejects with "a nickname: 1–64 characters, not
   * starting with @" or "you cannot give your own handles a nickname".
   */
  setNickname(uid: string, nickname: string): Promise<void>;
  /**
   * The send calls take an optional `replyTo`: the key of a TEXT, IMAGE, FILE or REPLY message of the conversation,
   * which the message then replies to (a REPLY row, §11.17). An unknown key rejects at once ("unknown message").
   */
  sendText(convId: string, text: string, replyTo?: string): Promise<void>;
  sendImage(convId: string, file: File, replyTo?: string): Promise<void>;
  /** Sends a file as it is (§8.3): no re-encoding, so its metadata goes with it. At most FILE_MAX bytes. */
  sendFile(convId: string, file: File, replyTo?: string): Promise<void>;
  /** Resolves after the switch to the new epoch and the first delivery attempt (§6.3). */
  addMembers(convId: string, handles: string[]): Promise<void>;
  /** Resolves after the switch to the new epoch and the first delivery attempt (§6.3). */
  removeMember(convId: string, uid: string): Promise<void>;
  leave(convId: string): Promise<void>;

  /**
   * Adds (`on`) or removes one emoji reaction to the TEXT, IMAGE, FILE or REPLY message `messageKey` (§11.12): one REACTION row,
   * sent as a text is (§11.3) but without an echo. Resolves when the row counts as delivered; a reaction that would
   * change nothing resolves at once without a row.
   */
  react(convId: string, messageKey: string, emoji: string, on: boolean): Promise<void>;
  /**
   * Edits self's TEXT message, or self's REPLY carrying a text, `messageKey` (§11.18): one EDIT row with the new text,
   * sent as a text is (§11.3) but without an echo. The message shows `text` at once (`edited.sending`), and its current
   * text again if the send fails. Resolves when the row counts as delivered; rejects with "unknown message" for an
   * unknown key, "this message cannot be edited" for any other member's message, an image or a file, or a message not
   * sent yet, "an edit cannot be empty", or "message is too long"; a text equal to the current one resolves at once
   * without a row.
   */
  editText(convId: string, messageKey: string, text: string): Promise<void>;
  /**
   * The versions of an edited message (§11.18 "Display"): its own text, then the text of each edit that counts, in
   * lane order, each with its time. Empty for a message without edits, and for an unknown key.
   */
  editHistory(convId: string, messageKey: string): EditVersion[];
  /**
   * The user's acceptance from the accept control (§11.5, §11.11): for a live copy whose inviter is neither self nor
   * a contact, writes the request's acceptance and the inviter's CONTACT at once; does nothing for any other copy.
   */
  accept(convId: string): Promise<void>;

  /**
   * Downloads + decrypts an image. Resolves with an object URL (cached per image id and key), which stays valid until
   * the caller calls `releaseImage` for it once it no longer shows it (not after a rejection).
   */
  loadImage(img: ImageRef): Promise<string>;
  /** The caller no longer shows an image that `loadImage` gave it: the URL may be revoked from now on. */
  releaseImage(img: ImageRef): void;
  /**
   * Downloads + decrypts a file, only when the user asks for it (§8.3). Resolves with an object URL of its bytes as
   * `application/octet-stream`, cached by `id.k`; the UI saves it under `name` and never shows its content.
   */
  loadFile(file: FileRef): Promise<string>;
  /**
   * Resets `unread` and starts scrollback once (§11.10–§11.11): the "conversation pane is open" hint, even when
   * `unread` is 0. It accepts nothing. `opened` (default true): the user opened the pane, or its page became visible
   * again; pass false when only rows arrived in a pane already open. Only an opening posts an alias's BELL row
   * (§11.13), so that no member can choose when an alias writes (§2.6).
   */
  markRead(convId: string, opened?: boolean): void;
  /**
   * Turns notifications on this device on or off (§11.13). Turning them on must be called from the user's click: it
   * may ask for permission.
   */
  setNotifications(on: boolean): Promise<void>;
  /** Chooses what notifications show on this device (§11.13). */
  setPreview(p: "none" | "name" | "message"): Promise<void>;
  /** Turns "quiet my other devices while I use this one" on or off for this device (§11.13). */
  setQuiet(on: boolean): Promise<void>;
  clearError(): void;
}
